use crate::util::{cgroup_root, unique_suffix};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::path::PathBuf;
use std::process;

pub(crate) struct Cgroup {
    path: PathBuf,
    dir: Option<File>,
    procs: Option<File>,
}

impl Cgroup {
    pub(crate) fn create() -> io::Result<Self> {
        let base = cgroup_root();
        let prefix = base.join("cargo-warden");
        fs::create_dir_all(&prefix)?;
        let identifier = format!("pid-{}-{}", process::id(), unique_suffix());
        let path = prefix.join(identifier);
        fs::create_dir(&path)?;
        let dir = File::open(&path)?;
        let procs_path = path.join("cgroup.procs");
        if !procs_path.exists() {
            File::create(&procs_path)?;
        }
        let procs = OpenOptions::new().write(true).open(&procs_path)?;
        Ok(Self {
            path,
            dir: Some(dir),
            procs: Some(procs),
        })
    }

    pub(crate) fn dir_file(&self) -> io::Result<&File> {
        self.dir
            .as_ref()
            .ok_or_else(|| io::Error::other("cgroup directory handle missing"))
    }

    pub(crate) fn procs_fd_raw(&self) -> io::Result<RawFd> {
        self.procs
            .as_ref()
            .map(|f| f.as_raw_fd())
            .ok_or_else(|| io::Error::other("cgroup procs handle missing"))
    }

    pub(crate) fn cleanup(&mut self) -> io::Result<()> {
        self.procs.take();
        self.dir.take();
        let procs_path = self.path.join("cgroup.procs");
        if let Err(err) = fs::remove_file(&procs_path) {
            match err.kind() {
                io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied => {}
                _ => return Err(err),
            }
        }
        match fs::remove_dir(&self.path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err),
        }
    }
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::CGROUP_ROOT_ENV;
    use serial_test::serial;
    use std::env;
    use std::fs;
    use tempfile::tempdir;

    struct EnvGuard {
        key: &'static str,
        original: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &std::path::Path) -> Self {
            let original = env::var_os(key);
            unsafe { env::set_var(key, value) };
            Self { key, original }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(val) = &self.original {
                unsafe { env::set_var(self.key, val) };
            } else {
                unsafe { env::remove_var(self.key) };
            }
        }
    }

    #[test]
    #[serial]
    fn create_and_cleanup_cgroup_under_fake_root() -> io::Result<()> {
        let temp = tempdir()?;
        let fake_root = temp.path().join("fake-cgroup-root");
        fs::create_dir_all(&fake_root)?;
        let _guard = EnvGuard::set(CGROUP_ROOT_ENV, &fake_root);

        let mut cgroup = Cgroup::create()?;
        let path = cgroup.path.clone();
        let procs_path = path.join("cgroup.procs");

        assert!(path.exists(), "cgroup directory should exist");
        assert!(procs_path.exists(), "cgroup.procs should be created");
        assert!(cgroup.procs_fd_raw()? >= 0);

        cgroup.cleanup()?;
        assert!(!path.exists(), "cgroup directory should be removed");
        assert!(
            !procs_path.exists(),
            "cgroup.procs should be removed during cleanup"
        );
        Ok(())
    }

    #[test]
    #[serial]
    fn cleanup_tolerates_missing_directories() -> io::Result<()> {
        let temp = tempdir()?;
        let fake_root = temp.path().join("fake-cgroup-root");
        fs::create_dir_all(&fake_root)?;
        let _guard = EnvGuard::set(CGROUP_ROOT_ENV, &fake_root);

        let mut cgroup = Cgroup::create()?;
        let path = cgroup.path.clone();

        fs::remove_dir_all(&path)?;
        assert!(!path.exists());

        cgroup.cleanup()?;
        Ok(())
    }
}
