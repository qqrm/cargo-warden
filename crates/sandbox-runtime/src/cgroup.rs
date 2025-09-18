use crate::util::{CGROUP_ROOT_ENV, cgroup_root, unique_suffix};
use std::env;
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
        let procs = OpenOptions::new()
            .write(true)
            .open(path.join("cgroup.procs"))?;
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
        if env::var_os(CGROUP_ROOT_ENV).is_some() {
            let procs_path = self.path.join("cgroup.procs");
            match fs::remove_file(&procs_path) {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(err) => return Err(err),
            }
        }
        match fs::remove_dir(&self.path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err),
        }
    }

    #[cfg(test)]
    fn path(&self) -> &PathBuf {
        &self.path
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
    use serial_test::serial;
    use std::ffi::{OsStr, OsString};
    use std::path::PathBuf;
    use tempfile::TempDir;

    struct EnvGuard {
        key: String,
        original: Option<OsString>,
    }

    impl EnvGuard {
        fn set(key: &str, value: impl AsRef<OsStr>) -> Self {
            let original = env::var_os(key);
            unsafe { env::set_var(key, value) };
            Self {
                key: key.to_string(),
                original,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(value) = &self.original {
                unsafe { env::set_var(&self.key, value) };
            } else {
                unsafe { env::remove_var(&self.key) };
            }
        }
    }

    #[test]
    #[serial]
    fn create_and_cleanup_removes_directory() -> io::Result<()> {
        let root = TempDir::new().expect("tempdir");
        let _guard = EnvGuard::set(CGROUP_ROOT_ENV, root.path());
        let mut cgroup = Cgroup::create()?;
        let path = cgroup.path().clone();
        assert!(path.exists(), "cgroup directory should exist");
        assert!(
            path.join("cgroup.procs").exists(),
            "cgroup.procs should exist"
        );
        cgroup.cleanup()?;
        assert!(!path.exists(), "cleanup should remove the cgroup directory");
        Ok(())
    }

    #[test]
    #[serial]
    fn drop_removes_directory() -> io::Result<()> {
        let root = TempDir::new().expect("tempdir");
        let _guard = EnvGuard::set(CGROUP_ROOT_ENV, root.path());
        let path: PathBuf;
        {
            let cgroup = Cgroup::create()?;
            path = cgroup.path().clone();
        }
        assert!(
            !path.exists(),
            "dropping the cgroup should remove the directory"
        );
        Ok(())
    }
}
