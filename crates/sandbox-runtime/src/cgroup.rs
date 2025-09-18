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
        let procs = match OpenOptions::new().write(true).open(&procs_path) {
            Ok(file) => file,
            Err(err) if err.kind() == io::ErrorKind::NotFound => File::create(&procs_path)?,
            Err(err) => return Err(err),
        };
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
        if procs_path.exists() {
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
        previous: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &std::path::Path) -> Self {
            let previous = env::var_os(key);
            unsafe {
                env::set_var(key, value);
            }
            Self { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(value) = self.previous.take() {
                unsafe {
                    env::set_var(self.key, value);
                }
            } else {
                unsafe {
                    env::remove_var(self.key);
                }
            }
        }
    }

    #[test]
    #[serial]
    fn cgroup_create_and_cleanup_respects_custom_root() -> io::Result<()> {
        let root = tempdir().expect("tempdir");
        let prefix = root.path().join("cargo-warden");
        let _guard = EnvGuard::set(CGROUP_ROOT_ENV, root.path());

        assert!(
            !prefix.exists(),
            "cgroup prefix should not exist before creation"
        );
        let mut cgroup = Cgroup::create()?;
        assert!(prefix.exists(), "expected prefix directory to be created");

        let created_dir = fs::read_dir(&prefix)
            .expect("prefix listing")
            .next()
            .expect("cgroup entry")?
            .path();
        assert!(
            created_dir.join("cgroup.procs").exists(),
            "expected cgroup procs file"
        );

        cgroup.dir_file()?.metadata()?;
        let procs_fd = cgroup.procs_fd_raw()?;
        assert!(procs_fd >= 0, "raw fd should be valid");

        cgroup.cleanup()?;
        assert!(
            !created_dir.exists(),
            "cleanup should remove cgroup directory: {}",
            created_dir.display()
        );
        Ok(())
    }
}
