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
