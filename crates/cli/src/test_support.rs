use std::path::{Path, PathBuf};

pub(crate) struct DirGuard {
    original: PathBuf,
}

impl DirGuard {
    pub(crate) fn change_to(path: &Path) -> Self {
        let original = std::env::current_dir().unwrap();
        std::env::set_current_dir(path).unwrap();
        Self { original }
    }
}

impl Drop for DirGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.original);
    }
}
