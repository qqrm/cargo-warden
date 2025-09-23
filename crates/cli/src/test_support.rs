use std::ffi::OsString;
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

pub(crate) struct EnvVarGuard {
    key: String,
    previous: Option<OsString>,
}

impl EnvVarGuard {
    pub(crate) fn set(key: &str, value: OsString) -> Self {
        let previous = std::env::var_os(key);
        unsafe {
            // SAFETY: tests invoke these helpers in a single-threaded context.
            std::env::set_var(key, &value);
        }
        Self {
            key: key.to_owned(),
            previous,
        }
    }

    pub(crate) fn unset(key: &str) -> Self {
        let previous = std::env::var_os(key);
        unsafe {
            // SAFETY: tests invoke these helpers in a single-threaded context.
            std::env::remove_var(key);
        }
        Self {
            key: key.to_owned(),
            previous,
        }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        if let Some(value) = self.previous.take() {
            unsafe {
                // SAFETY: tests invoke these helpers in a single-threaded context.
                std::env::set_var(&self.key, value);
            }
        } else {
            unsafe {
                // SAFETY: tests invoke these helpers in a single-threaded context.
                std::env::remove_var(&self.key);
            }
        }
    }
}
