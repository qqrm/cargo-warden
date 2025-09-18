use aya::maps::{MapData, ring_buf::RingBuf};
use aya::{Ebpf, EbpfLoader};
use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;

pub(crate) fn load_bpf() -> io::Result<Ebpf> {
    let path = bpf_object_path();
    let data = fs::read(&path)?;
    EbpfLoader::new().load(&data).map_err(|err| {
        io::Error::other(format!(
            "failed to load BPF object {}: {err}",
            path.display()
        ))
    })
}

fn bpf_object_path() -> PathBuf {
    if let Some(path) = env::var_os("QQRM_BPF_OBJECT") {
        PathBuf::from(path)
    } else {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../prebuilt")
            .join(env::consts::ARCH)
            .join("qqrm-bpf-core.o")
    }
}

pub(crate) fn take_events_ring(bpf: &mut Ebpf) -> io::Result<RingBuf<MapData>> {
    for name in ["events", "EVENTS"] {
        if let Some(map) = bpf.take_map(name) {
            return RingBuf::try_from(map).map_err(|err| {
                io::Error::other(format!("failed to open ring buffer {name}: {err}"))
            });
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "events ring buffer not found",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::env;
    use std::fs::File;
    use std::io::Write;
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
    fn load_bpf_reports_invalid_object_path() {
        let dir = tempdir().expect("tempdir");
        let object_path = dir.path().join("dummy.o");
        let mut file = File::create(&object_path).expect("create dummy object");
        file.write_all(b"not a valid bpf object")
            .expect("write dummy contents");
        drop(file);

        let _guard = EnvGuard::set("QQRM_BPF_OBJECT", &object_path);
        let err = load_bpf().expect_err("expected invalid object error");
        let message = err.to_string();
        assert!(
            message.contains("failed to load BPF object"),
            "unexpected error message: {message}"
        );
        assert!(
            message.contains(object_path.to_string_lossy().as_ref()),
            "error should mention object path: {message}"
        );
    }
}
