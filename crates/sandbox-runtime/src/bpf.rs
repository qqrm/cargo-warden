use aya::maps::{MapData, ring_buf::RingBuf};
use aya::{Ebpf, EbpfLoader};
use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;

const BPF_OBJECT_ENV: &str = "QQRM_BPF_OBJECT";

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
    if let Some(path) = env::var_os(BPF_OBJECT_ENV) {
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
    use std::ffi::{OsStr, OsString};
    use tempfile::tempdir;

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

        fn unset(key: &str) -> Self {
            let original = env::var_os(key);
            unsafe { env::remove_var(key) };
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
    fn load_bpf_reports_path_on_failure() {
        let dir = tempdir().expect("tempdir");
        let object_path = dir.path().join("fake.o");
        fs::write(&object_path, b"not a bpf object").expect("write fake object");
        let _guard = EnvGuard::set(BPF_OBJECT_ENV, &object_path);

        let err = load_bpf().expect_err("expected load failure");
        assert_eq!(err.kind(), io::ErrorKind::Other);
        let message = err.to_string();
        assert!(
            message.contains(object_path.to_str().expect("path utf8")),
            "error should mention object path: {message}"
        );
    }

    #[test]
    #[serial]
    fn bpf_object_path_defaults_to_prebuilt_location() {
        let _guard = EnvGuard::unset(BPF_OBJECT_ENV);
        let path = bpf_object_path();
        let expected_suffix = format!("prebuilt/{}/qqrm-bpf-core.o", env::consts::ARCH);
        let as_str = path.to_string_lossy();
        assert!(
            as_str.ends_with(&expected_suffix),
            "expected path to end with {expected_suffix}, got {as_str}"
        );
    }
}
