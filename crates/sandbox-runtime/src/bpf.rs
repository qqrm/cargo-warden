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
    use tempfile::tempdir;

    struct EnvGuard {
        original: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn set(value: &PathBuf) -> Self {
            let original = env::var_os("QQRM_BPF_OBJECT");
            unsafe { env::set_var("QQRM_BPF_OBJECT", value) };
            Self { original }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(value) = &self.original {
                unsafe { env::set_var("QQRM_BPF_OBJECT", value) };
            } else {
                unsafe { env::remove_var("QQRM_BPF_OBJECT") };
            }
        }
    }

    #[test]
    #[serial]
    fn respects_environment_override() {
        let dir = tempdir().unwrap();
        let custom = dir.path().join("custom.o");
        let _guard = EnvGuard::set(&custom);

        assert_eq!(bpf_object_path(), custom);
    }

    #[test]
    #[serial]
    fn default_path_targets_prebuilt_directory() {
        unsafe { env::remove_var("QQRM_BPF_OBJECT") };
        let path = bpf_object_path();

        let expected_suffix = PathBuf::from("prebuilt")
            .join(env::consts::ARCH)
            .join("qqrm-bpf-core.o");
        assert!(
            path.ends_with(&expected_suffix),
            "expected {} to end with {}",
            path.display(),
            expected_suffix.display()
        );
    }

    #[test]
    #[serial]
    fn load_bpf_reports_errors_with_path() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("invalid.o");
        std::fs::write(&file, b"not a valid object").unwrap();
        let _guard = EnvGuard::set(&file);

        let err = load_bpf().expect_err("loading invalid object should fail");
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert!(
            err.to_string().contains(file.to_str().unwrap()),
            "error should reference file path: {err}"
        );
    }
}
