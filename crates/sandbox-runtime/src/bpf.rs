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
