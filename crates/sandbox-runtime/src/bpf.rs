use aya::maps::{MapData, ring_buf::RingBuf};
use aya::{Ebpf, EbpfLoader};
use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;

use warden_bpf_host::prebuilt::PrebuiltObject;

pub(crate) fn load_bpf() -> io::Result<Ebpf> {
    let (data, path) = if let Some(path) = env::var_os("WARDEN_BPF_OBJECT") {
        let path = PathBuf::from(path);
        let data = fs::read(&path)?;
        (data, path)
    } else {
        let object = PrebuiltObject::locate_default()?;
        let path = object.path();
        let data = object.into_bytes()?;
        (data, path)
    };

    EbpfLoader::new().load(&data).map_err(|err| {
        io::Error::other(format!(
            "failed to load BPF object {}: {err}",
            path.display()
        ))
    })
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
