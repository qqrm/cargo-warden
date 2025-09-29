use aya::maps::{Array, HashMap, MapData};
use aya::{Ebpf, Pod};
use bpf_api::{MODE_FLAG_ENFORCE, MODE_FLAG_OBSERVE};
use bytemuck::Pod as BytemuckPod;
use policy_core::Mode;
use qqrm_policy_compiler::MapsLayout;
use std::convert::TryFrom;
use std::io;

pub(crate) fn populate_maps(bpf: &mut Ebpf, layout: &MapsLayout) -> io::Result<()> {
    update_array(
        bpf,
        "EXEC_ALLOWLIST",
        "EXEC_ALLOWLIST_LENGTH",
        &layout.exec_allowlist,
    )?;
    update_array(bpf, "NET_RULES", "NET_RULES_LENGTH", &layout.net_rules)?;
    update_array(
        bpf,
        "NET_PARENTS",
        "NET_PARENTS_LENGTH",
        &layout.net_parents,
    )?;
    update_array(bpf, "FS_RULES", "FS_RULES_LENGTH", &layout.fs_rules)?;
    Ok(())
}

pub(crate) fn write_workload_units(bpf: &mut Ebpf, entries: &[(u32, u32)]) -> io::Result<()> {
    if entries.len() > bpf_api::WORKLOAD_UNITS_CAPACITY as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "map WORKLOAD_UNITS capacity {} exceeded by {} entries",
                bpf_api::WORKLOAD_UNITS_CAPACITY,
                entries.len()
            ),
        ));
    }

    let map_name = "WORKLOAD_UNITS";
    let map = bpf
        .map_mut(map_name)
        .ok_or_else(|| map_not_found(map_name))?;
    let mut hash = HashMap::<&mut MapData, u32, u32>::try_from(map)
        .map_err(|err| io::Error::other(format!("{map_name}: {err}")))?;
    let mut existing = Vec::new();
    {
        for next in hash.keys() {
            let key = next.map_err(|err| io::Error::other(format!("iterate {map_name}: {err}")))?;
            existing.push(key);
        }
    }
    for key in existing {
        hash.remove(&key)
            .map_err(|err| io::Error::other(format!("remove {map_name}[{key}]: {err}")))?;
    }
    for (key, value) in entries {
        hash.insert(key, value, 0)
            .map_err(|err| io::Error::other(format!("set {map_name}[{key}]: {err}")))?;
    }
    Ok(())
}

pub(crate) fn write_mode_flag(bpf: &mut Ebpf, mode: Mode) -> io::Result<()> {
    let value = match mode {
        Mode::Observe => MODE_FLAG_OBSERVE,
        Mode::Enforce => MODE_FLAG_ENFORCE,
    };
    let map_name = "MODE_FLAGS";
    let map = bpf
        .map_mut(map_name)
        .ok_or_else(|| map_not_found(map_name))?;
    let mut array = Array::<&mut MapData, u32>::try_from(map)
        .map_err(|err| io::Error::other(format!("{map_name}: {err}")))?;
    array
        .set(0, value, 0)
        .map_err(|err| io::Error::other(format!("set {map_name}[0]: {err}")))
}

fn update_array<T>(
    bpf: &mut Ebpf,
    map_name: &str,
    len_map_name: &str,
    entries: &[T],
) -> io::Result<()>
where
    T: Pod + BytemuckPod + Copy,
{
    {
        let len_map = bpf
            .map_mut(len_map_name)
            .ok_or_else(|| map_not_found(len_map_name))?;
        let mut len_array = Array::<&mut MapData, u32>::try_from(len_map)
            .map_err(|err| io::Error::other(format!("{len_map_name}: {err}")))?;
        len_array
            .set(0, 0, 0)
            .map_err(|err| io::Error::other(format!("set {len_map_name}: {err}")))?;
    }

    {
        let map = bpf
            .map_mut(map_name)
            .ok_or_else(|| map_not_found(map_name))?;
        let mut array = Array::<&mut MapData, T>::try_from(map)
            .map_err(|err| io::Error::other(format!("{map_name}: {err}")))?;
        let capacity = array.len() as usize;
        if entries.len() > capacity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "map {map_name} capacity {capacity} exceeded by {} entries",
                    entries.len()
                ),
            ));
        }
        for (idx, entry) in entries.iter().copied().enumerate() {
            array
                .set(idx as u32, entry, 0)
                .map_err(|err| io::Error::other(format!("set {map_name}[{idx}]: {err}")))?;
        }
    }

    let len = u32::try_from(entries.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("too many entries for map {map_name}"),
        )
    })?;
    {
        let len_map = bpf
            .map_mut(len_map_name)
            .ok_or_else(|| map_not_found(len_map_name))?;
        let mut len_array = Array::<&mut MapData, u32>::try_from(len_map)
            .map_err(|err| io::Error::other(format!("{len_map_name}: {err}")))?;
        len_array
            .set(0, len, 0)
            .map_err(|err| io::Error::other(format!("set {len_map_name}: {err}")))?;
    }
    Ok(())
}

fn map_not_found(name: &str) -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, format!("missing BPF map {name}"))
}
