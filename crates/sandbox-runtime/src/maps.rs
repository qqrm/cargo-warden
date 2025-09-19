use aya::maps::{Array, MapData};
use aya::{Ebpf, Pod};
use bpf_api::{
    ExecAllowEntry, FsRuleEntry, MODE_FLAG_ENFORCE, MODE_FLAG_OBSERVE, NetParentEntry, NetRuleEntry,
};
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
        |entry| ExecAllowEntryPod(*entry),
    )?;
    update_array(
        bpf,
        "NET_RULES",
        "NET_RULES_LENGTH",
        &layout.net_rules,
        |entry| NetRuleEntryPod(*entry),
    )?;
    update_array(
        bpf,
        "NET_PARENTS",
        "NET_PARENTS_LENGTH",
        &layout.net_parents,
        |entry| NetParentEntryPod(*entry),
    )?;
    update_array(
        bpf,
        "FS_RULES",
        "FS_RULES_LENGTH",
        &layout.fs_rules,
        |entry| FsRuleEntryPod(*entry),
    )?;
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

fn update_array<T, P, F>(
    bpf: &mut Ebpf,
    map_name: &str,
    len_map_name: &str,
    entries: &[T],
    convert: F,
) -> io::Result<()>
where
    P: Pod,
    F: Fn(&T) -> P,
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
        let mut array = Array::<&mut MapData, P>::try_from(map)
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
        for (idx, entry) in entries.iter().enumerate() {
            array
                .set(idx as u32, convert(entry), 0)
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

#[repr(transparent)]
#[derive(Clone, Copy)]
struct ExecAllowEntryPod(ExecAllowEntry);

unsafe impl Pod for ExecAllowEntryPod {}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct NetRuleEntryPod(NetRuleEntry);

unsafe impl Pod for NetRuleEntryPod {}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct NetParentEntryPod(NetParentEntry);

unsafe impl Pod for NetParentEntryPod {}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct FsRuleEntryPod(FsRuleEntry);

unsafe impl Pod for FsRuleEntryPod {}
