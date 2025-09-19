use bpf_api::{FS_READ, FS_WRITE, FsRuleEntry, NetParentEntry, NetRuleEntry};
use policy_core::Mode;
use qqrm_policy_compiler::MapsLayout;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

pub(crate) const FAKE_LAYOUT_ENV: &str = "QQRM_WARDEN_FAKE_LAYOUT_PATH";

pub(crate) struct LayoutRecorder {
    writer: BufWriter<File>,
}

impl LayoutRecorder {
    pub(crate) fn from_env() -> io::Result<Option<Self>> {
        let Some(path) = env::var_os(FAKE_LAYOUT_ENV) else {
            return Ok(None);
        };
        let path = PathBuf::from(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Some(Self {
            writer: BufWriter::new(file),
        }))
    }

    pub(crate) fn record(&mut self, layout: &MapsLayout, mode: Mode) -> io::Result<()> {
        let snapshot = LayoutSnapshot::from_layout(layout, mode);
        serde_json::to_writer(&mut self.writer, &snapshot).map_err(io::Error::other)?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()
    }
}

/// Snapshot of the policy layout emitted by the fake sandbox.
#[derive(Debug, Serialize, Deserialize)]
pub struct LayoutSnapshot {
    pub mode: String,
    pub mode_flag: Option<u32>,
    pub exec: Vec<String>,
    pub net: Vec<NetRuleSnapshot>,
    pub net_parents: Vec<NetParentSnapshot>,
    pub fs: Vec<FsRuleSnapshot>,
}

/// Snapshot of a network rule for fake recording consumers.
#[derive(Debug, Serialize, Deserialize)]
pub struct NetRuleSnapshot {
    pub unit: u32,
    pub protocol: u8,
    pub prefix_len: u8,
    pub port: u16,
    pub addr: String,
}

/// Snapshot of a network rule parent relationship.
#[derive(Debug, Serialize, Deserialize)]
pub struct NetParentSnapshot {
    pub child: u32,
    pub parent: u32,
}

/// Snapshot of a filesystem rule in the fake sandbox mode.
#[derive(Debug, Serialize, Deserialize)]
pub struct FsRuleSnapshot {
    pub unit: u32,
    pub path: String,
    pub read: bool,
    pub write: bool,
}

impl LayoutSnapshot {
    pub(crate) fn from_layout(layout: &MapsLayout, mode: Mode) -> Self {
        Self {
            mode: mode_to_string(mode),
            mode_flag: layout.mode_flags.first().copied(),
            exec: layout
                .exec_allowlist
                .iter()
                .map(|entry| decode_path(&entry.path))
                .collect(),
            net: layout.net_rules.iter().map(NetRuleSnapshot::from).collect(),
            net_parents: layout
                .net_parents
                .iter()
                .map(NetParentSnapshot::from)
                .collect(),
            fs: layout.fs_rules.iter().map(FsRuleSnapshot::from).collect(),
        }
    }
}

impl From<&NetRuleEntry> for NetRuleSnapshot {
    fn from(entry: &NetRuleEntry) -> Self {
        Self {
            unit: entry.unit,
            protocol: entry.rule.protocol,
            prefix_len: entry.rule.prefix_len,
            port: entry.rule.port,
            addr: decode_net_addr(entry),
        }
    }
}

impl From<&NetParentEntry> for NetParentSnapshot {
    fn from(entry: &NetParentEntry) -> Self {
        Self {
            child: entry.child,
            parent: entry.parent,
        }
    }
}

impl From<&FsRuleEntry> for FsRuleSnapshot {
    fn from(entry: &FsRuleEntry) -> Self {
        let access = entry.rule.access;
        Self {
            unit: entry.unit,
            path: decode_path(&entry.rule.path),
            read: access & FS_READ != 0,
            write: access & FS_WRITE != 0,
        }
    }
}

fn decode_path(bytes: &[u8]) -> String {
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).to_string()
}

fn decode_net_addr(entry: &NetRuleEntry) -> String {
    if entry.rule.prefix_len <= 32 {
        Ipv4Addr::new(
            entry.rule.addr[0],
            entry.rule.addr[1],
            entry.rule.addr[2],
            entry.rule.addr[3],
        )
        .to_string()
    } else {
        Ipv6Addr::from(entry.rule.addr).to_string()
    }
}

fn mode_to_string(mode: Mode) -> String {
    match mode {
        Mode::Observe => "observe",
        Mode::Enforce => "enforce",
    }
    .to_string()
}
