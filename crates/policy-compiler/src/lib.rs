use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

use bpf_api::{
    ExecAllowEntry, FS_READ, FS_WRITE, FsRule, FsRuleEntry, NetParentEntry, NetRule, NetRuleEntry,
};
use policy_core::{ExecDefault, FsDefault, NetDefault, Policy};
use thiserror::Error;

const TCP_PROTOCOL: u8 = 6;
const MAX_PATH_BYTES: usize = 255;

/// Errors that can occur while compiling a [`Policy`].
#[derive(Debug, Error)]
pub enum CompileError {
    /// Executable path is longer than supported.
    #[error("executable path '{path}' exceeds {MAX_PATH_BYTES} bytes")]
    ExecPathTooLong { path: String },
    /// Filesystem path is longer than supported.
    #[error("filesystem path '{path}' exceeds {MAX_PATH_BYTES} bytes")]
    FsPathTooLong { path: String },
    /// Filesystem path is not valid UTF-8.
    #[error("filesystem path contains non-UTF-8 data: {path:?}")]
    FsPathInvalidUtf8 { path: PathBuf },
    /// Network host entry is malformed.
    #[error("invalid network host entry '{host}'")]
    InvalidNetHost { host: String },
}

/// Serialized representation of policy data for BPF maps.
#[derive(Debug, Clone)]
pub struct MapsLayout {
    /// Entries for the `exec_allowlist` map.
    pub exec_allowlist: Vec<ExecAllowEntry>,
    /// Entries for the `net_rules` map.
    pub net_rules: Vec<NetRuleEntry>,
    /// Entries for the `net_parents` map.
    pub net_parents: Vec<NetParentEntry>,
    /// Entries for the `fs_rules` map.
    pub fs_rules: Vec<FsRuleEntry>,
}

impl MapsLayout {
    /// Convert the layout into raw byte buffers for each map.
    pub fn to_binary(&self) -> MapsBinary {
        MapsBinary {
            exec_allowlist: slice_to_bytes(&self.exec_allowlist),
            net_rules: slice_to_bytes(&self.net_rules),
            net_parents: slice_to_bytes(&self.net_parents),
            fs_rules: slice_to_bytes(&self.fs_rules),
        }
    }
}

/// Raw byte buffers for each BPF map.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MapsBinary {
    pub exec_allowlist: Vec<u8>,
    pub net_rules: Vec<u8>,
    pub net_parents: Vec<u8>,
    pub fs_rules: Vec<u8>,
}

/// Compile a [`Policy`] into serialized BPF map entries.
pub fn compile(policy: &Policy) -> Result<MapsLayout, CompileError> {
    Ok(MapsLayout {
        exec_allowlist: compile_exec_allowlist(policy)?,
        net_rules: compile_net_rules(policy)?,
        net_parents: Vec::new(),
        fs_rules: compile_fs_rules(policy)?,
    })
}

fn compile_exec_allowlist(policy: &Policy) -> Result<Vec<ExecAllowEntry>, CompileError> {
    if policy.exec.default != ExecDefault::Allowlist {
        return Ok(Vec::new());
    }
    policy
        .allow
        .exec
        .allowed
        .iter()
        .map(|path| encode_exec_path(path).map(|encoded| ExecAllowEntry { path: encoded }))
        .collect()
}

fn compile_net_rules(policy: &Policy) -> Result<Vec<NetRuleEntry>, CompileError> {
    if policy.net.default != NetDefault::Deny {
        return Ok(Vec::new());
    }
    policy
        .allow
        .net
        .hosts
        .iter()
        .map(|host| parse_host_entry(host))
        .collect()
}

fn compile_fs_rules(policy: &Policy) -> Result<Vec<FsRuleEntry>, CompileError> {
    if policy.fs.default != FsDefault::Strict {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    for path in &policy.allow.fs.write_extra {
        entries.push(fs_rule_entry(path, FS_READ | FS_WRITE)?);
    }
    for path in &policy.allow.fs.read_extra {
        entries.push(fs_rule_entry(path, FS_READ)?);
    }
    Ok(entries)
}

fn fs_rule_entry(path: &Path, access: u8) -> Result<FsRuleEntry, CompileError> {
    let path = path
        .to_str()
        .ok_or_else(|| CompileError::FsPathInvalidUtf8 {
            path: path.to_path_buf(),
        })?;
    let encoded = encode_fs_path(path)?;
    Ok(FsRuleEntry {
        unit: 0,
        rule: FsRule {
            access,
            reserved: [0; 3],
            path: encoded,
        },
    })
}

fn parse_host_entry(host: &str) -> Result<NetRuleEntry, CompileError> {
    let socket: SocketAddr = host
        .parse()
        .map_err(|_| CompileError::InvalidNetHost { host: host.into() })?;
    let mut addr = [0u8; 16];
    let prefix_len = match socket {
        SocketAddr::V4(v4) => {
            addr[..4].copy_from_slice(&v4.ip().octets());
            32
        }
        SocketAddr::V6(v6) => {
            addr.copy_from_slice(&v6.ip().octets());
            128
        }
    };
    Ok(NetRuleEntry {
        unit: 0,
        rule: NetRule {
            addr,
            protocol: TCP_PROTOCOL,
            prefix_len,
            port: socket.port(),
        },
    })
}

fn encode_exec_path(path: &str) -> Result<[u8; 256], CompileError> {
    fill_path_bytes(path).ok_or_else(|| CompileError::ExecPathTooLong { path: path.into() })
}

fn encode_fs_path(path: &str) -> Result<[u8; 256], CompileError> {
    fill_path_bytes(path).ok_or_else(|| CompileError::FsPathTooLong { path: path.into() })
}

fn fill_path_bytes(path: &str) -> Option<[u8; 256]> {
    let bytes = path.as_bytes();
    if bytes.len() > MAX_PATH_BYTES {
        return None;
    }
    let mut buf = [0u8; 256];
    buf[..bytes.len()].copy_from_slice(bytes);
    Some(buf)
}

fn slice_to_bytes<T: Copy>(slice: &[T]) -> Vec<u8> {
    let len = core::mem::size_of_val(slice);
    unsafe { core::slice::from_raw_parts(slice.as_ptr() as *const u8, len).to_vec() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    fn to_string(bytes: &[u8]) -> String {
        let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        String::from_utf8(bytes[..len].to_vec()).unwrap()
    }

    #[test]
    fn compiles_policy_into_layout() {
        let policy = Policy {
            mode: policy_core::Mode::Enforce,
            fs: policy_core::FsPolicy {
                default: FsDefault::Strict,
            },
            net: policy_core::NetPolicy {
                default: NetDefault::Deny,
            },
            exec: policy_core::ExecPolicy {
                default: ExecDefault::Allowlist,
            },
            syscall: policy_core::SyscallPolicy { deny: vec![] },
            allow: policy_core::AllowSection {
                exec: policy_core::ExecAllow {
                    allowed: vec!["/usr/bin/rustc".into(), "/bin/bash".into()],
                },
                net: policy_core::NetAllow {
                    hosts: vec!["127.0.0.1:8080".into()],
                },
                fs: policy_core::FsAllow {
                    write_extra: vec![PathBuf::from("/tmp/logs")],
                    read_extra: vec![PathBuf::from("/etc/ssl/certs")],
                },
            },
        };

        let layout = compile(&policy).expect("compile");

        assert_eq!(layout.exec_allowlist.len(), 2);
        assert_eq!(to_string(&layout.exec_allowlist[0].path), "/usr/bin/rustc");
        assert_eq!(to_string(&layout.exec_allowlist[1].path), "/bin/bash");

        assert_eq!(layout.net_rules.len(), 1);
        let net_rule = &layout.net_rules[0];
        assert_eq!(net_rule.unit, 0);
        assert_eq!(net_rule.rule.port, 8080);
        assert_eq!(net_rule.rule.protocol, TCP_PROTOCOL);
        assert_eq!(net_rule.rule.prefix_len, 32);
        assert_eq!(&net_rule.rule.addr[..4], &[127, 0, 0, 1]);
        assert!(layout.net_parents.is_empty());

        assert_eq!(layout.fs_rules.len(), 2);
        let write_rule = &layout.fs_rules[0];
        assert_eq!(write_rule.unit, 0);
        assert_eq!(write_rule.rule.access, FS_READ | FS_WRITE);
        assert_eq!(to_string(&write_rule.rule.path), "/tmp/logs");
        let read_rule = &layout.fs_rules[1];
        assert_eq!(read_rule.rule.access, FS_READ);
        assert_eq!(to_string(&read_rule.rule.path), "/etc/ssl/certs");
    }

    #[test]
    fn binary_serialization_matches_layout() {
        let policy = Policy {
            mode: policy_core::Mode::Enforce,
            fs: policy_core::FsPolicy {
                default: FsDefault::Strict,
            },
            net: policy_core::NetPolicy {
                default: NetDefault::Deny,
            },
            exec: policy_core::ExecPolicy {
                default: ExecDefault::Allowlist,
            },
            syscall: policy_core::SyscallPolicy { deny: vec![] },
            allow: policy_core::AllowSection {
                exec: policy_core::ExecAllow {
                    allowed: vec!["/usr/bin/rustc".into()],
                },
                net: policy_core::NetAllow {
                    hosts: vec!["127.0.0.1:8080".into()],
                },
                fs: policy_core::FsAllow {
                    write_extra: vec![PathBuf::from("/tmp/logs")],
                    read_extra: vec![],
                },
            },
        };

        let layout = compile(&policy).expect("compile");
        let binary = layout.to_binary();

        assert_eq!(
            binary.exec_allowlist.len(),
            layout.exec_allowlist.len() * size_of::<ExecAllowEntry>()
        );
        assert_eq!(
            binary.net_rules.len(),
            layout.net_rules.len() * size_of::<NetRuleEntry>()
        );
        assert_eq!(
            binary.net_parents.len(),
            layout.net_parents.len() * size_of::<NetParentEntry>()
        );
        assert_eq!(
            binary.fs_rules.len(),
            layout.fs_rules.len() * size_of::<FsRuleEntry>()
        );
        assert!(binary.exec_allowlist.starts_with(b"/usr/bin/rustc"));
    }
}
