use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

use arrayvec::ArrayVec;
use bpf_api::{
    ExecAllowEntry, FS_READ, FS_WRITE, FsRule, FsRuleEntry, MODE_FLAG_ENFORCE, MODE_FLAG_OBSERVE,
    NetParentEntry, NetRule, NetRuleEntry,
};
use bytemuck::{Pod, TransparentWrapper, Zeroable, cast_slice};
use policy_core::{ExecDefault, FsDefault, Mode, NetDefault, Policy};
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
    /// Entries for the `mode_flags` map.
    pub mode_flags: Vec<u32>,
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
            mode_flags: slice_to_bytes(&self.mode_flags),
            exec_allowlist: slice_to_bytes(ExecAllowEntryPod::wrap_slice(&self.exec_allowlist)),
            net_rules: slice_to_bytes(NetRuleEntryPod::wrap_slice(&self.net_rules)),
            net_parents: slice_to_bytes(NetParentEntryPod::wrap_slice(&self.net_parents)),
            fs_rules: slice_to_bytes(FsRuleEntryPod::wrap_slice(&self.fs_rules)),
        }
    }
}

/// Raw byte buffers for each BPF map.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MapsBinary {
    pub mode_flags: Vec<u8>,
    pub exec_allowlist: Vec<u8>,
    pub net_rules: Vec<u8>,
    pub net_parents: Vec<u8>,
    pub fs_rules: Vec<u8>,
}

/// Compiled representation of a [`Policy`].
#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    /// Serialized entries ready for BPF maps.
    pub maps_layout: MapsLayout,
    /// Names of environment variables allowed for reads.
    pub allowed_env_vars: Vec<String>,
}

/// Compile a [`Policy`] into serialized BPF map entries and metadata.
pub fn compile(policy: &Policy) -> Result<CompiledPolicy, CompileError> {
    let maps_layout = MapsLayout {
        mode_flags: vec![mode_flag(policy.mode)],
        exec_allowlist: compile_exec_allowlist(policy)?,
        net_rules: compile_net_rules(policy)?,
        net_parents: Vec::new(),
        fs_rules: compile_fs_rules(policy)?,
    };

    let mut allowed_env_vars: Vec<String> = policy.env_read_vars().cloned().collect();
    allowed_env_vars.sort();
    allowed_env_vars.dedup();

    Ok(CompiledPolicy {
        maps_layout,
        allowed_env_vars,
    })
}

fn mode_flag(mode: Mode) -> u32 {
    match mode {
        Mode::Observe => MODE_FLAG_OBSERVE,
        Mode::Enforce => MODE_FLAG_ENFORCE,
    }
}

fn compile_exec_allowlist(policy: &Policy) -> Result<Vec<ExecAllowEntry>, CompileError> {
    if policy.exec_default() != ExecDefault::Allowlist {
        return Ok(Vec::new());
    }
    policy
        .exec_allowed()
        .map(|path| encode_exec_path(path).map(|encoded| ExecAllowEntry { path: encoded }))
        .collect()
}

fn compile_net_rules(policy: &Policy) -> Result<Vec<NetRuleEntry>, CompileError> {
    if policy.net_default() != NetDefault::Deny {
        return Ok(Vec::new());
    }
    policy
        .net_hosts()
        .map(|host| parse_host_entry(host))
        .collect()
}

fn compile_fs_rules(policy: &Policy) -> Result<Vec<FsRuleEntry>, CompileError> {
    if policy.fs_default() != FsDefault::Strict {
        return Ok(Vec::new());
    }
    policy
        .fs_write_paths()
        .map(|path| fs_rule_entry(path.as_path(), FS_READ | FS_WRITE))
        .chain(
            policy
                .fs_read_paths()
                .map(|path| fs_rule_entry(path.as_path(), FS_READ)),
        )
        .collect()
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
    build_path_vec(path)
        .map(into_padded_array)
        .ok_or_else(|| CompileError::ExecPathTooLong { path: path.into() })
}

fn encode_fs_path(path: &str) -> Result<[u8; 256], CompileError> {
    build_path_vec(path)
        .map(into_padded_array)
        .ok_or_else(|| CompileError::FsPathTooLong { path: path.into() })
}

fn build_path_vec(path: &str) -> Option<ArrayVec<u8, 256>> {
    let bytes = path.as_bytes();
    if bytes.len() > MAX_PATH_BYTES {
        return None;
    }
    let mut buf = ArrayVec::<u8, 256>::new();
    buf.try_extend_from_slice(bytes).expect("capacity checked");
    Some(buf)
}

fn into_padded_array(buf: ArrayVec<u8, 256>) -> [u8; 256] {
    let mut array = [0u8; 256];
    let len = buf.len();
    array[..len].copy_from_slice(buf.as_slice());
    array
}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct ExecAllowEntryPod(ExecAllowEntry);

unsafe impl Zeroable for ExecAllowEntryPod {}
unsafe impl Pod for ExecAllowEntryPod {}
unsafe impl TransparentWrapper<ExecAllowEntry> for ExecAllowEntryPod {}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct NetRuleEntryPod(NetRuleEntry);

unsafe impl Zeroable for NetRuleEntryPod {}
unsafe impl Pod for NetRuleEntryPod {}
unsafe impl TransparentWrapper<NetRuleEntry> for NetRuleEntryPod {}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct NetParentEntryPod(NetParentEntry);

unsafe impl Zeroable for NetParentEntryPod {}
unsafe impl Pod for NetParentEntryPod {}
unsafe impl TransparentWrapper<NetParentEntry> for NetParentEntryPod {}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct FsRuleEntryPod(FsRuleEntry);

unsafe impl Zeroable for FsRuleEntryPod {}
unsafe impl Pod for FsRuleEntryPod {}
unsafe impl TransparentWrapper<FsRuleEntry> for FsRuleEntryPod {}

fn slice_to_bytes<T: Pod>(slice: &[T]) -> Vec<u8> {
    cast_slice(slice).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        mem::size_of,
        path::{Path, PathBuf},
    };

    fn to_string(bytes: &[u8]) -> String {
        let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        String::from_utf8(bytes[..len].to_vec()).unwrap()
    }

    fn workspace_root_path() -> PathBuf {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace = manifest.ancestors().nth(2).expect("workspace root");
        std::fs::canonicalize(workspace).unwrap_or_else(|_| workspace.to_path_buf())
    }

    fn workspace_root_string() -> String {
        workspace_root_path().to_string_lossy().into_owned()
    }

    fn target_dir_string() -> String {
        let target = workspace_root_path().join("target");
        std::fs::canonicalize(&target)
            .unwrap_or(target)
            .to_string_lossy()
            .into_owned()
    }

    fn ensure_default_fs_paths(policy: &mut Policy) {
        let workspace = workspace_root_path();
        if !policy.fs_read_paths().any(|path| path == &workspace) {
            policy.extend_fs_reads(std::iter::once(workspace));
        }
        let target = workspace_root_path().join("target");
        let target = std::fs::canonicalize(&target).unwrap_or(target);
        if !policy.fs_write_paths().any(|path| path == &target) {
            policy.extend_fs_writes(std::iter::once(target));
        }
    }

    #[test]
    fn compiles_policy_into_layout() {
        let mut policy = Policy::with_defaults(
            policy_core::Mode::Enforce,
            FsDefault::Strict,
            NetDefault::Deny,
            ExecDefault::Allowlist,
        );
        policy.extend_exec_allowed(vec!["/usr/bin/rustc".into(), "/bin/bash".into()]);
        policy.extend_net_hosts(vec!["127.0.0.1:8080".into()]);
        policy.extend_fs_writes(vec![PathBuf::from("/tmp/logs")]);
        policy.extend_fs_reads(vec![PathBuf::from("/etc/ssl/certs")]);
        policy.extend_env_read_vars(vec!["PATH".into(), "HOME".into(), "HOME".into()]);
        ensure_default_fs_paths(&mut policy);

        let CompiledPolicy {
            maps_layout: layout,
            allowed_env_vars,
        } = compile(&policy).expect("compile");

        assert_eq!(
            allowed_env_vars,
            vec!["HOME".to_string(), "PATH".to_string()]
        );

        assert_eq!(layout.mode_flags, vec![MODE_FLAG_ENFORCE]);
        assert_eq!(layout.exec_allowlist.len(), 2);
        let exec_paths: Vec<_> = layout
            .exec_allowlist
            .iter()
            .map(|entry| to_string(&entry.path))
            .collect();
        assert_eq!(exec_paths, vec!["/bin/bash", "/usr/bin/rustc"]);

        assert_eq!(layout.net_rules.len(), 1);
        let net_rule = &layout.net_rules[0];
        assert_eq!(net_rule.unit, 0);
        assert_eq!(net_rule.rule.port, 8080);
        assert_eq!(net_rule.rule.protocol, TCP_PROTOCOL);
        assert_eq!(net_rule.rule.prefix_len, 32);
        assert_eq!(&net_rule.rule.addr[..4], &[127, 0, 0, 1]);
        assert!(layout.net_parents.is_empty());

        assert_eq!(layout.fs_rules.len(), 4);
        let expected_target = target_dir_string();
        let expected_workspace = workspace_root_string();
        let mut fs_entries: Vec<_> = layout
            .fs_rules
            .iter()
            .map(|entry| (entry.unit, entry.rule.access, to_string(&entry.rule.path)))
            .collect();
        fs_entries.sort();
        let mut expected_fs_entries = vec![
            (0, FS_READ | FS_WRITE, "/tmp/logs".to_string()),
            (0, FS_READ | FS_WRITE, expected_target),
            (0, FS_READ, "/etc/ssl/certs".to_string()),
            (0, FS_READ, expected_workspace),
        ];
        expected_fs_entries.sort();
        assert_eq!(fs_entries, expected_fs_entries);
    }

    #[test]
    fn binary_serialization_matches_layout() {
        let mut policy = Policy::with_defaults(
            policy_core::Mode::Enforce,
            FsDefault::Strict,
            NetDefault::Deny,
            ExecDefault::Allowlist,
        );
        policy.extend_exec_allowed(vec!["/usr/bin/rustc".into()]);
        policy.extend_net_hosts(vec!["127.0.0.1:8080".into()]);
        policy.extend_fs_writes(vec![PathBuf::from("/tmp/logs")]);
        ensure_default_fs_paths(&mut policy);

        let CompiledPolicy {
            maps_layout: layout,
            allowed_env_vars,
        } = compile(&policy).expect("compile");
        assert!(allowed_env_vars.is_empty());
        let binary = layout.to_binary();

        assert_eq!(binary.mode_flags.len(), size_of::<u32>());
        let mut mode_bytes = [0u8; size_of::<u32>()];
        mode_bytes.copy_from_slice(&binary.mode_flags);
        assert_eq!(u32::from_ne_bytes(mode_bytes), MODE_FLAG_ENFORCE);
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

    #[test]
    fn observe_mode_sets_flag() {
        let policy = Policy::new(policy_core::Mode::Observe);

        let layout = compile(&policy).expect("compile").maps_layout;
        assert_eq!(layout.mode_flags, vec![MODE_FLAG_OBSERVE]);
    }
}
