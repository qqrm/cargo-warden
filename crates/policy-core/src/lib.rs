use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    path::PathBuf,
};

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Observe,
    Enforce,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum FsDefault {
    Strict,
    Unrestricted,
}

impl Default for FsDefault {
    fn default() -> Self {
        Self::Strict
    }
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum NetDefault {
    Deny,
    Allow,
}

impl Default for NetDefault {
    fn default() -> Self {
        Self::Deny
    }
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum ExecDefault {
    Allowlist,
    Allow,
}

impl Default for ExecDefault {
    fn default() -> Self {
        Self::Allowlist
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Permission {
    FsDefault(FsDefault),
    FsRead(PathBuf),
    FsWrite(PathBuf),
    NetDefault(NetDefault),
    NetConnect(String),
    ExecDefault(ExecDefault),
    Exec(String),
    SyscallDeny(String),
    EnvRead(String),
}

#[derive(Debug, Clone)]
pub struct Policy {
    pub mode: Mode,
    pub rules: Vec<Permission>,
}

impl Policy {
    pub fn from_toml_str(toml_str: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(toml_str)
    }

    pub fn rules(&self) -> &[Permission] {
        &self.rules
    }

    pub fn fs_default(&self) -> FsDefault {
        self.rules
            .iter()
            .rev()
            .find_map(|perm| match perm {
                Permission::FsDefault(default) => Some(*default),
                _ => None,
            })
            .unwrap_or_default()
    }

    pub fn net_default(&self) -> NetDefault {
        self.rules
            .iter()
            .rev()
            .find_map(|perm| match perm {
                Permission::NetDefault(default) => Some(*default),
                _ => None,
            })
            .unwrap_or_default()
    }

    pub fn exec_default(&self) -> ExecDefault {
        self.rules
            .iter()
            .rev()
            .find_map(|perm| match perm {
                Permission::ExecDefault(default) => Some(*default),
                _ => None,
            })
            .unwrap_or_default()
    }

    pub fn fs_read_paths(&self) -> impl Iterator<Item = &PathBuf> {
        self.rules.iter().filter_map(|perm| match perm {
            Permission::FsRead(path) => Some(path),
            _ => None,
        })
    }

    pub fn fs_write_paths(&self) -> impl Iterator<Item = &PathBuf> {
        self.rules.iter().filter_map(|perm| match perm {
            Permission::FsWrite(path) => Some(path),
            _ => None,
        })
    }

    pub fn exec_allowed(&self) -> impl Iterator<Item = &String> {
        self.rules.iter().filter_map(|perm| match perm {
            Permission::Exec(path) => Some(path),
            _ => None,
        })
    }

    pub fn net_hosts(&self) -> impl Iterator<Item = &String> {
        self.rules.iter().filter_map(|perm| match perm {
            Permission::NetConnect(host) => Some(host),
            _ => None,
        })
    }

    pub fn syscall_deny(&self) -> impl Iterator<Item = &String> {
        self.rules.iter().filter_map(|perm| match perm {
            Permission::SyscallDeny(name) => Some(name),
            _ => None,
        })
    }

    pub fn env_read_vars(&self) -> impl Iterator<Item = &String> {
        self.rules.iter().filter_map(|perm| match perm {
            Permission::EnvRead(name) => Some(name),
            _ => None,
        })
    }

    pub fn validate(&self) -> ValidationReport {
        use ValidationError::*;
        use ValidationWarning::*;

        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        let exec_allowed: Vec<String> = self.exec_allowed().cloned().collect();
        if let Some(dup) = find_first_duplicate(&exec_allowed) {
            errors.push(DuplicateExec(dup));
        }

        let net_hosts: Vec<String> = self.net_hosts().cloned().collect();
        if let Some(dup) = find_first_duplicate(&net_hosts) {
            errors.push(DuplicateNet(dup));
        }

        let fs_writes: Vec<PathBuf> = self.fs_write_paths().cloned().collect();
        if let Some(dup) = find_first_duplicate(&fs_writes) {
            errors.push(DuplicateFsWrite(dup.to_string_lossy().into()));
        }

        let fs_reads: Vec<PathBuf> = self.fs_read_paths().cloned().collect();
        if let Some(dup) = find_first_duplicate(&fs_reads) {
            errors.push(DuplicateFsRead(dup.to_string_lossy().into()));
        }

        let syscalls: Vec<String> = self.syscall_deny().cloned().collect();
        if let Some(dup) = find_first_duplicate(&syscalls) {
            errors.push(DuplicateSyscall(dup));
        }

        let read_set: HashSet<_> = fs_reads.iter().cloned().collect();
        for w in &fs_writes {
            if read_set.contains(w) {
                errors.push(FsReadWriteConflict(w.to_string_lossy().into()));
            }
        }

        if self.exec_default() == ExecDefault::Allow && !exec_allowed.is_empty() {
            warnings.push(UnusedExecAllow);
        }

        if self.net_default() == NetDefault::Allow && !net_hosts.is_empty() {
            warnings.push(UnusedNetAllow);
        }

        if self.fs_default() == FsDefault::Unrestricted
            && (!fs_reads.is_empty() || !fs_writes.is_empty())
        {
            warnings.push(UnusedFsAllow);
        }

        ValidationReport { errors, warnings }
    }
}

impl<'de> Deserialize<'de> for Policy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let raw = RawPolicy::deserialize(deserializer)?;
        Ok(raw.into())
    }
}

#[derive(Debug, Deserialize, Clone)]
struct RawPolicy {
    mode: Mode,
    #[serde(default)]
    fs: RawFsPolicy,
    #[serde(default)]
    net: RawNetPolicy,
    #[serde(default)]
    exec: RawExecPolicy,
    #[serde(default)]
    syscall: RawSyscallPolicy,
    #[serde(default)]
    allow: RawAllowSection,
}

impl From<RawPolicy> for Policy {
    fn from(raw: RawPolicy) -> Self {
        let RawPolicy {
            mode,
            fs,
            net,
            exec,
            syscall,
            allow,
        } = raw;

        let mut rules = Vec::new();
        rules.push(Permission::FsDefault(fs.default));
        rules.push(Permission::NetDefault(net.default));
        rules.push(Permission::ExecDefault(exec.default));
        rules.extend(allow.fs.read_extra.into_iter().map(Permission::FsRead));
        rules.extend(allow.fs.write_extra.into_iter().map(Permission::FsWrite));
        rules.extend(allow.net.hosts.into_iter().map(Permission::NetConnect));
        rules.extend(allow.exec.allowed.into_iter().map(Permission::Exec));
        rules.extend(allow.env.read.into_iter().map(Permission::EnvRead));
        rules.extend(syscall.deny.into_iter().map(Permission::SyscallDeny));

        Policy { mode, rules }
    }
}

impl RawPolicy {
    fn apply_override(&mut self, override_policy: &RawPolicyOverride) {
        if let Some(fs) = &override_policy.fs {
            self.fs = fs.clone();
        }
        if let Some(net) = &override_policy.net {
            self.net = net.clone();
        }
        if let Some(exec) = &override_policy.exec {
            self.exec = exec.clone();
        }
        if let Some(syscall) = &override_policy.syscall {
            self.syscall = syscall.clone();
        }
        if let Some(allow) = &override_policy.allow {
            self.allow = allow.clone();
        }
    }
}

#[derive(Debug, Deserialize, Clone, Default)]
struct RawFsPolicy {
    #[serde(default)]
    default: FsDefault,
}

#[derive(Debug, Deserialize, Clone, Default)]
struct RawNetPolicy {
    #[serde(default)]
    default: NetDefault,
}

#[derive(Debug, Deserialize, Clone, Default)]
struct RawExecPolicy {
    #[serde(default)]
    default: ExecDefault,
}

#[derive(Debug, Deserialize, Clone, Default)]
struct RawSyscallPolicy {
    #[serde(default)]
    deny: Vec<String>,
}

#[derive(Debug, Deserialize, Clone, Default)]
struct RawAllowSection {
    #[serde(default)]
    exec: RawExecAllow,
    #[serde(default)]
    net: RawNetAllow,
    #[serde(default)]
    fs: RawFsAllow,
    #[serde(default)]
    env: RawEnvAllow,
}

#[derive(Debug, Deserialize, Clone, Default)]
struct RawExecAllow {
    #[serde(default)]
    allowed: Vec<String>,
}

#[derive(Debug, Deserialize, Clone, Default)]
struct RawNetAllow {
    #[serde(default)]
    hosts: Vec<String>,
}

#[derive(Debug, Deserialize, Clone, Default)]
struct RawFsAllow {
    #[serde(default)]
    write_extra: Vec<PathBuf>,
    #[serde(default)]
    read_extra: Vec<PathBuf>,
}

#[derive(Debug, Deserialize, Clone, Default)]
struct RawEnvAllow {
    #[serde(default)]
    read: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PolicyOverride {
    raw: RawPolicyOverride,
}

impl PolicyOverride {
    fn raw(&self) -> &RawPolicyOverride {
        &self.raw
    }
}

impl Default for PolicyOverride {
    fn default() -> Self {
        Self {
            raw: RawPolicyOverride::default(),
        }
    }
}

impl From<RawPolicyOverride> for PolicyOverride {
    fn from(raw: RawPolicyOverride) -> Self {
        Self { raw }
    }
}

#[derive(Debug, Deserialize, Clone, Default)]
struct RawPolicyOverride {
    fs: Option<RawFsPolicy>,
    net: Option<RawNetPolicy>,
    exec: Option<RawExecPolicy>,
    syscall: Option<RawSyscallPolicy>,
    allow: Option<RawAllowSection>,
}

#[derive(Debug, Clone)]
pub struct WorkspacePolicy {
    raw_root: RawPolicy,
    pub root: Policy,
    pub members: HashMap<String, PolicyOverride>,
}

impl WorkspacePolicy {
    pub fn policy_for(&self, member: &str) -> Policy {
        let mut raw = self.raw_root.clone();
        if let Some(override_policy) = self.members.get(member) {
            raw.apply_override(override_policy.raw());
        }
        raw.into()
    }
}

impl<'de> Deserialize<'de> for WorkspacePolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let raw = RawWorkspacePolicy::deserialize(deserializer)?;
        let root_policy = raw.root.clone().into();
        let members = raw
            .members
            .into_iter()
            .map(|(name, override_policy)| (name, PolicyOverride::from(override_policy)))
            .collect();
        Ok(Self {
            raw_root: raw.root,
            root: root_policy,
            members,
        })
    }
}

#[derive(Debug, Deserialize)]
struct RawWorkspacePolicy {
    root: RawPolicy,
    #[serde(default)]
    members: HashMap<String, RawPolicyOverride>,
}

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("duplicate exec allow rule: {0}")]
    DuplicateExec(String),
    #[error("duplicate net host rule: {0}")]
    DuplicateNet(String),
    #[error("duplicate fs write rule: {0}")]
    DuplicateFsWrite(String),
    #[error("duplicate fs read rule: {0}")]
    DuplicateFsRead(String),
    #[error("path {0} present in both read and write allowlists")]
    FsReadWriteConflict(String),
    #[error("duplicate syscall deny rule: {0}")]
    DuplicateSyscall(String),
}

#[derive(Debug, thiserror::Error)]
pub enum ValidationWarning {
    #[error("exec allowlist is unused because exec.default is 'allow'")]
    UnusedExecAllow,
    #[error("network host allowlist is unused because net.default is 'allow'")]
    UnusedNetAllow,
    #[error("filesystem allowlists are unused because fs.default is 'unrestricted'")]
    UnusedFsAllow,
}

pub struct ValidationReport {
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<ValidationWarning>,
}

fn find_first_duplicate<T>(items: &[T]) -> Option<T>
where
    T: Eq + Hash + Clone,
{
    let mut seen = HashSet::new();
    for item in items {
        if !seen.insert(item.clone()) {
            return Some(item.clone());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::HashSet;

    fn slow_first_duplicate<T>(items: &[T]) -> Option<T>
    where
        T: Eq + Clone,
    {
        for j in 0..items.len() {
            for i in 0..j {
                if items[i] == items[j] {
                    return Some(items[j].clone());
                }
            }
        }
        None
    }

    fn base_policy() -> Policy {
        Policy {
            mode: Mode::Enforce,
            rules: vec![
                Permission::FsDefault(FsDefault::Strict),
                Permission::NetDefault(NetDefault::Deny),
                Permission::ExecDefault(ExecDefault::Allowlist),
            ],
        }
    }

    proptest! {
        #[test]
        fn first_duplicate_matches_naive(xs in proptest::collection::vec(any::<u8>(), 0..100)) {
            assert_eq!(find_first_duplicate(&xs), slow_first_duplicate(&xs));
        }
    }

    proptest! {
        #[test]
        fn exec_duplicates_flagged(xs in proptest::collection::vec(any::<u8>(), 0..20)) {
            let allowed: Vec<String> = xs.iter().map(|b| b.to_string()).collect();
            let mut policy = base_policy();
            policy
                .rules
                .extend(allowed.iter().cloned().map(Permission::Exec));
            let report = policy.validate();
            let mut seen = HashSet::new();
            let has_dup = allowed.iter().any(|x| !seen.insert(x));
            if has_dup {
                assert!(report.errors.iter().any(|e| matches!(e, ValidationError::DuplicateExec(_))));
            } else {
                assert!(report.errors.iter().all(|e| !matches!(e, ValidationError::DuplicateExec(_))));
            }
        }
    }

    const VALID: &str = r#"
mode = "enforce"
fs.default = "strict"
net.default = "deny"
exec.default = "allowlist"

[allow.exec]
allowed = ["rustc", "rustdoc"]

[allow.net]
hosts = ["127.0.0.1:1080"]

[allow.fs]
write_extra = ["/tmp/warden-scratch"]
read_extra = ["/usr/include"]

[allow.env]
read = ["HOME"]

[syscall]
deny = ["clone"]
"#;

    #[test]
    fn parse_and_validate() {
        let policy = Policy::from_toml_str(VALID).unwrap();
        let report = policy.validate();
        assert!(report.errors.is_empty());
        assert!(report.warnings.is_empty());
        assert_eq!(policy.mode, Mode::Enforce);
        assert_eq!(policy.exec_default(), ExecDefault::Allowlist);
        assert_eq!(policy.net_default(), NetDefault::Deny);
        assert_eq!(policy.fs_default(), FsDefault::Strict);
        assert!(policy.exec_allowed().any(|bin| bin == "rustc"));
        assert!(policy.env_read_vars().any(|var| var == "HOME"));
    }

    const SYSCALL_DUP: &str = r#"
mode = "enforce"
[syscall]
deny = ["clone", "clone"]
"#;

    #[test]
    fn duplicate_syscall_detected() {
        let policy = Policy::from_toml_str(SYSCALL_DUP).unwrap();
        let report = policy.validate();
        assert!(matches!(
            report.errors[0],
            ValidationError::DuplicateSyscall(_)
        ));
    }

    #[test]
    fn duplicate_exec_detected() {
        let text = r#"
mode = "enforce"
fs.default = "strict"
net.default = "deny"
exec.default = "allowlist"

[allow.exec]
allowed = ["bash", "bash"]
"#;
        let policy = Policy::from_toml_str(text).unwrap();
        let report = policy.validate();
        assert!(matches!(
            report.errors[0],
            ValidationError::DuplicateExec(_)
        ));
    }

    #[test]
    fn unused_net_rules_detected() {
        let text = r#"
mode = "enforce"
fs.default = "strict"
net.default = "allow"
exec.default = "allow"

[allow.net]
hosts = ["1.2.3.4:80"]

[allow.exec]
allowed = ["bash"]
"#;
        let policy = Policy::from_toml_str(text).unwrap();
        let report = policy.validate();
        assert!(report.errors.is_empty());
        assert!(
            report
                .warnings
                .iter()
                .any(|e| matches!(e, ValidationWarning::UnusedNetAllow))
        );
        assert!(
            report
                .warnings
                .iter()
                .any(|e| matches!(e, ValidationWarning::UnusedExecAllow))
        );
    }

    #[test]
    fn fs_conflict_detected() {
        let text = r#"
mode = "enforce"
fs.default = "strict"
net.default = "deny"
exec.default = "allowlist"

[allow.fs]
write_extra = ["/tmp/path", "/tmp/path"]
read_extra = ["/tmp/path"]
"#;
        let policy = Policy::from_toml_str(text).unwrap();
        let report = policy.validate();
        assert!(
            report
                .errors
                .iter()
                .any(|e| matches!(e, ValidationError::DuplicateFsWrite(_)))
        );
        assert!(
            report
                .errors
                .iter()
                .any(|e| matches!(e, ValidationError::FsReadWriteConflict(_)))
        );
    }

    const WORKSPACE: &str = r#"
[root]
mode = "enforce"

[root.exec]
default = "allowlist"

[root.allow.exec]
allowed = ["rustc"]

[members.pkg.exec]
default = "allow"

[members.pkg.allow.exec]
allowed = ["bash"]
"#;

    #[test]
    fn workspace_member_overrides() {
        let ws: WorkspacePolicy = toml::from_str(WORKSPACE).unwrap();
        let pkg = ws.policy_for("pkg");
        assert_eq!(pkg.exec_default(), ExecDefault::Allow);
        assert!(pkg.exec_allowed().any(|bin| bin == "bash"));
        let other = ws.policy_for("other");
        assert_eq!(other.exec_default(), ExecDefault::Allowlist);
        assert!(other.exec_allowed().any(|bin| bin == "rustc"));
    }
}
