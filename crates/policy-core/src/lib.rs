use serde::Deserialize;
use std::{
    collections::{BTreeSet, HashMap},
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
    fs: FsRules,
    net: NetRules,
    exec: ExecRules,
    syscall: SyscallRules,
    env: EnvRules,
}

impl Policy {
    pub fn new(mode: Mode) -> Self {
        Self {
            mode,
            fs: FsRules::default(),
            net: NetRules::default(),
            exec: ExecRules::default(),
            syscall: SyscallRules::default(),
            env: EnvRules::default(),
        }
    }

    pub fn with_defaults(
        mode: Mode,
        fs_default: FsDefault,
        net_default: NetDefault,
        exec_default: ExecDefault,
    ) -> Self {
        let mut policy = Self::new(mode);
        policy.fs.default = fs_default;
        policy.net.default = net_default;
        policy.exec.default = exec_default;
        policy
    }

    pub fn from_toml_str(toml_str: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(toml_str)
    }

    pub fn merge(&mut self, other: Policy) {
        self.mode = other.mode;
        self.fs.merge(other.fs);
        self.net.merge(other.net);
        self.exec.merge(other.exec);
        self.syscall.merge(other.syscall);
        self.env.merge(other.env);
    }

    pub fn set_fs_default(&mut self, default: FsDefault) {
        self.fs.default = default;
    }

    pub fn set_net_default(&mut self, default: NetDefault) {
        self.net.default = default;
    }

    pub fn set_exec_default(&mut self, default: ExecDefault) {
        self.exec.default = default;
    }

    pub fn extend_exec_allowed<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = String>,
    {
        self.exec.extend(iter);
    }

    pub fn extend_net_hosts<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = String>,
    {
        self.net.extend(iter);
    }

    pub fn extend_fs_writes<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = PathBuf>,
    {
        self.fs.extend_writes(iter);
    }

    pub fn extend_fs_reads<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = PathBuf>,
    {
        self.fs.extend_reads(iter);
    }

    pub fn extend_syscall_deny<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = String>,
    {
        self.syscall.extend(iter);
    }

    pub fn extend_env_read_vars<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = String>,
    {
        self.env.extend(iter);
    }

    pub fn fs_default(&self) -> FsDefault {
        self.fs.default
    }

    pub fn net_default(&self) -> NetDefault {
        self.net.default
    }

    pub fn exec_default(&self) -> ExecDefault {
        self.exec.default
    }

    pub fn fs_read_paths(&self) -> impl Iterator<Item = &PathBuf> {
        self.fs.read_iter()
    }

    pub fn fs_write_paths(&self) -> impl Iterator<Item = &PathBuf> {
        self.fs.write_iter()
    }

    pub fn exec_allowed(&self) -> impl Iterator<Item = &String> {
        self.exec.iter()
    }

    pub fn net_hosts(&self) -> impl Iterator<Item = &String> {
        self.net.iter()
    }

    pub fn syscall_deny(&self) -> impl Iterator<Item = &String> {
        self.syscall.iter()
    }

    pub fn env_read_vars(&self) -> impl Iterator<Item = &String> {
        self.env.iter()
    }

    pub fn validate(&self) -> ValidationReport {
        use ValidationError::*;
        use ValidationWarning::*;

        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        if let Some(dup) = self.exec.first_duplicate() {
            errors.push(DuplicateExec(dup.clone()));
        }
        if let Some(dup) = self.net.first_duplicate() {
            errors.push(DuplicateNet(dup.clone()));
        }
        if let Some(dup) = self.fs.first_duplicate_write() {
            errors.push(DuplicateFsWrite(dup.to_string_lossy().into()));
        }
        if let Some(dup) = self.fs.first_duplicate_read() {
            errors.push(DuplicateFsRead(dup.to_string_lossy().into()));
        }
        if let Some(dup) = self.syscall.first_duplicate() {
            errors.push(DuplicateSyscall(dup.clone()));
        }

        for conflict in self.fs.conflicts() {
            errors.push(FsReadWriteConflict(conflict.to_string_lossy().into()));
        }

        if self.exec.default == ExecDefault::Allow && !self.exec.is_empty() {
            warnings.push(UnusedExecAllow);
        }
        if self.net.default == NetDefault::Allow && !self.net.is_empty() {
            warnings.push(UnusedNetAllow);
        }
        if self.fs.default == FsDefault::Unrestricted && !self.fs.is_empty() {
            warnings.push(UnusedFsAllow);
        }

        ValidationReport { errors, warnings }
    }
}

#[derive(Debug, Clone)]
struct FsRules {
    default: FsDefault,
    write: BTreeSet<PathBuf>,
    read: BTreeSet<PathBuf>,
    duplicate_write: BTreeSet<PathBuf>,
    duplicate_read: BTreeSet<PathBuf>,
}

impl Default for FsRules {
    fn default() -> Self {
        Self {
            default: FsDefault::Strict,
            write: BTreeSet::new(),
            read: BTreeSet::new(),
            duplicate_write: BTreeSet::new(),
            duplicate_read: BTreeSet::new(),
        }
    }
}

impl FsRules {
    fn with_default(default: FsDefault) -> Self {
        Self {
            default,
            ..Self::default()
        }
    }

    fn insert_write_raw(&mut self, path: PathBuf) {
        if !self.write.insert(path.clone()) {
            self.duplicate_write.insert(path);
        }
    }

    fn insert_read_raw(&mut self, path: PathBuf) {
        if !self.read.insert(path.clone()) {
            self.duplicate_read.insert(path);
        }
    }

    fn extend_writes<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = PathBuf>,
    {
        for path in iter {
            self.insert_write_raw(path);
        }
    }

    fn extend_reads<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = PathBuf>,
    {
        for path in iter {
            self.insert_read_raw(path);
        }
    }

    fn merge(&mut self, other: FsRules) {
        self.default = other.default;
        self.write.extend(other.write);
        self.read.extend(other.read);
        self.duplicate_write.extend(other.duplicate_write);
        self.duplicate_read.extend(other.duplicate_read);
    }

    fn write_iter(&self) -> impl Iterator<Item = &PathBuf> {
        self.write.iter()
    }

    fn read_iter(&self) -> impl Iterator<Item = &PathBuf> {
        self.read.iter()
    }

    fn first_duplicate_write(&self) -> Option<&PathBuf> {
        self.duplicate_write.iter().next()
    }

    fn first_duplicate_read(&self) -> Option<&PathBuf> {
        self.duplicate_read.iter().next()
    }

    fn conflicts(&self) -> impl Iterator<Item = &PathBuf> {
        self.write.intersection(&self.read)
    }

    fn is_empty(&self) -> bool {
        self.write.is_empty() && self.read.is_empty()
    }
}

#[derive(Debug, Clone)]
struct NetRules {
    default: NetDefault,
    hosts: BTreeSet<String>,
    duplicates: BTreeSet<String>,
}

impl Default for NetRules {
    fn default() -> Self {
        Self {
            default: NetDefault::Deny,
            hosts: BTreeSet::new(),
            duplicates: BTreeSet::new(),
        }
    }
}

impl NetRules {
    fn with_default(default: NetDefault) -> Self {
        Self {
            default,
            ..Self::default()
        }
    }

    fn insert_raw(&mut self, host: String) {
        if !self.hosts.insert(host.clone()) {
            self.duplicates.insert(host);
        }
    }

    fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = String>,
    {
        for host in iter {
            self.insert_raw(host);
        }
    }

    fn merge(&mut self, other: NetRules) {
        self.default = other.default;
        self.hosts.extend(other.hosts);
        self.duplicates.extend(other.duplicates);
    }

    fn iter(&self) -> impl Iterator<Item = &String> {
        self.hosts.iter()
    }

    fn first_duplicate(&self) -> Option<&String> {
        self.duplicates.iter().next()
    }

    fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }
}

#[derive(Debug, Clone)]
struct ExecRules {
    default: ExecDefault,
    allowed: BTreeSet<String>,
    duplicates: BTreeSet<String>,
}

impl Default for ExecRules {
    fn default() -> Self {
        Self {
            default: ExecDefault::Allowlist,
            allowed: BTreeSet::new(),
            duplicates: BTreeSet::new(),
        }
    }
}

impl ExecRules {
    fn with_default(default: ExecDefault) -> Self {
        Self {
            default,
            ..Self::default()
        }
    }

    fn insert_raw(&mut self, value: String) {
        if !self.allowed.insert(value.clone()) {
            self.duplicates.insert(value);
        }
    }

    fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = String>,
    {
        for value in iter {
            self.insert_raw(value);
        }
    }

    fn merge(&mut self, other: ExecRules) {
        self.default = other.default;
        self.allowed.extend(other.allowed);
        self.duplicates.extend(other.duplicates);
    }

    fn iter(&self) -> impl Iterator<Item = &String> {
        self.allowed.iter()
    }

    fn first_duplicate(&self) -> Option<&String> {
        self.duplicates.iter().next()
    }

    fn is_empty(&self) -> bool {
        self.allowed.is_empty()
    }
}

#[derive(Debug, Clone, Default)]
struct SyscallRules {
    deny: BTreeSet<String>,
    duplicates: BTreeSet<String>,
}

impl SyscallRules {
    fn insert_raw(&mut self, name: String) {
        if !self.deny.insert(name.clone()) {
            self.duplicates.insert(name);
        }
    }

    fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = String>,
    {
        for name in iter {
            self.insert_raw(name);
        }
    }

    fn merge(&mut self, other: SyscallRules) {
        self.deny.extend(other.deny);
        self.duplicates.extend(other.duplicates);
    }

    fn iter(&self) -> impl Iterator<Item = &String> {
        self.deny.iter()
    }

    fn first_duplicate(&self) -> Option<&String> {
        self.duplicates.iter().next()
    }
}

#[derive(Debug, Clone, Default)]
struct EnvRules {
    read: BTreeSet<String>,
}

impl EnvRules {
    fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = String>,
    {
        self.read.extend(iter);
    }

    fn merge(&mut self, other: EnvRules) {
        self.read.extend(other.read);
    }

    fn iter(&self) -> impl Iterator<Item = &String> {
        self.read.iter()
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

        let RawAllowSection {
            exec: RawExecAllow {
                allowed: exec_allowed,
            },
            net: RawNetAllow { hosts },
            fs: RawFsAllow {
                write_extra,
                read_extra,
            },
            env: RawEnvAllow { read: env_read },
        } = allow;

        let mut fs_rules = FsRules::with_default(fs.default);
        for path in read_extra {
            fs_rules.insert_read_raw(path);
        }
        for path in write_extra {
            fs_rules.insert_write_raw(path);
        }

        let mut net_rules = NetRules::with_default(net.default);
        for host in hosts {
            net_rules.insert_raw(host);
        }

        let mut exec_rules = ExecRules::with_default(exec.default);
        for bin in exec_allowed {
            exec_rules.insert_raw(bin);
        }

        let mut syscall_rules = SyscallRules::default();
        for name in syscall.deny {
            syscall_rules.insert_raw(name);
        }

        let mut env_rules = EnvRules::default();
        env_rules.extend(env_read);

        Policy {
            mode,
            fs: fs_rules,
            net: net_rules,
            exec: exec_rules,
            syscall: syscall_rules,
            env: env_rules,
        }
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

#[derive(Debug, Clone, Default)]
pub struct PolicyOverride {
    raw: RawPolicyOverride,
}

impl PolicyOverride {
    fn raw(&self) -> &RawPolicyOverride {
        &self.raw
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

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::HashSet;
    use std::path::PathBuf;

    fn policy_from_exec_allowed(allowed: Vec<String>) -> Policy {
        Policy::from(RawPolicy {
            mode: Mode::Enforce,
            fs: RawFsPolicy::default(),
            net: RawNetPolicy::default(),
            exec: RawExecPolicy::default(),
            syscall: RawSyscallPolicy::default(),
            allow: RawAllowSection {
                exec: RawExecAllow { allowed },
                net: RawNetAllow::default(),
                fs: RawFsAllow::default(),
                env: RawEnvAllow::default(),
            },
        })
    }

    proptest! {
        #[test]
        fn exec_duplicates_flagged(xs in proptest::collection::vec(any::<u8>(), 0..20)) {
            let allowed: Vec<String> = xs.iter().map(|b| b.to_string()).collect();
            let policy = policy_from_exec_allowed(allowed.clone());
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

    #[test]
    fn merge_combines_rules_and_defaults() {
        let mut base = Policy::new(Mode::Enforce);
        base.extend_exec_allowed(vec!["/usr/bin/rustc".into()]);
        base.extend_net_hosts(vec!["127.0.0.1:3000".into()]);
        base.extend_fs_writes(vec![PathBuf::from("/tmp/logs")]);

        let mut extra = Policy::with_defaults(
            Mode::Observe,
            FsDefault::Unrestricted,
            NetDefault::Allow,
            ExecDefault::Allow,
        );
        extra.extend_exec_allowed(vec!["/usr/bin/rustc".into(), "/bin/bash".into()]);
        extra.extend_syscall_deny(vec!["clone".into()]);

        base.merge(extra);

        let report = base.validate();
        assert!(
            report
                .errors
                .iter()
                .all(|e| !matches!(e, ValidationError::DuplicateExec(_)))
        );
        assert_eq!(base.mode, Mode::Observe);
        assert_eq!(base.fs_default(), FsDefault::Unrestricted);
        assert_eq!(base.net_default(), NetDefault::Allow);
        assert_eq!(base.exec_default(), ExecDefault::Allow);
        let exec: Vec<_> = base.exec_allowed().cloned().collect();
        assert!(exec.contains(&"/usr/bin/rustc".into()));
        assert!(exec.contains(&"/bin/bash".into()));
        assert!(base.net_hosts().any(|host| host == "127.0.0.1:3000"));
        assert!(base.syscall_deny().any(|name| name == "clone"));
        assert!(
            base.fs_write_paths()
                .any(|path| path == &PathBuf::from("/tmp/logs"))
        );
    }

    #[test]
    fn extend_exec_allowed_reports_duplicates() {
        let mut policy = Policy::new(Mode::Enforce);
        policy.extend_exec_allowed(vec!["/bin/bash".into(), "/bin/bash".into()]);
        let report = policy.validate();
        assert_eq!(report.errors.len(), 1);
        assert!(matches!(
            &report.errors[0],
            ValidationError::DuplicateExec(dup) if dup == "/bin/bash"
        ));
    }

    #[test]
    fn extend_net_hosts_reports_duplicates() {
        let mut policy = Policy::new(Mode::Enforce);
        policy.extend_net_hosts(vec!["127.0.0.1:80".into(), "127.0.0.1:80".into()]);
        let report = policy.validate();
        assert_eq!(report.errors.len(), 1);
        assert!(matches!(
            &report.errors[0],
            ValidationError::DuplicateNet(dup) if dup == "127.0.0.1:80"
        ));
    }

    #[test]
    fn extend_fs_writes_reports_duplicates() {
        let mut policy = Policy::new(Mode::Enforce);
        let path = PathBuf::from("/tmp/write");
        policy.extend_fs_writes(vec![path.clone(), path.clone()]);
        let report = policy.validate();
        assert_eq!(report.errors.len(), 1);
        assert!(matches!(
            &report.errors[0],
            ValidationError::DuplicateFsWrite(dup) if dup == "/tmp/write"
        ));
    }

    #[test]
    fn extend_fs_reads_reports_duplicates() {
        let mut policy = Policy::new(Mode::Enforce);
        let path = PathBuf::from("/tmp/read");
        policy.extend_fs_reads(vec![path.clone(), path.clone()]);
        let report = policy.validate();
        assert_eq!(report.errors.len(), 1);
        assert!(matches!(
            &report.errors[0],
            ValidationError::DuplicateFsRead(dup) if dup == "/tmp/read"
        ));
    }

    #[test]
    fn extend_syscall_deny_reports_duplicates() {
        let mut policy = Policy::new(Mode::Enforce);
        policy.extend_syscall_deny(vec!["clone".into(), "clone".into()]);
        let report = policy.validate();
        assert_eq!(report.errors.len(), 1);
        assert!(matches!(
            &report.errors[0],
            ValidationError::DuplicateSyscall(dup) if dup == "clone"
        ));
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
