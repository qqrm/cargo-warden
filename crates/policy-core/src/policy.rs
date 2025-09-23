use crate::raw::RawPolicy;
use crate::rules::{EnvRules, ExecRules, FsRules, NetRules, SyscallRules};
use crate::validation::{ValidationError, ValidationReport, ValidationWarning};
use serde::Deserialize;
use std::path::PathBuf;

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

#[derive(Debug, Clone)]
pub struct Policy {
    pub mode: Mode,
    pub(crate) fs: FsRules,
    pub(crate) net: NetRules,
    pub(crate) exec: ExecRules,
    pub(crate) syscall: SyscallRules,
    pub(crate) env: EnvRules,
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

impl<'de> Deserialize<'de> for Policy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let raw = RawPolicy::deserialize(deserializer)?;
        Ok(raw.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw::{
        RawAllowSection, RawEnvAllow, RawExecAllow, RawExecPolicy, RawFsAllow, RawFsPolicy,
        RawNetAllow, RawNetPolicy, RawPolicy, RawSyscallPolicy,
    };
    use proptest::prelude::*;
    use std::collections::HashSet;
    use std::path::{Path, PathBuf};

    fn workspace_root_path() -> PathBuf {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = path.ancestors().nth(2).expect("workspace root");
        std::fs::canonicalize(workspace_root).unwrap_or_else(|_| workspace_root.to_path_buf())
    }

    fn default_target_path() -> PathBuf {
        let target = workspace_root_path().join("target");
        std::fs::canonicalize(&target).unwrap_or(target)
    }

    fn ensure_default_fs_paths(policy: &mut Policy) {
        let workspace = workspace_root_path();
        if !policy.fs_read_paths().any(|path| path == &workspace) {
            policy.extend_fs_reads(std::iter::once(workspace));
        }
        let target = default_target_path();
        if !policy.fs_write_paths().any(|path| path == &target) {
            policy.extend_fs_writes(std::iter::once(target));
        }
    }

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
        let mut policy = Policy::from_toml_str(VALID).unwrap();
        ensure_default_fs_paths(&mut policy);
        let report = policy.validate();
        assert!(report.errors.is_empty());
        assert!(report.warnings.is_empty());
        assert_eq!(policy.mode, Mode::Enforce);
        assert_eq!(policy.exec_default(), ExecDefault::Allowlist);
        assert_eq!(policy.net_default(), NetDefault::Deny);
        assert_eq!(policy.fs_default(), FsDefault::Strict);
        assert!(policy.exec_allowed().any(|bin| bin == "rustc"));
        assert!(policy.env_read_vars().any(|var| var == "HOME"));
        assert!(
            policy
                .fs_write_paths()
                .any(|path| path == &PathBuf::from("/tmp/warden-scratch"))
        );
        assert!(
            policy
                .fs_read_paths()
                .any(|path| path == &PathBuf::from("/usr/include"))
        );
        let default_target = default_target_path();
        assert!(policy.fs_write_paths().any(|path| path == &default_target));
        let workspace_root = workspace_root_path();
        assert!(policy.fs_read_paths().any(|path| path == &workspace_root));
        assert!(policy.net_hosts().any(|host| host == "127.0.0.1:1080"));
        assert!(policy.syscall_deny().any(|name| name == "clone"));
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
exec.default = "allowlist"

[allow.net]
hosts = ["127.0.0.1:1080"]
"#;
        let policy = Policy::from_toml_str(text).unwrap();
        let report = policy.validate();
        assert!(matches!(
            report.warnings[0],
            ValidationWarning::UnusedNetAllow
        ));
    }

    #[test]
    fn merge() {
        let mut base = Policy::from(RawPolicy {
            mode: Mode::Enforce,
            fs: RawFsPolicy {
                default: FsDefault::Strict,
            },
            net: RawNetPolicy {
                default: NetDefault::Deny,
            },
            exec: RawExecPolicy {
                default: ExecDefault::Allowlist,
            },
            syscall: RawSyscallPolicy {
                deny: vec!["clone".into()],
            },
            allow: RawAllowSection {
                exec: RawExecAllow {
                    allowed: vec!["rustc".into()],
                },
                net: RawNetAllow {
                    hosts: vec!["127.0.0.1:3000".into()],
                },
                fs: RawFsAllow {
                    write_extra: vec!["/tmp/logs".into()],
                    read_extra: vec![],
                },
                env: RawEnvAllow {
                    read: vec!["HOME".into()],
                },
            },
        });

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

    #[test]
    fn new_policy_has_empty_rule_sets() {
        let mut policy = Policy::new(Mode::Enforce);
        ensure_default_fs_paths(&mut policy);
        assert_eq!(policy.mode, Mode::Enforce);
        assert_eq!(policy.exec_default(), ExecDefault::Allowlist);
        assert_eq!(policy.net_default(), NetDefault::Deny);
        assert_eq!(policy.fs_default(), FsDefault::Strict);
        assert!(policy.exec_allowed().next().is_none());
        assert!(policy.net_hosts().next().is_none());
        let writes: Vec<PathBuf> = policy.fs_write_paths().cloned().collect();
        let default_target = default_target_path();
        assert_eq!(writes, vec![default_target]);
        let reads: Vec<PathBuf> = policy.fs_read_paths().cloned().collect();
        let workspace_root = workspace_root_path();
        assert_eq!(reads, vec![workspace_root]);
        assert!(policy.syscall_deny().next().is_none());
        assert!(policy.env_read_vars().next().is_none());
    }
}
