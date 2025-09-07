use serde::Deserialize;
use std::{collections::HashSet, hash::Hash, path::PathBuf};

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Observe,
    Enforce,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Deserialize)]
pub struct Policy {
    pub mode: Mode,
    #[serde(default)]
    pub fs: FsPolicy,
    #[serde(default)]
    pub net: NetPolicy,
    #[serde(default)]
    pub exec: ExecPolicy,
    #[serde(default)]
    pub syscall: SyscallPolicy,
    #[serde(default)]
    pub allow: AllowSection,
}

#[derive(Debug, Deserialize, Default)]
pub struct FsPolicy {
    #[serde(default)]
    pub default: FsDefault,
}

#[derive(Debug, Deserialize, Default)]
pub struct NetPolicy {
    #[serde(default)]
    pub default: NetDefault,
}

#[derive(Debug, Deserialize, Default)]
pub struct ExecPolicy {
    #[serde(default)]
    pub default: ExecDefault,
}

#[derive(Debug, Deserialize, Default)]
pub struct SyscallPolicy {
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct AllowSection {
    #[serde(default)]
    pub exec: ExecAllow,
    #[serde(default)]
    pub net: NetAllow,
    #[serde(default)]
    pub fs: FsAllow,
}

#[derive(Debug, Deserialize, Default)]
pub struct ExecAllow {
    #[serde(default)]
    pub allowed: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct NetAllow {
    #[serde(default)]
    pub hosts: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct FsAllow {
    #[serde(default)]
    pub write_extra: Vec<PathBuf>,
    #[serde(default)]
    pub read_extra: Vec<PathBuf>,
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
    #[error("exec allowlist is unused because exec.default is 'allow'")]
    UnusedExecAllow,
    #[error("network host allowlist is unused because net.default is 'allow'")]
    UnusedNetAllow,
    #[error("filesystem allowlists are unused because fs.default is 'unrestricted'")]
    UnusedFsAllow,
    #[error("duplicate syscall deny rule: {0}")]
    DuplicateSyscall(String),
}

impl Policy {
    pub fn from_toml_str(toml_str: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(toml_str)
    }

    pub fn validate(&self) -> Result<(), Vec<ValidationError>> {
        use ValidationError::*;
        let mut errors = Vec::new();

        if let Some(dup) = find_first_duplicate(&self.allow.exec.allowed) {
            errors.push(DuplicateExec(dup));
        }
        if let Some(dup) = find_first_duplicate(&self.allow.net.hosts) {
            errors.push(DuplicateNet(dup));
        }
        if let Some(dup) = find_first_duplicate(&self.allow.fs.write_extra) {
            errors.push(DuplicateFsWrite(dup.to_string_lossy().into()));
        }
        if let Some(dup) = find_first_duplicate(&self.allow.fs.read_extra) {
            errors.push(DuplicateFsRead(dup.to_string_lossy().into()));
        }
        if let Some(dup) = find_first_duplicate(&self.syscall.deny) {
            errors.push(DuplicateSyscall(dup));
        }

        let read_set: HashSet<_> = self.allow.fs.read_extra.iter().collect();
        for w in &self.allow.fs.write_extra {
            if read_set.contains(w) {
                errors.push(FsReadWriteConflict(w.to_string_lossy().into()));
            }
        }

        if self.exec.default == ExecDefault::Allow && !self.allow.exec.allowed.is_empty() {
            errors.push(UnusedExecAllow);
        }
        if self.net.default == NetDefault::Allow && !self.allow.net.hosts.is_empty() {
            errors.push(UnusedNetAllow);
        }
        if self.fs.default == FsDefault::Unrestricted
            && (!self.allow.fs.read_extra.is_empty() || !self.allow.fs.write_extra.is_empty())
        {
            errors.push(UnusedFsAllow);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
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
"#;

    #[test]
    fn parse_and_validate() {
        let policy = Policy::from_toml_str(VALID).unwrap();
        policy.validate().unwrap();
        assert_eq!(policy.mode, Mode::Enforce);
    }

    const SYSCALL_DUP: &str = r#"
mode = "enforce"
[syscall]
deny = ["clone", "clone"]
"#;

    #[test]
    fn duplicate_syscall_detected() {
        let policy = Policy::from_toml_str(SYSCALL_DUP).unwrap();
        let errs = policy.validate().unwrap_err();
        assert!(matches!(errs[0], ValidationError::DuplicateSyscall(_)));
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
        let errs = policy.validate().unwrap_err();
        assert!(matches!(errs[0], ValidationError::DuplicateExec(_)));
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
        let errs = policy.validate().unwrap_err();
        assert!(
            errs.iter()
                .any(|e| matches!(e, ValidationError::UnusedNetAllow))
        );
        assert!(
            errs.iter()
                .any(|e| matches!(e, ValidationError::UnusedExecAllow))
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
        let errs = policy.validate().unwrap_err();
        assert!(
            errs.iter()
                .any(|e| matches!(e, ValidationError::DuplicateFsWrite(_)))
        );
        assert!(
            errs.iter()
                .any(|e| matches!(e, ValidationError::FsReadWriteConflict(_)))
        );
    }
}
