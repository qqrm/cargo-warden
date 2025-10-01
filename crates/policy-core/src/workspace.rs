use crate::policy::Policy;
use crate::raw::{
    RawAllowSection, RawExecPolicy, RawFsPolicy, RawNetPolicy, RawPolicy, RawSyscallPolicy,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;

#[derive(Debug, Clone, Default)]
pub struct PolicyOverride {
    raw: RawPolicyOverride,
}

impl PolicyOverride {
    pub(crate) fn raw(&self) -> &RawPolicyOverride {
        &self.raw
    }
}

impl From<RawPolicyOverride> for PolicyOverride {
    fn from(raw: RawPolicyOverride) -> Self {
        Self { raw }
    }
}

#[derive(Debug, Deserialize, Clone, Default)]
pub(crate) struct RawPolicyOverride {
    pub(crate) fs: Option<RawFsPolicy>,
    pub(crate) net: Option<RawNetPolicy>,
    pub(crate) exec: Option<RawExecPolicy>,
    pub(crate) syscall: Option<RawSyscallPolicy>,
    pub(crate) allow: Option<RawAllowSection>,
}

#[derive(Debug, Clone)]
pub struct WorkspacePolicy {
    pub(crate) raw_root: RawPolicy,
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

    pub fn from_toml_path(path: &Path) -> io::Result<Self> {
        let text = fs::read_to_string(path)?;
        Self::from_toml_str_with_path(path, &text)
    }

    pub fn from_toml_str_with_path(path: &Path, text: &str) -> io::Result<Self> {
        toml::from_str(text).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{}: {err}", path.display()),
            )
        })
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
pub(crate) struct RawWorkspacePolicy {
    pub(crate) root: RawPolicy,
    #[serde(default)]
    pub(crate) members: HashMap<String, RawPolicyOverride>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::ExecDefault;
    use std::io;
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_workspace_path(suffix: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!(
            "workspace_policy_test_{}_{}_{}.toml",
            std::process::id(),
            nanos,
            suffix
        ));
        path
    }

    #[test]
    fn workspace_member_overrides() {
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
        let ws: WorkspacePolicy = toml::from_str(WORKSPACE).unwrap();
        let pkg = ws.policy_for("pkg");
        assert_eq!(pkg.exec_default(), ExecDefault::Allow);
        assert!(pkg.exec_allowed().any(|bin| bin == "bash"));
        let other = ws.policy_for("other");
        assert_eq!(other.exec_default(), ExecDefault::Allowlist);
        assert!(other.exec_allowed().any(|bin| bin == "rustc"));
    }

    #[test]
    fn from_toml_path_loads_workspace() {
        const CONTENT: &str = r#"
[root]
mode = "enforce"

[members.pkg.exec]
default = "allow"
"#;
        let path = temp_workspace_path("valid");
        std::fs::write(&path, CONTENT).unwrap();
        let ws = WorkspacePolicy::from_toml_path(&path).unwrap();
        let policy = ws.policy_for("pkg");
        assert_eq!(policy.exec_default(), ExecDefault::Allow);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn from_toml_str_with_path_wraps_error() {
        let err = WorkspacePolicy::from_toml_str_with_path(
            Path::new("broken-workspace.toml"),
            "not toml",
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("broken-workspace.toml"));
    }
}
