use crate::policy::Policy;
use crate::raw::{
    RawAllowOverrideSection, RawExecPolicy, RawFsPolicy, RawNetPolicy, RawPolicy, RawSyscallPolicy,
};
use serde::Deserialize;
use std::collections::HashMap;

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
    pub(crate) allow: Option<RawAllowOverrideSection>,
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
    fn workspace_override_retains_unmodified_allow_sections() {
        const WORKSPACE: &str = r#"
[root]
mode = "enforce"

[root.allow.exec]
allowed = ["rustc"]

[root.allow.net]
hosts = ["10.0.0.1:1234"]

[members.pkg.allow.exec]
allowed = ["bash"]
"#;
        let ws: WorkspacePolicy = toml::from_str(WORKSPACE).unwrap();
        let pkg = ws.policy_for("pkg");
        assert!(pkg.exec_allowed().any(|bin| bin == "rustc"));
        assert!(pkg.exec_allowed().any(|bin| bin == "bash"));
        assert!(pkg.net_hosts().any(|host| host == "10.0.0.1:1234"));

        let other = ws.policy_for("other");
        assert!(other.exec_allowed().any(|bin| bin == "rustc"));
        assert!(other.net_hosts().any(|host| host == "10.0.0.1:1234"));
    }
}
