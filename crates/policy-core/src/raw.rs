use crate::policy::{ExecDefault, FsDefault, Mode, NetDefault, Policy};
use crate::rules::{EnvRules, ExecRules, FsRules, NetRules, SyscallRules};
use crate::workspace::RawPolicyOverride;
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct RawPolicy {
    pub(crate) mode: Mode,
    #[serde(default)]
    pub(crate) fs: RawFsPolicy,
    #[serde(default)]
    pub(crate) net: RawNetPolicy,
    #[serde(default)]
    pub(crate) exec: RawExecPolicy,
    #[serde(default)]
    pub(crate) syscall: RawSyscallPolicy,
    #[serde(default)]
    pub(crate) allow: RawAllowSection,
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
        for var in env_read {
            env_rules.insert_raw(var);
        }

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
    pub(crate) fn apply_override(&mut self, override_policy: &RawPolicyOverride) {
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
pub(crate) struct RawFsPolicy {
    #[serde(default)]
    pub(crate) default: FsDefault,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub(crate) struct RawNetPolicy {
    #[serde(default)]
    pub(crate) default: NetDefault,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub(crate) struct RawExecPolicy {
    #[serde(default)]
    pub(crate) default: ExecDefault,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub(crate) struct RawSyscallPolicy {
    #[serde(default)]
    pub(crate) deny: Vec<String>,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub(crate) struct RawAllowSection {
    #[serde(default)]
    pub(crate) exec: RawExecAllow,
    #[serde(default)]
    pub(crate) net: RawNetAllow,
    #[serde(default)]
    pub(crate) fs: RawFsAllow,
    #[serde(default)]
    pub(crate) env: RawEnvAllow,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub(crate) struct RawExecAllow {
    #[serde(default)]
    pub(crate) allowed: Vec<String>,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub(crate) struct RawNetAllow {
    #[serde(default)]
    pub(crate) hosts: Vec<String>,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub(crate) struct RawFsAllow {
    #[serde(default)]
    pub(crate) write_extra: Vec<PathBuf>,
    #[serde(default)]
    pub(crate) read_extra: Vec<PathBuf>,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub(crate) struct RawEnvAllow {
    #[serde(default)]
    pub(crate) read: Vec<String>,
}
