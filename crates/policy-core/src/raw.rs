use crate::policy::{ExecDefault, FsDefault, Mode, NetDefault, Policy};
use crate::rules::{EnvRules, ExecRules, FsRules, NetRules, SyscallRules};
use crate::workspace::RawPolicyOverride;
use serde::Deserialize;
use std::path::PathBuf;

macro_rules! raw_wrapper {
    ($name:ident, $field:ident, $ty:ty) => {
        #[derive(Debug, Deserialize, Clone, Default)]
        pub(crate) struct $name {
            #[serde(default)]
            pub(crate) $field: $ty,
        }
    };
}

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
        fs_rules.extend_reads(read_extra.into_iter().chain(std::iter::empty()));
        fs_rules.extend_writes(write_extra.into_iter().chain(std::iter::empty()));

        let mut net_rules = NetRules::with_default(net.default);
        net_rules.extend(hosts.into_iter().chain(std::iter::empty()));

        let mut exec_rules = ExecRules::with_default(exec.default);
        exec_rules.extend(exec_allowed.into_iter().chain(std::iter::empty()));

        let mut syscall_rules = SyscallRules::default();
        syscall_rules.extend(syscall.deny.into_iter().chain(std::iter::empty()));

        let mut env_rules = EnvRules::default();
        env_rules.extend(env_read.into_iter().chain(std::iter::empty()));

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
            if let Some(exec) = &allow.exec {
                self.allow.exec.allowed.extend(exec.allowed.iter().cloned());
            }
            if let Some(net) = &allow.net {
                self.allow.net.hosts.extend(net.hosts.iter().cloned());
            }
            if let Some(fs) = &allow.fs {
                self.allow
                    .fs
                    .write_extra
                    .extend(fs.write_extra.iter().cloned());
                self.allow
                    .fs
                    .read_extra
                    .extend(fs.read_extra.iter().cloned());
            }
            if let Some(env) = &allow.env {
                self.allow.env.read.extend(env.read.iter().cloned());
            }
        }
    }
}

raw_wrapper!(RawFsPolicy, default, FsDefault);
raw_wrapper!(RawNetPolicy, default, NetDefault);
raw_wrapper!(RawExecPolicy, default, ExecDefault);

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
pub(crate) struct RawAllowOverrideSection {
    #[serde(default)]
    pub(crate) exec: Option<RawExecAllow>,
    #[serde(default)]
    pub(crate) net: Option<RawNetAllow>,
    #[serde(default)]
    pub(crate) fs: Option<RawFsAllow>,
    #[serde(default)]
    pub(crate) env: Option<RawEnvAllow>,
}

raw_wrapper!(RawExecAllow, allowed, Vec<String>);
raw_wrapper!(RawNetAllow, hosts, Vec<String>);

#[derive(Debug, Deserialize, Clone, Default)]
pub(crate) struct RawFsAllow {
    #[serde(default)]
    pub(crate) write_extra: Vec<PathBuf>,
    #[serde(default)]
    pub(crate) read_extra: Vec<PathBuf>,
}

raw_wrapper!(RawEnvAllow, read, Vec<String>);
