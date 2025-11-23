use std::error::Error;
use std::fmt;
use std::fs;

const CAP_SYS_ADMIN: u8 = 21;
const CAP_BPF: u8 = 38;
const CAP_NAMES: [&str; 40] = [
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_KILL",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETPCAP",
    "CAP_LINUX_IMMUTABLE",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_BROADCAST",
    "CAP_NET_ADMIN",
    "CAP_NET_RAW",
    "CAP_IPC_LOCK",
    "CAP_IPC_OWNER",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_CHROOT",
    "CAP_SYS_PTRACE",
    "CAP_SYS_PACCT",
    "CAP_SYS_ADMIN",
    "CAP_SYS_BOOT",
    "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE",
    "CAP_SYS_TIME",
    "CAP_SYS_TTY_CONFIG",
    "CAP_MKNOD",
    "CAP_LEASE",
    "CAP_AUDIT_WRITE",
    "CAP_AUDIT_CONTROL",
    "CAP_SETFCAP",
    "CAP_MAC_OVERRIDE",
    "CAP_MAC_ADMIN",
    "CAP_SYSLOG",
    "CAP_WAKE_ALARM",
    "CAP_BLOCK_SUSPEND",
    "CAP_AUDIT_READ",
    "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE",
];
const REQUIRED_CAP_MASK: u64 = (1u64 << CAP_SYS_ADMIN) | (1u64 << CAP_BPF);
const SKIP_ENV: &str = "CARGO_WARDEN_SKIP_PRIVILEGE_CHECK";
const CONTAINER_ENV_MARKERS: [&str; 7] = [
    "docker",
    "podman",
    "containerd",
    "kubepods",
    "lxc",
    "lxd",
    "nspawn",
];
const CONTAINER_CGROUP_MARKERS: [&str; 6] = [
    "docker",
    "kubepods",
    "containerd",
    "podman",
    "libpod",
    "lxc",
];

#[derive(Debug)]
pub(crate) enum PrivilegeError {
    RunningAsRoot,
    MissingContainerIsolation,
    MissingCapabilities { current: u64, missing: u64 },
    ExtraCapabilities { current: u64, extra: u64 },
    CapabilitiesUnavailable,
    ParseCapabilities { raw: String },
    Io(std::io::Error),
}

impl fmt::Display for PrivilegeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PrivilegeError::RunningAsRoot => write!(
                f,
                "cargo-warden must run under a dedicated non-root user; drop to an account with only CAP_BPF and CAP_SYS_ADMIN"
            ),
            PrivilegeError::MissingContainerIsolation => write!(
                f,
                "cargo-warden must run inside an isolated container or VM; see README for podman/docker guidance"
            ),
            PrivilegeError::MissingCapabilities { current, missing } => write!(
                f,
                "missing required capabilities: {} (effective set: {})",
                describe_capabilities(*missing),
                describe_capabilities(*current)
            ),
            PrivilegeError::ExtraCapabilities { current, extra } => write!(
                f,
                "too many effective capabilities: {} (required: CAP_BPF, CAP_SYS_ADMIN; effective set: {})",
                describe_capabilities(*extra),
                describe_capabilities(*current)
            ),
            PrivilegeError::CapabilitiesUnavailable => {
                write!(f, "unable to read CapEff from /proc/self/status")
            }
            PrivilegeError::ParseCapabilities { raw } => {
                write!(f, "failed to parse CapEff value: {raw}")
            }
            PrivilegeError::Io(err) => err.fmt(f),
        }
    }
}

impl Error for PrivilegeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            PrivilegeError::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for PrivilegeError {
    fn from(value: std::io::Error) -> Self {
        PrivilegeError::Io(value)
    }
}

pub(crate) fn enforce_least_privilege() -> Result<(), PrivilegeError> {
    if std::env::var_os(SKIP_ENV).is_some() {
        return Ok(());
    }

    if !detect_containerization()? {
        return Err(PrivilegeError::MissingContainerIsolation);
    }

    let uid = unsafe { libc::geteuid() };
    if uid == 0 {
        return Err(PrivilegeError::RunningAsRoot);
    }

    let effective_caps = read_effective_capabilities()?;
    validate_capabilities(effective_caps)
}

fn validate_capabilities(effective_caps: u64) -> Result<(), PrivilegeError> {
    if effective_caps & REQUIRED_CAP_MASK != REQUIRED_CAP_MASK {
        let missing = REQUIRED_CAP_MASK & !effective_caps;
        return Err(PrivilegeError::MissingCapabilities {
            current: effective_caps,
            missing,
        });
    }

    let extra = effective_caps & !REQUIRED_CAP_MASK;
    if extra != 0 {
        return Err(PrivilegeError::ExtraCapabilities {
            current: effective_caps,
            extra,
        });
    }

    Ok(())
}

fn detect_containerization() -> Result<bool, PrivilegeError> {
    let markers = ContainerMarkers::gather()?;
    Ok(has_container_markers(&markers))
}

fn has_container_markers(markers: &ContainerMarkers) -> bool {
    if markers.has_dockerenv || markers.has_containerenv {
        return true;
    }

    if let Some(env) = &markers.container_env {
        let env_lower = env.to_ascii_lowercase();
        if CONTAINER_ENV_MARKERS
            .iter()
            .any(|marker| env_lower.contains(marker))
        {
            return true;
        }
    }

    markers.cgroup.lines().any(|line| {
        CONTAINER_CGROUP_MARKERS
            .iter()
            .any(|marker| line.contains(marker))
    })
}

fn read_effective_capabilities() -> Result<u64, PrivilegeError> {
    let status = fs::read_to_string("/proc/self/status")?;
    for line in status.lines() {
        if let Some(value) = line.strip_prefix("CapEff:") {
            let trimmed = value.trim();
            return u64::from_str_radix(trimmed, 16).map_err(|_| {
                PrivilegeError::ParseCapabilities {
                    raw: trimmed.into(),
                }
            });
        }
    }

    Err(PrivilegeError::CapabilitiesUnavailable)
}

fn describe_capabilities(mask: u64) -> String {
    let mut entries = Vec::new();
    for (bit, name) in CAP_NAMES.iter().enumerate() {
        if mask & (1u64 << bit) != 0 {
            entries.push(*name);
        }
    }

    for bit in CAP_NAMES.len() as u8..64 {
        if mask & (1u64 << bit) != 0 {
            entries.push("UNKNOWN_CAP");
            break;
        }
    }

    if entries.is_empty() {
        "<none>".to_string()
    } else {
        entries.join(", ")
    }
}

#[derive(Default)]
struct ContainerMarkers {
    container_env: Option<String>,
    cgroup: String,
    has_dockerenv: bool,
    has_containerenv: bool,
}

impl ContainerMarkers {
    fn gather() -> Result<Self, PrivilegeError> {
        let container_env = std::env::var("container").ok();
        let cgroup = fs::read_to_string("/proc/1/cgroup")
            .or_else(|_| fs::read_to_string("/proc/self/cgroup"))?;
        let has_dockerenv = std::path::Path::new("/.dockerenv").exists();
        let has_containerenv = std::path::Path::new("/run/.containerenv").exists();

        Ok(ContainerMarkers {
            container_env,
            cgroup,
            has_dockerenv,
            has_containerenv,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_missing_capabilities() {
        let result = validate_capabilities(1u64 << CAP_BPF);
        assert!(matches!(
            result,
            Err(PrivilegeError::MissingCapabilities { missing, .. }) if missing & (1u64 << CAP_SYS_ADMIN) != 0
        ));
    }

    #[test]
    fn rejects_extra_capabilities() {
        let extra_mask = (1u64 << CAP_BPF) | (1u64 << CAP_SYS_ADMIN) | (1u64 << 0);
        let result = validate_capabilities(extra_mask);
        assert!(matches!(
            result,
            Err(PrivilegeError::ExtraCapabilities { extra, .. }) if extra & (1u64 << 0) != 0
        ));
    }

    #[test]
    fn accepts_minimal_capabilities() {
        let result = validate_capabilities((1u64 << CAP_BPF) | (1u64 << CAP_SYS_ADMIN));
        assert!(result.is_ok());
    }

    #[test]
    fn describes_known_capabilities() {
        let desc = describe_capabilities((1u64 << CAP_BPF) | (1u64 << CAP_SYS_ADMIN));
        assert!(desc.contains("CAP_BPF"));
        assert!(desc.contains("CAP_SYS_ADMIN"));
    }

    #[test]
    fn detects_container_by_cgroup_marker() {
        let markers = ContainerMarkers {
            cgroup: String::from("0::/kubepods.slice"),
            ..Default::default()
        };
        assert!(has_container_markers(&markers));
    }

    #[test]
    fn detects_container_by_env_and_sentinels() {
        let markers = ContainerMarkers {
            container_env: Some(String::from("podman")),
            ..Default::default()
        };
        assert!(has_container_markers(&markers));

        let sentinel = ContainerMarkers {
            has_dockerenv: true,
            ..Default::default()
        };
        assert!(has_container_markers(&sentinel));
    }

    #[test]
    fn rejects_plain_host_markers() {
        let markers = ContainerMarkers::default();
        assert!(!has_container_markers(&markers));
    }
}
