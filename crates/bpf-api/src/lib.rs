#![no_std]

/// Bit flag for read access.
pub const FS_READ: u8 = 1;
/// Bit flag for write access.
pub const FS_WRITE: u8 = 2;

/// Maximum number of exec allowlist entries supported by the eBPF map.
pub const EXEC_ALLOWLIST_CAPACITY: u32 = 64;
/// Maximum number of network rules supported by the eBPF map.
pub const NET_RULES_CAPACITY: u32 = 256;
/// Maximum number of parent relationships supported by the eBPF map.
pub const NET_PARENTS_CAPACITY: u32 = 256;
/// Maximum number of filesystem rules supported by the eBPF map.
pub const FS_RULES_CAPACITY: u32 = 256;
/// Size of the event ring buffer in bytes.
pub const EVENT_RINGBUF_CAPACITY_BYTES: u32 = 4096;
/// Number of slots tracked for emitted event counters.
pub const EVENT_COUNT_SLOTS: u32 = 1;
/// Number of entries in the mode flags map.
pub const MODE_FLAGS_CAPACITY: u32 = 1;
/// Maximum number of workload-to-unit mappings supported by the eBPF map.
pub const WORKLOAD_UNITS_CAPACITY: u32 = 256;
/// Flag value stored in the mode map when running in observe mode.
pub const MODE_FLAG_OBSERVE: u32 = 0;
/// Flag value stored in the mode map when running in enforce mode.
pub const MODE_FLAG_ENFORCE: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ExecAllowEntry {
    pub path: [u8; 256],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NetRule {
    pub addr: [u8; 16],
    pub protocol: u8,
    pub prefix_len: u8,
    pub port: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NetRuleEntry {
    pub unit: u32,
    pub rule: NetRule,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NetParentEntry {
    pub child: u32,
    pub parent: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FsRule {
    pub access: u8,
    pub reserved: [u8; 3],
    pub path: [u8; 256],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FsRuleEntry {
    pub unit: u32,
    pub rule: FsRule,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
/// Event emitted by BPF programs.
pub struct Event {
    /// Process identifier.
    pub pid: u32,
    /// Workload category that produced the event.
    pub unit: u8,
    /// Operation being monitored.
    pub action: u8,
    /// Allow (0) or deny (1).
    pub verdict: u8,
    /// Reserved for future use.
    pub reserved: u8,
    /// Identifier of the container or sandbox.
    pub container_id: u64,
    /// Bitmask of Linux capabilities held by the process.
    pub caps: u64,
    /// Null-terminated path or network address.
    pub path_or_addr: [u8; 256],
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn exec_allow_entry_size() {
        assert_eq!(size_of::<ExecAllowEntry>(), 256);
    }

    #[test]
    fn net_rule_size() {
        assert_eq!(size_of::<NetRule>(), 20);
    }

    #[test]
    fn net_rule_entry_size() {
        assert_eq!(size_of::<NetRuleEntry>(), 24);
    }

    #[test]
    fn net_parent_entry_size() {
        assert_eq!(size_of::<NetParentEntry>(), 8);
    }

    #[test]
    fn fs_rule_size() {
        assert_eq!(size_of::<FsRule>(), 260);
    }

    #[test]
    fn fs_rule_entry_size() {
        assert_eq!(size_of::<FsRuleEntry>(), 264);
    }

    #[test]
    fn event_size() {
        assert_eq!(size_of::<Event>(), 280);
    }
}
