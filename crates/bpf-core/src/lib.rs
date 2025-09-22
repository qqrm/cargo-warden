#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(target_arch = "bpf", allow(static_mut_refs))]
#![cfg_attr(target_arch = "bpf", allow(unsafe_op_in_unsafe_fn))]
#![cfg_attr(not(target_arch = "bpf"), allow(dead_code))]

#[cfg(target_arch = "bpf")]
use aya_bpf::{
    helpers::bpf_probe_read_kernel,
    macros::map,
    maps::{Array, HashMap, RingBuf},
};
#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
use bpf_api::{self, Event};
#[cfg(any(test, feature = "fuzzing"))]
use bpf_host::{
    fs::{dentry_path_ptr, file_mode_bits, file_path_ptr},
    maps::{DummyRingBuf, TestArray, TestHashMap},
};
#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
use core::{ffi::c_void, mem::size_of};

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
const _EVENT_SIZE: usize = size_of::<Event>();

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
const EPERM: i32 = 1;

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
const ACTION_OPEN: u8 = 0;

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
const ACTION_RENAME: u8 = 1;

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
const ACTION_UNLINK: u8 = 2;

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn deny() -> i32 {
    -EPERM
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn deny_with_mode() -> i32 {
    if is_observe_mode() { 0 } else { deny() }
}

#[cfg(target_arch = "bpf")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

macro_rules! map_type_alias {
    (@define EXEC_ALLOWLIST, $value:ty, $capacity:expr) => {
        #[cfg(target_arch = "bpf")]
        type ExecAllowlistMap = Array<$value>;
        #[cfg(any(test, feature = "fuzzing"))]
        type ExecAllowlistMap = TestArray<$value, { ($capacity) as usize }>;
    };
    (@define EXEC_ALLOWLIST_LENGTH, $value:ty, $capacity:expr) => {
        #[cfg(target_arch = "bpf")]
        type LengthMap = Array<$value>;
        #[cfg(any(test, feature = "fuzzing"))]
        type LengthMap = TestArray<$value, { ($capacity) as usize }>;
    };
    (@define NET_RULES, $value:ty, $capacity:expr) => {
        #[cfg(target_arch = "bpf")]
        type NetRulesMap = Array<$value>;
        #[cfg(any(test, feature = "fuzzing"))]
        type NetRulesMap = TestArray<$value, { ($capacity) as usize }>;
    };
    (@define NET_PARENTS, $value:ty, $capacity:expr) => {
        #[cfg(target_arch = "bpf")]
        type NetParentsMap = Array<$value>;
        #[cfg(any(test, feature = "fuzzing"))]
        type NetParentsMap = TestArray<$value, { ($capacity) as usize }>;
    };
    (@define FS_RULES, $value:ty, $capacity:expr) => {
        #[cfg(target_arch = "bpf")]
        type FsRulesMap = Array<$value>;
        #[cfg(any(test, feature = "fuzzing"))]
        type FsRulesMap = TestArray<$value, { ($capacity) as usize }>;
    };
    (@define EVENT_COUNTS, $value:ty, $capacity:expr) => {
        #[cfg(target_arch = "bpf")]
        type EventCountsMap = Array<$value>;
        #[cfg(any(test, feature = "fuzzing"))]
        type EventCountsMap = TestArray<$value, { ($capacity) as usize }>;
    };
    (@define MODE_FLAGS, $value:ty, $capacity:expr) => {
        #[cfg(target_arch = "bpf")]
        type ModeFlagsMap = Array<$value>;
        #[cfg(any(test, feature = "fuzzing"))]
        type ModeFlagsMap = TestArray<$value, { ($capacity) as usize }>;
    };
    (@define $other:ident, $value:ty, $capacity:expr) => {
        compile_error!(concat!(
            "Missing type alias mapping for ",
            stringify!($other)
        ));
    };
    (@name EXEC_ALLOWLIST) => {
        ExecAllowlistMap
    };
    (@name EXEC_ALLOWLIST_LENGTH) => {
        LengthMap
    };
    (@name NET_RULES) => {
        NetRulesMap
    };
    (@name NET_RULES_LENGTH) => {
        LengthMap
    };
    (@name NET_PARENTS) => {
        NetParentsMap
    };
    (@name NET_PARENTS_LENGTH) => {
        LengthMap
    };
    (@name FS_RULES) => {
        FsRulesMap
    };
    (@name FS_RULES_LENGTH) => {
        LengthMap
    };
    (@name EVENT_COUNTS) => {
        EventCountsMap
    };
    (@name MODE_FLAGS) => {
        ModeFlagsMap
    };
    (@name $other:ident) => {
        compile_error!(concat!(
            "Missing type alias mapping for ",
            stringify!($other)
        ));
    };
}

macro_rules! map_ctor_fn {
    (@define EXEC_ALLOWLIST, $value:ty, $capacity:expr) => {
        #[cfg(target_arch = "bpf")]
        const fn exec_allowlist_map() -> ExecAllowlistMap {
            Array::with_max_entries($capacity, 0)
        }

        #[cfg(any(test, feature = "fuzzing"))]
        const fn exec_allowlist_map() -> ExecAllowlistMap {
            TestArray::new()
        }
    };
    (@define EXEC_ALLOWLIST_LENGTH, $value:ty, $capacity:expr) => {
        #[cfg(target_arch = "bpf")]
        const fn length_map() -> LengthMap {
            Array::with_max_entries($capacity, 0)
        }

        #[cfg(any(test, feature = "fuzzing"))]
        const fn length_map() -> LengthMap {
            TestArray::new()
        }
    };
    (@define NET_RULES, $value:ty, $capacity:expr) => {
        #[cfg(target_arch = "bpf")]
        const fn net_rules_map() -> NetRulesMap {
            Array::with_max_entries($capacity, 0)
        }

        #[cfg(any(test, feature = "fuzzing"))]
        const fn net_rules_map() -> NetRulesMap {
            TestArray::new()
        }
    };
    (@define NET_PARENTS, $value:ty, $capacity:expr) => {
        #[cfg(target_arch = "bpf")]
        const fn net_parents_map() -> NetParentsMap {
            Array::with_max_entries($capacity, 0)
        }

        #[cfg(any(test, feature = "fuzzing"))]
        const fn net_parents_map() -> NetParentsMap {
            TestArray::new()
        }
    };
    (@define FS_RULES, $value:ty, $capacity:expr) => {
        #[cfg(target_arch = "bpf")]
        const fn fs_rules_map() -> FsRulesMap {
            Array::with_max_entries($capacity, 0)
        }

        #[cfg(any(test, feature = "fuzzing"))]
        const fn fs_rules_map() -> FsRulesMap {
            TestArray::new()
        }
    };
    (@define EVENT_COUNTS, $value:ty, $capacity:expr) => {
        #[cfg(target_arch = "bpf")]
        const fn event_counts_map() -> EventCountsMap {
            Array::with_max_entries($capacity, 0)
        }

        #[cfg(any(test, feature = "fuzzing"))]
        const fn event_counts_map() -> EventCountsMap {
            TestArray::new()
        }
    };
    (@define MODE_FLAGS, $value:ty, $capacity:expr) => {
        #[cfg(target_arch = "bpf")]
        const fn mode_flags_map() -> ModeFlagsMap {
            Array::with_max_entries($capacity, 0)
        }

        #[cfg(any(test, feature = "fuzzing"))]
        const fn mode_flags_map() -> ModeFlagsMap {
            TestArray::new()
        }
    };
    (@define $other:ident, $value:ty, $capacity:expr) => {
        compile_error!(concat!(
            "Missing constructor mapping for ",
            stringify!($other)
        ));
    };
    (@name EXEC_ALLOWLIST) => {
        exec_allowlist_map
    };
    (@name EXEC_ALLOWLIST_LENGTH) => {
        length_map
    };
    (@name NET_RULES) => {
        net_rules_map
    };
    (@name NET_RULES_LENGTH) => {
        length_map
    };
    (@name NET_PARENTS) => {
        net_parents_map
    };
    (@name NET_PARENTS_LENGTH) => {
        length_map
    };
    (@name FS_RULES) => {
        fs_rules_map
    };
    (@name FS_RULES_LENGTH) => {
        length_map
    };
    (@name EVENT_COUNTS) => {
        event_counts_map
    };
    (@name MODE_FLAGS) => {
        mode_flags_map
    };
    (@name $other:ident) => {
        compile_error!(concat!(
            "Missing constructor mapping for ",
            stringify!($other)
        ));
    };
}

macro_rules! map_define_alias {
    (EXEC_ALLOWLIST, $define:ident, $skip:ident, $($rest:tt)*) => {
        $define!(EXEC_ALLOWLIST, $($rest)*);
    };
    (EXEC_ALLOWLIST_LENGTH, $define:ident, $skip:ident, $($rest:tt)*) => {
        $define!(EXEC_ALLOWLIST_LENGTH, $($rest)*);
    };
    (NET_RULES, $define:ident, $skip:ident, $($rest:tt)*) => {
        $define!(NET_RULES, $($rest)*);
    };
    (NET_RULES_LENGTH, $define:ident, $skip:ident, $($rest:tt)*) => {
        $skip!(NET_RULES_LENGTH, $($rest)*);
    };
    (NET_PARENTS, $define:ident, $skip:ident, $($rest:tt)*) => {
        $define!(NET_PARENTS, $($rest)*);
    };
    (NET_PARENTS_LENGTH, $define:ident, $skip:ident, $($rest:tt)*) => {
        $skip!(NET_PARENTS_LENGTH, $($rest)*);
    };
    (FS_RULES, $define:ident, $skip:ident, $($rest:tt)*) => {
        $define!(FS_RULES, $($rest)*);
    };
    (FS_RULES_LENGTH, $define:ident, $skip:ident, $($rest:tt)*) => {
        $skip!(FS_RULES_LENGTH, $($rest)*);
    };
    (EVENT_COUNTS, $define:ident, $skip:ident, $($rest:tt)*) => {
        $define!(EVENT_COUNTS, $($rest)*);
    };
    (MODE_FLAGS, $define:ident, $skip:ident, $($rest:tt)*) => {
        $define!(MODE_FLAGS, $($rest)*);
    };
    ($other:ident, $define:ident, $skip:ident, $($rest:tt)*) => {
        compile_error!(concat!("Missing alias flag for ", stringify!($other)));
    };
}

macro_rules! define_map {
    ($ident:ident, $aya_name:literal, $value:ty, $capacity:expr $(,)?) => {
        map_define_alias!(
            $ident,
            define_map_define,
            define_map_skip,
            $aya_name,
            $value,
            $capacity
        );
    };
}

macro_rules! define_map_define {
    ($ident:ident, $aya_name:literal, $value:ty, $capacity:expr) => {
        map_type_alias!(@define $ident, $value, $capacity);
        map_ctor_fn!(@define $ident, $value, $capacity);
        define_map_static!($ident, $aya_name);
    };
}

macro_rules! define_map_skip {
    ($ident:ident, $aya_name:literal, $value:ty, $capacity:expr) => {
        define_map_static!($ident, $aya_name);
    };
}

macro_rules! define_map_static {
    ($ident:ident, $aya_name:literal) => {
        #[cfg(target_arch = "bpf")]
        #[map(name = $aya_name)]
static mut $ident: map_type_alias!(@name $ident) = map_ctor_fn!(@name $ident)();

        #[cfg(any(test, feature = "fuzzing"))]
static $ident: map_type_alias!(@name $ident) = map_ctor_fn!(@name $ident)();
    };
}

define_map!(
    EXEC_ALLOWLIST,
    "EXEC_ALLOWLIST",
    bpf_api::ExecAllowEntry,
    bpf_api::EXEC_ALLOWLIST_CAPACITY,
);
define_map!(EXEC_ALLOWLIST_LENGTH, "EXEC_ALLOWLIST_LENGTH", u32, 1);
define_map!(
    NET_RULES,
    "NET_RULES",
    bpf_api::NetRuleEntry,
    bpf_api::NET_RULES_CAPACITY,
);
define_map!(NET_RULES_LENGTH, "NET_RULES_LENGTH", u32, 1);
define_map!(
    NET_PARENTS,
    "NET_PARENTS",
    bpf_api::NetParentEntry,
    bpf_api::NET_PARENTS_CAPACITY,
);
define_map!(NET_PARENTS_LENGTH, "NET_PARENTS_LENGTH", u32, 1);
define_map!(
    FS_RULES,
    "FS_RULES",
    bpf_api::FsRuleEntry,
    bpf_api::FS_RULES_CAPACITY,
);
define_map!(FS_RULES_LENGTH, "FS_RULES_LENGTH", u32, 1);
define_map!(
    EVENT_COUNTS,
    "EVENT_COUNTS",
    u64,
    bpf_api::EVENT_COUNT_SLOTS,
);
define_map!(MODE_FLAGS, "MODE_FLAGS", u32, bpf_api::MODE_FLAGS_CAPACITY);

#[cfg(target_arch = "bpf")]
#[map(name = "WORKLOAD_UNITS")]
static mut WORKLOAD_UNITS: HashMap<u32, u32> =
    HashMap::with_max_entries(bpf_api::WORKLOAD_UNITS_CAPACITY, 0);

#[cfg(any(test, feature = "fuzzing"))]
static WORKLOAD_UNITS: TestHashMap<u32, u32, { bpf_api::WORKLOAD_UNITS_CAPACITY as usize }> =
    TestHashMap::new();

#[cfg(target_arch = "bpf")]
type EventsMap = RingBuf;
#[cfg(any(test, feature = "fuzzing"))]
type EventsMap = DummyRingBuf;

#[cfg(target_arch = "bpf")]
const fn events_map() -> EventsMap {
    RingBuf::with_byte_size(bpf_api::EVENT_RINGBUF_CAPACITY_BYTES, 0)
}

#[cfg(any(test, feature = "fuzzing"))]
const fn events_map() -> EventsMap {
    DummyRingBuf
}

#[cfg(target_arch = "bpf")]
#[map(name = "EVENTS")]
static mut EVENTS: EventsMap = events_map();

#[cfg(any(test, feature = "fuzzing"))]
static EVENTS: EventsMap = events_map();

#[cfg(target_arch = "bpf")]
unsafe fn load_mode_flags() -> u32 {
    MODE_FLAGS.get(0).copied().unwrap_or(0)
}

#[cfg(any(test, feature = "fuzzing"))]
unsafe fn load_mode_flags() -> u32 {
    MODE_FLAGS.get(0).unwrap_or(0)
}

#[cfg(target_arch = "bpf")]
unsafe fn load_length(map: &LengthMap) -> u32 {
    map.get(0).copied().unwrap_or(0)
}

#[cfg(any(test, feature = "fuzzing"))]
unsafe fn load_length(map: &LengthMap) -> u32 {
    map.get(0).unwrap_or(0)
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn is_observe_mode() -> bool {
    let flags = unsafe { load_mode_flags() };
    match flags {
        bpf_api::MODE_FLAG_OBSERVE => true,
        bpf_api::MODE_FLAG_ENFORCE => false,
        _ => false,
    }
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn clamp_len(len: u32, capacity: u32) -> u32 {
    len.min(capacity)
}

macro_rules! define_map_accessors {
    (
        $load_fn:ident,
        $len_fn:ident,
        $map:ident,
        $len_map:ident,
        $entry:ty,
        $capacity:expr
    ) => {
        #[cfg(target_arch = "bpf")]
        unsafe fn $load_fn(index: u32) -> Option<$entry> {
            $map.get(index).copied()
        }

        #[cfg(any(test, feature = "fuzzing"))]
        unsafe fn $load_fn(index: u32) -> Option<$entry> {
            $map.get(index)
        }

        #[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
        fn $len_fn() -> u32 {
            clamp_len(unsafe { load_length(&$len_map) }, $capacity)
        }
    };
}

define_map_accessors!(
    load_exec_allow_entry,
    exec_allowlist_len,
    EXEC_ALLOWLIST,
    EXEC_ALLOWLIST_LENGTH,
    bpf_api::ExecAllowEntry,
    bpf_api::EXEC_ALLOWLIST_CAPACITY
);

define_map_accessors!(
    load_net_rule,
    net_rules_len,
    NET_RULES,
    NET_RULES_LENGTH,
    bpf_api::NetRuleEntry,
    bpf_api::NET_RULES_CAPACITY
);

define_map_accessors!(
    load_net_parent,
    net_parents_len,
    NET_PARENTS,
    NET_PARENTS_LENGTH,
    bpf_api::NetParentEntry,
    bpf_api::NET_PARENTS_CAPACITY
);

define_map_accessors!(
    load_fs_rule,
    fs_rules_len,
    FS_RULES,
    FS_RULES_LENGTH,
    bpf_api::FsRuleEntry,
    bpf_api::FS_RULES_CAPACITY
);

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn increment_event_count() {
    #[cfg(target_arch = "bpf")]
    unsafe {
        if let Some(counter) = EVENT_COUNTS.get_ptr_mut(0) {
            let new_value = (*counter).wrapping_add(1);
            *counter = new_value;
        }
    }

    #[cfg(any(test, feature = "fuzzing"))]
    {
        let current = EVENT_COUNTS.get(0).unwrap_or(0);
        EVENT_COUNTS.set(0, current.wrapping_add(1));
    }
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn path_matches(a: &[u8; 256], b: &[u8; 256]) -> bool {
    let mut i = 0;
    while i < 256 {
        if a[i] != b[i] {
            return false;
        }
        if a[i] == 0 {
            break;
        }
        i += 1;
    }
    true
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
static mut CURRENT_UNIT: u32 = 0;

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn current_unit() -> u32 {
    refresh_current_unit();
    unsafe { CURRENT_UNIT }
}

#[cfg(target_arch = "bpf")]
fn refresh_current_unit() {
    let pid = unsafe { (bpf_get_current_pid_tgid() >> 32) as u32 };
    let unit = unsafe { WORKLOAD_UNITS.get(&pid).copied().unwrap_or(0) };
    unsafe {
        CURRENT_UNIT = unit;
    }
}

#[cfg(any(test, feature = "fuzzing"))]
fn refresh_current_unit() {
    let pid = unsafe { (bpf_get_current_pid_tgid() >> 32) as u32 };
    if let Some(unit) = WORKLOAD_UNITS.get(pid) {
        unsafe {
            CURRENT_UNIT = unit;
        }
    }
}

#[cfg(any(test, feature = "fuzzing"))]
fn set_workload_unit(pid: u32, unit: u32) {
    WORKLOAD_UNITS.insert(pid, unit);
}

#[cfg(any(test, feature = "fuzzing"))]
fn clear_workload_units() {
    WORKLOAD_UNITS.clear();
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn addr_matches(rule: &bpf_api::NetRule, addr: &[u8; 16]) -> bool {
    let mut bits = rule.prefix_len;
    let mut i = 0;
    while bits > 0 {
        let mask = if bits >= 8 {
            0xff
        } else {
            (!0u8) << (8 - bits)
        };
        if (rule.addr[i] & mask) != (addr[i] & mask) {
            return false;
        }
        bits = bits.saturating_sub(8);
        i += 1;
    }
    true
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn rule_matches(rule: &bpf_api::NetRule, addr: &[u8; 16], port: u16, protocol: u8) -> bool {
    rule.port == port && rule.protocol == protocol && addr_matches(rule, addr)
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn get_parent(unit: u32) -> Option<u32> {
    let len = net_parents_len();
    let mut i = 0;
    while i < len {
        if let Some(entry) = unsafe { load_net_parent(i) }
            && entry.child == unit
        {
            if entry.parent != unit {
                return Some(entry.parent);
            } else {
                return None;
            }
        }
        i += 1;
    }
    None
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn net_allowed(addr: &[u8; 16], port: u16, protocol: u8) -> bool {
    let mut unit = current_unit();
    loop {
        let len = net_rules_len();
        let mut i = 0;
        while i < len {
            if let Some(entry) = unsafe { load_net_rule(i) }
                && entry.unit == unit
                && rule_matches(&entry.rule, addr, port, protocol)
            {
                return true;
            }
            i += 1;
        }
        match get_parent(unit) {
            Some(p) => unit = p,
            None => break,
        }
    }
    false
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn c_str_len(buf: &[u8; 256]) -> usize {
    let mut len = 0;
    while len < buf.len() && buf[len] != 0 {
        len += 1;
    }
    len
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn trimmed_len(buf: &[u8; 256]) -> usize {
    let mut len = c_str_len(buf);
    while len > 1 && buf[len - 1] == b'/' {
        len -= 1;
    }
    len
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn path_prefix_matches(rule_path: &[u8; 256], actual_path: &[u8; 256]) -> bool {
    let prefix_len = trimmed_len(rule_path);
    if prefix_len == 0 {
        return false;
    }
    let path_len = c_str_len(actual_path);
    if prefix_len > path_len {
        return false;
    }
    let mut i = 0;
    while i < prefix_len {
        if rule_path[i] != actual_path[i] {
            return false;
        }
        i += 1;
    }
    if prefix_len == path_len {
        return true;
    }
    let last = rule_path[prefix_len - 1];
    if last == b'/' {
        return true;
    }
    actual_path.get(prefix_len).copied() == Some(b'/')
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn rule_allows_access(rule_access: u8, needed: u8) -> bool {
    if needed == 0 {
        return true;
    }
    let missing = needed & !rule_access;
    if missing == 0 {
        return true;
    }
    missing == bpf_api::FS_READ && (rule_access & bpf_api::FS_WRITE) != 0
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn fs_entry_allows(entry: &bpf_api::FsRuleEntry, path: &[u8; 256], needed: u8) -> bool {
    rule_allows_access(entry.rule.access, needed) && path_prefix_matches(&entry.rule.path, path)
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn unit_fs_allowed(unit: u32, path: &[u8; 256], needed: u8) -> bool {
    let len = fs_rules_len();
    let mut i = 0;
    while i < len {
        if let Some(entry) = unsafe { load_fs_rule(i) }
            && entry.unit == unit
            && fs_entry_allows(&entry, path, needed)
        {
            return true;
        }
        i += 1;
    }
    false
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn fs_allowed(path: &[u8; 256], needed: u8) -> bool {
    if needed == 0 {
        return true;
    }
    let mut unit = current_unit();
    let mut checked_root = unit == 0;
    loop {
        if unit_fs_allowed(unit, path, needed) {
            return true;
        }
        match get_parent(unit) {
            Some(parent) => {
                unit = parent;
                if unit == 0 {
                    checked_root = true;
                }
            }
            None => break,
        }
    }
    if !checked_root && unit_fs_allowed(0, path, needed) {
        return true;
    }
    false
}

const FMODE_READ: u32 = 1;
const FMODE_WRITE: u32 = 2;
const MAY_WRITE: i32 = 2;
const MAY_READ: i32 = 4;
const MAY_APPEND: i32 = 8;

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn access_from_mode(mode: u32) -> u8 {
    let mut access = 0;
    if (mode & FMODE_READ) != 0 {
        access |= bpf_api::FS_READ;
    }
    if (mode & FMODE_WRITE) != 0 {
        access |= bpf_api::FS_WRITE;
    }
    if access == 0 {
        access = bpf_api::FS_READ;
    }
    access
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn access_from_mask(mask: i32) -> u8 {
    let mut access = 0;
    if (mask & MAY_READ) != 0 {
        access |= bpf_api::FS_READ;
    }
    if (mask & (MAY_WRITE | MAY_APPEND)) != 0 {
        access |= bpf_api::FS_WRITE;
    }
    access
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn read_user_path(path_ptr: *const u8) -> Option<[u8; 256]> {
    if path_ptr.is_null() {
        return None;
    }
    let mut buf = [0u8; 256];
    let res = unsafe { bpf_probe_read_user_str(buf.as_mut_ptr(), buf.len() as u32, path_ptr) };
    if res < 0 { None } else { Some(buf) }
}

#[cfg(target_arch = "bpf")]
#[allow(non_camel_case_types)]
#[derive(Clone, Copy)]
#[repr(C)]
struct file {
    f_path: path,
    f_mode: u32,
}

#[cfg(target_arch = "bpf")]
#[allow(non_camel_case_types)]
#[derive(Clone, Copy)]
#[repr(C)]
struct path {
    dentry: *mut dentry,
}

#[cfg(target_arch = "bpf")]
#[allow(non_camel_case_types)]
#[derive(Clone, Copy)]
#[repr(C)]
struct dentry {
    d_name: qstr,
}

#[cfg(target_arch = "bpf")]
#[allow(non_camel_case_types)]
#[derive(Clone, Copy)]
#[repr(C)]
struct qstr {
    name: *const u8,
}

#[cfg(target_arch = "bpf")]
fn read_kernel_value<T: Copy>(ptr: *const T) -> Option<T> {
    unsafe { bpf_probe_read_kernel(ptr).ok() }
}

#[cfg(target_arch = "bpf")]
fn file_path_ptr(file: *mut c_void) -> Option<*const u8> {
    if file.is_null() {
        return None;
    }

    unsafe {
        let file_ptr = file as *const file;
        let path = read_kernel_value(core::ptr::addr_of!((*file_ptr).f_path))?;
        let dentry_ptr = path.dentry;
        if dentry_ptr.is_null() {
            return None;
        }
        let name = read_kernel_value(core::ptr::addr_of!((*dentry_ptr).d_name))?;
        let name_ptr = name.name;
        if name_ptr.is_null() {
            None
        } else {
            Some(name_ptr)
        }
    }
}

#[cfg(target_arch = "bpf")]
fn file_mode_bits(file: *mut c_void) -> Option<u32> {
    if file.is_null() {
        return None;
    }

    unsafe {
        let file_ptr = file as *const file;
        read_kernel_value(core::ptr::addr_of!((*file_ptr).f_mode))
    }
}

#[cfg(target_arch = "bpf")]
fn dentry_path_ptr(dentry: *mut c_void) -> Option<*const u8> {
    if dentry.is_null() {
        return None;
    }

    unsafe {
        let dentry_ptr = dentry as *const dentry;
        let name = read_kernel_value(core::ptr::addr_of!((*dentry_ptr).d_name))?;
        let name_ptr = name.name;
        if name_ptr.is_null() {
            None
        } else {
            Some(name_ptr)
        }
    }
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn fs_event(action: u8, path: &[u8; 256], allowed: bool) -> Event {
    let mut event = Event {
        pid: unsafe { (bpf_get_current_pid_tgid() >> 32) as u32 },
        unit: {
            let unit = current_unit();
            if unit > u8::MAX as u32 {
                u8::MAX
            } else {
                unit as u8
            }
        },
        action,
        verdict: if allowed { 0 } else { 1 },
        reserved: 0,
        container_id: 0,
        caps: 0,
        path_or_addr: [0; 256],
    };

    let mut len = path.iter().position(|&b| b == 0).unwrap_or(path.len());
    if len >= event.path_or_addr.len() {
        len = event.path_or_addr.len() - 1;
    }
    event.path_or_addr[..len].copy_from_slice(&path[..len]);
    event.path_or_addr[len] = 0;

    event
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn publish_event(event: &Event) {
    let ringbuf_ptr = {
        #[cfg(target_arch = "bpf")]
        {
            core::ptr::addr_of_mut!(EVENTS) as *mut c_void
        }

        #[cfg(any(test, feature = "fuzzing"))]
        {
            core::ptr::addr_of!(EVENTS) as *const _ as *mut c_void
        }
    };
    unsafe {
        bpf_ringbuf_output(
            ringbuf_ptr,
            event as *const _ as *const c_void,
            size_of::<Event>() as u64,
            0,
        );
    }
    increment_event_count();
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
#[repr(C)]
struct SockAddr {
    user_ip4: u32,
    user_ip6: [u32; 4],
    user_port: u16,
    family: u16,
    protocol: u32,
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn check4(ctx: *mut c_void) -> i32 {
    let ctx = unsafe { &*(ctx as *const SockAddr) };
    let mut addr = [0u8; 16];
    addr[..4].copy_from_slice(&ctx.user_ip4.to_be_bytes());
    let port = u16::from_be(ctx.user_port);
    let proto = ctx.protocol as u8;
    if net_allowed(&addr, port, proto) {
        0
    } else {
        deny_with_mode()
    }
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn check6(ctx: *mut c_void) -> i32 {
    let ctx = unsafe { &*(ctx as *const SockAddr) };
    let mut addr = [0u8; 16];
    for (i, part) in ctx.user_ip6.iter().enumerate() {
        addr[i * 4..(i + 1) * 4].copy_from_slice(&part.to_be_bytes());
    }
    let port = u16::from_be(ctx.user_port);
    let proto = ctx.protocol as u8;
    if net_allowed(&addr, port, proto) {
        0
    } else {
        deny_with_mode()
    }
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
unsafe extern "C" {
    fn bpf_probe_read_user_str(dst: *mut u8, size: u32, src: *const u8) -> i32;
    fn bpf_ringbuf_output(ringbuf: *mut c_void, data: *const c_void, len: u64, flags: u64) -> i64;
    fn bpf_get_current_pid_tgid() -> u64;
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
#[unsafe(no_mangle)]
#[unsafe(link_section = "lsm/bprm_check_security")]
pub extern "C" fn bprm_check_security(ctx: *mut c_void) -> i32 {
    let filename_ptr = unsafe { *(ctx as *const *const u8) };
    let mut buf = [0u8; 256];
    if unsafe { bpf_probe_read_user_str(buf.as_mut_ptr(), buf.len() as u32, filename_ptr) } < 0 {
        return deny_with_mode();
    }
    let len = exec_allowlist_len();
    let mut i = 0;
    while i < len {
        if let Some(entry) = unsafe { load_exec_allow_entry(i) }
            && path_matches(&entry.path, &buf)
        {
            return 0;
        }
        i += 1;
    }
    deny_with_mode()
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
#[unsafe(no_mangle)]
#[unsafe(link_section = "cgroup/connect4")]
pub extern "C" fn connect4(ctx: *mut c_void) -> i32 {
    check4(ctx)
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
#[unsafe(no_mangle)]
#[unsafe(link_section = "cgroup/connect6")]
pub extern "C" fn connect6(ctx: *mut c_void) -> i32 {
    check6(ctx)
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
#[unsafe(no_mangle)]
#[unsafe(link_section = "cgroup/sendmsg4")]
pub extern "C" fn sendmsg4(ctx: *mut c_void) -> i32 {
    check4(ctx)
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
#[unsafe(no_mangle)]
#[unsafe(link_section = "cgroup/sendmsg6")]
pub extern "C" fn sendmsg6(ctx: *mut c_void) -> i32 {
    check6(ctx)
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
#[unsafe(no_mangle)]
#[unsafe(link_section = "lsm/file_open")]
pub extern "C" fn file_open(file: *mut c_void, _cred: *mut c_void) -> i32 {
    let path_ptr = match file_path_ptr(file) {
        Some(ptr) => ptr,
        None => return deny_with_mode(),
    };
    let Some(path) = read_user_path(path_ptr) else {
        return deny_with_mode();
    };
    let access = file_mode_bits(file)
        .map(access_from_mode)
        .unwrap_or(bpf_api::FS_READ);
    let allowed = fs_allowed(&path, access);
    let event = fs_event(ACTION_OPEN, &path, allowed);
    publish_event(&event);
    if allowed { 0 } else { deny_with_mode() }
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
#[unsafe(no_mangle)]
#[unsafe(link_section = "lsm/file_permission")]
pub extern "C" fn file_permission(file: *mut c_void, mask: i32) -> i32 {
    let access = access_from_mask(mask);
    if access == 0 {
        return 0;
    }
    let path_ptr = match file_path_ptr(file) {
        Some(ptr) => ptr,
        None => return deny_with_mode(),
    };
    let Some(path) = read_user_path(path_ptr) else {
        return deny_with_mode();
    };
    if fs_allowed(&path, access) {
        0
    } else {
        let event = fs_event(ACTION_OPEN, &path, false);
        publish_event(&event);
        deny_with_mode()
    }
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
#[unsafe(no_mangle)]
#[unsafe(link_section = "lsm/inode_rename")]
pub extern "C" fn inode_rename(
    _old_dir: *mut c_void,
    old_dentry: *mut c_void,
    _new_dir: *mut c_void,
    new_dentry: *mut c_void,
    _flags: u32,
) -> i32 {
    let old_path_ptr = match dentry_path_ptr(old_dentry) {
        Some(ptr) => ptr,
        None => return deny_with_mode(),
    };
    let Some(old_path) = read_user_path(old_path_ptr) else {
        return deny_with_mode();
    };
    let new_path_ptr = match dentry_path_ptr(new_dentry) {
        Some(ptr) => ptr,
        None => return deny_with_mode(),
    };
    let Some(new_path) = read_user_path(new_path_ptr) else {
        return deny_with_mode();
    };

    let mut allowed = true;

    if !fs_allowed(&old_path, bpf_api::FS_WRITE) {
        let event = fs_event(ACTION_RENAME, &old_path, false);
        publish_event(&event);
        allowed = false;
    }

    if !fs_allowed(&new_path, bpf_api::FS_WRITE) {
        let event = fs_event(ACTION_RENAME, &new_path, false);
        publish_event(&event);
        allowed = false;
    }

    if allowed { 0 } else { deny_with_mode() }
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
#[unsafe(no_mangle)]
#[unsafe(link_section = "lsm/inode_unlink")]
pub extern "C" fn inode_unlink(_dir: *mut c_void, dentry: *mut c_void) -> i32 {
    let path_ptr = match dentry_path_ptr(dentry) {
        Some(ptr) => ptr,
        None => return deny_with_mode(),
    };
    let Some(path) = read_user_path(path_ptr) else {
        return deny_with_mode();
    };
    if fs_allowed(&path, bpf_api::FS_WRITE) {
        0
    } else {
        let event = fs_event(ACTION_UNLINK, &path, false);
        publish_event(&event);
        deny_with_mode()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bpf_api::{FS_READ, FS_WRITE};
    use bpf_host::{
        fs::{TestDentry, TestFile},
        resolve_host,
    };
    use core::ffi::c_void;
    use std::ptr;
    use std::sync::Mutex;

    static LAST_EVENT: Mutex<Option<Event>> = Mutex::new(None);
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[unsafe(no_mangle)]
    extern "C" fn bpf_ringbuf_output(
        _ringbuf: *mut c_void,
        data: *const c_void,
        len: u64,
        _flags: u64,
    ) -> i64 {
        assert_eq!(len as usize, core::mem::size_of::<Event>());
        let event = unsafe { *(data as *const Event) };
        *LAST_EVENT.lock().unwrap() = Some(event);
        0
    }

    #[unsafe(no_mangle)]
    extern "C" fn bpf_get_current_pid_tgid() -> u64 {
        1234u64 << 32
    }

    #[unsafe(no_mangle)]
    extern "C" fn bpf_probe_read_user_str(dst: *mut u8, size: u32, src: *const u8) -> i32 {
        if dst.is_null() || src.is_null() || size == 0 {
            return -1;
        }
        let size = size as usize;
        let mut copied = 0usize;
        unsafe {
            while copied < size {
                let byte = *src.add(copied);
                *dst.add(copied) = byte;
                copied += 1;
                if byte == 0 {
                    return copied as i32;
                }
            }
            if size > 0 {
                *dst.add(size - 1) = 0;
            }
        }
        size as i32
    }

    #[test]
    fn bprm_check_security_denies_without_rule() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_network_state();
        reset_fs_state();
        reset_exec_state();
        assert!(
            !is_observe_mode(),
            "enforce mode should be active by default"
        );
        let path = c_string("/workspace/bin/forbidden");
        let mut filename_ptr = path.as_ptr();
        let mut ctx = (&mut filename_ptr) as *mut *const u8;
        let result = bprm_check_security((&mut ctx) as *mut _ as *mut c_void);
        assert_ne!(result, 0);
    }

    #[test]
    fn bprm_check_security_observe_mode_allows_without_rule() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_network_state();
        reset_fs_state();
        reset_exec_state();
        enable_observe_mode();
        assert!(is_observe_mode(), "observe mode should be enabled");
        let path = c_string("/workspace/bin/forbidden");
        let mut filename_ptr = path.as_ptr();
        let mut ctx = (&mut filename_ptr) as *mut *const u8;
        let result = bprm_check_security((&mut ctx) as *mut _ as *mut c_void);
        assert_eq!(result, 0);
    }

    #[test]
    fn file_open_emits_event() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_network_state();
        reset_fs_state();
        EVENT_COUNTS.clear();
        LAST_EVENT.lock().unwrap().take();
        let path = "/workspace/allowed/file.txt";
        set_fs_rules(&[fs_rule_entry(0, path, FS_READ | FS_WRITE)]);
        let path_bytes = c_string(path);
        let mut file = TestFile {
            path: path_bytes.as_ptr(),
            mode: FMODE_READ,
        };
        let result = file_open((&mut file) as *mut _ as *mut c_void, ptr::null_mut());
        assert_eq!(result, 0);
        let event = LAST_EVENT.lock().unwrap().as_ref().copied().expect("event");
        assert_eq!(event.pid, 1234);
        assert_eq!(event.unit, 0);
        assert_eq!(event.action, ACTION_OPEN);
        assert_eq!(event.verdict, 0);
        assert_eq!(bytes_to_string(&event.path_or_addr), path);
        let count = EVENT_COUNTS.get(0).unwrap_or(0);
        assert_eq!(count, 1);
    }

    #[test]
    fn file_open_denies_without_rule() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_network_state();
        reset_fs_state();
        EVENT_COUNTS.clear();
        LAST_EVENT.lock().unwrap().take();
        let path = "/workspace/forbidden.txt";
        let path_bytes = c_string(path);
        let mut file = TestFile {
            path: path_bytes.as_ptr(),
            mode: FMODE_READ,
        };
        let result = file_open((&mut file) as *mut _ as *mut c_void, ptr::null_mut());
        assert_ne!(result, 0);
        let event = LAST_EVENT.lock().unwrap().as_ref().copied().expect("event");
        assert_eq!(event.action, ACTION_OPEN);
        assert_eq!(event.verdict, 1);
        assert_eq!(bytes_to_string(&event.path_or_addr), path);
    }

    #[test]
    fn file_open_observe_mode_allows_but_logs() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_network_state();
        reset_fs_state();
        enable_observe_mode();
        assert!(is_observe_mode(), "observe mode should be enabled");
        EVENT_COUNTS.clear();
        LAST_EVENT.lock().unwrap().take();
        let path = "/workspace/forbidden.txt";
        let path_bytes = c_string(path);
        let mut file = TestFile {
            path: path_bytes.as_ptr(),
            mode: FMODE_READ,
        };
        let result = file_open((&mut file) as *mut _ as *mut c_void, ptr::null_mut());
        assert_eq!(result, 0);
        let event = LAST_EVENT.lock().unwrap().as_ref().copied().expect("event");
        assert_eq!(event.action, ACTION_OPEN);
        assert_eq!(event.verdict, 1);
        assert_eq!(bytes_to_string(&event.path_or_addr), path);
        let count = EVENT_COUNTS.get(0).unwrap_or(0);
        assert_eq!(count, 1);
    }

    #[test]
    fn file_permission_respects_access_bits() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_network_state();
        reset_fs_state();
        let path = "/workspace/read-only";
        set_fs_rules(&[fs_rule_entry(0, path, FS_READ)]);
        let path_bytes = c_string(path);
        let mut file = TestFile {
            path: path_bytes.as_ptr(),
            mode: FMODE_READ,
        };
        let file_ptr = (&mut file) as *mut _ as *mut c_void;
        LAST_EVENT.lock().unwrap().take();
        assert_eq!(file_permission(file_ptr, MAY_READ), 0);
        assert!(LAST_EVENT.lock().unwrap().is_none());

        LAST_EVENT.lock().unwrap().take();
        assert_ne!(file_permission(file_ptr, MAY_WRITE), 0);
        let event = LAST_EVENT.lock().unwrap().as_ref().copied().expect("event");
        assert_eq!(event.action, ACTION_OPEN);
        assert_eq!(event.verdict, 1);
        assert_eq!(bytes_to_string(&event.path_or_addr), path);

        set_fs_rules(&[fs_rule_entry(0, path, FS_READ | FS_WRITE)]);
        LAST_EVENT.lock().unwrap().take();
        assert_eq!(file_permission(file_ptr, MAY_WRITE), 0);
        assert!(LAST_EVENT.lock().unwrap().is_none());
    }

    #[test]
    fn file_permission_observe_mode_allows_but_logs() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_network_state();
        reset_fs_state();
        enable_observe_mode();
        assert!(is_observe_mode(), "observe mode should be enabled");
        let path = "/workspace/read-only";
        set_fs_rules(&[fs_rule_entry(0, path, FS_READ)]);
        let path_bytes = c_string(path);
        let mut file = TestFile {
            path: path_bytes.as_ptr(),
            mode: FMODE_READ,
        };
        let file_ptr = (&mut file) as *mut _ as *mut c_void;
        LAST_EVENT.lock().unwrap().take();
        let result = file_permission(file_ptr, MAY_WRITE);
        assert_eq!(result, 0);
        let event = LAST_EVENT.lock().unwrap().as_ref().copied().expect("event");
        assert_eq!(event.action, ACTION_OPEN);
        assert_eq!(event.verdict, 1);
        assert_eq!(bytes_to_string(&event.path_or_addr), path);
    }

    #[test]
    fn file_open_rejects_null_path_pointer() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_network_state();
        reset_fs_state();
        EVENT_COUNTS.clear();
        LAST_EVENT.lock().unwrap().take();
        let mut file = TestFile {
            path: ptr::null(),
            mode: FMODE_READ,
        };
        let result = file_open((&mut file) as *mut _ as *mut c_void, ptr::null_mut());
        assert_ne!(result, 0);
        assert!(LAST_EVENT.lock().unwrap().is_none());
        let count = EVENT_COUNTS.get(0).unwrap_or(0);
        assert_eq!(count, 0);
    }

    #[test]
    fn file_permission_allows_matching_rule() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_network_state();
        reset_fs_state();
        let base_path = "/workspace/data";
        set_fs_rules(&[fs_rule_entry(0, base_path, FS_READ | FS_WRITE)]);
        let file_path = c_string("/workspace/data/reports/output.log");
        let mut file = TestFile {
            path: file_path.as_ptr(),
            mode: FMODE_READ | FMODE_WRITE,
        };
        let file_ptr = (&mut file) as *mut _ as *mut c_void;
        assert_eq!(file_permission(file_ptr, MAY_READ), 0);
        assert_eq!(file_permission(file_ptr, MAY_WRITE), 0);
    }

    #[test]
    fn file_permission_denies_without_matching_rule() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_network_state();
        reset_fs_state();
        let file_path = c_string("/workspace/forbidden/data.txt");
        let mut file = TestFile {
            path: file_path.as_ptr(),
            mode: FMODE_READ,
        };
        let file_ptr = (&mut file) as *mut _ as *mut c_void;
        assert_ne!(file_permission(file_ptr, MAY_READ), 0);
    }

    #[test]
    fn file_permission_allows_prefix_rule() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_network_state();
        reset_fs_state();
        let rule_path = "/workspace/data";
        set_fs_rules(&[fs_rule_entry(0, rule_path, FS_READ | FS_WRITE)]);
        let file_path = c_string("/workspace/data/subdir/file.txt");
        let mut file = TestFile {
            path: file_path.as_ptr(),
            mode: FMODE_READ,
        };
        let file_ptr = (&mut file) as *mut _ as *mut c_void;
        assert_eq!(file_permission(file_ptr, MAY_READ), 0);
    }

    #[test]
    fn file_permission_denies_mismatched_prefix() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_network_state();
        reset_fs_state();
        let rule_path = "/workspace/data";
        set_fs_rules(&[fs_rule_entry(0, rule_path, FS_READ | FS_WRITE)]);
        let file_path = c_string("/workspace/database");
        let mut file = TestFile {
            path: file_path.as_ptr(),
            mode: FMODE_READ,
        };
        let file_ptr = (&mut file) as *mut _ as *mut c_void;
        assert_ne!(file_permission(file_ptr, MAY_READ), 0);
    }

    #[test]
    fn inode_rename_denies_when_source_not_allowed() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_network_state();
        reset_fs_state();
        EVENT_COUNTS.clear();
        LAST_EVENT.lock().unwrap().take();
        let old_path = "/workspace/src.txt";
        let new_path = "/workspace/dst.txt";
        set_fs_rules(&[fs_rule_entry(0, new_path, FS_WRITE)]);
        let old_bytes = c_string(old_path);
        let new_bytes = c_string(new_path);
        let mut old_dentry = TestDentry {
            name: old_bytes.as_ptr(),
        };
        let mut new_dentry = TestDentry {
            name: new_bytes.as_ptr(),
        };
        let result = inode_rename(
            ptr::null_mut(),
            (&mut old_dentry) as *mut _ as *mut c_void,
            ptr::null_mut(),
            (&mut new_dentry) as *mut _ as *mut c_void,
            0,
        );
        assert_ne!(result, 0);
        let event = LAST_EVENT.lock().unwrap().as_ref().copied().expect("event");
        assert_eq!(event.action, ACTION_RENAME);
        assert_eq!(event.verdict, 1);
        assert_eq!(bytes_to_string(&event.path_or_addr), old_path);
        let count = EVENT_COUNTS.get(0).unwrap_or(0);
        assert_eq!(count, 1);
    }

    #[test]
    fn inode_rename_denies_when_target_not_allowed() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_network_state();
        reset_fs_state();
        EVENT_COUNTS.clear();
        LAST_EVENT.lock().unwrap().take();
        let old_path = "/workspace/allowed.txt";
        let new_path = "/workspace/blocked.txt";
        set_fs_rules(&[fs_rule_entry(0, old_path, FS_WRITE)]);
        let old_bytes = c_string(old_path);
        let new_bytes = c_string(new_path);
        let mut old_dentry = TestDentry {
            name: old_bytes.as_ptr(),
        };
        let mut new_dentry = TestDentry {
            name: new_bytes.as_ptr(),
        };
        let result = inode_rename(
            ptr::null_mut(),
            (&mut old_dentry) as *mut _ as *mut c_void,
            ptr::null_mut(),
            (&mut new_dentry) as *mut _ as *mut c_void,
            0,
        );
        assert_ne!(result, 0);
        let event = LAST_EVENT.lock().unwrap().as_ref().copied().expect("event");
        assert_eq!(event.action, ACTION_RENAME);
        assert_eq!(event.verdict, 1);
        assert_eq!(bytes_to_string(&event.path_or_addr), new_path);
        let count = EVENT_COUNTS.get(0).unwrap_or(0);
        assert_eq!(count, 1);
    }

    #[test]
    fn inode_rename_allows_when_rules_cover_both_paths() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_network_state();
        reset_fs_state();
        EVENT_COUNTS.clear();
        LAST_EVENT.lock().unwrap().take();
        let old_path = "/workspace/dir/source.txt";
        let new_path = "/workspace/dir/dest.txt";
        set_fs_rules(&[fs_rule_entry(0, "/workspace/dir", FS_WRITE)]);
        let old_bytes = c_string(old_path);
        let new_bytes = c_string(new_path);
        let mut old_dentry = TestDentry {
            name: old_bytes.as_ptr(),
        };
        let mut new_dentry = TestDentry {
            name: new_bytes.as_ptr(),
        };
        let result = inode_rename(
            ptr::null_mut(),
            (&mut old_dentry) as *mut _ as *mut c_void,
            ptr::null_mut(),
            (&mut new_dentry) as *mut _ as *mut c_void,
            0,
        );
        assert_eq!(result, 0);
        assert!(LAST_EVENT.lock().unwrap().is_none());
        let count = EVENT_COUNTS.get(0).unwrap_or(0);
        assert_eq!(count, 0);
    }

    #[test]
    fn inode_rename_observe_mode_allows_but_logs() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_network_state();
        reset_fs_state();
        enable_observe_mode();
        assert!(is_observe_mode(), "observe mode should be enabled");
        EVENT_COUNTS.clear();
        LAST_EVENT.lock().unwrap().take();
        let old_path = "/workspace/src.txt";
        let new_path = "/workspace/dst.txt";
        let old_bytes = c_string(old_path);
        let new_bytes = c_string(new_path);
        let mut old_dentry = TestDentry {
            name: old_bytes.as_ptr(),
        };
        let mut new_dentry = TestDentry {
            name: new_bytes.as_ptr(),
        };
        let result = inode_rename(
            ptr::null_mut(),
            (&mut old_dentry) as *mut _ as *mut c_void,
            ptr::null_mut(),
            (&mut new_dentry) as *mut _ as *mut c_void,
            0,
        );
        assert_eq!(result, 0);
        let event = LAST_EVENT.lock().unwrap().as_ref().copied().expect("event");
        assert_eq!(event.action, ACTION_RENAME);
        assert_eq!(event.verdict, 1);
        assert_eq!(bytes_to_string(&event.path_or_addr), new_path);
        let count = EVENT_COUNTS.get(0).unwrap_or(0);
        assert_eq!(count, 2);
    }

    #[test]
    fn inode_rename_requires_non_null_paths() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_network_state();
        reset_fs_state();
        EVENT_COUNTS.clear();
        LAST_EVENT.lock().unwrap().take();
        let mut old_dentry = TestDentry { name: ptr::null() };
        let mut new_dentry = TestDentry { name: ptr::null() };
        let result = inode_rename(
            ptr::null_mut(),
            (&mut old_dentry) as *mut _ as *mut c_void,
            ptr::null_mut(),
            (&mut new_dentry) as *mut _ as *mut c_void,
            0,
        );
        assert_ne!(result, 0);
        assert!(LAST_EVENT.lock().unwrap().is_none());
        let count = EVENT_COUNTS.get(0).unwrap_or(0);
        assert_eq!(count, 0);
    }

    #[test]
    fn inode_unlink_requires_write_permission() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_network_state();
        reset_fs_state();
        let path = "/workspace/temp.txt";
        let path_bytes = c_string(path);
        let mut dentry = TestDentry {
            name: path_bytes.as_ptr(),
        };
        LAST_EVENT.lock().unwrap().take();
        assert_ne!(
            inode_unlink(ptr::null_mut(), (&mut dentry) as *mut _ as *mut c_void),
            0
        );
        let event = LAST_EVENT.lock().unwrap().as_ref().copied().expect("event");
        assert_eq!(event.action, ACTION_UNLINK);
        assert_eq!(event.verdict, 1);
        assert_eq!(bytes_to_string(&event.path_or_addr), path);

        set_fs_rules(&[fs_rule_entry(0, path, FS_READ | FS_WRITE)]);
        LAST_EVENT.lock().unwrap().take();
        assert_eq!(
            inode_unlink(ptr::null_mut(), (&mut dentry) as *mut _ as *mut c_void),
            0
        );
        assert!(LAST_EVENT.lock().unwrap().is_none());

        set_fs_rules(&[fs_rule_entry(0, path, FS_READ)]);
        LAST_EVENT.lock().unwrap().take();
        assert_ne!(
            inode_unlink(ptr::null_mut(), (&mut dentry) as *mut _ as *mut c_void),
            0
        );
        let event = LAST_EVENT.lock().unwrap().as_ref().copied().expect("event");
        assert_eq!(event.action, ACTION_UNLINK);
        assert_eq!(event.verdict, 1);
        assert_eq!(bytes_to_string(&event.path_or_addr), path);
    }

    #[test]
    fn inode_unlink_observe_mode_allows_but_logs() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_network_state();
        reset_fs_state();
        enable_observe_mode();
        assert!(is_observe_mode(), "observe mode should be enabled");
        let path = "/workspace/temp.txt";
        let path_bytes = c_string(path);
        let mut dentry = TestDentry {
            name: path_bytes.as_ptr(),
        };
        LAST_EVENT.lock().unwrap().take();
        let result = inode_unlink(ptr::null_mut(), (&mut dentry) as *mut _ as *mut c_void);
        assert_eq!(result, 0);
        let event = LAST_EVENT.lock().unwrap().as_ref().copied().expect("event");
        assert_eq!(event.action, ACTION_UNLINK);
        assert_eq!(event.verdict, 1);
        assert_eq!(bytes_to_string(&event.path_or_addr), path);
    }

    #[test]
    fn inode_unlink_requires_valid_path_pointer() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_network_state();
        reset_fs_state();
        LAST_EVENT.lock().unwrap().take();
        let mut dentry = TestDentry { name: ptr::null() };
        let result = inode_unlink(ptr::null_mut(), (&mut dentry) as *mut _ as *mut c_void);
        assert_ne!(result, 0);
        assert!(LAST_EVENT.lock().unwrap().is_none());
    }

    #[test]
    fn file_rules_inherit_across_units() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_network_state();
        reset_fs_state();
        set_fs_rules(&[fs_rule_entry(1, "/workspace/shared", FS_READ)]);
        set_net_parents(&[bpf_api::NetParentEntry {
            child: 2,
            parent: 1,
        }]);
        let path = "/workspace/shared/file.txt";
        let path_bytes = c_string(path);
        let mut file = TestFile {
            path: path_bytes.as_ptr(),
            mode: FMODE_READ,
        };
        unsafe {
            CURRENT_UNIT = 2;
        }
        assert_eq!(
            file_open((&mut file) as *mut _ as *mut c_void, ptr::null_mut()),
            0
        );
        let other_path = "/workspace/other.txt";
        let other_bytes = c_string(other_path);
        let mut other_file = TestFile {
            path: other_bytes.as_ptr(),
            mode: FMODE_READ,
        };
        assert_ne!(
            file_open((&mut other_file) as *mut _ as *mut c_void, ptr::null_mut()),
            0
        );
    }

    #[test]
    fn file_rules_apply_globally_without_parents() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_network_state();
        reset_fs_state();
        set_fs_rules(&[fs_rule_entry(0, "/workspace/global", FS_READ | FS_WRITE)]);
        let path = "/workspace/global/output.txt";
        let path_bytes = c_string(path);
        let mut file = TestFile {
            path: path_bytes.as_ptr(),
            mode: FMODE_WRITE,
        };
        unsafe {
            CURRENT_UNIT = 7;
        }
        assert_eq!(
            file_open((&mut file) as *mut _ as *mut c_void, ptr::null_mut()),
            0
        );
    }

    #[test]
    fn file_events_include_workload_unit() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_network_state();
        reset_fs_state();
        set_workload_unit(1234, 5);
        set_fs_rules(&[fs_rule_entry(0, "/workspace/data", FS_READ)]);
        let path = "/workspace/data/file.txt";
        let path_bytes = c_string(path);
        let mut file = TestFile {
            path: path_bytes.as_ptr(),
            mode: FMODE_READ,
        };
        unsafe {
            CURRENT_UNIT = 0;
        }
        LAST_EVENT.lock().unwrap().take();
        assert_eq!(
            file_open((&mut file) as *mut _ as *mut c_void, ptr::null_mut()),
            0
        );
        let event = LAST_EVENT.lock().unwrap().as_ref().copied().expect("event");
        assert_eq!(event.unit, 5);
    }

    fn rule_entry(
        unit: u32,
        addr: std::net::IpAddr,
        port: u16,
        proto: u8,
    ) -> bpf_api::NetRuleEntry {
        let mut bytes = [0u8; 16];
        let prefix = match addr {
            std::net::IpAddr::V4(v4) => {
                bytes[..4].copy_from_slice(&v4.octets());
                32
            }
            std::net::IpAddr::V6(v6) => {
                bytes.copy_from_slice(&v6.octets());
                128
            }
        };
        bpf_api::NetRuleEntry {
            unit,
            rule: bpf_api::NetRule {
                addr: bytes,
                protocol: proto,
                prefix_len: prefix,
                port,
            },
        }
    }

    fn set_net_rules(entries: &[bpf_api::NetRuleEntry]) {
        NET_RULES.clear();
        NET_RULES_LENGTH.clear();
        for (idx, entry) in entries.iter().enumerate() {
            NET_RULES.set(idx as u32, *entry);
        }
        NET_RULES_LENGTH.set(0, entries.len() as u32);
    }

    fn set_net_parents(entries: &[bpf_api::NetParentEntry]) {
        NET_PARENTS.clear();
        NET_PARENTS_LENGTH.clear();
        for (idx, entry) in entries.iter().enumerate() {
            NET_PARENTS.set(idx as u32, *entry);
        }
        NET_PARENTS_LENGTH.set(0, entries.len() as u32);
    }

    fn reset_mode_flags() {
        MODE_FLAGS.clear();
        MODE_FLAGS.set(0, bpf_api::MODE_FLAG_ENFORCE);
    }

    fn reset_network_state() {
        NET_RULES.clear();
        NET_RULES_LENGTH.clear();
        NET_PARENTS.clear();
        NET_PARENTS_LENGTH.clear();
        reset_mode_flags();
        clear_workload_units();
        unsafe {
            CURRENT_UNIT = 0;
        }
    }

    fn set_fs_rules(entries: &[bpf_api::FsRuleEntry]) {
        FS_RULES.clear();
        FS_RULES_LENGTH.clear();
        for (idx, entry) in entries.iter().enumerate() {
            FS_RULES.set(idx as u32, *entry);
        }
        FS_RULES_LENGTH.set(0, entries.len() as u32);
    }

    fn reset_fs_state() {
        FS_RULES.clear();
        FS_RULES_LENGTH.clear();
        reset_mode_flags();
        clear_workload_units();
        unsafe {
            CURRENT_UNIT = 0;
        }
    }

    fn enable_observe_mode() {
        reset_mode_flags();
        MODE_FLAGS.set(0, bpf_api::MODE_FLAG_OBSERVE);
    }

    fn reset_exec_state() {
        EXEC_ALLOWLIST.clear();
        EXEC_ALLOWLIST_LENGTH.clear();
    }

    fn fs_rule_entry(unit: u32, path: &str, access: u8) -> bpf_api::FsRuleEntry {
        let bytes = path.as_bytes();
        assert!(bytes.len() < 256, "path too long");
        let mut encoded = [0u8; 256];
        encoded[..bytes.len()].copy_from_slice(bytes);
        bpf_api::FsRuleEntry {
            unit,
            rule: bpf_api::FsRule {
                access,
                reserved: [0; 3],
                path: encoded,
            },
        }
    }

    fn c_string(path: &str) -> Vec<u8> {
        let mut bytes = path.as_bytes().to_vec();
        bytes.push(0);
        bytes
    }

    fn bytes_to_string(bytes: &[u8; 256]) -> String {
        let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        String::from_utf8(bytes[..len].to_vec()).unwrap()
    }

    fn ipv6_words(addr: std::net::Ipv6Addr) -> [u32; 4] {
        let octets = addr.octets();
        let mut words = [0u32; 4];
        for (i, chunk) in octets.chunks_exact(4).enumerate() {
            words[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        words
    }

    #[test]
    fn connect4_respects_rules() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_network_state();
        let ip = resolve_host("localhost")
            .unwrap()
            .into_iter()
            .find(|i| i.is_ipv4())
            .unwrap();
        let fallback = std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 1));
        set_net_rules(&[rule_entry(1, fallback, 80, 6), rule_entry(1, ip, 80, 6)]);
        set_net_parents(&[
            bpf_api::NetParentEntry {
                child: 1,
                parent: 0,
            },
            bpf_api::NetParentEntry {
                child: 2,
                parent: 1,
            },
        ]);
        let denied_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 1));
        let allowed = SockAddr {
            user_ip4: match ip {
                std::net::IpAddr::V4(v4) => u32::from_be_bytes(v4.octets()),
                _ => 0,
            },
            user_ip6: [0; 4],
            user_port: 80u16.to_be(),
            family: 2,
            protocol: 6,
        };
        let other = SockAddr {
            user_ip4: match denied_ip {
                std::net::IpAddr::V4(v4) => u32::from_be_bytes(v4.octets()),
                _ => 0,
            },
            user_ip6: [0; 4],
            user_port: 80u16.to_be(),
            family: 2,
            protocol: 6,
        };
        unsafe {
            CURRENT_UNIT = 1;
        }
        assert_eq!(connect4(&allowed as *const _ as *mut c_void), 0);
        assert_ne!(connect4(&other as *const _ as *mut c_void), 0);
        assert_eq!(sendmsg4(&allowed as *const _ as *mut c_void), 0);
        assert_ne!(sendmsg4(&other as *const _ as *mut c_void), 0);
        unsafe {
            CURRENT_UNIT = 2;
        }
        assert_eq!(connect4(&allowed as *const _ as *mut c_void), 0);
        assert_eq!(sendmsg4(&allowed as *const _ as *mut c_void), 0);
        assert_ne!(connect4(&other as *const _ as *mut c_void), 0);
        unsafe {
            CURRENT_UNIT = 3;
        }
        assert_ne!(connect4(&allowed as *const _ as *mut c_void), 0);
        assert_ne!(sendmsg4(&allowed as *const _ as *mut c_void), 0);
    }

    #[test]
    fn connect4_observe_mode_allows_denied_requests() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_network_state();
        enable_observe_mode();
        assert!(is_observe_mode(), "observe mode should be enabled");
        let denied = SockAddr {
            user_ip4: u32::from_be_bytes([203, 0, 113, 2]),
            user_ip6: [0; 4],
            user_port: 8080u16.to_be(),
            family: 2,
            protocol: 6,
        };
        assert_eq!(connect4(&denied as *const _ as *mut c_void), 0);
        assert_eq!(sendmsg4(&denied as *const _ as *mut c_void), 0);
    }

    #[test]
    fn connect6_respects_rules() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_network_state();
        let ip = resolve_host("localhost")
            .unwrap()
            .into_iter()
            .find(|i| i.is_ipv6())
            .unwrap();
        let fallback = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        set_net_rules(&[
            rule_entry(1, std::net::IpAddr::V6(fallback), 80, 6),
            rule_entry(1, ip, 80, 6),
        ]);
        set_net_parents(&[
            bpf_api::NetParentEntry {
                child: 1,
                parent: 0,
            },
            bpf_api::NetParentEntry {
                child: 2,
                parent: 1,
            },
        ]);
        let denied = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let mut ip6_words = [0u32; 4];
        if let std::net::IpAddr::V6(v6) = ip {
            ip6_words = ipv6_words(v6);
        }
        let allowed = SockAddr {
            user_ip4: 0,
            user_ip6: ip6_words,
            user_port: 80u16.to_be(),
            family: 10,
            protocol: 6,
        };
        let other = SockAddr {
            user_ip4: 0,
            user_ip6: ipv6_words(denied),
            user_port: 80u16.to_be(),
            family: 10,
            protocol: 6,
        };
        unsafe {
            CURRENT_UNIT = 1;
        }
        assert_eq!(connect6(&allowed as *const _ as *mut c_void), 0);
        assert_ne!(connect6(&other as *const _ as *mut c_void), 0);
        assert_eq!(sendmsg6(&allowed as *const _ as *mut c_void), 0);
        assert_ne!(sendmsg6(&other as *const _ as *mut c_void), 0);
        unsafe {
            CURRENT_UNIT = 2;
        }
        assert_eq!(connect6(&allowed as *const _ as *mut c_void), 0);
        assert_eq!(sendmsg6(&allowed as *const _ as *mut c_void), 0);
        assert_ne!(connect6(&other as *const _ as *mut c_void), 0);
        unsafe {
            CURRENT_UNIT = 3;
        }
        assert_ne!(connect6(&allowed as *const _ as *mut c_void), 0);
        assert_ne!(sendmsg6(&allowed as *const _ as *mut c_void), 0);
    }

    #[test]
    fn connect6_observe_mode_allows_denied_requests() {
        let _g = TEST_LOCK.lock().unwrap();
        reset_network_state();
        enable_observe_mode();
        assert!(is_observe_mode(), "observe mode should be enabled");
        let denied_addr = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let denied = SockAddr {
            user_ip4: 0,
            user_ip6: ipv6_words(denied_addr),
            user_port: 8080u16.to_be(),
            family: 10,
            protocol: 6,
        };
        assert_eq!(connect6(&denied as *const _ as *mut c_void), 0);
        assert_eq!(sendmsg6(&denied as *const _ as *mut c_void), 0);
    }
}

#[cfg(all(feature = "fuzzing", not(target_arch = "bpf"), not(test)))]
mod fuzzing_shims {
    use core::ffi::c_void;

    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_ringbuf_output(
        _ringbuf: *mut c_void,
        _data: *const c_void,
        _len: u64,
        _flags: u64,
    ) -> i64 {
        0
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_get_current_pid_tgid() -> u64 {
        0
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_probe_read_user_str(dst: *mut u8, size: u32, src: *const u8) -> i32 {
        if dst.is_null() || src.is_null() || size == 0 {
            return -1;
        }
        let size = size as usize;
        let mut copied = 0usize;
        unsafe {
            while copied < size {
                let byte = *src.add(copied);
                *dst.add(copied) = byte;
                copied += 1;
                if byte == 0 {
                    return copied as i32;
                }
            }
            if size > 0 {
                *dst.add(size - 1) = 0;
            }
        }
        size as i32
    }
}
