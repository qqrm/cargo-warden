#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(target_arch = "bpf", allow(static_mut_refs))]
#![cfg_attr(target_arch = "bpf", allow(unsafe_op_in_unsafe_fn))]
#![cfg_attr(not(target_arch = "bpf"), allow(dead_code))]

#[cfg(target_arch = "bpf")]
use aya_bpf::{
    macros::map,
    maps::{Array, RingBuf},
};
#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
use bpf_api::{self, Event};
#[cfg(any(test, feature = "fuzzing"))]
use bpf_host::{
    fs::{dentry_path_ptr, file_mode_bits, file_path_ptr},
    maps::{DummyRingBuf, TestArray},
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
const ACTION_UNLINK: u8 = 2;

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
const MODE_FLAG_OBSERVE: u32 = 1;

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

#[cfg(target_arch = "bpf")]
type ExecAllowlistMap = Array<bpf_api::ExecAllowEntry>;
#[cfg(any(test, feature = "fuzzing"))]
type ExecAllowlistMap =
    TestArray<bpf_api::ExecAllowEntry, { bpf_api::EXEC_ALLOWLIST_CAPACITY as usize }>;

#[cfg(target_arch = "bpf")]
type NetRulesMap = Array<bpf_api::NetRuleEntry>;
#[cfg(any(test, feature = "fuzzing"))]
type NetRulesMap = TestArray<bpf_api::NetRuleEntry, { bpf_api::NET_RULES_CAPACITY as usize }>;

#[cfg(target_arch = "bpf")]
type NetParentsMap = Array<bpf_api::NetParentEntry>;
#[cfg(any(test, feature = "fuzzing"))]
type NetParentsMap = TestArray<bpf_api::NetParentEntry, { bpf_api::NET_PARENTS_CAPACITY as usize }>;

#[cfg(target_arch = "bpf")]
type FsRulesMap = Array<bpf_api::FsRuleEntry>;
#[cfg(any(test, feature = "fuzzing"))]
type FsRulesMap = TestArray<bpf_api::FsRuleEntry, { bpf_api::FS_RULES_CAPACITY as usize }>;

#[cfg(target_arch = "bpf")]
type LengthMap = Array<u32>;
#[cfg(any(test, feature = "fuzzing"))]
type LengthMap = TestArray<u32, 1>;

#[cfg(target_arch = "bpf")]
type EventCountsMap = Array<u64>;
#[cfg(any(test, feature = "fuzzing"))]
type EventCountsMap = TestArray<u64, { bpf_api::EVENT_COUNT_SLOTS as usize }>;

#[cfg(target_arch = "bpf")]
type ModeFlagsMap = Array<u32>;
#[cfg(any(test, feature = "fuzzing"))]
type ModeFlagsMap = TestArray<u32, 1>;

#[cfg(target_arch = "bpf")]
type EventsMap = RingBuf;
#[cfg(any(test, feature = "fuzzing"))]
type EventsMap = DummyRingBuf;

#[cfg(target_arch = "bpf")]
const fn exec_allowlist_map() -> ExecAllowlistMap {
    Array::with_max_entries(bpf_api::EXEC_ALLOWLIST_CAPACITY, 0)
}

#[cfg(any(test, feature = "fuzzing"))]
const fn exec_allowlist_map() -> ExecAllowlistMap {
    TestArray::new()
}

#[cfg(target_arch = "bpf")]
const fn net_rules_map() -> NetRulesMap {
    Array::with_max_entries(bpf_api::NET_RULES_CAPACITY, 0)
}

#[cfg(any(test, feature = "fuzzing"))]
const fn net_rules_map() -> NetRulesMap {
    TestArray::new()
}

#[cfg(target_arch = "bpf")]
const fn net_parents_map() -> NetParentsMap {
    Array::with_max_entries(bpf_api::NET_PARENTS_CAPACITY, 0)
}

#[cfg(any(test, feature = "fuzzing"))]
const fn net_parents_map() -> NetParentsMap {
    TestArray::new()
}

#[cfg(target_arch = "bpf")]
const fn fs_rules_map() -> FsRulesMap {
    Array::with_max_entries(bpf_api::FS_RULES_CAPACITY, 0)
}

#[cfg(any(test, feature = "fuzzing"))]
const fn fs_rules_map() -> FsRulesMap {
    TestArray::new()
}

#[cfg(target_arch = "bpf")]
const fn length_map() -> LengthMap {
    Array::with_max_entries(1, 0)
}

#[cfg(any(test, feature = "fuzzing"))]
const fn length_map() -> LengthMap {
    TestArray::new()
}

#[cfg(target_arch = "bpf")]
const fn events_map() -> EventsMap {
    RingBuf::with_byte_size(bpf_api::EVENT_RINGBUF_CAPACITY_BYTES, 0)
}

#[cfg(any(test, feature = "fuzzing"))]
const fn events_map() -> EventsMap {
    DummyRingBuf
}

#[cfg(target_arch = "bpf")]
const fn event_counts_map() -> EventCountsMap {
    Array::with_max_entries(bpf_api::EVENT_COUNT_SLOTS, 0)
}

#[cfg(any(test, feature = "fuzzing"))]
const fn event_counts_map() -> EventCountsMap {
    TestArray::new()
}

#[cfg(target_arch = "bpf")]
const fn mode_flags_map() -> ModeFlagsMap {
    Array::with_max_entries(1, 0)
}

#[cfg(any(test, feature = "fuzzing"))]
const fn mode_flags_map() -> ModeFlagsMap {
    TestArray::new()
}

#[cfg(target_arch = "bpf")]
#[map(name = "EXEC_ALLOWLIST")]
static mut EXEC_ALLOWLIST: ExecAllowlistMap = exec_allowlist_map();

#[cfg(any(test, feature = "fuzzing"))]
static EXEC_ALLOWLIST: ExecAllowlistMap = exec_allowlist_map();

#[cfg(target_arch = "bpf")]
#[map(name = "EXEC_ALLOWLIST_LENGTH")]
static mut EXEC_ALLOWLIST_LENGTH: LengthMap = length_map();

#[cfg(any(test, feature = "fuzzing"))]
static EXEC_ALLOWLIST_LENGTH: LengthMap = length_map();

#[cfg(target_arch = "bpf")]
#[map(name = "NET_RULES")]
static mut NET_RULES: NetRulesMap = net_rules_map();

#[cfg(any(test, feature = "fuzzing"))]
static NET_RULES: NetRulesMap = net_rules_map();

#[cfg(target_arch = "bpf")]
#[map(name = "NET_RULES_LENGTH")]
static mut NET_RULES_LENGTH: LengthMap = length_map();

#[cfg(any(test, feature = "fuzzing"))]
static NET_RULES_LENGTH: LengthMap = length_map();

#[cfg(target_arch = "bpf")]
#[map(name = "NET_PARENTS")]
static mut NET_PARENTS: NetParentsMap = net_parents_map();

#[cfg(any(test, feature = "fuzzing"))]
static NET_PARENTS: NetParentsMap = net_parents_map();

#[cfg(target_arch = "bpf")]
#[map(name = "NET_PARENTS_LENGTH")]
static mut NET_PARENTS_LENGTH: LengthMap = length_map();

#[cfg(any(test, feature = "fuzzing"))]
static NET_PARENTS_LENGTH: LengthMap = length_map();

#[cfg(target_arch = "bpf")]
#[map(name = "EVENTS")]
static mut EVENTS: EventsMap = events_map();

#[cfg(any(test, feature = "fuzzing"))]
static EVENTS: EventsMap = events_map();

#[cfg(target_arch = "bpf")]
#[map(name = "EVENT_COUNTS")]
static mut EVENT_COUNTS: EventCountsMap = event_counts_map();

#[cfg(any(test, feature = "fuzzing"))]
static EVENT_COUNTS: EventCountsMap = event_counts_map();

#[cfg(target_arch = "bpf")]
#[map(name = "MODE_FLAGS")]
static mut MODE_FLAGS: ModeFlagsMap = mode_flags_map();

#[cfg(any(test, feature = "fuzzing"))]
static MODE_FLAGS: ModeFlagsMap = mode_flags_map();

#[cfg(target_arch = "bpf")]
#[map(name = "FS_RULES")]
static mut FS_RULES: FsRulesMap = fs_rules_map();

#[cfg(any(test, feature = "fuzzing"))]
static FS_RULES: FsRulesMap = fs_rules_map();

#[cfg(target_arch = "bpf")]
#[map(name = "FS_RULES_LENGTH")]
static mut FS_RULES_LENGTH: LengthMap = length_map();

#[cfg(any(test, feature = "fuzzing"))]
static FS_RULES_LENGTH: LengthMap = length_map();

#[cfg(target_arch = "bpf")]
unsafe fn load_exec_allow_entry(index: u32) -> Option<bpf_api::ExecAllowEntry> {
    EXEC_ALLOWLIST.get(index).copied()
}

#[cfg(any(test, feature = "fuzzing"))]
unsafe fn load_exec_allow_entry(index: u32) -> Option<bpf_api::ExecAllowEntry> {
    EXEC_ALLOWLIST.get(index)
}

#[cfg(target_arch = "bpf")]
unsafe fn load_net_rule(index: u32) -> Option<bpf_api::NetRuleEntry> {
    NET_RULES.get(index).copied()
}

#[cfg(any(test, feature = "fuzzing"))]
unsafe fn load_net_rule(index: u32) -> Option<bpf_api::NetRuleEntry> {
    NET_RULES.get(index)
}

#[cfg(target_arch = "bpf")]
unsafe fn load_net_parent(index: u32) -> Option<bpf_api::NetParentEntry> {
    NET_PARENTS.get(index).copied()
}

#[cfg(any(test, feature = "fuzzing"))]
unsafe fn load_net_parent(index: u32) -> Option<bpf_api::NetParentEntry> {
    NET_PARENTS.get(index)
}

#[cfg(target_arch = "bpf")]
unsafe fn load_fs_rule(index: u32) -> Option<bpf_api::FsRuleEntry> {
    FS_RULES.get(index).copied()
}

#[cfg(any(test, feature = "fuzzing"))]
unsafe fn load_fs_rule(index: u32) -> Option<bpf_api::FsRuleEntry> {
    FS_RULES.get(index)
}

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
    (flags & MODE_FLAG_OBSERVE) != 0
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn clamp_len(len: u32, capacity: u32) -> u32 {
    len.min(capacity)
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn exec_allowlist_len() -> u32 {
    clamp_len(
        unsafe { load_length(&EXEC_ALLOWLIST_LENGTH) },
        bpf_api::EXEC_ALLOWLIST_CAPACITY,
    )
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn net_rules_len() -> u32 {
    clamp_len(
        unsafe { load_length(&NET_RULES_LENGTH) },
        bpf_api::NET_RULES_CAPACITY,
    )
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn net_parents_len() -> u32 {
    clamp_len(
        unsafe { load_length(&NET_PARENTS_LENGTH) },
        bpf_api::NET_PARENTS_CAPACITY,
    )
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn fs_rules_len() -> u32 {
    clamp_len(
        unsafe { load_length(&FS_RULES_LENGTH) },
        bpf_api::FS_RULES_CAPACITY,
    )
}

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
    unsafe { CURRENT_UNIT }
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
fn file_path_ptr(_file: *mut c_void) -> Option<*const u8> {
    None
}

#[cfg(target_arch = "bpf")]
fn file_mode_bits(_file: *mut c_void) -> Option<u32> {
    None
}

#[cfg(target_arch = "bpf")]
fn dentry_path_ptr(_dentry: *mut c_void) -> Option<*const u8> {
    None
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
    }

    fn reset_network_state() {
        NET_RULES.clear();
        NET_RULES_LENGTH.clear();
        NET_PARENTS.clear();
        NET_PARENTS_LENGTH.clear();
        reset_mode_flags();
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
        unsafe {
            CURRENT_UNIT = 0;
        }
    }

    fn enable_observe_mode() {
        reset_mode_flags();
        MODE_FLAGS.set(0, MODE_FLAG_OBSERVE);
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
