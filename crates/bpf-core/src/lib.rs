#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(not(target_arch = "bpf"), allow(dead_code))]

#[cfg(target_arch = "bpf")]
use aya_bpf::{
    macros::map,
    maps::{Array, RingBuf},
};
#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
use bpf_api::{self, Event};
#[cfg(any(test, feature = "fuzzing"))]
use core::cell::UnsafeCell;
#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
use core::{ffi::c_void, mem::size_of};

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
const _EVENT_SIZE: usize = size_of::<Event>();

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
const EPERM: i32 = 1;

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn deny() -> i32 {
    -EPERM
}

#[cfg(target_arch = "bpf")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[cfg(any(test, feature = "fuzzing"))]
struct TestArray<T: Copy, const N: usize> {
    data: UnsafeCell<[Option<T>; N]>,
}

#[cfg(any(test, feature = "fuzzing"))]
unsafe impl<T: Copy, const N: usize> Sync for TestArray<T, N> {}

#[cfg(any(test, feature = "fuzzing"))]
impl<T: Copy, const N: usize> TestArray<T, N> {
    const fn new() -> Self {
        Self {
            data: UnsafeCell::new([None; N]),
        }
    }

    fn get(&self, index: u32) -> Option<T> {
        let idx = index as usize;
        if idx >= N {
            return None;
        }
        unsafe { (*self.data.get())[idx] }
    }

    fn set(&self, index: u32, value: T) {
        let idx = index as usize;
        if idx >= N {
            return;
        }
        unsafe {
            (*self.data.get())[idx] = Some(value);
        }
    }

    fn clear(&self) {
        unsafe {
            for slot in (*self.data.get()).iter_mut() {
                *slot = None;
            }
        }
    }
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
type LengthMap = Array<u32>;
#[cfg(any(test, feature = "fuzzing"))]
type LengthMap = TestArray<u32, 1>;

#[cfg(target_arch = "bpf")]
type EventCountsMap = Array<u64>;
#[cfg(any(test, feature = "fuzzing"))]
type EventCountsMap = TestArray<u64, { bpf_api::EVENT_COUNT_SLOTS as usize }>;

#[cfg(target_arch = "bpf")]
type EventsMap = RingBuf;
#[cfg(any(test, feature = "fuzzing"))]
#[derive(Copy, Clone)]
struct DummyRingBuf;
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
unsafe fn load_length(map: &LengthMap) -> u32 {
    map.get(0).copied().unwrap_or(0)
}

#[cfg(any(test, feature = "fuzzing"))]
unsafe fn load_length(map: &LengthMap) -> u32 {
    map.get(0).unwrap_or(0)
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
fn increment_event_count() {
    #[cfg(target_arch = "bpf")]
    unsafe {
        if let Some(counter) = EVENT_COUNTS.get_ptr_mut(0) {
            *counter = counter.wrapping_add(1);
        }
    }

    #[cfg(any(test, feature = "fuzzing"))]
    {
        let current = EVENT_COUNTS.get(0).unwrap_or(0);
        EVENT_COUNTS.set(0, current.wrapping_add(1));
    }
}

#[cfg(target_arch = "bpf")]
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
        deny()
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
        deny()
    }
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
unsafe extern "C" {
    fn bpf_probe_read_user_str(dst: *mut u8, size: u32, src: *const u8) -> i32;
    fn bpf_ringbuf_output(ringbuf: *mut c_void, data: *const c_void, len: u64, flags: u64) -> i64;
    fn bpf_get_current_pid_tgid() -> u64;
}

#[cfg(not(target_arch = "bpf"))]
pub fn resolve_host(host: &str) -> std::io::Result<Vec<std::net::IpAddr>> {
    use std::net::ToSocketAddrs;
    (host, 0)
        .to_socket_addrs()
        .map(|iter| iter.map(|s| s.ip()).collect())
}

#[cfg(target_arch = "bpf")]
#[unsafe(no_mangle)]
#[unsafe(link_section = "lsm/bprm_check_security")]
pub extern "C" fn bprm_check_security(ctx: *mut c_void) -> i32 {
    let filename_ptr = unsafe { *(ctx as *const *const u8) };
    let mut buf = [0u8; 256];
    if unsafe { bpf_probe_read_user_str(buf.as_mut_ptr(), buf.len() as u32, filename_ptr) } < 0 {
        return deny();
    }
    let len = exec_allowlist_len();
    let mut i = 0;
    while i < len {
        if let Some(entry) = unsafe { load_exec_allow_entry(i) } {
            if path_matches(&entry.path, &buf) {
                return 0;
            }
        }
        i += 1;
    }
    deny()
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
pub extern "C" fn file_open(_file: *mut c_void, _cred: *mut c_void) -> i32 {
    let event = Event {
        pid: unsafe { (bpf_get_current_pid_tgid() >> 32) as u32 },
        unit: 0,
        action: 0,
        verdict: 0,
        reserved: 0,
        container_id: 0,
        caps: 0,
        path_or_addr: [0; 256],
    };
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
            &event as *const _ as *const c_void,
            size_of::<Event>() as u64,
            0,
        );
    }
    increment_event_count();
    0
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
#[unsafe(no_mangle)]
#[unsafe(link_section = "lsm/file_permission")]
pub extern "C" fn file_permission(_file: *mut c_void, mask: i32) -> i32 {
    const MAY_WRITE: i32 = 2;
    if (mask & MAY_WRITE) != 0 { deny() } else { 0 }
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
#[unsafe(no_mangle)]
#[unsafe(link_section = "lsm/inode_unlink")]
pub extern "C" fn inode_unlink(_dir: *mut c_void, _dentry: *mut c_void) -> i32 {
    deny()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bpf_api::FS_WRITE;
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
    extern "C" fn bpf_probe_read_user_str(_dst: *mut u8, _size: u32, _src: *const u8) -> i32 {
        0
    }

    #[test]
    fn file_open_emits_event() {
        let _g = TEST_LOCK.lock().unwrap();
        EVENT_COUNTS.clear();
        file_open(ptr::null_mut(), ptr::null_mut());
        let event = LAST_EVENT.lock().unwrap().expect("event");
        assert_eq!(event.pid, 1234);
        assert_eq!(event.unit, 0);
        assert_eq!(event.action, 0);
        assert_eq!(event.verdict, 0);
        assert_eq!(event.path_or_addr[0], 0);
        let count = EVENT_COUNTS.get(0).unwrap_or(0);
        assert_eq!(count, 1);
    }

    #[test]
    fn file_permission_denies_writes() {
        assert_ne!(file_permission(ptr::null_mut(), FS_WRITE as i32), 0);
        assert_eq!(file_permission(ptr::null_mut(), 0), 0);
    }

    #[test]
    fn inode_unlink_denies() {
        assert_ne!(inode_unlink(ptr::null_mut(), ptr::null_mut()), 0);
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

    fn reset_network_state() {
        NET_RULES.clear();
        NET_RULES_LENGTH.clear();
        NET_PARENTS.clear();
        NET_PARENTS_LENGTH.clear();
        unsafe {
            CURRENT_UNIT = 0;
        }
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
}
