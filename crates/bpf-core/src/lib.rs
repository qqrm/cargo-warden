#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(not(target_arch = "bpf"), allow(dead_code))]

#[cfg(any(target_arch = "bpf", test))]
use bpf_api::Event;
#[cfg(any(target_arch = "bpf", test))]
use core::{ffi::c_void, mem::size_of};

#[cfg(any(target_arch = "bpf", test))]
const _EVENT_SIZE: usize = size_of::<Event>();

#[cfg(any(target_arch = "bpf", test))]
const EPERM: i32 = 1;

#[cfg(any(target_arch = "bpf", test))]
fn deny() -> i32 {
    -EPERM
}

#[cfg(target_arch = "bpf")]
#[unsafe(no_mangle)]
#[unsafe(link_section = "maps/exec_allowlist")]
pub static mut EXEC_ALLOWLIST: [bpf_api::ExecAllowEntry; 1] =
    [bpf_api::ExecAllowEntry { path: [0; 256] }];

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

#[cfg(any(target_arch = "bpf", test))]
#[unsafe(no_mangle)]
#[unsafe(link_section = "maps/net_rules")]
pub static mut NET_RULES: [bpf_api::NetRuleEntry; 1] = [bpf_api::NetRuleEntry {
    unit: 0,
    rule: bpf_api::NetRule {
        addr: [0; 16],
        protocol: 0,
        prefix_len: 0,
        port: 0,
    },
}];

#[cfg(any(target_arch = "bpf", test))]
fn current_unit() -> u32 {
    0
}

#[cfg(any(target_arch = "bpf", test))]
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

#[cfg(any(target_arch = "bpf", test))]
fn rule_matches(rule: &bpf_api::NetRule, addr: &[u8; 16], port: u16, protocol: u8) -> bool {
    rule.port == port && rule.protocol == protocol && addr_matches(rule, addr)
}

#[cfg(any(target_arch = "bpf", test))]
fn net_allowed(addr: &[u8; 16], port: u16, protocol: u8) -> bool {
    let unit = current_unit();
    unsafe {
        let mut i = 0;
        while i < 1 {
            let entry = core::ptr::read(core::ptr::addr_of!(NET_RULES[i]));
            if entry.unit == unit && rule_matches(&entry.rule, addr, port, protocol) {
                return true;
            }
            i += 1;
        }
    }
    false
}

#[cfg(any(target_arch = "bpf", test))]
#[repr(C)]
struct SockAddr {
    user_ip4: u32,
    user_ip6: [u32; 4],
    user_port: u16,
    family: u16,
    protocol: u32,
}

#[cfg(any(target_arch = "bpf", test))]
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

#[cfg(any(target_arch = "bpf", test))]
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

#[cfg(any(target_arch = "bpf", test))]
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

#[cfg(any(target_arch = "bpf", test))]
#[unsafe(no_mangle)]
#[unsafe(link_section = "maps/events")]
pub static mut EVENTS: [u8; 0] = [];

#[cfg(target_arch = "bpf")]
#[unsafe(no_mangle)]
#[unsafe(link_section = "lsm/bprm_check_security")]
pub extern "C" fn bprm_check_security(ctx: *mut c_void) -> i32 {
    let filename_ptr = unsafe { *(ctx as *const *const u8) };
    let mut buf = [0u8; 256];
    unsafe {
        if bpf_probe_read_user_str(buf.as_mut_ptr(), buf.len() as u32, filename_ptr) < 0 {
            return deny();
        }
        for entry in &EXEC_ALLOWLIST {
            if path_matches(&entry.path, &buf) {
                return 0;
            }
        }
        deny()
    }
}

#[cfg(any(target_arch = "bpf", test))]
#[unsafe(no_mangle)]
#[unsafe(link_section = "cgroup/connect4")]
pub extern "C" fn connect4(ctx: *mut c_void) -> i32 {
    check4(ctx)
}

#[cfg(any(target_arch = "bpf", test))]
#[unsafe(no_mangle)]
#[unsafe(link_section = "cgroup/connect6")]
pub extern "C" fn connect6(ctx: *mut c_void) -> i32 {
    check6(ctx)
}

#[cfg(any(target_arch = "bpf", test))]
#[unsafe(no_mangle)]
#[unsafe(link_section = "cgroup/sendmsg4")]
pub extern "C" fn sendmsg4(ctx: *mut c_void) -> i32 {
    check4(ctx)
}

#[cfg(any(target_arch = "bpf", test))]
#[unsafe(no_mangle)]
#[unsafe(link_section = "cgroup/sendmsg6")]
pub extern "C" fn sendmsg6(ctx: *mut c_void) -> i32 {
    check6(ctx)
}

#[cfg(any(target_arch = "bpf", test))]
#[unsafe(no_mangle)]
#[unsafe(link_section = "lsm/file_open")]
pub extern "C" fn file_open(_file: *mut c_void, _cred: *mut c_void) -> i32 {
    let event = Event {
        pid: unsafe { (bpf_get_current_pid_tgid() >> 32) as u32 },
        unit: 0,
        action: 0,
        verdict: 0,
        reserved: 0,
        path_or_addr: [0; 256],
    };
    unsafe {
        bpf_ringbuf_output(
            core::ptr::addr_of_mut!(EVENTS) as *mut c_void,
            &event as *const _ as *const c_void,
            size_of::<Event>() as u64,
            0,
        );
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ffi::c_void;
    use std::ptr;
    use std::sync::Mutex;

    static LAST_EVENT: Mutex<Option<Event>> = Mutex::new(None);

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
        file_open(ptr::null_mut(), ptr::null_mut());
        let event = LAST_EVENT.lock().unwrap().expect("event");
        assert_eq!(event.pid, 1234);
        assert_eq!(event.unit, 0);
        assert_eq!(event.action, 0);
        assert_eq!(event.verdict, 0);
        assert_eq!(event.path_or_addr[0], 0);
    }

    fn set_rule(addr: std::net::IpAddr, port: u16, proto: u8) {
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
        unsafe {
            NET_RULES[0] = bpf_api::NetRuleEntry {
                unit: 0,
                rule: bpf_api::NetRule {
                    addr: bytes,
                    protocol: proto,
                    prefix_len: prefix,
                    port,
                },
            };
        }
    }

    #[test]
    fn connect4_respects_rules() {
        let ip = resolve_host("localhost")
            .unwrap()
            .into_iter()
            .find(|i| i.is_ipv4())
            .unwrap();
        set_rule(ip, 80, 6);
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
        let denied = SockAddr {
            user_ip4: u32::from_be_bytes([1, 1, 1, 1]),
            user_ip6: [0; 4],
            user_port: 80u16.to_be(),
            family: 2,
            protocol: 6,
        };
        assert_eq!(connect4(&allowed as *const _ as *mut c_void), 0);
        assert_ne!(connect4(&denied as *const _ as *mut c_void), 0);
        assert_eq!(sendmsg4(&allowed as *const _ as *mut c_void), 0);
        assert_ne!(sendmsg4(&denied as *const _ as *mut c_void), 0);
    }

    #[test]
    fn connect6_respects_rules() {
        let ip = resolve_host("localhost")
            .unwrap()
            .into_iter()
            .find(|i| i.is_ipv6())
            .unwrap();
        set_rule(ip, 80, 6);
        let mut ip6_words = [0u32; 4];
        if let std::net::IpAddr::V6(v6) = ip {
            let octets = v6.octets();
            for i in 0..4 {
                ip6_words[i] = u32::from_be_bytes([
                    octets[i * 4],
                    octets[i * 4 + 1],
                    octets[i * 4 + 2],
                    octets[i * 4 + 3],
                ]);
            }
        }
        let allowed = SockAddr {
            user_ip4: 0,
            user_ip6: ip6_words,
            user_port: 80u16.to_be(),
            family: 10,
            protocol: 6,
        };
        let denied = SockAddr {
            user_ip4: 0,
            user_ip6: [0; 4],
            user_port: 80u16.to_be(),
            family: 10,
            protocol: 6,
        };
        assert_eq!(connect6(&allowed as *const _ as *mut c_void), 0);
        assert_ne!(connect6(&denied as *const _ as *mut c_void), 0);
        assert_eq!(sendmsg6(&allowed as *const _ as *mut c_void), 0);
        assert_ne!(sendmsg6(&denied as *const _ as *mut c_void), 0);
    }
}
