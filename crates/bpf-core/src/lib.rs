#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(not(target_arch = "bpf"), allow(dead_code))]

#[cfg(any(target_arch = "bpf", test))]
use bpf_api::Event;
#[cfg(any(target_arch = "bpf", test))]
use core::{ffi::c_void, mem::size_of};

#[cfg(any(target_arch = "bpf", test))]
const _EVENT_SIZE: usize = size_of::<Event>();

#[cfg(target_arch = "bpf")]
const EPERM: i32 = 1;

#[cfg(target_arch = "bpf")]
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
unsafe extern "C" {
    fn bpf_probe_read_user_str(dst: *mut u8, size: u32, src: *const u8) -> i32;
    fn bpf_ringbuf_output(ringbuf: *mut c_void, data: *const c_void, len: u64, flags: u64) -> i64;
    fn bpf_get_current_pid_tgid() -> u64;
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

#[cfg(target_arch = "bpf")]
#[unsafe(no_mangle)]
#[unsafe(link_section = "cgroup/connect4")]
pub extern "C" fn connect4(_ctx: *mut c_void) -> i32 {
    deny()
}

#[cfg(target_arch = "bpf")]
#[unsafe(no_mangle)]
#[unsafe(link_section = "cgroup/connect6")]
pub extern "C" fn connect6(_ctx: *mut c_void) -> i32 {
    deny()
}

#[cfg(target_arch = "bpf")]
#[unsafe(no_mangle)]
#[unsafe(link_section = "cgroup/sendmsg4")]
pub extern "C" fn sendmsg4(_ctx: *mut c_void) -> i32 {
    deny()
}

#[cfg(target_arch = "bpf")]
#[unsafe(no_mangle)]
#[unsafe(link_section = "cgroup/sendmsg6")]
pub extern "C" fn sendmsg6(_ctx: *mut c_void) -> i32 {
    deny()
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
}
