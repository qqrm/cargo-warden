#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(not(target_arch = "bpf"), allow(dead_code))]

#[cfg(target_arch = "bpf")]
use bpf_api::Event;
#[cfg(target_arch = "bpf")]
use core::{ffi::c_void, mem::size_of};

#[cfg(target_arch = "bpf")]
const _EVENT_SIZE: usize = size_of::<Event>();

#[cfg(target_arch = "bpf")]
const EPERM: i32 = 1;

#[cfg(target_arch = "bpf")]
fn deny() -> i32 {
    -EPERM
}

#[cfg(target_arch = "bpf")]
#[no_mangle]
#[link_section = "maps/exec_allowlist"]
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

#[cfg(target_arch = "bpf")]
extern "C" {
    fn bpf_probe_read_user_str(dst: *mut u8, size: u32, src: *const u8) -> i32;
}

#[cfg(target_arch = "bpf")]
#[no_mangle]
#[link_section = "lsm/bprm_check_security"]
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
#[no_mangle]
#[link_section = "cgroup/connect4"]
pub extern "C" fn connect4(_ctx: *mut c_void) -> i32 {
    deny()
}

#[cfg(target_arch = "bpf")]
#[no_mangle]
#[link_section = "cgroup/connect6"]
pub extern "C" fn connect6(_ctx: *mut c_void) -> i32 {
    deny()
}

#[cfg(target_arch = "bpf")]
#[no_mangle]
#[link_section = "cgroup/sendmsg4"]
pub extern "C" fn sendmsg4(_ctx: *mut c_void) -> i32 {
    deny()
}

#[cfg(target_arch = "bpf")]
#[no_mangle]
#[link_section = "cgroup/sendmsg6"]
pub extern "C" fn sendmsg6(_ctx: *mut c_void) -> i32 {
    deny()
}
