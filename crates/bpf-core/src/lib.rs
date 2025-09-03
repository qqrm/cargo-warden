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
