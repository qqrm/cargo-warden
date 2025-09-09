#![no_main]
use arbitrary::Arbitrary;
use bpf_core::connect4;
use core::ffi::c_void;
use libfuzzer_sys::fuzz_target;

#[repr(C)]
#[derive(Arbitrary, Debug)]
struct SockAddr {
    user_ip4: u32,
    user_ip6: [u32; 4],
    user_port: u16,
    family: u16,
    protocol: u8,
}

fuzz_target!(|addr: SockAddr| {
    let mut data = addr;
    let ctx = &mut data as *mut SockAddr as *mut c_void;
    let _ = connect4(ctx);
});
