// PATCH_APPLIED_MARKER
#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(target_arch = "bpf", allow(static_mut_refs))]
#![cfg_attr(target_arch = "bpf", allow(unsafe_op_in_unsafe_fn))]
#![cfg_attr(not(target_arch = "bpf"), allow(dead_code))]


#[cfg(target_arch = "bpf")]
use aya_bpf::{
    cty::{c_char, c_long},
    helpers::bpf_probe_read_kernel,
    macros::{cgroup_sock_addr, map, tracepoint},
    maps::{Array, HashMap, RingBuf},
    programs::{SockAddrContext, TracePointContext},
};



#[cfg(target_arch = "bpf")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}




#[cfg(target_arch = "bpf")]
#[unsafe(no_mangle)]
pub extern "C" fn __bpf_trap() -> ! {
    loop {}
}





#[cfg(target_arch = "bpf")]
type ExecAllowlistMap = Array<bpf_api::ExecAllowEntry>;

#[cfg(target_arch = "bpf")]
type LengthMap = Array<u32>;

#[cfg(target_arch = "bpf")]
type NetRulesMap = Array<bpf_api::NetRuleEntry>;

#[cfg(target_arch = "bpf")]
type NetParentsMap = Array<bpf_api::NetParentEntry>;

#[cfg(target_arch = "bpf")]
type FsRulesMap = Array<bpf_api::FsRuleEntry>;

#[cfg(target_arch = "bpf")]
type ModeFlagsMap = Array<u32>;

#[cfg(target_arch = "bpf")]
type WorkloadUnitsMap = HashMap<u32, u32>;

#[cfg(target_arch = "bpf")]
type EventsMap = RingBuf;

#[cfg(target_arch = "bpf")]
#[map(name = "EXEC_ALLOWLIST")]
static mut EXEC_ALLOWLIST: ExecAllowlistMap = EXEC_ALLOWLIST_DESCRIPTOR.bpf_map();


#[cfg(target_arch = "bpf")]
#[map(name = "EXEC_ALLOWLIST_LENGTH")]
static mut EXEC_ALLOWLIST_LENGTH: LengthMap = EXEC_ALLOWLIST_LENGTH_DESCRIPTOR.bpf_map();

#[cfg(target_arch = "bpf")]
#[map(name = "NET_RULES")]
static mut NET_RULES: NetRulesMap = NET_RULES_DESCRIPTOR.bpf_map();

#[cfg(target_arch = "bpf")]
#[map(name = "NET_RULES_LENGTH")]
static mut NET_RULES_LENGTH: LengthMap = NET_RULES_LENGTH_DESCRIPTOR.bpf_map();

#[cfg(target_arch = "bpf")]
#[map(name = "NET_PARENTS")]
static mut NET_PARENTS: NetParentsMap = NET_PARENTS_DESCRIPTOR.bpf_map();

#[cfg(target_arch = "bpf")]
#[map(name = "NET_PARENTS_LENGTH")]
static mut NET_PARENTS_LENGTH: LengthMap = NET_PARENTS_LENGTH_DESCRIPTOR.bpf_map();

#[cfg(target_arch = "bpf")]
#[map(name = "FS_RULES")]
static mut FS_RULES: FsRulesMap = FS_RULES_DESCRIPTOR.bpf_map();

#[cfg(target_arch = "bpf")]
#[map(name = "FS_RULES_LENGTH")]
static mut FS_RULES_LENGTH: LengthMap = FS_RULES_LENGTH_DESCRIPTOR.bpf_map();


#[cfg(target_arch = "bpf")]
#[cfg(target_arch = "bpf")]
#[map(name = "MODE_FLAGS")]
static mut MODE_FLAGS: ModeFlagsMap = MODE_FLAGS_DESCRIPTOR.bpf_map();

#[cfg(target_arch = "bpf")]
#[map(name = "WORKLOAD_UNITS")]
static mut WORKLOAD_UNITS: WorkloadUnitsMap = WORKLOAD_UNITS_DESCRIPTOR.bpf_map();

#[cfg(target_arch = "bpf")]
#[map(name = "EVENTS")]
static mut EVENTS: EventsMap = EVENTS_DESCRIPTOR.bpf_map();






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


#[cfg(target_arch = "bpf")]
#[repr(C)]
struct SysEnterExecveArgs {
    _unused: u64,
    syscall: u64,
    args: [u64; 6],
}

#[cfg(target_arch = "bpf")]
#[repr(C)]
struct SchedProcessForkArgs {
    _unused: u64,
    parent_comm: [c_char; 16],
    parent_pid: i32,
    parent_tgid: i32,
    child_comm: [c_char; 16],
    child_pid: i32,
    child_tgid: i32,
}

#[cfg(target_arch = "bpf")]
#[repr(C)]
struct SchedProcessExitArgs {
    _unused: u64,
    comm: [c_char; 16],
    pid: i32,
    prio: i32,
    state: c_long,
}

#[cfg(target_arch = "bpf")]
fn classify_and_record_exec(ctx: &SysEnterExecveArgs) {
    let pid = unsafe { (bpf_get_current_pid_tgid() >> 32) as u32 };
    let filename_ptr = ctx.args[0] as *const u8;
    let argv_ptr = ctx.args[1] as *const u64;
    let mut path = [0u8; 256];
    let mut unit = bpf_api::UNIT_OTHER;

    if !filename_ptr.is_null() {
        let read =
            unsafe { bpf_probe_read_user_str(path.as_mut_ptr(), path.len() as u32, filename_ptr) };
        if read >= 0 {
            let mut arg_buffers = [[0u8; MAX_ARG_LENGTH]; MAX_CAPTURED_ARGS];
            let mut arg_refs: [&[u8]; MAX_CAPTURED_ARGS] = [&[]; MAX_CAPTURED_ARGS];
            let mut captured = 0usize;
            if !argv_ptr.is_null() {
                let mut idx = 0usize;
                while idx < MAX_CAPTURED_ARGS {
                    let mut arg_ptr_value: u64 = 0;
                    let read_ptr = unsafe {
                        bpf_probe_read_user(
                            (&mut arg_ptr_value as *mut u64).cast(),
                            core::mem::size_of::<u64>() as u32,
                            argv_ptr.add(idx).cast(),
                        )
                    };
                    if read_ptr < 0 || arg_ptr_value == 0 {
                        break;
                    }
                    let mut captured_slice: Option<(*const u8, usize)> = None;
                    {
                        let buffer = &mut arg_buffers[idx];
                        let read_arg = unsafe {
                            bpf_probe_read_user_str(
                                buffer.as_mut_ptr(),
                                MAX_ARG_LENGTH as u32,
                                arg_ptr_value as *const u8,
                            )
                        };
                        if read_arg >= 0 {
                            let mut length = read_arg as usize;
                            if length > 0 {
                                length = length.saturating_sub(1).min(MAX_ARG_LENGTH - 1);
                            }
                            captured_slice = Some((buffer.as_ptr(), length));
                        }
                    }
                    if let Some((ptr, length)) = captured_slice {
                        let slice = unsafe { core::slice::from_raw_parts(ptr, length) };
                        arg_refs[idx] = slice;
                        captured = idx + 1;
                    }
                    idx += 1;
                }
            }
            let path_len = find_c_string_len(&path);
            let command_path = &path[..path_len];
            unit = classify_workload_unit(command_path, &arg_refs[..captured]);
        }
    }

    set_workload_unit(pid, unit);
}

#[cfg(target_arch = "bpf")]
#[tracepoint(name = "sys_enter_execve", category = "syscalls")]
pub fn sys_enter_execve(ctx: TracePointContext) -> u32 {
    let _ = unsafe { try_sys_enter_execve(ctx) };
    0
}

#[cfg(target_arch = "bpf")]
unsafe fn try_sys_enter_execve(ctx: TracePointContext) -> Result<(), i64> {
    let args: SysEnterExecveArgs = ctx.read_at(0)?;
    classify_and_record_exec(&args);
    Ok(())
}

#[cfg(target_arch = "bpf")]
#[tracepoint(name = "sched_process_fork", category = "sched")]
pub fn sched_process_fork(ctx: TracePointContext) -> u32 {
    let _ = unsafe { try_sched_process_fork(ctx) };
    0
}

#[cfg(target_arch = "bpf")]
unsafe fn try_sched_process_fork(ctx: TracePointContext) -> Result<(), i64> {
    let args: SchedProcessForkArgs = ctx.read_at(0)?;
    let parent = args.parent_tgid as u32;
    let child = args.child_tgid as u32;
    let unit = workload_unit_for_pid(parent);
    set_workload_unit(child, unit);
    Ok(())
}

#[cfg(target_arch = "bpf")]
#[tracepoint(name = "sched_process_exit", category = "sched")]
pub fn sched_process_exit(ctx: TracePointContext) -> u32 {
    let _ = unsafe { try_sched_process_exit(ctx) };
    0
}

#[cfg(target_arch = "bpf")]
unsafe fn try_sched_process_exit(ctx: TracePointContext) -> Result<(), i64> {
    let args: SchedProcessExitArgs = ctx.read_at(0)?;
    let pid = args.pid as u32;
    remove_workload_unit(pid);
    Ok(())
}



#[cfg(target_arch = "bpf")]
#[inline(never)]
fn unit_fs_allowed(unit: u32, path: &CStr, needed: u8) -> bool {
    let len = fs_rules_len();
    let mut i = 0;
    while i < len {
        if let Some(entry) = unsafe { FS_RULES.get(i) } {
            if entry.unit == unit && fs_entry_allows(entry, path, needed) {
                return true;
            }
        }
        i += 1;
    }
    false
}


const FMODE_READ: u32 = 1;
const FMODE_WRITE: u32 = 2;
const MAY_WRITE: i32 = 2;
const MAY_READ: i32 = 4;
const MAY_APPEND: i32 = 8;


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
fn copy_c_string(dst: &mut [u8], src: &[u8]) {
    if dst.is_empty() {
        return;
    }
    let mut len = src.iter().position(|&b| b == 0).unwrap_or(src.len());
    if len >= dst.len() {
        len = dst.len() - 1;
    }
    dst[..len].copy_from_slice(&src[..len]);
    dst[len] = 0;
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn fs_needed_perm(access: u8) -> Option<&'static [u8]> {
    if (access & bpf_api::FS_WRITE) != 0 {
        Some(b"allow.fs.write_extra")
    } else if (access & bpf_api::FS_READ) != 0 {
        Some(b"allow.fs.read_extra")
    } else {
        None
    }
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn fs_event(action: u8, path: &[u8; 256], access: u8, allowed: bool) -> Event {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let mut event = Event {
        pid: (pid_tgid >> 32) as u32,
        tgid: pid_tgid as u32,
        time_ns: unsafe { bpf_ktime_get_ns() },
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
        needed_perm: [0; 64],
    };

    copy_c_string(&mut event.path_or_addr, path);
    if !allowed && let Some(perm) = fs_needed_perm(access) {
        copy_c_string(&mut event.needed_perm, perm);
    }

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
}

#[cfg(any(test, feature = "fuzzing"))]
#[repr(C)]
struct SockAddr {
    user_ip4: u32,
    user_ip6: [u32; 4],
    user_port: u32,
    family: u32,
    protocol: u32,
}

#[cfg(target_arch = "bpf")]
fn check4(ctx: SockAddrContext) -> i32 {
    let ctx = unsafe { &*ctx.sock_addr };
    let mut addr = [0u8; 16];
    addr[..4].copy_from_slice(&ctx.user_ip4.to_be_bytes());
    let port = u16::from_be(ctx.user_port as u16);
    let proto = ctx.protocol as u8;
    if net_allowed(&addr, port, proto) {
        0
    } else {
        deny_with_mode()
    }
}

#[cfg(any(test, feature = "fuzzing"))]
fn check4(ctx: *mut c_void) -> i32 {
    let ctx = unsafe { &*(ctx as *const SockAddr) };
    let mut addr = [0u8; 16];
    addr[..4].copy_from_slice(&ctx.user_ip4.to_be_bytes());
    let port = u16::from_be(ctx.user_port as u16);
    let proto = ctx.protocol as u8;
    if net_allowed(&addr, port, proto) {
        0
    } else {
        deny_with_mode()
    }
}

#[cfg(target_arch = "bpf")]
fn check6(ctx: SockAddrContext) -> i32 {
    let ctx = unsafe { &*ctx.sock_addr };
    let mut addr = [0u8; 16];
    for (i, part) in ctx.user_ip6.iter().enumerate() {
        addr[i * 4..(i + 1) * 4].copy_from_slice(&part.to_be_bytes());
    }
    let port = u16::from_be(ctx.user_port as u16);
    let proto = ctx.protocol as u8;
    if net_allowed(&addr, port, proto) {
        0
    } else {
        deny_with_mode()
    }
}

#[cfg(any(test, feature = "fuzzing"))]
fn check6(ctx: *mut c_void) -> i32 {
    let ctx = unsafe { &*(ctx as *const SockAddr) };
    let mut addr = [0u8; 16];
    for (i, part) in ctx.user_ip6.iter().enumerate() {
        addr[i * 4..(i + 1) * 4].copy_from_slice(&part.to_be_bytes());
    }
    let port = u16::from_be(ctx.user_port as u16);
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
    fn bpf_probe_read_user(dst: *mut c_void, size: u32, src: *const c_void) -> i32;
    fn bpf_ringbuf_output(ringbuf: *mut c_void, data: *const c_void, len: u64, flags: u64) -> i64;
    fn bpf_get_current_pid_tgid() -> u64;
    fn bpf_ktime_get_ns() -> u64;
}

#[cfg(target_arch = "bpf")]
#[unsafe(no_mangle)]
#[unsafe(link_section = "lsm/bprm_check_security")]
#[inline(never)]
pub extern "C" fn bprm_check_security(ctx: *mut c_void) -> i32 {
    let filename_ptr = unsafe { *(ctx as *const *const u8) };

    let mut buf = [0u8; 256];
    if unsafe { bpf_probe_read_user_str(buf.as_mut_ptr(), buf.len() as u32, filename_ptr) } < 0 {
        return deny_with_mode();
    }

    let len = exec_allowlist_len();
    let mut i = 0;
    while i < len {
        // ключевая правка: доступ к EXEC_ALLOWLIST в unsafe
        let entry = unsafe { EXEC_ALLOWLIST.get(i) };
        if let Some(entry) = entry {
            if path_matches(&entry.path, &buf) {
                return 0;
            }
        }
        i += 1;
    }
    deny_with_mode()
}

#[cfg(any(test, feature = "fuzzing"))]
#[unsafe(no_mangle)]
#[unsafe(link_section = "lsm/bprm_check_security")]
#[inline(never)]
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

#[cfg(target_arch = "bpf")]
#[cgroup_sock_addr(connect4)]
pub fn connect4(ctx: SockAddrContext) -> i32 {
    check4(ctx)
}

#[cfg(any(test, feature = "fuzzing"))]
#[unsafe(no_mangle)]
#[unsafe(link_section = "cgroup/connect4")]
pub extern "C" fn connect4(ctx: *mut c_void) -> i32 {
    check4(ctx)
}

#[cfg(target_arch = "bpf")]
#[cgroup_sock_addr(connect6)]
pub fn connect6(ctx: SockAddrContext) -> i32 {
    check6(ctx)
}

#[cfg(any(test, feature = "fuzzing"))]
#[unsafe(no_mangle)]
#[unsafe(link_section = "cgroup/connect6")]
pub extern "C" fn connect6(ctx: *mut c_void) -> i32 {
    check6(ctx)
}

#[cfg(target_arch = "bpf")]
#[cgroup_sock_addr(sendmsg4)]
pub fn sendmsg4(ctx: SockAddrContext) -> i32 {
    check4(ctx)
}

#[cfg(any(test, feature = "fuzzing"))]
#[unsafe(no_mangle)]
#[unsafe(link_section = "cgroup/sendmsg4")]
pub extern "C" fn sendmsg4(ctx: *mut c_void) -> i32 {
    check4(ctx)
}

#[cfg(target_arch = "bpf")]
#[cgroup_sock_addr(sendmsg6)]
pub fn sendmsg6(ctx: SockAddrContext) -> i32 {
    check6(ctx)
}

#[cfg(any(test, feature = "fuzzing"))]
#[unsafe(no_mangle)]
#[unsafe(link_section = "cgroup/sendmsg6")]
pub extern "C" fn sendmsg6(ctx: *mut c_void) -> i32 {
    check6(ctx)
}

#[cfg(target_arch = "bpf")]
#[unsafe(no_mangle)]
#[unsafe(link_section = "lsm/file_open")]
#[inline(never)]
pub extern "C" fn file_open(file: *mut c_void, _cred: *mut c_void) -> i32 {
    let path_ptr = match file_path_ptr(file) {
        Some(ptr) => ptr,
        None => return deny_with_mode(),
    };

    let mut path = [0u8; 256];
    if !read_user_path_into(path_ptr, &mut path) {
        return deny_with_mode();
    }

    let access = file_mode_bits(file)
        .map(access_from_mode)
        .unwrap_or(bpf_api::FS_READ);

    let allowed = fs_allowed(&path, access);
    if allowed { 0 } else { deny_with_mode() }
}



#[cfg(target_arch = "bpf")]
#[unsafe(no_mangle)]
#[unsafe(link_section = "lsm/file_permission")]
#[inline(never)]
pub extern "C" fn file_permission(file: *mut c_void, mask: i32) -> i32 {
    let access = access_from_mask(mask);
    if access == 0 {
        return 0;
    }

    let path_ptr = match file_path_ptr(file) {
        Some(ptr) => ptr,
        None => return deny_with_mode(),
    };

    let mut path = [0u8; 256];
    if !read_user_path_into(path_ptr, &mut path) {
        return deny_with_mode();
    }

    if fs_allowed(&path, access) {
        0
    } else {
        deny_with_mode()
    }
}




#[cfg(test)]
mod tests;

