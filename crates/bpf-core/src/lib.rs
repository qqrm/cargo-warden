// PATCH_APPLIED_MARKER
#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(target_arch = "bpf", allow(static_mut_refs))]
#![cfg_attr(target_arch = "bpf", allow(unsafe_op_in_unsafe_fn))]
#![cfg_attr(not(target_arch = "bpf"), allow(dead_code))]

#[cfg(target_arch = "bpf")]
use aya_bpf::{
    cty::{c_char, c_long},
    helpers::bpf_probe_read_kernel,
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user, bpf_probe_read_user_str_bytes},
    macros::map,
    maps::{Array, HashMap, RingBuf},
};

#[cfg(target_arch = "bpf")]
use bpf_api;

#[cfg(target_arch = "bpf")]
use core::ffi::{CStr, c_void};

#[cfg(target_arch = "bpf")]
use core::marker::PhantomData;

#[cfg(target_arch = "bpf")]
const MAX_CAPTURED_ARGS: usize = 4;

#[cfg(target_arch = "bpf")]
const MAX_ARG_LENGTH: usize = 48;

#[cfg(target_arch = "bpf")]
struct ArrayDescriptor<T, const CAPACITY: usize> {
    _marker: PhantomData<T>,
}

#[cfg(target_arch = "bpf")]
impl<T: Copy, const CAPACITY: usize> ArrayDescriptor<T, CAPACITY> {
    const fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    const fn bpf_map(&self) -> Array<T> {
        Array::with_max_entries(CAPACITY as u32, 0)
    }
}

#[cfg(target_arch = "bpf")]
struct HashMapDescriptor<K, V, const CAPACITY: usize> {
    _marker: PhantomData<(K, V)>,
}

#[cfg(target_arch = "bpf")]
impl<K: Copy + PartialEq, V: Copy, const CAPACITY: usize> HashMapDescriptor<K, V, CAPACITY> {
    const fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    const fn bpf_map(&self) -> HashMap<K, V> {
        HashMap::with_max_entries(CAPACITY as u32, 0)
    }
}

#[cfg(target_arch = "bpf")]
struct RingBufDescriptor<const BYTE_SIZE: usize>;

#[cfg(target_arch = "bpf")]
impl<const BYTE_SIZE: usize> RingBufDescriptor<BYTE_SIZE> {
    const fn new() -> Self {
        Self
    }

    const fn bpf_map(&self) -> RingBuf {
        RingBuf::with_byte_size(BYTE_SIZE as u32, 0)
    }
}

#[cfg(target_arch = "bpf")]
const EXEC_ALLOWLIST_DESCRIPTOR: ArrayDescriptor<
    bpf_api::ExecAllowEntry,
    { bpf_api::EXEC_ALLOWLIST_CAPACITY as usize },
> = ArrayDescriptor::new();

#[cfg(target_arch = "bpf")]
const EXEC_ALLOWLIST_LENGTH_DESCRIPTOR: ArrayDescriptor<u32, 1> = ArrayDescriptor::new();

#[cfg(target_arch = "bpf")]
const NET_RULES_DESCRIPTOR: ArrayDescriptor<
    bpf_api::NetRuleEntry,
    { bpf_api::NET_RULES_CAPACITY as usize },
> = ArrayDescriptor::new();

#[cfg(target_arch = "bpf")]
const NET_RULES_LENGTH_DESCRIPTOR: ArrayDescriptor<u32, 1> = ArrayDescriptor::new();

#[cfg(target_arch = "bpf")]
const NET_PARENTS_DESCRIPTOR: ArrayDescriptor<
    bpf_api::NetParentEntry,
    { bpf_api::NET_PARENTS_CAPACITY as usize },
> = ArrayDescriptor::new();

#[cfg(target_arch = "bpf")]
const NET_PARENTS_LENGTH_DESCRIPTOR: ArrayDescriptor<u32, 1> = ArrayDescriptor::new();

#[cfg(target_arch = "bpf")]
const FS_RULES_DESCRIPTOR: ArrayDescriptor<
    bpf_api::FsRuleEntry,
    { bpf_api::FS_RULES_CAPACITY as usize },
> = ArrayDescriptor::new();

#[cfg(target_arch = "bpf")]
const FS_RULES_LENGTH_DESCRIPTOR: ArrayDescriptor<u32, 1> = ArrayDescriptor::new();

#[cfg(target_arch = "bpf")]
const MODE_FLAGS_DESCRIPTOR: ArrayDescriptor<u32, { bpf_api::MODE_FLAGS_CAPACITY as usize }> =
    ArrayDescriptor::new();

#[cfg(target_arch = "bpf")]
const WORKLOAD_UNITS_DESCRIPTOR: HashMapDescriptor<
    u32,
    u32,
    { bpf_api::WORKLOAD_UNITS_CAPACITY as usize },
> = HashMapDescriptor::new();

#[cfg(target_arch = "bpf")]
const EVENTS_DESCRIPTOR: RingBufDescriptor<{ bpf_api::EVENT_RINGBUF_CAPACITY_BYTES as usize }> =
    RingBufDescriptor::new();

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

#[cfg(target_arch = "bpf")]
fn clamp_len(len: u32, capacity: u32) -> u32 {
    if len > capacity { capacity } else { len }
}

#[cfg(target_arch = "bpf")]
unsafe fn load_length(map: &LengthMap) -> u32 {
    map.get(0).copied().unwrap_or(0)
}

#[cfg(target_arch = "bpf")]
unsafe fn load_mode_flags() -> u32 {
    MODE_FLAGS.get(0).copied().unwrap_or(0)
}

#[cfg(target_arch = "bpf")]
fn is_observe_mode() -> bool {
    match unsafe { load_mode_flags() } {
        bpf_api::MODE_FLAG_OBSERVE => true,
        bpf_api::MODE_FLAG_ENFORCE => false,
        _ => false,
    }
}

#[cfg(target_arch = "bpf")]
fn deny() -> i32 {
    const EPERM: i32 = 1;
    -EPERM
}

#[cfg(target_arch = "bpf")]
fn deny_with_mode() -> i32 {
    if is_observe_mode() { 0 } else { deny() }
}

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
fn find_c_string_len(bytes: &[u8]) -> usize {
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 0 {
            return i;
        }
        i += 1;
    }
    bytes.len()
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

#[cfg(target_arch = "bpf")]
fn read_user_path_into(path_ptr: *const u8, buf: &mut [u8; 256]) -> bool {
    if path_ptr.is_null() {
        return false;
    }

    match unsafe { bpf_probe_read_user_str_bytes(path_ptr, buf) } {
        Ok(bytes) => {
            let n = bytes.len();
            if n == 0 {
                buf[0] = 0;
            } else if n >= buf.len() {
                buf[buf.len() - 1] = 0;
            } else {
                buf[n] = 0;
            }
            true
        }
        Err(_) => false,
    }
}

#[cfg(target_arch = "bpf")]
fn classify_workload_unit(_path: &[u8], _args: &[&[u8]]) -> u32 {
    bpf_api::UNIT_OTHER
}

#[cfg(target_arch = "bpf")]
fn workload_unit_for_pid(pid: u32) -> u32 {
    unsafe { WORKLOAD_UNITS.get(&pid).copied().unwrap_or(0) }
}

#[cfg(target_arch = "bpf")]
fn set_workload_unit(pid: u32, unit: u32) {
    let _ = unsafe { WORKLOAD_UNITS.insert(&pid, &unit, 0) };
}

#[cfg(target_arch = "bpf")]
fn remove_workload_unit(pid: u32) {
    let _ = unsafe { WORKLOAD_UNITS.remove(&pid) };
}

#[cfg(target_arch = "bpf")]
fn fs_allowed(_path: &[u8; 256], _needed: u8) -> bool {
    true
}

#[cfg(target_arch = "bpf")]
fn classify_and_record_exec(ctx: &SysEnterExecveArgs) {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    let filename_ptr = ctx.args[0] as *const u8;
    let argv_ptr = ctx.args[1] as *const u64;

    let mut path = [0u8; 256];
    let mut unit = bpf_api::UNIT_OTHER;

    if !filename_ptr.is_null() {
        if unsafe { bpf_probe_read_user_str_bytes(filename_ptr, &mut path) }.is_ok() {
            let mut arg_buffers = [[0u8; MAX_ARG_LENGTH]; MAX_CAPTURED_ARGS];
            let mut arg_lens = [0usize; MAX_CAPTURED_ARGS];
            let mut captured = 0usize;

            if !argv_ptr.is_null() {
                let mut idx = 0usize;
                while idx < MAX_CAPTURED_ARGS {
                    let arg_ptr_value: u64 = match unsafe { bpf_probe_read_user(argv_ptr.add(idx)) }
                    {
                        Ok(v) => v,
                        Err(_) => break,
                    };

                    if arg_ptr_value == 0 {
                        break;
                    }

                    let buffer = &mut arg_buffers[idx];
                    if let Ok(bytes) =
                        unsafe { bpf_probe_read_user_str_bytes(arg_ptr_value as *const u8, buffer) }
                    {
                        let mut len: usize = bytes.len();
                        if len > 0 && buffer[len - 1] == 0 {
                            len -= 1;
                        }
                        if len > MAX_ARG_LENGTH {
                            len = MAX_ARG_LENGTH;
                        }

                        arg_lens[idx] = len;
                        captured = idx + 1;
                    } else {
                        break;
                    }

                    idx += 1;
                }
            }

            let mut arg_refs: [&[u8]; MAX_CAPTURED_ARGS] = [&[]; MAX_CAPTURED_ARGS];
            let mut j = 0usize;
            while j < captured {
                let len = arg_lens[j];
                arg_refs[j] = &arg_buffers[j][..len];
                j += 1;
            }

            let path_len = find_c_string_len(&path);
            let command_path = &path[..path_len];
            unit = classify_workload_unit(command_path, &arg_refs[..captured]);
        }
    }

    set_workload_unit(pid, unit);
}

#[cfg(target_arch = "bpf")]
#[unsafe(no_mangle)]
#[unsafe(link_section = "tracepoint/syscalls/sys_enter_execve")]
pub extern "C" fn sys_enter_execve(ctx: *mut c_void) -> i32 {
    let args = unsafe { &*(ctx as *const SysEnterExecveArgs) };
    classify_and_record_exec(args);
    0
}

#[cfg(target_arch = "bpf")]
#[unsafe(no_mangle)]
#[unsafe(link_section = "tracepoint/sched/sched_process_fork")]
pub extern "C" fn sched_process_fork(ctx: *mut c_void) -> i32 {
    let args = unsafe { &*(ctx as *const SchedProcessForkArgs) };
    let parent = args.parent_tgid as u32;
    let child = args.child_tgid as u32;
    let unit = workload_unit_for_pid(parent);
    set_workload_unit(child, unit);
    0
}

#[cfg(target_arch = "bpf")]
#[unsafe(no_mangle)]
#[unsafe(link_section = "tracepoint/sched/sched_process_exit")]
pub extern "C" fn sched_process_exit(ctx: *mut c_void) -> i32 {
    let args = unsafe { &*(ctx as *const SchedProcessExitArgs) };
    let pid = args.pid as u32;
    remove_workload_unit(pid);
    0
}

#[cfg(target_arch = "bpf")]
fn exec_allowlist_len() -> u32 {
    clamp_len(
        unsafe { load_length(&EXEC_ALLOWLIST_LENGTH) },
        bpf_api::EXEC_ALLOWLIST_CAPACITY,
    )
}

#[allow(dead_code)]
const FMODE_READ: u32 = 1;
#[allow(dead_code)]
const FMODE_WRITE: u32 = 2;
#[allow(dead_code)]
const MAY_WRITE: i32 = 2;
#[allow(dead_code)]
const MAY_READ: i32 = 4;
#[allow(dead_code)]
const MAY_APPEND: i32 = 8;

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
#[unsafe(no_mangle)]
#[unsafe(link_section = "lsm/bprm_check_security")]
#[inline(never)]
pub extern "C" fn bprm_check_security(ctx: *mut c_void) -> i32 {
    let filename_ptr = unsafe { *(ctx as *const *const u8) };
    if filename_ptr.is_null() {
        return deny_with_mode();
    }

    let mut buf = [0u8; 256];
    if unsafe { bpf_probe_read_user_str_bytes(filename_ptr, &mut buf) }.is_err() {
        return deny_with_mode();
    }

    let len = exec_allowlist_len();
    let mut i = 0;
    while i < len {
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
