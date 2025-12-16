// PATCH_APPLIED_MARKER
#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(target_arch = "bpf", allow(static_mut_refs))]
#![cfg_attr(target_arch = "bpf", allow(unsafe_op_in_unsafe_fn))]
#![cfg_attr(not(target_arch = "bpf"), allow(dead_code))]

#[cfg(any(test, feature = "fuzzing"))]
use crate::host_shims::{
    fs::{dentry_path_ptr, file_mode_bits, file_path_ptr},
    maps::{DummyRingBuf, TestArray, TestHashMap},
};
#[cfg(target_arch = "bpf")]
use aya_bpf::{
    cty::{c_char, c_long},
    helpers::bpf_probe_read_kernel,
    macros::map,
    maps::{Array, HashMap, RingBuf},
};
#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
use bpf_api::{self, Event};
#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
use core::ffi::{CStr, c_void};
#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
use core::marker::PhantomData;
#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
use core::mem::size_of;

#[cfg(any(test, feature = "fuzzing"))]
mod host_shims;

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
const MAX_CAPTURED_ARGS: usize = 4;

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
const MAX_ARG_LENGTH: usize = 48;

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

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
struct ArrayDescriptor<T, const CAPACITY: usize> {
    #[cfg(any(test, feature = "fuzzing"))]
    name: &'static str,
    _marker: PhantomData<T>,
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
impl<T: Copy, const CAPACITY: usize> ArrayDescriptor<T, CAPACITY> {
    const fn new(name: &'static str) -> Self {
        #[cfg(not(any(test, feature = "fuzzing")))]
        let _ = name;
        Self {
            #[cfg(any(test, feature = "fuzzing"))]
            name,
            _marker: PhantomData,
        }
    }

    #[cfg(target_arch = "bpf")]
    const fn bpf_map(&self) -> Array<T> {
        Array::with_max_entries(CAPACITY as u32, 0)
    }

    #[cfg(any(test, feature = "fuzzing"))]
    const fn host_map(&self) -> TestArray<T, CAPACITY> {
        TestArray::<T, CAPACITY>::new()
    }

    #[cfg(any(test, feature = "fuzzing"))]
    const fn map_descriptor(&self, clear: fn()) -> MapDescriptor {
        MapDescriptor {
            name: self.name,
            kind: MapKind::Array {
                value_size: size_of::<T>() as u32,
            },
            capacity: CAPACITY as u32,
            clear,
        }
    }
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
struct HashMapDescriptor<K, V, const CAPACITY: usize> {
    #[cfg(any(test, feature = "fuzzing"))]
    name: &'static str,
    _marker: PhantomData<(K, V)>,
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
impl<K: Copy + PartialEq, V: Copy, const CAPACITY: usize> HashMapDescriptor<K, V, CAPACITY> {
    const fn new(name: &'static str) -> Self {
        #[cfg(not(any(test, feature = "fuzzing")))]
        let _ = name;
        Self {
            #[cfg(any(test, feature = "fuzzing"))]
            name,
            _marker: PhantomData,
        }
    }

    #[cfg(target_arch = "bpf")]
    const fn bpf_map(&self) -> HashMap<K, V> {
        HashMap::with_max_entries(CAPACITY as u32, 0)
    }

    #[cfg(any(test, feature = "fuzzing"))]
    const fn host_map(&self) -> TestHashMap<K, V, CAPACITY> {
        TestHashMap::<K, V, CAPACITY>::new()
    }

    #[cfg(any(test, feature = "fuzzing"))]
    const fn map_descriptor(&self, clear: fn()) -> MapDescriptor {
        MapDescriptor {
            name: self.name,
            kind: MapKind::HashMap {
                key_size: size_of::<K>() as u32,
                value_size: size_of::<V>() as u32,
            },
            capacity: CAPACITY as u32,
            clear,
        }
    }
}

#[cfg(target_arch = "bpf")]
#[unsafe(no_mangle)]
pub extern "C" fn __bpf_trap() -> ! {
    loop {}
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
struct RingBufDescriptor<const BYTE_SIZE: usize> {
    #[cfg(any(test, feature = "fuzzing"))]
    name: &'static str,
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
impl<const BYTE_SIZE: usize> RingBufDescriptor<BYTE_SIZE> {
    const fn new(name: &'static str) -> Self {
        #[cfg(not(any(test, feature = "fuzzing")))]
        let _ = name;
        Self {
            #[cfg(any(test, feature = "fuzzing"))]
            name,
        }
    }

    #[cfg(target_arch = "bpf")]
    const fn bpf_map(&self) -> RingBuf {
        RingBuf::with_byte_size(BYTE_SIZE as u32, 0)
    }

    #[cfg(any(test, feature = "fuzzing"))]
    const fn host_map(&self) -> DummyRingBuf {
        DummyRingBuf::new()
    }

    #[cfg(any(test, feature = "fuzzing"))]
    const fn map_descriptor(&self, clear: fn()) -> MapDescriptor {
        MapDescriptor {
            name: self.name,
            kind: MapKind::RingBuf {
                byte_size: BYTE_SIZE as u32,
            },
            capacity: BYTE_SIZE as u32,
            clear,
        }
    }
}

#[cfg(any(test, feature = "fuzzing"))]
#[derive(Clone, Copy)]
pub struct MapDescriptor {
    pub name: &'static str,
    pub kind: MapKind,
    pub capacity: u32,
    pub clear: fn(),
}

#[cfg(any(test, feature = "fuzzing"))]
#[derive(Clone, Copy)]
pub enum MapKind {
    Array { value_size: u32 },
    HashMap { key_size: u32, value_size: u32 },
    RingBuf { byte_size: u32 },
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
const EXEC_ALLOWLIST_DESCRIPTOR: ArrayDescriptor<
    bpf_api::ExecAllowEntry,
    { bpf_api::EXEC_ALLOWLIST_CAPACITY as usize },
> = ArrayDescriptor::new("EXEC_ALLOWLIST");
#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
const EXEC_ALLOWLIST_LENGTH_DESCRIPTOR: ArrayDescriptor<u32, 1> =
    ArrayDescriptor::new("EXEC_ALLOWLIST_LENGTH");
#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
const NET_RULES_DESCRIPTOR: ArrayDescriptor<
    bpf_api::NetRuleEntry,
    { bpf_api::NET_RULES_CAPACITY as usize },
> = ArrayDescriptor::new("NET_RULES");
#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
const NET_RULES_LENGTH_DESCRIPTOR: ArrayDescriptor<u32, 1> =
    ArrayDescriptor::new("NET_RULES_LENGTH");
#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
const NET_PARENTS_DESCRIPTOR: ArrayDescriptor<
    bpf_api::NetParentEntry,
    { bpf_api::NET_PARENTS_CAPACITY as usize },
> = ArrayDescriptor::new("NET_PARENTS");
#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
const NET_PARENTS_LENGTH_DESCRIPTOR: ArrayDescriptor<u32, 1> =
    ArrayDescriptor::new("NET_PARENTS_LENGTH");
#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
const FS_RULES_DESCRIPTOR: ArrayDescriptor<
    bpf_api::FsRuleEntry,
    { bpf_api::FS_RULES_CAPACITY as usize },
> = ArrayDescriptor::new("FS_RULES");
#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
const FS_RULES_LENGTH_DESCRIPTOR: ArrayDescriptor<u32, 1> = ArrayDescriptor::new("FS_RULES_LENGTH");
#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
const MODE_FLAGS_DESCRIPTOR: ArrayDescriptor<u32, { bpf_api::MODE_FLAGS_CAPACITY as usize }> =
    ArrayDescriptor::new("MODE_FLAGS");
#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
const WORKLOAD_UNITS_DESCRIPTOR: HashMapDescriptor<
    u32,
    u32,
    { bpf_api::WORKLOAD_UNITS_CAPACITY as usize },
> = HashMapDescriptor::new("WORKLOAD_UNITS");
#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
const EVENTS_DESCRIPTOR: RingBufDescriptor<{ bpf_api::EVENT_RINGBUF_CAPACITY_BYTES as usize }> =
    RingBufDescriptor::new("EVENTS");

#[cfg(target_arch = "bpf")]
type ExecAllowlistMap = Array<bpf_api::ExecAllowEntry>;
#[cfg(any(test, feature = "fuzzing"))]
type ExecAllowlistMap =
    TestArray<bpf_api::ExecAllowEntry, { bpf_api::EXEC_ALLOWLIST_CAPACITY as usize }>;

#[cfg(target_arch = "bpf")]
type LengthMap = Array<u32>;
#[cfg(any(test, feature = "fuzzing"))]
type LengthMap = TestArray<u32, 1>;

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
type ModeFlagsMap = Array<u32>;
#[cfg(any(test, feature = "fuzzing"))]
type ModeFlagsMap = TestArray<u32, { bpf_api::MODE_FLAGS_CAPACITY as usize }>;

#[cfg(target_arch = "bpf")]
type WorkloadUnitsMap = HashMap<u32, u32>;
#[cfg(any(test, feature = "fuzzing"))]
type WorkloadUnitsMap = TestHashMap<u32, u32, { bpf_api::WORKLOAD_UNITS_CAPACITY as usize }>;

#[cfg(target_arch = "bpf")]
type EventsMap = RingBuf;
#[cfg(any(test, feature = "fuzzing"))]
type EventsMap = DummyRingBuf;

#[cfg(target_arch = "bpf")]
#[map(name = "EXEC_ALLOWLIST")]
static mut EXEC_ALLOWLIST: ExecAllowlistMap = EXEC_ALLOWLIST_DESCRIPTOR.bpf_map();

#[cfg(any(test, feature = "fuzzing"))]
static EXEC_ALLOWLIST: ExecAllowlistMap = EXEC_ALLOWLIST_DESCRIPTOR.host_map();

#[cfg(target_arch = "bpf")]
#[map(name = "EXEC_ALLOWLIST_LENGTH")]
static mut EXEC_ALLOWLIST_LENGTH: LengthMap = EXEC_ALLOWLIST_LENGTH_DESCRIPTOR.bpf_map();

#[cfg(any(test, feature = "fuzzing"))]
static EXEC_ALLOWLIST_LENGTH: LengthMap = EXEC_ALLOWLIST_LENGTH_DESCRIPTOR.host_map();

#[cfg(target_arch = "bpf")]
#[map(name = "NET_RULES")]
static mut NET_RULES: NetRulesMap = NET_RULES_DESCRIPTOR.bpf_map();

#[cfg(any(test, feature = "fuzzing"))]
static NET_RULES: NetRulesMap = NET_RULES_DESCRIPTOR.host_map();

#[cfg(target_arch = "bpf")]
#[map(name = "NET_RULES_LENGTH")]
static mut NET_RULES_LENGTH: LengthMap = NET_RULES_LENGTH_DESCRIPTOR.bpf_map();

#[cfg(any(test, feature = "fuzzing"))]
static NET_RULES_LENGTH: LengthMap = NET_RULES_LENGTH_DESCRIPTOR.host_map();

#[cfg(target_arch = "bpf")]
#[map(name = "NET_PARENTS")]
static mut NET_PARENTS: NetParentsMap = NET_PARENTS_DESCRIPTOR.bpf_map();

#[cfg(any(test, feature = "fuzzing"))]
static NET_PARENTS: NetParentsMap = NET_PARENTS_DESCRIPTOR.host_map();

#[cfg(target_arch = "bpf")]
#[map(name = "NET_PARENTS_LENGTH")]
static mut NET_PARENTS_LENGTH: LengthMap = NET_PARENTS_LENGTH_DESCRIPTOR.bpf_map();

#[cfg(any(test, feature = "fuzzing"))]
static NET_PARENTS_LENGTH: LengthMap = NET_PARENTS_LENGTH_DESCRIPTOR.host_map();

#[cfg(target_arch = "bpf")]
#[map(name = "FS_RULES")]
static mut FS_RULES: FsRulesMap = FS_RULES_DESCRIPTOR.bpf_map();

#[cfg(any(test, feature = "fuzzing"))]
static FS_RULES: FsRulesMap = FS_RULES_DESCRIPTOR.host_map();

#[cfg(target_arch = "bpf")]
#[map(name = "FS_RULES_LENGTH")]
static mut FS_RULES_LENGTH: LengthMap = FS_RULES_LENGTH_DESCRIPTOR.bpf_map();

#[cfg(any(test, feature = "fuzzing"))]
static FS_RULES_LENGTH: LengthMap = FS_RULES_LENGTH_DESCRIPTOR.host_map();

#[cfg(target_arch = "bpf")]
#[cfg(target_arch = "bpf")]
#[map(name = "MODE_FLAGS")]
static mut MODE_FLAGS: ModeFlagsMap = MODE_FLAGS_DESCRIPTOR.bpf_map();

#[cfg(any(test, feature = "fuzzing"))]
static MODE_FLAGS: ModeFlagsMap = MODE_FLAGS_DESCRIPTOR.host_map();

#[cfg(target_arch = "bpf")]
#[map(name = "WORKLOAD_UNITS")]
static mut WORKLOAD_UNITS: WorkloadUnitsMap = WORKLOAD_UNITS_DESCRIPTOR.bpf_map();

#[cfg(any(test, feature = "fuzzing"))]
static WORKLOAD_UNITS: WorkloadUnitsMap = WORKLOAD_UNITS_DESCRIPTOR.host_map();

#[cfg(target_arch = "bpf")]
#[map(name = "EVENTS")]
static mut EVENTS: EventsMap = EVENTS_DESCRIPTOR.bpf_map();

#[cfg(any(test, feature = "fuzzing"))]
static EVENTS: EventsMap = EVENTS_DESCRIPTOR.host_map();

#[cfg(any(test, feature = "fuzzing"))]
fn clear_array<T: Copy, const CAPACITY: usize>(map: &'static TestArray<T, CAPACITY>) {
    map.clear();
}

#[cfg(any(test, feature = "fuzzing"))]
fn clear_hash_map<K: Copy + PartialEq, V: Copy, const CAPACITY: usize>(
    map: &'static TestHashMap<K, V, CAPACITY>,
) {
    map.clear();
}

#[cfg(any(test, feature = "fuzzing"))]
fn clear_exec_allowlist() {
    clear_array(&EXEC_ALLOWLIST);
}

#[cfg(any(test, feature = "fuzzing"))]
fn clear_exec_allowlist_length() {
    clear_array(&EXEC_ALLOWLIST_LENGTH);
}

#[cfg(any(test, feature = "fuzzing"))]
fn clear_net_rules() {
    clear_array(&NET_RULES);
}

#[cfg(any(test, feature = "fuzzing"))]
fn clear_net_rules_length() {
    clear_array(&NET_RULES_LENGTH);
}

#[cfg(any(test, feature = "fuzzing"))]
fn clear_net_parents() {
    clear_array(&NET_PARENTS);
}

#[cfg(any(test, feature = "fuzzing"))]
fn clear_net_parents_length() {
    clear_array(&NET_PARENTS_LENGTH);
}

#[cfg(any(test, feature = "fuzzing"))]
fn clear_fs_rules() {
    clear_array(&FS_RULES);
}

#[cfg(any(test, feature = "fuzzing"))]
fn clear_fs_rules_length() {
    clear_array(&FS_RULES_LENGTH);
}

#[cfg(any(test, feature = "fuzzing"))]
#[cfg(any(test, feature = "fuzzing"))]
fn clear_mode_flags() {
    clear_array(&MODE_FLAGS);
}

#[cfg(any(test, feature = "fuzzing"))]
fn clear_workload_units_map() {
    clear_hash_map(&WORKLOAD_UNITS);
}

#[cfg(any(test, feature = "fuzzing"))]
fn clear_events_map() {
    EVENTS.clear();
}

#[cfg(any(test, feature = "fuzzing"))]
const HOST_MAP_DESCRIPTORS: &[MapDescriptor] = &[
    EXEC_ALLOWLIST_DESCRIPTOR.map_descriptor(clear_exec_allowlist),
    EXEC_ALLOWLIST_LENGTH_DESCRIPTOR.map_descriptor(clear_exec_allowlist_length),
    NET_RULES_DESCRIPTOR.map_descriptor(clear_net_rules),
    NET_RULES_LENGTH_DESCRIPTOR.map_descriptor(clear_net_rules_length),
    NET_PARENTS_DESCRIPTOR.map_descriptor(clear_net_parents),
    NET_PARENTS_LENGTH_DESCRIPTOR.map_descriptor(clear_net_parents_length),
    FS_RULES_DESCRIPTOR.map_descriptor(clear_fs_rules),
    FS_RULES_LENGTH_DESCRIPTOR.map_descriptor(clear_fs_rules_length),
    MODE_FLAGS_DESCRIPTOR.map_descriptor(clear_mode_flags),
    WORKLOAD_UNITS_DESCRIPTOR.map_descriptor(clear_workload_units_map),
    EVENTS_DESCRIPTOR.map_descriptor(clear_events_map),
];

#[cfg(any(test, feature = "fuzzing"))]
pub mod host_maps;

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
unsafe fn load_mode_flags() -> u32 {
    #[cfg(target_arch = "bpf")]
    {
        MODE_FLAGS.get(0).copied().unwrap_or(0)
    }

    #[cfg(any(test, feature = "fuzzing"))]
    {
        MODE_FLAGS.get(0).unwrap_or(0)
    }
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
unsafe fn load_length(map: &LengthMap) -> u32 {
    #[cfg(target_arch = "bpf")]
    {
        map.get(0).copied().unwrap_or(0)
    }

    #[cfg(any(test, feature = "fuzzing"))]
    {
        map.get(0).unwrap_or(0)
    }
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

// define_map_accessors!(
//     load_fs_rule,
//     fs_rules_len,
//     FS_RULES,
//     FS_RULES_LENGTH,
//     bpf_api::FsRuleEntry,
//     bpf_api::FS_RULES_CAPACITY
// );

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

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn slice_eq_ignore_ascii_case(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut i = 0;
    while i < left.len() {
        let a = left[i];
        let b = right[i];
        if a == b {
            i += 1;
            continue;
        }
        let upper_a = if a.is_ascii_uppercase() { a + 32 } else { a };
        let upper_b = if b.is_ascii_uppercase() { b + 32 } else { b };
        if upper_a != upper_b {
            return false;
        }
        i += 1;
    }
    true
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        if slice_eq_ignore_ascii_case(&haystack[i..i + needle.len()], needle) {
            return true;
        }
        i += 1;
    }
    false
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn filename_from_path(path: &[u8]) -> &[u8] {
    let mut start = 0usize;
    let mut i = 0usize;
    while i < path.len() {
        match path[i] {
            b'/' | b'\\' => start = i + 1,
            _ => {}
        }
        i += 1;
    }
    &path[start..]
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn arg_matches_proc_macro(arg: &[u8]) -> bool {
    contains_ascii_case_insensitive(arg, b"proc-macro")
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn args_include_proc_macro(args: &[&[u8]]) -> bool {
    let mut i = 0usize;
    while i < args.len() {
        let current = args[i];
        if contains_ascii_case_insensitive(current, b"--crate-type=proc-macro") {
            return true;
        }
        if slice_eq_ignore_ascii_case(current, b"--crate-type") {
            if let Some(next) = args.get(i + 1)
                && arg_matches_proc_macro(next)
            {
                return true;
            }
        } else if slice_eq_ignore_ascii_case(current, b"--crate-type=proc-macro") {
            return true;
        }
        i += 1;
    }
    false
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn is_build_script(path: &[u8], filename: &[u8]) -> bool {
    contains_ascii_case_insensitive(filename, b"build-script")
        || contains_ascii_case_insensitive(path, b"/build-script-")
        || contains_ascii_case_insensitive(path, b"\\build-script-")
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn is_rustc(filename: &[u8]) -> bool {
    slice_eq_ignore_ascii_case(filename, b"rustc")
        || slice_eq_ignore_ascii_case(filename, b"rustc.exe")
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn is_cargo(filename: &[u8]) -> bool {
    slice_eq_ignore_ascii_case(filename, b"cargo")
        || slice_eq_ignore_ascii_case(filename, b"cargo.exe")
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn is_linker(filename: &[u8]) -> bool {
    const LINKER_NAMES: [&[u8]; 12] = [
        b"ld",
        b"ld.lld",
        b"ld64",
        b"lld",
        b"link",
        b"link.exe",
        b"cc",
        b"clang",
        b"clang++",
        b"gcc",
        b"g++",
        b"collect2",
    ];
    let mut i = 0usize;
    while i < LINKER_NAMES.len() {
        if slice_eq_ignore_ascii_case(filename, LINKER_NAMES[i]) {
            return true;
        }
        i += 1;
    }
    false
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn classify_workload_unit(path: &[u8], args: &[&[u8]]) -> u32 {
    let filename = filename_from_path(path);
    if is_build_script(path, filename) {
        return bpf_api::UNIT_BUILD_SCRIPT;
    }
    if is_linker(filename) {
        return bpf_api::UNIT_LINKER;
    }
    if is_rustc(filename) {
        if args_include_proc_macro(args) {
            return bpf_api::UNIT_PROC_MACRO;
        }
        return bpf_api::UNIT_RUSTC;
    }
    if is_cargo(filename) {
        return bpf_api::UNIT_OTHER;
    }
    bpf_api::UNIT_OTHER
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
static mut CURRENT_UNIT: u32 = 0;

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn current_unit() -> u32 {
    refresh_current_unit();
    unsafe { CURRENT_UNIT }
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn workload_unit_for_pid(pid: u32) -> u32 {
    #[cfg(target_arch = "bpf")]
    {
        unsafe { WORKLOAD_UNITS.get(&pid).copied().unwrap_or(0) }
    }

    #[cfg(any(test, feature = "fuzzing"))]
    {
        WORKLOAD_UNITS.get(pid).unwrap_or(0)
    }
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn set_workload_unit(pid: u32, unit: u32) {
    #[cfg(target_arch = "bpf")]
    {
        let _ = unsafe { WORKLOAD_UNITS.insert(&pid, &unit, 0) };
    }

    #[cfg(any(test, feature = "fuzzing"))]
    {
        WORKLOAD_UNITS.insert(pid, unit);
    }
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn remove_workload_unit(pid: u32) {
    #[cfg(target_arch = "bpf")]
    {
        let _ = unsafe { WORKLOAD_UNITS.remove(&pid) };
    }

    #[cfg(any(test, feature = "fuzzing"))]
    {
        WORKLOAD_UNITS.remove(pid);
    }
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn refresh_current_unit() {
    let pid = unsafe { (bpf_get_current_pid_tgid() >> 32) as u32 };
    let unit = workload_unit_for_pid(pid);
    unsafe {
        CURRENT_UNIT = unit;
    }
}

#[cfg(any(test, feature = "fuzzing"))]
fn clear_workload_units() {
    host_maps::clear_by_name("WORKLOAD_UNITS");
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
fn c_path(buf: &[u8; 256]) -> Option<&CStr> {
    CStr::from_bytes_until_nul(buf).ok()
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn c_str_len(path: &CStr) -> usize {
    path.to_bytes().len()
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn trimmed_len(path: &CStr) -> usize {
    let bytes = path.to_bytes();
    if bytes.len() <= 1 {
        return bytes.len();
    }
    bytes
        .iter()
        .rposition(|&b| b != b'/')
        .map(|idx| idx + 1)
        .unwrap_or(1)
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn trimmed_bytes(path: &CStr) -> &[u8] {
    let len = trimmed_len(path);
    &path.to_bytes()[..len]
}

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn path_prefix_matches(rule_path: &CStr, actual_path: &CStr) -> bool {
    let rule_bytes = trimmed_bytes(rule_path);
    if rule_bytes.is_empty() {
        return false;
    }
    let path_len = c_str_len(actual_path);
    if rule_bytes.len() > path_len {
        return false;
    }
    let actual_bytes = actual_path.to_bytes();
    if !actual_bytes.starts_with(rule_bytes) {
        return false;
    }
    if rule_bytes.len() == path_len {
        return true;
    }
    if rule_bytes.last().copied() == Some(b'/') {
        return true;
    }
    actual_bytes.get(rule_bytes.len()).copied() == Some(b'/')
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
#[inline(never)]
fn fs_entry_allows(entry: &bpf_api::FsRuleEntry, path: &CStr, needed: u8) -> bool {
    if !rule_allows_access(entry.rule.access, needed) {
        return false;
    }
    let Some(rule_path) = c_path(&entry.rule.path) else {
        return false;
    };
    path_prefix_matches(rule_path, path)
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

#[cfg(any(test, feature = "fuzzing"))]
#[inline(never)]
fn unit_fs_allowed(unit: u32, path: &CStr, needed: u8) -> bool {
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
    let Some(path) = c_path(path) else {
        return false;
    };
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

// #[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
// #[inline(never)]
// fn read_user_path(path_ptr: *const u8) -> Option<[u8; 256]> {
//     if path_ptr.is_null() {
//         return None;
//     }
//     let mut buf = [0u8; 256];
//     let res = unsafe { bpf_probe_read_user_str(buf.as_mut_ptr(), buf.len() as u32, path_ptr) };
//     if res < 0 { None } else { Some(buf) }
// }

#[cfg(any(target_arch = "bpf", test, feature = "fuzzing"))]
fn read_user_path_into(path_ptr: *const u8, buf: &mut [u8; 256]) -> bool {
    if path_ptr.is_null() {
        return false;
    }
    let res = unsafe { bpf_probe_read_user_str(buf.as_mut_ptr(), buf.len() as u32, path_ptr) };
    res >= 0
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

#[cfg(any(test, feature = "fuzzing"))]
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
    let event = fs_event(ACTION_OPEN, &path, access, allowed);
    publish_event(&event);
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

#[cfg(any(test, feature = "fuzzing"))]
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
        let event = fs_event(ACTION_OPEN, &path, access, false);
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
    let mut path = [0u8; 256];

    let old_path_ptr = match dentry_path_ptr(old_dentry) {
        Some(ptr) => ptr,
        None => return deny_with_mode(),
    };
    if !read_user_path_into(old_path_ptr, &mut path) {
        return deny_with_mode();
    }

    let mut allowed = true;

    if !fs_allowed(&path, bpf_api::FS_WRITE) {
        let event = fs_event(ACTION_RENAME, &path, bpf_api::FS_WRITE, false);
        publish_event(&event);
        allowed = false;
    }

    let new_path_ptr = match dentry_path_ptr(new_dentry) {
        Some(ptr) => ptr,
        None => return deny_with_mode(),
    };
    if !read_user_path_into(new_path_ptr, &mut path) {
        return deny_with_mode();
    }

    if !fs_allowed(&path, bpf_api::FS_WRITE) {
        let event = fs_event(ACTION_RENAME, &path, bpf_api::FS_WRITE, false);
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

    let mut path = [0u8; 256];
    if !read_user_path_into(path_ptr, &mut path) {
        return deny_with_mode();
    }

    if fs_allowed(&path, bpf_api::FS_WRITE) {
        0
    } else {
        let event = fs_event(ACTION_UNLINK, &path, bpf_api::FS_WRITE, false);
        publish_event(&event);
        deny_with_mode()
    }
}

#[cfg(test)]
mod tests;

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
    pub extern "C" fn bpf_ktime_get_ns() -> u64 {
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

    #[unsafe(no_mangle)]
    pub extern "C" fn bpf_probe_read_user(dst: *mut c_void, size: u32, src: *const c_void) -> i32 {
        if dst.is_null() || src.is_null() {
            return -1;
        }
        let size = size as usize;
        let mut offset = 0usize;

        unsafe {
            while offset < size {
                let byte = *(src as *const u8).add(offset);
                *(dst as *mut u8).add(offset) = byte;
                offset += 1;
            }
        }
        0
    }
}
