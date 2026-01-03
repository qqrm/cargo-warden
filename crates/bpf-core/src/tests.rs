use super::*;
use crate::host_maps;
use crate::host_shims::{
    fs::{TestDentry, TestFile},
    net::resolve_host,
};
use bpf_api::{FS_READ, FS_WRITE};
use core::ffi::c_void;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::Mutex;

static EVENTS: Mutex<Vec<Event>> = Mutex::new(Vec::new());
static TEST_LOCK: Mutex<()> = Mutex::new(());
const TEST_PID: u32 = 1234;
const TEST_TGID: u32 = 4321;
const TEST_TIME_NS: u64 = 123_456_789;

fn workspace_root_path() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest.ancestors().nth(2).expect("workspace root");
    std::fs::canonicalize(workspace).unwrap_or_else(|_| workspace.to_path_buf())
}

fn workspace_root_string() -> String {
    workspace_root_path().to_string_lossy().into_owned()
}

fn target_dir_string() -> String {
    let target = workspace_root_path().join("target");
    std::fs::canonicalize(&target)
        .unwrap_or(target)
        .to_string_lossy()
        .into_owned()
}

fn default_fs_rules() -> Vec<bpf_api::FsRuleEntry> {
    let target = target_dir_string();
    let workspace = workspace_root_string();
    vec![
        fs_rule_entry(0, &target, FS_READ | FS_WRITE),
        fs_rule_entry(0, &workspace, FS_READ),
    ]
}

fn reset_events() {
    EVENTS.lock().unwrap().clear();
    host_maps::clear_by_name("EVENTS");
}

fn record_event(event: Event) {
    EVENTS.lock().unwrap().push(event);
}

fn event_count() -> usize {
    EVENTS.lock().unwrap().len()
}

fn last_event() -> Option<Event> {
    EVENTS.lock().unwrap().last().copied()
}

#[unsafe(no_mangle)]
extern "C" fn bpf_ringbuf_output(
    _ringbuf: *mut c_void,
    data: *const c_void,
    len: u64,
    _flags: u64,
) -> i64 {
    assert_eq!(len as usize, core::mem::size_of::<Event>());
    let event = unsafe { *(data as *const Event) };
    record_event(event);
    0
}

#[unsafe(no_mangle)]
extern "C" fn bpf_get_current_pid_tgid() -> u64 {
    ((TEST_PID as u64) << 32) | (TEST_TGID as u64)
}

#[unsafe(no_mangle)]
extern "C" fn bpf_ktime_get_ns() -> u64 {
    TEST_TIME_NS
}

fn assign_unit(unit: u32) {
    set_workload_unit(TEST_PID, unit);
    refresh_current_unit();
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
    assert!(
        !is_observe_mode(),
        "enforce mode should be active by default"
    );
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
    assert!(is_observe_mode(), "observe mode should be enabled");
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
    reset_events();
    let path = "/var/warden/allowed/file.txt";
    set_fs_rules(&[fs_rule_entry(0, path, FS_READ | FS_WRITE)]);
    let path_bytes = c_string(path);
    let mut file = TestFile {
        path: path_bytes.as_ptr(),
        mode: FMODE_READ,
    };
    let result = file_open((&mut file) as *mut _ as *mut c_void, ptr::null_mut());
    assert_eq!(result, 0);
    let event = last_event().expect("event");
    assert_eq!(event.pid, 1234);
    assert_eq!(event.tgid, 4321);
    assert_eq!(event.time_ns, 123_456_789);
    assert_eq!(event.unit, 0);
    assert_eq!(event.action, ACTION_OPEN);
    assert_eq!(event.verdict, 0);
    assert_eq!(bytes_to_string(&event.path_or_addr), path);
    assert!(bytes_to_string(&event.needed_perm).is_empty());
    let count = event_count();
    assert_eq!(count, 1);
}

#[test]
fn file_open_denies_without_rule() {
    let _g = TEST_LOCK.lock().unwrap();
    reset_network_state();
    reset_fs_state();
    reset_events();
    let rules = default_fs_rules();
    set_fs_rules(&rules);
    let allowed_path = format!("{}/README.md", workspace_root_string());
    let allowed_bytes = c_string(&allowed_path);
    let mut allowed_file = TestFile {
        path: allowed_bytes.as_ptr(),
        mode: FMODE_READ,
    };
    assert_eq!(
        file_open(
            (&mut allowed_file) as *mut _ as *mut c_void,
            ptr::null_mut()
        ),
        0
    );
    let allowed_event = last_event().expect("event");
    assert_eq!(allowed_event.action, ACTION_OPEN);
    assert_eq!(allowed_event.verdict, 0);
    assert_eq!(bytes_to_string(&allowed_event.path_or_addr), allowed_path);
    assert!(bytes_to_string(&allowed_event.needed_perm).is_empty());
    let allowed_count = event_count();
    assert_eq!(allowed_count, 1);
    reset_events();
    let path = "/etc/warden/forbidden.txt";
    let path_bytes = c_string(path);
    let mut file = TestFile {
        path: path_bytes.as_ptr(),
        mode: FMODE_READ,
    };
    let result = file_open((&mut file) as *mut _ as *mut c_void, ptr::null_mut());
    assert_ne!(result, 0);
    let event = last_event().expect("event");
    assert_eq!(event.action, ACTION_OPEN);
    assert_eq!(event.verdict, 1);
    assert_eq!(bytes_to_string(&event.path_or_addr), path);
    assert_eq!(bytes_to_string(&event.needed_perm), "allow.fs.read_extra");
}

#[test]
fn file_open_observe_mode_allows_but_logs() {
    let _g = TEST_LOCK.lock().unwrap();
    reset_network_state();
    reset_fs_state();
    enable_observe_mode();
    assert!(is_observe_mode(), "observe mode should be enabled");
    reset_events();
    let path = "/var/warden/forbidden.txt";
    let path_bytes = c_string(path);
    let mut file = TestFile {
        path: path_bytes.as_ptr(),
        mode: FMODE_READ,
    };
    let result = file_open((&mut file) as *mut _ as *mut c_void, ptr::null_mut());
    assert_eq!(result, 0);
    let event = last_event().expect("event");
    assert_eq!(event.action, ACTION_OPEN);
    assert_eq!(event.verdict, 1);
    assert_eq!(bytes_to_string(&event.path_or_addr), path);
    assert_eq!(bytes_to_string(&event.needed_perm), "allow.fs.read_extra");
    let count = event_count();
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
    reset_events();
    assert_eq!(file_permission(file_ptr, MAY_READ), 0);
    assert!(last_event().is_none());

    reset_events();
    assert_ne!(file_permission(file_ptr, MAY_WRITE), 0);
    let event = last_event().expect("event");
    assert_eq!(event.action, ACTION_OPEN);
    assert_eq!(event.verdict, 1);
    assert_eq!(bytes_to_string(&event.path_or_addr), path);

    set_fs_rules(&[fs_rule_entry(0, path, FS_READ | FS_WRITE)]);
    reset_events();
    assert_eq!(file_permission(file_ptr, MAY_WRITE), 0);
    assert!(last_event().is_none());
}

#[test]
fn file_permission_observe_mode_allows_but_logs() {
    let _g = TEST_LOCK.lock().unwrap();
    reset_network_state();
    reset_fs_state();
    enable_observe_mode();
    assert!(is_observe_mode(), "observe mode should be enabled");
    let path = "/workspace/read-only";
    set_fs_rules(&[fs_rule_entry(0, path, FS_READ)]);
    let path_bytes = c_string(path);
    let mut file = TestFile {
        path: path_bytes.as_ptr(),
        mode: FMODE_READ,
    };
    let file_ptr = (&mut file) as *mut _ as *mut c_void;
    reset_events();
    let result = file_permission(file_ptr, MAY_WRITE);
    assert_eq!(result, 0);
    let event = last_event().expect("event");
    assert_eq!(event.action, ACTION_OPEN);
    assert_eq!(event.verdict, 1);
    assert_eq!(bytes_to_string(&event.path_or_addr), path);
}

#[test]
fn file_open_allows_workspace_defaults() {
    let _g = TEST_LOCK.lock().unwrap();
    reset_network_state();
    reset_fs_state();
    reset_events();
    let rules = default_fs_rules();
    set_fs_rules(&rules);
    let path = format!("{}/README.md", workspace_root_string());
    let path_bytes = c_string(&path);
    let mut file = TestFile {
        path: path_bytes.as_ptr(),
        mode: FMODE_READ,
    };
    let result = file_open((&mut file) as *mut _ as *mut c_void, ptr::null_mut());
    assert_eq!(result, 0);
    let event = last_event().expect("event");
    assert_eq!(event.action, ACTION_OPEN);
    assert_eq!(event.verdict, 0);
    assert_eq!(bytes_to_string(&event.path_or_addr), path);
    let count = event_count();
    assert_eq!(count, 1);
}

#[test]
fn file_open_rejects_null_path_pointer() {
    let _g = TEST_LOCK.lock().unwrap();
    reset_network_state();
    reset_fs_state();
    reset_events();
    let mut file = TestFile {
        path: ptr::null(),
        mode: FMODE_READ,
    };
    let result = file_open((&mut file) as *mut _ as *mut c_void, ptr::null_mut());
    assert_ne!(result, 0);
    assert!(last_event().is_none());
    let count = event_count();
    assert_eq!(count, 0);
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
    let rules = default_fs_rules();
    set_fs_rules(&rules);
    let workspace_path = format!("{}/SPEC.md", workspace_root_string());
    let workspace_bytes = c_string(&workspace_path);
    let mut workspace_file = TestFile {
        path: workspace_bytes.as_ptr(),
        mode: FMODE_READ,
    };
    let workspace_ptr = (&mut workspace_file) as *mut _ as *mut c_void;
    assert_eq!(file_permission(workspace_ptr, MAY_READ), 0);

    let target_path = format!("{}/build/artifact.txt", target_dir_string());
    let target_bytes = c_string(&target_path);
    let mut target_file = TestFile {
        path: target_bytes.as_ptr(),
        mode: FMODE_READ | FMODE_WRITE,
    };
    let target_ptr = (&mut target_file) as *mut _ as *mut c_void;
    assert_eq!(file_permission(target_ptr, MAY_WRITE), 0);

    let file_path = c_string("/etc/warden/data.txt");
    let mut file = TestFile {
        path: file_path.as_ptr(),
        mode: FMODE_READ,
    };
    let file_ptr = (&mut file) as *mut _ as *mut c_void;
    assert_ne!(file_permission(file_ptr, MAY_READ), 0);
}

#[test]
fn file_permission_allows_workspace_default_read() {
    let _g = TEST_LOCK.lock().unwrap();
    reset_network_state();
    reset_fs_state();
    let rules = default_fs_rules();
    set_fs_rules(&rules);
    let path = format!("{}/SPEC.md", workspace_root_string());
    let path_bytes = c_string(&path);
    let mut file = TestFile {
        path: path_bytes.as_ptr(),
        mode: FMODE_READ,
    };
    let file_ptr = (&mut file) as *mut _ as *mut c_void;
    assert_eq!(file_permission(file_ptr, MAY_READ), 0);
}

#[test]
fn file_permission_allows_target_default_write() {
    let _g = TEST_LOCK.lock().unwrap();
    reset_network_state();
    reset_fs_state();
    let rules = default_fs_rules();
    set_fs_rules(&rules);
    let path = format!("{}/build/artifact.txt", target_dir_string());
    let path_bytes = c_string(&path);
    let mut file = TestFile {
        path: path_bytes.as_ptr(),
        mode: FMODE_READ | FMODE_WRITE,
    };
    let file_ptr = (&mut file) as *mut _ as *mut c_void;
    assert_eq!(file_permission(file_ptr, MAY_WRITE), 0);
}

#[test]
fn file_permission_allows_prefix_rule() {
    let _g = TEST_LOCK.lock().unwrap();
    reset_network_state();
    reset_fs_state();
    let rule_path = "/var/data";
    set_fs_rules(&[fs_rule_entry(0, rule_path, FS_READ | FS_WRITE)]);
    let file_path = c_string("/var/data/subdir/file.txt");
    let mut file = TestFile {
        path: file_path.as_ptr(),
        mode: FMODE_READ,
    };
    let file_ptr = (&mut file) as *mut _ as *mut c_void;
    assert_eq!(file_permission(file_ptr, MAY_READ), 0);
}

#[test]
fn file_permission_allows_rule_with_trailing_slash() {
    let _g = TEST_LOCK.lock().unwrap();
    reset_network_state();
    reset_fs_state();
    set_fs_rules(&[fs_rule_entry(0, "/var/data/", FS_READ | FS_WRITE)]);

    let file_path = c_string("/var/data/report.log");
    let mut file = TestFile {
        path: file_path.as_ptr(),
        mode: FMODE_READ | FMODE_WRITE,
    };
    let file_ptr = (&mut file) as *mut _ as *mut c_void;
    assert_eq!(file_permission(file_ptr, MAY_READ), 0);
    assert_eq!(file_permission(file_ptr, MAY_WRITE), 0);

    let dir_path = c_string("/var/data/");
    let mut dir = TestFile {
        path: dir_path.as_ptr(),
        mode: FMODE_READ,
    };
    let dir_ptr = (&mut dir) as *mut _ as *mut c_void;
    assert_eq!(file_permission(dir_ptr, MAY_READ), 0);
}

#[test]
fn file_permission_denies_mismatched_prefix() {
    let _g = TEST_LOCK.lock().unwrap();
    reset_network_state();
    reset_fs_state();
    let rule_path = "/var/data";
    set_fs_rules(&[fs_rule_entry(0, rule_path, FS_READ | FS_WRITE)]);
    let file_path = c_string("/var/database");
    let mut file = TestFile {
        path: file_path.as_ptr(),
        mode: FMODE_READ,
    };
    let file_ptr = (&mut file) as *mut _ as *mut c_void;
    assert_ne!(file_permission(file_ptr, MAY_READ), 0);
}

#[test]
fn file_permission_denies_trailing_slash_rule_without_separator() {
    let _g = TEST_LOCK.lock().unwrap();
    reset_network_state();
    reset_fs_state();
    set_fs_rules(&[fs_rule_entry(0, "/var/data/", FS_READ)]);
    let file_path = c_string("/var/data-archive");
    let mut file = TestFile {
        path: file_path.as_ptr(),
        mode: FMODE_READ,
    };
    let file_ptr = (&mut file) as *mut _ as *mut c_void;
    assert_ne!(file_permission(file_ptr, MAY_READ), 0);
}

#[test]
fn inode_rename_denies_when_source_not_allowed() {
    let _g = TEST_LOCK.lock().unwrap();
    reset_network_state();
    reset_fs_state();
    reset_events();
    let old_path = "/etc/warden/src.txt";
    let new_path = "/etc/warden/dst.txt";
    set_fs_rules(&[fs_rule_entry(0, new_path, FS_WRITE)]);
    let old_bytes = c_string(old_path);
    let new_bytes = c_string(new_path);
    let mut old_dentry = TestDentry {
        name: old_bytes.as_ptr(),
    };
    let mut new_dentry = TestDentry {
        name: new_bytes.as_ptr(),
    };
    let result = inode_rename(
        ptr::null_mut(),
        (&mut old_dentry) as *mut _ as *mut c_void,
        ptr::null_mut(),
        (&mut new_dentry) as *mut _ as *mut c_void,
        0,
    );
    assert_ne!(result, 0);
    let event = last_event().expect("event");
    assert_eq!(event.action, ACTION_RENAME);
    assert_eq!(event.verdict, 1);
    assert_eq!(bytes_to_string(&event.path_or_addr), old_path);
    assert_eq!(bytes_to_string(&event.needed_perm), "allow.fs.write_extra");
}

#[test]
fn inode_rename_denies_when_target_not_allowed() {
    let _g = TEST_LOCK.lock().unwrap();
    reset_network_state();
    reset_fs_state();
    reset_events();
    let old_path = "/etc/warden/allowed.txt";
    let new_path = "/etc/warden/blocked.txt";
    set_fs_rules(&[fs_rule_entry(0, old_path, FS_WRITE)]);
    let old_bytes = c_string(old_path);
    let new_bytes = c_string(new_path);
    let mut old_dentry = TestDentry {
        name: old_bytes.as_ptr(),
    };
    let mut new_dentry = TestDentry {
        name: new_bytes.as_ptr(),
    };
    let result = inode_rename(
        ptr::null_mut(),
        (&mut old_dentry) as *mut _ as *mut c_void,
        ptr::null_mut(),
        (&mut new_dentry) as *mut _ as *mut c_void,
        0,
    );
    assert_ne!(result, 0);
    let event = last_event().expect("event");
    assert_eq!(event.action, ACTION_RENAME);
    assert_eq!(event.verdict, 1);
    assert_eq!(bytes_to_string(&event.path_or_addr), new_path);
    assert_eq!(bytes_to_string(&event.needed_perm), "allow.fs.write_extra");
    let count = event_count();
    assert_eq!(count, 1);
}

#[test]
fn inode_rename_allows_when_rules_cover_both_paths() {
    let _g = TEST_LOCK.lock().unwrap();
    reset_network_state();
    reset_fs_state();
    reset_events();
    let old_path = "/workspace/dir/source.txt";
    let new_path = "/workspace/dir/dest.txt";
    set_fs_rules(&[fs_rule_entry(0, "/workspace/dir", FS_WRITE)]);
    let old_bytes = c_string(old_path);
    let new_bytes = c_string(new_path);
    let mut old_dentry = TestDentry {
        name: old_bytes.as_ptr(),
    };
    let mut new_dentry = TestDentry {
        name: new_bytes.as_ptr(),
    };
    let result = inode_rename(
        ptr::null_mut(),
        (&mut old_dentry) as *mut _ as *mut c_void,
        ptr::null_mut(),
        (&mut new_dentry) as *mut _ as *mut c_void,
        0,
    );
    assert_eq!(result, 0);
    assert!(last_event().is_none());
    let count = event_count();
    assert_eq!(count, 0);
}

#[test]
fn inode_rename_observe_mode_allows_but_logs() {
    let _g = TEST_LOCK.lock().unwrap();
    reset_network_state();
    reset_fs_state();
    enable_observe_mode();
    assert!(is_observe_mode(), "observe mode should be enabled");
    reset_events();
    let old_path = "/etc/warden/src.txt";
    let new_path = "/etc/warden/dst.txt";
    let old_bytes = c_string(old_path);
    let new_bytes = c_string(new_path);
    let mut old_dentry = TestDentry {
        name: old_bytes.as_ptr(),
    };
    let mut new_dentry = TestDentry {
        name: new_bytes.as_ptr(),
    };
    let result = inode_rename(
        ptr::null_mut(),
        (&mut old_dentry) as *mut _ as *mut c_void,
        ptr::null_mut(),
        (&mut new_dentry) as *mut _ as *mut c_void,
        0,
    );
    assert_eq!(result, 0);
    let event = last_event().expect("event");
    assert_eq!(event.action, ACTION_RENAME);
    assert_eq!(event.verdict, 1);
    assert_eq!(bytes_to_string(&event.path_or_addr), new_path);
    let count = event_count();
    assert_eq!(count, 2);
}

#[test]
fn inode_rename_denies_when_both_paths_not_allowed() {
    let _g = TEST_LOCK.lock().unwrap();
    reset_network_state();
    reset_fs_state();
    reset_events();
    let old_path = "/etc/warden/src.txt";
    let new_path = "/etc/warden/dst.txt";
    let old_bytes = c_string(old_path);
    let new_bytes = c_string(new_path);
    let mut old_dentry = TestDentry {
        name: old_bytes.as_ptr(),
    };
    let mut new_dentry = TestDentry {
        name: new_bytes.as_ptr(),
    };
    let result = inode_rename(
        ptr::null_mut(),
        (&mut old_dentry) as *mut _ as *mut c_void,
        ptr::null_mut(),
        (&mut new_dentry) as *mut _ as *mut c_void,
        0,
    );
    assert_ne!(result, 0);
    let event = last_event().expect("event");
    assert_eq!(event.action, ACTION_RENAME);
    assert_eq!(event.verdict, 1);
    assert_eq!(bytes_to_string(&event.path_or_addr), new_path);
    let count = event_count();
    assert_eq!(count, 2);
}

#[test]
fn inode_rename_requires_non_null_paths() {
    let _g = TEST_LOCK.lock().unwrap();
    reset_network_state();
    reset_fs_state();
    reset_events();
    let mut old_dentry = TestDentry { name: ptr::null() };
    let mut new_dentry = TestDentry { name: ptr::null() };
    let result = inode_rename(
        ptr::null_mut(),
        (&mut old_dentry) as *mut _ as *mut c_void,
        ptr::null_mut(),
        (&mut new_dentry) as *mut _ as *mut c_void,
        0,
    );
    assert_ne!(result, 0);
    assert!(last_event().is_none());
    let count = event_count();
    assert_eq!(count, 0);
}

#[test]
fn inode_unlink_requires_write_permission() {
    let _g = TEST_LOCK.lock().unwrap();
    reset_network_state();
    reset_fs_state();
    let path = "/etc/warden/temp.txt";
    let path_bytes = c_string(path);
    let mut dentry = TestDentry {
        name: path_bytes.as_ptr(),
    };
    reset_events();
    assert_ne!(
        inode_unlink(ptr::null_mut(), (&mut dentry) as *mut _ as *mut c_void),
        0
    );
    let event = last_event().expect("event");
    assert_eq!(event.action, ACTION_UNLINK);
    assert_eq!(event.verdict, 1);
    assert_eq!(bytes_to_string(&event.path_or_addr), path);
    assert_eq!(bytes_to_string(&event.needed_perm), "allow.fs.write_extra");

    set_fs_rules(&[fs_rule_entry(0, path, FS_READ | FS_WRITE)]);
    reset_events();
    assert_eq!(
        inode_unlink(ptr::null_mut(), (&mut dentry) as *mut _ as *mut c_void),
        0
    );
    assert!(last_event().is_none());

    set_fs_rules(&[fs_rule_entry(0, path, FS_READ)]);
    reset_events();
    assert_ne!(
        inode_unlink(ptr::null_mut(), (&mut dentry) as *mut _ as *mut c_void),
        0
    );
    let event = last_event().expect("event");
    assert_eq!(event.action, ACTION_UNLINK);
    assert_eq!(event.verdict, 1);
    assert_eq!(bytes_to_string(&event.path_or_addr), path);
    assert_eq!(bytes_to_string(&event.needed_perm), "allow.fs.write_extra");
}

#[test]
fn inode_unlink_observe_mode_allows_but_logs() {
    let _g = TEST_LOCK.lock().unwrap();
    reset_network_state();
    reset_fs_state();
    enable_observe_mode();
    assert!(is_observe_mode(), "observe mode should be enabled");
    let path = "/etc/warden/temp.txt";
    let path_bytes = c_string(path);
    let mut dentry = TestDentry {
        name: path_bytes.as_ptr(),
    };
    reset_events();
    let result = inode_unlink(ptr::null_mut(), (&mut dentry) as *mut _ as *mut c_void);
    assert_eq!(result, 0);
    let event = last_event().expect("event");
    assert_eq!(event.action, ACTION_UNLINK);
    assert_eq!(event.verdict, 1);
    assert_eq!(bytes_to_string(&event.path_or_addr), path);
    assert_eq!(bytes_to_string(&event.needed_perm), "allow.fs.write_extra");
}

#[test]
fn inode_unlink_requires_valid_path_pointer() {
    let _g = TEST_LOCK.lock().unwrap();
    reset_network_state();
    reset_fs_state();
    reset_events();
    let mut dentry = TestDentry { name: ptr::null() };
    let result = inode_unlink(ptr::null_mut(), (&mut dentry) as *mut _ as *mut c_void);
    assert_ne!(result, 0);
    assert!(last_event().is_none());
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
    assign_unit(2);
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
    assign_unit(7);
    assert_eq!(
        file_open((&mut file) as *mut _ as *mut c_void, ptr::null_mut()),
        0
    );
}

#[test]
fn file_events_include_workload_unit() {
    let _g = TEST_LOCK.lock().unwrap();
    reset_network_state();
    reset_fs_state();
    set_fs_rules(&[fs_rule_entry(0, "/workspace/data", FS_READ)]);
    let path = "/workspace/data/file.txt";
    let path_bytes = c_string(path);
    let mut file = TestFile {
        path: path_bytes.as_ptr(),
        mode: FMODE_READ,
    };
    assign_unit(5);
    reset_events();
    assert_eq!(
        file_open((&mut file) as *mut _ as *mut c_void, ptr::null_mut()),
        0
    );
    let event = last_event().expect("event");
    assert_eq!(event.unit, 5);
}

#[test]
fn classify_workload_units_from_paths() {
    let rustc = super::classify_workload_unit(b"/usr/bin/rustc", &[]);
    assert_eq!(rustc, bpf_api::UNIT_RUSTC);

    let proc_macro_args = [&b"--crate-type=proc-macro"[..]];
    let proc_macro = super::classify_workload_unit(b"/usr/bin/rustc", &proc_macro_args);
    assert_eq!(proc_macro, bpf_api::UNIT_PROC_MACRO);

    let build_script = super::classify_workload_unit(
        b"/workspace/target/debug/build/foo-12345/build-script-build",
        &[],
    );
    assert_eq!(build_script, bpf_api::UNIT_BUILD_SCRIPT);

    let linker = super::classify_workload_unit(b"/usr/bin/ld", &[]);
    assert_eq!(linker, bpf_api::UNIT_LINKER);

    let cargo = super::classify_workload_unit(b"/usr/bin/cargo", &[]);
    assert_eq!(cargo, bpf_api::UNIT_OTHER);
}

fn rule_entry(unit: u32, addr: std::net::IpAddr, port: u16, proto: u8) -> bpf_api::NetRuleEntry {
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
    host_maps::clear_by_name("NET_RULES");
    host_maps::clear_by_name("NET_RULES_LENGTH");
    for (idx, entry) in entries.iter().enumerate() {
        NET_RULES.set(idx as u32, *entry);
    }
    NET_RULES_LENGTH.set(0, entries.len() as u32);
}

fn set_net_parents(entries: &[bpf_api::NetParentEntry]) {
    host_maps::clear_by_name("NET_PARENTS");
    host_maps::clear_by_name("NET_PARENTS_LENGTH");
    for (idx, entry) in entries.iter().enumerate() {
        NET_PARENTS.set(idx as u32, *entry);
    }
    NET_PARENTS_LENGTH.set(0, entries.len() as u32);
}

fn reset_mode_flags() {
    host_maps::clear_by_name("MODE_FLAGS");
    MODE_FLAGS.set(0, bpf_api::MODE_FLAG_ENFORCE);
}

fn reset_network_state() {
    host_maps::clear_by_name("NET_RULES");
    host_maps::clear_by_name("NET_RULES_LENGTH");
    host_maps::clear_by_name("NET_PARENTS");
    host_maps::clear_by_name("NET_PARENTS_LENGTH");
    reset_mode_flags();
    clear_workload_units();
    refresh_current_unit();
}

fn set_fs_rules(entries: &[bpf_api::FsRuleEntry]) {
    host_maps::clear_by_name("FS_RULES");
    host_maps::clear_by_name("FS_RULES_LENGTH");
    for (idx, entry) in entries.iter().enumerate() {
        FS_RULES.set(idx as u32, *entry);
    }
    FS_RULES_LENGTH.set(0, entries.len() as u32);
}

fn reset_fs_state() {
    host_maps::clear_by_name("FS_RULES");
    host_maps::clear_by_name("FS_RULES_LENGTH");
    reset_mode_flags();
    clear_workload_units();
    refresh_current_unit();
}

fn enable_observe_mode() {
    reset_mode_flags();
    MODE_FLAGS.set(0, bpf_api::MODE_FLAG_OBSERVE);
}

fn reset_exec_state() {
    host_maps::clear_by_name("EXEC_ALLOWLIST");
    host_maps::clear_by_name("EXEC_ALLOWLIST_LENGTH");
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

fn bytes_to_string(bytes: &[u8]) -> String {
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
        user_port: u32::from(80u16.to_be()),
        family: 2,
        protocol: 6,
    };
    let other = SockAddr {
        user_ip4: match denied_ip {
            std::net::IpAddr::V4(v4) => u32::from_be_bytes(v4.octets()),
            _ => 0,
        },
        user_ip6: [0; 4],
        user_port: u32::from(80u16.to_be()),
        family: 2,
        protocol: 6,
    };
    assign_unit(1);
    assert_eq!(connect4(&allowed as *const _ as *mut c_void), 0);
    assert_ne!(connect4(&other as *const _ as *mut c_void), 0);
    assert_eq!(sendmsg4(&allowed as *const _ as *mut c_void), 0);
    assert_ne!(sendmsg4(&other as *const _ as *mut c_void), 0);
    assign_unit(2);
    assert_eq!(connect4(&allowed as *const _ as *mut c_void), 0);
    assert_eq!(sendmsg4(&allowed as *const _ as *mut c_void), 0);
    assert_ne!(connect4(&other as *const _ as *mut c_void), 0);
    assign_unit(3);
    assert_ne!(connect4(&allowed as *const _ as *mut c_void), 0);
    assert_ne!(sendmsg4(&allowed as *const _ as *mut c_void), 0);
}

#[test]
fn connect4_observe_mode_allows_denied_requests() {
    let _g = TEST_LOCK.lock().unwrap();
    reset_network_state();
    enable_observe_mode();
    assert!(is_observe_mode(), "observe mode should be enabled");
    let denied = SockAddr {
        user_ip4: u32::from_be_bytes([203, 0, 113, 2]),
        user_ip6: [0; 4],
        user_port: u32::from(8080u16.to_be()),
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
    let fallback = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let ip = resolve_host("localhost")
        .ok()
        .and_then(|ips| ips.into_iter().find(|addr| addr.is_ipv6()))
        .unwrap_or(std::net::IpAddr::V6(fallback));
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
        user_port: u32::from(80u16.to_be()),
        family: 10,
        protocol: 6,
    };
    let other = SockAddr {
        user_ip4: 0,
        user_ip6: ipv6_words(denied),
        user_port: u32::from(80u16.to_be()),
        family: 10,
        protocol: 6,
    };
    assign_unit(1);
    assert_eq!(connect6(&allowed as *const _ as *mut c_void), 0);
    assert_ne!(connect6(&other as *const _ as *mut c_void), 0);
    assert_eq!(sendmsg6(&allowed as *const _ as *mut c_void), 0);
    assert_ne!(sendmsg6(&other as *const _ as *mut c_void), 0);
    assign_unit(2);
    assert_eq!(connect6(&allowed as *const _ as *mut c_void), 0);
    assert_eq!(sendmsg6(&allowed as *const _ as *mut c_void), 0);
    assert_ne!(connect6(&other as *const _ as *mut c_void), 0);
    assign_unit(3);
    assert_ne!(connect6(&allowed as *const _ as *mut c_void), 0);
    assert_ne!(sendmsg6(&allowed as *const _ as *mut c_void), 0);
}

#[test]
fn connect6_observe_mode_allows_denied_requests() {
    let _g = TEST_LOCK.lock().unwrap();
    reset_network_state();
    enable_observe_mode();
    assert!(is_observe_mode(), "observe mode should be enabled");
    let denied_addr = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
    let denied = SockAddr {
        user_ip4: 0,
        user_ip6: ipv6_words(denied_addr),
        user_port: u32::from(8080u16.to_be()),
        family: 10,
        protocol: 6,
    };
    assert_eq!(connect6(&denied as *const _ as *mut c_void), 0);
    assert_eq!(sendmsg6(&denied as *const _ as *mut c_void), 0);
}
