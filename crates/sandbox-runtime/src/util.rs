use std::collections::HashSet;
use std::env;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) const EVENTS_PATH_ENV: &str = "QQRM_WARDEN_EVENTS_PATH";
pub(crate) const FAKE_CGROUP_DIR_ENV: &str = "QQRM_WARDEN_FAKE_CGROUP_DIR";
pub(crate) const FAKE_CGROUP_ROOT_ENV: &str = "QQRM_WARDEN_FAKE_CGROUP_ROOT";
pub(crate) const CGROUP_ROOT_ENV: &str = "QQRM_WARDEN_CGROUP_ROOT";
pub(crate) const ESSENTIAL_ENV_VARS: &[&str] = &["PATH"];

pub(crate) fn events_path() -> PathBuf {
    if let Some(path) = env::var_os(EVENTS_PATH_ENV) {
        PathBuf::from(path)
    } else {
        PathBuf::from("warden-events.jsonl")
    }
}

pub(crate) fn fake_cgroup_dir() -> PathBuf {
    if let Some(path) = env::var_os(FAKE_CGROUP_DIR_ENV) {
        PathBuf::from(path)
    } else {
        let root = env::var_os(FAKE_CGROUP_ROOT_ENV)
            .map(PathBuf::from)
            .unwrap_or_else(env::temp_dir);
        root.join(format!(
            "fake-cargo-warden-{}-{}",
            process::id(),
            unique_suffix()
        ))
    }
}

pub(crate) fn cgroup_root() -> PathBuf {
    env::var_os(CGROUP_ROOT_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/sys/fs/cgroup"))
}

pub(crate) fn unique_suffix() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros())
        .unwrap_or(0)
}

pub(crate) fn filter_environment(allowed: &[String]) -> Vec<(OsString, OsString)> {
    let mut allowed_names: HashSet<String> = allowed.iter().cloned().collect();
    allowed_names.extend(ESSENTIAL_ENV_VARS.iter().map(|name| (*name).to_string()));

    env::vars_os()
        .filter(|(key, _)| {
            key.to_str()
                .map(|name| allowed_names.contains(name))
                .unwrap_or(false)
        })
        .collect()
}
