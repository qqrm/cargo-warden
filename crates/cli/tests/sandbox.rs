use assert_cmd::Command;
use bpf_api::{FS_READ, FS_WRITE};
use serde::Deserialize;
use std::fs;
use tempfile::tempdir;

#[derive(Debug, Deserialize)]
struct RecordedLayout {
    exec_allowlist: Vec<String>,
    net_rules: Vec<RecordedNetRule>,
    fs_rules: Vec<RecordedFsRule>,
}

#[derive(Debug, Deserialize)]
struct RecordedNetRule {
    addr: String,
    prefix_len: u8,
    port: u16,
    protocol: u8,
}

#[derive(Debug, Deserialize)]
struct RecordedFsRule {
    path: String,
    access: u8,
}

#[test]
fn run_fake_sandbox_records_events_and_layout() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let events_path = dir.path().join("warden-events.jsonl");
    let cgroup_path = dir.path().join("fake-cgroup");
    let layout_path = dir.path().join("layout-log.jsonl");
    let policy_path = dir.path().join("policy.toml");
    let allow_path = dir.path().join("bin").join("allowed-exec");
    let fs_write_path = dir.path().join("state").join("write.log");
    let fs_read_path = dir.path().join("state").join("read.log");

    let allow_path_str = allow_path.display().to_string();
    let fs_write_str = fs_write_path.display().to_string();
    let fs_read_str = fs_read_path.display().to_string();

    let policy_contents = format!(
        r#"
mode = "enforce"
fs.default = "strict"
net.default = "deny"
exec.default = "allowlist"

[allow.net]
hosts = ["127.0.0.1:9000"]

[allow.fs]
write_extra = ["{write}"]
read_extra = ["{read}"]
"#,
        write = fs_write_str,
        read = fs_read_str,
    );
    fs::write(&policy_path, policy_contents)?;

    let mut cmd = Command::cargo_bin("cargo-warden")?;
    cmd.arg("run")
        .arg("--allow")
        .arg(&allow_path_str)
        .arg("--policy")
        .arg(&policy_path)
        .arg("--")
        .arg("true")
        .env("QQRM_WARDEN_FAKE_SANDBOX", "1")
        .env("QQRM_WARDEN_EVENTS_PATH", &events_path)
        .env("QQRM_WARDEN_FAKE_CGROUP_DIR", &cgroup_path)
        .env("QQRM_WARDEN_FAKE_LAYOUT_PATH", &layout_path);
    cmd.assert().success();

    let contents = fs::read_to_string(&events_path)?;
    assert!(
        contents.lines().any(|line| line.contains("\"fake\":true")),
        "expected fake event in {}: {contents}",
        events_path.display()
    );
    assert!(
        !cgroup_path.exists(),
        "expected fake cgroup removal: {}",
        cgroup_path.display()
    );

    let layout_raw = fs::read_to_string(&layout_path)?;
    let layouts: Vec<RecordedLayout> = layout_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    assert_eq!(
        layouts.len(),
        1,
        "expected a single layout record, found {}",
        layouts.len()
    );
    let layout = &layouts[0];

    assert!(
        layout
            .exec_allowlist
            .iter()
            .any(|entry| entry == &allow_path_str),
        "missing exec allowlist entry for {allow_path_str}: {:?}",
        layout.exec_allowlist
    );

    assert!(
        layout.net_rules.iter().any(|rule| {
            rule.addr == "127.0.0.1"
                && rule.port == 9000
                && rule.prefix_len == 32
                && rule.protocol == 6
        }),
        "missing expected network rule: {:?}",
        layout.net_rules
    );

    assert!(
        layout
            .fs_rules
            .iter()
            .any(|rule| { rule.path == fs_write_str && rule.access == (FS_READ | FS_WRITE) }),
        "missing filesystem write rule: {:?}",
        layout.fs_rules
    );
    assert!(
        layout
            .fs_rules
            .iter()
            .any(|rule| rule.path == fs_read_str && rule.access == FS_READ),
        "missing filesystem read rule: {:?}",
        layout.fs_rules
    );
    Ok(())
}
