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
    port: u16,
}

#[derive(Debug, Deserialize)]
struct RecordedFsRule {
    access: u8,
    path: String,
}

#[test]
fn run_fake_sandbox_records_events() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let events_path = dir.path().join("warden-events.jsonl");
    let cgroup_path = dir.path().join("fake-cgroup");
    let layout_path = dir.path().join("maps-layout.jsonl");
    let policy_path = dir.path().join("policy.toml");

    fs::write(
        &policy_path,
        r#"
mode = "enforce"

[fs]
default = "strict"

[net]
default = "deny"

[exec]
default = "allowlist"

[allow.net]
hosts = ["127.0.0.1:8080"]

[allow.fs]
read_extra = ["/etc/hosts"]
write_extra = ["/tmp/logs"]
"#,
    )?;

    let mut cmd = Command::cargo_bin("cargo-warden")?;
    cmd.current_dir(dir.path())
        .arg("--allow")
        .arg("/usr/bin/true")
        .arg("--policy")
        .arg(policy_path.as_os_str())
        .arg("run")
        .arg("--")
        .arg("/usr/bin/true")
        .env("QQRM_WARDEN_FAKE_SANDBOX", "1")
        .env("QQRM_WARDEN_EVENTS_PATH", events_path.as_os_str())
        .env("QQRM_WARDEN_FAKE_CGROUP_DIR", cgroup_path.as_os_str())
        .env("QQRM_WARDEN_FAKE_LAYOUT_PATH", layout_path.as_os_str());
    cmd.assert().success();

    let contents = fs::read_to_string(&events_path)?;
    assert!(
        contents.lines().any(|line| line.contains("\"fake\":true")),
        "expected fake event in {}: {contents}",
        events_path.display()
    );

    let layout_contents = fs::read_to_string(&layout_path)?;
    let mut layouts = Vec::new();
    for line in layout_contents.lines() {
        if line.trim().is_empty() {
            continue;
        }
        layouts.push(serde_json::from_str::<RecordedLayout>(line)?);
    }
    let recorded = layouts.last().expect("expected recorded layout entry");
    assert!(
        recorded
            .exec_allowlist
            .iter()
            .any(|path| path == "/usr/bin/true"),
        "expected exec allowlist to include /usr/bin/true: {recorded:?}"
    );
    assert!(
        recorded
            .net_rules
            .iter()
            .any(|rule| rule.addr == "127.0.0.1" && rule.port == 8080),
        "expected network rule for 127.0.0.1:8080: {recorded:?}"
    );
    assert!(
        recorded
            .fs_rules
            .iter()
            .any(|rule| rule.path == "/etc/hosts" && rule.access == FS_READ),
        "expected filesystem read rule for /etc/hosts: {recorded:?}"
    );
    assert!(
        recorded
            .fs_rules
            .iter()
            .any(|rule| { rule.path == "/tmp/logs" && rule.access == (FS_READ | FS_WRITE) }),
        "expected filesystem write rule for /tmp/logs: {recorded:?}"
    );
    assert!(
        !cgroup_path.exists(),
        "expected fake cgroup removal: {}",
        cgroup_path.display()
    );
    Ok(())
}
