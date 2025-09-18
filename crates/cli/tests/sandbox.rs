use assert_cmd::Command;
use serde::Deserialize;
use std::fs;
use tempfile::tempdir;

#[derive(Debug, Deserialize)]
struct LayoutSnapshot {
    exec_allowlist: Vec<String>,
    net_rules: Vec<LayoutNetRule>,
    net_parents: Vec<LayoutNetParent>,
    fs_rules: Vec<LayoutFsRule>,
}

#[derive(Debug, Deserialize)]
struct LayoutNetRule {
    addr: String,
    protocol: u8,
    port: u16,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct LayoutNetParent {
    child: u32,
    parent: u32,
}

#[derive(Debug, Deserialize)]
struct LayoutFsRule {
    access: u8,
    path: String,
}

#[test]
fn run_fake_sandbox_records_layout() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let layout_path = dir.path().join("fake-layouts.jsonl");
    let events_path = dir.path().join("warden-events.jsonl");
    let cgroup_path = dir.path().join("fake-cgroup");
    let policy_path = dir.path().join("policy.toml");

    fs::write(
        &policy_path,
        r#"
mode = "enforce"
fs.default = "strict"
net.default = "deny"
exec.default = "allowlist"

[allow.net]
hosts = ["127.0.0.1:8080"]

[allow.fs]
write_extra = ["/tmp/logs"]
read_extra = ["/etc/resolv.conf"]
"#,
    )?;

    let mut cmd = Command::cargo_bin("cargo-warden")?;
    cmd.arg("--allow")
        .arg("/bin/echo")
        .arg("--policy")
        .arg(&policy_path)
        .arg("run")
        .arg("--")
        .arg("true")
        .current_dir(dir.path())
        .env("QQRM_WARDEN_FAKE_SANDBOX", "1")
        .env("QQRM_WARDEN_EVENTS_PATH", &events_path)
        .env("QQRM_WARDEN_FAKE_CGROUP_DIR", &cgroup_path)
        .env("QQRM_WARDEN_FAKE_LAYOUT_PATH", &layout_path);
    cmd.assert().success();

    let layout_log = fs::read_to_string(&layout_path)?;
    let snapshot_line = layout_log
        .lines()
        .last()
        .ok_or_else(|| format!("missing layout snapshot in {}", layout_path.display()))?;
    let snapshot: LayoutSnapshot = serde_json::from_str(snapshot_line)?;

    assert!(
        snapshot
            .exec_allowlist
            .iter()
            .any(|path| path == "/bin/echo"),
        "expected exec allowlist entry for /bin/echo: {:?}",
        snapshot.exec_allowlist
    );
    assert!(
        snapshot
            .net_rules
            .iter()
            .any(|rule| rule.addr == "127.0.0.1" && rule.port == 8080 && rule.protocol == 6),
        "expected net rule for 127.0.0.1:8080, found {:?}",
        snapshot.net_rules
    );
    assert!(
        snapshot.fs_rules.iter().any(|rule| rule.path == "/tmp/logs"
            && rule.access == (bpf_api::FS_READ | bpf_api::FS_WRITE)),
        "expected fs write rule for /tmp/logs, found {:?}",
        snapshot.fs_rules
    );
    assert!(
        snapshot
            .fs_rules
            .iter()
            .any(|rule| rule.path == "/etc/resolv.conf" && rule.access == bpf_api::FS_READ),
        "expected fs read rule for /etc/resolv.conf, found {:?}",
        snapshot.fs_rules
    );
    assert!(
        snapshot.net_parents.is_empty(),
        "expected no net parent entries, found {:?}",
        snapshot.net_parents
    );

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
    dir.close()?;
    Ok(())
}
