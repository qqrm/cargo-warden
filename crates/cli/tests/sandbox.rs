use assert_cmd::Command;
use bpf_api::MODE_FLAG_ENFORCE;
use sandbox_runtime::LayoutSnapshot;
use std::fs;
use tempfile::tempdir;

#[test]
fn run_fake_sandbox_records_layout() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let events_path = dir.path().join("warden-events.jsonl");
    let layout_path = dir.path().join("fake-layout.jsonl");
    let cgroup_path = dir.path().join("fake-cgroup");
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
write_extra = ["/tmp/logs"]
read_extra = ["/etc/ssl/certs"]
"#,
    )?;

    let mut cmd = Command::cargo_bin("cargo-warden")?;
    cmd.arg("run")
        .arg("--allow")
        .arg("/bin/echo")
        .arg("--policy")
        .arg(&policy_path)
        .arg("--")
        .arg("true")
        .current_dir(dir.path())
        .env("QQRM_WARDEN_FAKE_SANDBOX", "1")
        .env("QQRM_WARDEN_EVENTS_PATH", &events_path)
        .env("QQRM_WARDEN_FAKE_CGROUP_DIR", &cgroup_path)
        .env("QQRM_WARDEN_FAKE_LAYOUT_PATH", &layout_path);
    cmd.assert().success();

    let layout_contents = fs::read_to_string(&layout_path)?;
    let snapshots: Vec<LayoutSnapshot> = layout_contents
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    assert!(
        !snapshots.is_empty(),
        "expected at least one layout snapshot in {}",
        layout_path.display()
    );
    let snapshot = snapshots.last().unwrap();

    assert_eq!(snapshot.mode, "enforce");
    assert_eq!(snapshot.mode_flag, Some(MODE_FLAG_ENFORCE));
    assert!(
        snapshot.exec.iter().any(|path| path == "/bin/echo"),
        "expected exec allowlist entry for /bin/echo: {:?}",
        snapshot.exec
    );
    assert!(
        snapshot
            .net
            .iter()
            .any(|rule| rule.addr == "127.0.0.1" && rule.port == 8080),
        "expected net rule for 127.0.0.1:8080: {:?}",
        snapshot.net
    );
    assert!(
        snapshot.net_parents.is_empty(),
        "expected no net parents: {:?}",
        snapshot.net_parents
    );
    assert!(
        snapshot
            .fs
            .iter()
            .any(|rule| rule.path == "/tmp/logs" && rule.write),
        "expected write rule for /tmp/logs: {:?}",
        snapshot.fs
    );
    assert!(
        snapshot
            .fs
            .iter()
            .any(|rule| rule.path == "/etc/ssl/certs" && rule.read && !rule.write),
        "expected read-only rule for /etc/ssl/certs: {:?}",
        snapshot.fs
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
    Ok(())
}

#[test]
fn observe_mode_records_denied_event() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let events_path = dir.path().join("warden-events.jsonl");
    let layout_path = dir.path().join("fake-layout.jsonl");
    let cgroup_path = dir.path().join("fake-cgroup");
    let policy_path = dir.path().join("policy.toml");
    let forbidden_path = dir.path().join("classified.txt");

    fs::write(&forbidden_path, "restricted")?;
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

[allow.exec]
allowed = ["/bin/sh", "/bin/cat"]

[allow.fs]
write_extra = []
read_extra = []
"#,
    )?;

    let expected_path = forbidden_path.display().to_string();

    let mut cmd = Command::cargo_bin("cargo-warden")?;
    cmd.arg("run")
        .arg("--mode")
        .arg("observe")
        .arg("--allow")
        .arg("/bin/sh")
        .arg("--allow")
        .arg("/bin/cat")
        .arg("--policy")
        .arg(&policy_path)
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg(format!("cat {}", forbidden_path.display()))
        .current_dir(dir.path())
        .env("QQRM_WARDEN_FAKE_SANDBOX", "1")
        .env("QQRM_WARDEN_EVENTS_PATH", &events_path)
        .env("QQRM_WARDEN_FAKE_CGROUP_DIR", &cgroup_path)
        .env("QQRM_WARDEN_FAKE_LAYOUT_PATH", &layout_path)
        .env("QQRM_WARDEN_FAKE_DENIED_PATH", &forbidden_path);
    cmd.assert().success();

    let layout_contents = fs::read_to_string(&layout_path)?;
    let snapshots: Vec<LayoutSnapshot> = layout_contents
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    assert!(
        !snapshots.is_empty(),
        "expected at least one layout snapshot in {}",
        layout_path.display()
    );
    let snapshot = snapshots.last().unwrap();
    assert_eq!(snapshot.mode, "observe");

    let events_contents = fs::read_to_string(&events_path)?;
    let mut found_denied = false;
    for line in events_contents.lines() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let path = value
            .get("path_or_addr")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if path != expected_path {
            continue;
        }
        let verdict = value.get("verdict").and_then(|v| v.as_u64());
        assert_eq!(verdict, Some(1), "expected deny verdict for {value}");
        let observe_flag = value.get("observe").and_then(|v| v.as_bool());
        assert_eq!(
            observe_flag,
            Some(true),
            "expected observe flag for {value}"
        );
        found_denied = true;
        break;
    }
    assert!(
        found_denied,
        "expected denied event for {} in {}: {events_contents}",
        expected_path,
        events_path.display()
    );

    Ok(())
}
