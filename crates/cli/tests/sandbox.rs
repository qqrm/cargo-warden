use assert_cmd::Command;
use bpf_api::MODE_FLAG_ENFORCE;
use predicates::prelude::*;
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
fn run_filters_environment_variables() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let events_path = dir.path().join("warden-events.jsonl");
    let cgroup_path = dir.path().join("fake-cgroup");
    let layout_path = dir.path().join("fake-layout.jsonl");
    let policy_path = dir.path().join("policy.toml");

    fs::write(
        &policy_path,
        r#"mode = "enforce"

[fs]
default = "strict"

[net]
default = "deny"

[exec]
default = "allowlist"

[allow.exec]
allowed = ["/usr/bin/env"]

[allow.env]
read = ["ALLOWED_VAR"]
"#,
    )?;

    let mut cmd = Command::cargo_bin("cargo-warden")?;
    cmd.arg("run")
        .arg("--policy")
        .arg(&policy_path)
        .arg("--")
        .arg("/usr/bin/env")
        .current_dir(dir.path())
        .env("QQRM_WARDEN_FAKE_SANDBOX", "1")
        .env("QQRM_WARDEN_EVENTS_PATH", &events_path)
        .env("QQRM_WARDEN_FAKE_CGROUP_DIR", &cgroup_path)
        .env("QQRM_WARDEN_FAKE_LAYOUT_PATH", &layout_path)
        .env("ALLOWED_VAR", "visible")
        .env("SECRET_VAR", "hidden");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("ALLOWED_VAR=visible"))
        .stdout(predicate::str::contains("PATH="))
        .stdout(predicate::str::contains("SECRET_VAR=").not())
        .stdout(predicate::str::contains("QQRM_WARDEN_FAKE_SANDBOX=").not());

    Ok(())
}
