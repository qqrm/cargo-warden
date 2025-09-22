use assert_cmd::Command;
use bpf_api::{MODE_FLAG_ENFORCE, MODE_FLAG_OBSERVE};
use event_reporting::EventRecord;
use sandbox_runtime::LayoutSnapshot;
use serde_json::json;
use std::fs;
use std::io;
use std::path::Path;
use std::time::Duration;
use tempfile::tempdir;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

fn read_snapshots(path: &Path) -> Result<Vec<LayoutSnapshot>, Box<dyn std::error::Error>> {
    let layout_contents = fs::read_to_string(path)?;
    let snapshots = layout_contents
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<Vec<LayoutSnapshot>, _>>()?;
    Ok(snapshots)
}

fn wait_for_fake_agent(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let mut attempts = 0;
    loop {
        match fs::read_to_string(path) {
            Ok(contents) => {
                if contents.lines().any(|line| line.contains("\"fake\":true")) {
                    return Ok(contents);
                }
                if attempts > 50 {
                    return Err(format!(
                        "fake agent did not record final entry in {}: {}",
                        path.display(),
                        contents
                    )
                    .into());
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                if attempts > 50 {
                    return Err(format!(
                        "fake agent never created events file at {}",
                        path.display()
                    )
                    .into());
                }
            }
            Err(err) => return Err(err.into()),
        }
        attempts += 1;
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn read_event_records(path: &Path) -> Result<Vec<EventRecord>, Box<dyn std::error::Error>> {
    let contents = wait_for_fake_agent(path)?;
    let mut events = Vec::new();
    for line in contents.lines() {
        if let Ok(event) = serde_json::from_str::<EventRecord>(line) {
            events.push(event);
        }
    }
    Ok(events)
}

const DENIED_ENDPOINT: &str = "198.51.100.10:443";
const DENIED_PID: u32 = 7777;
const DENIED_ACTION: u8 = 4;

fn run_in_fake_sandbox(
    mut cmd: Command,
    events_path: &Path,
) -> Result<(std::process::ExitStatus, Vec<EventRecord>), Box<dyn std::error::Error>> {
    let output = cmd.output()?;
    let status = output.status;
    let events = read_event_records(events_path)?;
    Ok((status, events))
}

#[cfg(unix)]
fn make_executable(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

fn write_denied_action_script(
    dir: &Path,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let script_path = dir.join("denied-action.sh");
    let deny_event = json!({
        "pid": DENIED_PID,
        "unit": 0,
        "action": DENIED_ACTION,
        "verdict": 1,
        "container_id": 0,
        "caps": 0,
        "path_or_addr": DENIED_ENDPOINT,
    })
    .to_string();
    fs::write(
        &script_path,
        format!(
            r#"#!/bin/sh
set -eu

EVENTS="$1"
MODE="$2"

printf '%s\n' '{event}' >> "$EVENTS"

if [ "$MODE" = "enforce" ]; then
    exit 42
fi

exit 0
"#,
            event = deny_event
        ),
    )?;
    make_executable(&script_path)?;
    Ok(script_path)
}

fn write_policy_for_mode(
    dir: &Path,
    script_path: &Path,
    mode: &str,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let script_str = script_path.as_os_str();
    let script_utf8 = script_str.to_str().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "script path is not valid UTF-8")
    })?;
    let script_entry = serde_json::to_string(script_utf8)?;
    let policy_path = dir.join(format!("{mode}-policy.toml"));
    fs::write(
        &policy_path,
        format!(
            r#"mode = "{mode}"

[fs]
default = "strict"

[net]
default = "deny"

[exec]
default = "allowlist"

[allow.exec]
allowed = [{script_entry}]
"#,
            mode = mode,
            script_entry = script_entry,
        ),
    )?;
    Ok(policy_path)
}

#[test]
fn fake_sandbox_enforce_denial_fails_child() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let events_path = dir.path().join("enforce-events.jsonl");
    let layout_path = dir.path().join("enforce-layout.jsonl");
    let cgroup_path = dir.path().join("enforce-cgroup");
    let script_path = write_denied_action_script(dir.path())?;
    let policy_path = write_policy_for_mode(dir.path(), &script_path, "enforce")?;

    fs::File::create(&events_path)?;

    let mut cmd = Command::cargo_bin("cargo-warden")?;
    cmd.arg("run")
        .arg("--policy")
        .arg(&policy_path)
        .arg("--")
        .arg(&script_path)
        .arg(&events_path)
        .arg("enforce")
        .current_dir(dir.path())
        .env("QQRM_WARDEN_FAKE_SANDBOX", "1")
        .env("QQRM_WARDEN_EVENTS_PATH", &events_path)
        .env("QQRM_WARDEN_FAKE_CGROUP_DIR", &cgroup_path)
        .env("QQRM_WARDEN_FAKE_LAYOUT_PATH", &layout_path);

    let (status, events) = run_in_fake_sandbox(cmd, &events_path)?;

    assert!(
        !status.success(),
        "expected failure exit status when sandbox denies action"
    );
    assert_eq!(status.code(), Some(42));

    assert_eq!(
        events.len(),
        1,
        "expected single denial event: {:?}",
        events
    );
    let event = &events[0];
    assert_eq!(event.pid, DENIED_PID);
    assert_eq!(event.action, DENIED_ACTION);
    assert_eq!(event.verdict, 1);
    assert_eq!(event.path_or_addr, DENIED_ENDPOINT);

    let snapshots = read_snapshots(&layout_path)?;
    let snapshot = snapshots.last().expect("layout snapshot present");
    assert_eq!(snapshot.mode, "enforce");
    assert_eq!(snapshot.mode_flag, Some(MODE_FLAG_ENFORCE));

    assert!(
        !cgroup_path.exists(),
        "fake sandbox should clean up cgroup directory"
    );

    Ok(())
}

#[test]
fn fake_sandbox_observe_denial_allows_child() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let events_path = dir.path().join("observe-events.jsonl");
    let layout_path = dir.path().join("observe-layout.jsonl");
    let cgroup_path = dir.path().join("observe-cgroup");
    let script_path = write_denied_action_script(dir.path())?;
    let policy_path = write_policy_for_mode(dir.path(), &script_path, "observe")?;

    fs::File::create(&events_path)?;

    let mut cmd = Command::cargo_bin("cargo-warden")?;
    cmd.arg("run")
        .arg("--policy")
        .arg(&policy_path)
        .arg("--")
        .arg(&script_path)
        .arg(&events_path)
        .arg("observe")
        .current_dir(dir.path())
        .env("QQRM_WARDEN_FAKE_SANDBOX", "1")
        .env("QQRM_WARDEN_EVENTS_PATH", &events_path)
        .env("QQRM_WARDEN_FAKE_CGROUP_DIR", &cgroup_path)
        .env("QQRM_WARDEN_FAKE_LAYOUT_PATH", &layout_path);

    let (status, events) = run_in_fake_sandbox(cmd, &events_path)?;

    assert!(
        status.success(),
        "observe mode should allow denied action, got status: {:?}",
        status
    );
    assert_eq!(status.code(), Some(0));

    assert_eq!(
        events.len(),
        1,
        "expected single denial event: {:?}",
        events
    );
    let event = &events[0];
    assert_eq!(event.pid, DENIED_PID);
    assert_eq!(event.action, DENIED_ACTION);
    assert_eq!(event.verdict, 1);
    assert_eq!(event.path_or_addr, DENIED_ENDPOINT);

    let snapshots = read_snapshots(&layout_path)?;
    let snapshot = snapshots.last().expect("layout snapshot present");
    assert_eq!(snapshot.mode, "observe");
    assert_eq!(snapshot.mode_flag, Some(MODE_FLAG_OBSERVE));

    assert!(
        !cgroup_path.exists(),
        "fake sandbox should clean up cgroup directory"
    );

    Ok(())
}

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

    let snapshots = read_snapshots(&layout_path)?;
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
fn workspace_policy_overrides_modify_layout() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let workspace_root = dir.path();
    let events_a = workspace_root.join("alpha-events.jsonl");
    let layout_a = workspace_root.join("alpha-layout.jsonl");
    let cgroup_a = workspace_root.join("alpha-cgroup");
    let events_b = workspace_root.join("beta-events.jsonl");
    let layout_b = workspace_root.join("beta-layout.jsonl");
    let cgroup_b = workspace_root.join("beta-cgroup");

    fs::create_dir_all(workspace_root.join("members/alpha/src"))?;
    fs::create_dir_all(workspace_root.join("members/beta/src"))?;

    fs::write(
        workspace_root.join("Cargo.toml"),
        r#"[workspace]
members = ["members/alpha", "members/beta"]
"#,
    )?;

    fs::write(
        workspace_root.join("members/alpha/Cargo.toml"),
        r#"[package]
name = "alpha"
version = "0.1.0"
edition = "2024"
"#,
    )?;
    fs::write(
        workspace_root.join("members/alpha/src/lib.rs"),
        "pub fn alpha() {}\n",
    )?;

    fs::write(
        workspace_root.join("members/beta/Cargo.toml"),
        r#"[package]
name = "beta"
version = "0.1.0"
edition = "2024"
"#,
    )?;
    fs::write(
        workspace_root.join("members/beta/src/lib.rs"),
        "pub fn beta() {}\n",
    )?;

    fs::write(
        workspace_root.join("workspace.warden.toml"),
        r#"[root]
mode = "enforce"

[root.exec]
default = "allowlist"

[root.net]
default = "deny"

[root.allow.exec]
allowed = []

[root.allow.net]
hosts = []

[root.allow.fs]
write_extra = []
read_extra = []

[members.alpha.allow.exec]
allowed = ["/usr/bin/member-a"]

[members.beta.exec]
default = "allow"

[members.beta.allow.exec]
allowed = []

[members.beta.allow.net]
hosts = ["10.0.0.1:1234"]
"#,
    )?;

    let alpha_dir = workspace_root.join("members/alpha");
    let mut cmd = Command::cargo_bin("cargo-warden")?;
    cmd.arg("run")
        .arg("--")
        .arg("true")
        .current_dir(&alpha_dir)
        .env("QQRM_WARDEN_FAKE_SANDBOX", "1")
        .env("QQRM_WARDEN_EVENTS_PATH", &events_a)
        .env("QQRM_WARDEN_FAKE_CGROUP_DIR", &cgroup_a)
        .env("QQRM_WARDEN_FAKE_LAYOUT_PATH", &layout_a);
    cmd.assert().success();

    let alpha_snapshots = read_snapshots(&layout_a)?;
    let alpha_snapshot = alpha_snapshots.last().expect("alpha snapshot present");
    assert!(
        alpha_snapshot
            .exec
            .iter()
            .any(|path| path == "/usr/bin/member-a"),
        "expected per-member exec allowance for alpha: {:?}",
        alpha_snapshot.exec
    );
    assert!(
        alpha_snapshot
            .net
            .iter()
            .all(|rule| !(rule.addr == "10.0.0.1" && rule.port == 1234)),
        "alpha overrides should not include beta network host: {:?}",
        alpha_snapshot.net
    );

    let mut cmd = Command::cargo_bin("cargo-warden")?;
    cmd.arg("run")
        .arg("--")
        .arg("true")
        .current_dir(workspace_root)
        .env("CARGO_PRIMARY_PACKAGE", "beta")
        .env("QQRM_WARDEN_FAKE_SANDBOX", "1")
        .env("QQRM_WARDEN_EVENTS_PATH", &events_b)
        .env("QQRM_WARDEN_FAKE_CGROUP_DIR", &cgroup_b)
        .env("QQRM_WARDEN_FAKE_LAYOUT_PATH", &layout_b);
    cmd.assert().success();

    let beta_snapshots = read_snapshots(&layout_b)?;
    let beta_snapshot = beta_snapshots.last().expect("beta snapshot present");
    assert!(
        !beta_snapshot
            .exec
            .iter()
            .any(|path| path == "/usr/bin/member-a"),
        "beta overrides should not inherit alpha exec allowlist: {:?}",
        beta_snapshot.exec
    );
    assert!(
        beta_snapshot
            .net
            .iter()
            .any(|rule| rule.addr == "10.0.0.1" && rule.port == 1234),
        "beta overrides should include network host 10.0.0.1:1234: {:?}",
        beta_snapshot.net
    );

    assert!(
        !cgroup_a.exists() && !cgroup_b.exists(),
        "fake sandbox should remove cgroup directories"
    );

    Ok(())
}
