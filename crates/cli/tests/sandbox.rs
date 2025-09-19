use assert_cmd::Command;
use bpf_api::MODE_FLAG_ENFORCE;
use sandbox_runtime::LayoutSnapshot;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

fn read_snapshots(path: &Path) -> Result<Vec<LayoutSnapshot>, Box<dyn std::error::Error>> {
    let layout_contents = fs::read_to_string(path)?;
    let snapshots = layout_contents
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<Vec<LayoutSnapshot>, _>>()?;
    Ok(snapshots)
}

#[test]
fn run_fake_sandbox_filters_environment() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let events_path = dir.path().join("warden-events.jsonl");
    let layout_path = dir.path().join("fake-layout.jsonl");
    let cgroup_path = dir.path().join("fake-cgroup");
    let policy_path = dir.path().join("policy.toml");

    fs::write(
        &policy_path,
        r#"mode = "enforce"

[allow.env]
read = ["ALLOWED_VAR"]
"#,
    )?;

    let mut cmd = Command::cargo_bin("cargo-warden")?;
    let output = cmd
        .arg("run")
        .arg("--policy")
        .arg(&policy_path)
        .arg("--")
        .arg("env")
        .current_dir(dir.path())
        .env("QQRM_WARDEN_FAKE_SANDBOX", "1")
        .env("QQRM_WARDEN_EVENTS_PATH", &events_path)
        .env("QQRM_WARDEN_FAKE_CGROUP_DIR", &cgroup_path)
        .env("QQRM_WARDEN_FAKE_LAYOUT_PATH", &layout_path)
        .env("ALLOWED_VAR", "visible")
        .env("DENIED_VAR", "hidden")
        .output()?;

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("ALLOWED_VAR=visible"));
    assert!(!stdout.contains("DENIED_VAR="));
    assert!(stdout.contains("PATH="));

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
