use assert_cmd::Command;
use bpf_api::{MODE_FLAG_ENFORCE, MODE_FLAG_OBSERVE, UNIT_RUSTC};
use event_reporting::EventRecord;
use policy_core::Mode;
use qqrm_testkits::{LayoutSnapshotExt, TestProject};

const DENIED_ENDPOINT: &str = "198.51.100.10:443";
const DENIED_PID: u32 = 7777;
const DENIED_ACTION: u8 = 4;
const DENIED_UNIT: u8 = UNIT_RUSTC as u8;
const RENAME_PATH: &str = "/var/warden/forbidden";
const RENAME_ACTION: u8 = 1;

fn assert_denial(event: &EventRecord, action: u8, path_or_addr: &str) {
    assert_eq!(event.pid, DENIED_PID);
    assert_eq!(event.action, action);
    assert_eq!(event.unit, DENIED_UNIT);
    assert_eq!(event.verdict, 1);
    assert_eq!(event.path_or_addr, path_or_addr);
}

#[test]
fn fake_sandbox_enforce_denial_fails_child() -> Result<(), Box<dyn std::error::Error>> {
    let project = TestProject::new()?;
    project.init_cargo_package("fixture")?;
    let sandbox = project.fake_sandbox("enforce")?;
    sandbox.touch_event_log()?;

    let script = project.write_violation_script(
        "deny-action",
        DENIED_ACTION,
        DENIED_UNIT,
        DENIED_ENDPOINT,
    )?;
    let policy = project.write_exec_policy("enforce", Mode::Enforce, &[&script])?;

    let mut cmd = Command::cargo_bin("cargo-warden")?;
    cmd.arg("run")
        .arg("--policy")
        .arg(&policy)
        .arg("--")
        .arg(&script)
        .arg(sandbox.events_path())
        .arg("enforce")
        .current_dir(project.path());
    sandbox.apply_assert(&mut cmd);

    cmd.assert().failure().code(42);

    let events = sandbox.read_events()?;
    assert_eq!(
        events.len(),
        1,
        "expected single denial event: {:?}",
        events
    );
    assert_denial(&events[0], DENIED_ACTION, DENIED_ENDPOINT);

    let snapshot = sandbox.last_layout()?;
    assert_eq!(snapshot.mode(), "enforce");
    assert_eq!(snapshot.mode_flag, Some(MODE_FLAG_ENFORCE));
    sandbox.assert_cgroup_removed()?;

    Ok(())
}

#[test]
fn fake_sandbox_enforce_rename_denial_reports_event() -> Result<(), Box<dyn std::error::Error>> {
    let project = TestProject::new()?;
    project.init_cargo_package("fixture")?;
    let sandbox = project.fake_sandbox("rename")?;
    sandbox.touch_event_log()?;

    let script =
        project.write_violation_script("deny-rename", RENAME_ACTION, DENIED_UNIT, RENAME_PATH)?;
    let policy = project.write_exec_policy("rename", Mode::Enforce, &[&script])?;

    let mut cmd = Command::cargo_bin("cargo-warden")?;
    cmd.arg("run")
        .arg("--policy")
        .arg(&policy)
        .arg("--")
        .arg(&script)
        .arg(sandbox.events_path())
        .arg("enforce")
        .current_dir(project.path());
    sandbox.apply_assert(&mut cmd);

    cmd.assert().failure().code(42);

    let events = sandbox.read_events()?;
    assert_eq!(
        events.len(),
        1,
        "expected single rename event: {:?}",
        events
    );
    assert_denial(&events[0], RENAME_ACTION, RENAME_PATH);

    let snapshot = sandbox.last_layout()?;
    assert_eq!(snapshot.mode(), "enforce");
    assert_eq!(snapshot.mode_flag, Some(MODE_FLAG_ENFORCE));
    sandbox.assert_cgroup_removed()?;

    Ok(())
}

#[test]
fn fake_sandbox_observe_denial_allows_child() -> Result<(), Box<dyn std::error::Error>> {
    let project = TestProject::new()?;
    project.init_cargo_package("fixture")?;
    let sandbox = project.fake_sandbox("observe")?;
    sandbox.touch_event_log()?;

    let script = project.write_violation_script(
        "deny-observe",
        DENIED_ACTION,
        DENIED_UNIT,
        DENIED_ENDPOINT,
    )?;
    let policy = project.write_exec_policy("observe", Mode::Observe, &[&script])?;

    let mut cmd = Command::cargo_bin("cargo-warden")?;
    cmd.arg("run")
        .arg("--policy")
        .arg(&policy)
        .arg("--")
        .arg(&script)
        .arg(sandbox.events_path())
        .arg("observe")
        .current_dir(project.path());
    sandbox.apply_assert(&mut cmd);

    cmd.assert().success().code(0);

    let events = sandbox.read_events()?;
    assert_eq!(
        events.len(),
        1,
        "expected single denial event: {:?}",
        events
    );
    assert_denial(&events[0], DENIED_ACTION, DENIED_ENDPOINT);

    let snapshot = sandbox.last_layout()?;
    assert_eq!(snapshot.mode(), "observe");
    assert_eq!(snapshot.mode_flag, Some(MODE_FLAG_OBSERVE));
    sandbox.assert_cgroup_removed()?;

    Ok(())
}

#[test]
fn run_fake_sandbox_records_layout() -> Result<(), Box<dyn std::error::Error>> {
    let project = TestProject::new()?;
    project.init_cargo_package("fixture")?;
    let sandbox = project.fake_sandbox("layout")?;
    sandbox.touch_event_log()?;

    project.write(
        "policy.toml",
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

    let policy = project.child("policy.toml");

    let mut cmd = Command::cargo_bin("cargo-warden")?;
    cmd.arg("run")
        .arg("--allow")
        .arg("/bin/echo")
        .arg("--policy")
        .arg(&policy)
        .arg("--")
        .arg("true")
        .current_dir(project.path());
    sandbox.apply_assert(&mut cmd);
    cmd.assert().success();

    let snapshots = sandbox.read_layouts()?;
    assert!(
        !snapshots.is_empty(),
        "expected at least one layout snapshot"
    );
    let snapshot = snapshots.last().unwrap();

    assert_eq!(snapshot.mode(), "enforce");
    assert_eq!(snapshot.mode_flag, Some(MODE_FLAG_ENFORCE));
    assert!(
        snapshot.exec_contains("/bin/echo"),
        "expected exec allowlist entry for /bin/echo: {:?}",
        snapshot.exec
    );
    assert!(
        snapshot.net_contains("127.0.0.1", 8080),
        "expected net rule for 127.0.0.1:8080: {:?}",
        snapshot.net
    );
    assert!(
        snapshot.net_parents.is_empty(),
        "expected no net parents: {:?}",
        snapshot.net_parents
    );
    let logs_rule = snapshot.fs_rule("/tmp/logs").expect("logs rule present");
    assert!(
        logs_rule.write,
        "expected write rule for /tmp/logs: {:?}",
        snapshot.fs
    );
    assert!(
        snapshot.fs_contains("/etc/ssl/certs", true, false),
        "expected read-only rule for /etc/ssl/certs: {:?}",
        snapshot.fs
    );

    let events_log = sandbox.raw_event_log()?;
    assert!(
        events_log
            .lines()
            .any(|line| line.contains("\"fake\":true")),
        "expected fake event marker in log: {}",
        events_log
    );
    sandbox.assert_cgroup_removed()?;

    Ok(())
}

#[test]
fn strict_mode_auto_paths_allow_build() -> Result<(), Box<dyn std::error::Error>> {
    let project = TestProject::new()?;
    project.init_cargo_package("fixture")?;
    let sandbox = project.fake_sandbox("strict")?;
    sandbox.touch_event_log()?;

    let target_override = project.child("custom-target");
    let out_dir_override = project.child("custom-out");
    project.create_dir_all(&target_override)?;
    project.create_dir_all(&out_dir_override)?;

    let mut cmd = Command::cargo_bin("cargo-warden")?;
    cmd.arg("run")
        .arg("--")
        .arg("true")
        .current_dir(project.path())
        .env("CARGO_TARGET_DIR", &target_override)
        .env("OUT_DIR", &out_dir_override);
    sandbox.apply_assert(&mut cmd);
    cmd.assert().success();

    let snapshot = sandbox.last_layout()?;

    let workspace = project
        .path()
        .canonicalize()
        .unwrap_or_else(|_| project.path().to_path_buf())
        .to_string_lossy()
        .into_owned();
    let target = target_override
        .canonicalize()
        .unwrap_or(target_override.clone())
        .to_string_lossy()
        .into_owned();
    let out_dir = out_dir_override
        .canonicalize()
        .unwrap_or(out_dir_override.clone())
        .to_string_lossy()
        .into_owned();

    assert!(
        snapshot.fs_contains(&workspace, true, false),
        "expected workspace read rule: {:?}",
        snapshot.fs
    );
    let target_rule = snapshot
        .fs_rule(&target)
        .expect("target override rule present");
    assert!(
        target_rule.write,
        "expected target write rule: {:?}",
        snapshot.fs
    );
    let out_rule = snapshot
        .fs_rule(&out_dir)
        .expect("out dir override rule present");
    assert!(
        out_rule.write,
        "expected out dir write rule: {:?}",
        snapshot.fs
    );

    sandbox.assert_cgroup_removed()?;

    Ok(())
}

#[test]
fn workspace_policy_overrides_modify_layout() -> Result<(), Box<dyn std::error::Error>> {
    let project = TestProject::new()?;
    let sandbox_alpha = project.fake_sandbox("alpha")?;
    let sandbox_beta = project.fake_sandbox("beta")?;

    project.create_dir_all("members/alpha/src")?;
    project.create_dir_all("members/beta/src")?;

    project.write(
        "Cargo.toml",
        "[workspace]\nmembers = [\"members/alpha\", \"members/beta\"]\n",
    )?;

    project.write(
        "members/alpha/Cargo.toml",
        "[package]\nname = \"alpha\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )?;
    project.write("members/alpha/src/lib.rs", "pub fn alpha() {}\n")?;

    project.write(
        "members/beta/Cargo.toml",
        "[package]\nname = \"beta\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )?;
    project.write("members/beta/src/lib.rs", "pub fn beta() {}\n")?;

    project.write(
        "workspace.warden.toml",
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

    sandbox_alpha.touch_event_log()?;
    let alpha_dir = project.child("members/alpha");
    let mut cmd = Command::cargo_bin("cargo-warden")?;
    cmd.arg("run").arg("--").arg("true").current_dir(&alpha_dir);
    sandbox_alpha.apply_assert(&mut cmd);
    cmd.assert().success();

    let alpha_snapshot = sandbox_alpha.last_layout()?;
    assert!(
        alpha_snapshot.exec_contains("/usr/bin/member-a"),
        "expected per-member exec allowance for alpha: {:?}",
        alpha_snapshot.exec
    );
    assert!(
        !alpha_snapshot.net_contains("10.0.0.1", 1234),
        "alpha overrides should not include beta network host: {:?}",
        alpha_snapshot.net
    );
    sandbox_alpha.assert_cgroup_removed()?;

    sandbox_beta.touch_event_log()?;
    let mut cmd = Command::cargo_bin("cargo-warden")?;
    cmd.arg("run")
        .arg("--")
        .arg("true")
        .current_dir(project.path())
        .env("CARGO_PRIMARY_PACKAGE", "beta");
    sandbox_beta.apply_assert(&mut cmd);
    cmd.assert().success();

    let beta_snapshot = sandbox_beta.last_layout()?;
    assert!(
        !beta_snapshot.exec_contains("/usr/bin/member-a"),
        "beta overrides should not inherit alpha exec allowlist: {:?}",
        beta_snapshot.exec
    );
    assert!(
        beta_snapshot.net_contains("10.0.0.1", 1234),
        "beta overrides should include network host 10.0.0.1:1234: {:?}",
        beta_snapshot.net
    );
    sandbox_beta.assert_cgroup_removed()?;

    Ok(())
}
