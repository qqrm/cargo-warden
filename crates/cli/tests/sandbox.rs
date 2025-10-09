use assert_cmd::Command;
use bpf_api::{MODE_FLAG_ENFORCE, MODE_FLAG_OBSERVE, UNIT_RUSTC};
use event_reporting::{EventRecord, METRICS_SNAPSHOT_FILE};
use policy_core::Mode;
use qqrm_testkits::{LayoutSnapshotExt, TestProject};
use serde_json::{Value, json};
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;

const DENIED_ENDPOINT: &str = "198.51.100.10:443";
const DENIED_PID: u32 = 7777;
const DENIED_ACTION: u8 = 4;
const DENIED_UNIT: u8 = UNIT_RUSTC as u8;
const RENAME_PATH: &str = "/var/warden/forbidden";
const RENAME_ACTION: u8 = 1;

#[cfg(unix)]
fn set_executable(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms)
}

#[cfg(not(unix))]
fn set_executable(path: &Path) -> std::io::Result<()> {
    let _ = path;
    Ok(())
}

fn assert_denial(event: &EventRecord, action: u8, path_or_addr: &str, needed_perm: &str) {
    assert_eq!(event.pid, DENIED_PID);
    assert_eq!(event.action, action);
    assert_eq!(event.unit, DENIED_UNIT);
    assert_eq!(event.verdict, 1);
    assert_eq!(event.path_or_addr, path_or_addr);
    assert_eq!(event.needed_perm, needed_perm);
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
        "allow.net.hosts",
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

    cmd.assert().failure().code(13);

    let events = sandbox.read_events()?;
    assert_eq!(
        events.len(),
        1,
        "expected single denial event: {:?}",
        events
    );
    assert_denial(
        &events[0],
        DENIED_ACTION,
        DENIED_ENDPOINT,
        "allow.net.hosts",
    );

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

    let script = project.write_violation_script(
        "deny-rename",
        RENAME_ACTION,
        DENIED_UNIT,
        RENAME_PATH,
        "allow.fs.write_extra",
    )?;
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

    cmd.assert().failure().code(13);

    let events = sandbox.read_events()?;
    assert_eq!(
        events.len(),
        1,
        "expected single rename event: {:?}",
        events
    );
    assert_denial(
        &events[0],
        RENAME_ACTION,
        RENAME_PATH,
        "allow.fs.write_extra",
    );

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
        "allow.net.hosts",
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
    assert_denial(
        &events[0],
        DENIED_ACTION,
        DENIED_ENDPOINT,
        "allow.net.hosts",
    );

    let display = sandbox.last_event()?.to_string();
    assert!(
        display.contains("hint=allow.net.hosts"),
        "expected hint in observe mode display: {display}"
    );

    let snapshot = sandbox.last_layout()?;
    assert_eq!(snapshot.mode(), "observe");
    assert_eq!(snapshot.mode_flag, Some(MODE_FLAG_OBSERVE));
    sandbox.assert_cgroup_removed()?;

    Ok(())
}

#[test]
fn fake_sandbox_manifest_metadata_extends_policy() -> Result<(), Box<dyn std::error::Error>> {
    let project = TestProject::new()?;
    project.init_cargo_package("fixture")?;
    project.create_dir_all("bin")?;
    project.create_dir_all("include")?;

    let tool_path = project.child("bin/tool.sh");
    project.write(&tool_path, "#!/bin/sh\nexit 0\n")?;

    project.write(
        "Cargo.toml",
        format!(
            r#"[package]
name = "fixture"
version = "0.1.0"
edition = "2021"

[package.metadata.cargo-warden]
permissions = [
  "exec:{tool}",
]

[[package.metadata.cargo-warden.plugins]]
permissions = ["fs:read:include"]
"#,
            tool = tool_path.display(),
        ),
    )?;

    let sandbox = project.fake_sandbox("metadata-permissions")?;
    sandbox.touch_event_log()?;

    let mut cmd = Command::cargo_bin("cargo-warden")?;
    cmd.arg("run")
        .arg("--")
        .arg("true")
        .current_dir(project.path());
    sandbox.apply_assert(&mut cmd);
    cmd.assert().success();

    let snapshot = sandbox.last_layout()?;
    let tool_string = tool_path.to_string_lossy().into_owned();
    assert!(snapshot.exec_contains(&tool_string));

    let include_path = std::fs::canonicalize(project.child("include"))?;
    let include_string = include_path.to_string_lossy().into_owned();
    assert!(snapshot.fs_contains(&include_string, true, false));

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
fn cli_merges_multiple_policies_and_cli_allow() -> Result<(), Box<dyn std::error::Error>> {
    let project = TestProject::new()?;
    project.init_cargo_package("fixture")?;
    let sandbox = project.fake_sandbox("merge-policies")?;
    sandbox.touch_event_log()?;

    let policy_a = project.child("policy-a.toml");
    project.write(
        &policy_a,
        r#"
mode = "observe"

[fs]
default = "strict"

[net]
default = "deny"

[exec]
default = "allowlist"

[allow.exec]
allowed = ["/usr/bin/policy-a"]
"#,
    )?;

    let policy_b = project.child("policy-b.toml");
    project.write(
        &policy_b,
        r#"
mode = "enforce"

[fs]
default = "strict"

[net]
default = "deny"

[exec]
default = "allowlist"

[allow.exec]
allowed = ["/usr/bin/policy-b"]

[allow.net]
hosts = ["203.0.113.1:8080"]
"#,
    )?;

    let mut cmd = Command::cargo_bin("cargo-warden")?;
    cmd.arg("run")
        .arg("--policy")
        .arg(&policy_a)
        .arg("--policy")
        .arg(&policy_b)
        .arg("--allow")
        .arg("/usr/bin/cli-override")
        .arg("--")
        .arg("true")
        .current_dir(project.path());
    sandbox.apply_assert(&mut cmd);
    cmd.assert().success();

    let snapshot = sandbox.last_layout()?;
    assert_eq!(snapshot.mode(), "enforce");
    assert!(snapshot.exec_contains("/usr/bin/policy-a"));
    assert!(snapshot.exec_contains("/usr/bin/policy-b"));
    assert!(snapshot.exec_contains("/usr/bin/cli-override"));
    assert!(snapshot.net_contains("203.0.113.1", 8080));
    sandbox.assert_cgroup_removed()?;

    Ok(())
}

#[test]
fn build_merges_multiple_policies_and_cli_allow() -> Result<(), Box<dyn std::error::Error>> {
    let project = TestProject::new()?;
    project.init_cargo_package("fixture")?;
    let sandbox = project.fake_sandbox("build-merge")?;
    sandbox.touch_event_log()?;

    let policy_a = project.child("build-policy-a.toml");
    project.write(
        &policy_a,
        r#"
mode = "observe"

[fs]
default = "strict"

[net]
default = "deny"

[exec]
default = "allowlist"

[allow.exec]
allowed = ["/usr/bin/build-a"]

[allow.env]
read = ["PATH"]
"#,
    )?;

    let policy_b = project.child("build-policy-b.toml");
    project.write(
        &policy_b,
        r#"
mode = "enforce"

[fs]
default = "strict"

[net]
default = "deny"

[exec]
default = "allowlist"

[allow.exec]
allowed = ["/usr/bin/build-b"]

[allow.net]
hosts = ["203.0.113.2:8081"]
"#,
    )?;

    let cargo_stub = project.child("cargo");
    project.write(
        &cargo_stub,
        r#"#!/bin/sh
set -eu

if [ "$1" = "build" ]; then
    exit "${CARGO_WARDEN_EXIT:-0}"
fi

echo "unexpected cargo invocation" >&2
exit 1
"#,
    )?;
    set_executable(&cargo_stub)?;

    let mut cmd = Command::cargo_bin("cargo-warden")?;
    cmd.arg("build")
        .arg("--policy")
        .arg(&policy_a)
        .arg("--policy")
        .arg(&policy_b)
        .arg("--allow")
        .arg("/usr/bin/build-cli")
        .current_dir(project.path());
    sandbox.apply_assert(&mut cmd);

    let mut path_entries = vec![project.path().to_path_buf()];
    if let Some(existing) = env::var_os("PATH") {
        path_entries.extend(env::split_paths(&existing));
    }
    let joined = env::join_paths(path_entries)?;
    cmd.env("PATH", joined);
    cmd.env("CARGO_WARDEN_EXIT", "0");

    cmd.assert().success();

    let snapshot = sandbox.last_layout()?;
    assert_eq!(snapshot.mode(), "enforce");
    assert!(snapshot.exec_contains("/usr/bin/build-a"));
    assert!(snapshot.exec_contains("/usr/bin/build-b"));
    assert!(snapshot.exec_contains("/usr/bin/build-cli"));
    assert!(snapshot.net_contains("203.0.113.2", 8081));
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

#[test]
fn status_reports_policy_sources_and_events() -> Result<(), Box<dyn std::error::Error>> {
    let project = TestProject::new()?;
    project.init_cargo_package("fixture")?;

    project.write("warden.toml", "mode = \"observe\"\n")?;
    let cli_policy = project.child("cli-policy.toml");
    project.write(&cli_policy, "mode = \"enforce\"\n")?;

    let events_path = project.child("warden-events.jsonl");
    let mut events_file = File::create(&events_path)?;
    writeln!(
        events_file,
        "{}",
        json!({
            "pid": 1,
            "tgid": 10,
            "time_ns": 100,
            "unit": DENIED_UNIT,
            "action": DENIED_ACTION,
            "verdict": 1,
            "container_id": 0,
            "caps": 0,
            "path_or_addr": DENIED_ENDPOINT,
            "needed_perm": "allow.net.hosts"
        })
    )?;
    writeln!(events_file, "{{ not json }}")?;

    let mut cmd = Command::cargo_bin("cargo-warden")?;
    cmd.arg("status")
        .arg("--policy")
        .arg(&cli_policy)
        .current_dir(project.path());

    let assert = cmd.assert().success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone())?;

    assert!(stdout.contains("local policy"));
    assert!(stdout.contains("CLI policy"));
    assert!(stdout.contains("effective mode: enforce"));
    assert!(stdout.contains("recent events"));
    assert!(stdout.contains("hint=allow.net.hosts"));

    Ok(())
}

#[test]
fn report_emits_json_with_metrics() -> Result<(), Box<dyn std::error::Error>> {
    let project = TestProject::new()?;
    project.init_cargo_package("fixture")?;

    let events_path = project.child("warden-events.jsonl");
    let mut events_file = File::create(&events_path)?;
    writeln!(
        events_file,
        "{}",
        json!({
            "pid": 11,
            "tgid": 20,
            "time_ns": 200,
            "unit": DENIED_UNIT,
            "action": DENIED_ACTION,
            "verdict": 1,
            "container_id": 0,
            "caps": 0,
            "path_or_addr": DENIED_ENDPOINT,
            "needed_perm": "allow.net.hosts"
        })
    )?;
    writeln!(
        events_file,
        "{}",
        json!({
            "pid": 12,
            "tgid": 22,
            "time_ns": 220,
            "unit": DENIED_UNIT,
            "action": DENIED_ACTION,
            "verdict": 0,
            "container_id": 0,
            "caps": 0,
            "path_or_addr": "/bin/echo",
            "needed_perm": ""
        })
    )?;
    writeln!(events_file, "{{ invalid }}")?;

    project.write(
        METRICS_SNAPSHOT_FILE,
        serde_json::to_string(&json!({
            "allowed_total": 5,
            "denied_total": 1,
            "violations_total": 1,
            "blocked_total": 1,
            "per_unit": {
                DENIED_UNIT.to_string(): {
                    "allowed": 2,
                    "denied": 1,
                    "io_read_bytes": 32,
                    "io_write_bytes": 16,
                    "cpu_time_ms": 7,
                    "page_faults": 3
                }
            }
        }))?,
    )?;

    let mut cmd = Command::cargo_bin("cargo-warden")?;
    cmd.arg("report")
        .arg("--format")
        .arg("json")
        .current_dir(project.path());

    let assert = cmd.assert().success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone())?;
    let payload: Value = serde_json::from_str(&stdout)?;

    assert_eq!(payload["stats"]["denied"], 1);
    assert_eq!(payload["stats"]["skipped_events"], 1);
    assert_eq!(payload["stats"]["metrics"]["denied_total"], 1);
    assert_eq!(payload["events"].as_array().map(|a| a.len()), Some(2));

    Ok(())
}
