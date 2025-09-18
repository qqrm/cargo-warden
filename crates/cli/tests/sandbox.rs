use assert_cmd::Command;
use std::fs;
use tempfile::tempdir;

#[test]
fn run_fake_sandbox_records_events() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let events_path = dir.path().join("warden-events.jsonl");
    let cgroup_path = dir.path().join("fake-cgroup");

    let mut cmd = Command::cargo_bin("cargo-warden")?;
    cmd.arg("run")
        .arg("--")
        .arg("true")
        .env("QQRM_WARDEN_FAKE_SANDBOX", "1")
        .env("QQRM_WARDEN_EVENTS_PATH", &events_path)
        .env("QQRM_WARDEN_FAKE_CGROUP_DIR", &cgroup_path);
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
    Ok(())
}
