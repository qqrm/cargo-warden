use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use std::path::Path;
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

#[test]
fn run_host_sandbox_allows_project_paths() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let workspace = dir.path();
    let events_path = workspace.join("warden-events.jsonl");
    let target_dir = workspace.join("target");
    let out_dir = workspace.join("out");
    fs::create_dir_all(&target_dir)?;
    fs::create_dir_all(&out_dir)?;
    write_policy(workspace, &target_dir, &out_dir)?;

    let mut cmd = Command::cargo_bin("cargo-warden")?;
    cmd.current_dir(workspace)
        .arg("run")
        .arg("--")
        .arg("true")
        .env("QQRM_WARDEN_HOST_HARNESS", "1")
        .env("QQRM_WARDEN_EVENTS_PATH", &events_path)
        .env(
            "QQRM_WARDEN_HOST_WRITE_PATHS",
            join_paths([
                target_dir.join("artifact.rlib"),
                out_dir.join("generated.rs"),
            ]),
        );
    cmd.assert().success();

    if events_path.exists() {
        let contents = fs::read_to_string(&events_path)?;
        assert!(
            contents.trim().is_empty(),
            "expected no events, found: {contents}"
        );
    }

    Ok(())
}

#[test]
fn run_host_sandbox_blocks_external_paths() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let workspace = dir.path();
    let events_path = workspace.join("warden-events.jsonl");
    let target_dir = workspace.join("target");
    let out_dir = workspace.join("out");
    fs::create_dir_all(&target_dir)?;
    fs::create_dir_all(&out_dir)?;
    write_policy(workspace, &target_dir, &out_dir)?;

    let forbidden = workspace.join("forbidden.log");
    let denied_message = format!("Denied filesystem access: {}", forbidden.display());

    let mut cmd = Command::cargo_bin("cargo-warden")?;
    cmd.current_dir(workspace)
        .arg("run")
        .arg("--")
        .arg("true")
        .env("QQRM_WARDEN_HOST_HARNESS", "1")
        .env("QQRM_WARDEN_EVENTS_PATH", &events_path)
        .env(
            "QQRM_WARDEN_HOST_WRITE_PATHS",
            join_paths([target_dir.join("artifact.rlib"), forbidden.clone()]),
        );
    let assert = cmd.assert().failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        stderr.contains(&denied_message),
        "expected stderr to contain '{denied_message}', got: {stderr}"
    );

    let contents = fs::read_to_string(&events_path)?;
    let mut lines = contents.lines();
    let line = lines.next().expect("event entry");
    assert!(lines.next().is_none(), "expected single event: {contents}");
    let record: Value = serde_json::from_str(line)?;
    assert_eq!(record["verdict"], 1);
    assert_eq!(record["path_or_addr"], forbidden.display().to_string());

    Ok(())
}

fn write_policy(
    workspace: &Path,
    target: &Path,
    out_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let policy = format!(
        "mode = \"enforce\"\n\
         fs.default = \"strict\"\n\
         net.default = \"deny\"\n\
         exec.default = \"allowlist\"\n\
         \n\
         [allow.fs]\n\
         write_extra = [\"{}\", \"{}\"]\n",
        target.display(),
        out_dir.display()
    );
    fs::write(workspace.join("warden.toml"), policy)?;
    Ok(())
}

fn join_paths<I, P>(paths: I) -> std::ffi::OsString
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    let os_strings: Vec<std::ffi::OsString> = paths
        .into_iter()
        .map(|path| path.as_ref().as_os_str().to_os_string())
        .collect();
    std::env::join_paths(os_strings).expect("join paths")
}
