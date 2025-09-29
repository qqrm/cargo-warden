//! Utilities for integration testing sandbox components.
//!
//! The helpers in this crate make it straightforward to exercise the fake
//! sandbox that ships with `cargo-warden` from integration tests. They cover
//! the common pieces of wiring that the real binaries expect – temporary
//! workspaces, example policies, event logs, and assertions over the serialized
//! BPF map state recorded by the fake sandbox.
//!
//! # Examples
//!
//! ```rust,no_run
//! use assert_cmd::Command;
//! use policy_core::Mode;
//! use qqrm_testkits::{LayoutSnapshotExt, TestProject};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let project = TestProject::new()?;
//! project.init_cargo_package("fixture")?;
//! let sandbox = project.fake_sandbox("demo")?;
//! sandbox.touch_event_log()?;
//!
//! let script = project.write_violation_script("deny", 4, 1, "198.51.100.10:443")?;
//! let policy = project.write_exec_policy("demo", Mode::Enforce, &[&script])?;
//!
//! let mut cmd = Command::cargo_bin("cargo-warden")?;
//! cmd.arg("run")
//!     .arg("--policy")
//!     .arg(&policy)
//!     .arg("--")
//!     .arg(&script)
//!     .arg(sandbox.events_path())
//!     .arg("enforce")
//!     .current_dir(project.path());
//! sandbox.apply_assert(&mut cmd);
//! cmd.assert().failure();
//!
//! let layout = sandbox.last_layout()?;
//! assert_eq!(layout.mode(), "enforce");
//! assert!(!layout.exec_contains("/bin/echo"));
//! # Ok(())
//! # }
//! ```
//!
//! The example above demonstrates the typical workflow used throughout the
//! repository’s integration tests.

use assert_cmd::Command;
use event_reporting::EventRecord;
use policy_core::Mode;
use sandbox_runtime::{FsRuleSnapshot, LayoutSnapshot};
use serde::de::DeserializeOwned;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process;
use std::thread;
use std::time::Duration;
use tempfile::TempDir;

/// Convenient alias for results produced by the testkits helpers.
pub type Result<T> = std::result::Result<T, TestkitError>;

const FAKE_SANDBOX_ENV: &str = "QQRM_WARDEN_FAKE_SANDBOX";
const EVENTS_PATH_ENV: &str = "QQRM_WARDEN_EVENTS_PATH";
const FAKE_CGROUP_DIR_ENV: &str = "QQRM_WARDEN_FAKE_CGROUP_DIR";
const FAKE_LAYOUT_PATH_ENV: &str = "QQRM_WARDEN_FAKE_LAYOUT_PATH";

const MAX_ATTEMPTS: usize = 50;
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Error returned by the integration testing helpers.
#[derive(Debug, thiserror::Error)]
pub enum TestkitError {
    /// Wrapper around [`io::Error`].
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    /// Wrapper around [`serde_json::Error`].
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    /// The fake sandbox did not produce the expected output in time.
    #[error("timeout waiting for {path}: {message}")]
    Timeout { path: PathBuf, message: String },
    /// Assertion helper triggered an error.
    #[error("assertion failure: {message}")]
    Assertion { message: String },
}

/// Temporary cargo workspace for integration tests.
#[derive(Debug)]
pub struct TestProject {
    tempdir: TempDir,
}

impl TestProject {
    /// Create a new temporary workspace.
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            tempdir: tempfile::tempdir()?,
        })
    }

    /// Root path of the workspace.
    pub fn path(&self) -> &Path {
        self.tempdir.path()
    }

    /// Resolve a path relative to the workspace.
    pub fn child(&self, rel: impl AsRef<Path>) -> PathBuf {
        self.path().join(rel)
    }

    /// Write file contents relative to the workspace.
    pub fn write(&self, rel: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> io::Result<()> {
        let path = self.child(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, contents)
    }

    /// Create a directory (and all intermediate components) inside the workspace.
    pub fn create_dir_all(&self, rel: impl AsRef<Path>) -> io::Result<()> {
        fs::create_dir_all(self.child(rel))
    }

    /// Generate a simple library crate manifest in the workspace root.
    pub fn init_cargo_package(&self, name: &str) -> io::Result<()> {
        self.write(
            "Cargo.toml",
            format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"),
        )?;
        self.create_dir_all("src")?;
        self.write("src/lib.rs", "pub fn fixture() {}\n")
    }

    /// Create a fake sandbox fixture rooted in this workspace.
    pub fn fake_sandbox(&self, prefix: &str) -> io::Result<FakeSandbox> {
        FakeSandbox::new(self.path(), prefix)
    }

    /// Write a violation shell script that reports an event through the fake sandbox.
    pub fn write_violation_script(
        &self,
        stem: &str,
        action: u8,
        unit: u8,
        path_or_addr: &str,
    ) -> io::Result<PathBuf> {
        let script_path = self.child(format!("{stem}.sh"));
        let deny_event = serde_json::json!({
            "pid": 7777u32,
            "tgid": 8888u32,
            "time_ns": 1_234_567_890u64,
            "unit": unit,
            "action": action,
            "verdict": 1,
            "container_id": 0,
            "caps": 0,
            "path_or_addr": path_or_addr,
            "needed_perm": "allow.net.hosts",
        })
        .to_string();

        self.write(
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

    /// Write a minimal policy file that allowlists the provided exec paths.
    pub fn write_exec_policy<P: AsRef<Path>>(
        &self,
        stem: &str,
        mode: Mode,
        allowed_exec: &[P],
    ) -> Result<PathBuf> {
        let allowed = allowed_exec
            .iter()
            .map(|path| {
                let os = path.as_ref().as_os_str();
                os.to_str()
                    .map(ToOwned::to_owned)
                    .ok_or_else(|| TestkitError::Assertion {
                        message: format!(
                            "exec path {} is not valid UTF-8",
                            path.as_ref().display()
                        ),
                    })
            })
            .collect::<Result<Vec<String>>>()?;

        let allowed_list = allowed
            .iter()
            .map(|entry| format!("\"{entry}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let policy_path = self.child(format!("{stem}-policy.toml"));
        self.write(
            &policy_path,
            format!(
                "mode = \"{mode}\"\n\n[fs]\ndefault = \"strict\"\n\n[net]\ndefault = \"deny\"\n\n[exec]\ndefault = \"allowlist\"\n\n[allow.exec]\nallowed = [{allowed_list}]\n",
                mode = mode_name(mode)
            ),
        )?;
        Ok(policy_path)
    }
}

/// A fake sandbox instance configured through environment variables.
#[derive(Debug, Clone)]
pub struct FakeSandbox {
    events_path: PathBuf,
    layout_path: PathBuf,
    cgroup_path: PathBuf,
}

impl FakeSandbox {
    fn new(root: &Path, prefix: &str) -> io::Result<Self> {
        Ok(Self {
            events_path: root.join(format!("{prefix}-events.jsonl")),
            layout_path: root.join(format!("{prefix}-layout.jsonl")),
            cgroup_path: root.join(format!("{prefix}-cgroup")),
        })
    }

    /// Path to the events JSON lines file.
    pub fn events_path(&self) -> &Path {
        &self.events_path
    }

    /// Path to the layout JSON lines file.
    pub fn layout_path(&self) -> &Path {
        &self.layout_path
    }

    /// Path to the fake cgroup directory used by the sandbox.
    pub fn cgroup_path(&self) -> &Path {
        &self.cgroup_path
    }

    /// Pre-create the event log file expected by the fake sandbox.
    pub fn touch_event_log(&self) -> io::Result<()> {
        if let Some(parent) = self.events_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::File::create(&self.events_path).map(|_| ())
    }

    /// Apply fake sandbox environment variables to a command.
    pub fn apply(&self, command: &mut process::Command) {
        command.env(FAKE_SANDBOX_ENV, "1");
        command.env(EVENTS_PATH_ENV, &self.events_path);
        command.env(FAKE_CGROUP_DIR_ENV, &self.cgroup_path);
        command.env(FAKE_LAYOUT_PATH_ENV, &self.layout_path);
    }

    /// Apply fake sandbox environment variables to an [`assert_cmd::Command`].
    pub fn apply_assert(&self, command: &mut Command) {
        command
            .env(FAKE_SANDBOX_ENV, "1")
            .env(EVENTS_PATH_ENV, &self.events_path)
            .env(FAKE_CGROUP_DIR_ENV, &self.cgroup_path)
            .env(FAKE_LAYOUT_PATH_ENV, &self.layout_path);
    }

    /// Wait for the fake agent to flush its events and return the parsed JSON lines.
    pub fn read_events(&self) -> Result<Vec<EventRecord>> {
        let contents = wait_for_fake_agent(&self.events_path)?;
        let events = contents
            .lines()
            .filter_map(|line| serde_json::from_str::<EventRecord>(line).ok())
            .collect::<Vec<_>>();
        Ok(events)
    }

    /// Return the raw events log emitted by the fake sandbox, including sentinel entries.
    pub fn raw_event_log(&self) -> Result<String> {
        wait_for_fake_agent(&self.events_path)
    }

    /// Read all layout snapshots recorded by the fake sandbox.
    pub fn read_layouts(&self) -> Result<Vec<LayoutSnapshot>> {
        read_json_lines(&self.layout_path)
    }

    /// Convenience wrapper returning the most recent layout snapshot.
    pub fn last_layout(&self) -> Result<LayoutSnapshot> {
        let mut snapshots = self.read_layouts()?;
        snapshots.pop().ok_or_else(|| TestkitError::Assertion {
            message: format!(
                "expected at least one layout snapshot in {}",
                self.layout_path.display()
            ),
        })
    }

    /// Assert that the fake sandbox removed the cgroup directory after execution.
    pub fn assert_cgroup_removed(&self) -> Result<()> {
        if self.cgroup_path.exists() {
            return Err(TestkitError::Assertion {
                message: format!(
                    "expected fake sandbox to remove {}, but it still exists",
                    self.cgroup_path.display()
                ),
            });
        }
        Ok(())
    }
}

fn wait_for_fake_agent(path: &Path) -> Result<String> {
    for attempt in 0..=MAX_ATTEMPTS {
        match fs::read_to_string(path) {
            Ok(contents) => {
                if contents.lines().any(|line| line.contains("\"fake\":true")) {
                    return Ok(contents);
                }
                if attempt == MAX_ATTEMPTS {
                    return Err(TestkitError::Timeout {
                        path: path.to_path_buf(),
                        message: format!("fake agent did not record final entry: {contents}"),
                    });
                }
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                if attempt == MAX_ATTEMPTS {
                    return Err(TestkitError::Timeout {
                        path: path.to_path_buf(),
                        message: "fake agent never created events file".into(),
                    });
                }
            }
            Err(err) => return Err(err.into()),
        }
        thread::sleep(POLL_INTERVAL);
    }
    Err(TestkitError::Timeout {
        path: path.to_path_buf(),
        message: "fake agent did not produce events".into(),
    })
}

fn read_json_lines<T: DeserializeOwned>(path: &Path) -> Result<Vec<T>> {
    for attempt in 0..=MAX_ATTEMPTS {
        match fs::read_to_string(path) {
            Ok(contents) => {
                if contents.is_empty() && attempt != MAX_ATTEMPTS {
                    thread::sleep(POLL_INTERVAL);
                    continue;
                }
                let mut items = Vec::new();
                for line in contents.lines() {
                    if line.trim().is_empty() {
                        continue;
                    }
                    items.push(serde_json::from_str(line)?);
                }
                return Ok(items);
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound && attempt != MAX_ATTEMPTS => {
                thread::sleep(POLL_INTERVAL);
                continue;
            }
            Err(err) => return Err(err.into()),
        }
    }
    Err(TestkitError::Timeout {
        path: path.to_path_buf(),
        message: "timed out waiting for JSON lines".into(),
    })
}

/// Extension methods for asserting over fake sandbox layout snapshots.
pub trait LayoutSnapshotExt {
    /// Expose the sandbox mode as a string.
    fn mode(&self) -> &str;
    /// Returns true if the exec allowlist contains the provided path.
    fn exec_contains(&self, path: &str) -> bool;
    /// Returns the filesystem rule associated with the provided path, if any.
    fn fs_rule(&self, path: &str) -> Option<&FsRuleSnapshot>;
    /// Returns true if the filesystem rules contain an entry with the expected access.
    fn fs_contains(&self, path: &str, read: bool, write: bool) -> bool;
    /// Returns true if the network rules contain an entry matching the address and port.
    fn net_contains(&self, addr: &str, port: u16) -> bool;
    /// Returns true if the provided parent relationship exists.
    fn has_net_parent(&self, child: u32, parent: u32) -> bool;
}

impl LayoutSnapshotExt for LayoutSnapshot {
    fn mode(&self) -> &str {
        &self.mode
    }

    fn exec_contains(&self, path: &str) -> bool {
        self.exec.iter().any(|entry| entry == path)
    }

    fn fs_rule(&self, path: &str) -> Option<&FsRuleSnapshot> {
        self.fs.iter().find(|rule| rule.path == path)
    }

    fn fs_contains(&self, path: &str, read: bool, write: bool) -> bool {
        self.fs_rule(path)
            .map(|rule| rule.read == read && rule.write == write)
            .unwrap_or(false)
    }

    fn net_contains(&self, addr: &str, port: u16) -> bool {
        self.net
            .iter()
            .any(|rule| rule.addr == addr && rule.port == port)
    }

    fn has_net_parent(&self, child: u32, parent: u32) -> bool {
        self.net_parents
            .iter()
            .any(|entry| entry.child == child && entry.parent == parent)
    }
}

fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::Enforce => "enforce",
        Mode::Observe => "observe",
    }
}

fn make_executable(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms)
    }

    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}
