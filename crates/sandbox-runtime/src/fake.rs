use crate::layout::LayoutRecorder;
use crate::util::{events_path, fake_cgroup_dir};
use qqrm_policy_compiler::MapsLayout;
use std::fs;
use std::io;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, ExitStatus};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

pub(crate) struct FakeSandbox {
    cgroup_dir: PathBuf,
    agent: Option<FakeAgent>,
    layout_recorder: Option<LayoutRecorder>,
}

impl FakeSandbox {
    pub(crate) fn new() -> io::Result<Self> {
        let events = events_path();
        if let Some(parent) = events.parent() {
            fs::create_dir_all(parent)?;
        }
        let cgroup_dir = fake_cgroup_dir();
        if let Some(parent) = cgroup_dir.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::create_dir_all(&cgroup_dir)?;
        let agent = FakeAgent::spawn(events)?;
        let layout_recorder = LayoutRecorder::from_env()?;
        Ok(Self {
            cgroup_dir,
            agent: Some(agent),
            layout_recorder,
        })
    }

    pub(crate) fn run(
        &mut self,
        mut command: Command,
        layout: &MapsLayout,
    ) -> io::Result<ExitStatus> {
        if let Some(recorder) = &mut self.layout_recorder {
            recorder.record(layout)?;
        }
        command.status()
    }

    pub(crate) fn shutdown(mut self) -> io::Result<()> {
        if let Some(agent) = self.agent.take() {
            agent.stop()?;
        }
        if self.cgroup_dir.exists() {
            fs::remove_dir_all(&self.cgroup_dir)?;
        }
        Ok(())
    }
}

impl Drop for FakeSandbox {
    fn drop(&mut self) {
        if let Some(agent) = self.agent.take() {
            let _ = agent.stop();
        }
        if self.cgroup_dir.exists() {
            let _ = fs::remove_dir_all(&self.cgroup_dir);
        }
    }
}

struct FakeAgent {
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<io::Result<()>>>,
}

impl FakeAgent {
    fn spawn(path: PathBuf) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = stop.clone();
        let handle = thread::Builder::new()
            .name("fake-agent-lite".into())
            .spawn(move || {
                while !stop_thread.load(Ordering::SeqCst) {
                    thread::sleep(Duration::from_millis(10));
                }
                let mut file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)?;
                writeln!(file, "{{\"fake\":true}}")?;
                Ok(())
            })
            .map_err(|err| io::Error::other(format!("failed to spawn fake agent: {err}")))?;
        Ok(Self {
            stop,
            handle: Some(handle),
        })
    }

    fn stop(mut self) -> io::Result<()> {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            match handle.join() {
                Ok(result) => result,
                Err(err) => Err(io::Error::other(format!("fake agent panicked: {err:?}"))),
            }
        } else {
            Ok(())
        }
    }
}

impl Drop for FakeAgent {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::{FAKE_LAYOUT_ENV, LayoutSnapshot};
    use crate::util::{EVENTS_PATH_ENV, FAKE_CGROUP_DIR_ENV};
    use bpf_api::{ExecAllowEntry, FsRule, FsRuleEntry};
    use qqrm_policy_compiler::MapsLayout;
    use serial_test::serial;
    use std::env;
    use std::fs::{self, File};
    use std::io::Read;
    use std::process::Command;
    use tempfile::tempdir;

    struct EnvGuard {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &std::path::Path) -> Self {
            let previous = env::var_os(key);
            unsafe {
                env::set_var(key, value);
            }
            Self { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(value) = self.previous.take() {
                unsafe {
                    env::set_var(self.key, value);
                }
            } else {
                unsafe {
                    env::remove_var(self.key);
                }
            }
        }
    }

    #[test]
    #[serial]
    fn fake_sandbox_records_layout_and_events() -> io::Result<()> {
        let dir = tempdir().expect("tempdir");
        let events_path = dir.path().join("events.jsonl");
        let layout_path = dir.path().join("layout.jsonl");
        let cgroup_dir = dir.path().join("fake-cgroup");

        let _events_guard = EnvGuard::set(EVENTS_PATH_ENV, &events_path);
        let _layout_guard = EnvGuard::set(FAKE_LAYOUT_ENV, &layout_path);
        let _cgroup_guard = EnvGuard::set(FAKE_CGROUP_DIR_ENV, &cgroup_dir);

        let mut sandbox = FakeSandbox::new()?;
        let mut exec_entry = [0u8; 256];
        exec_entry[.."/bin/echo".len()].copy_from_slice(b"/bin/echo");
        let layout = MapsLayout {
            exec_allowlist: vec![ExecAllowEntry { path: exec_entry }],
            net_rules: Vec::new(),
            net_parents: Vec::new(),
            fs_rules: vec![FsRuleEntry {
                unit: 0,
                rule: FsRule {
                    access: bpf_api::FS_READ | bpf_api::FS_WRITE,
                    reserved: [0; 3],
                    path: {
                        let mut buf = [0u8; 256];
                        buf[.."/tmp/logs".len()].copy_from_slice(b"/tmp/logs");
                        buf
                    },
                },
            }],
        };

        let status = sandbox.run(Command::new("true"), &layout)?;
        assert!(status.success(), "fake sandbox command should succeed");
        sandbox.shutdown()?;

        let mut layout_contents = String::new();
        File::open(&layout_path)?.read_to_string(&mut layout_contents)?;
        let snapshots: Vec<LayoutSnapshot> = layout_contents
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?;
        assert!(
            !snapshots.is_empty(),
            "expected at least one recorded layout entry"
        );
        let latest = snapshots.last().unwrap();
        assert!(
            latest.exec.iter().any(|entry| entry == "/bin/echo"),
            "expected exec allowlist entry: {:?}",
            latest.exec
        );
        assert!(
            latest
                .fs
                .iter()
                .any(|rule| rule.path == "/tmp/logs" && rule.write),
            "expected filesystem write rule: {:?}",
            latest.fs
        );

        let events_contents = fs::read_to_string(&events_path)?;
        assert!(
            events_contents
                .lines()
                .any(|line| line.contains("\"fake\":true")),
            "expected fake agent event: {events_contents}"
        );
        assert!(
            !cgroup_dir.exists(),
            "fake sandbox shutdown should remove cgroup directory"
        );
        Ok(())
    }
}
