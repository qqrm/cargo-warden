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
    use crate::util::{EVENTS_PATH_ENV, FAKE_CGROUP_DIR_ENV, FAKE_CGROUP_ROOT_ENV};
    use bpf_api::{
        ExecAllowEntry, FS_READ, FS_WRITE, FsRule, FsRuleEntry, NetParentEntry, NetRule,
        NetRuleEntry,
    };
    use serial_test::serial;
    use std::env;
    use std::ffi::{OsStr, OsString};
    use std::process::Command;
    use tempfile::TempDir;

    struct EnvGuard {
        key: String,
        original: Option<OsString>,
    }

    impl EnvGuard {
        fn set(key: &str, value: impl AsRef<OsStr>) -> Self {
            let original = env::var_os(key);
            unsafe { env::set_var(key, value) };
            Self {
                key: key.to_string(),
                original,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(value) = &self.original {
                unsafe { env::set_var(&self.key, value) };
            } else {
                unsafe { env::remove_var(&self.key) };
            }
        }
    }

    fn encoded_path(path: &str) -> [u8; 256] {
        let mut buf = [0u8; 256];
        let bytes = path.as_bytes();
        buf[..bytes.len()].copy_from_slice(bytes);
        buf
    }

    fn sample_layout() -> MapsLayout {
        let mut addr = [0u8; 16];
        addr[..4].copy_from_slice(&[127, 0, 0, 1]);
        MapsLayout {
            exec_allowlist: vec![ExecAllowEntry {
                path: encoded_path("/bin/echo"),
            }],
            net_rules: vec![NetRuleEntry {
                unit: 1,
                rule: NetRule {
                    addr,
                    protocol: 6,
                    prefix_len: 32,
                    port: 8080,
                },
            }],
            net_parents: vec![NetParentEntry {
                child: 1,
                parent: 0,
            }],
            fs_rules: vec![
                FsRuleEntry {
                    unit: 2,
                    rule: FsRule {
                        access: FS_READ | FS_WRITE,
                        reserved: [0; 3],
                        path: encoded_path("/tmp/logs"),
                    },
                },
                FsRuleEntry {
                    unit: 3,
                    rule: FsRule {
                        access: FS_READ,
                        reserved: [0; 3],
                        path: encoded_path("/etc/ssl/certs"),
                    },
                },
            ],
        }
    }

    #[test]
    #[serial]
    fn fake_sandbox_records_layout_and_events() -> io::Result<()> {
        let temp = TempDir::new().expect("tempdir");
        let events_path = temp.path().join("events.jsonl");
        let layout_path = temp.path().join("layout.jsonl");
        let cgroup_root = temp.path().join("cgroup-root");
        let fake_dir = temp.path().join("fake-cgroup");
        fs::create_dir_all(&cgroup_root)?;

        let _events_guard = EnvGuard::set(EVENTS_PATH_ENV, &events_path);
        let _layout_guard = EnvGuard::set(FAKE_LAYOUT_ENV, &layout_path);
        let _dir_guard = EnvGuard::set(FAKE_CGROUP_DIR_ENV, &fake_dir);
        let _root_guard = EnvGuard::set(FAKE_CGROUP_ROOT_ENV, &cgroup_root);

        let mut sandbox = FakeSandbox::new()?;
        let layout = sample_layout();
        let status = sandbox
            .run(Command::new("true"), &layout)
            .expect("run should succeed");
        assert!(status.success(), "command should succeed");

        sandbox.shutdown()?;

        let layout_contents = fs::read_to_string(&layout_path)?;
        let snapshots: Vec<LayoutSnapshot> = layout_contents
            .lines()
            .map(|line| serde_json::from_str(line).expect("valid json"))
            .collect();
        assert!(!snapshots.is_empty(), "expected at least one snapshot");
        let snapshot = snapshots.last().unwrap();
        assert!(
            snapshot.exec.iter().any(|entry| entry == "/bin/echo"),
            "expected exec entry for /bin/echo"
        );
        assert!(
            snapshot
                .net
                .iter()
                .any(|rule| rule.addr == "127.0.0.1" && rule.port == 8080),
            "expected network rule for localhost"
        );
        assert!(
            snapshot
                .net_parents
                .iter()
                .any(|p| p.child == 1 && p.parent == 0),
            "expected net parent relationship"
        );
        assert!(
            snapshot
                .fs
                .iter()
                .any(|rule| rule.path == "/tmp/logs" && rule.write),
            "expected write rule for /tmp/logs"
        );
        assert!(
            snapshot
                .fs
                .iter()
                .any(|rule| { rule.path == "/etc/ssl/certs" && rule.read && !rule.write }),
            "expected read-only rule for /etc/ssl/certs"
        );

        let events_contents = fs::read_to_string(&events_path)?;
        assert!(
            events_contents
                .lines()
                .any(|line| line.contains("\"fake\":true")),
            "expected fake event entry"
        );
        assert!(
            !fake_dir.exists(),
            "fake cgroup directory should be removed"
        );
        Ok(())
    }
}
