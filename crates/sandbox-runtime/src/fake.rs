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
    use serial_test::serial;
    use std::env;
    use std::fs;
    use tempfile::tempdir;

    fn layout() -> MapsLayout {
        use bpf_api::{
            ExecAllowEntry, FS_READ, FS_WRITE, FsRule, FsRuleEntry, NetParentEntry, NetRule,
            NetRuleEntry,
        };

        let mut exec_path = [0u8; 256];
        exec_path[..10].copy_from_slice(b"/bin/echo\0");

        let net_rule = NetRuleEntry {
            unit: 7,
            rule: NetRule {
                addr: {
                    let mut addr = [0u8; 16];
                    addr[..4].copy_from_slice(&[127, 0, 0, 1]);
                    addr
                },
                protocol: 6,
                prefix_len: 32,
                port: 8080,
            },
        };

        let parent = NetParentEntry {
            child: 7,
            parent: 1,
        };

        let mut fs_path = [0u8; 256];
        fs_path[..9].copy_from_slice(b"/tmp/log\0");
        let fs_rule = FsRuleEntry {
            unit: 2,
            rule: FsRule {
                access: FS_READ | FS_WRITE,
                reserved: [0; 3],
                path: fs_path,
            },
        };

        MapsLayout {
            exec_allowlist: vec![ExecAllowEntry { path: exec_path }],
            net_rules: vec![net_rule],
            net_parents: vec![parent],
            fs_rules: vec![fs_rule],
        }
    }

    struct EnvGuard {
        previous: Vec<(&'static str, Option<std::ffi::OsString>)>,
    }

    impl EnvGuard {
        fn new() -> Self {
            Self {
                previous: Vec::new(),
            }
        }

        fn set(&mut self, key: &'static str, value: &std::path::Path) {
            let original = env::var_os(key);
            unsafe { env::set_var(key, value) };
            self.previous.push((key, original));
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, value) in self.previous.drain(..) {
                if let Some(val) = value {
                    unsafe { env::set_var(key, val) };
                } else {
                    unsafe { env::remove_var(key) };
                }
            }
        }
    }

    #[test]
    #[serial]
    fn fake_sandbox_records_layout_and_events() -> io::Result<()> {
        let temp = tempdir()?;
        let events_path = temp.path().join("events.jsonl");
        let layout_path = temp.path().join("layout.jsonl");
        let cgroup_dir = temp.path().join("fake-cgroup");

        let mut guard = EnvGuard::new();
        guard.set(EVENTS_PATH_ENV, &events_path);
        guard.set(FAKE_CGROUP_DIR_ENV, &cgroup_dir);
        guard.set(FAKE_LAYOUT_ENV, &layout_path);

        let mut sandbox = FakeSandbox::new()?;
        let recorded_dir = sandbox.cgroup_dir.clone();
        let layout = layout();

        let mut command = Command::new("sh");
        command.arg("-c").arg(":");
        let status = sandbox
            .run(command, &layout)
            .expect("command should execute");
        assert!(status.success());

        sandbox.shutdown()?;

        let contents = fs::read_to_string(&layout_path)?;
        let snapshots: Vec<LayoutSnapshot> = contents
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?;
        assert_eq!(snapshots.len(), 1, "expected single layout snapshot");
        let snapshot = &snapshots[0];
        assert!(snapshot.exec.iter().any(|p| p == "/bin/echo"));
        assert!(
            snapshot
                .net
                .iter()
                .any(|rule| rule.addr == "127.0.0.1" && rule.port == 8080)
        );
        assert!(snapshot.net_parents.iter().any(|rel| rel.child == 7));
        assert!(
            snapshot
                .fs
                .iter()
                .any(|rule| rule.path == "/tmp/log" && rule.write)
        );

        let events = fs::read_to_string(&events_path)?;
        assert!(events.contains("\"fake\":true"));
        assert!(
            !recorded_dir.exists(),
            "fake cgroup directory should be removed"
        );

        Ok(())
    }
}
