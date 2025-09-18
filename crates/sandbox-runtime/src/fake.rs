use crate::layout::LayoutRecorder;
use crate::util::{events_path, fake_cgroup_dir};
use event_reporting::EventRecord;
use policy_core::Mode;
use qqrm_policy_compiler::MapsLayout;
use std::env;
use std::fs::{self, OpenOptions};
use std::io;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, ExitStatus};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

const FAKE_DENIED_PATH_ENV: &str = "QQRM_WARDEN_FAKE_DENIED_PATH";

pub(crate) struct FakeSandbox {
    cgroup_dir: PathBuf,
    agent: Option<FakeAgent>,
    layout_recorder: Option<LayoutRecorder>,
    events_path: PathBuf,
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
        let agent = FakeAgent::spawn(events.clone())?;
        let layout_recorder = LayoutRecorder::from_env()?;
        Ok(Self {
            cgroup_dir,
            agent: Some(agent),
            layout_recorder,
            events_path: events,
        })
    }

    pub(crate) fn run(
        &mut self,
        mut command: Command,
        _mode: Mode,
        layout: &MapsLayout,
    ) -> io::Result<ExitStatus> {
        if let Some(recorder) = &mut self.layout_recorder {
            recorder.record(layout)?;
        }
        let status = command.status()?;
        if let Some(path) = env::var_os(FAKE_DENIED_PATH_ENV) {
            let path = path.to_string_lossy();
            self.record_fake_event(&path)?;
        }
        Ok(status)
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

impl FakeSandbox {
    fn record_fake_event(&self, path: &str) -> io::Result<()> {
        let event = EventRecord {
            pid: 0,
            unit: 0,
            action: 0,
            verdict: 1,
            container_id: 0,
            caps: 0,
            path_or_addr: path.into(),
        };
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.events_path)?;
        serde_json::to_writer(&mut file, &event).map_err(io::Error::other)?;
        file.write_all(b"\n")?;
        file.flush()?;
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
