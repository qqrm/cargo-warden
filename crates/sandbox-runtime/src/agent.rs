use anyhow::Error as AnyhowError;
use aya::maps::{MapData, ring_buf::RingBuf};
use std::io;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;
use warden_agent_lite::{self, Config as AgentConfig, Shutdown, ShutdownHandle};

pub(crate) struct AgentHandle {
    shutdown: ShutdownHandle,
    thread: Option<thread::JoinHandle<Result<(), AnyhowError>>>,
}

impl AgentHandle {
    pub(crate) fn stop(mut self) -> io::Result<()> {
        self.shutdown.request();
        if let Some(handle) = self.thread.take() {
            match handle.join() {
                Ok(result) => result.map_err(|err| io::Error::other(err.to_string())),
                Err(err) => Err(io::Error::other(format!("agent thread panicked: {err:?}"))),
            }
        } else {
            Ok(())
        }
    }
}

impl Drop for AgentHandle {
    fn drop(&mut self) {
        if let Some(handle) = self.thread.take() {
            self.shutdown.request();
            let _ = handle.join();
        }
    }
}

pub(crate) fn start_agent(
    ring: RingBuf<MapData>,
    events_path: PathBuf,
    config: AgentConfig,
) -> io::Result<AgentHandle> {
    let (shutdown, signal) = Shutdown::new(Duration::from_millis(100));
    let thread = thread::Builder::new()
        .name("warden-agent-lite".into())
        .spawn(move || warden_agent_lite::run_with_shutdown(ring, &events_path, config, signal))
        .map_err(|err| io::Error::other(format!("failed to spawn agent thread: {err}")))?;
    Ok(AgentHandle {
        shutdown,
        thread: Some(thread),
    })
}
