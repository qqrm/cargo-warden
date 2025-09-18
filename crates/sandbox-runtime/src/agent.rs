use anyhow::Error as AnyhowError;
use aya::maps::{MapData, ring_buf::RingBuf};
use qqrm_agent_lite::{self, Config as AgentConfig, Shutdown, ShutdownHandle};
use std::io;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

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

pub(crate) fn start_agent(ring: RingBuf<MapData>, events_path: PathBuf) -> io::Result<AgentHandle> {
    let cfg = AgentConfig::default();
    let (shutdown, signal) = Shutdown::new(Duration::from_millis(100));
    let thread = thread::Builder::new()
        .name("qqrm-agent-lite".into())
        .spawn(move || qqrm_agent_lite::run_with_shutdown(ring, &events_path, cfg, signal))
        .map_err(|err| io::Error::other(format!("failed to spawn agent thread: {err}")))?;
    Ok(AgentHandle {
        shutdown,
        thread: Some(thread),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    #[serial]
    fn stop_waits_for_thread_completion() {
        let (shutdown, _) = Shutdown::new(Duration::from_millis(10));
        let completed = Arc::new(AtomicBool::new(false));
        let flag = completed.clone();
        let thread = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            flag.store(true, Ordering::SeqCst);
            Ok(())
        });
        let handle = AgentHandle {
            shutdown,
            thread: Some(thread),
        };
        let start = std::time::Instant::now();
        handle.stop().expect("stop should succeed");
        assert!(completed.load(Ordering::SeqCst), "thread should finish");
        assert!(
            start.elapsed() >= Duration::from_millis(50),
            "stop should wait for the thread"
        );
    }

    #[test]
    #[serial]
    fn stop_propagates_thread_error() {
        let (shutdown, _) = Shutdown::new(Duration::from_millis(10));
        let thread = thread::spawn(|| Err(AnyhowError::msg("boom")));
        let handle = AgentHandle {
            shutdown,
            thread: Some(thread),
        };
        let err = handle.stop().expect_err("expected error");
        assert!(
            err.to_string().contains("boom"),
            "error should mention the thread failure"
        );
    }
}
