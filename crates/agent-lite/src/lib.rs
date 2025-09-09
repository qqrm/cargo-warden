use aya::maps::{MapData, ring_buf::RingBuf};
use bpf_api::Event;
use log::{info, warn};
use serde::Serialize;
use serde_json::json;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

#[cfg(feature = "grpc")]
use tokio::sync::broadcast;

const ACTION_EXEC: u8 = 3;
const ACTION_CONNECT: u8 = 4;
const VERDICT_DENIED: u8 = 1;

#[cfg(feature = "grpc")]
pub mod proto {
    tonic::include_proto!("agent");
}

/// User-facing representation of an event.
#[derive(Debug, Serialize, Clone)]
pub struct EventRecord {
    pub pid: u32,
    pub unit: u8,
    pub action: u8,
    pub verdict: u8,
    pub container_id: u64,
    pub caps: u64,
    pub path_or_addr: String,
}

/// Log rotation settings.
#[derive(Debug, Clone)]
pub struct RotationConfig {
    pub max_bytes: u64,
    pub retain: usize,
}

/// Agent runtime configuration.
#[derive(Debug, Default, Clone)]
pub struct Config {
    pub rotation: Option<RotationConfig>,
    #[cfg(feature = "grpc")]
    pub grpc_port: Option<u16>,
}

impl From<Event> for EventRecord {
    fn from(e: Event) -> Self {
        let end = e
            .path_or_addr
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(e.path_or_addr.len());
        let path_or_addr = String::from_utf8_lossy(&e.path_or_addr[..end]).to_string();
        Self {
            pid: e.pid,
            unit: e.unit,
            action: e.action,
            verdict: e.verdict,
            container_id: e.container_id,
            caps: e.caps,
            path_or_addr,
        }
    }
}

impl std::fmt::Display for EventRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "pid={} unit={} action={} verdict={} container_id={} caps={} path_or_addr={}",
            self.pid,
            self.unit,
            self.action,
            self.verdict,
            self.container_id,
            self.caps,
            self.path_or_addr
        )
    }
}

fn diagnostic(record: &EventRecord) -> Option<String> {
    if record.verdict != VERDICT_DENIED {
        return None;
    }
    match record.action {
        ACTION_EXEC => Some(format!("Execution denied: {}", record.path_or_addr)),
        ACTION_CONNECT => Some(format!("Network denied: {}", record.path_or_addr)),
        _ => None,
    }
}

/// Builds a SARIF log from a slice of events.
pub fn sarif_from_events(events: &[EventRecord]) -> serde_json::Value {
    let results: Vec<_> = events
        .iter()
        .map(|e| {
            json!({
                "ruleId": e.action.to_string(),
                "level": if e.verdict == VERDICT_DENIED { "error" } else { "note" },
                "message": { "text": format!("{}", e) },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": e.path_or_addr }
                    }
                }]
            })
        })
        .collect();
    json!({
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": { "name": "cargo-warden" } },
            "results": results
        }]
    })
}

/// Writes a SARIF log to the given path.
pub fn export_sarif(events: &[EventRecord], path: &Path) -> Result<(), anyhow::Error> {
    let sarif = sarif_from_events(events);
    std::fs::write(path, serde_json::to_string_pretty(&sarif)?)?;
    Ok(())
}

/// Polls a ring buffer map and streams logs to JSONL file and systemd journal.
pub fn run(mut ring: RingBuf<MapData>, jsonl: &Path, cfg: Config) -> Result<(), anyhow::Error> {
    if let Ok(j) = systemd_journal_logger::JournalLog::new() {
        let _ = j.install();
    }
    let path = jsonl.to_path_buf();
    let mut file = OpenOptions::new().create(true).append(true).open(&path)?;

    #[cfg(feature = "grpc")]
    let (tx, _) = broadcast::channel(64);
    #[cfg(feature = "grpc")]
    if let Some(port) = cfg.grpc_port {
        grpc::start(port, tx.clone());
    }

    loop {
        let mut fds = [libc::pollfd {
            fd: ring.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        }];
        let ret = unsafe { libc::poll(fds.as_mut_ptr(), 1, -1) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        while let Some(item) = ring.next() {
            if item.len() < core::mem::size_of::<Event>() {
                continue;
            }
            let event = unsafe { *(item.as_ptr() as *const Event) };
            let record: EventRecord = event.into();
            #[cfg(feature = "grpc")]
            {
                write_outputs(&record, &mut file, &path, cfg.rotation.as_ref(), Some(&tx))?;
            }
            #[cfg(not(feature = "grpc"))]
            {
                write_outputs(&record, &mut file, &path, cfg.rotation.as_ref())?;
            }
        }
    }
}

#[cfg(feature = "grpc")]
fn write_outputs(
    record: &EventRecord,
    file: &mut File,
    path: &Path,
    rotation: Option<&RotationConfig>,
    tx: Option<&broadcast::Sender<EventRecord>>,
) -> Result<(), anyhow::Error> {
    let json = serde_json::to_string(record)?;
    writeln!(file, "{}", json)?;
    info!("{}", json);
    if let Some(cfg) = rotation {
        rotate_if_needed(file, path, cfg)?;
    }
    if let Some(msg) = diagnostic(record) {
        warn!("{}", msg);
    }
    if let Some(sender) = tx {
        let _ = sender.send(record.clone());
    }
    Ok(())
}

#[cfg(not(feature = "grpc"))]
fn write_outputs(
    record: &EventRecord,
    file: &mut File,
    path: &Path,
    rotation: Option<&RotationConfig>,
) -> Result<(), anyhow::Error> {
    let json = serde_json::to_string(record)?;
    writeln!(file, "{}", json)?;
    info!("{}", json);
    if let Some(cfg) = rotation {
        rotate_if_needed(file, path, cfg)?;
    }
    if let Some(msg) = diagnostic(record) {
        warn!("{}", msg);
    }
    Ok(())
}

fn rotate_if_needed(
    file: &mut File,
    path: &Path,
    cfg: &RotationConfig,
) -> Result<(), anyhow::Error> {
    file.flush()?;
    if file.metadata()?.len() <= cfg.max_bytes {
        return Ok(());
    }
    rotate_files(path, cfg.retain)?;
    *file = OpenOptions::new().create(true).append(true).open(path)?;
    Ok(())
}

fn rotate_files(base: &Path, retain: usize) -> Result<(), anyhow::Error> {
    let last = rotated_path(base, retain);
    if last.exists() {
        std::fs::remove_file(&last)?;
    }
    for i in (1..retain).rev() {
        let from = rotated_path(base, i);
        if from.exists() {
            let to = rotated_path(base, i + 1);
            std::fs::rename(from, to)?;
        }
    }
    std::fs::rename(base, rotated_path(base, 1))?;
    Ok(())
}

fn rotated_path(base: &Path, index: usize) -> PathBuf {
    PathBuf::from(format!("{}.{index}", base.display()))
}

#[cfg(feature = "grpc")]
mod grpc {
    use super::*;
    use futures_core::Stream;
    use futures_util::StreamExt;
    use std::pin::Pin;
    use std::thread;
    use tokio::sync::broadcast;
    use tokio_stream::wrappers::BroadcastStream;
    use tonic::{Request, Response, Status, transport::Server};

    pub fn start(port: u16, tx: broadcast::Sender<EventRecord>) {
        thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("runtime");
            rt.block_on(async move {
                struct S {
                    tx: broadcast::Sender<EventRecord>,
                }

                #[tonic::async_trait]
                impl proto::agent_server::Agent for S {
                    type WatchEventsStream =
                        Pin<Box<dyn Stream<Item = Result<proto::EventRecord, Status>> + Send>>;

                    async fn watch_events(
                        &self,
                        _req: Request<proto::Empty>,
                    ) -> Result<Response<Self::WatchEventsStream>, Status> {
                        let rx = self.tx.subscribe();
                        let stream = BroadcastStream::new(rx)
                            .filter_map(|e| async move { e.ok() })
                            .map(|r| {
                                Ok(proto::EventRecord {
                                    pid: r.pid,
                                    unit: r.unit as u32,
                                    action: r.action as u32,
                                    verdict: r.verdict as u32,
                                    container_id: r.container_id,
                                    caps: r.caps,
                                    path_or_addr: r.path_or_addr,
                                })
                            });
                        Ok(Response::new(Box::pin(stream)))
                    }
                }

                let addr = ([0, 0, 0, 0], port).into();
                let svc = S { tx };
                if let Err(e) = Server::builder()
                    .add_service(proto::agent_server::AgentServer::new(svc))
                    .serve(addr)
                    .await
                {
                    eprintln!("gRPC server error: {e}");
                }
            });
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::File,
        io::{Read, Seek},
    };
    use tempfile::NamedTempFile;

    #[test]
    fn event_record_formats() {
        let mut path = [0u8; 256];
        path[..4].copy_from_slice(b"/bin");
        let event = Event {
            pid: 42,
            unit: 1,
            action: 2,
            verdict: 0,
            reserved: 0,
            container_id: 7,
            caps: 1,
            path_or_addr: path,
        };
        let record: EventRecord = event.into();
        assert_eq!(record.pid, 42);
        assert_eq!(record.unit, 1);
        assert_eq!(record.action, 2);
        assert_eq!(record.verdict, 0);
        assert_eq!(record.container_id, 7);
        assert_eq!(record.caps, 1);
        assert_eq!(record.path_or_addr, "/bin");
        let text = format!("{}", record);
        assert!(text.contains("pid=42"));
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"pid\":42"));
    }

    #[test]
    fn diagnostics_for_denied_actions() {
        let exec = EventRecord {
            pid: 1,
            unit: 0,
            action: ACTION_EXEC,
            verdict: VERDICT_DENIED,
            container_id: 0,
            caps: 0,
            path_or_addr: "/bin/bash".into(),
        };
        assert_eq!(
            diagnostic(&exec),
            Some("Execution denied: /bin/bash".to_string())
        );
        let net = EventRecord {
            pid: 1,
            unit: 0,
            action: ACTION_CONNECT,
            verdict: VERDICT_DENIED,
            container_id: 0,
            caps: 0,
            path_or_addr: "1.2.3.4:80".into(),
        };
        assert_eq!(
            diagnostic(&net),
            Some("Network denied: 1.2.3.4:80".to_string())
        );
        let allow = EventRecord {
            pid: 1,
            unit: 0,
            action: ACTION_EXEC,
            verdict: 0,
            container_id: 0,
            caps: 0,
            path_or_addr: "/bin/bash".into(),
        };
        assert!(diagnostic(&allow).is_none());
    }

    #[test]
    fn writes_jsonl_line() {
        let record = EventRecord {
            pid: 1,
            unit: 0,
            action: ACTION_EXEC,
            verdict: 0,
            container_id: 0,
            caps: 0,
            path_or_addr: "/bin/echo".into(),
        };
        let mut tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        #[cfg(feature = "grpc")]
        {
            use tokio::sync::broadcast;
            let (tx, _) = broadcast::channel(1);
            write_outputs(&record, tmp.as_file_mut(), &path, None, Some(&tx)).unwrap();
        }
        #[cfg(not(feature = "grpc"))]
        {
            write_outputs(&record, tmp.as_file_mut(), &path, None).unwrap();
        }
        tmp.as_file_mut().rewind().unwrap();
        let mut content = String::new();
        tmp.as_file_mut().read_to_string(&mut content).unwrap();
        assert!(content.contains("\"pid\":1"));
    }

    #[test]
    fn exports_sarif_file() {
        let record = EventRecord {
            pid: 2,
            unit: 0,
            action: ACTION_EXEC,
            verdict: VERDICT_DENIED,
            container_id: 0,
            caps: 0,
            path_or_addr: "/bin/bad".into(),
        };
        let tmp = NamedTempFile::new().unwrap();
        export_sarif(std::slice::from_ref(&record), tmp.path()).unwrap();
        let mut content = String::new();
        File::open(tmp.path())
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();
        assert!(content.contains("\"version\": \"2.1.0\""));
        assert!(content.contains(&record.path_or_addr));
    }
}
