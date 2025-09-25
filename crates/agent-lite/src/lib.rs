use aya::maps::{MapData, ring_buf::RingBuf};
use bpf_api::{Event, UNIT_BUILD_SCRIPT, UNIT_LINKER, UNIT_OTHER, UNIT_PROC_MACRO, UNIT_RUSTC};
use cfg_if::cfg_if;
use log::{info, warn};
use prometheus::{Encoder, IntCounter, IntGaugeVec, Registry, TextEncoder};
use std::convert::TryFrom;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use std::collections::HashMap;

#[cfg(feature = "grpc")]
use tokio::sync::broadcast;

pub use event_reporting::{
    EventRecord, METRICS_SNAPSHOT_FILE, MetricsSnapshot, UnitMetricsSnapshot, export_sarif,
    sarif_from_events,
};

const ACTION_EXEC: u8 = 3;
const ACTION_CONNECT: u8 = 4;
const VERDICT_DENIED: u8 = 1;

static REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::new);
static EVENT_COUNTER: LazyLock<IntCounter> = LazyLock::new(|| {
    let c = IntCounter::new("warden_events_total", "Total number of events processed").unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});
static DENIED_COUNTER: LazyLock<IntCounter> = LazyLock::new(|| {
    let c = IntCounter::new(
        "warden_denied_events_total",
        "Total number of denied events",
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});
static VIOLATIONS_COUNTER: LazyLock<IntCounter> = LazyLock::new(|| {
    let c = IntCounter::new(
        "violations_total",
        "Total number of policy violations observed",
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});
static BLOCKED_COUNTER: LazyLock<IntCounter> = LazyLock::new(|| {
    let c = IntCounter::new(
        "blocked_total",
        "Total number of operations blocked by enforcement",
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});
static ALLOWED_COUNTER: LazyLock<IntCounter> = LazyLock::new(|| {
    let c = IntCounter::new("allowed_total", "Total number of operations allowed").unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});
static IO_READ_GAUGE: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    let g = IntGaugeVec::new(
        prometheus::Opts::new(
            "io_read_bytes_by_unit",
            "Cumulative read IO usage in bytes grouped by unit",
        ),
        &["unit"],
    )
    .unwrap();
    REGISTRY.register(Box::new(g.clone())).unwrap();
    g
});
static IO_WRITE_GAUGE: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    let g = IntGaugeVec::new(
        prometheus::Opts::new(
            "io_write_bytes_by_unit",
            "Cumulative write IO usage in bytes grouped by unit",
        ),
        &["unit"],
    )
    .unwrap();
    REGISTRY.register(Box::new(g.clone())).unwrap();
    g
});
static CPU_TIME_GAUGE: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    let g = IntGaugeVec::new(
        prometheus::Opts::new(
            "cpu_time_ms_by_unit",
            "CPU time spent in milliseconds grouped by unit",
        ),
        &["unit"],
    )
    .unwrap();
    REGISTRY.register(Box::new(g.clone())).unwrap();
    g
});
static PAGE_FAULTS_GAUGE: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    let g = IntGaugeVec::new(
        prometheus::Opts::new(
            "page_faults_by_unit",
            "Number of page faults grouped by unit",
        ),
        &["unit"],
    )
    .unwrap();
    REGISTRY.register(Box::new(g.clone())).unwrap();
    g
});

static UNIT_LABELS: LazyLock<Mutex<HashMap<u32, &'static str>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

static METRICS_RECORDER: LazyLock<Mutex<MetricsRecorder>> =
    LazyLock::new(|| Mutex::new(MetricsRecorder::default()));

#[derive(Default)]
struct MetricsRecorder {
    snapshot: MetricsSnapshot,
    path: Option<PathBuf>,
}

impl MetricsRecorder {
    fn configure_path(&mut self, events_path: &Path) -> io::Result<()> {
        let metrics_path = events_path.with_file_name(METRICS_SNAPSHOT_FILE);
        self.path = Some(metrics_path.clone());
        if metrics_path.exists() {
            let data = fs::read(&metrics_path)?;
            if !data.is_empty() {
                if let Ok(snapshot) = serde_json::from_slice::<MetricsSnapshot>(&data) {
                    self.snapshot = snapshot;
                } else {
                    self.snapshot = MetricsSnapshot::default();
                }
            } else {
                self.snapshot = MetricsSnapshot::default();
            }
        } else {
            self.snapshot = MetricsSnapshot::default();
            self.persist()?;
        }
        Ok(())
    }

    fn update_from_event(&mut self, record: &EventRecord) -> io::Result<()> {
        match record.verdict {
            VERDICT_DENIED => {
                self.snapshot.denied_total += 1;
                self.snapshot.violations_total += 1;
                self.snapshot.blocked_total += 1;
            }
            _ => {
                self.snapshot.allowed_total += 1;
            }
        }
        let unit_metrics = self
            .snapshot
            .per_unit
            .entry(u32::from(record.unit))
            .or_default();
        match record.verdict {
            VERDICT_DENIED => {
                unit_metrics.denied += 1;
            }
            _ => {
                unit_metrics.allowed += 1;
            }
        }
        self.persist()
    }

    fn update_resources(
        &mut self,
        unit: u32,
        read_bytes: u64,
        write_bytes: u64,
        cpu_time_ms: u64,
        page_faults: u64,
    ) -> io::Result<()> {
        let metrics = self.snapshot.per_unit.entry(unit).or_default();
        metrics.io_read_bytes = read_bytes;
        metrics.io_write_bytes = write_bytes;
        metrics.cpu_time_ms = cpu_time_ms;
        metrics.page_faults = page_faults;
        self.persist()
    }

    fn persist(&self) -> io::Result<()> {
        if let Some(path) = &self.path {
            let data = serde_json::to_vec_pretty(&self.snapshot).map_err(io::Error::other)?;
            fs::write(path, data)?;
        }
        Ok(())
    }

    #[cfg(test)]
    fn reset(&mut self) {
        self.snapshot = MetricsSnapshot::default();
        self.path = None;
    }
}

fn configure_metrics_storage(path: &Path) -> Result<(), anyhow::Error> {
    METRICS_RECORDER
        .lock()
        .expect("metrics recorder mutex poisoned")
        .configure_path(path)
        .map_err(anyhow::Error::from)
}

fn unit_label(unit: u32) -> &'static str {
    match unit {
        UNIT_OTHER => "other",
        UNIT_BUILD_SCRIPT => "build_script",
        UNIT_PROC_MACRO => "proc_macro",
        UNIT_RUSTC => "rustc",
        UNIT_LINKER => "linker",
        _ => {
            let mut labels = UNIT_LABELS.lock().expect("unit label mutex poisoned");
            if let Some(&label) = labels.get(&unit) {
                return label;
            }
            let leaked = Box::<str>::leak(unit.to_string().into_boxed_str());
            labels.insert(unit, leaked);
            leaked
        }
    }
}

fn saturating_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn record_event_metrics(record: &EventRecord) -> Result<(), anyhow::Error> {
    EVENT_COUNTER.inc();
    if record.verdict == VERDICT_DENIED {
        DENIED_COUNTER.inc();
        VIOLATIONS_COUNTER.inc();
        BLOCKED_COUNTER.inc();
    } else {
        ALLOWED_COUNTER.inc();
    }
    let mut recorder = METRICS_RECORDER
        .lock()
        .expect("metrics recorder mutex poisoned");
    recorder
        .update_from_event(record)
        .map_err(anyhow::Error::from)
}

pub fn update_unit_resource_metrics(
    unit: u32,
    read_bytes: u64,
    write_bytes: u64,
    cpu_time_ms: u64,
    page_faults: u64,
) {
    let unit_label = unit_label(unit);
    IO_READ_GAUGE
        .with_label_values(&[unit_label])
        .set(saturating_i64(read_bytes));
    IO_WRITE_GAUGE
        .with_label_values(&[unit_label])
        .set(saturating_i64(write_bytes));
    CPU_TIME_GAUGE
        .with_label_values(&[unit_label])
        .set(saturating_i64(cpu_time_ms));
    PAGE_FAULTS_GAUGE
        .with_label_values(&[unit_label])
        .set(saturating_i64(page_faults));
    if let Err(err) = METRICS_RECORDER
        .lock()
        .expect("metrics recorder mutex poisoned")
        .update_resources(unit, read_bytes, write_bytes, cpu_time_ms, page_faults)
    {
        warn!("failed to persist metrics snapshot: {err}");
    }
}

#[cfg(test)]
fn reset_all_metrics() {
    EVENT_COUNTER.reset();
    DENIED_COUNTER.reset();
    VIOLATIONS_COUNTER.reset();
    BLOCKED_COUNTER.reset();
    ALLOWED_COUNTER.reset();
    IO_READ_GAUGE.reset();
    IO_WRITE_GAUGE.reset();
    CPU_TIME_GAUGE.reset();
    PAGE_FAULTS_GAUGE.reset();
    UNIT_LABELS
        .lock()
        .expect("unit label mutex poisoned")
        .clear();
    METRICS_RECORDER
        .lock()
        .expect("metrics recorder mutex poisoned")
        .reset();
}

#[cfg(feature = "grpc")]
pub mod proto {
    tonic::include_proto!("agent");
}

#[cfg(feature = "grpc")]
type EventSender<'a> = &'a broadcast::Sender<EventRecord>;
#[cfg(not(feature = "grpc"))]
type EventSender<'a> = &'a ();

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
    pub metrics_port: Option<u16>,
}

/// Handle used to request shutdown of the agent loop.
#[derive(Clone, Debug)]
pub struct ShutdownHandle {
    flag: Arc<AtomicBool>,
}

impl ShutdownHandle {
    /// Signals the agent loop to stop at the next polling interval.
    pub fn request(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }
}

/// Shutdown configuration passed to [`run_with_shutdown`].
#[derive(Debug)]
pub struct Shutdown {
    flag: Arc<AtomicBool>,
    timeout_ms: i32,
    enabled: bool,
}

impl Shutdown {
    /// Creates a shutdown pair composed of a handle and loop configuration.
    pub fn new(timeout: Duration) -> (ShutdownHandle, Self) {
        let millis = timeout.as_millis().min(i32::MAX as u128) as i32;
        let flag = Arc::new(AtomicBool::new(false));
        let handle = ShutdownHandle { flag: flag.clone() };
        let shutdown = Shutdown {
            flag,
            timeout_ms: millis,
            enabled: true,
        };
        (handle, shutdown)
    }

    /// Returns a shutdown configuration that never stops the loop.
    pub fn disabled() -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
            timeout_ms: -1,
            enabled: false,
        }
    }

    fn is_requested(&self) -> bool {
        self.enabled && self.flag.load(Ordering::SeqCst)
    }

    fn poll_timeout(&self) -> i32 {
        if self.enabled { self.timeout_ms } else { -1 }
    }
}

fn event_record_from_event(e: Event) -> EventRecord {
    let end = e
        .path_or_addr
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(e.path_or_addr.len());
    let path_or_addr = String::from_utf8_lossy(&e.path_or_addr[..end]).to_string();
    let perm_end = e
        .needed_perm
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(e.needed_perm.len());
    let needed_perm = String::from_utf8_lossy(&e.needed_perm[..perm_end]).to_string();
    EventRecord {
        pid: e.pid,
        tgid: e.tgid,
        time_ns: e.time_ns,
        unit: e.unit,
        action: e.action,
        verdict: e.verdict,
        container_id: e.container_id,
        caps: e.caps,
        path_or_addr,
        needed_perm,
    }
}

fn diagnostic(record: &EventRecord) -> Option<String> {
    if record.verdict != VERDICT_DENIED {
        return None;
    }
    let hint = if record.needed_perm.is_empty() {
        String::new()
    } else {
        format!(" (hint: {})", record.needed_perm)
    };
    match record.action {
        ACTION_EXEC => Some(format!("Execution denied: {}{}", record.path_or_addr, hint)),
        ACTION_CONNECT => Some(format!("Network denied: {}{}", record.path_or_addr, hint)),
        _ => None,
    }
}

/// Polls a ring buffer map and streams logs to JSONL file and systemd journal.
pub fn run(ring: RingBuf<MapData>, jsonl: &Path, cfg: Config) -> Result<(), anyhow::Error> {
    run_with_shutdown(ring, jsonl, cfg, Shutdown::disabled())
}

/// Polls a ring buffer map until [`ShutdownHandle::request`] is invoked.
pub fn run_with_shutdown(
    mut ring: RingBuf<MapData>,
    jsonl: &Path,
    cfg: Config,
    shutdown: Shutdown,
) -> Result<(), anyhow::Error> {
    if let Ok(j) = systemd_journal_logger::JournalLog::new() {
        let _ = j.install();
    }
    let path = jsonl.to_path_buf();
    let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
    configure_metrics_storage(&path)?;
    if let Some(port) = cfg.metrics_port {
        start_metrics_server(port);
    }

    #[cfg(feature = "grpc")]
    let (tx, _) = broadcast::channel(64);
    #[cfg(feature = "grpc")]
    if let Some(port) = cfg.grpc_port {
        grpc::start(port, tx.clone());
    }

    loop {
        if shutdown.is_requested() {
            break;
        }
        let mut fds = [libc::pollfd {
            fd: ring.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        }];
        let ret = unsafe { libc::poll(fds.as_mut_ptr(), 1, shutdown.poll_timeout()) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if ret == 0 {
            continue;
        }
        while let Some(item) = ring.next() {
            if item.len() < core::mem::size_of::<Event>() {
                continue;
            }
            let event = unsafe { *(item.as_ptr() as *const Event) };
            let record = event_record_from_event(event);
            cfg_if! {
                if #[cfg(feature = "grpc")] {
                    write_outputs(
                        &record,
                        &mut file,
                        &path,
                        cfg.rotation.as_ref(),
                        Some(&tx),
                    )?;
                } else {
                    write_outputs(
                        &record,
                        &mut file,
                        &path,
                        cfg.rotation.as_ref(),
                        None,
                    )?;
                }
            }
        }
    }
    Ok(())
}

fn start_metrics_server(port: u16) {
    use std::io::Cursor;
    use tiny_http::{Header, Method, Response, Server, StatusCode};
    std::thread::spawn(move || {
        let server = Server::http(("0.0.0.0", port)).expect("start server");
        for req in server.incoming_requests() {
            if req.method() != &Method::Get || req.url() != "/metrics" {
                let _ = req.respond(Response::new_empty(StatusCode(404)));
                continue;
            }
            let metric_families = REGISTRY.gather();
            let mut buffer = Vec::new();
            let encoder = TextEncoder::new();
            if encoder.encode(&metric_families, &mut buffer).is_ok() {
                let len = buffer.len();
                let response = Response::new(
                    StatusCode(200),
                    vec![
                        Header::from_bytes("Content-Type", "text/plain; version=0.0.4").unwrap(),
                        Header::from_bytes("Cache-Control", "no-cache").unwrap(),
                    ],
                    Cursor::new(buffer),
                    Some(len),
                    None,
                );
                let _ = req.respond(response);
            } else {
                let response = Response::new_empty(StatusCode(500));
                let _ = req.respond(response);
            }
        }
    });
}

#[cfg_attr(not(feature = "grpc"), allow(unused_variables))]
fn write_outputs(
    record: &EventRecord,
    file: &mut File,
    path: &Path,
    rotation: Option<&RotationConfig>,
    tx: Option<EventSender<'_>>,
) -> Result<(), anyhow::Error> {
    let json = serde_json::to_string(record)?;
    writeln!(file, "{}", json)?;
    info!("{}", json);
    record_event_metrics(record)?;
    if let Some(cfg) = rotation {
        rotate_if_needed(file, path, cfg)?;
    }
    if let Some(msg) = diagnostic(record) {
        warn!("{}", msg);
    }
    #[cfg(feature = "grpc")]
    if let Some(sender) = tx {
        let _ = sender.send(record.clone());
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
                                    tgid: r.tgid,
                                    time_ns: r.time_ns,
                                    unit: r.unit as u32,
                                    action: r.action as u32,
                                    verdict: r.verdict as u32,
                                    container_id: r.container_id,
                                    caps: r.caps,
                                    path_or_addr: r.path_or_addr,
                                    needed_perm: r.needed_perm,
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
    use serial_test::serial;
    use std::{
        fs::{self, File},
        io::{Read, Seek, Write},
        net::{Shutdown, TcpListener, TcpStream},
        thread,
        time::Duration,
    };
    use tempfile::{NamedTempFile, tempdir};

    #[test]
    fn event_record_formats() {
        let mut path = [0u8; 256];
        path[..4].copy_from_slice(b"/bin");
        let mut needed = [0u8; 64];
        let suggestion = b"allow.fs.read_extra";
        needed[..suggestion.len()].copy_from_slice(suggestion);
        let event = Event {
            pid: 42,
            tgid: 24,
            time_ns: 123,
            unit: 1,
            action: 2,
            verdict: 0,
            reserved: 0,
            container_id: 7,
            caps: 1,
            path_or_addr: path,
            needed_perm: needed,
        };
        let record = event_record_from_event(event);
        assert_eq!(record.pid, 42);
        assert_eq!(record.tgid, 24);
        assert_eq!(record.time_ns, 123);
        assert_eq!(record.unit, 1);
        assert_eq!(record.action, 2);
        assert_eq!(record.verdict, 0);
        assert_eq!(record.container_id, 7);
        assert_eq!(record.caps, 1);
        assert_eq!(record.path_or_addr, "/bin");
        assert_eq!(record.needed_perm, "allow.fs.read_extra");
        let text = format!("{}", record);
        assert!(text.contains("pid=42"));
        assert!(text.contains("tgid=24"));
        assert!(text.contains("hint=allow.fs.read_extra"));
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"pid\":42"));
        assert!(json.contains("\"tgid\":24"));
    }

    #[test]
    fn diagnostics_for_denied_actions() {
        let exec = EventRecord {
            pid: 1,
            tgid: 11,
            time_ns: 1,
            unit: 0,
            action: ACTION_EXEC,
            verdict: VERDICT_DENIED,
            container_id: 0,
            caps: 0,
            path_or_addr: "/bin/bash".into(),
            needed_perm: "allow.exec.allowed".into(),
        };
        assert_eq!(
            diagnostic(&exec),
            Some("Execution denied: /bin/bash (hint: allow.exec.allowed)".to_string())
        );
        let net = EventRecord {
            pid: 1,
            tgid: 12,
            time_ns: 2,
            unit: 0,
            action: ACTION_CONNECT,
            verdict: VERDICT_DENIED,
            container_id: 0,
            caps: 0,
            path_or_addr: "1.2.3.4:80".into(),
            needed_perm: "allow.net.hosts".into(),
        };
        assert_eq!(
            diagnostic(&net),
            Some("Network denied: 1.2.3.4:80 (hint: allow.net.hosts)".to_string())
        );
        let allow = EventRecord {
            pid: 1,
            tgid: 13,
            time_ns: 3,
            unit: 0,
            action: ACTION_EXEC,
            verdict: 0,
            container_id: 0,
            caps: 0,
            path_or_addr: "/bin/bash".into(),
            needed_perm: String::new(),
        };
        assert!(diagnostic(&allow).is_none());
    }

    #[test]
    #[serial]
    fn writes_jsonl_line() {
        let record = EventRecord {
            pid: 1,
            tgid: 21,
            time_ns: 10,
            unit: 0,
            action: ACTION_EXEC,
            verdict: 0,
            container_id: 0,
            caps: 0,
            path_or_addr: "/bin/echo".into(),
            needed_perm: String::new(),
        };
        let mut tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        cfg_if! {
            if #[cfg(feature = "grpc")] {
                use tokio::sync::broadcast;
                let (tx, _) = broadcast::channel(1);
                write_outputs(&record, tmp.as_file_mut(), &path, None, Some(&tx)).unwrap();
            } else {
                write_outputs(&record, tmp.as_file_mut(), &path, None, None).unwrap();
            }
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
            tgid: 22,
            time_ns: 20,
            unit: 0,
            action: ACTION_EXEC,
            verdict: VERDICT_DENIED,
            container_id: 0,
            caps: 0,
            path_or_addr: "/bin/bad".into(),
            needed_perm: "allow.exec.allowed".into(),
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

    #[test]
    #[serial]
    fn metrics_count_events() {
        reset_all_metrics();
        let record = EventRecord {
            pid: 3,
            tgid: 23,
            time_ns: 30,
            unit: 0,
            action: ACTION_EXEC,
            verdict: VERDICT_DENIED,
            container_id: 0,
            caps: 0,
            path_or_addr: "/bin/deny".into(),
            needed_perm: "allow.exec.allowed".into(),
        };
        let mut tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        cfg_if! {
            if #[cfg(feature = "grpc")] {
                use tokio::sync::broadcast;
                let (tx, _) = broadcast::channel(1);
                write_outputs(&record, tmp.as_file_mut(), &path, None, Some(&tx)).unwrap();
            } else {
                write_outputs(&record, tmp.as_file_mut(), &path, None, None).unwrap();
            }
        }
        assert_eq!(EVENT_COUNTER.get(), 1);
        assert_eq!(DENIED_COUNTER.get(), 1);
        assert_eq!(VIOLATIONS_COUNTER.get(), 1);
        assert_eq!(BLOCKED_COUNTER.get(), 1);
        assert_eq!(ALLOWED_COUNTER.get(), 0);
    }

    #[test]
    #[serial]
    fn metrics_http_endpoint_exposes_series() {
        reset_all_metrics();
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind listener");
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        start_metrics_server(port);
        thread::sleep(Duration::from_millis(50));

        let mut tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();

        let denied_record = EventRecord {
            pid: 10,
            tgid: 110,
            time_ns: 40,
            unit: 1,
            action: ACTION_EXEC,
            verdict: VERDICT_DENIED,
            container_id: 0,
            caps: 0,
            path_or_addr: "/bin/deny".into(),
            needed_perm: "allow.exec.allowed".into(),
        };
        write_outputs(&denied_record, tmp.as_file_mut(), &path, None, None).unwrap();

        let allowed_record = EventRecord {
            pid: 11,
            tgid: 111,
            time_ns: 41,
            unit: 1,
            action: ACTION_EXEC,
            verdict: 0,
            container_id: 0,
            caps: 0,
            path_or_addr: "/bin/allow".into(),
            needed_perm: String::new(),
        };
        write_outputs(&allowed_record, tmp.as_file_mut(), &path, None, None).unwrap();

        update_unit_resource_metrics(1, 1024, 2048, 500, 7);
        update_unit_resource_metrics(99, 1, 2, 3, 4);

        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect metrics");
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();

        let body = response
            .split_once("\r\n\r\n")
            .map(|(_, b)| b)
            .unwrap_or(&response);
        assert!(body.contains("violations_total 1"));
        assert!(body.contains("blocked_total 1"));
        assert!(body.contains("allowed_total 1"));
        assert!(body.contains("io_read_bytes_by_unit{unit=\"build_script\"} 1024"));
        assert!(body.contains("io_write_bytes_by_unit{unit=\"build_script\"} 2048"));
        assert!(body.contains("cpu_time_ms_by_unit{unit=\"build_script\"} 500"));
        assert!(body.contains("page_faults_by_unit{unit=\"build_script\"} 7"));
        assert!(body.contains("io_read_bytes_by_unit{unit=\"99\"} 1"));
    }

    #[test]
    #[serial]
    fn metrics_snapshot_persisted() {
        reset_all_metrics();
        let dir = tempdir().unwrap();
        let events_path = dir.path().join("warden-events.jsonl");
        File::create(&events_path).unwrap();
        configure_metrics_storage(&events_path).unwrap();

        let record = EventRecord {
            pid: 20,
            tgid: 200,
            time_ns: 123,
            unit: 0,
            action: ACTION_EXEC,
            verdict: VERDICT_DENIED,
            container_id: 0,
            caps: 0,
            path_or_addr: "/bin/deny".into(),
            needed_perm: "allow.exec.allowed".into(),
        };
        record_event_metrics(&record).unwrap();
        update_unit_resource_metrics(0, 4096, 2048, 100, 6);

        let metrics_path = events_path.with_file_name(METRICS_SNAPSHOT_FILE);
        let contents = fs::read_to_string(metrics_path).unwrap();
        let snapshot: MetricsSnapshot = serde_json::from_str(&contents).unwrap();
        let unit_metrics = snapshot.per_unit.get(&0).unwrap();
        assert_eq!(snapshot.denied_total, 1);
        assert_eq!(snapshot.blocked_total, 1);
        assert_eq!(unit_metrics.denied, 1);
        assert_eq!(unit_metrics.io_write_bytes, 2048);
        assert_eq!(unit_metrics.page_faults, 6);
        reset_all_metrics();
    }
}
