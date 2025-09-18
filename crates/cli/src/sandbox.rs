use crate::apply_seccomp;
use anyhow::Error as AnyhowError;
use aya::maps::{Array, MapData, ring_buf::RingBuf};
use aya::programs::cgroup_sock_addr::CgroupSockAddrLink;
use aya::programs::lsm::LsmLink;
use aya::programs::{CgroupAttachMode, CgroupSockAddr, Lsm};
use aya::{Btf, Ebpf, EbpfLoader, Pod};
use bpf_api::{ExecAllowEntry, FsRuleEntry, NetParentEntry, NetRule, NetRuleEntry};
use qqrm_agent_lite::{self, Config as AgentConfig, Shutdown, ShutdownHandle};
use qqrm_policy_compiler::MapsLayout;
use serde::Serialize;
use std::cell::UnsafeCell;
use std::convert::TryFrom;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{self, Command, ExitStatus};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Wrapper responsible for BPF setup, agent management and cleanup.
pub(crate) struct Sandbox {
    inner: SandboxImpl,
}

enum SandboxImpl {
    Real(RealSandbox),
    Fake(FakeSandbox),
}

impl Sandbox {
    pub(crate) fn new() -> io::Result<Self> {
        if env::var_os("QQRM_WARDEN_FAKE_SANDBOX").is_some() {
            return Ok(Self {
                inner: SandboxImpl::Fake(FakeSandbox::new()?),
            });
        }
        Ok(Self {
            inner: SandboxImpl::Real(RealSandbox::new()?),
        })
    }

    pub(crate) fn run(
        &mut self,
        command: Command,
        deny: &[String],
        layout: &MapsLayout,
    ) -> io::Result<ExitStatus> {
        match &mut self.inner {
            SandboxImpl::Real(real) => real.run(command, deny, layout),
            SandboxImpl::Fake(fake) => fake.run(command, layout),
        }
    }

    pub(crate) fn shutdown(self) -> io::Result<()> {
        match self.inner {
            SandboxImpl::Real(real) => real.shutdown(),
            SandboxImpl::Fake(fake) => fake.shutdown(),
        }
    }
}

struct RealSandbox {
    bpf: UnsafeCell<Ebpf>,
    cgroup: Cgroup,
    lsm_links: Vec<LsmLink>,
    cgroup_links: Vec<CgroupSockAddrLink>,
    agent: Option<AgentHandle>,
    events_path: PathBuf,
}

impl RealSandbox {
    fn new() -> io::Result<Self> {
        let events_path = events_path();
        if let Some(parent) = events_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let bpf = load_bpf()?;
        let cgroup = Cgroup::create()?;
        let mut sandbox = RealSandbox {
            bpf: UnsafeCell::new(bpf),
            cgroup,
            lsm_links: Vec::new(),
            cgroup_links: Vec::new(),
            agent: None,
            events_path,
        };
        sandbox.attach_lsm()?;
        sandbox.attach_cgroup()?;
        let ring = sandbox.with_bpf(take_events_ring)?;
        sandbox.agent = Some(start_agent(ring, sandbox.events_path.clone())?);
        Ok(sandbox)
    }

    fn with_bpf<R>(&self, func: impl FnOnce(&mut Ebpf) -> io::Result<R>) -> io::Result<R> {
        let ptr = self.bpf.get();
        // SAFETY: `RealSandbox` ensures exclusive access to the underlying `Ebpf`
        // instance. We only call this helper on the main thread or in the pre-exec
        // hook after `fork`, so no concurrent mutable borrows occur.
        unsafe { func(&mut *ptr) }
    }

    fn attach_lsm(&mut self) -> io::Result<()> {
        let btf = Btf::from_sys_fs().map_err(io::Error::other)?;
        let mut links = Vec::new();
        self.with_bpf(|bpf| {
            for hook in [
                "bprm_check_security",
                "file_open",
                "file_permission",
                "inode_unlink",
            ] {
                let program = bpf
                    .program_mut(hook)
                    .ok_or_else(|| program_not_found(hook))?;
                let program: &mut Lsm = program.try_into().map_err(|err| {
                    io::Error::other(format!("program {hook} type mismatch: {err}"))
                })?;
                program
                    .load(hook, &btf)
                    .map_err(|err| io::Error::other(format!("load {hook}: {err}")))?;
                let link_id = program
                    .attach()
                    .map_err(|err| io::Error::other(format!("attach {hook}: {err}")))?;
                let link = program
                    .take_link(link_id)
                    .map_err(|err| io::Error::other(format!("link {hook}: {err}")))?;
                links.push(link);
            }
            Ok(())
        })?;
        self.lsm_links.extend(links);
        Ok(())
    }

    fn attach_cgroup(&mut self) -> io::Result<()> {
        let dir = self.cgroup.dir_file()?;
        let mut links = Vec::new();
        self.with_bpf(|bpf| {
            for name in ["connect4", "connect6", "sendmsg4", "sendmsg6"] {
                let program = bpf
                    .program_mut(name)
                    .ok_or_else(|| program_not_found(name))?;
                let program: &mut CgroupSockAddr = program.try_into().map_err(|err| {
                    io::Error::other(format!("program {name} type mismatch: {err}"))
                })?;
                program
                    .load()
                    .map_err(|err| io::Error::other(format!("load {name}: {err}")))?;
                let link_id = program
                    .attach(dir, CgroupAttachMode::Single)
                    .map_err(|err| io::Error::other(format!("attach {name}: {err}")))?;
                let link = program
                    .take_link(link_id)
                    .map_err(|err| io::Error::other(format!("link {name}: {err}")))?;
                links.push(link);
            }
            Ok(())
        })?;
        self.cgroup_links.extend(links);
        Ok(())
    }

    fn run(
        &self,
        command: Command,
        deny: &[String],
        layout: &MapsLayout,
    ) -> io::Result<ExitStatus> {
        let mut command = command;
        self.install_pre_exec(&mut command, deny, layout.clone())?;
        let mut child = command.spawn()?;
        child.wait()
    }

    fn install_pre_exec(
        &self,
        cmd: &mut Command,
        deny: &[String],
        layout: MapsLayout,
    ) -> io::Result<()> {
        let procs_fd = self.cgroup.procs_fd_raw()?;
        let rules = deny.to_vec();
        let bpf_ptr = self.bpf.get() as usize;
        unsafe {
            cmd.pre_exec(move || {
                join_cgroup_fd(procs_fd)?;
                {
                    let bpf = &mut *(bpf_ptr as *mut Ebpf);
                    populate_maps(bpf, &layout)?;
                }
                if !rules.is_empty() {
                    apply_seccomp(&rules)?;
                }
                Ok(())
            });
        }
        Ok(())
    }

    fn shutdown(mut self) -> io::Result<()> {
        if let Some(agent) = self.agent.take() {
            agent.stop()?;
        }
        self.cgroup.cleanup()?;
        Ok(())
    }
}

fn populate_maps(bpf: &mut Ebpf, layout: &MapsLayout) -> io::Result<()> {
    update_array(
        bpf,
        "EXEC_ALLOWLIST",
        "EXEC_ALLOWLIST_LENGTH",
        &layout.exec_allowlist,
        |entry| ExecAllowEntryPod(*entry),
    )?;
    update_array(
        bpf,
        "NET_RULES",
        "NET_RULES_LENGTH",
        &layout.net_rules,
        |entry| NetRuleEntryPod(*entry),
    )?;
    update_array(
        bpf,
        "NET_PARENTS",
        "NET_PARENTS_LENGTH",
        &layout.net_parents,
        |entry| NetParentEntryPod(*entry),
    )?;
    update_array(
        bpf,
        "FS_RULES",
        "FS_RULES_LENGTH",
        &layout.fs_rules,
        |entry| FsRuleEntryPod(*entry),
    )?;
    Ok(())
}

fn update_array<T, P, F>(
    bpf: &mut Ebpf,
    map_name: &str,
    len_map_name: &str,
    entries: &[T],
    convert: F,
) -> io::Result<()>
where
    P: Pod,
    F: Fn(&T) -> P,
{
    {
        let len_map = bpf
            .map_mut(len_map_name)
            .ok_or_else(|| map_not_found(len_map_name))?;
        let mut len_array = Array::<&mut MapData, u32>::try_from(len_map)
            .map_err(|err| io::Error::other(format!("{len_map_name}: {err}")))?;
        len_array
            .set(0, 0, 0)
            .map_err(|err| io::Error::other(format!("set {len_map_name}: {err}")))?;
    }

    {
        let map = bpf
            .map_mut(map_name)
            .ok_or_else(|| map_not_found(map_name))?;
        let mut array = Array::<&mut MapData, P>::try_from(map)
            .map_err(|err| io::Error::other(format!("{map_name}: {err}")))?;
        let capacity = array.len() as usize;
        if entries.len() > capacity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "map {map_name} capacity {capacity} exceeded by {} entries",
                    entries.len()
                ),
            ));
        }
        for (idx, entry) in entries.iter().enumerate() {
            array
                .set(idx as u32, convert(entry), 0)
                .map_err(|err| io::Error::other(format!("set {map_name}[{idx}]: {err}")))?;
        }
    }

    let len = u32::try_from(entries.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("too many entries for map {map_name}"),
        )
    })?;
    {
        let len_map = bpf
            .map_mut(len_map_name)
            .ok_or_else(|| map_not_found(len_map_name))?;
        let mut len_array = Array::<&mut MapData, u32>::try_from(len_map)
            .map_err(|err| io::Error::other(format!("{len_map_name}: {err}")))?;
        len_array
            .set(0, len, 0)
            .map_err(|err| io::Error::other(format!("set {len_map_name}: {err}")))?;
    }
    Ok(())
}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct ExecAllowEntryPod(ExecAllowEntry);

unsafe impl Pod for ExecAllowEntryPod {}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct NetRuleEntryPod(NetRuleEntry);

unsafe impl Pod for NetRuleEntryPod {}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct NetParentEntryPod(NetParentEntry);

unsafe impl Pod for NetParentEntryPod {}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct FsRuleEntryPod(FsRuleEntry);

unsafe impl Pod for FsRuleEntryPod {}

struct AgentHandle {
    shutdown: ShutdownHandle,
    thread: Option<thread::JoinHandle<Result<(), AnyhowError>>>,
}

impl AgentHandle {
    fn stop(mut self) -> io::Result<()> {
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

struct Cgroup {
    path: PathBuf,
    dir: Option<File>,
    procs: Option<File>,
}

impl Cgroup {
    fn create() -> io::Result<Self> {
        let base = env::var_os("QQRM_WARDEN_CGROUP_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/sys/fs/cgroup"));
        let prefix = base.join("cargo-warden");
        fs::create_dir_all(&prefix)?;
        let identifier = format!("pid-{}-{}", process::id(), unique_suffix());
        let path = prefix.join(identifier);
        fs::create_dir(&path)?;
        let dir = File::open(&path)?;
        let procs = OpenOptions::new()
            .write(true)
            .open(path.join("cgroup.procs"))?;
        Ok(Self {
            path,
            dir: Some(dir),
            procs: Some(procs),
        })
    }

    fn dir_file(&self) -> io::Result<&File> {
        self.dir
            .as_ref()
            .ok_or_else(|| io::Error::other("cgroup directory handle missing"))
    }

    fn procs_fd_raw(&self) -> io::Result<RawFd> {
        self.procs
            .as_ref()
            .map(|f| f.as_raw_fd())
            .ok_or_else(|| io::Error::other("cgroup procs handle missing"))
    }

    fn cleanup(&mut self) -> io::Result<()> {
        self.procs.take();
        self.dir.take();
        match fs::remove_dir(&self.path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err),
        }
    }
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

struct FakeSandbox {
    cgroup_dir: PathBuf,
    agent: Option<FakeAgent>,
    layout_recorder: Option<LayoutRecorder>,
}

impl FakeSandbox {
    fn new() -> io::Result<Self> {
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

    fn run(&mut self, mut command: Command, layout: &MapsLayout) -> io::Result<ExitStatus> {
        if let Some(recorder) = &self.layout_recorder {
            recorder.record(layout)?;
        }
        command.status()
    }

    fn shutdown(mut self) -> io::Result<()> {
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

struct LayoutRecorder {
    path: PathBuf,
}

impl LayoutRecorder {
    fn from_env() -> io::Result<Option<Self>> {
        match env::var_os("QQRM_WARDEN_FAKE_LAYOUT_PATH") {
            Some(path) => {
                let path = PathBuf::from(path);
                if let Some(parent) = path.parent() {
                    if !parent.as_os_str().is_empty() {
                        fs::create_dir_all(parent)?;
                    }
                }
                Ok(Some(Self { path }))
            }
            None => Ok(None),
        }
    }

    fn record(&self, layout: &MapsLayout) -> io::Result<()> {
        let record = RecordedLayout::from(layout);
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        serde_json::to_writer(&mut file, &record).map_err(io::Error::other)?;
        file.write_all(b"\n")?;
        Ok(())
    }
}

#[derive(Serialize)]
struct RecordedLayout {
    exec_allowlist: Vec<String>,
    net_rules: Vec<RecordedNetRule>,
    fs_rules: Vec<RecordedFsRule>,
}

impl From<&MapsLayout> for RecordedLayout {
    fn from(layout: &MapsLayout) -> Self {
        Self {
            exec_allowlist: layout
                .exec_allowlist
                .iter()
                .map(|entry| decode_null_terminated(&entry.path))
                .collect(),
            net_rules: layout.net_rules.iter().map(RecordedNetRule::from).collect(),
            fs_rules: layout.fs_rules.iter().map(RecordedFsRule::from).collect(),
        }
    }
}

#[derive(Serialize)]
struct RecordedNetRule {
    addr: String,
    prefix_len: u8,
    port: u16,
    protocol: u8,
}

impl From<&NetRuleEntry> for RecordedNetRule {
    fn from(entry: &NetRuleEntry) -> Self {
        Self {
            addr: decode_net_addr(&entry.rule),
            prefix_len: entry.rule.prefix_len,
            port: entry.rule.port,
            protocol: entry.rule.protocol,
        }
    }
}

#[derive(Serialize)]
struct RecordedFsRule {
    path: String,
    access: u8,
}

impl From<&FsRuleEntry> for RecordedFsRule {
    fn from(entry: &FsRuleEntry) -> Self {
        Self {
            path: decode_null_terminated(&entry.rule.path),
            access: entry.rule.access,
        }
    }
}

fn decode_null_terminated(bytes: &[u8]) -> String {
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).to_string()
}

fn decode_net_addr(rule: &NetRule) -> String {
    if rule.addr[4..].iter().all(|&b| b == 0) {
        let mut octets = [0u8; 4];
        octets.copy_from_slice(&rule.addr[..4]);
        Ipv4Addr::from(octets).to_string()
    } else {
        Ipv6Addr::from(rule.addr).to_string()
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
                let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
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

fn load_bpf() -> io::Result<Ebpf> {
    let path = bpf_object_path();
    let data = fs::read(&path)?;
    EbpfLoader::new().load(&data).map_err(|err| {
        io::Error::other(format!(
            "failed to load BPF object {}: {err}",
            path.display()
        ))
    })
}

fn bpf_object_path() -> PathBuf {
    if let Some(path) = env::var_os("QQRM_BPF_OBJECT") {
        PathBuf::from(path)
    } else {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../prebuilt")
            .join(env::consts::ARCH)
            .join("qqrm-bpf-core.o")
    }
}

fn take_events_ring(bpf: &mut Ebpf) -> io::Result<RingBuf<MapData>> {
    for name in ["events", "EVENTS"] {
        if let Some(map) = bpf.take_map(name) {
            return RingBuf::try_from(map).map_err(|err| {
                io::Error::other(format!("failed to open ring buffer {name}: {err}"))
            });
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "events ring buffer not found",
    ))
}

fn start_agent(ring: RingBuf<MapData>, events_path: PathBuf) -> io::Result<AgentHandle> {
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

fn join_cgroup_fd(fd: RawFd) -> io::Result<()> {
    let data = b"0\n";
    let offset = unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };
    if offset < 0 {
        return Err(io::Error::last_os_error());
    }
    let written = unsafe { libc::write(fd, data.as_ptr() as *const _, data.len()) };
    if written < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn events_path() -> PathBuf {
    if let Some(path) = env::var_os("QQRM_WARDEN_EVENTS_PATH") {
        PathBuf::from(path)
    } else {
        PathBuf::from("warden-events.jsonl")
    }
}

fn fake_cgroup_dir() -> PathBuf {
    if let Some(path) = env::var_os("QQRM_WARDEN_FAKE_CGROUP_DIR") {
        PathBuf::from(path)
    } else {
        let root = env::var_os("QQRM_WARDEN_FAKE_CGROUP_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(env::temp_dir);
        root.join(format!(
            "fake-cargo-warden-{}-{}",
            process::id(),
            unique_suffix()
        ))
    }
}

fn map_not_found(name: &str) -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, format!("missing BPF map {name}"))
}

fn program_not_found(name: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!("missing BPF program {name}"),
    )
}

fn unique_suffix() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros())
        .unwrap_or(0)
}
