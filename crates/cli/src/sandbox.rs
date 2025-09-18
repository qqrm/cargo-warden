use crate::apply_seccomp;
use anyhow::Error as AnyhowError;
use aya::maps::{Array, MapData, ring_buf::RingBuf};
use aya::programs::cgroup_sock_addr::CgroupSockAddrLink;
use aya::programs::lsm::LsmLink;
use aya::programs::{CgroupAttachMode, CgroupSockAddr, Lsm};
use aya::{Btf, Ebpf, EbpfLoader, Pod};
use bpf_api::{ExecAllowEntry, FsRuleEntry, NetParentEntry, NetRuleEntry};
use policy_compiler::MapsLayout;
use qqrm_agent_lite::{self, Config as AgentConfig, Shutdown, ShutdownHandle};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{self, Command, ExitStatus};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[repr(transparent)]
#[derive(Copy, Clone)]
struct ExecAllowEntryPod(ExecAllowEntry);

unsafe impl Pod for ExecAllowEntryPod {}

impl From<ExecAllowEntry> for ExecAllowEntryPod {
    fn from(entry: ExecAllowEntry) -> Self {
        Self(entry)
    }
}

#[repr(transparent)]
#[derive(Copy, Clone)]
struct NetRuleEntryPod(NetRuleEntry);

unsafe impl Pod for NetRuleEntryPod {}

impl From<NetRuleEntry> for NetRuleEntryPod {
    fn from(entry: NetRuleEntry) -> Self {
        Self(entry)
    }
}

#[repr(transparent)]
#[derive(Copy, Clone)]
struct NetParentEntryPod(NetParentEntry);

unsafe impl Pod for NetParentEntryPod {}

impl From<NetParentEntry> for NetParentEntryPod {
    fn from(entry: NetParentEntry) -> Self {
        Self(entry)
    }
}

#[repr(transparent)]
#[derive(Copy, Clone)]
struct FsRuleEntryPod(FsRuleEntry);

unsafe impl Pod for FsRuleEntryPod {}

impl From<FsRuleEntry> for FsRuleEntryPod {
    fn from(entry: FsRuleEntry) -> Self {
        Self(entry)
    }
}

/// Wrapper responsible for BPF setup, agent management and cleanup.
pub(crate) struct Sandbox {
    inner: SandboxImpl,
}

enum SandboxImpl {
    Real(RealSandbox),
    Fake(FakeSandbox),
}

impl Sandbox {
    pub(crate) fn new(layout: &MapsLayout) -> io::Result<Self> {
        if env::var_os("QQRM_WARDEN_FAKE_SANDBOX").is_some() {
            return Ok(Self {
                inner: SandboxImpl::Fake(FakeSandbox::new()?),
            });
        }
        Ok(Self {
            inner: SandboxImpl::Real(RealSandbox::new(layout)?),
        })
    }

    pub(crate) fn run(&mut self, command: Command, deny: &[String]) -> io::Result<ExitStatus> {
        match &mut self.inner {
            SandboxImpl::Real(real) => real.run(command, deny),
            SandboxImpl::Fake(fake) => fake.run(command),
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
    bpf: Ebpf,
    cgroup: Cgroup,
    lsm_links: Vec<LsmLink>,
    cgroup_links: Vec<CgroupSockAddrLink>,
    agent: Option<AgentHandle>,
    events_path: PathBuf,
}

impl RealSandbox {
    fn new(layout: &MapsLayout) -> io::Result<Self> {
        let events_path = events_path();
        if let Some(parent) = events_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let bpf = load_bpf()?;
        let cgroup = Cgroup::create()?;
        let mut sandbox = RealSandbox {
            bpf,
            cgroup,
            lsm_links: Vec::new(),
            cgroup_links: Vec::new(),
            agent: None,
            events_path,
        };
        sandbox.load_maps(layout)?;
        sandbox.attach_lsm()?;
        sandbox.attach_cgroup()?;
        let ring = take_events_ring(&mut sandbox.bpf)?;
        sandbox.agent = Some(start_agent(ring, sandbox.events_path.clone())?);
        Ok(sandbox)
    }

    fn load_maps(&mut self, layout: &MapsLayout) -> io::Result<()> {
        populate_array_map::<ExecAllowEntry, ExecAllowEntryPod>(
            &mut self.bpf,
            "EXEC_ALLOWLIST",
            &layout.exec_allowlist,
        )?;
        set_length_map(
            &mut self.bpf,
            "EXEC_ALLOWLIST_LENGTH",
            layout.exec_allowlist.len() as u32,
        )?;
        populate_array_map::<NetRuleEntry, NetRuleEntryPod>(
            &mut self.bpf,
            "NET_RULES",
            &layout.net_rules,
        )?;
        set_length_map(
            &mut self.bpf,
            "NET_RULES_LENGTH",
            layout.net_rules.len() as u32,
        )?;
        populate_array_map::<NetParentEntry, NetParentEntryPod>(
            &mut self.bpf,
            "NET_PARENTS",
            &layout.net_parents,
        )?;
        set_length_map(
            &mut self.bpf,
            "NET_PARENTS_LENGTH",
            layout.net_parents.len() as u32,
        )?;
        populate_array_map::<FsRuleEntry, FsRuleEntryPod>(
            &mut self.bpf,
            "FS_RULES",
            &layout.fs_rules,
        )?;
        set_length_map(
            &mut self.bpf,
            "FS_RULES_LENGTH",
            layout.fs_rules.len() as u32,
        )?;
        Ok(())
    }

    fn attach_lsm(&mut self) -> io::Result<()> {
        let btf = Btf::from_sys_fs().map_err(io::Error::other)?;
        for hook in [
            "bprm_check_security",
            "file_open",
            "file_permission",
            "inode_unlink",
        ] {
            let program = self
                .bpf
                .program_mut(hook)
                .ok_or_else(|| program_not_found(hook))?;
            let program: &mut Lsm = program
                .try_into()
                .map_err(|err| io::Error::other(format!("program {hook} type mismatch: {err}")))?;
            program
                .load(hook, &btf)
                .map_err(|err| io::Error::other(format!("load {hook}: {err}")))?;
            let link_id = program
                .attach()
                .map_err(|err| io::Error::other(format!("attach {hook}: {err}")))?;
            let link = program
                .take_link(link_id)
                .map_err(|err| io::Error::other(format!("link {hook}: {err}")))?;
            self.lsm_links.push(link);
        }
        Ok(())
    }

    fn attach_cgroup(&mut self) -> io::Result<()> {
        let dir = self.cgroup.dir_file()?;
        for name in ["connect4", "connect6", "sendmsg4", "sendmsg6"] {
            let program = self
                .bpf
                .program_mut(name)
                .ok_or_else(|| program_not_found(name))?;
            let program: &mut CgroupSockAddr = program
                .try_into()
                .map_err(|err| io::Error::other(format!("program {name} type mismatch: {err}")))?;
            program
                .load()
                .map_err(|err| io::Error::other(format!("load {name}: {err}")))?;
            let link_id = program
                .attach(dir, CgroupAttachMode::Single)
                .map_err(|err| io::Error::other(format!("attach {name}: {err}")))?;
            let link = program
                .take_link(link_id)
                .map_err(|err| io::Error::other(format!("link {name}: {err}")))?;
            self.cgroup_links.push(link);
        }
        Ok(())
    }

    fn run(&self, command: Command, deny: &[String]) -> io::Result<ExitStatus> {
        let mut command = command;
        self.install_pre_exec(&mut command, deny)?;
        let mut child = command.spawn()?;
        child.wait()
    }

    fn install_pre_exec(&self, cmd: &mut Command, deny: &[String]) -> io::Result<()> {
        let procs_fd = self.cgroup.procs_fd_raw()?;
        let rules = deny.to_vec();
        unsafe {
            cmd.pre_exec(move || {
                join_cgroup_fd(procs_fd)?;
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

fn populate_array_map<T, P>(bpf: &mut Ebpf, name: &str, entries: &[T]) -> io::Result<()>
where
    T: Copy,
    P: From<T> + Pod,
{
    let map = bpf.map_mut(name).ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, format!("BPF map {name} not found"))
    })?;
    let mut array = Array::<_, P>::try_from(map)
        .map_err(|err| io::Error::other(format!("map {name} type mismatch: {err}")))?;
    for (idx, entry) in entries.iter().copied().enumerate() {
        let pod = P::from(entry);
        array
            .set(idx as u32, pod, 0)
            .map_err(|err| io::Error::other(format!("failed to update {name}[{idx}]: {err}")))?;
    }
    Ok(())
}

fn set_length_map(bpf: &mut Ebpf, name: &str, len: u32) -> io::Result<()> {
    let map = bpf.map_mut(name).ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, format!("BPF map {name} not found"))
    })?;
    let mut array = Array::<_, u32>::try_from(map)
        .map_err(|err| io::Error::other(format!("map {name} type mismatch: {err}")))?;
    array
        .set(0, len, 0)
        .map_err(|err| io::Error::other(format!("failed to set {name}: {err}")))
}

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
        Ok(Self {
            cgroup_dir,
            agent: Some(agent),
        })
    }

    fn run(&mut self, mut command: Command) -> io::Result<ExitStatus> {
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
