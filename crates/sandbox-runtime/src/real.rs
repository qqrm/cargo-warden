use crate::agent::{AgentHandle, start_agent};
use crate::bpf::{load_bpf, take_events_ring};
use crate::cgroup::Cgroup;
use crate::maps::{populate_maps, write_mode_flag};
use crate::seccomp::apply_seccomp;
use crate::util::{apply_allowed_environment, events_path};
use aya::programs::cgroup_sock_addr::CgroupSockAddrLink;
use aya::programs::lsm::LsmLink;
use aya::programs::{CgroupAttachMode, CgroupSockAddr, Lsm};
use aya::{Btf, Ebpf};
use policy_core::Mode;
use qqrm_policy_compiler::MapsLayout;
use std::cell::UnsafeCell;
use std::io;
use std::os::fd::RawFd;
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitStatus};

pub(crate) struct RealSandbox {
    bpf: UnsafeCell<Ebpf>,
    cgroup: Cgroup,
    lsm_links: Vec<LsmLink>,
    cgroup_links: Vec<CgroupSockAddrLink>,
    agent: Option<AgentHandle>,
    events_path: std::path::PathBuf,
}

impl RealSandbox {
    pub(crate) fn new() -> io::Result<Self> {
        let events_path = events_path();
        if let Some(parent) = events_path.parent() {
            std::fs::create_dir_all(parent)?;
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

    pub(crate) fn run(
        &self,
        command: Command,
        mode: Mode,
        deny: &[String],
        layout: &MapsLayout,
        allowed_env: &[String],
    ) -> io::Result<ExitStatus> {
        let mut command = command;
        apply_allowed_environment(&mut command, allowed_env);
        self.install_pre_exec(&mut command, deny, layout.clone(), mode)?;
        let mut child = command.spawn()?;
        child.wait()
    }

    pub(crate) fn shutdown(mut self) -> io::Result<()> {
        if let Some(agent) = self.agent.take() {
            agent.stop()?;
        }
        self.cgroup.cleanup()?;
        Ok(())
    }

    fn with_bpf<R>(&self, func: impl FnOnce(&mut Ebpf) -> io::Result<R>) -> io::Result<R> {
        let ptr = self.bpf.get();
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

    fn install_pre_exec(
        &self,
        cmd: &mut Command,
        deny: &[String],
        layout: MapsLayout,
        mode: Mode,
    ) -> io::Result<()> {
        let procs_fd = self.cgroup.procs_fd_raw()?;
        let rules = deny.to_vec();
        let bpf_ptr = self.bpf.get() as usize;
        let mode_value = mode;
        unsafe {
            cmd.pre_exec(move || {
                join_cgroup_fd(procs_fd)?;
                {
                    let bpf = &mut *(bpf_ptr as *mut Ebpf);
                    write_mode_flag(bpf, mode_value)?;
                    populate_maps(bpf, &layout)?;
                }
                if should_apply_seccomp(mode_value, &rules) {
                    apply_seccomp(mode_value, &rules)?;
                }
                Ok(())
            });
        }
        Ok(())
    }
}

fn should_apply_seccomp(mode: Mode, rules: &[String]) -> bool {
    matches!(mode, Mode::Enforce) && !rules.is_empty()
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

fn program_not_found(name: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!("missing BPF program {name}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seccomp_skipped_in_observe_mode() {
        let rules = vec!["open".to_string()];
        assert!(!should_apply_seccomp(Mode::Observe, &rules));
    }

    #[test]
    fn seccomp_applied_in_enforce_with_rules() {
        let rules = vec!["open".to_string()];
        assert!(should_apply_seccomp(Mode::Enforce, &rules));
    }

    #[test]
    fn seccomp_skipped_when_no_rules() {
        let rules: Vec<String> = Vec::new();
        assert!(!should_apply_seccomp(Mode::Enforce, &rules));
    }
}
