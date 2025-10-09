use crate::fake::FakeSandbox;
use crate::real::RealSandbox;
use crate::workload::detect_program_unit;
use policy_core::Mode;
use qqrm_policy_compiler::MapsLayout;
use std::env;
use std::ffi::OsString;
use std::io;
use std::process::{Command, ExitStatus};

const FAKE_SANDBOX_ENV: &str = "QQRM_WARDEN_FAKE_SANDBOX";

enum SandboxImpl {
    Real(RealSandbox),
    Fake(FakeSandbox),
}

/// Runtime wrapper that orchestrates sandbox lifecycle management.
pub struct Sandbox {
    inner: SandboxImpl,
}

impl Sandbox {
    /// Constructs a new sandbox runtime based on the configured environment.
    pub fn new() -> io::Result<Self> {
        if env::var_os(FAKE_SANDBOX_ENV).is_some() {
            Ok(Self {
                inner: SandboxImpl::Fake(FakeSandbox::new()?),
            })
        } else {
            Ok(Self {
                inner: SandboxImpl::Real(RealSandbox::new()?),
            })
        }
    }

    /// Runs a command inside the sandbox, applying syscall deny rules and
    /// populating BPF maps from the provided layout.
    pub fn run(
        &mut self,
        command: Command,
        mode: Mode,
        deny: &[String],
        layout: &MapsLayout,
        allowed_env: &[String],
    ) -> io::Result<ExitStatus> {
        let program = command.get_program().to_owned();
        let args: Vec<OsString> = command.get_args().map(|arg| arg.to_owned()).collect();
        let unit = detect_program_unit(&program, &args);
        let parent_pid = std::process::id();
        self.write_workload_units(&[(parent_pid, unit)])?;

        match &mut self.inner {
            SandboxImpl::Real(real) => real.run(command, mode, deny, layout, allowed_env),
            SandboxImpl::Fake(fake) => fake.run(command, mode, deny, layout, allowed_env),
        }
    }

    /// Populates workload-to-unit mappings prior to launching a command.
    pub fn write_workload_units(&mut self, units: &[(u32, u32)]) -> io::Result<()> {
        match &mut self.inner {
            SandboxImpl::Real(real) => real.write_workload_units(units),
            SandboxImpl::Fake(fake) => fake.write_workload_units(units),
        }
    }

    /// Shuts down the sandbox runtime, releasing all resources.
    pub fn shutdown(self) -> io::Result<()> {
        match self.inner {
            SandboxImpl::Real(real) => real.shutdown(),
            SandboxImpl::Fake(fake) => fake.shutdown(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scoped_env::ScopedEnv;
    use std::ffi::OsStr;
    use std::io;
    use std::process::Command;
    use std::sync::{Mutex, OnceLock};

    use crate::LayoutSnapshot;
    use crate::layout::FAKE_LAYOUT_ENV;
    use crate::util::{EVENTS_PATH_ENV, FAKE_CGROUP_DIR_ENV};
    use bpf_api::{ExecAllowEntry, MODE_FLAG_ENFORCE};
    use serde_json::from_str;

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn empty_layout() -> MapsLayout {
        MapsLayout {
            mode_flags: Vec::new(),
            exec_allowlist: Vec::new(),
            net_rules: Vec::new(),
            net_parents: Vec::new(),
            fs_rules: Vec::new(),
        }
    }

    #[test]
    fn restricts_environment_to_allowed_keys() -> io::Result<()> {
        let _guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
        let _fake = ScopedEnv::set(OsStr::new(super::FAKE_SANDBOX_ENV), OsStr::new("1"));
        let _allowed_parent = ScopedEnv::set(OsStr::new("ALLOWED_PARENT"), OsStr::new("visible"));
        let _blocked_parent = ScopedEnv::set(OsStr::new("BLOCKED_PARENT"), OsStr::new("hidden"));

        let mut sandbox = Sandbox::new()?;
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg("test \"${ALLOWED_PARENT}\" = visible && test -z \"${BLOCKED_PARENT}\"");

        let allowed = vec!["ALLOWED_PARENT".to_string(), "PATH".to_string()];
        let status = sandbox.run(command, Mode::Enforce, &[], &empty_layout(), &allowed)?;
        assert!(status.success());
        Ok(())
    }

    #[test]
    fn filters_command_defined_environment() -> io::Result<()> {
        let _guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
        let _fake = ScopedEnv::set(OsStr::new(super::FAKE_SANDBOX_ENV), OsStr::new("1"));
        let _clear_allowed = ScopedEnv::remove(OsStr::new("ALLOWED_OVERRIDE"));

        let mut sandbox = Sandbox::new()?;
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg("test \"${ALLOWED_OVERRIDE}\" = custom && test -z \"${BLOCKED_OVERRIDE}\"");
        command.env("ALLOWED_OVERRIDE", "custom");
        command.env("BLOCKED_OVERRIDE", "value");

        let allowed = vec!["ALLOWED_OVERRIDE".to_string(), "PATH".to_string()];
        let status = sandbox.run(command, Mode::Enforce, &[], &empty_layout(), &allowed)?;
        assert!(status.success());
        Ok(())
    }

    #[test]
    fn write_workload_units_available() -> io::Result<()> {
        let _guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
        let _fake = ScopedEnv::set(OsStr::new(super::FAKE_SANDBOX_ENV), OsStr::new("1"));

        let mut sandbox = Sandbox::new()?;
        sandbox.write_workload_units(&[(1, 2)])?;
        sandbox.shutdown()?;
        Ok(())
    }

    #[test]
    fn fake_runtime_records_compiled_layout() -> io::Result<()> {
        let _guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
        let _fake = ScopedEnv::set(OsStr::new(super::FAKE_SANDBOX_ENV), OsStr::new("1"));

        let root = std::env::temp_dir().join(format!(
            "sandbox-runtime-test-{}",
            crate::util::unique_suffix()
        ));
        std::fs::create_dir_all(&root)?;
        let layout_path = root.join("layout.jsonl");
        let events_path = root.join("events.jsonl");
        let cgroup_dir = root.join("cgroup");

        let _layout_env = ScopedEnv::set(OsStr::new(FAKE_LAYOUT_ENV), layout_path.as_os_str());
        let _events_env = ScopedEnv::set(OsStr::new(EVENTS_PATH_ENV), events_path.as_os_str());
        let _cgroup_env = ScopedEnv::set(OsStr::new(FAKE_CGROUP_DIR_ENV), cgroup_dir.as_os_str());

        let mut sandbox = Sandbox::new()?;
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg("exit 0");

        let mut exec_entry = ExecAllowEntry { path: [0; 256] };
        let exec_path = b"/usr/bin/compiled";
        exec_entry.path[..exec_path.len()].copy_from_slice(exec_path);
        let layout = MapsLayout {
            mode_flags: vec![MODE_FLAG_ENFORCE],
            exec_allowlist: vec![exec_entry],
            net_rules: Vec::new(),
            net_parents: Vec::new(),
            fs_rules: Vec::new(),
        };

        let status = sandbox.run(command, Mode::Enforce, &[], &layout, &["PATH".into()])?;
        assert!(status.success());
        sandbox.shutdown()?;

        let contents = std::fs::read_to_string(&layout_path)?;
        let snapshot = contents
            .lines()
            .rev()
            .find(|line| !line.trim().is_empty())
            .map(|line| from_str::<LayoutSnapshot>(line).unwrap())
            .ok_or_else(|| io::Error::other("missing layout snapshot"))?;
        assert_eq!(snapshot.mode, "enforce");
        assert_eq!(snapshot.mode_flag, Some(MODE_FLAG_ENFORCE));
        assert!(
            snapshot
                .exec
                .iter()
                .any(|entry| entry == "/usr/bin/compiled")
        );

        let _ = std::fs::remove_dir_all(&root);

        Ok(())
    }
}
