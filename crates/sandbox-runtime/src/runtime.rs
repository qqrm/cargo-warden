use crate::fake::FakeSandbox;
use crate::real::RealSandbox;
use policy_core::Mode;
use qqrm_policy_compiler::MapsLayout;
use std::env;
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
        match &mut self.inner {
            SandboxImpl::Real(real) => real.run(command, mode, deny, layout, allowed_env),
            SandboxImpl::Fake(fake) => fake.run(command, mode, deny, layout, allowed_env),
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
    use std::env;
    use std::io;
    use std::process::Command;
    use std::sync::{Mutex, OnceLock};

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    struct VarGuard {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl VarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = env::var_os(key);
            // SAFETY: guarded by `ENV_LOCK`, so environment mutations are serialized.
            unsafe {
                env::set_var(key, value);
            }
            Self { key, previous }
        }

        fn remove(key: &'static str) -> Self {
            let previous = env::var_os(key);
            // SAFETY: guarded by `ENV_LOCK`, so environment mutations are serialized.
            unsafe {
                env::remove_var(key);
            }
            Self { key, previous }
        }
    }

    impl Drop for VarGuard {
        fn drop(&mut self) {
            if let Some(value) = &self.previous {
                // SAFETY: guarded by `ENV_LOCK`, so environment mutations are serialized.
                unsafe {
                    env::set_var(self.key, value);
                }
            } else {
                // SAFETY: guarded by `ENV_LOCK`, so environment mutations are serialized.
                unsafe {
                    env::remove_var(self.key);
                }
            }
        }
    }

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
        let _fake = VarGuard::set(super::FAKE_SANDBOX_ENV, "1");
        let _allowed_parent = VarGuard::set("ALLOWED_PARENT", "visible");
        let _blocked_parent = VarGuard::set("BLOCKED_PARENT", "hidden");

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
        let _fake = VarGuard::set(super::FAKE_SANDBOX_ENV, "1");
        let _clear_allowed = VarGuard::remove("ALLOWED_OVERRIDE");

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
}
