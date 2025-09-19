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
    ) -> io::Result<ExitStatus> {
        match &mut self.inner {
            SandboxImpl::Real(real) => real.run(command, mode, deny, layout),
            SandboxImpl::Fake(fake) => fake.run(command, mode, deny, layout),
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
