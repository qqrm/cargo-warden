use std::io;
use std::process::ExitStatus;

use policy_core::Mode;
use sandbox_runtime::{AgentConfig, Sandbox};

use policy_orchestrator::IsolationConfig;

pub(crate) fn run_in_sandbox(
    command: std::process::Command,
    mode: Mode,
    isolation: &IsolationConfig,
    agent_config: AgentConfig,
) -> io::Result<ExitStatus> {
    let mut sandbox = Sandbox::new_with_agent_config(agent_config)?;
    let run_result = sandbox.run(
        command,
        mode,
        &isolation.syscall_deny,
        &isolation.maps_layout,
        &isolation.allowed_env_vars,
    );
    let shutdown_result = sandbox.shutdown();
    let status = match run_result {
        Ok(status) => status,
        Err(err) => {
            let _ = shutdown_result;
            return Err(err);
        }
    };
    shutdown_result?;
    Ok(status)
}
