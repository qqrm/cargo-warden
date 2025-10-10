use std::io;
use std::process::{Command, exit};

use policy_core::Mode;

use crate::policy::setup_isolation;
use crate::sandbox::run_in_sandbox;

pub(crate) fn exec(
    cmd: Vec<String>,
    allow: &[String],
    policy: &[String],
    mode_override: Option<Mode>,
    agent_config: sandbox_runtime::AgentConfig,
) -> io::Result<()> {
    if cmd.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing command",
        ));
    }
    let isolation = setup_isolation(allow, policy, mode_override)?;
    let status = run_in_sandbox(run_command(&cmd), isolation.mode, &isolation, agent_config)?;
    if !status.success() {
        exit(status.code().unwrap_or(1));
    }
    Ok(())
}

fn run_command(cmd: &[String]) -> Command {
    let mut command = Command::new(&cmd[0]);
    if cmd.len() > 1 {
        command.args(&cmd[1..]);
    }
    command
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn run_command_forms_expected_command() {
        let args = vec!["echo".to_string(), "hello".to_string()];
        let cmd = run_command(&args);
        assert_eq!(cmd.get_program(), OsStr::new("echo"));
        let collected: Vec<String> = cmd
            .get_args()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert_eq!(collected, ["hello"]);
    }
}
