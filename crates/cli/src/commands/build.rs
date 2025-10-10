use std::io;
use std::process::{Command, exit};

use policy_core::Mode;

use crate::policy::setup_isolation;
use crate::sandbox::run_in_sandbox;

pub(crate) fn exec(
    args: Vec<String>,
    allow: &[String],
    policy: &[String],
    mode_override: Option<Mode>,
    agent_config: sandbox_runtime::AgentConfig,
) -> io::Result<()> {
    let isolation = setup_isolation(allow, policy, mode_override)?;
    let status = run_in_sandbox(
        build_command(&args),
        isolation.mode,
        &isolation,
        agent_config,
    )?;
    if !status.success() {
        exit(status.code().unwrap_or(1));
    }
    Ok(())
}

fn build_command(args: &[String]) -> Command {
    let mut cmd = Command::new("cargo");
    cmd.arg("build").args(args);
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn build_command_forms_cargo_build() {
        let args = vec!["--release".to_string(), "--verbose".to_string()];
        let cmd = build_command(&args);
        assert_eq!(cmd.get_program(), OsStr::new("cargo"));
        let collected: Vec<String> = cmd
            .get_args()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert_eq!(collected, ["build", "--release", "--verbose"]);
    }
}
