use clap::{Parser, Subcommand};
use std::io;
use std::process::{Command, exit};

/// Cargo subcommand providing warden functionality.
#[derive(Parser)]
#[command(name = "cargo-warden", version, about = "Cargo Warden CLI")]
struct Cli {
    /// Allowed executables passed directly via CLI.
    #[arg(long = "allow", value_name = "PATH", global = true)]
    allow: Vec<String>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build wrapper that will configure isolation.
    Build {
        /// Arguments passed to `cargo build`.
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
    /// Run wrapper for arbitrary commands.
    Run {
        /// Command to execute after `--`.
        #[arg(trailing_var_arg = true)]
        cmd: Vec<String>,
    },
    /// Show active policy and recent events.
    Status,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Build { args } => {
            if let Err(e) = handle_build(args, &cli.allow) {
                eprintln!("build failed: {e}");
                exit(1);
            }
        }
        Commands::Run { cmd } => {
            if let Err(e) = handle_run(cmd, &cli.allow) {
                eprintln!("run failed: {e}");
                exit(1);
            }
        }
        Commands::Status => {
            if let Err(e) = handle_status() {
                eprintln!("status failed: {e}");
                exit(1);
            }
        }
    }
}

fn handle_build(args: Vec<String>, allow: &[String]) -> io::Result<()> {
    setup_isolation(allow)?;
    let status = build_command(&args).status()?;
    if !status.success() {
        exit(status.code().unwrap_or(1));
    }
    Ok(())
}

fn setup_isolation(_allow: &[String]) -> io::Result<()> {
    Ok(())
}

fn build_command(args: &[String]) -> Command {
    let mut cmd = Command::new("cargo");
    cmd.arg("build").args(args);
    cmd
}

fn handle_run(cmd: Vec<String>, allow: &[String]) -> io::Result<()> {
    if cmd.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing command",
        ));
    }
    setup_isolation(allow)?;
    let status = run_command(&cmd).status()?;
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

fn handle_status() -> io::Result<()> {
    println!("active policy: none");
    println!("recent events: none");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Cli, Commands, build_command, run_command};
    use clap::{CommandFactory, Parser};
    use std::ffi::OsStr;

    #[test]
    fn verify_cli() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parse_allow_for_build() {
        let cli = Cli::parse_from([
            "cargo-warden",
            "build",
            "--allow",
            "/bin/bash",
            "--",
            "--release",
        ]);
        assert_eq!(cli.allow, vec!["/bin/bash".to_string()]);
        match cli.command {
            Commands::Build { args } => {
                assert_eq!(args, vec!["--release".to_string()]);
            }
            _ => panic!("expected build command"),
        }
    }

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

    #[test]
    fn parse_status_command() {
        let cli = Cli::parse_from(["cargo-warden", "status"]);
        match cli.command {
            Commands::Status => {}
            _ => panic!("expected status command"),
        }
    }
}
