use clap::{Parser, Subcommand};
use std::io;
use std::process::{Command, exit};

/// Cargo subcommand providing warden functionality.
#[derive(Parser)]
#[command(name = "cargo-warden", version, about = "Cargo Warden CLI")]
struct Cli {
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
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Build { args } => {
            if let Err(e) = handle_build(args) {
                eprintln!("build failed: {e}");
                exit(1);
            }
        }
        Commands::Run { cmd } => {
            println!("run not implemented: {:?}", cmd);
        }
    }
}

fn handle_build(args: Vec<String>) -> io::Result<()> {
    setup_isolation()?;
    let status = build_command(&args).status()?;
    if !status.success() {
        exit(status.code().unwrap_or(1));
    }
    Ok(())
}

fn setup_isolation() -> io::Result<()> {
    Ok(())
}

fn build_command(args: &[String]) -> Command {
    let mut cmd = Command::new("cargo");
    cmd.arg("build").args(args);
    cmd
}

#[cfg(test)]
mod tests {
    use super::{Cli, build_command};
    use clap::CommandFactory;
    use std::ffi::OsStr;

    #[test]
    fn verify_cli() {
        Cli::command().debug_assert();
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
}
