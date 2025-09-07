use clap::{Parser, Subcommand};
use std::fs::File;
use std::io::{self, BufRead, Write};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, exit};

/// Cargo subcommand providing warden functionality.
#[derive(Parser)]
#[command(name = "cargo-warden", version, about = "Cargo Warden CLI")]
struct Cli {
    /// Allowed executables passed directly via CLI.
    #[arg(long = "allow", value_name = "PATH", global = true)]
    allow: Vec<String>,
    /// Policy files referenced via CLI.
    #[arg(long = "policy", value_name = "FILE", global = true)]
    policy: Vec<String>,
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
    /// Initialize warden configuration.
    Init,
    /// Show active policy and recent events.
    Status,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Build { args } => {
            if let Err(e) = handle_build(args, &cli.allow, &cli.policy) {
                eprintln!("build failed: {e}");
                exit(1);
            }
        }
        Commands::Run { cmd } => {
            if let Err(e) = handle_run(cmd, &cli.allow, &cli.policy) {
                eprintln!("run failed: {e}");
                exit(1);
            }
        }
        Commands::Init => {
            if let Err(e) = handle_init() {
                eprintln!("init failed: {e}");
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

fn handle_build(args: Vec<String>, allow: &[String], policy: &[String]) -> io::Result<()> {
    let deny = setup_isolation(allow, policy)?;
    let mut cmd = build_command(&args);
    if !deny.is_empty() {
        apply_seccomp_to_command(&mut cmd, &deny)?;
    }
    let status = cmd.status()?;
    if !status.success() {
        exit(status.code().unwrap_or(1));
    }
    Ok(())
}

fn setup_isolation(_allow: &[String], policy: &[String]) -> io::Result<Vec<String>> {
    if let Some(path) = policy.first() {
        let text = std::fs::read_to_string(path)?;
        let policy = policy_core::Policy::from_toml_str(&text)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let report = policy.validate();
        if !report.errors.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{:?}", report.errors),
            ));
        }
        for warn in report.warnings {
            eprintln!("warning: {warn}");
        }
        Ok(policy.syscall.deny)
    } else {
        Ok(Vec::new())
    }
}

fn build_command(args: &[String]) -> Command {
    let mut cmd = Command::new("cargo");
    cmd.arg("build").args(args);
    cmd
}

fn handle_run(cmd: Vec<String>, allow: &[String], policy: &[String]) -> io::Result<()> {
    if cmd.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing command",
        ));
    }
    let deny = setup_isolation(allow, policy)?;
    let mut command = run_command(&cmd);
    if !deny.is_empty() {
        apply_seccomp_to_command(&mut command, &deny)?;
    }
    let status = command.status()?;
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

fn apply_seccomp_to_command(cmd: &mut Command, deny: &[String]) -> io::Result<()> {
    let rules = deny.to_owned();
    unsafe {
        cmd.pre_exec(move || {
            apply_seccomp(&rules)?;
            Ok(())
        });
    }
    Ok(())
}

#[cfg(not(test))]
fn apply_seccomp(deny: &[String]) -> io::Result<()> {
    use libseccomp::{ScmpAction, ScmpFilterContext, ScmpSyscall};
    let mut filter = ScmpFilterContext::new_filter(ScmpAction::Allow).map_err(io::Error::other)?;
    for name in deny {
        if let Ok(sys) = ScmpSyscall::from_name(name) {
            filter
                .add_rule(ScmpAction::Errno(libc::EPERM), sys)
                .map_err(io::Error::other)?;
        }
    }
    filter.load().map_err(io::Error::other)
}

#[cfg(test)]
fn apply_seccomp(_deny: &[String]) -> io::Result<()> {
    Ok(())
}

fn handle_status() -> io::Result<()> {
    println!("active policy: none");
    println!("recent events: none");
    Ok(())
}

fn handle_init() -> io::Result<()> {
    let mut input = io::stdin().lock();
    let mut output = io::stdout();
    handle_init_with(&mut input, &mut output)
}

fn handle_init_with<R: BufRead, W: Write>(input: &mut R, output: &mut W) -> io::Result<()> {
    let path = Path::new("warden.toml");
    if path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "warden.toml already exists",
        ));
    }
    writeln!(output, "Enter allowlist entries (comma separated):")?;
    let mut line = String::new();
    input.read_line(&mut line)?;
    let entries: Vec<String> = line
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let mut file = File::create(path)?;
    writeln!(file, "[allowlist]")?;
    writeln!(file, "paths = [")?;
    for (i, entry) in entries.iter().enumerate() {
        if i + 1 == entries.len() {
            writeln!(file, "    \"{}\"", entry)?;
        } else {
            writeln!(file, "    \"{}\",", entry)?;
        }
    }
    writeln!(file, "]")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Cli, Commands, build_command, handle_init_with, run_command};
    use clap::{CommandFactory, Parser};
    use std::ffi::OsStr;
    use std::io::Cursor;

    use tempfile::tempdir;

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
    fn parse_policy_for_build() {
        let cli = Cli::parse_from([
            "cargo-warden",
            "build",
            "--policy",
            "policy.toml",
            "--",
            "--verbose",
        ]);
        assert_eq!(cli.policy, vec!["policy.toml".to_string()]);
        match cli.command {
            Commands::Build { args } => {
                assert_eq!(args, vec!["--verbose".to_string()]);
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

    #[test]
    fn parse_init_command() {
        let cli = Cli::parse_from(["cargo-warden", "init"]);
        match cli.command {
            Commands::Init => {}
            _ => panic!("expected init command"),
        }
    }

    #[test]
    fn handle_init_creates_file_and_prompts() {
        let dir = tempdir().unwrap();
        let old_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();

        let input_data = "foo, bar\n";
        let mut input = Cursor::new(input_data.as_bytes());
        let mut output = Vec::new();

        handle_init_with(&mut input, &mut output).unwrap();

        std::env::set_current_dir(old_dir).unwrap();

        let out_str = String::from_utf8(output).unwrap();
        assert!(out_str.contains("Enter allowlist entries"));

        let config = std::fs::read_to_string(dir.path().join("warden.toml")).unwrap();
        assert!(config.contains("foo"));
        assert!(config.contains("bar"));
    }
}
