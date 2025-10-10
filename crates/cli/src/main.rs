mod commands;
pub(crate) mod policy;
mod sandbox;
#[cfg(test)]
pub(crate) mod test_support;

use clap::{Parser, Subcommand, ValueEnum};
use policy_core::Mode;
use std::process::exit;

use crate::commands::report::ReportFormat as ExecReportFormat;

#[derive(Copy, Clone, Debug, ValueEnum)]
enum CliMode {
    Observe,
    Enforce,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum CliReportFormat {
    Text,
    Json,
    Sarif,
}

impl From<CliMode> for Mode {
    fn from(mode: CliMode) -> Self {
        match mode {
            CliMode::Observe => Mode::Observe,
            CliMode::Enforce => Mode::Enforce,
        }
    }
}

impl From<CliReportFormat> for ExecReportFormat {
    fn from(format: CliReportFormat) -> Self {
        match format {
            CliReportFormat::Text => ExecReportFormat::Text,
            CliReportFormat::Json => ExecReportFormat::Json,
            CliReportFormat::Sarif => ExecReportFormat::Sarif,
        }
    }
}

/// Cargo subcommand providing warden functionality.
#[derive(Parser)]
#[command(
    name = "cargo-warden",
    bin_name = "cargo warden",
    version,
    about = "Cargo Warden CLI"
)]
struct Cli {
    /// Allowed executables passed directly via CLI.
    #[arg(long = "allow", value_name = "PATH", global = true)]
    allow: Vec<String>,
    /// Policy files referenced via CLI.
    #[arg(long = "policy", value_name = "FILE", global = true)]
    policy: Vec<String>,
    /// Override sandbox mode declared in policies.
    #[arg(long = "mode", value_enum, global = true)]
    mode: Option<CliMode>,
    /// Expose the Prometheus metrics endpoint on the given port.
    #[arg(long = "metrics-port", value_name = "PORT", global = true)]
    metrics_port: Option<u16>,
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
    /// Export events in text, JSON, or SARIF format.
    Report {
        /// Output format for the report.
        #[arg(long = "format", value_enum, default_value_t = CliReportFormat::Text)]
        format: CliReportFormat,
        /// Output file for the SARIF report (defaults to `warden.sarif`).
        #[arg(long = "output", value_name = "FILE")]
        output: Option<String>,
    },
}

fn main() {
    let mut args: Vec<String> = std::env::args().collect();
    if args.get(1).map(|s| s == "warden").unwrap_or(false) {
        args.remove(1);
    }
    let cli = Cli::parse_from(args);
    let Cli {
        allow,
        policy,
        mode,
        metrics_port,
        command,
    } = cli;
    let mode_override = mode.map(Mode::from);
    let agent_config = sandbox_runtime::AgentConfig {
        metrics_port,
        ..Default::default()
    };
    match command {
        Commands::Build { args } => {
            if let Err(e) =
                commands::build::exec(args, &allow, &policy, mode_override, agent_config.clone())
            {
                eprintln!("build failed: {e}");
                exit(1);
            }
        }
        Commands::Run { cmd } => {
            if let Err(e) =
                commands::run::exec(cmd, &allow, &policy, mode_override, agent_config.clone())
            {
                eprintln!("run failed: {e}");
                exit(1);
            }
        }
        Commands::Init => {
            if let Err(e) = commands::init::exec() {
                eprintln!("init failed: {e}");
                exit(1);
            }
        }
        Commands::Status => {
            if let Err(e) = commands::status::exec(&policy, mode_override) {
                eprintln!("status failed: {e}");
                exit(1);
            }
        }
        Commands::Report { format, output } => {
            if let Err(e) = commands::report::exec(format.into(), output.as_deref()) {
                eprintln!("report failed: {e}");
                exit(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};

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
        assert!(cli.mode.is_none());
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
        assert!(cli.mode.is_none());
        match cli.command {
            Commands::Build { args } => {
                assert_eq!(args, vec!["--verbose".to_string()]);
            }
            _ => panic!("expected build command"),
        }
    }

    #[test]
    fn parse_multiple_policies_for_build() {
        let cli = Cli::parse_from([
            "cargo-warden",
            "build",
            "--policy",
            "a.toml",
            "--policy",
            "b.toml",
        ]);
        assert_eq!(cli.policy, vec!["a.toml".to_string(), "b.toml".to_string()]);
        assert!(cli.mode.is_none());
        match cli.command {
            Commands::Build { args } => {
                assert!(args.is_empty());
            }
            _ => panic!("expected build command"),
        }
    }

    #[test]
    fn parse_metrics_port_flag() {
        let cli = Cli::parse_from(["cargo-warden", "build", "--metrics-port", "9898"]);
        assert_eq!(cli.metrics_port, Some(9898));
        match cli.command {
            Commands::Build { .. } => {}
            _ => panic!("expected build command"),
        }
    }

    #[test]
    fn parse_mode_for_build() {
        let cli = Cli::parse_from(["cargo-warden", "--mode", "observe", "build"]);
        assert!(matches!(cli.mode, Some(CliMode::Observe)));
        match cli.command {
            Commands::Build { args } => {
                assert!(args.is_empty());
            }
            _ => panic!("expected build command"),
        }
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
    fn parse_report_command() {
        let cli = Cli::parse_from(["cargo-warden", "report"]);
        match cli.command {
            Commands::Report { .. } => {}
            _ => panic!("expected report command"),
        }
    }

    #[test]
    fn parse_report_defaults_to_text() {
        let cli = Cli::parse_from(["cargo-warden", "report"]);
        match cli.command {
            Commands::Report { format, output } => {
                assert!(matches!(format, CliReportFormat::Text));
                assert!(output.is_none());
            }
            _ => panic!("expected report command"),
        }
    }

    #[test]
    fn parse_report_accepts_sarif_output() {
        let cli = Cli::parse_from([
            "cargo-warden",
            "report",
            "--format",
            "sarif",
            "--output",
            "custom.sarif",
        ]);
        match cli.command {
            Commands::Report { format, output } => {
                assert!(matches!(format, CliReportFormat::Sarif));
                assert_eq!(output.as_deref(), Some("custom.sarif"));
            }
            _ => panic!("expected report command"),
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
}
