mod commands;
pub(crate) mod policy;
mod privileges;
mod sandbox;
#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
mod allocation_tracker {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;

    pub struct CountingAllocator;

    thread_local! {
        static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    }

    #[inline]
    fn record_allocation() {
        ALLOCATIONS.with(|cell| cell.set(cell.get().saturating_add(1)));
    }

    unsafe impl GlobalAlloc for CountingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            record_allocation();
            unsafe { System.alloc(layout) }
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            record_allocation();
            unsafe { System.alloc_zeroed(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            unsafe { System.dealloc(ptr, layout) }
        }

        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            record_allocation();
            unsafe { System.realloc(ptr, layout, new_size) }
        }
    }

    pub fn allocation_count() -> usize {
        ALLOCATIONS.with(|cell| cell.get())
    }

    pub fn reset() {
        ALLOCATIONS.with(|cell| cell.set(0));
    }
}

#[cfg(test)]
#[global_allocator]
static GLOBAL_ALLOCATOR: allocation_tracker::CountingAllocator =
    allocation_tracker::CountingAllocator;

#[cfg(test)]
pub(crate) fn allocation_count() -> usize {
    allocation_tracker::allocation_count()
}

#[cfg(test)]
pub(crate) fn reset_allocation_count() {
    allocation_tracker::reset();
}

#[cfg(test)]
mod allocation_helpers {
    use super::{allocation_count, reset_allocation_count};

    #[test]
    fn allocation_counters_can_be_used() {
        reset_allocation_count();
        assert_eq!(allocation_count(), 0);
    }
}

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
    Init {
        /// Generate a policy from the default events log (warden-events.jsonl).
        #[arg(long = "from-last-run", conflicts_with = "from_events")]
        from_last_run: bool,
        /// Generate a policy from a specific events log.
        #[arg(long = "from-events", value_name = "FILE")]
        from_events: Option<String>,
        /// Mode written into the generated policy (defaults to enforce).
        #[arg(long = "policy-mode", value_enum, default_value_t = CliMode::Enforce)]
        policy_mode: CliMode,
        /// Output path for the generated policy (defaults to warden.toml).
        #[arg(long = "output", value_name = "FILE", default_value = "warden.toml")]
        output: String,
    },
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
    /// Diagnose host prerequisites and configuration.
    Doctor,
    /// Install a prebuilt eBPF bundle into the default search path.
    Setup {
        /// Path to prebuilt.tar.gz bundle.
        #[arg(long = "bundle", value_name = "FILE")]
        bundle: Option<String>,
        /// Destination directory (defaults to XDG data dir cargo-warden/bpf).
        #[arg(long = "dest", value_name = "DIR")]
        dest: Option<String>,
        /// Replace an existing installation.
        #[arg(long = "force")]
        force: bool,
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

    let needs_privileges = matches!(command, Commands::Build { .. } | Commands::Run { .. });
    if needs_privileges {
        if let Err(err) = privileges::enforce_least_privilege() {
            eprintln!("privilege check failed: {err}");
            eprintln!(
                "Use a dedicated service user with CAP_SYS_ADMIN and, when available, CAP_BPF (see README for setup instructions)."
            );
            exit(1);
        }
    }

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
        Commands::Init {
            from_last_run,
            from_events,
            policy_mode,
            output,
        } => {
            let out = std::path::Path::new(&output);
            if from_last_run || from_events.is_some() {
                let events = from_events.as_deref().unwrap_or("warden-events.jsonl");
                if let Err(e) = commands::init::exec_from_events(
                    std::path::Path::new(events),
                    out,
                    Mode::from(policy_mode),
                ) {
                    eprintln!("init failed: {e}");
                    exit(1);
                }
            } else if let Err(e) = commands::init::exec_to(out) {
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
        Commands::Doctor => {
            if let Err(e) = commands::doctor::exec() {
                eprintln!("doctor failed: {e}");
                exit(1);
            }
        }
        Commands::Setup {
            bundle,
            dest,
            force,
        } => {
            let args = commands::setup::SetupArgs {
                bundle: bundle.map(std::path::PathBuf::from),
                dest: dest.map(std::path::PathBuf::from),
                force,
            };
            if let Err(e) = commands::setup::exec(args) {
                eprintln!("setup failed: {e}");
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
        let Commands::Build { args } = cli.command else {
            panic!("expected build command");
        };
        assert_eq!(args, vec!["--release".to_string()]);
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
        let Commands::Build { args } = cli.command else {
            panic!("expected build command");
        };
        assert_eq!(args, vec!["--verbose".to_string()]);
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
        let Commands::Build { args } = cli.command else {
            panic!("expected build command");
        };
        assert!(args.is_empty());
    }

    #[test]
    fn parse_metrics_port_flag() {
        let cli = Cli::parse_from(["cargo-warden", "build", "--metrics-port", "9898"]);
        assert_eq!(cli.metrics_port, Some(9898));
        assert!(matches!(cli.command, Commands::Build { .. }));
    }

    #[test]
    fn parse_mode_for_build() {
        let cli = Cli::parse_from(["cargo-warden", "--mode", "observe", "build"]);
        assert!(matches!(cli.mode, Some(CliMode::Observe)));
        let Commands::Build { args } = cli.command else {
            panic!("expected build command");
        };
        assert!(args.is_empty());
    }

    #[test]
    fn parse_status_command() {
        let cli = Cli::parse_from(["cargo-warden", "status"]);
        assert!(matches!(cli.command, Commands::Status));
    }

    #[test]
    fn parse_report_command() {
        let cli = Cli::parse_from(["cargo-warden", "report"]);
        assert!(matches!(cli.command, Commands::Report { .. }));
    }

    #[test]
    fn parse_report_defaults_to_text() {
        let cli = Cli::parse_from(["cargo-warden", "report"]);
        let Commands::Report { format, output } = cli.command else {
            panic!("expected report command");
        };
        assert!(matches!(format, CliReportFormat::Text));
        assert!(output.is_none());
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
        let Commands::Report { format, output } = cli.command else {
            panic!("expected report command");
        };
        assert!(matches!(format, CliReportFormat::Sarif));
        assert_eq!(output.as_deref(), Some("custom.sarif"));
    }

    #[test]
    fn parse_init_command() {
        let cli = Cli::parse_from(["cargo-warden", "init"]);
        assert!(matches!(cli.command, Commands::Init { .. }));
    }
}
