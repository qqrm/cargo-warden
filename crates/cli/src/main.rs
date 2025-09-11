use clap::{Parser, Subcommand};
use serde::Deserialize;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, exit};

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
    /// Export events to a SARIF report.
    Report {
        /// Output file for the SARIF report.
        #[arg(long = "output", value_name = "FILE", default_value = "warden.sarif")]
        output: String,
    },
}

#[derive(Debug, Deserialize)]
struct EventRecord {
    pid: u32,
    unit: u8,
    action: u8,
    verdict: u8,
    container_id: u64,
    caps: u64,
    path_or_addr: String,
}

impl std::fmt::Display for EventRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "pid={} unit={} action={} verdict={} container_id={} caps={} path_or_addr={}",
            self.pid,
            self.unit,
            self.action,
            self.verdict,
            self.container_id,
            self.caps,
            self.path_or_addr
        )
    }
}

fn sarif_from_events(events: &[EventRecord]) -> serde_json::Value {
    let results: Vec<_> = events
        .iter()
        .map(|e| {
            serde_json::json!({
                "ruleId": e.action.to_string(),
                "level": if e.verdict == 1 { "error" } else { "note" },
                "message": { "text": format!("{}", e) },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": e.path_or_addr }
                    }
                }]
            })
        })
        .collect();
    serde_json::json!({
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": { "name": "cargo-warden" } },
            "results": results
        }]
    })
}

fn export_sarif(events: &[EventRecord], path: &Path) -> io::Result<()> {
    let sarif = sarif_from_events(events);
    let content = serde_json::to_string_pretty(&sarif).map_err(io::Error::other)?;
    std::fs::write(path, content)
}

fn main() {
    let mut args: Vec<String> = std::env::args().collect();
    if args.get(1).map(|s| s == "warden").unwrap_or(false) {
        args.remove(1);
    }
    let cli = Cli::parse_from(args);
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
        Commands::Report { output } => {
            if let Err(e) = handle_report(&output) {
                eprintln!("report failed: {e}");
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
    use std::collections::HashSet;
    let mut deny = HashSet::new();
    for path in policy {
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
        deny.extend(policy.syscall.deny);
    }
    Ok(deny.into_iter().collect())
}

fn build_command(args: &[String]) -> Command {
    let mut cmd = Command::new("cargo");
    cmd.arg("build").args(args);
    cmd
}

fn read_recent_events(path: &Path, limit: usize) -> io::Result<Vec<EventRecord>> {
    if !path.exists() {
        return Ok(vec![]);
    }
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let lines: Vec<String> = reader.lines().collect::<Result<_, _>>()?;
    let start = lines.len().saturating_sub(limit);
    let mut events = Vec::new();
    for line in &lines[start..] {
        if let Ok(ev) = serde_json::from_str::<EventRecord>(line) {
            events.push(ev);
        }
    }
    Ok(events)
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
    let policy_path = Path::new("warden.toml");
    if policy_path.exists() {
        println!("active policy: {}", policy_path.display());
    } else {
        println!("active policy: none");
    }
    let events = read_recent_events(Path::new("warden-events.jsonl"), 10)?;
    if events.is_empty() {
        println!("recent events: none");
    } else {
        println!("recent events:");
        for e in events {
            println!("{}", e);
        }
    }
    Ok(())
}

fn handle_report(output: &str) -> io::Result<()> {
    let events = read_recent_events(Path::new("warden-events.jsonl"), usize::MAX)?;
    export_sarif(&events, Path::new(output))
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
    use super::{
        Cli, Commands, EventRecord, build_command, export_sarif, handle_init_with, handle_report,
        read_recent_events, run_command, setup_isolation,
    };
    use clap::{CommandFactory, Parser};
    use std::ffi::OsStr;
    use std::fs::File;
    use std::io::{Cursor, Write};

    use tempfile::{NamedTempFile, tempdir};

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
        match cli.command {
            Commands::Build { args } => {
                assert!(args.is_empty());
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
    fn parse_report_command() {
        let cli = Cli::parse_from(["cargo-warden", "report"]);
        match cli.command {
            Commands::Report { .. } => {}
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

    #[test]
    fn read_recent_events_reads_log() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        let mut file = File::create(&path).unwrap();
        writeln!(
            file,
            "{}",
            serde_json::json!({
                "pid": 1,
                "unit": 0,
                "action": 3,
                "verdict": 0,
                "container_id": 0,
                "caps": 0,
                "path_or_addr": "/bin/echo"
            })
        )
        .unwrap();
        writeln!(
            file,
            "{}",
            serde_json::json!({
                "pid": 2,
                "unit": 0,
                "action": 4,
                "verdict": 1,
                "container_id": 0,
                "caps": 0,
                "path_or_addr": "1.2.3.4:80"
            })
        )
        .unwrap();
        let events = read_recent_events(&path, 10).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].pid, 1);
        assert_eq!(events[1].verdict, 1);
    }

    #[test]
    fn exports_sarif_file() {
        let record = EventRecord {
            pid: 2,
            unit: 0,
            action: 3,
            verdict: 1,
            container_id: 0,
            caps: 0,
            path_or_addr: "/bin/bad".into(),
        };
        let tmp = NamedTempFile::new().unwrap();
        export_sarif(std::slice::from_ref(&record), tmp.path()).unwrap();
        let content = std::fs::read_to_string(tmp.path()).unwrap();
        assert!(content.contains("\"version\": \"2.1.0\""));
        assert!(content.contains(&record.path_or_addr));
    }

    #[test]
    fn report_creates_empty_file() {
        let dir = tempdir().unwrap();
        let old_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();

        File::create("warden-events.jsonl").unwrap();
        handle_report("out.sarif").unwrap();
        assert!(dir.path().join("out.sarif").exists());

        std::env::set_current_dir(old_dir).unwrap();
    }

    #[test]
    fn setup_isolation_merges_syscalls() {
        use std::fs::write;
        let dir = tempdir().unwrap();
        let p1 = dir.path().join("p1.toml");
        let p2 = dir.path().join("p2.toml");
        write(&p1, "mode = \"enforce\"\n[syscall]\ndeny = [\"clone\"]").unwrap();
        write(&p2, "mode = \"enforce\"\n[syscall]\ndeny = [\"execve\"]").unwrap();
        let paths = [p1.to_str().unwrap().into(), p2.to_str().unwrap().into()];
        let deny = setup_isolation(&[], &paths).unwrap();
        assert!(deny.contains(&"clone".to_string()));
        assert!(deny.contains(&"execve".to_string()));
        assert_eq!(deny.len(), 2);
    }
}
