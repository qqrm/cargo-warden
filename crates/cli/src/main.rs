use clap::{Parser, Subcommand, ValueEnum};
use event_reporting::{EventRecord, export_sarif};
use policy_core::{ExecDefault, FsDefault, Mode, NetDefault, Permission, Policy, WorkspacePolicy};
use qqrm_policy_compiler::{self, MapsLayout};
use serde::Deserialize;
use std::collections::HashSet;
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, exit};

use sandbox_runtime::Sandbox;

#[derive(Copy, Clone, Debug, ValueEnum)]
enum CliMode {
    Observe,
    Enforce,
}

impl From<CliMode> for Mode {
    fn from(mode: CliMode) -> Self {
        match mode {
            CliMode::Observe => Mode::Observe,
            CliMode::Enforce => Mode::Enforce,
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

struct IsolationConfig {
    mode: Mode,
    syscall_deny: Vec<String>,
    maps_layout: MapsLayout,
}

fn main() {
    let mut args: Vec<String> = std::env::args().collect();
    if args.get(1).map(|s| s == "warden").unwrap_or(false) {
        args.remove(1);
    }
    let cli = Cli::parse_from(args);
    match cli.command {
        Commands::Build { args } => {
            if let Err(e) = handle_build(args, &cli.allow, &cli.policy, cli.mode.map(Mode::from)) {
                eprintln!("build failed: {e}");
                exit(1);
            }
        }
        Commands::Run { cmd } => {
            if let Err(e) = handle_run(cmd, &cli.allow, &cli.policy, cli.mode.map(Mode::from)) {
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

fn handle_build(
    args: Vec<String>,
    allow: &[String],
    policy: &[String],
    mode_override: Option<Mode>,
) -> io::Result<()> {
    let isolation = setup_isolation(allow, policy, mode_override)?;
    let status = run_in_sandbox(build_command(&args), isolation.mode, &isolation)?;
    if !status.success() {
        exit(status.code().unwrap_or(1));
    }
    Ok(())
}

fn setup_isolation(
    allow: &[String],
    policy_paths: &[String],
    mode_override: Option<Mode>,
) -> io::Result<IsolationConfig> {
    let mut policy = load_default_policy()?;
    for path in policy_paths {
        let extra = load_policy(Path::new(path))?;
        merge_policy(&mut policy, extra);
    }
    policy
        .rules
        .extend(allow.iter().cloned().map(Permission::Exec));
    if let Some(mode) = mode_override {
        policy.mode = mode;
    }
    dedup_policy_lists(&mut policy);

    let report = policy.validate();
    if !report.errors.is_empty() {
        let message = report
            .errors
            .into_iter()
            .map(|err| err.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(io::Error::new(io::ErrorKind::InvalidInput, message));
    }
    for warn in report.warnings {
        eprintln!("warning: {warn}");
    }

    let layout = qqrm_policy_compiler::compile(&policy)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;

    Ok(IsolationConfig {
        mode: policy.mode,
        syscall_deny: policy.syscall_deny().cloned().collect(),
        maps_layout: layout,
    })
}

fn load_default_policy() -> io::Result<Policy> {
    if let Some(policy) = load_workspace_policy()? {
        return Ok(policy);
    }
    let path = Path::new("warden.toml");
    match std::fs::read_to_string(path) {
        Ok(text) => parse_policy_from_str(path, &text),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(empty_policy()),
        Err(err) => Err(err),
    }
}

fn load_workspace_policy() -> io::Result<Option<Policy>> {
    let path = Path::new("workspace.warden.toml");
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    let workspace: WorkspacePolicy = toml::from_str(&text).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{}: {err}", path.display()),
        )
    })?;
    let member = determine_active_workspace_member()?;
    let policy = match member {
        Some(member) => workspace.policy_for(&member),
        None => workspace.root.clone(),
    };
    Ok(Some(policy))
}

fn load_policy(path: &Path) -> io::Result<Policy> {
    let text = std::fs::read_to_string(path)?;
    parse_policy_from_str(path, &text)
}

fn parse_policy_from_str(path: &Path, text: &str) -> io::Result<Policy> {
    Policy::from_toml_str(text).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{}: {err}", path.display()),
        )
    })
}

fn determine_active_workspace_member() -> io::Result<Option<String>> {
    if let Some(from_env) = workspace_member_from_env() {
        return Ok(Some(from_env));
    }
    let metadata = load_cargo_metadata()?;
    workspace_member_from_dir(&metadata)
}

fn workspace_member_from_env() -> Option<String> {
    const VARS: [&str; 2] = ["CARGO_PRIMARY_PACKAGE", "CARGO_PKG_NAME"];
    for var in VARS {
        if let Ok(value) = std::env::var(var)
            && let Some(name) = parse_workspace_member_value(&value)
        {
            return Some(name);
        }
    }
    None
}

fn parse_workspace_member_value(value: &str) -> Option<String> {
    let candidate = value
        .split(|c: char| c.is_ascii_whitespace() || matches!(c, ';' | ','))
        .find(|part| !part.is_empty())?
        .trim();
    if candidate.is_empty() {
        return None;
    }
    if let Some((_, fragment)) = candidate.rsplit_once('#') {
        let name = fragment.split('@').next().unwrap_or(fragment).trim();
        if !name.is_empty() {
            return Some(name.to_string());
        }
    }
    if let Some((name, _)) = candidate.split_once('@') {
        let trimmed = name.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    Some(candidate.to_string())
}

fn load_cargo_metadata() -> io::Result<CargoMetadata> {
    let cargo: OsString = std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let output = Command::new(cargo)
        .arg("metadata")
        .arg("--no-deps")
        .arg("--format-version=1")
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(io::Error::other(format!("cargo metadata failed: {stderr}")));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

fn workspace_member_from_dir(metadata: &CargoMetadata) -> io::Result<Option<String>> {
    let member_ids: HashSet<&str> = metadata
        .workspace_members
        .iter()
        .map(String::as_str)
        .collect();
    let cwd = std::env::current_dir()?;
    let canonical_cwd = cwd.canonicalize().unwrap_or(cwd);
    let mut best_match: Option<(String, usize, bool)> = None;

    for pkg in &metadata.packages {
        if !member_ids.contains(pkg.id.as_str()) {
            continue;
        }
        let manifest_path = PathBuf::from(&pkg.manifest_path);
        let Some(manifest_dir) = manifest_path.parent() else {
            continue;
        };
        let canonical_dir = manifest_dir
            .canonicalize()
            .unwrap_or_else(|_| manifest_dir.to_path_buf());
        if !canonical_cwd.starts_with(&canonical_dir) {
            continue;
        }
        let exact = canonical_cwd == canonical_dir;
        let depth = canonical_dir.components().count();
        if let Some((_, current_depth, current_exact)) = &mut best_match
            && ((*current_exact && !exact) || (*current_exact == exact && *current_depth >= depth))
        {
            continue;
        }
        best_match = Some((pkg.name.clone(), depth, exact));
    }

    Ok(best_match.map(|(name, _, _)| name))
}

#[derive(Deserialize)]
struct CargoMetadata {
    packages: Vec<CargoPackage>,
    workspace_members: Vec<String>,
}

#[derive(Deserialize)]
struct CargoPackage {
    id: String,
    name: String,
    manifest_path: PathBuf,
}

fn merge_policy(base: &mut Policy, extra: Policy) {
    let Policy { mode, mut rules } = extra;
    base.mode = mode;
    base.rules.append(&mut rules);
}

fn dedup_policy_lists(policy: &mut Policy) {
    use Permission::*;

    let mut keep = vec![true; policy.rules.len()];

    let mut seen_exec: HashSet<&String> = HashSet::new();
    let mut seen_net: HashSet<&String> = HashSet::new();
    let mut seen_fs_write: HashSet<&std::path::PathBuf> = HashSet::new();
    let mut seen_fs_read: HashSet<&std::path::PathBuf> = HashSet::new();
    let mut seen_syscall: HashSet<&String> = HashSet::new();
    let mut seen_env: HashSet<&String> = HashSet::new();

    // Walk from the end so the last override of each rule type wins while we keep
    // the rules in their original order.
    for (index, perm) in policy.rules.iter().enumerate().rev() {
        let should_keep = match perm {
            Exec(path) => seen_exec.insert(path),
            NetConnect(host) => seen_net.insert(host),
            FsWrite(path) => seen_fs_write.insert(path),
            FsRead(path) => seen_fs_read.insert(path),
            SyscallDeny(name) => seen_syscall.insert(name),
            EnvRead(name) => seen_env.insert(name),
            _ => true,
        };

        if !should_keep {
            keep[index] = false;
        }
    }

    let mut idx = 0;
    policy.rules.retain(|_| {
        let retain = keep[idx];
        idx += 1;
        retain
    });
}

fn empty_policy() -> Policy {
    Policy {
        mode: Mode::Enforce,
        rules: vec![
            Permission::FsDefault(FsDefault::Strict),
            Permission::NetDefault(NetDefault::Deny),
            Permission::ExecDefault(ExecDefault::Allowlist),
        ],
    }
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

fn handle_run(
    cmd: Vec<String>,
    allow: &[String],
    policy: &[String],
    mode_override: Option<Mode>,
) -> io::Result<()> {
    if cmd.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing command",
        ));
    }
    let isolation = setup_isolation(allow, policy, mode_override)?;
    let status = run_in_sandbox(run_command(&cmd), isolation.mode, &isolation)?;
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

fn run_in_sandbox(
    command: Command,
    mode: Mode,
    isolation: &IsolationConfig,
) -> io::Result<ExitStatus> {
    let mut sandbox = Sandbox::new()?;
    let run_result = sandbox.run(
        command,
        mode,
        &isolation.syscall_deny,
        &isolation.maps_layout,
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
    writeln!(
        output,
        "Enter allowed executables for [allow.exec] (comma separated, leave blank for none):",
    )?;
    let mut line = String::new();
    input.read_line(&mut line)?;
    let entries: Vec<String> = line
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let allowed = toml::Value::Array(entries.iter().cloned().map(toml::Value::String).collect());
    let content = format!(
        "mode = \"enforce\"\n\
         fs.default = \"strict\"\n\
         net.default = \"deny\"\n\
         exec.default = \"allowlist\"\n\
         \n\
         [allow.exec]\n\
         allowed = {}\n\
         \n\
         [allow.net]\n\
         hosts = []\n\
         \n\
         [allow.fs]\n\
         write_extra = []\n\
         read_extra = []\n",
        allowed
    );
    std::fs::write(path, content)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        Cli, CliMode, Commands, EventRecord, build_command, export_sarif, handle_init_with,
        handle_report, read_recent_events, run_command, setup_isolation,
    };
    use clap::{CommandFactory, Parser};
    use policy_core::{ExecDefault, FsDefault, Mode, NetDefault, Policy};
    use serial_test::serial;
    use std::ffi::OsStr;
    use std::fs::File;
    use std::io::{Cursor, Write};
    use std::path::{Path, PathBuf};

    use qqrm_policy_compiler::MapsLayout;

    use tempfile::{NamedTempFile, tempdir};

    struct DirGuard {
        original: PathBuf,
    }

    impl DirGuard {
        fn change_to(path: &Path) -> Self {
            let original = std::env::current_dir().unwrap();
            std::env::set_current_dir(path).unwrap();
            Self { original }
        }
    }

    impl Drop for DirGuard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.original);
        }
    }

    fn exec_paths(layout: &MapsLayout) -> Vec<String> {
        layout
            .exec_allowlist
            .iter()
            .map(|entry| {
                let len = entry
                    .path
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(entry.path.len());
                String::from_utf8_lossy(&entry.path[..len]).into_owned()
            })
            .collect()
    }

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
    #[serial]
    fn handle_init_creates_file_and_prompts() {
        let dir = tempdir().unwrap();
        let _guard = DirGuard::change_to(dir.path());

        let input_data = "foo, bar\n";
        let mut input = Cursor::new(input_data.as_bytes());
        let mut output = Vec::new();

        handle_init_with(&mut input, &mut output).unwrap();

        let config_path = dir.path().join("warden.toml");
        let config = std::fs::read_to_string(&config_path).unwrap();

        let out_str = String::from_utf8(output).unwrap();
        assert!(out_str.contains(
            "Enter allowed executables for [allow.exec] (comma separated, leave blank for none):"
        ));

        assert!(config.contains("mode = \"enforce\""));
        assert!(config.contains("fs.default = \"strict\""));
        assert!(config.contains("net.default = \"deny\""));
        assert!(config.contains("exec.default = \"allowlist\""));

        let policy = Policy::from_toml_str(&config).unwrap();
        assert_eq!(policy.mode, Mode::Enforce);
        assert_eq!(policy.fs_default(), FsDefault::Strict);
        assert_eq!(policy.net_default(), NetDefault::Deny);
        assert_eq!(policy.exec_default(), ExecDefault::Allowlist);
        let exec_allowed: Vec<_> = policy.exec_allowed().cloned().collect();
        assert_eq!(exec_allowed, ["foo", "bar"]);
        assert!(policy.net_hosts().next().is_none());
        assert!(policy.fs_write_paths().next().is_none());
        assert!(policy.fs_read_paths().next().is_none());
    }

    #[test]
    #[serial]
    fn handle_init_produces_parseable_policy() {
        let dir = tempdir().unwrap();
        let _guard = DirGuard::change_to(dir.path());

        let mut input = Cursor::new(b"\n" as &[u8]);
        let mut output = Vec::new();

        handle_init_with(&mut input, &mut output).unwrap();

        let config_path = dir.path().join("warden.toml");
        let config = std::fs::read_to_string(&config_path).unwrap();
        Policy::from_toml_str(&config).unwrap();
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
    #[serial]
    fn report_creates_empty_file() {
        let dir = tempdir().unwrap();
        let _guard = DirGuard::change_to(dir.path());

        File::create("warden-events.jsonl").unwrap();
        handle_report("out.sarif").unwrap();
        assert!(dir.path().join("out.sarif").exists());
    }

    #[test]
    #[serial]
    fn setup_isolation_merges_syscalls_and_allow_entries() {
        use std::fs::write;
        let dir = tempdir().unwrap();
        let _guard = DirGuard::change_to(dir.path());

        write(
            "warden.toml",
            r#"mode = "enforce"
fs.default = "strict"
net.default = "deny"
exec.default = "allowlist"

[allow.exec]
allowed = ["/usr/bin/rustc"]
"#,
        )
        .unwrap();

        let p1 = dir.path().join("p1.toml");
        write(
            &p1,
            r#"mode = "enforce"
fs.default = "strict"
net.default = "deny"
exec.default = "allowlist"

[syscall]
deny = ["clone"]

[allow.exec]
allowed = ["/bin/bash"]
"#,
        )
        .unwrap();

        let p2 = dir.path().join("p2.toml");
        write(
            &p2,
            r#"mode = "enforce"
fs.default = "strict"
net.default = "deny"
exec.default = "allowlist"

[syscall]
deny = ["execve"]
"#,
        )
        .unwrap();

        let paths = [p1.to_str().unwrap().into(), p2.to_str().unwrap().into()];
        let allow = vec!["/usr/bin/rustc".to_string(), "/usr/bin/git".to_string()];
        let isolation = setup_isolation(&allow, &paths, None).unwrap();

        assert_eq!(isolation.mode, Mode::Enforce);
        assert!(isolation.syscall_deny.contains(&"clone".to_string()));
        assert!(isolation.syscall_deny.contains(&"execve".to_string()));
        assert_eq!(isolation.syscall_deny.len(), 2);

        let exec = exec_paths(&isolation.maps_layout);
        assert!(exec.contains(&"/usr/bin/rustc".to_string()));
        assert!(exec.contains(&"/bin/bash".to_string()));
        assert!(exec.contains(&"/usr/bin/git".to_string()));
        assert_eq!(exec.len(), 3);
    }

    #[test]
    #[serial]
    fn setup_isolation_defaults_to_empty_policy() {
        let dir = tempdir().unwrap();
        let _guard = DirGuard::change_to(dir.path());

        let isolation = setup_isolation(&[], &[], None).unwrap();

        assert_eq!(isolation.mode, Mode::Enforce);
        assert!(isolation.syscall_deny.is_empty());
        assert!(isolation.maps_layout.exec_allowlist.is_empty());
        assert!(isolation.maps_layout.net_rules.is_empty());
    }

    #[test]
    #[serial]
    fn setup_isolation_uses_cli_allow_when_no_file() {
        let dir = tempdir().unwrap();
        let _guard = DirGuard::change_to(dir.path());

        let allow = vec!["/bin/bash".to_string()];
        let isolation = setup_isolation(&allow, &[], None).unwrap();

        assert_eq!(isolation.mode, Mode::Enforce);
        let exec = exec_paths(&isolation.maps_layout);
        assert_eq!(exec, vec!["/bin/bash".to_string()]);
    }

    #[test]
    #[serial]
    fn setup_isolation_applies_mode_override() {
        use std::fs::write;

        let dir = tempdir().unwrap();
        let _guard = DirGuard::change_to(dir.path());

        write(
            "warden.toml",
            r#"mode = "enforce"
fs.default = "unrestricted"
net.default = "allow"
exec.default = "allow"
"#,
        )
        .unwrap();

        let isolation = setup_isolation(&[], &[], Some(Mode::Observe)).unwrap();

        assert_eq!(isolation.mode, Mode::Observe);
        assert!(isolation.maps_layout.exec_allowlist.is_empty());
        assert!(isolation.maps_layout.net_rules.is_empty());
        assert!(isolation.maps_layout.fs_rules.is_empty());
    }
}
