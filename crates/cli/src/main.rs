use bpf_api::{FS_READ, FS_WRITE, FsRule, FsRuleEntry};
use cargo_metadata::MetadataCommand;
use clap::{Parser, Subcommand, ValueEnum};
use policy_core::{ExecDefault, FsDefault, Mode, NetDefault, Permission, Policy};
use qqrm_policy_compiler::{self, MapsLayout};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, exit};

mod sandbox;

use sandbox::Sandbox;

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

struct IsolationConfig {
    #[cfg(test)]
    mode: Mode,
    syscall_deny: Vec<String>,
    maps_layout: MapsLayout,
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
    let status = run_in_sandbox(build_command(&args), &isolation)?;
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

    let mut layout = qqrm_policy_compiler::compile(&policy)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;

    if policy.fs_default() == FsDefault::Strict {
        let cargo_dirs = discover_cargo_directories()?;
        let implicit_paths = implicit_fs_permissions(&cargo_dirs);
        merge_fs_rules_with_implicit(&mut layout, &implicit_paths)?;
    }

    Ok(IsolationConfig {
        #[cfg(test)]
        mode: policy.mode,
        syscall_deny: policy.syscall_deny().cloned().collect(),
        maps_layout: layout,
    })
}

struct CargoDirectories {
    workspace: PathBuf,
    target: PathBuf,
    out_dir: Option<PathBuf>,
}

fn discover_cargo_directories() -> io::Result<CargoDirectories> {
    let metadata = MetadataCommand::new()
        .no_deps()
        .exec()
        .map_err(io::Error::other)
        .ok();
    let workspace = metadata
        .as_ref()
        .map(|meta| PathBuf::from(meta.workspace_root.clone()))
        .unwrap_or(std::env::current_dir()?);

    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .or_else(|| {
            metadata
                .as_ref()
                .map(|meta| meta.target_directory.clone().into_std_path_buf())
        })
        .unwrap_or_else(|| workspace.join("target"));
    let target = absolutize_path(target, &workspace);

    let out_dir = std::env::var_os("OUT_DIR")
        .map(PathBuf::from)
        .map(|dir| absolutize_path(dir, &workspace));

    Ok(CargoDirectories {
        workspace,
        target,
        out_dir,
    })
}

fn absolutize_path(path: PathBuf, base: &Path) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        base.join(path)
    }
}

fn implicit_fs_permissions(dirs: &CargoDirectories) -> Vec<(PathBuf, u8)> {
    let mut entries = vec![
        (dirs.workspace.clone(), FS_READ),
        (dirs.target.clone(), FS_READ | FS_WRITE),
    ];
    if let Some(out_dir) = &dirs.out_dir {
        entries.push((out_dir.clone(), FS_READ | FS_WRITE));
    }
    entries
}

fn merge_fs_rules_with_implicit(
    layout: &mut MapsLayout,
    implicit: &[(PathBuf, u8)],
) -> io::Result<()> {
    let mut merged = Vec::new();
    let mut index: HashMap<(u32, [u8; 256]), usize> = HashMap::new();

    for entry in layout.fs_rules.drain(..) {
        insert_fs_rule(&mut merged, &mut index, entry);
    }

    let mut units: Vec<u32> = merged.iter().map(|entry| entry.unit).collect();
    if !units.contains(&0) {
        units.push(0);
    }
    units.sort_unstable();
    units.dedup();

    for &unit in &units {
        for (path, access) in implicit {
            let entry = fs_rule_entry_from_path(unit, path, *access)?;
            insert_fs_rule(&mut merged, &mut index, entry);
        }
    }

    layout.fs_rules = merged;
    Ok(())
}

fn insert_fs_rule(
    entries: &mut Vec<FsRuleEntry>,
    index: &mut HashMap<(u32, [u8; 256]), usize>,
    entry: FsRuleEntry,
) {
    let key = (entry.unit, entry.rule.path);
    if let Some(position) = index.get(&key) {
        entries[*position].rule.access |= entry.rule.access;
    } else {
        index.insert(key, entries.len());
        entries.push(entry);
    }
}

fn fs_rule_entry_from_path(unit: u32, path: &Path, access: u8) -> io::Result<FsRuleEntry> {
    let path_str = path.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("filesystem path contains invalid UTF-8: {}", path.display()),
        )
    })?;
    let encoded = qqrm_policy_compiler::encode_fs_path(path_str).map_err(io::Error::other)?;
    Ok(FsRuleEntry {
        unit,
        rule: FsRule {
            access,
            reserved: [0; 3],
            path: encoded,
        },
    })
}

fn load_default_policy() -> io::Result<Policy> {
    let path = Path::new("warden.toml");
    match std::fs::read_to_string(path) {
        Ok(text) => parse_policy_from_str(path, &text),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(empty_policy()),
        Err(err) => Err(err),
    }
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
    let status = run_in_sandbox(run_command(&cmd), &isolation)?;
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

fn run_in_sandbox(command: Command, isolation: &IsolationConfig) -> io::Result<ExitStatus> {
    let mut sandbox = Sandbox::new()?;
    let run_result = sandbox.run(command, &isolation.syscall_deny, &isolation.maps_layout);
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

#[cfg(not(test))]
pub(crate) fn apply_seccomp(deny: &[String]) -> io::Result<()> {
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
pub(crate) fn apply_seccomp(_deny: &[String]) -> io::Result<()> {
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
    use bpf_api::{FS_READ, FS_WRITE};
    use clap::{CommandFactory, Parser};
    use policy_core::{ExecDefault, FsDefault, Mode, NetDefault, Policy};
    use serial_test::serial;
    use std::ffi::{OsStr, OsString};
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

    struct EnvGuard {
        key: String,
        original: Option<OsString>,
    }

    impl EnvGuard {
        fn set(key: &str, value: &OsStr) -> Self {
            let original = std::env::var_os(key);
            unsafe {
                std::env::set_var(key, value);
            }
            Self {
                key: key.to_string(),
                original,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(value) = self.original.take() {
                unsafe {
                    std::env::set_var(&self.key, value);
                }
            } else {
                unsafe {
                    std::env::remove_var(&self.key);
                }
            }
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

    fn fs_rules(layout: &MapsLayout) -> Vec<(u32, String, u8)> {
        layout
            .fs_rules
            .iter()
            .map(|entry| {
                let len = entry
                    .rule
                    .path
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(entry.rule.path.len());
                (
                    entry.unit,
                    String::from_utf8_lossy(&entry.rule.path[..len]).into_owned(),
                    entry.rule.access,
                )
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

        let exec = exec_paths(&isolation.maps_layout);
        assert_eq!(exec, vec!["/bin/bash".to_string()]);
    }

    #[test]
    #[serial]
    fn setup_isolation_includes_cargo_directories() {
        let dir = tempdir().unwrap();
        let _guard = DirGuard::change_to(dir.path());

        std::fs::write(
            "Cargo.toml",
            r#"[package]
name = "sample"
version = "0.1.0"
edition = "2021"
"#,
        )
        .unwrap();
        std::fs::create_dir_all("src").unwrap();
        std::fs::write("src/lib.rs", "pub fn dummy() {}\n").unwrap();

        let target_dir = dir.path().join("custom-target");
        let out_dir = dir.path().join("custom-target/build-out");
        let _target_guard = EnvGuard::set("CARGO_TARGET_DIR", target_dir.as_os_str());
        let _out_guard = EnvGuard::set("OUT_DIR", out_dir.as_os_str());

        let isolation = setup_isolation(&[], &[], None).unwrap();
        let rules = fs_rules(&isolation.maps_layout);

        let workspace = dir.path().to_string_lossy().to_string();
        assert!(
            rules
                .iter()
                .any(|(unit, path, access)| *unit == 0 && path == &workspace && *access == FS_READ)
        );

        let target_path = target_dir.to_string_lossy().to_string();
        assert!(rules.iter().any(|(unit, path, access)| {
            *unit == 0
                && path == &target_path
                && (*access & (FS_READ | FS_WRITE)) == (FS_READ | FS_WRITE)
        }));

        let out_path = out_dir.to_string_lossy().to_string();
        assert!(rules.iter().any(|(unit, path, access)| {
            *unit == 0
                && path == &out_path
                && (*access & (FS_READ | FS_WRITE)) == (FS_READ | FS_WRITE)
        }));
    }

    #[test]
    #[serial]
    fn implicit_permissions_merge_with_policy_entries() {
        let dir = tempdir().unwrap();
        let _guard = DirGuard::change_to(dir.path());

        std::fs::write(
            "Cargo.toml",
            r#"[package]
name = "sample"
version = "0.1.0"
edition = "2021"
"#,
        )
        .unwrap();
        std::fs::create_dir_all("src").unwrap();
        std::fs::write("src/lib.rs", "pub fn dummy() {}\n").unwrap();

        let target_dir = dir.path().join("custom-target");
        let _target_guard = EnvGuard::set("CARGO_TARGET_DIR", target_dir.as_os_str());

        let target_toml = target_dir.to_str().unwrap().replace('\\', "\\\\");
        std::fs::write(
            "warden.toml",
            format!(
                r#"mode = "enforce"
fs.default = "strict"
net.default = "deny"
exec.default = "allowlist"

[allow.fs]
write_extra = ["{path}"]
read_extra = []
"#,
                path = target_toml
            ),
        )
        .unwrap();

        let isolation = setup_isolation(&[], &[], None).unwrap();
        let rules = fs_rules(&isolation.maps_layout);

        let target_path = target_dir.to_string_lossy().to_string();
        let matches: Vec<_> = rules
            .iter()
            .filter(|(_, path, _)| path == &target_path)
            .collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].2 & (FS_READ | FS_WRITE), FS_READ | FS_WRITE);
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
