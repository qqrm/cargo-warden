use policy_core::{FsDefault, Mode, Policy, WorkspacePolicy};
use qqrm_policy_compiler::{self, CompiledPolicy, MapsLayout};
use serde::Deserialize;
use std::collections::HashSet;
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

pub(crate) struct IsolationConfig {
    pub(crate) mode: Mode,
    pub(crate) syscall_deny: Vec<String>,
    pub(crate) maps_layout: MapsLayout,
    pub(crate) allowed_env_vars: Vec<String>,
}

pub(crate) fn setup_isolation(
    allow: &[String],
    policy_paths: &[String],
    mode_override: Option<Mode>,
) -> io::Result<IsolationConfig> {
    let mut policy = load_default_policy()?;
    for path in policy_paths {
        let extra = load_policy(Path::new(path))?;
        merge_policy(&mut policy, extra);
    }
    policy.extend_exec_allowed(allow.iter().cloned());
    extend_fs_access(&mut policy)?;
    if let Some(mode) = mode_override {
        policy.mode = mode;
    }

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

    let compiled = qqrm_policy_compiler::compile(&policy)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    let CompiledPolicy {
        maps_layout,
        allowed_env_vars,
    } = compiled;

    Ok(IsolationConfig {
        mode: policy.mode,
        syscall_deny: policy.syscall_deny().cloned().collect(),
        maps_layout,
        allowed_env_vars,
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
    let Some(path) = find_workspace_file("workspace.warden.toml")? else {
        return Ok(None);
    };
    let text = std::fs::read_to_string(&path)?;
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

fn find_workspace_file(name: &str) -> io::Result<Option<PathBuf>> {
    let mut dir = std::env::current_dir()?;
    loop {
        let candidate = dir.join(name);
        match std::fs::metadata(&candidate) {
            Ok(meta) => {
                if meta.is_file() {
                    return Ok(Some(candidate));
                }
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
        if !dir.pop() {
            break;
        }
    }
    Ok(None)
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
    if let Ok(value) = std::env::var("CARGO_PRIMARY_PACKAGE") {
        parse_workspace_member_value(&value)
    } else {
        None
    }
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

fn extend_fs_access(policy: &mut Policy) -> io::Result<()> {
    if policy.fs_default() != FsDefault::Strict {
        return Ok(());
    }

    let metadata = load_cargo_metadata()?;
    maybe_extend_fs_read(policy, &metadata.workspace_root);
    maybe_extend_fs_write(policy, &metadata.target_directory);

    Ok(())
}

fn maybe_extend_fs_read(policy: &mut Policy, path: &Path) {
    let normalized = normalize_path(path);
    if !contains_path(policy.fs_read_paths(), &normalized) {
        policy.extend_fs_reads(std::iter::once(normalized));
    }
}

fn maybe_extend_fs_write(policy: &mut Policy, path: &Path) {
    let normalized = normalize_path(path);
    if !contains_path(policy.fs_write_paths(), &normalized) {
        policy.extend_fs_writes(std::iter::once(normalized));
    }
}

fn normalize_path(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn contains_path<'a>(paths: impl Iterator<Item = &'a PathBuf>, candidate: &Path) -> bool {
    let candidate_canon = std::fs::canonicalize(candidate).ok();
    for existing in paths {
        if existing.as_path() == candidate {
            return true;
        }
        if let Some(ref canon) = candidate_canon
            && existing.as_path() == canon.as_path()
        {
            return true;
        }
        if let Ok(existing_canon) = std::fs::canonicalize(existing) {
            if existing_canon == candidate {
                return true;
            }
            if let Some(ref canon) = candidate_canon
                && existing_canon == canon.as_path()
            {
                return true;
            }
        }
    }
    false
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

fn merge_policy(base: &mut Policy, extra: Policy) {
    base.merge(extra);
}

fn empty_policy() -> Policy {
    Policy::new(Mode::Enforce)
}

#[derive(Deserialize)]
struct CargoMetadata {
    packages: Vec<CargoPackage>,
    workspace_members: Vec<String>,
    workspace_root: PathBuf,
    target_directory: PathBuf,
}

#[derive(Deserialize)]
struct CargoPackage {
    id: String,
    name: String,
    manifest_path: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bpf_api::{FS_READ, FS_WRITE};
    use serial_test::serial;
    use std::fs::{self, write};
    use std::path::Path;

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

    fn fs_entries(layout: &MapsLayout) -> Vec<(String, u8)> {
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
                let path = String::from_utf8_lossy(&entry.rule.path[..len]).into_owned();
                (path, entry.rule.access)
            })
            .collect()
    }

    fn init_cargo_package(dir: &Path) {
        write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        fs::create_dir_all(dir.join("src")).unwrap();
        write(dir.join("src/lib.rs"), "pub fn fixture() {}\n").unwrap();
    }

    #[test]
    #[serial]
    fn setup_isolation_merges_syscalls_and_allow_entries() {
        let dir = tempfile::tempdir().unwrap();
        let _guard = crate::test_support::DirGuard::change_to(dir.path());
        init_cargo_package(dir.path());

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
        let allow = vec!["/usr/bin/git".to_string()];
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

        let metadata = super::load_cargo_metadata().unwrap();
        let workspace = super::normalize_path(&metadata.workspace_root);
        let target = super::normalize_path(&metadata.target_directory);
        let fs_rules = fs_entries(&isolation.maps_layout);
        assert!(
            fs_rules
                .iter()
                .any(|(path, access)| path == &workspace.to_string_lossy() && *access == FS_READ)
        );
        assert!(fs_rules.iter().any(|(path, access)| {
            path == &target.to_string_lossy() && *access == (FS_READ | FS_WRITE)
        }));
        assert_eq!(fs_rules.len(), 2);
    }

    #[test]
    #[serial]
    fn setup_isolation_defaults_to_empty_policy() {
        let dir = tempfile::tempdir().unwrap();
        let _guard = crate::test_support::DirGuard::change_to(dir.path());
        init_cargo_package(dir.path());

        let isolation = setup_isolation(&[], &[], None).unwrap();

        assert_eq!(isolation.mode, Mode::Enforce);
        assert!(isolation.syscall_deny.is_empty());
        assert!(isolation.maps_layout.exec_allowlist.is_empty());
        assert!(isolation.maps_layout.net_rules.is_empty());

        let metadata = super::load_cargo_metadata().unwrap();
        let workspace = super::normalize_path(&metadata.workspace_root);
        let target = super::normalize_path(&metadata.target_directory);
        let fs_rules = fs_entries(&isolation.maps_layout);
        assert!(
            fs_rules
                .iter()
                .any(|(path, access)| path == &workspace.to_string_lossy() && *access == FS_READ)
        );
        assert!(fs_rules.iter().any(|(path, access)| {
            path == &target.to_string_lossy() && *access == (FS_READ | FS_WRITE)
        }));
        assert_eq!(fs_rules.len(), 2);
    }

    #[test]
    #[serial]
    fn setup_isolation_uses_cli_allow_when_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let _guard = crate::test_support::DirGuard::change_to(dir.path());
        init_cargo_package(dir.path());

        let allow = vec!["/bin/bash".to_string()];
        let isolation = setup_isolation(&allow, &[], None).unwrap();

        assert_eq!(isolation.mode, Mode::Enforce);
        let exec = exec_paths(&isolation.maps_layout);
        assert_eq!(exec, vec!["/bin/bash".to_string()]);

        let metadata = super::load_cargo_metadata().unwrap();
        let workspace = super::normalize_path(&metadata.workspace_root);
        let target = super::normalize_path(&metadata.target_directory);
        let fs_rules = fs_entries(&isolation.maps_layout);
        assert!(
            fs_rules
                .iter()
                .any(|(path, access)| path == &workspace.to_string_lossy() && *access == FS_READ)
        );
        assert!(fs_rules.iter().any(|(path, access)| {
            path == &target.to_string_lossy() && *access == (FS_READ | FS_WRITE)
        }));
        assert_eq!(fs_rules.len(), 2);
    }

    #[test]
    #[serial]
    fn setup_isolation_applies_mode_override() {
        let dir = tempfile::tempdir().unwrap();
        let _guard = crate::test_support::DirGuard::change_to(dir.path());
        init_cargo_package(dir.path());

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

    #[test]
    #[serial]
    fn setup_isolation_reports_duplicate_cli_allow() {
        let dir = tempfile::tempdir().unwrap();
        let _guard = crate::test_support::DirGuard::change_to(dir.path());
        init_cargo_package(dir.path());

        let allow = vec!["/bin/bash".to_string(), "/bin/bash".to_string()];
        let err = match setup_isolation(&allow, &[], None) {
            Ok(_) => panic!("expected duplicate error"),
            Err(err) => err,
        };

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let message = err.to_string();
        assert!(message.contains("duplicate exec allow rule: /bin/bash"));
    }

    #[test]
    #[serial]
    fn setup_isolation_skips_duplicate_fs_rules() {
        let dir = tempfile::tempdir().unwrap();
        let _guard = crate::test_support::DirGuard::change_to(dir.path());
        init_cargo_package(dir.path());

        let metadata = super::load_cargo_metadata().unwrap();
        let workspace = metadata.workspace_root.to_string_lossy().into_owned();
        let target = metadata.target_directory.to_string_lossy().into_owned();

        write(
            "warden.toml",
            format!(
                "mode = \"enforce\"\nfs.default = \"strict\"\nnet.default = \"deny\"\nexec.default = \"allowlist\"\n\n[allow.fs]\nwrite_extra = [\"{target}\"]\nread_extra = [\"{workspace}\"]\n"
            ),
        )
        .unwrap();

        let isolation = setup_isolation(&[], &[], None).unwrap();
        let fs_rules = fs_entries(&isolation.maps_layout);

        assert_eq!(fs_rules.len(), 2);
        assert!(
            fs_rules
                .iter()
                .any(|(path, access)| { path == &workspace && *access == FS_READ })
        );
        assert!(
            fs_rules
                .iter()
                .any(|(path, access)| { path == &target && *access == (FS_READ | FS_WRITE) })
        );
    }
}
