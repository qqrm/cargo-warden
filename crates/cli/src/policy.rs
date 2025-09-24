use policy_core::{FsDefault, Mode, Policy, WorkspacePolicy};
use qqrm_policy_compiler::{self, CompiledPolicy, MapsLayout};
use semver::{Version, VersionReq};
use serde::Deserialize;
use serde_json::Value;
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
    let metadata = load_cargo_metadata()?;
    apply_manifest_permissions(&mut policy, &metadata)?;
    apply_trust_permissions(&mut policy, &metadata)?;
    for path in policy_paths {
        let extra = load_policy(Path::new(path))?;
        merge_policy(&mut policy, extra);
    }
    policy.extend_exec_allowed(allow.iter().cloned());
    extend_fs_access(&mut policy, &metadata)?;
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

fn extend_fs_access(policy: &mut Policy, metadata: &CargoMetadata) -> io::Result<()> {
    if policy.fs_default() != FsDefault::Strict {
        return Ok(());
    }

    let build_paths = detect_build_paths(metadata);

    maybe_extend_fs_read(policy, &build_paths.workspace_root);
    for target in build_paths.target_dirs {
        maybe_extend_fs_write(policy, &target);
    }
    for out_dir in build_paths.out_dirs {
        maybe_extend_fs_write(policy, &out_dir);
    }

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
    match path.canonicalize() {
        Ok(canonical) => canonical,
        Err(_) => {
            if path.is_absolute() {
                path.to_path_buf()
            } else if let Ok(cwd) = std::env::current_dir() {
                cwd.join(path)
            } else {
                path.to_path_buf()
            }
        }
    }
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

fn apply_manifest_permissions(policy: &mut Policy, metadata: &CargoMetadata) -> io::Result<()> {
    let member_ids: HashSet<&str> = metadata
        .workspace_members
        .iter()
        .map(String::as_str)
        .collect();

    for package in &metadata.packages {
        if !member_ids.contains(package.id.as_str()) {
            continue;
        }
        let Some(manifest_dir) = package.manifest_path.parent() else {
            continue;
        };
        let manifest_dir = normalize_path(manifest_dir);

        let Value::Object(ref map) = package.metadata else {
            continue;
        };
        let Some(warden) = map.get("cargo-warden") else {
            continue;
        };
        if warden.is_null() {
            continue;
        }

        let source = PermissionSource::Manifest {
            package: package.name.as_str(),
        };
        let mut permissions = Vec::new();
        collect_permission_strings(warden, &source, &mut permissions)?;
        if permissions.is_empty() {
            continue;
        }
        apply_permission_list(
            policy,
            permissions.iter().map(String::as_str),
            manifest_dir.as_path(),
            metadata,
            &source,
        )?;
    }

    Ok(())
}

fn apply_trust_permissions(policy: &mut Policy, metadata: &CargoMetadata) -> io::Result<()> {
    let Some(db) = load_trust_db()? else {
        return Ok(());
    };
    if db.entries.is_empty() {
        return Ok(());
    }

    let member_ids: HashSet<&str> = metadata
        .workspace_members
        .iter()
        .map(String::as_str)
        .collect();

    for package in &metadata.packages {
        if !member_ids.contains(package.id.as_str()) {
            continue;
        }
        let Some(manifest_dir) = package.manifest_path.parent() else {
            continue;
        };
        let manifest_dir = normalize_path(manifest_dir);
        let version = Version::parse(&package.version).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "failed to parse version '{}' for package '{}': {err}",
                    package.version, package.name
                ),
            )
        })?;

        for entry in &db.entries {
            if entry.package != package.name {
                continue;
            }
            if !entry.matches(&version)? {
                continue;
            }
            if entry.permissions.is_empty() {
                continue;
            }
            let source = PermissionSource::Trust {
                package: package.name.as_str(),
                version_range: entry
                    .version_range
                    .as_deref()
                    .map(str::trim)
                    .and_then(|s| if s.is_empty() { None } else { Some(s) }),
            };
            apply_permission_list(
                policy,
                entry.permissions.iter().map(String::as_str),
                manifest_dir.as_path(),
                metadata,
                &source,
            )?;
        }
    }

    Ok(())
}

enum PermissionSource<'a> {
    Manifest {
        package: &'a str,
    },
    Trust {
        package: &'a str,
        version_range: Option<&'a str>,
    },
}

impl<'a> PermissionSource<'a> {
    fn describe(&self) -> String {
        match self {
            PermissionSource::Manifest { package } => {
                format!("package metadata for '{package}'")
            }
            PermissionSource::Trust {
                package,
                version_range,
            } => {
                if let Some(range) = version_range {
                    format!("trust database entry for '{package}' ({range})")
                } else {
                    format!("trust database entry for '{package}'")
                }
            }
        }
    }
}

fn metadata_error(source: &PermissionSource<'_>, detail: impl Into<String>) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("{}: {}", source.describe(), detail.into()),
    )
}

fn permission_error(
    source: &PermissionSource<'_>,
    permission: &str,
    detail: impl Into<String>,
) -> io::Error {
    metadata_error(
        source,
        format!("invalid permission '{permission}': {}", detail.into()),
    )
}

fn collect_permission_strings(
    value: &Value,
    source: &PermissionSource<'_>,
    output: &mut Vec<String>,
) -> io::Result<()> {
    match value {
        Value::Null => Ok(()),
        Value::Object(map) => {
            if let Some(raw_permissions) = map.get("permissions") {
                let permissions = raw_permissions.as_array().ok_or_else(|| {
                    metadata_error(source, "'permissions' must be an array of strings")
                })?;
                for entry in permissions {
                    let Some(text) = entry.as_str() else {
                        return Err(metadata_error(
                            source,
                            "'permissions' entries must be strings",
                        ));
                    };
                    output.push(text.to_string());
                }
            }
            for (key, nested) in map {
                if key == "permissions" {
                    continue;
                }
                collect_permission_strings(nested, source, output)?;
            }
            Ok(())
        }
        Value::Array(items) => {
            for item in items {
                collect_permission_strings(item, source, output)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn apply_permission_list<'a, I>(
    policy: &mut Policy,
    permissions: I,
    manifest_dir: &Path,
    metadata: &CargoMetadata,
    source: &PermissionSource<'_>,
) -> io::Result<()>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut exec_paths = Vec::new();
    let mut net_hosts = Vec::new();
    let mut fs_reads = Vec::new();
    let mut fs_writes = Vec::new();
    let mut env_reads = Vec::new();
    let mut syscall_denies = Vec::new();

    for permission in permissions {
        let trimmed = permission.trim();
        if trimmed.is_empty() {
            return Err(metadata_error(source, "encountered empty permission entry"));
        }
        let (kind, rest) = trimmed.split_once(':').ok_or_else(|| {
            metadata_error(
                source,
                format!("permission '{trimmed}' is missing ':' separator"),
            )
        })?;
        let value = rest.trim();
        if value.is_empty() {
            return Err(permission_error(source, trimmed, "missing value"));
        }

        match kind {
            "exec" => {
                exec_paths.push(value.to_string());
            }
            "net" => {
                let host = value.strip_prefix("host:").unwrap_or(value).trim();
                if host.is_empty() {
                    return Err(permission_error(source, trimmed, "missing host value"));
                }
                net_hosts.push(host.to_string());
            }
            "fs" => {
                let (mode, path_value) = value.split_once(':').ok_or_else(|| {
                    permission_error(source, trimmed, "expected format 'fs:<mode>:<path>'")
                })?;
                let mode = mode.trim();
                let path_value = path_value.trim();
                if path_value.is_empty() {
                    return Err(permission_error(source, trimmed, "missing filesystem path"));
                }
                let resolved = resolve_fs_path(path_value, manifest_dir, metadata);
                match mode {
                    "read" => fs_reads.push(resolved),
                    "write" => fs_writes.push(resolved),
                    _ => {
                        return Err(permission_error(
                            source,
                            trimmed,
                            format!("unsupported filesystem mode '{mode}'"),
                        ));
                    }
                }
            }
            "env" => {
                let (action, name) = value.split_once(':').ok_or_else(|| {
                    permission_error(source, trimmed, "expected format 'env:read:<VAR>'")
                })?;
                let action = action.trim();
                let name = name.trim();
                if name.is_empty() {
                    return Err(permission_error(
                        source,
                        trimmed,
                        "missing environment variable",
                    ));
                }
                match action {
                    "read" => env_reads.push(name.to_string()),
                    _ => {
                        return Err(permission_error(
                            source,
                            trimmed,
                            format!("unsupported environment action '{action}'"),
                        ));
                    }
                }
            }
            "syscall" => {
                let (action, name) = value.split_once(':').ok_or_else(|| {
                    permission_error(source, trimmed, "expected format 'syscall:deny:<name>'")
                })?;
                let action = action.trim();
                let name = name.trim();
                if name.is_empty() {
                    return Err(permission_error(source, trimmed, "missing syscall name"));
                }
                match action {
                    "deny" => syscall_denies.push(name.to_string()),
                    _ => {
                        return Err(permission_error(
                            source,
                            trimmed,
                            format!("unsupported syscall action '{action}'"),
                        ));
                    }
                }
            }
            other => {
                return Err(permission_error(
                    source,
                    trimmed,
                    format!("unknown permission kind '{other}'"),
                ));
            }
        }
    }

    if !exec_paths.is_empty() {
        policy.extend_exec_allowed(exec_paths);
    }
    if !net_hosts.is_empty() {
        policy.extend_net_hosts(net_hosts);
    }
    if !fs_reads.is_empty() {
        policy.extend_fs_reads(fs_reads);
    }
    if !fs_writes.is_empty() {
        policy.extend_fs_writes(fs_writes);
    }
    if !env_reads.is_empty() {
        policy.extend_env_read_vars(env_reads);
    }
    if !syscall_denies.is_empty() {
        policy.extend_syscall_deny(syscall_denies);
    }

    Ok(())
}

fn resolve_fs_path(value: &str, manifest_dir: &Path, metadata: &CargoMetadata) -> PathBuf {
    match value {
        "workspace" => normalize_path(metadata.workspace_root.as_path()),
        "target" => normalize_path(metadata.target_directory.as_path()),
        "manifest" | "package" => normalize_path(manifest_dir),
        other => {
            let path = PathBuf::from(other);
            let absolute = if path.is_absolute() {
                path
            } else {
                manifest_dir.join(path)
            };
            normalize_path(&absolute)
        }
    }
}

fn load_trust_db() -> io::Result<Option<TrustDb>> {
    let Some(path) = trust_db_path() else {
        return Ok(None);
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(err) => return Err(err),
    };
    let db: TrustDb = serde_json::from_str(&text).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{}: {err}", path.display()),
        )
    })?;
    Ok(Some(db))
}

fn trust_db_path() -> Option<PathBuf> {
    if let Some(explicit) = std::env::var_os("CARGO_WARDEN_TRUST_PATH") {
        if explicit.is_empty() {
            return None;
        }
        return Some(PathBuf::from(explicit));
    }

    let base = if let Some(dir) = std::env::var_os("XDG_CONFIG_HOME") {
        if dir.is_empty() {
            None
        } else {
            Some(PathBuf::from(dir))
        }
    } else if let Some(home) = std::env::var_os("HOME") {
        if home.is_empty() {
            None
        } else {
            Some(PathBuf::from(home).join(".config"))
        }
    } else {
        None
    }?;

    let mut path = base;
    path.push("cargo-warden");
    path.push("trust.json");
    Some(path)
}

#[derive(Deserialize)]
struct TrustDb {
    #[serde(default)]
    entries: Vec<TrustEntry>,
}

#[derive(Deserialize)]
struct TrustEntry {
    package: String,
    #[serde(default)]
    version_range: Option<String>,
    #[serde(default)]
    permissions: Vec<String>,
    #[allow(dead_code)]
    #[serde(default)]
    granted_at: Option<String>,
}

impl TrustEntry {
    fn matches(&self, version: &Version) -> io::Result<bool> {
        let Some(range) = self.version_range.as_deref().map(str::trim) else {
            return Ok(true);
        };
        if range.is_empty() {
            return Ok(true);
        }
        let req = VersionReq::parse(range).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "invalid version range '{range}' for trust entry '{}': {err}",
                    self.package
                ),
            )
        })?;
        Ok(req.matches(version))
    }
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

struct BuildPaths {
    workspace_root: PathBuf,
    target_dirs: Vec<PathBuf>,
    out_dirs: Vec<PathBuf>,
}

fn detect_build_paths(metadata: &CargoMetadata) -> BuildPaths {
    let workspace_root = metadata.workspace_root.clone();

    let mut target_dirs = Vec::new();
    if let Some(env_target) = env_path("CARGO_TARGET_DIR") {
        target_dirs.push(env_target);
    }
    target_dirs.push(metadata.target_directory.clone());
    dedup_paths(&mut target_dirs);

    let mut out_dirs = Vec::new();
    if let Some(out_dir) = env_path("OUT_DIR") {
        out_dirs.push(out_dir);
    }
    if let Some(tmp_dir) = env_path("CARGO_TARGET_TMPDIR") {
        out_dirs.push(tmp_dir);
    }
    dedup_paths(&mut out_dirs);

    BuildPaths {
        workspace_root,
        target_dirs,
        out_dirs,
    }
}

fn env_path(var: &str) -> Option<PathBuf> {
    let value = std::env::var_os(var)?;
    if value.is_empty() {
        return None;
    }
    Some(PathBuf::from(value))
}

fn dedup_paths(paths: &mut Vec<PathBuf>) {
    let mut seen = HashSet::new();
    paths.retain(|path| seen.insert(path.clone()));
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
    version: String,
    manifest_path: PathBuf,
    #[serde(default)]
    metadata: Value,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{DirGuard, EnvVarGuard};
    use bpf_api::{FS_READ, FS_WRITE};
    use serial_test::serial;
    use std::ffi::OsString;
    use std::fs::{self, write};
    use std::net::{Ipv4Addr, Ipv6Addr};
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

    fn net_hosts(layout: &MapsLayout) -> Vec<String> {
        layout
            .net_rules
            .iter()
            .map(|entry| {
                let rule = &entry.rule;
                match rule.prefix_len {
                    32 => {
                        let mut octets = [0u8; 4];
                        octets.copy_from_slice(&rule.addr[..4]);
                        format!("{}:{}", Ipv4Addr::from(octets), rule.port)
                    }
                    128 => {
                        let addr = Ipv6Addr::from(rule.addr);
                        format!("[{}]:{}", addr, rule.port)
                    }
                    _ => format!("{:?}:{}", rule.addr, rule.port),
                }
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

    fn guard_build_env() -> (EnvVarGuard, EnvVarGuard, EnvVarGuard) {
        (
            EnvVarGuard::unset("OUT_DIR"),
            EnvVarGuard::unset("CARGO_TARGET_DIR"),
            EnvVarGuard::unset("CARGO_TARGET_TMPDIR"),
        )
    }

    #[test]
    #[serial]
    fn setup_isolation_merges_syscalls_and_allow_entries() {
        let dir = tempfile::tempdir().unwrap();
        let (_out_guard, _target_guard, _tmp_guard) = guard_build_env();
        let _guard = DirGuard::change_to(dir.path());
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
        let (_out_guard, _target_guard, _tmp_guard) = guard_build_env();
        let _guard = DirGuard::change_to(dir.path());
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
        let (_out_guard, _target_guard, _tmp_guard) = guard_build_env();
        let _guard = DirGuard::change_to(dir.path());
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
        let (_out_guard, _target_guard, _tmp_guard) = guard_build_env();
        let _guard = DirGuard::change_to(dir.path());
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
        let (_out_guard, _target_guard, _tmp_guard) = guard_build_env();
        let _guard = DirGuard::change_to(dir.path());
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
        let (_out_guard, _target_guard, _tmp_guard) = guard_build_env();
        let _guard = DirGuard::change_to(dir.path());
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

    #[test]
    #[serial]
    fn setup_isolation_includes_out_dir_from_env() {
        let dir = tempfile::tempdir().unwrap();
        let (_out_guard, _target_guard, _tmp_guard) = guard_build_env();
        let _guard = DirGuard::change_to(dir.path());
        init_cargo_package(dir.path());

        let out_dir_path = dir.path().join("custom-out");
        fs::create_dir_all(&out_dir_path).unwrap();
        let out_guard = EnvVarGuard::set("OUT_DIR", out_dir_path.as_os_str().to_os_string());

        let isolation = setup_isolation(&[], &[], None).unwrap();
        drop(out_guard);

        let metadata = super::load_cargo_metadata().unwrap();
        let workspace = super::normalize_path(&metadata.workspace_root);
        let target = super::normalize_path(&metadata.target_directory);
        let out_dir = super::normalize_path(&out_dir_path);

        let fs_rules = fs_entries(&isolation.maps_layout);
        assert!(
            fs_rules
                .iter()
                .any(|(path, access)| path == &workspace.to_string_lossy() && *access == FS_READ)
        );
        assert!(fs_rules.iter().any(|(path, access)| {
            path == &target.to_string_lossy() && *access == (FS_READ | FS_WRITE)
        }));
        assert!(fs_rules.iter().any(|(path, access)| {
            path == &out_dir.to_string_lossy() && *access == (FS_READ | FS_WRITE)
        }));
        assert_eq!(fs_rules.len(), 3);
    }

    #[test]
    #[serial]
    fn setup_isolation_applies_manifest_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let (_out_guard, _target_guard, _tmp_guard) = guard_build_env();
        let _guard = DirGuard::change_to(dir.path());
        init_cargo_package(dir.path());

        let include_dir = dir.path().join("include");
        fs::create_dir_all(&include_dir).unwrap();

        write(
            dir.path().join("Cargo.toml"),
            r#"[package]
name = "fixture"
version = "0.1.0"
edition = "2021"

[package.metadata.cargo-warden]
permissions = [
  "exec:/usr/bin/protoc",
  "fs:read:include",
  "fs:write:target",
  "net:127.0.0.1:8080",
  "env:read:PROTO_INCLUDE",
  "syscall:deny:clone"
]

[package.metadata.cargo-warden.proc-macro]
permissions = ["env:read:PROTOC"]
"#,
        )
        .unwrap();

        let isolation = setup_isolation(&[], &[], None).unwrap();

        assert!(isolation.syscall_deny.contains(&"clone".to_string()));

        let exec = exec_paths(&isolation.maps_layout);
        assert!(exec.contains(&"/usr/bin/protoc".to_string()));

        let fs_rules = fs_entries(&isolation.maps_layout);
        let include_path = super::normalize_path(&include_dir);
        let workspace = super::normalize_path(dir.path());
        let metadata = super::load_cargo_metadata().unwrap();
        let target = super::normalize_path(&metadata.target_directory);

        assert!(fs_rules.iter().any(|(path, access)| {
            path == &include_path.to_string_lossy() && *access == FS_READ
        }));
        assert!(
            fs_rules.iter().any(|(path, access)| {
                path == &workspace.to_string_lossy() && *access == FS_READ
            })
        );
        assert!(fs_rules.iter().any(|(path, access)| {
            path == &target.to_string_lossy() && *access == (FS_READ | FS_WRITE)
        }));

        let net = net_hosts(&isolation.maps_layout);
        assert!(net.contains(&"127.0.0.1:8080".to_string()));

        assert!(
            isolation
                .allowed_env_vars
                .contains(&"PROTO_INCLUDE".to_string())
        );
        assert!(isolation.allowed_env_vars.contains(&"PROTOC".to_string()));
    }

    #[test]
    #[serial]
    fn setup_isolation_applies_trust_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let (_out_guard, _target_guard, _tmp_guard) = guard_build_env();
        let _guard = DirGuard::change_to(dir.path());
        init_cargo_package(dir.path());

        let config_dir = dir.path().join("config");
        let trust_path = config_dir.join("cargo-warden").join("trust.json");
        fs::create_dir_all(trust_path.parent().unwrap()).unwrap();
        let _config_guard =
            EnvVarGuard::set("XDG_CONFIG_HOME", OsString::from(config_dir.as_os_str()));

        write(
            &trust_path,
            r#"{
  "entries": [
    {
      "package": "fixture",
      "version_range": "^0.1",
      "permissions": ["exec:/usr/local/bin/custom", "fs:read:/opt/data"]
    }
  ]
}
"#,
        )
        .unwrap();

        let isolation = setup_isolation(&[], &[], None).unwrap();

        let exec = exec_paths(&isolation.maps_layout);
        assert!(exec.contains(&"/usr/local/bin/custom".to_string()));

        let fs_rules = fs_entries(&isolation.maps_layout);
        assert!(
            fs_rules
                .iter()
                .any(|(path, access)| { path == "/opt/data" && *access == FS_READ })
        );
    }

    #[test]
    #[serial]
    fn load_trust_db_ignores_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join("cfg");
        let _config_guard =
            EnvVarGuard::set("XDG_CONFIG_HOME", OsString::from(config_dir.as_os_str()));

        assert!(super::load_trust_db().unwrap().is_none());
    }
}
