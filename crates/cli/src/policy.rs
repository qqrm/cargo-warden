use cargo_metadata::{Metadata, MetadataCommand, Package, PackageId};
use directories::ProjectDirs;
use policy_core::{ExecDefault, FsDefault, Mode, NetDefault, Policy, WorkspacePolicy};
use semver::{Version, VersionReq};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};
use warden_policy_compiler::{self, CompiledPolicy, MapsLayout};

pub(crate) struct IsolationConfig {
    pub(crate) mode: Mode,
    pub(crate) syscall_deny: Vec<String>,
    pub(crate) maps_layout: MapsLayout,
    pub(crate) allowed_env_vars: Vec<String>,
}

#[derive(Default)]
struct PolicyContext {
    metadata: Option<Metadata>,
}

impl PolicyContext {
    fn metadata(&mut self) -> io::Result<&Metadata> {
        if self.metadata.is_none() {
            self.metadata = Some(fetch_cargo_metadata()?);
        }
        Ok(self.metadata.as_ref().unwrap())
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PolicyStatus {
    pub(crate) sources: Vec<PolicySource>,
    pub(crate) effective_mode: Mode,
}

#[derive(Debug, Clone)]
pub(crate) struct PolicySource {
    pub(crate) kind: PolicySourceKind,
    pub(crate) mode: Mode,
}

#[derive(Debug, Clone)]
pub(crate) enum PolicySourceKind {
    Workspace {
        path: PathBuf,
        member: Option<String>,
    },
    LocalFile {
        path: PathBuf,
    },
    CliFile {
        path: PathBuf,
    },
    BuiltinDefault,
    ModeOverride,
}

pub(crate) fn setup_isolation(
    allow: &[String],
    policy_paths: &[String],
    mode_override: Option<Mode>,
) -> io::Result<IsolationConfig> {
    let mut ctx = PolicyContext::default();
    let mut policy = load_default_policy(&mut ctx)?;
    let metadata = ctx.metadata()?;
    apply_manifest_permissions(&mut policy, metadata)?;
    apply_trust_permissions(&mut policy, metadata)?;
    for path in policy_paths {
        let extra = load_policy(Path::new(path))?;
        policy.merge(extra);
    }
    policy.extend_exec_allowed(allow.iter().cloned());
    extend_fs_access(&mut policy, metadata)?;
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

    let compiled = warden_policy_compiler::compile(&policy)
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

fn load_default_policy(ctx: &mut PolicyContext) -> io::Result<Policy> {
    load_default_policy_layer(ctx).map(|layer| layer.policy)
}

fn load_default_policy_layer(ctx: &mut PolicyContext) -> io::Result<PolicyLayer> {
    if let Some(layer) = load_workspace_policy_layer(ctx)? {
        return Ok(layer);
    }
    load_local_policy_layer()
}

fn load_workspace_policy_layer(ctx: &mut PolicyContext) -> io::Result<Option<PolicyLayer>> {
    let Some(path) = find_workspace_file("workspace.warden.toml")? else {
        return Ok(None);
    };
    let workspace: WorkspacePolicy = read_toml_file(&path)?;
    let member = determine_active_workspace_member(ctx)?;
    let policy = match member {
        Some(ref member) => workspace.policy_for(member),
        None => workspace.root.clone(),
    };
    Ok(Some(PolicyLayer {
        policy,
        source: PolicySourceKind::Workspace { path, member },
    }))
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
    read_toml_file(path)
}

fn load_local_policy_layer() -> io::Result<PolicyLayer> {
    let path = PathBuf::from("warden.toml");
    match read_toml_file(&path) {
        Ok(policy) => Ok(PolicyLayer {
            policy,
            source: PolicySourceKind::LocalFile { path },
        }),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(builtin_default_policy_layer()),
        Err(err) => Err(err),
    }
}

fn builtin_default_policy_layer() -> PolicyLayer {
    let policy = Policy::with_defaults(
        Mode::Observe,
        FsDefault::Strict,
        NetDefault::Deny,
        ExecDefault::Allowlist,
    );
    PolicyLayer {
        policy,
        source: PolicySourceKind::BuiltinDefault,
    }
}

fn determine_active_workspace_member(ctx: &mut PolicyContext) -> io::Result<Option<String>> {
    if let Some(from_env) = workspace_member_from_env() {
        return Ok(Some(from_env));
    }
    let metadata = ctx.metadata()?;
    workspace_member_from_dir(metadata)
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

fn fetch_cargo_metadata() -> io::Result<Metadata> {
    let mut command = MetadataCommand::new();
    if let Some(cargo) = std::env::var_os("CARGO").filter(|value| !value.is_empty()) {
        command.cargo_path(cargo);
    }
    command.no_deps();
    command.exec().map_err(io::Error::other)
}

fn extend_fs_access(policy: &mut Policy, metadata: &Metadata) -> io::Result<()> {
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

fn normalize_path(path: impl AsRef<Path>) -> PathBuf {
    let path = path.as_ref();
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

fn apply_manifest_permissions(policy: &mut Policy, metadata: &Metadata) -> io::Result<()> {
    for member in workspace_members(metadata) {
        let Some(warden) = member.package.metadata.get("cargo-warden") else {
            continue;
        };
        if warden.is_null() {
            continue;
        }

        let source = PermissionSource::Manifest {
            package: member.package.name.as_str(),
        };
        let mut permissions = Vec::new();
        collect_permission_strings(warden, &source, &mut permissions)?;
        if permissions.is_empty() {
            continue;
        }
        apply_permission_list(
            policy,
            permissions.iter().map(String::as_str),
            member.manifest_dir.as_path(),
            metadata,
            &source,
        )?;
    }

    Ok(())
}

fn apply_trust_permissions(policy: &mut Policy, metadata: &Metadata) -> io::Result<()> {
    let Some(db) = load_trust_db()? else {
        return Ok(());
    };
    if db.entries.is_empty() {
        return Ok(());
    }

    for member in workspace_members(metadata) {
        let version = member.package.version.clone();
        for entry in &db.entries {
            if entry.package != member.package.name {
                continue;
            }
            if !entry.matches(&version)? {
                continue;
            }
            if entry.permissions.is_empty() {
                continue;
            }
            let source = PermissionSource::Trust {
                package: member.package.name.as_str(),
                version_range: entry
                    .version_range
                    .as_deref()
                    .map(str::trim)
                    .and_then(|s| if s.is_empty() { None } else { Some(s) }),
            };
            apply_permission_list(
                policy,
                entry.permissions.iter().map(String::as_str),
                member.manifest_dir.as_path(),
                metadata,
                &source,
            )?;
        }
    }

    Ok(())
}

struct WorkspaceMember<'a> {
    package: &'a Package,
    manifest_dir: PathBuf,
}

struct WorkspaceMembers<'a> {
    member_ids: HashSet<PackageId>,
    packages: std::slice::Iter<'a, Package>,
}

impl<'a> WorkspaceMembers<'a> {
    fn new(metadata: &'a Metadata) -> Self {
        Self {
            member_ids: metadata.workspace_members.iter().cloned().collect(),
            packages: metadata.packages.iter(),
        }
    }
}

impl<'a> Iterator for WorkspaceMembers<'a> {
    type Item = WorkspaceMember<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        for package in self.packages.by_ref() {
            if !self.member_ids.contains(&package.id) {
                continue;
            }
            let Some(manifest_dir) = package.manifest_path.parent() else {
                continue;
            };
            let manifest_dir = normalize_path(manifest_dir.to_path_buf());
            return Some(WorkspaceMember {
                package,
                manifest_dir,
            });
        }
        None
    }
}

fn workspace_members(metadata: &Metadata) -> WorkspaceMembers<'_> {
    WorkspaceMembers::new(metadata)
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
    metadata: &Metadata,
    source: &PermissionSource<'_>,
) -> io::Result<()>
where
    I: IntoIterator<Item = &'a str>,
{
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
                policy.extend_exec_allowed(std::iter::once(value.to_string()));
            }
            "net" => {
                let host = value.strip_prefix("host:").unwrap_or(value).trim();
                if host.is_empty() {
                    return Err(permission_error(source, trimmed, "missing host value"));
                }
                policy.extend_net_hosts(std::iter::once(host.to_string()));
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
                    "read" => policy.extend_fs_reads(std::iter::once(resolved)),
                    "write" => policy.extend_fs_writes(std::iter::once(resolved)),
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
                    "read" => policy.extend_env_read_vars(std::iter::once(name.to_string())),
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
                    "deny" => policy.extend_syscall_deny(std::iter::once(name.to_string())),
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

    Ok(())
}

fn resolve_fs_path(value: &str, manifest_dir: &Path, metadata: &Metadata) -> PathBuf {
    match value {
        "workspace" => normalize_path(metadata.workspace_root.clone().into_std_path_buf()),
        "target" => normalize_path(metadata.target_directory.clone().into_std_path_buf()),
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

    let dirs = ProjectDirs::from("", "", "cargo-warden")?;
    Some(dirs.config_dir().join("trust.json"))
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

fn workspace_member_from_dir(metadata: &Metadata) -> io::Result<Option<String>> {
    let member_ids: HashSet<&PackageId> = metadata.workspace_members.iter().collect();
    let cwd = std::env::current_dir()?;
    let canonical_cwd = cwd.canonicalize().unwrap_or(cwd);
    let mut best_match: Option<(String, usize, bool)> = None;

    for pkg in &metadata.packages {
        if !member_ids.contains(&pkg.id) {
            continue;
        }
        let Some(manifest_dir) = pkg.manifest_path.parent() else {
            continue;
        };
        let manifest_dir = manifest_dir.as_std_path().to_path_buf();
        let canonical_dir = manifest_dir
            .canonicalize()
            .unwrap_or_else(|_| manifest_dir.clone());
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

fn read_toml_file<T>(path: &Path) -> io::Result<T>
where
    T: DeserializeOwned,
{
    let text = std::fs::read_to_string(path)?;
    toml::from_str(&text).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{}: {err}", path.display()),
        )
    })
}

#[derive(Debug)]
struct PolicyLayer {
    policy: Policy,
    source: PolicySourceKind,
}

pub(crate) fn collect_policy_status(
    policy_paths: &[String],
    mode_override: Option<Mode>,
) -> io::Result<PolicyStatus> {
    let mut ctx = PolicyContext::default();
    let PolicyLayer {
        policy: default_policy,
        source: default_source,
    } = load_default_policy_layer(&mut ctx)?;
    let mut sources = Vec::new();
    sources.push(PolicySource {
        kind: default_source,
        mode: default_policy.mode,
    });

    let mut effective_mode = default_policy.mode;

    for path in policy_paths {
        let path_buf = PathBuf::from(path);
        let extra = load_policy(path_buf.as_path())?;
        effective_mode = extra.mode;
        sources.push(PolicySource {
            kind: PolicySourceKind::CliFile { path: path_buf },
            mode: extra.mode,
        });
    }

    if let Some(mode) = mode_override {
        effective_mode = mode;
        sources.push(PolicySource {
            kind: PolicySourceKind::ModeOverride,
            mode,
        });
    }

    Ok(PolicyStatus {
        sources,
        effective_mode,
    })
}

struct BuildPaths {
    workspace_root: PathBuf,
    target_dirs: Vec<PathBuf>,
    out_dirs: Vec<PathBuf>,
}

fn detect_build_paths(metadata: &Metadata) -> BuildPaths {
    let workspace_root = metadata.workspace_root.clone().into_std_path_buf();

    let mut target_dirs = Vec::new();
    if let Some(env_target) = env_path("CARGO_TARGET_DIR") {
        target_dirs.push(env_target);
    }
    target_dirs.push(metadata.target_directory.clone().into_std_path_buf());
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{DirGuard, ScopedEnv};
    use bpf_api::{FS_READ, FS_WRITE};
    use serial_test::serial;
    use std::ffi::{OsStr, OsString};
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

    fn guard_build_env() -> (
        ScopedEnv<&'static OsStr>,
        ScopedEnv<&'static OsStr>,
        ScopedEnv<&'static OsStr>,
    ) {
        (
            ScopedEnv::remove(OsStr::new("OUT_DIR")),
            ScopedEnv::remove(OsStr::new("CARGO_TARGET_DIR")),
            ScopedEnv::remove(OsStr::new("CARGO_TARGET_TMPDIR")),
        )
    }

    #[test]
    #[serial]
    fn collect_policy_status_reports_workspace_source() {
        let dir = tempfile::tempdir().unwrap();
        let workspace_dir = dir.path();
        write(
            workspace_dir.join("Cargo.toml"),
            "[workspace]\nmembers = [\"member\"]\n",
        )
        .unwrap();
        let member_dir = workspace_dir.join("member");
        fs::create_dir_all(&member_dir).unwrap();
        init_cargo_package(&member_dir);
        write(
            workspace_dir.join("workspace.warden.toml"),
            "[root]\nmode = \"observe\"\n",
        )
        .unwrap();

        let (_out_guard, _target_guard, _tmp_guard) = guard_build_env();
        let _dir_guard = DirGuard::change_to(member_dir.as_path());

        let status = collect_policy_status(&[], None).unwrap();
        assert_eq!(status.effective_mode, Mode::Observe);
        assert_eq!(status.sources.len(), 1);
        match &status.sources[0].kind {
            PolicySourceKind::Workspace { path, member } => {
                assert_eq!(
                    path.file_name().unwrap().to_str().unwrap(),
                    "workspace.warden.toml"
                );
                assert_eq!(member.as_deref(), Some("fixture"));
            }
            other => panic!("expected workspace policy, found {other:?}"),
        }
        assert_eq!(status.sources[0].mode, Mode::Observe);
    }

    #[test]
    #[serial]
    fn collect_policy_status_includes_cli_policy_and_override() {
        let dir = tempfile::tempdir().unwrap();
        let (_out_guard, _target_guard, _tmp_guard) = guard_build_env();
        let _dir_guard = DirGuard::change_to(dir.path());
        init_cargo_package(dir.path());

        write(dir.path().join("warden.toml"), "mode = \"enforce\"\n").unwrap();

        let cli_policy = dir.path().join("cli.toml");
        write(&cli_policy, "mode = \"observe\"\n").unwrap();

        let cli_arg = cli_policy.to_str().unwrap().to_string();
        let status = collect_policy_status(&[cli_arg], Some(Mode::Enforce)).unwrap();

        assert_eq!(status.effective_mode, Mode::Enforce);
        assert_eq!(status.sources.len(), 3);
        assert!(matches!(
            status.sources[0].kind,
            PolicySourceKind::LocalFile { .. }
        ));
        assert_eq!(status.sources[0].mode, Mode::Enforce);
        match &status.sources[1].kind {
            PolicySourceKind::CliFile { path } => {
                assert_eq!(path.file_name().unwrap().to_str().unwrap(), "cli.toml");
            }
            other => panic!("expected CLI policy, found {other:?}"),
        }
        assert_eq!(status.sources[1].mode, Mode::Observe);
        assert!(matches!(
            status.sources[2].kind,
            PolicySourceKind::ModeOverride
        ));
        assert_eq!(status.sources[2].mode, Mode::Enforce);
    }

    #[test]
    #[serial]
    fn collect_policy_status_reports_empty_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let (_out_guard, _target_guard, _tmp_guard) = guard_build_env();
        let _dir_guard = DirGuard::change_to(dir.path());
        init_cargo_package(dir.path());

        let status = collect_policy_status(&[], None).unwrap();
        assert_eq!(status.effective_mode, Mode::Observe);
        assert_eq!(status.sources.len(), 1);
        assert!(matches!(
            status.sources[0].kind,
            PolicySourceKind::BuiltinDefault
        ));
        assert_eq!(status.sources[0].mode, Mode::Observe);
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

        let metadata = super::fetch_cargo_metadata().unwrap();
        let workspace = super::normalize_path(metadata.workspace_root.clone().into_std_path_buf());
        let target = super::normalize_path(metadata.target_directory.clone().into_std_path_buf());
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

        assert_eq!(isolation.mode, Mode::Observe);
        assert!(isolation.syscall_deny.is_empty());
        assert!(isolation.maps_layout.exec_allowlist.is_empty());
        assert!(isolation.maps_layout.net_rules.is_empty());

        let metadata = super::fetch_cargo_metadata().unwrap();
        let workspace = super::normalize_path(metadata.workspace_root.clone().into_std_path_buf());
        let target = super::normalize_path(metadata.target_directory.clone().into_std_path_buf());
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

        assert_eq!(isolation.mode, Mode::Observe);
        let exec = exec_paths(&isolation.maps_layout);
        assert_eq!(exec, vec!["/bin/bash".to_string()]);

        let metadata = super::fetch_cargo_metadata().unwrap();
        let workspace = super::normalize_path(metadata.workspace_root.clone().into_std_path_buf());
        let target = super::normalize_path(metadata.target_directory.clone().into_std_path_buf());
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

        let metadata = super::fetch_cargo_metadata().unwrap();
        let workspace = metadata.workspace_root.as_str().to_string();
        let target = metadata.target_directory.as_str().to_string();

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
        let out_guard = ScopedEnv::set(
            OsString::from("OUT_DIR"),
            out_dir_path.as_os_str().to_os_string(),
        );

        let isolation = setup_isolation(&[], &[], None).unwrap();
        drop(out_guard);

        let metadata = super::fetch_cargo_metadata().unwrap();
        let workspace = super::normalize_path(metadata.workspace_root.clone().into_std_path_buf());
        let target = super::normalize_path(metadata.target_directory.clone().into_std_path_buf());
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
        let metadata = super::fetch_cargo_metadata().unwrap();
        let target = super::normalize_path(metadata.target_directory.clone().into_std_path_buf());

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
    fn setup_isolation_handles_metadata_table_arrays() {
        let dir = tempfile::tempdir().unwrap();
        let (_out_guard, _target_guard, _tmp_guard) = guard_build_env();
        let _guard = DirGuard::change_to(dir.path());
        init_cargo_package(dir.path());

        let tool_path = dir.path().join("bin/tool.sh");
        fs::create_dir_all(tool_path.parent().unwrap()).unwrap();
        write(&tool_path, "#!/bin/sh\nexit 0\n").unwrap();

        let assets_dir = dir.path().join("assets");
        fs::create_dir_all(&assets_dir).unwrap();

        write(
            dir.path().join("Cargo.toml"),
            format!(
                r#"[package]
name = "fixture"
version = "0.1.0"
edition = "2021"

[package.metadata.cargo-warden]
permissions = [
  "env:read:ROOT",
  "exec:{tool}",
]

[[package.metadata.cargo-warden.plugins]]
permissions = ["env:read:PLUGIN_A"]

[[package.metadata.cargo-warden.plugins]]
permissions = ["fs:read:assets", "env:read:PLUGIN_B"]

[package.metadata.cargo-warden.plugins.settings]
permissions = ["env:read:PLUGIN_SETTINGS"]
"#,
                tool = tool_path.display()
            ),
        )
        .unwrap();

        let isolation = setup_isolation(&[], &[], None).unwrap();

        let exec = exec_paths(&isolation.maps_layout);
        let tool_string = tool_path.to_string_lossy().into_owned();
        assert!(exec.contains(&tool_string));

        let fs_rules = fs_entries(&isolation.maps_layout);
        let assets_path = super::normalize_path(&assets_dir);
        assert!(fs_rules.iter().any(|(path, access)| {
            path == &assets_path.to_string_lossy() && *access == FS_READ
        }));

        assert!(isolation.allowed_env_vars.contains(&"ROOT".to_string()));
        assert!(isolation.allowed_env_vars.contains(&"PLUGIN_A".to_string()));
        assert!(isolation.allowed_env_vars.contains(&"PLUGIN_B".to_string()));
        assert!(
            isolation
                .allowed_env_vars
                .contains(&"PLUGIN_SETTINGS".to_string())
        );
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
        let _config_guard = ScopedEnv::set(
            OsString::from("XDG_CONFIG_HOME"),
            OsString::from(config_dir.as_os_str()),
        );

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
    fn setup_isolation_merges_manifest_and_trust_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let (_out_guard, _target_guard, _tmp_guard) = guard_build_env();
        let _guard = DirGuard::change_to(dir.path());
        init_cargo_package(dir.path());

        let include_dir = dir.path().join("include");
        fs::create_dir_all(&include_dir).unwrap();
        let tool_path = dir.path().join("bin/tool.sh");
        fs::create_dir_all(tool_path.parent().unwrap()).unwrap();
        write(&tool_path, "#!/bin/sh\nexit 0\n").unwrap();

        write(
            dir.path().join("Cargo.toml"),
            format!(
                r#"[package]
name = "fixture"
version = "0.1.0"
edition = "2021"

[package.metadata.cargo-warden]
permissions = [
  "exec:{tool}",
  "fs:read:include",
  "env:read:PROTO_INCLUDE",
  "net:host:127.0.0.1:8080"
]
"#,
                tool = tool_path.display(),
            ),
        )
        .unwrap();

        let config_dir = dir.path().join("config");
        let trust_path = config_dir.join("cargo-warden").join("trust.json");
        fs::create_dir_all(trust_path.parent().unwrap()).unwrap();
        let _config_guard = ScopedEnv::set(
            OsString::from("XDG_CONFIG_HOME"),
            OsString::from(config_dir.as_os_str()),
        );

        write(
            &trust_path,
            r#"{
  "entries": [
    {
      "package": "fixture",
      "version_range": "*",
      "permissions": [
        "exec:/usr/local/bin/custom",
        "fs:read:/opt/data",
        "net:host:10.0.0.1:9000",
        "syscall:deny:clone"
      ]
    }
  ]
}
"#,
        )
        .unwrap();

        let isolation = setup_isolation(&[], &[], None).unwrap();

        let exec = exec_paths(&isolation.maps_layout);
        assert!(exec.contains(&tool_path.to_string_lossy().into_owned()));
        assert!(exec.contains(&"/usr/local/bin/custom".to_string()));

        let net = net_hosts(&isolation.maps_layout);
        assert!(net.contains(&"127.0.0.1:8080".to_string()));
        assert!(net.contains(&"10.0.0.1:9000".to_string()));

        assert!(
            isolation
                .allowed_env_vars
                .contains(&"PROTO_INCLUDE".to_string())
        );
        assert!(isolation.syscall_deny.contains(&"clone".to_string()));

        let fs_rules = fs_entries(&isolation.maps_layout);
        let include_path = super::normalize_path(&include_dir);
        assert!(fs_rules.iter().any(|(path, access)| {
            path == &include_path.to_string_lossy() && *access == FS_READ
        }));
        assert!(
            fs_rules
                .iter()
                .any(|(path, access)| { path == "/opt/data" && *access == FS_READ })
        );
    }

    #[test]
    #[serial]
    fn apply_permission_list_limits_allocations() {
        let metadata = super::fetch_cargo_metadata().unwrap();
        let manifest_dir = metadata.workspace_root.clone().into_std_path_buf();
        let mut policy = Policy::new(Mode::Observe);
        let source = super::PermissionSource::Manifest { package: "fixture" };
        let permissions = [
            "exec:/bin/true",
            "net:host:127.0.0.1:7000",
            "fs:read:workspace",
            "fs:write:target",
            "env:read:EXAMPLE",
            "syscall:deny:clone",
        ];

        crate::reset_allocation_count();
        let before = crate::allocation_count();

        super::apply_permission_list(
            &mut policy,
            permissions.into_iter(),
            manifest_dir.as_path(),
            &metadata,
            &source,
        )
        .unwrap();

        let after = crate::allocation_count();
        let delta = after.saturating_sub(before);
        assert!(
            delta <= 40,
            "apply_permission_list performed {delta} allocations"
        );
    }

    #[test]
    #[serial]
    fn load_trust_db_ignores_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join("cfg");
        let _config_guard = ScopedEnv::set(
            OsString::from("XDG_CONFIG_HOME"),
            OsString::from(config_dir.as_os_str()),
        );

        assert!(super::load_trust_db().unwrap().is_none());
    }
}
