use std::collections::BTreeMap;
use std::io::{self, BufRead, Write};
use std::path::Path;

use event_reporting::EventRecord;
use policy_core::Mode;
use serde_jsonlines::JsonLinesReader;

pub(crate) fn exec() -> io::Result<()> {
    let mut input = io::stdin().lock();
    let mut output = io::stdout();
    exec_with(&mut input, &mut output)
}

pub(crate) fn exec_with<R: BufRead, W: Write>(input: &mut R, output: &mut W) -> io::Result<()> {
    exec_with_path(input, output, Path::new("warden.toml"))
}

pub(crate) fn exec_to(output_path: &Path) -> io::Result<()> {
    let mut input = io::stdin().lock();
    let mut output = io::stdout();
    exec_with_path(&mut input, &mut output, output_path)
}

fn exec_with_path<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    path: &Path,
) -> io::Result<()> {
    if path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{} already exists", path.display()),
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
         # Strict mode implicitly allows writing to the Cargo target directory (including OUT_DIR).\n\
         write_extra = []\n\
         # Strict mode implicitly allows reading from the workspace root.\n\
         read_extra = []\n",
        allowed
    );
    std::fs::write(path, content)?;
    Ok(())
}

pub(crate) fn exec_from_events(
    events_path: &Path,
    output_path: &Path,
    mode: Mode,
) -> io::Result<()> {
    if output_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{} already exists", output_path.display()),
        ));
    }

    let summary = collect_policy_hints(events_path)?;
    let content = render_generated_policy(&summary, mode);
    std::fs::write(output_path, content)?;

    Ok(())
}

#[derive(Debug, Default)]
struct PolicyHintSummary {
    allow: BTreeMap<&'static str, Vec<String>>,
    unknown: Vec<(String, String)>,
    skipped: usize,
}

fn collect_policy_hints(events_path: &Path) -> io::Result<PolicyHintSummary> {
    let mut summary = PolicyHintSummary::default();

    let file = std::fs::File::open(events_path)?;
    let reader = io::BufReader::new(file);

    for record in JsonLinesReader::new(reader).read_all::<EventRecord>() {
        match record {
            Ok(event) => {
                if event.verdict != 1 {
                    continue;
                }
                if event.needed_perm.is_empty() {
                    continue;
                }
                match event.needed_perm.as_str() {
                    "allow.exec.allowed" => {
                        push_value(&mut summary.allow, "allow.exec", &event.path_or_addr)
                    }
                    "allow.net.hosts" => {
                        push_value(&mut summary.allow, "allow.net", &event.path_or_addr)
                    }
                    "allow.fs.write_extra" => push_value(
                        &mut summary.allow,
                        "allow.fs.write_extra",
                        &event.path_or_addr,
                    ),
                    "allow.fs.read_extra" => push_value(
                        &mut summary.allow,
                        "allow.fs.read_extra",
                        &event.path_or_addr,
                    ),
                    "allow.env.read" => {
                        push_value(&mut summary.allow, "allow.env", &event.path_or_addr)
                    }
                    "syscall.deny" => {
                        push_value(&mut summary.allow, "syscall.deny", &event.path_or_addr)
                    }
                    other => summary
                        .unknown
                        .push((other.to_string(), event.path_or_addr)),
                }
            }
            Err(err) if is_deserialization_error(&err) => summary.skipped += 1,
            Err(err) => return Err(err),
        }
    }

    for values in summary.allow.values_mut() {
        values.sort();
        values.dedup();
    }
    summary.unknown.sort();
    summary.unknown.dedup();

    Ok(summary)
}

fn is_deserialization_error(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::InvalidData
        && err
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<serde_json::Error>())
            .is_some()
}

fn push_value(map: &mut BTreeMap<&'static str, Vec<String>>, key: &'static str, value: &str) {
    map.entry(key).or_default().push(value.to_string());
}

fn render_generated_policy(summary: &PolicyHintSummary, mode: Mode) -> String {
    let mode_str = match mode {
        Mode::Observe => "observe",
        Mode::Enforce => "enforce",
    };

    let exec_allowed = toml_array(summary.allow.get("allow.exec").cloned().unwrap_or_default());
    let net_hosts = toml_array(summary.allow.get("allow.net").cloned().unwrap_or_default());
    let fs_write = toml_array(
        summary
            .allow
            .get("allow.fs.write_extra")
            .cloned()
            .unwrap_or_default(),
    );
    let fs_read = toml_array(
        summary
            .allow
            .get("allow.fs.read_extra")
            .cloned()
            .unwrap_or_default(),
    );

    let mut content = format!(
        "# Generated from denied events in warden-events.jsonl\n\
# Review and tighten before using in production CI.\n\
mode = \"{}\"\n\
fs.default = \"strict\"\n\
net.default = \"deny\"\n\
exec.default = \"allowlist\"\n\
\n\
[allow.exec]\n\
allowed = {}\n\
\n\
[allow.net]\n\
hosts = {}\n\
\n\
[allow.fs]\n\
# Strict mode implicitly allows writing to the Cargo target directory (including OUT_DIR).\n\
write_extra = {}\n\
# Strict mode implicitly allows reading from the workspace root.\n\
read_extra = {}\n",
        mode_str, exec_allowed, net_hosts, fs_write, fs_read
    );

    if let Some(env) = summary.allow.get("allow.env") {
        let env_read = toml_array(env.clone());
        content.push_str("\n[allow.env]\n");
        content.push_str(&format!("read = {}\n", env_read));
    }

    if let Some(syscalls) = summary.allow.get("syscall.deny") {
        let deny = toml_array(syscalls.clone());
        content.push_str("\n[syscall]\n");
        content.push_str(&format!("deny = {}\n", deny));
    }

    if summary.skipped > 0 {
        content.push_str(&format!(
            "\n# Note: skipped {} malformed event records while generating.\n",
            summary.skipped
        ));
    }
    if !summary.unknown.is_empty() {
        content.push_str("\n# Unhandled policy hints (needed_perm => value):\n");
        for (perm, value) in &summary.unknown {
            content.push_str(&format!("# - {perm} => {value}\n"));
        }
    }

    content
}

fn toml_array(values: Vec<String>) -> toml::Value {
    toml::Value::Array(values.into_iter().map(toml::Value::String).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use policy_core::{ExecDefault, FsDefault, Mode, NetDefault, Policy};
    use serial_test::serial;
    use std::fs::File;
    use std::io::{self, Cursor};

    #[test]
    #[serial]
    fn exec_creates_file_and_prompts() {
        let dir = tempfile::tempdir().unwrap();
        let _guard = crate::test_support::DirGuard::change_to(dir.path());

        let input_data = "foo, bar\n";
        let mut input = Cursor::new(input_data.as_bytes());
        let mut output = Vec::new();

        exec_with(&mut input, &mut output).unwrap();

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
        assert!(config.contains(
            "# Strict mode implicitly allows writing to the Cargo target directory (including OUT_DIR)."
        ));
        assert!(
            config.contains("# Strict mode implicitly allows reading from the workspace root.")
        );

        let policy = Policy::from_toml_str(&config).unwrap();
        assert_eq!(policy.mode, Mode::Enforce);
        assert_eq!(policy.fs_default(), FsDefault::Strict);
        assert_eq!(policy.net_default(), NetDefault::Deny);
        assert_eq!(policy.exec_default(), ExecDefault::Allowlist);
        let mut exec_allowed: Vec<_> = policy.exec_allowed().cloned().collect();
        exec_allowed.sort();
        assert_eq!(exec_allowed, ["bar", "foo"]);
        assert!(policy.net_hosts().next().is_none());
        assert!(policy.fs_write_paths().next().is_none());
        assert!(policy.fs_read_paths().next().is_none());
    }

    #[test]
    #[serial]
    fn exec_produces_parseable_policy() {
        let dir = tempfile::tempdir().unwrap();
        let _guard = crate::test_support::DirGuard::change_to(dir.path());

        let mut input = Cursor::new(b"\n" as &[u8]);
        let mut output = Vec::new();

        exec_with(&mut input, &mut output).unwrap();

        let config_path = dir.path().join("warden.toml");
        let config = std::fs::read_to_string(&config_path).unwrap();
        Policy::from_toml_str(&config).unwrap();
    }

    #[test]
    #[serial]
    fn exec_rejects_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let _guard = crate::test_support::DirGuard::change_to(dir.path());

        File::create("warden.toml").unwrap();
        let mut input = Cursor::new(b"\n" as &[u8]);
        let mut output = Vec::new();
        let err = exec_with(&mut input, &mut output).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    }

    #[test]
    #[serial]
    fn exec_from_events_generates_policy() {
        let dir = tempfile::tempdir().unwrap();
        let _guard = crate::test_support::DirGuard::change_to(dir.path());

        let events_path = dir.path().join("warden-events.jsonl");
        std::fs::write(
            &events_path,
            "{\"pid\":1,\"tgid\":1,\"time_ns\":0,\"unit\":0,\"action\":0,\"verdict\":1,\"container_id\":0,\"caps\":0,\"path_or_addr\":\"/bin/bash\",\"needed_perm\":\"allow.exec.allowed\"}\n\
{\"pid\":2,\"tgid\":2,\"time_ns\":0,\"unit\":0,\"action\":0,\"verdict\":1,\"container_id\":0,\"caps\":0,\"path_or_addr\":\"1.2.3.4:443\",\"needed_perm\":\"allow.net.hosts\"}\n\
{\"pid\":3,\"tgid\":3,\"time_ns\":0,\"unit\":0,\"action\":0,\"verdict\":1,\"container_id\":0,\"caps\":0,\"path_or_addr\":\"/tmp/foo\",\"needed_perm\":\"allow.fs.write_extra\"}\n",
        )
        .unwrap();

        let out = dir.path().join("generated.toml");
        exec_from_events(&events_path, &out, Mode::Enforce).unwrap();

        let config = std::fs::read_to_string(&out).unwrap();
        let policy = Policy::from_toml_str(&config).unwrap();
        assert_eq!(policy.mode, Mode::Enforce);
        assert!(policy.exec_allowed().any(|bin| bin == "/bin/bash"));
        assert!(policy.net_hosts().any(|host| host == "1.2.3.4:443"));
        assert!(
            policy
                .fs_write_paths()
                .any(|path| path.to_string_lossy() == "/tmp/foo")
        );
    }
}
