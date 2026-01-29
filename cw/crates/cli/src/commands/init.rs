use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

const CONFIG_FILE: &str = "warden.toml";
const EVENTS_FILE: &str = "warden-events.jsonl";
const GITIGNORE: &str = ".gitignore";

pub(crate) fn exec(force: bool, yes: bool) -> io::Result<()> {
    let mut input = io::stdin().lock();
    let mut output = io::stdout();
    exec_with_opts(&mut input, &mut output, force, yes)
}

pub(crate) fn exec_with_opts<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    force: bool,
    yes: bool,
) -> io::Result<()> {
    let config_path = Path::new(CONFIG_FILE);
    let events_path = Path::new(EVENTS_FILE);

    // Refuse to clobber by default.
    if !force {
        if config_path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "warden.toml already exists (use --force to overwrite)",
            ));
        }
        if events_path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "warden-events.jsonl already exists (use --force to overwrite)",
            ));
        }
    }

    // Collect allowed executables.
    let entries: Vec<String> = if yes {
        Vec::new()
    } else {
        writeln!(
            output,
            "Enter allowed executables for [allow.exec] (comma separated, leave blank for none):",
        )?;
        let mut line = String::new();
        input.read_line(&mut line)?;
        line.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    };

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

    if force {
        // Best-effort: if the file exists, ensure it's writable by truncating.
        // Any error here should still bubble up.
        std::fs::write(config_path, &content)?;
    } else {
        std::fs::write(config_path, &content)?;
    }

    // Create (or overwrite) an empty events log.
    // It's jsonlines, so empty file is valid.
    if force {
        std::fs::write(events_path, "")?;
    } else {
        std::fs::write(events_path, "")?;
    }

    // Add to .gitignore (best-effort, do not fail init if it can't be updated).
    try_update_gitignore(Path::new(GITIGNORE), EVENTS_FILE);

    Ok(())
}

fn try_update_gitignore(path: &Path, entry: &str) {
    // Only touch .gitignore in the current dir; ignore errors on purpose.
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    if existing.lines().any(|l| l.trim() == entry) {
        return;
    }

    let mut new_content = existing;
    if !new_content.is_empty() && !new_content.ends_with('\n') {
        new_content.push('\n');
    }
    new_content.push_str(entry);
    new_content.push('\n');

    let _ = std::fs::write(path, new_content);
}

#[cfg(test)]
mod tests {
    use super::*;
    use policy_core::{ExecDefault, FsDefault, Mode, NetDefault, Policy};
    use serial_test::serial;
    use std::fs::File;
    use std::io::{self, Cursor};

    fn read(p: impl AsRef<Path>) -> String {
        std::fs::read_to_string(p).unwrap()
    }

    #[test]
    #[serial]
    fn exec_creates_files_and_prompts() {
        let dir = tempfile::tempdir().unwrap();
        let _guard = crate::test_support::DirGuard::change_to(dir.path());

        let input_data = "foo, bar\n";
        let mut input = Cursor::new(input_data.as_bytes());
        let mut output = Vec::new();

        exec_with_opts(&mut input, &mut output, false, false).unwrap();

        let config = read(dir.path().join(CONFIG_FILE));
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
        assert!(config.contains("# Strict mode implicitly allows reading from the workspace root."));

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

        // Events file exists and is empty.
        assert!(dir.path().join(EVENTS_FILE).exists());
        assert_eq!(read(dir.path().join(EVENTS_FILE)), "");

        // .gitignore contains events file.
        assert!(read(dir.path().join(GITIGNORE)).lines().any(|l| l.trim() == EVENTS_FILE));
    }

    #[test]
    #[serial]
    fn exec_yes_is_non_interactive_and_uses_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let _guard = crate::test_support::DirGuard::change_to(dir.path());

        let mut input = Cursor::new(b"SHOULD_NOT_BE_READ\n" as &[u8]);
        let mut output = Vec::new();

        exec_with_opts(&mut input, &mut output, false, true).unwrap();

        let config = read(dir.path().join(CONFIG_FILE));
        let policy = Policy::from_toml_str(&config).unwrap();
        assert!(policy.exec_allowed().next().is_none());

        let out_str = String::from_utf8(output).unwrap();
        assert!(!out_str.contains("Enter allowed executables"));
    }

    #[test]
    #[serial]
    fn exec_rejects_existing_files_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let _guard = crate::test_support::DirGuard::change_to(dir.path());

        File::create(CONFIG_FILE).unwrap();
        let mut input = Cursor::new(b"\n" as &[u8]);
        let mut output = Vec::new();

        let err = exec_with_opts(&mut input, &mut output, false, false).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    }

    #[test]
    #[serial]
    fn exec_force_overwrites_existing_files() {
        let dir = tempfile::tempdir().unwrap();
        let _guard = crate::test_support::DirGuard::change_to(dir.path());

        std::fs::write(CONFIG_FILE, "old").unwrap();
        std::fs::write(EVENTS_FILE, "old").unwrap();
        std::fs::write(GITIGNORE, "something\n").unwrap();

        let mut input = Cursor::new(b"\n" as &[u8]);
        let mut output = Vec::new();

        exec_with_opts(&mut input, &mut output, true, true).unwrap();

        let config = read(dir.path().join(CONFIG_FILE));
        assert!(config.contains("mode = \"enforce\""));
        assert_eq!(read(dir.path().join(EVENTS_FILE)), "");
        assert!(read(dir.path().join(GITIGNORE)).lines().any(|l| l.trim() == EVENTS_FILE));
    }
}
