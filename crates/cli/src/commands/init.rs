use std::io::{self, BufRead, Write};
use std::path::Path;

pub(crate) fn exec() -> io::Result<()> {
    let mut input = io::stdin().lock();
    let mut output = io::stdout();
    exec_with(&mut input, &mut output)
}

pub(crate) fn exec_with<R: BufRead, W: Write>(input: &mut R, output: &mut W) -> io::Result<()> {
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
         # Strict mode implicitly allows writing to the Cargo target directory (including OUT_DIR).\n\
         write_extra = []\n\
         # Strict mode implicitly allows reading from the workspace root.\n\
         read_extra = []\n",
        allowed
    );
    std::fs::write(path, content)?;
    Ok(())
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
}
