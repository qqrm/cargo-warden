use cargo_metadata::{Metadata, MetadataCommand};
use policy_core::Mode;
use std::{env, io, path::PathBuf};
use warden_policy_orchestrator as orchestrator;

pub(crate) use orchestrator::{IsolationConfig, PolicySource, PolicySourceKind, PolicyStatus};

#[derive(Default)]
pub(crate) struct PolicyMetadata {
    metadata: Option<Metadata>,
}

impl PolicyMetadata {
    pub(crate) fn configure_isolation(
        &mut self,
        allow: &[String],
        policy_paths: &[String],
        mode_override: Option<Mode>,
    ) -> io::Result<IsolationConfig> {
        let metadata = self.metadata()?;
        orchestrator::configure_isolation(metadata, allow, policy_paths, mode_override)
    }

    pub(crate) fn collect_policy_status(
        &mut self,
        policy_paths: &[String],
        mode_override: Option<Mode>,
    ) -> io::Result<PolicyStatus> {
        let metadata = self.metadata()?;
        orchestrator::collect_policy_status(metadata, policy_paths, mode_override)
    }

    fn metadata(&mut self) -> io::Result<&Metadata> {
        if self.metadata.is_none() {
            let workspace = workspace_dir()?;
            ensure_process_dir(&workspace)?;

            let mut command = MetadataCommand::new();
            command.current_dir(&workspace);
            let discovered = command.exec().map_err(io::Error::other)?;
            self.metadata = Some(discovered);
        }

        Ok(self
            .metadata
            .as_ref()
            .expect("metadata is populated before returning"))
    }
}

fn workspace_dir() -> io::Result<PathBuf> {
    if let Some(dir) = env::var_os("WARDEN_WORKSPACE_ROOT") {
        return Ok(PathBuf::from(dir));
    }

    if let Ok(dir) = env::current_dir() {
        return Ok(dir);
    }

    if let Some(dir) = env::var_os("CARGO_MANIFEST_DIR") {
        return Ok(PathBuf::from(dir));
    }

    Ok(PathBuf::from(env!("CARGO_MANIFEST_DIR")))
}

fn ensure_process_dir(workspace: &PathBuf) -> io::Result<()> {
    if env::current_dir().is_err() {
        env::set_current_dir(workspace)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::PolicyMetadata;
    use std::{env, path::PathBuf};
    use tempfile::tempdir;

    struct EnvGuard {
        original_dir: PathBuf,
        workspace_root: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn new() -> Self {
            let original_dir = env::current_dir().expect("current directory is available");
            let workspace_root = env::var_os("WARDEN_WORKSPACE_ROOT");

            Self {
                original_dir,
                workspace_root,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            let _ = env::set_current_dir(&self.original_dir);

            match &self.workspace_root {
                Some(value) => unsafe {
                    // SAFETY: tests serialize access to environment variables and restore the
                    // previous value when the guard drops.
                    env::set_var("WARDEN_WORKSPACE_ROOT", value);
                },
                None => unsafe {
                    // SAFETY: tests serialize access to environment variables and restore the
                    // previous value when the guard drops.
                    env::remove_var("WARDEN_WORKSPACE_ROOT");
                },
            }
        }
    }

    #[test]
    #[serial_test::serial]
    fn caches_metadata_between_calls() {
        let mut metadata = PolicyMetadata::default();
        let first = metadata.metadata().unwrap() as *const _;
        let second = metadata.metadata().unwrap() as *const _;
        assert_eq!(first, second);
    }

    #[test]
    #[serial_test::serial]
    #[ignore = "Disabled in CI pending investigation of flaky current-dir teardown"]
    fn recovers_when_current_dir_is_missing() {
        let _guard = EnvGuard::new();
        let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

        let temp = tempdir().expect("tempdir is created");
        env::set_current_dir(temp.path()).expect("current dir can be set to tempdir");
        let temp_path = temp.keep();
        std::fs::remove_dir_all(temp_path).expect("tempdir is removed");

        unsafe {
            // SAFETY: tests serialize access to environment variables and restore the previous
            // state through EnvGuard.
            env::set_var("WARDEN_WORKSPACE_ROOT", &workspace);
        }

        let mut metadata = PolicyMetadata::default();
        metadata
            .metadata()
            .expect("metadata loads even when current dir is missing");
    }
}
