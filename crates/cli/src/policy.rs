use cargo_metadata::{Metadata, MetadataCommand};
use policy_core::Mode;
use std::io;
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
            let discovered = MetadataCommand::new().exec().map_err(io::Error::other)?;
            self.metadata = Some(discovered);
        }

        Ok(self
            .metadata
            .as_ref()
            .expect("metadata is populated before returning"))
    }
}

#[cfg(test)]
mod tests {
    use super::PolicyMetadata;

    #[test]
    fn caches_metadata_between_calls() {
        let mut metadata = PolicyMetadata::default();
        let first = metadata.metadata().unwrap() as *const _;
        let second = metadata.metadata().unwrap() as *const _;
        assert_eq!(first, second);
    }
}
