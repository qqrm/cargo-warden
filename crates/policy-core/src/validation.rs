use thiserror::Error;

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("duplicate exec allow rule: {0}")]
    DuplicateExec(String),
    #[error("duplicate net host rule: {0}")]
    DuplicateNet(String),
    #[error("duplicate fs write rule: {0}")]
    DuplicateFsWrite(String),
    #[error("duplicate fs read rule: {0}")]
    DuplicateFsRead(String),
    #[error("duplicate env read rule: {0}")]
    DuplicateEnv(String),
    #[error("path {0} present in both read and write allowlists")]
    FsReadWriteConflict(String),
    #[error("duplicate syscall deny rule: {0}")]
    DuplicateSyscall(String),
}

#[derive(Debug, Error)]
pub enum ValidationWarning {
    #[error("exec allowlist is unused because exec.default is 'allow'")]
    UnusedExecAllow,
    #[error("network host allowlist is unused because net.default is 'allow'")]
    UnusedNetAllow,
    #[error("filesystem allowlists are unused because fs.default is 'unrestricted'")]
    UnusedFsAllow,
}

pub struct ValidationReport {
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<ValidationWarning>,
}
