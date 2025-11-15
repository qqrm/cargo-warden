use cargo_metadata::{Metadata, MetadataCommand};
use std::io;

pub(crate) fn fetch_metadata() -> io::Result<Metadata> {
    let mut command = MetadataCommand::new();
    if let Some(cargo) = std::env::var_os("CARGO").filter(|value| !value.is_empty()) {
        command.cargo_path(cargo);
    }
    command.no_deps();
    command.exec().map_err(io::Error::other)
}
