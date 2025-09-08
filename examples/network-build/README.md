# Network Build Example

This crate's `build.rs` script attempts to connect to `example.com:80`.
When run under `cargo warden`, the network request fails. If the connection
unexpectedly succeeds, the build script panics.
