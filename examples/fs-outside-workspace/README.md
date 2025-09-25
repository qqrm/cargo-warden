# fs-outside-workspace

This example crate has a `build.rs` script that attempts to write to `/tmp/cargo-warden-outside-workspace`.
When the sandbox runs in enforce mode, the write should be denied and reported as a warning by the build script.
