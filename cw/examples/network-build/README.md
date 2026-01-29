# Network Build Example

This crate's `build.rs` script only tests network access when `WARDEN_OFFLINE`
is set. Run the example with `cargo warden` to verify that outbound
connections are blocked:

```bash
WARDEN_OFFLINE=1 cargo run -p cargo-warden -- build
```

If the connection unexpectedly succeeds, the build script panics.
