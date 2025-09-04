# Network Build Example

This crate's `build.rs` script attempts to connect to `example.com:80`.
When run under `cargo warden`, the network request is denied and the build
script prints a warning such as:

```text
warning: network blocked: Operation not permitted (os error 1)
```
