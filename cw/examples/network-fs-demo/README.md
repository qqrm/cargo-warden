# Network + Filesystem Demo

`warden-network-fs-demo` triggers both outbound network attempts and host
filesystem access from `build.rs`. Run it through `cargo warden` to watch the
sandbox record and block the operations.

Expected behavior:

- Write to `/tmp/warden-network-fs-demo.txt` fails under sandboxing.
- Reading `/etc/hostname` is denied.
- Connecting to `1.1.1.1:443` is blocked.
