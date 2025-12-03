# Network + Filesystem Demo

`warden-network-fs-demo` triggers both outbound network attempts and host
filesystem access from `build.rs`. Run it through `cargo warden` to watch the
sandbox record and block the operations.

Expected behavior:

- Write to `/tmp/warden-network-fs-demo.txt` fails under sandboxing.
- Reading `/etc/hostname` is denied.
- Connecting to `1.1.1.1:443` is blocked.

If the runtime reports trouble parsing the bundled eBPF object, rebuild the
artifacts locally and point the sandbox at them:

```bash
scripts/build-bpf.sh
WARDEN_BPF_DIST_DIR=$PWD/prebuilt cargo run --bin cargo-warden -- run -- \
  cargo build -p warden-network-fs-demo
```
