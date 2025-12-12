# ex_git_clone_https

This example crate contains a `build.rs` script that attempts to run
`git clone` over HTTPS. When network access is denied by Cargo Warden,
the build script logs a warning similar to:

```text
warning: git clone blocked as expected: fatal: unable to access 'https://127.0.0.1:9/cargo-warden-denied/': Failed to connect to 127.0.0.1 port 9: Connection refused
```

Run the example directly through the CLI:

```bash
WARDEN_FAKE_SANDBOX=1 cargo run --bin cargo-warden -- run -- cargo build -p warden-git-clone-https
```

Set `WARDEN_EXAMPLE_REMOTE` to point at a real repository if you want to
attempt a live HTTPS clone under enforcement.
