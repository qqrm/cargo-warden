# ex_git_clone_https

This example crate contains a `build.rs` script that attempts to run
`git clone` over HTTPS. When network access is denied by Cargo Warden,
the build script logs a warning similar to:

```text
warning: git clone blocked as expected: fatal: unable to access 'https://127.0.0.1:9/cargo-warden-denied/': Failed to connect to 127.0.0.1 port 9: Connection refused
```

To run the example through the helper script:

```bash
bash ./scripts/run_examples.sh ex_git_clone_https
```

Set `WARDEN_EXAMPLE_REMOTE` to point at a real repository if you want to
attempt a live HTTPS clone under enforcement.
