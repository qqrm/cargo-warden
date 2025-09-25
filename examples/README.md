# Examples

Run the examples under `cargo warden` using the helper script:

```bash
./run_examples.sh
```

Expected output includes messages such as:

```text
== network-build ==
warning: network blocked: Operation not permitted (os error 1)

== spawn-bash ==
spawn blocked: Permission denied (os error 1)

== fs-outside-workspace ==
warning: write outside workspace blocked as expected: Operation not permitted (os error 1)

== ex_git_clone_https ==
warning: git clone blocked as expected: fatal: unable to access 'https://127.0.0.1:9/cargo-warden-denied/': Failed to connect to 127.0.0.1 port 9: Connection refused
```

An example Prometheus dashboard is provided in `PROMETHEUS_DASHBOARD.json`.
The agent exposes metrics on a configurable port, allowing the dashboard to work out of the box.
