# End-to-End Policy Tutorial

This guide shows how to create and enforce a `warden.toml` policy for a Rust project.

## 1. Initialize policy

```bash
cargo warden init
```

This generates `warden.toml` with default restrictive rules.

## 2. Inspect and edit policy

Open `warden.toml` and adjust rules. For example, to allow running `rustfmt` and accessing a local HTTP proxy:

```toml
mode = "enforce"
fs.default = "strict"
net.default = "deny"
exec.default = "allowlist"

[allow.exec]
allowed = ["rustc", "rustdoc", "rustfmt"]

[allow.net]
hosts = ["127.0.0.1:8080"]

[allow.fs]
# Strict mode implicitly allows writing to the Cargo target directory (including OUT_DIR).
write_extra = ["/tmp/warden-scratch"]
# Strict mode implicitly allows reading from the workspace root.
read_extra = ["/usr/include"]
```

Save changes.

Strict filesystem mode always grants write access to Cargo's `target` directory (which
covers `OUT_DIR`) and read access to the workspace root. The `write_extra` and
`read_extra` arrays extend those implicit permissions when the build needs
additional paths.

## 3. Build under enforcement

```bash
cargo warden build
```

The build runs in a sandbox. Any denied action shows a hint describing the required permission.

## 4. Review logs

The agent writes events to `warden.log` in JSONL format. Each entry includes:

- `pid` – process identifier
- `unit` – build unit such as `rustc` or `build.rs`
- `action` – network, exec, or filesystem operation
- `path` or `address` – resource being accessed
- `verdict` – `allow` or `deny`

Tail the log to observe decisions in real time:

```bash
tail -f warden.log
```

## 5. Export reports

```bash
cargo warden report
```

By default, the command prints recent sandbox events in a readable text format. Use JSON when integrating with tooling:

```bash
cargo warden report --format json
```

Generate a SARIF file for ingestion by security scanners:

```bash
cargo warden report --format sarif --output warden.sarif
```

## 6. Workspaces

For multi-crate workspaces, create `workspace.warden.toml` to override rules per member:

```toml
[root]
mode = "enforce"

[members.example.exec]
default = "allow"
```

Run `cargo warden build` from the workspace root to apply these overrides.

This tutorial demonstrates the full flow from policy creation to enforcement using `cargo-warden`.
