# Policy cookbook (warden.toml)

Goal: run untrusted `cargo build/test/run` with fail-closed enforcement. If a build step tries to do something outside policy, cargo-warden should deny it and fail the command.

This covers build-stage behavior (build.rs, proc-macros, tests/benches). It is not static vulnerability scanning.

## Network

Current limitation: `allow.net.hosts` supports only `IP:port`, not hostnames.

Recommended safe default:

```toml
net.default = "deny"
```

If you must allow egress today, use a stable internal mirror/proxy and allow only its `IP:port`.

## Exec

Recommended default:

```toml
exec.default = "allowlist"

[allow.exec]
allowed = ["cargo", "rustc", "rustdoc", "ld"]
```

Only add tools you can justify (for example `git` when git deps are required).

## Filesystem

Keep writes limited to the workspace and build output. Deny secret locations.

```toml
fs.default = "strict"

[allow.fs]
# add exceptions only when required
read_extra = []
write_extra = []
```

Operational advice: run with a clean user account and keep secrets (SSH keys, tokens, wallets) out of that account.
