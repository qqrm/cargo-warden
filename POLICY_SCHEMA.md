# Policy Schema

The `warden.toml` file defines permissions for builds.

```toml
mode = "enforce"
fs.default = "strict"
net.default = "deny"
exec.default = "allowlist"

[allow.exec]
allowed = ["rustc", "rustdoc"]

[allow.net]
hosts = ["127.0.0.1:1080"]

[allow.fs]
write_extra = ["/tmp/warden-scratch"]
read_extra = ["/usr/include"]

[allow.env]
read = ["HOME", "CARGO"]

[syscall]
deny = ["clone"]
```

## Fields

### `mode`
Operating mode of the sandbox.

- `"observe"` – collect events without blocking.
- `"enforce"` – deny actions not permitted.

### `fs.default`
Filesystem access policy.

- `"strict"` – restrict writes to `target` and `OUT_DIR`; restrict reads to the workspace.
- `"unrestricted"` – no filesystem restrictions.

### `net.default`
Network policy.

- `"deny"` – block outbound network by default.
- `"allow"` – allow outbound network.

### `exec.default`
Executable policy.

- `"allowlist"` – allow only explicitly listed executables.
- `"allow"` – permit all executions.

### `allow.exec.allowed`
List of executables permitted when `exec.default = "allowlist"`.

### `allow.net.hosts`
List of hosts allowed when `net.default = "deny"`. Each entry uses `host:port` form.

### `allow.fs.write_extra`
Additional paths allowed for writing when `fs.default = "strict"`.

### `allow.fs.read_extra`
Additional paths allowed for reading when `fs.default = "strict"`.

### `allow.env.read`
Environment variables that build scripts are allowed to read explicitly.

### `syscall.deny`
System calls blocked via seccomp.

## Internal Representation

`warden.toml` entries are converted into a list of permission rules during
deserialization. Each rule is represented by the `policy-core` crate as a
`Permission` enum variant (for example `FsRead`, `Exec`, `NetConnect`, or
`EnvRead`). A parsed [`Policy`](./crates/policy-core/src/lib.rs) contains the
requested `mode` and the collected permission rules in evaluation order.

## Workspace Policy
`workspace.warden.toml` allows per-package overrides.

```toml
[root]
mode = "enforce"

[members.pkg.exec]
default = "allow"
```

The `root` table defines the base policy applied to all workspace members.
Entries under `members.<name>` override fields for that specific package.
