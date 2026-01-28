# cargo-warden

## What this is

cargo-warden is a `cargo` subcommand that hardens **the Cargo build stage** for **untrusted Rust projects**.

It loads eBPF programs (BPF LSM + cgroup hooks) to restrict:

- outbound network connections
- process launches
- filesystem access

The goal is practical: you should be able to clone a suspicious/test-assignment repository, run `cargo build/test/run` through cargo-warden, and get a fail-closed guardrail with clear violation reports.

A single canonical problem statement lives in: `docs/SOURCE_OF_TRUTH.md`.

## Documentation

- [Source of truth (problem, goals, current reality)](docs/SOURCE_OF_TRUTH.md)
- [Installation Guide](docs/INSTALLATION.md)
- [Policy cookbook](docs/POLICY_COOKBOOK.md)
- [Release Process](docs/RELEASING.md)
- [Project Specification](docs/SPEC.md)
- [Contributing Guide](docs/CONTRIBUTING.md)

## Quickstart (current supported path)

1. Install the published CLI.

   ```bash
   cargo install cargo-warden --locked
   ```

   Prebuilt binaries for the eBPF programs are produced by the "Build BPF Artifacts" GitHub workflow. Download the latest `prebuilt.tar.gz` bundle (or reuse the copy from a release package) and place it under
   `${XDG_DATA_HOME:-$HOME/.local/share}/cargo-warden/bpf`.

2. Run in **observe** mode (audit only) with the built-in starter policy (no `warden.toml` required):

   ```bash
   cargo warden run -- cargo test
   ```

   Observe mode records violations without blocking execution.

3. When evaluating untrusted code, switch to **enforce** with an explicit policy file:

   ```bash
   cargo warden init
   # edit warden.toml
   cargo warden --mode enforce build -- --release
   ```

4. Export reports:

   ```bash
   cargo warden status
   cargo warden report --format sarif --output warden.sarif
   ```

### Important: host isolation guardrail (today)

The CLI currently refuses to run directly on a host. The supported path is an isolated container or a throwaway VM with its own network namespace.

A rootless `podman` example (deny network at the namespace boundary, then apply eBPF policy inside):

```bash
podman run --rm -it   --cap-add=CAP_BPF --cap-add=CAP_SYS_ADMIN   --security-opt=no-new-privileges --network=none   --userns=keep-id -v "$PWD:/workspace":z -w /workspace   ghcr.io/qqrm/cargo-warden:latest cargo warden status
```

This is a *safety default*, not a statement that eBPF enforcement requires containers. The roadmap is to add an explicit “host mode” flag while keeping safe defaults.

## Setup requirements

The project requires a Linux system with the following features:

- **Kernel ≥ 5.13**

```bash
uname -r
```

- **BPF LSM enabled**

```bash
cat /sys/kernel/security/lsm | grep bpf
```

- **cgroup v2 mounted**

```bash
mount | grep cgroup2
```

- **Capabilities** `CAP_SYS_ADMIN` (required) and `CAP_BPF` (preferred when available; some hosts keep BPF behind `CAP_SYS_ADMIN` only)

```bash
capsh --print | grep -E 'cap_(bpf|sys_admin)'
```

### Least-privilege execution

cargo-warden refuses to run as root or with an expanded capability set. Run it under a dedicated service account that has `CAP_SYS_ADMIN` and, when supported by the host, `CAP_BPF`.

In hermetic CI where capabilities cannot be delegated, set `CARGO_WARDEN_SKIP_PRIVILEGE_CHECK=1` only for the test job to bypass the guardrail. Do not use this escape hatch on shared hosts.

## CLI commands

| Command | Description |
|---------|-------------|
| `cargo warden build [-- <args>]` | Runs `cargo build` under eBPF enforcement, applying the merged policy set. |
| `cargo warden run -- <command>` | Executes any command tree under enforcement. |
| `cargo warden init` | Creates a default `warden.toml` policy file. |
| `cargo warden status` | Shows the effective policy, sandbox mode, and recent events. |
| `cargo warden report --format <text|json|sarif>` | Writes the latest audit events in the selected format. |

Global flags apply to every subcommand:

- `--allow <PATH>` – allow executables without editing the policy file.
- `--policy <FILE>` – merge additional policy files into the execution context.
- `--mode <observe|enforce>` – override the mode declared in the policy.

## Policy schema (current)

`warden.toml` configures build permissions.

```toml
mode = "enforce"
fs.default = "strict"
net.default = "deny"
exec.default = "allowlist"

[allow.exec]
allowed = ["rustc", "rustdoc"]

[allow.net]
# NOTE: currently socket addresses only (IP:port), not hostnames.
hosts = ["127.0.0.1:1080"]

[allow.fs]
write_extra = ["/tmp/warden-scratch"]
read_extra = ["/usr/include"]

[allow.env]
read = ["HOME", "CARGO"]

[syscall]
deny = ["clone"]
```

If you need “allow only crates.io/github.com” today, you must either run fully offline (`net.default = "deny"`) or manage IP allowlists (not stable for CDNs). See `docs/SOURCE_OF_TRUTH.md` for the roadmap options.
