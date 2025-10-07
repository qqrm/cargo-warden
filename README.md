# cargo-warden

## Overview

cargo-warden hardens `cargo build` by loading eBPF programs that restrict
filesystem access, process launches, and outbound network traffic. The CLI wraps
`cargo` commands, enforces declarative policies, and emits actionable event
logs.

## Quickstart

1. Install the required toolchains and scripts.

   ```bash
   ./repo-setup.sh
   ```

2. Generate a starter policy.

   ```bash
   cargo warden init
   ```

3. Edit `warden.toml` to reflect the permissions your build needs.

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
   # Strict mode implicitly allows writing to Cargo's target directory (including OUT_DIR).
   write_extra = ["/tmp/warden-scratch"]
   # Strict mode implicitly allows reading from the workspace root.
   read_extra = ["/usr/include"]
   ```

4. Enforce the policy when building.

   ```bash
   cargo warden build -- --release
   ```

   Pass `--policy path/to/file` to load additional policy files and forward
   build arguments after `--`.

5. Observe other commands before promoting new rules to enforcement.

   ```bash
   cargo warden run --mode observe -- cargo test
   ```

6. Inspect the active configuration and export reports.

   ```bash
   cargo warden status
   cargo warden report --format sarif --output warden.sarif
   ```

## Setup Requirements

The project requires a Linux system with the following features:

- **Kernel ≥5.13**

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

- **Capabilities** `CAP_BPF` and `CAP_SYS_ADMIN`

```bash
capsh --print | grep -E 'cap_(bpf|sys_admin)'
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `cargo warden build [-- <args>]` | Runs `cargo build` inside the sandbox, applying the merged policy set. |
| `cargo warden run -- <command>` | Executes any command tree under warden's isolation. |
| `cargo warden init` | Creates a default `warden.toml` policy file. |
| `cargo warden status` | Shows the effective policy, sandbox mode, and recent events. |
| `cargo warden report --format <text\|json\|sarif>` | Writes the latest audit events in the selected format. |

Global flags apply to every subcommand:

- `--allow <PATH>` – allow executables without editing the policy file.
- `--policy <FILE>` – merge additional policy files into the execution context.
- `--mode <observe|enforce>` – override the mode declared in the policy.

## Policy Schema

`warden.toml` configures build permissions. Strict filesystem mode implicitly
allows writes to the Cargo `target` directory (including `OUT_DIR`) and reads
from the workspace root.

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

### Field reference

- `mode` – selects `observe` (audit only) or `enforce` (deny violations).
- `fs.default` – `strict` restricts writes to `target` and reads to the
  workspace; `unrestricted` disables filesystem enforcement.
- `net.default` – `deny` blocks outbound network unless allowlisted; `allow`
  keeps network open.
- `exec.default` – `allowlist` limits execution to entries in
  `allow.exec.allowed`; `allow` permits all executions.
- `allow.exec.allowed` – executables permitted when `exec.default = "allowlist"`.
- `allow.net.hosts` – host:port pairs allowed when `net.default = "deny"`.
- `allow.fs.write_extra` – additional write paths when `fs.default = "strict"`.
- `allow.fs.read_extra` – additional read paths when `fs.default = "strict"`.
- `allow.env.read` – environment variables exposed to build scripts.
- `syscall.deny` – extra syscalls denied via seccomp filters.

### Workspace policies

`workspace.warden.toml` lets you override rules per package.

```toml
[root]
mode = "enforce"

[members.pkg.exec]
default = "allow"
```

The `root` table defines the base policy. Entries under `members.<name>` replace
fields for that specific crate.

## Logs and Reports

The runtime writes JSONL events to `warden.log`. Tail the file to watch
decisions in real time:

```bash
tail -f warden.log
```

The `report` subcommand exports aggregated summaries in text, JSON, or SARIF.

### Event Log ABI

The eBPF layer emits `Event` records through a ring buffer shared with
userspace:

```rust
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Event {
    pub pid: u32,
    pub tgid: u32,
    pub time_ns: u64,
    pub unit: u8,        // 0 Other, 1 BuildRs, 2 ProcMacro, 3 Rustc, 4 Linker
    pub action: u8,      // 0 Open, 1 Rename, 2 Unlink, 3 Exec, 4 Connect
    pub verdict: u8,     // 0 Allowed, 1 Denied
    pub reserved: u8,
    pub container_id: u64,
    pub caps: u64,
    pub path_or_addr: [u8; 256],
    pub needed_perm: [u8; 64],
}
```

Each entry captures the process identifiers, workload classification, audited
operation, verdict, and suggested permission needed to allow the action.

## Security Model

cargo-warden treats build scripts and procedural macros as untrusted code. They
run inside the sandbox with restricted filesystem, network, and exec access.
Policies should be tracked in version control (or signed) to prevent tampering.

Threat considerations:

- **Supply chain attacks** – malicious dependencies attempting exfiltration or
  process spawning are denied unless explicitly allowed.
- **Privilege escalation** – escaping via kernel exploits or privileged
  capabilities is out of scope and relies on a hardened host.
- **Denial of service** – overly strict policies can break legitimate builds;
  iterate in observe mode before enforcing new rules.

Future work includes additional kernel integrations (such as fanotify for deep
filesystem auditing) and richer telemetry pipelines to help tune policies.

## Building prebuilt BPF objects

Generate the prebuilt BPF artifacts with:

```bash
scripts/build-bpf.sh
```

The script installs the nightly toolchain, required components and the `bpf-linker` before placing the resulting object files under `prebuilt/<arch>`.

Generated artifacts are excluded from version control; rerun the script to refresh them.

## Sandbox Hardening

cargo-warden layers eBPF enforcement with a seccomp deny-list sourced from the
active policy. When the policy runs in `enforce` mode, the runtime loads kernel
filters (for example, `clone`, `execve`, or entries declared under
`[syscall] deny`). Observability remains available in `observe` mode, allowing
you to refine rules before enabling blocking.

## Local CI parity

Use `scripts/run_ci_checks.sh` to reproduce the pull request GitHub Actions checks locally. The script:

- installs missing Debian packages (`pkg-config`, `libseccomp-dev`, `protobuf-compiler`, `jq`, `xxhash`),
- installs the cargo subcommands required by the pipeline (`cargo-machete`, `cargo-audit`, `cargo-nextest`, `cargo-udeps`),
- ensures the stable toolchain has the `rustfmt`, `clippy`, and `llvm-tools-preview` components, plus a nightly toolchain for `cargo udeps`,
- runs the same validation commands as the CI jobs, including formatting, linting, tests, supply-chain checks, and example runs.

Run it from the repository root:

```bash
scripts/run_ci_checks.sh
```

For a byte-for-byte reproduction of the GitHub Actions workflow, run it through [wrkflw](https://github.com/bahdotsh/wrkflw):

```bash
wrkflw validate
wrkflw run .github/workflows/CI.yml
```

## Repository Maintenance

Use `scripts/prune_branches.sh` to list feature branches that have been inactive for more than 48 hours. Pass `--prune` to
delete the remote branches once you have reviewed the list. Export `CARGO_WARDEN_PRUNE_AGE` (in seconds) to customise the age
threshold.
