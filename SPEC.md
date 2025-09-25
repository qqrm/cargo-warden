# cargo-warden OSS v0.1 - Modular Specification

Version: 0.1
Status: Draft for public OSS release

## 0. Implementation Status

| Area | Status | Notes |
|------|--------|-------|
| Kernel enforcement pipeline (bpf-api, bpf-core, sandbox runtime) | ✅ Complete | Implemented across `crates/bpf-api`, `crates/bpf-core`, `crates/bpf-host`, and `crates/sandbox-runtime` with unit coverage. |
| Policy engine and compiler | ✅ Complete | Policy parsing, validation, and map compilation live in `crates/policy-core` and `crates/policy-compiler`, including property-based tests. |
| CLI workflow (`build`, `run`, `init`, `status`, `report`) | ✅ Complete | `crates/cli` wires policy loading, sandbox orchestration, and reporting, supporting text, JSON, and SARIF outputs. |
| Agent, metrics, and event export | ✅ Complete | `crates/agent-lite` and `crates/event-reporting` process ring-buffer events, publish Prometheus metrics, and generate SARIF logs. |
| Test harness and fake sandbox | ✅ Complete | `crates/testkits` and the fake sandbox runtime back CLI integration tests and layout assertions. |
| Example workspaces | ✅ Complete | Example crates cover network, process launch, filesystem, proc-macro resource abuse, and git clone scenarios. |
| Documentation set | 🟡 In Progress | README and security model drafts exist; `CONTRIBUTING`, `SECURITY`, `CODEOWNERS`, and PR templates are still outstanding. |

Author: Alex + contributors
Core project license: MIT or Apache-2.0
Target platform: Linux kernel >= 5.13 with BPF LSM and cgroup v2 enabled

## 1. Introduction

The goal of cargo-warden is to provide Rust developers with a secure sandbox for the Cargo build stage without patching cargo or rustc. The tool restricts network access, arbitrary executable launches, and file system access during `cargo build`. The permission model is declarative and transparent. The project focuses on modularity and agent-oriented development. Each module has a small scope, clear boundaries, and stable contracts.

## 2. Problem Statement and Goals

**Problem**: `build.rs`, procedural macros, and auxiliary utilities executed during build may perform arbitrary actions—network calls, spawning processes, writing outside `target`—which pose supply chain risks.

**Goals**

* Hard isolation of the build at the kernel level without changing the Cargo ecosystem.
* A clear permission model with project configuration and a local trust database.
* Modular architecture for agent-based development and independent testing.
* Low overhead.

**Non-goals**

* Source analysis for deriving policies.
* Replacement for cargo-vet or dependency scanners.
* Runtime protection of launched binaries.

## 3. Scope and Use Cases

* Local development: enforce or observe mode for `cargo build` and `cargo test`.
* CI on a Linux runner: enforce policy for PRs and releases.
* Research mode: collect metrics on build events and anomalies.

## 4. Threat Model and Coverage

| Threat                           | Where it occurs                    | Risk                                | Mitigated via eBPF |
|----------------------------------|------------------------------------|-------------------------------------|--------------------|
| Exec Injection                   | `build.rs`, proc-macro              | launching bash/curl, malicious code | LSM `bprm_check_security` |
| Network Exfiltration/Injection  | `build.rs` HTTP(S), curl           | key leaks, dependency tampering     | `cgroup/connect4/6` deny-all |
| Filesystem Abuse (write)        | `build.rs` writes outside `target`/`OUT_DIR` | modifying `$HOME/.ssh`, `/etc` | LSM `file_open`, `inode_unlink/rename` |
| Filesystem Abuse (read)         | `build.rs` reads `/etc`, `~/.ssh`   | stealing passwords and private data | LSM `file_open` (read deny) |
| Persistence / Sabotage          | `build.rs` alters `.git/`, `.bashrc` | backdoors, sabotage                | LSM `file_open` + workspace write deny |
| Proc-macro Resource Hog (DoS)   | derive macro loads entire tree     | long builds, OOM crashes           | `sched/trace` + metrics agent |
| Time/Env Abuse                  | `build.rs` reads time/env          | nondeterministic builds            | control env-read, time deny/allow |

**Not covered**

| What it doesn't cover           | Why |
|---------------------------------|-----|
| Rustc or LLVM bugs              | Compiler vulnerabilities remain |
| Runtime vulnerabilities of binaries | Protection is only at build stage |
| Crates.io source substitution   | Use cargo-vet and review, not sandbox |
| Social engineering and malicious maintainers | Sandbox limits damage but doesn't replace review |
| Non-Linux attacks               | Requires Linux >= 5.13 with BPF LSM |

## 5. Requirements

**Functional**

* Block `exec` outside the allowed list.
* Block network by default and allow only explicit exceptions.
* Restrict writes to `target` and `OUT_DIR`; restrict reads to workspace and explicit paths.
* Provide readable violation reports with suggestions for required permissions.
* Operate as a `cargo` subcommand and as a wrapper around arbitrary commands.

**Non-functional**

* CPU overhead ≤ 3% on typical projects, I/O overhead ≤ 5%.
* Fail-closed and immutable policies during build.
* Modular architecture with small modules and clear contracts.

**Compatibility**

* Linux kernel ≥ 5.13, BPF LSM, cgroup v2.
* Requires `CAP_BPF` and `CAP_SYS_ADMIN` to load eBPF programs.

## 6. High-Level Architecture

Components:

* **qqrm-bpf-core** – eBPF programs (LSM and cgroup) for exec, filesystem, and network.
* **qqrm-bpf-api** – shared structures and map layouts with stable ABI.
* **qqrm-policy-core** – permission model and config parsing.
* **qqrm-policy-compiler** – compiles policies into compact structures for eBPF maps.
* **qqrm-agent-lite** – userspace daemon for events, logs, and basic telemetry.
* **cli** – `cargo-warden` subcommand and wrapper: creates cgroup, loads BPF, handles UX.
* **qqrm-testkits** – utilities for integration testing.
* **examples** – demonstration projects with benign and malicious cases.

Boundaries:

* `qqrm-bpf-core` imports only types from `qqrm-bpf-api`.
* `cli` and `qqrm-agent-lite` contain no business logic—only wiring and output.
* `qqrm-policy-core` knows nothing about eBPF, `qqrm-policy-compiler` knows nothing about the CLI.

## 7. Workspace Layout and Features

Workspace crates:

* ✅ `crates/bpf-api` (spec: `qqrm-bpf-api`)
* ✅ `crates/bpf-core` (spec: `qqrm-bpf-core`)
* ✅ `crates/policy-core` (spec: `qqrm-policy-core`)
* ✅ `crates/policy-compiler` (spec: `qqrm-policy-compiler`)
* ✅ `crates/agent-lite` (spec: `qqrm-agent-lite`)
* ✅ `crates/cli`
* ✅ `crates/testkits` (spec: `qqrm-testkits`)
* ✅ `examples/*` – `network-build`, `spawn-bash`, `fs-outside-workspace`, `proc-macro-hog`, and `git-clone-https`

Feature flags:

* `observe` – log events without blocking.
* `enforce` – enable blocking with `EPERM`.
* `fs-strict` – restrict writes to `target` and `OUT_DIR` only.
* `net-allowlist` – simple host:port allowlist for OSS.

## 8. Module Contracts

`qqrm-bpf-api`

```rust
#[repr(C)]
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

`qqrm-policy-core`

```rust
pub enum Mode {
  Observe,
  Enforce,
}

pub struct Policy {
  pub mode: Mode,
  pub(crate) fs: FsRules,
  pub(crate) net: NetRules,
  pub(crate) exec: ExecRules,
  pub(crate) syscall: SyscallRules,
  pub(crate) env: EnvRules,
}

impl Policy {
  pub fn fs_default(&self) -> FsDefault;
  pub fn fs_read_paths(&self) -> impl Iterator<Item = &PathBuf>;
  pub fn fs_write_paths(&self) -> impl Iterator<Item = &PathBuf>;
  pub fn net_default(&self) -> NetDefault;
  pub fn net_hosts(&self) -> impl Iterator<Item = &String>;
  pub fn exec_default(&self) -> ExecDefault;
  pub fn exec_allowed(&self) -> impl Iterator<Item = &String>;
  pub fn syscall_deny(&self) -> impl Iterator<Item = &String>;
  pub fn env_read_vars(&self) -> impl Iterator<Item = &String>;
}
```

`qqrm-policy-compiler`

```rust
pub struct MapsLayout { /* descriptions for eBPF maps */ }

pub fn compile(policy: &Policy) -> Result<MapsLayout, Error>;
```

`qqrm-agent-lite`

```rust
pub fn run(layout: &MapsLayout) -> anyhow::Result<Report>;
```

`cli`

```
cargo warden build
cargo warden run -- cargo test
cargo warden report --format json|text
```

## 9. Configurations and Permission Format

Project file `warden.toml`:

```toml
mode = "enforce"            # observe or enforce
fs.default = "strict"       # strict – write only to target and OUT_DIR
net.default = "deny"         # deny – network off, allow by rules
exec.default = "allowlist"   # list of tool binaries

[allow.exec]
allowed = ["rustc", "rustdoc", "ar", "ld", "cc", "pkg-config"]

[allow.net]
hosts = ["127.0.0.1:1080"]  # example local proxy

[allow.fs]
# Strict mode implicitly allows writing to the Cargo target directory (including OUT_DIR).
write_extra = ["/tmp/warden-scratch"]
# Strict mode implicitly allows reading from the workspace root.
read_extra  = ["/usr/include"]

[allow.env]
read = ["CARGO", "OUT_DIR"]
```

Strict filesystem mode automatically whitelists the workspace root for reads and the
Cargo `target` directory (which covers `OUT_DIR`) for writes. The `allow.fs`
settings extend those implicit permissions for additional paths.

Optional declarations in package `Cargo.toml`:

```toml
[package.metadata.cargo-warden]
reason = "Code generation from .proto"
permissions = [
  "fs:read:workspace",
  "fs:write:target",
  "exec:/usr/bin/protoc"
]

[package.metadata.cargo-warden.proc-macro]
permissions = ["fs:read:workspace"]
```

User’s local trust database:

```json
{
  "entries": [
    {
      "package": "protoc-gen",
      "version_range": "^0.3",
      "permissions": ["exec:/usr/bin/protoc", "fs:read:/usr/include"],
      "granted_at": "2025-09-01T12:00:00Z"
    }
  ]
}
```

## 10. eBPF Programs and Hook Points

**LSM hooks**

* `bprm_check_security` – exec control, deny by default, allow via whitelist.
* `file_open` – control read and write, check workspace, target, and lists.
* `inode_unlink` and `inode_rename` – prohibit deletion and renaming outside allowed paths.

**Cgroup hooks**

* `cgroup/connect4` and `cgroup/connect6` – deny outbound connections, allow only from allowlist or to `127.0.0.1:proxy`.
* `cgroup/sendmsg4` and `cgroup/sendmsg6` – deny UDP bypass of DNS and proxy.

**Tracepoints**

* `syscalls/sys_enter_execve` – inspect argv to classify commands and store pid→unit mappings.
* `sched/sched_process_fork` – inherit the parent's unit for newly forked tasks.
* `sched/sched_process_exit` – remove workload entries when tasks terminate.

**Performance structures in eBPF**

* Prefix trees for read/write path checks.
* Hash set of allowed exec paths.
* Compact bitmasks for capability flags.
* Hash map (`WORKLOAD_UNITS`) mapping pid to workload units for policy lookups.

## 11. Execution Flow

* `cli` creates a cgroup for the build and loads eBPF programs.
* Launches `cargo` as a child process; the entire process tree inherits the cgroup.
* Tracepoints classify commands, populate `WORKLOAD_UNITS`, and keep unit hierarchy in sync.
* On risky operations eBPF returns Allow or `EPERM`.
* `qqrm-agent-lite` reads events from a ring buffer and writes a report.

## 12. User Experience and Commands

Commands:

* `cargo warden build`
* `cargo warden run` – any command under protection
* `cargo warden report` – print report and statistics

Behavior on violation:

```
Violation: exec by build.rs of crate foo v0.3.1
Binary: /usr/bin/bash
Needed: exec allow for /usr/bin/bash or remove the call
Mode: enforce – operation blocked with EPERM
```

Modes:

* `observe` – log only with recommendations.
* `enforce` – block and fail the build.

## 13. Reports and Metrics

Report formats:

* `text` – human-readable log.
* `json` – for integrations.

Basic metrics:

* `violations_total`, `blocked_total`, `allowed_total`.
* `io_read_bytes_by_unit`, `io_write_bytes_by_unit`.
* `cpu_time_ms_by_unit`, `page_faults_by_unit`.

## 14. Performance and Reliability

* Minimize data copies in eBPF.
* Cache inode and realpath in userspace with TTL.
* Fail-closed: build stops if the agent crashes (configurable).
* Policies are immutable during execution.

## 15. Compatibility and Limitations

* Linux with BPF LSM and cgroup v2 only.
* On macOS and Windows, only userspace part works in observe mode without guarantees.

## 16. Testing

Levels:

* ✅ Unit tests in each crate.
* ✅ Integration tests in `cli` with fake sandbox harness.
* ✅ Negative tests expect `EPERM` and precise hints (enforced in CLI and sandbox tests).
* ✅ Property-based tests in `policy-core` cover rule deduplication and validation.
* 🟡 Fuzzing in config parsers and event handling (harnesses exist under `fuzz/`, additional targets welcome).

Examples:

* `qqrm-network-build` (`examples/network-build`) – network call in `build.rs`.
* `qqrm-spawn-bash` (`examples/spawn-bash`) – attempt to run `bash`.
* `qqrm-fs-outside-workspace` (`examples/fs-outside-workspace`) – write to `$HOME` and `/tmp`.
* `qqrm-proc-macro-hog` (`examples/proc-macro-hog`) – heavy proc macro stress test.
* `qqrm-git-clone-https` (`examples/git-clone-https`) – `git clone` in `build.rs`.

CI:

* GitHub Actions on `ubuntu-latest` with kernel ≥ 5.15 and rights for BPF.
* Job runs integration tests and publishes reports.

## 17. Documentation and Contribution

* ✅ `README` with quick start instructions (gif pending).
* ⬜ `CONTRIBUTING` with development rules, lints, and style.
* ⬜ `SECURITY` with vulnerability reporting procedure (current `SECURITY_MODEL.md` is internal design only).
* ⬜ `CODEOWNERS` and PR templates.

## 18. Risks and Mitigations

* Clients ignore `HTTPS_PROXY` – solved via cgroup hooks denying direct connections.
* Symlinks and bind mounts – match by inode and check realpath.
* Performance on large workspaces – profiling and caches.

## 19. Licensing and Ecosystem

* OSS license MIT or Apache-2.0.
* Compatible with `cargo-vet` and `cargo-crev` as additional supply-chain tools.

## 20. Appendices

### A. Minimal GitHub Actions Workflow

```yaml
name: Warden CI
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: actions-rs/toolchain@v1
        with:
          profile: minimal
          toolchain: stable
          override: true
      - name: Install cargo-warden
        run: cargo install --path crates/cli
      - name: Enforce build
        run: cargo warden build
```

### B. Key Kernel Hooks

* LSM `bprm_check_security` – exec
* LSM `file_open` – filesystem read/write
* LSM `inode_unlink` and `inode_rename` – tree integrity
* `cgroup/connect4` and `connect6` – TCP network
* `cgroup/sendmsg4` and `sendmsg6` – UDP network

### C. Code Conventions

* Rust 2024, `clippy` strict, deny warnings
* Format with stable `rustfmt`
* Public API only in `qqrm-bpf-api` and `qqrm-policy-core`; everything else `pub(crate)`

### D. Glossary

* **Unit** – process: `rustc`, `build.rs`, proc-macro, linker.
* **Allowlist** – list of explicitly permitted entities.
* **Workspace** – root of the Cargo project.

_End of v0.1 specification._

