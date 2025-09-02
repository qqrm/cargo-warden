# cargo-warden OSS v0.1 - Modular Specification

Version: 0.1
Status: Draft for public OSS release
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

* **bpf-core** – eBPF programs (LSM and cgroup) for exec, filesystem, and network.
* **bpf-api** – shared structures and map layouts with stable ABI.
* **policy-core** – permission model and config parsing.
* **policy-compiler** – compiles policies into compact structures for eBPF maps.
* **agent-lite** – userspace daemon for events, logs, and basic telemetry.
* **cli** – `cargo-warden` subcommand and wrapper: creates cgroup, loads BPF, handles UX.
* **testkits** – utilities for integration testing.
* **examples** – demonstration projects with benign and malicious cases.

Boundaries:

* `bpf-core` imports only types from `bpf-api`.
* `cli` and `agent-lite` contain no business logic—only wiring and output.
* `policy-core` knows nothing about eBPF, `policy-compiler` knows nothing about the CLI.

## 7. Workspace Layout and Features

Workspace crates:

* `crates/bpf-api`
* `crates/bpf-core`
* `crates/policy-core`
* `crates/policy-compiler`
* `crates/agent-lite`
* `crates/cli`
* `crates/testkits`
* `crates/examples/*`

Feature flags:

* `observe` – log events without blocking.
* `enforce` – enable blocking with `EPERM`.
* `fs-strict` – restrict writes to `target` and `OUT_DIR` only.
* `net-allowlist` – simple host:port allowlist for OSS.

## 8. Module Contracts

`bpf-api`

```rust
#[repr(C)]
pub struct Event {
  pub pid: u32,
  pub tgid: u32,
  pub time_ns: u64,
  pub unit: u8,        // 0 Other, 1 BuildRs, 2 ProcMacro, 3 Rustc, 4 Linker
  pub action: u8,      // 0 Open, 1 Rename, 2 Unlink, 3 Exec, 4 Connect
  pub verdict: u8,     // 0 Allowed, 1 Denied
  pub path_or_addr: [u8; 256],
  pub needed_perm: [u8; 64],
}
```

`policy-core`

```rust
pub enum Permission {
  FsRead(PathSpec),
  FsWrite(PathSpec),
  Exec(ExecSpec),
  NetConnect(HostPortSpec),
  EnvRead(String),
}

pub struct Policy { pub rules: Vec<Permission>, pub mode: Mode }
```

`policy-compiler`

```rust
pub struct MapsLayout { /* descriptions for eBPF maps */ }

pub fn compile(policy: &Policy) -> Result<MapsLayout, Error>;
```

`agent-lite`

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
write_extra = ["/tmp/warden-scratch"]
read_extra  = ["/usr/include"]
```

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

**Uprobes**

* `cargo` and `rustc` – mark processes with unit types via argv for precise policy mapping.

**Performance structures in eBPF**

* Prefix trees for read/write path checks.
* Hash set of allowed exec paths.
* Compact bitmasks for capability flags.

## 11. Execution Flow

* `cli` creates a cgroup for the build and loads eBPF programs.
* Launches `cargo` as a child process; the entire process tree inherits the cgroup.
* Uprobes tag processes and populate eBPF maps with policy IDs.
* On risky operations eBPF returns Allow or `EPERM`.
* `agent-lite` reads events from a ring buffer and writes a report.

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

* Unit tests in each crate.
* Integration tests in `cli` with examples.
* Negative tests expect `EPERM` and precise hints.
* Property-based tests in `policy-compiler` for paths and rules.
* Fuzzing in config parsers and event handling.

Examples:

* `ex_net_curl_buildrs` – network call in `build.rs`.
* `ex_exec_bash_buildrs` – attempt to run `bash`.
* `ex_fs_outside_workspace` – write to `$HOME` and `/tmp`.
* `ex_proc_macro_hog` – heavy proc macro.
* `ex_git_clone_https` – `git clone` in `build.rs`.

CI:

* GitHub Actions on `ubuntu-latest` with kernel ≥ 5.15 and rights for BPF.
* Job runs integration tests and publishes reports.

## 17. Documentation and Contribution

* `README` with quick start and gif.
* `CONTRIBUTING` with development rules, lints, and style.
* `SECURITY` with vulnerability reporting procedure.
* `CODEOWNERS` and PR templates.

## 18. OSS Roadmap

Phased without dates. Each phase has a clear scope, artifacts, and exit criteria for agent-oriented development and modular testing.

### Phase 1 – MVP of Basic Isolation

**Scope**

* Enforce network via cgroup `connect4/6` and `sendmsg4/6` – deny-all.
* Enforce exec via LSM `bprm_check_security` – tool allowlist.
* Observe filesystem events (`file_open`) without blocking.
* CLI as Cargo subcommand: `cargo warden build`, `cargo warden run -- <cmd>`.
* Examples: network `build.rs`, exec `bash`.

**Artifacts**

* Crates: `bpf-api`, `bpf-core`, `cli`, `agent-lite`, `examples`.
* Text report and JSON events.

**Exit criteria**

* Direct connections blocked with `EPERM`, allowed host passes.
* Any exec outside allowlist gets `EPERM` with hint about needed permission.
* Logs contain `pid`, unit, action, path/address, verdict.

**Out of scope**

* Strict filesystem policy, trust DB, SARIF, Prometheus.

### Phase 2 – Filesystem Policy and Trust

**Scope**

* `fs-strict`: write only `target` and `OUT_DIR`; read only workspace + explicit paths.
* `inode_unlink/rename` to protect integrity.
* Project `warden.toml` – basic permission model.
* User’s local trust DB for grants.
* Improved CLI UX: `report --format json|text`.

**Artifacts**

* Crates: `policy-core`, `policy-compiler`, updates to `bpf-core` and `cli`.
* Examples: writing to `$HOME`, `/tmp`, reading secrets.

**Exit criteria**

* Writes outside `target/OUT_DIR` get `EPERM` with precise hint.
* Reads of sensitive paths denied unless explicitly allowed.
* Project with valid declarations builds without interactive questions.

**Out of scope**

* SARIF, Prometheus, GitHub Action.

### Phase 3 – Reports and CI Integration

**Scope**

* SARIF reports for PR annotations.
* Basic Prometheus metrics and example dashboard.
* GitHub Action: documentation and minimal workflow.

**Artifacts**

* Crates: `report-lite` or extension to `agent-lite` for metrics and SARIF export.
* `.github/workflows/warden-ci.yml` example.

**Exit criteria**

* PR with violation gets SARIF annotation.
* Metrics visible in Prometheus, dashboard works out of the box.

**Out of scope**

* GitHub-aware proxy, SHA256 pinning.

### Phase 4 – Hardening and API Stabilization

**Scope**

* Performance: CPU ≤ 3%, I/O ≤ 5% on typical projects.
* Property-based tests for `policy-compiler`, fuzzing parsers.
* Freeze `bpf-api` ABI and map layout, version compatibility policy.
* Complete `CONTRIBUTING`, `SECURITY`, `CODEOWNERS`.

**Artifacts**

* Stable releases `v0.1.x` and migration guide.

**Exit criteria**

* All negative examples deterministically return `EPERM` with clear hints.
* API stability documented; semantic versioning applied.

**Out of scope**

* Enterprise features and GitHub-aware proxy.

## 19. Risks and Mitigations

* Clients ignore `HTTPS_PROXY` – solved via cgroup hooks denying direct connections.
* Symlinks and bind mounts – match by inode and check realpath.
* Performance on large workspaces – profiling and caches.

## 20. Licensing and Ecosystem

* OSS license MIT or Apache-2.0.
* Compatible with `cargo-vet` and `cargo-crev` as additional supply-chain tools.

## 21. Appendices

### A. Minimal GitHub Actions Workflow

```yaml
name: warden-ci
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

* Rust 2021, `clippy` strict, deny warnings
* Format with stable `rustfmt`
* Public API only in `bpf-api` and `policy-core`; everything else `pub(crate)`

### D. Glossary

* **Unit** – process: `rustc`, `build.rs`, proc-macro, linker.
* **Allowlist** – list of explicitly permitted entities.
* **Workspace** – root of the Cargo project.

_End of v0.1 specification._

