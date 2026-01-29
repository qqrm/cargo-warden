# Source of truth: cargo-warden

This document is the canonical description of **what problem cargo-warden solves**, **what it does not solve**, and **what is true today** (code), even if other documentation drifts.

## 1) Problem

Building and testing an untrusted Rust project is dangerous.

During `cargo build`, `cargo test`, and `cargo run`, the following build-stage code can execute on the developer machine:

- `build.rs` scripts
- procedural macros (including transitive dependencies)
- test/bench binaries
- auxiliary tooling invoked by Cargo (linkers, C toolchains, `pkg-config`, etc.)

This code can perform arbitrary actions: connect to the internet, read secrets from `$HOME`, spawn other programs, and modify files outside the project. In the worst case it can exfiltrate credentials or steal assets simply because you tried to compile a repository.

## 2) Goal

cargo-warden provides a **kernel-enforced guardrail** for the Cargo build stage.

You run untrusted builds through a single entrypoint:

- `cargo warden build ...`
- `cargo warden run -- <command>`
- `cargo warden test ...` (if/when exposed as a shortcut)

cargo-warden attaches eBPF programs (BPF LSM + cgroup hooks) to the process tree created by the command and enforces a declarative policy.

**Default intent for untrusted code**: *fail closed*.
If the build tries to do something outside policy, cargo-warden must:

1) deny the action at the kernel boundary
2) fail the wrapped command with a non-zero exit code
3) emit a clear violation report: who did what, where, and which policy rule blocked it

## 3) In-scope protections

cargo-warden focuses on **behavioral enforcement** during build/test/run:

- Network egress control (deny by default, allow explicit exceptions)
- Executable launch control (allowlist)
- Filesystem access control (workspace/target allowed; secrets/system areas denied)
- Clear audit trail and export formats (text/JSON/SARIF)

## 4) Out of scope (non-goals)

cargo-warden does **not** attempt to:

- prove the absence of backdoors in source code
- statically find vulnerabilities in a codebase
- replace dependency review tools (e.g. cargo-vet, scanners)
- protect arbitrary long-running applications outside the build stage

It reduces blast radius of **build-stage execution**. It does not make untrusted code “safe” in the absolute sense.

## 5) Current reality (what the code does today)

These statements describe the current implementation shipped in this repository.

### 5.1 Modes and defaults

- When no `warden.toml` is present, the built-in starter policy runs in **observe** mode (audit-only).
- `cargo warden init` generates a starter `warden.toml`, but today it primarily guides **exec allowlist** setup; network/filesystem rules still require manual editing.

### 5.2 Network policy granularity

- `allow.net.hosts` currently accepts **socket addresses** (`IP:port`), not domain names.
- This means “allow only github.com and crates.io” cannot be expressed directly as hostnames today; it must be done via IP allowlists (not stable for CDNs).

### 5.3 Host isolation guardrail

- The CLI contains a guardrail that **refuses to run directly on a host**. The documented supported path is an isolated container or a throwaway VM.
- This is a *safety default*, not a fundamental limitation of eBPF enforcement. It exists to reduce accidental damage when experimenting.

### 5.4 What enforcement is actually eBPF-driven

- Exec, filesystem, and connect controls are enforced by eBPF programs attached to the command’s cgroup and LSM hooks.
- Reporting is produced from kernel events streamed to userspace.

## 6) Roadmap aligned to the problem

The following items are the highest-impact changes to fully solve the stated problem in a usable way.

1) **Host mode (explicit)**
   - Keep the current “refuse host” behavior as the default.
   - Add an explicit flag (e.g. `--allow-host` / `--i-know-what-im-doing`) that enables running on a host with loud warnings and mandatory deny-by-default policy.

2) **Usable network policy**
   Choose one approach and implement it end-to-end:
   - **Proxy-first**: enforce that all egress must go through a local proxy, and apply domain/SNI rules there; eBPF blocks direct egress.
   - **Offline-first**: default to `net=deny` and rely on vendoring/mirrors for dependencies.
   - **Hostname-to-IP compilation** (partial): allow hostnames in policy and resolve/compile into IP allowlists at start; document its limitations.

3) **“Learn” workflow for policies**
   - Add `cargo warden learn -- <cmd>` to record actions and propose a minimal *safe* policy, with risk labels (e.g. reads `~/.ssh`).

4) **Truthful docs**
   - Every user-facing document must match “Current reality” above.
   - Where there is a mismatch, it must be explicitly marked as “Roadmap”.

