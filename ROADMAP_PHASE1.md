# Phase 1 Roadmap – MVP of Basic Isolation

## BPF API
- [x] Define structs for exec allowlist and network control.
- [x] Document ABI for event logs (pid, unit, action, path/address, verdict).

## BPF Core
- [x] Implement cgroup hooks (`connect4`, `connect6`, `sendmsg4`, `sendmsg6`) denying all network by default.
- [x] Implement `bprm_check_security` exec restriction based on allowlist map.
- [x] Add `file_open` probe capturing read/write attempts (observation only).
- [x] Provide minimal tests verifying expected events.

## CLI
- [x] Scaffold cargo subcommand `cargo warden`.
- [x] Implement `build` wrapper that sets up cgroup, loads eBPF programs, and invokes Cargo.
- [x] Implement `run -- <cmd>` wrapper for arbitrary commands.
- [x] Add allowlist CLI option or config stub.

## Agent-lite
- [x] Collect events from BPF maps and output text and JSON logs.
- [x] Include fields: pid, unit, action, path/address, verdict.
- [x] Provide basic diagnostics for denied exec or network.

## Examples
- [x] Example crate with `build.rs` making a network request blocked by default.
- [x] Example crate attempting to spawn `/bin/bash`.
- [x] Document expected `EPERM` results and hints.

## Cross-cutting
- [x] Provide script or Makefile to run examples under `cargo warden`.
- [x] Document setup requirements (BPF LSM, cgroup v2).
- [x] Update code and docs to Rust 2024 edition.
- [x] Add GitHub CI pipeline for formatting, linting, and tests.
- [x] Draft roadmap for Phase 2.

## Phase 2 Progress
- [x] Design declarative policy schema in TOML.

