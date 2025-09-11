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
- [x] Display policy and recent events via `status` command.

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
- [x] Install cargo-deny in CI pipeline for dependency auditing.
- [x] Plan additional DevSecOps tooling: cargo-audit, cargo-udeps, cargo-llvm-cov, cargo-nextest, cargo-spellcheck, actionlint.
- [x] Draft roadmap for Phase 2.
- [x] Draft roadmap for Phase 3.

## Phase 2 Progress
- [x] Expose control for filesystem read/write policies in BPF API.
- [x] Document enriched event metadata such as container ID and capability bits.
- [x] Support `--policy` flag referencing external policy files.
- [x] Add hooks for file write and delete operations with deny by default.
- [x] Design declarative policy schema in TOML.
- [x] Validate policies against schema during CLI commands.
- [x] Emit warnings for unused or contradictory rules.
- [x] Support policy inheritance and overrides per workspace member.
- [x] Stream events to JSONL file and systemd journal simultaneously.
- [x] Offer configurable log rotation and retention settings.
- [x] Provide optional gRPC endpoint for remote monitoring.
- [x] Provide Docker image with runtime dependencies preinstalled.
- [x] Merge multiple policy files referenced via CLI.
- [x] Replace polling with blocking ring buffer reads in agent.
- [x] Integrate `cargo-deny` for dependency auditing.
- [x] Document security model and threat considerations.
- [x] Write end-to-end tutorial covering policy creation and enforcement.
- [x] Publish prebuilt BPF artifacts for common architectures.
- [x] Generate distributable archive with CLI and agent binaries.
- [x] Expand CI to test examples under multiple kernel versions.
- [x] Add fuzzing harness for BPF programs.

## Phase 3 Progress
- [x] Document usage in `.github/workflows/warden-ci.yml`.
- [x] Export violation events to SARIF for PR annotations.
- [x] Use actionlint to validate GitHub workflow files.
- [x] Integrate `cargo-audit` for dependency vulnerability checks.
- [x] Integrate `cargo-udeps` to detect unused dependencies.
- [x] Adopt `cargo-nextest` for parallel test execution.
- [x] Add coverage reports using `cargo-llvm-cov`.
- [x] Run `cargo-spellcheck` for documentation consistency.

- [x] Upload SARIF reports in GitHub workflow.
- [x] Provide example Prometheus dashboard.

