# Phase 2 Roadmap – Expanded Isolation and Policy Control

## BPF API
- [x] Support per-package network rules via hierarchical maps.
- [x] Expose control for filesystem read/write policies.
 - [x] Document enriched event metadata such as container ID and capability bits.

## BPF Core
- [x] Enforce network allowlists with CIDR matching and DNS resolution.
- [x] Add hooks for file write and delete operations with deny by default.
- [x] Implement configurable syscall filtering via seccomp integration.
- [x] Provide metrics maps for event counters.

## CLI
- [x] Implement `init` subcommand to bootstrap project configuration.
- [x] Add interactive prompts for generating allowlists.
- [x] Support `--policy` flag referencing external policy files.
- [x] Provide `status` command displaying active policy and recent events.

## Policy Engine
- [x] Design declarative policy schema in TOML.
- [x] Validate policies against schema during CLI commands.
 - [x] Support policy inheritance and overrides per workspace member.
- [x] Emit warnings for unused or contradictory rules.

## Agent
 - [x] Stream events to JSONL file and systemd journal simultaneously.
- [x] Offer configurable log rotation and retention settings.
- [x] Provide optional gRPC endpoint for remote monitoring.

## Packaging and Distribution
- [ ] Publish prebuilt BPF artifacts for common architectures.
- [x] Provide Docker image with runtime dependencies preinstalled.
- [ ] Generate distributable archive with CLI and agent binaries.

## CI and Tooling
- [ ] Expand CI to test examples under multiple kernel versions.
- [ ] Add fuzzing harness for BPF programs.
 - [x] Integrate `cargo-deny` for dependency auditing.

## Cross-cutting
- [ ] Write end-to-end tutorial covering policy creation and enforcement.
- [ ] Document security model and threat considerations.
- [ ] Solicit community feedback and iterate on design.
