# Phase 2 Roadmap – Expanded Isolation and Policy Control

## BPF API
- [x] Support per-package network rules via hierarchical maps.
- [x] Expose control for filesystem read/write policies.
- [ ] Document enriched event metadata such as container ID and capability bits.

## BPF Core
- [x] Enforce network allowlists with CIDR matching and DNS resolution.
- [ ] Add hooks for file write and delete operations with deny by default.
- [ ] Implement configurable syscall filtering via seccomp integration.
- [ ] Provide metrics maps for event counters.

## CLI
- [x] Implement `init` subcommand to bootstrap project configuration.
- [x] Add interactive prompts for generating allowlists.
- [ ] Support `--policy` flag referencing external policy files.
- [x] Provide `status` command displaying active policy and recent events.

## Policy Engine
- [ ] Design declarative policy schema in TOML.
- [ ] Validate policies against schema during CLI commands.
- [ ] Support policy inheritance and overrides per workspace member.
- [ ] Emit warnings for unused or contradictory rules.

## Agent
- [ ] Stream events to JSONL file and systemd journal simultaneously.
- [ ] Offer configurable log rotation and retention settings.
- [ ] Provide optional gRPC endpoint for remote monitoring.

## Packaging and Distribution
- [ ] Publish prebuilt BPF artifacts for common architectures.
- [ ] Provide Docker image with runtime dependencies preinstalled.
- [ ] Generate distributable archive with CLI and agent binaries.

## CI and Tooling
- [ ] Expand CI to test examples under multiple kernel versions.
- [ ] Add fuzzing harness for BPF programs.
- [ ] Integrate `cargo-deny` for dependency auditing.

## Cross-cutting
- [ ] Write end-to-end tutorial covering policy creation and enforcement.
- [ ] Document security model and threat considerations.
- [ ] Solicit community feedback and iterate on design.
