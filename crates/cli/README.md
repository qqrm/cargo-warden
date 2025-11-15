# CLI Architecture Notes

## Policy Loading Flow
- `commands::build::exec` and `commands::run::exec` forward shared CLI flags (`--policy`, `--allow`, `--mode`) plus the resolved metadata to `policy_orchestrator::configure_isolation`.
- `configure_isolation` (in `crates/policy-orchestrator`) layers workspace policies (`workspace.warden.toml`), local overrides (`warden.toml`), and any CLI `--policy` files by calling `Policy::merge` in order.
- Manifest metadata and trust database entries extend the base policy before CLI overrides are applied. CLI `--allow` paths are added last to the exec allowlist so they always win.
- Every assembled policy is validated and compiled via `warden_policy_compiler::compile` inside the orchestrator, yielding the `IsolationConfig` used by the sandbox: `mode`, syscall deny list, compiled BPF map layout (`MapsLayout`), and the list of environment variables allowed to leak through.

## Sandbox Wiring
- `sandbox::run_in_sandbox` constructs a new `sandbox_runtime::Sandbox`, launches the requested command, and always calls `shutdown`, propagating any run errors.
- `Sandbox::run` forwards the compiled `MapsLayout`, syscall deny list, and allowed environment variables to the runtime. `RealSandbox::install_pre_exec` calls `write_mode_flag` and `populate_maps` with the `MapsLayout` produced by `warden_policy_compiler::compile`, then applies seccomp if enforcement and deny rules require it. The fake runtime records the same layout snapshots for integration assertions.
- Cgroups are created through `sandbox_runtime::cgroup::Cgroup::create` for each invocation. Cleanup is triggered via `Sandbox::shutdown`, ensuring fake and real sandboxes remove their cgroup directories even when the workload fails.

## Command Summaries
- `build` wraps `cargo build` and exits with the child status (matching `EPERM` failures when enforcement blocks the build).
- `run` executes arbitrary commands after `--`, applying the same isolation stack; it validates arguments and mirrors the child exit code.
- `status` reports layered policy sources (workspace, local, CLI overrides, and mode overrides) plus recent events from `warden-events.jsonl`, including observe-mode hints surfaced by `EventRecord::to_string`.
- `report` reuses the recorded events and metrics snapshot to emit text, JSON, or SARIF outputs, bubbling up skipped malformed lines and missing metrics gracefully.

These notes capture how CLI options travel through policy compilation into sandbox map loading, complementing the integration tests under `tests/sandbox.rs`.
