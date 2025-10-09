# CLI Architecture Notes

## Policy Loading Flow
- `commands::build::exec` and `commands::run::exec` forward shared CLI flags (`--policy`, `--allow`, `--mode`) to `policy::setup_isolation`.
- `setup_isolation` layers workspace policies (`workspace.warden.toml`), local overrides (`warden.toml`), and any CLI `--policy` files by calling `Policy::merge` in order.
- Manifest metadata and trust database entries extend the base policy before CLI overrides are applied. CLI `--allow` paths are added last to the exec allowlist so they always win.
- Every assembled policy is validated and compiled via `qqrm_policy_compiler::compile`, yielding BPF map entries (`MapsLayout`) and the final mode.

## Sandbox Wiring
- `sandbox::run_in_sandbox` constructs a new `sandbox_runtime::Sandbox`, launches the requested command, and always calls `shutdown`, propagating any run errors.
- `Sandbox::run` injects the compiled `MapsLayout` into the runtime by calling `populate_maps` inside the pre-exec hook before the child starts executing. The compiled mode flag is written to BPF maps alongside environment restrictions.
- Cgroups are created through `sandbox_runtime::cgroup::Cgroup::create` for each invocation. Cleanup is triggered via `Sandbox::shutdown`, ensuring fake and real sandboxes remove their cgroup directories.

## Command Summaries
- `build` wraps `cargo build` and exits with the child status (matching `EPERM` failures when enforcement blocks the build).
- `run` executes arbitrary commands after `--`, applying the same isolation stack; it validates arguments and mirrors the child exit code.
- `status` reports layered policy sources (workspace, local, CLI overrides, and mode overrides) plus recent events from `warden-events.jsonl`.
- `report` reuses the recorded events and metrics snapshot to emit text, JSON, or SARIF outputs.

These notes capture how CLI options travel through policy compilation into sandbox map loading, complementing the integration tests under `tests/sandbox.rs`.
