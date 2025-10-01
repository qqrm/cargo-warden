# Agent Lite Adapter Audit

## Metadata
- Avatar for this task: [Blue Circuit Fox](https://qqrm.github.io/avatars-mcp/blue-fox.png)
- Scope: `crates/agent-lite`

## Legacy Adapter Findings
- **gRPC streaming loop**: `grpc::start` spawned a dedicated thread and Tokio runtime, duplicating async infrastructure already required elsewhere. It also rebuilt the tonic service on each spawn instead of reusing shared runtime facilities.
- **HTTP metrics server**: `start_metrics_server` relied on `tiny_http`, creating a standalone blocking thread that duplicated request handling logic the async stack already provides.
- **Output fan-out**: `write_outputs` had to juggle conditional compilation (`cfg_if!`) to send events to optional sinks, reflecting tight coupling between logging, metrics, and transport adapters.

## Library Substitutions
- Replaced the bespoke `tiny_http` server with a Tokio-powered TCP listener that serves Prometheus text directly, eliminating the blocking adapter.
- Collapsed the per-service runtimes into a single `AsyncServices` manager that hosts both gRPC (when enabled) and metrics endpoints on one Tokio runtime thread.
- Updated the gRPC bridge to reuse tonic streams without spawning ad-hoc runtimes or threads.

## Feature & Dependency Cleanup
- Promoted `tokio` to a base dependency so HTTP metrics no longer rely on an auxiliary blocking server. The `grpc` feature now gates only tonic/prost streaming glue.
- Dropped `tiny_http` and `cfg-if` from the crate while keeping `futures-util` scoped to the `grpc` feature.
- Simplified the `grpc` feature flag dependency list—`tokio` is no longer toggled, minimizing feature flag churn.

## Follow-up Suggestions
- Consider exposing shutdown handles for async services to allow graceful tear-down in integration tests.
- Evaluate whether the `grpc` feature should become default or remain opt-in based on deployment expectations; current refactor keeps it optional but easier to integrate.
