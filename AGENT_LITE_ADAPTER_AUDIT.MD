# Agent Lite Adapter Audit

## Runtime Consolidation
- Replaced the bespoke gRPC thread runtime with a shared Tokio executor so streaming and metrics reuse the same event loop.
- Simplified adapter glue by removing `cfg_if!` branches in the log writer and tests; the code now relies on direct `#[cfg]` guards.

## HTTP Metrics Endpoint
- Dropped the legacy `tiny_http` server and now expose metrics via a Tokio TCP listener with a minimal HTTP response encoder.
- Retained Prometheus' `TextEncoder` as the canonical formatter to avoid custom serialization logic.

## Dependency and Feature Flags
- Promoted Tokio to a required dependency and pruned the `cfg-if` crate.
- Narrowed the `grpc` feature to tonic/prost related crates; Tokio is no longer feature-gated, matching the shared runtime design.

## Follow-up Opportunities
- Consider extracting the TCP response helper into a reusable crate if other agents need lightweight HTTP responders.
- Validate whether the Prometheus registry should expose compression or TLS behind optional features once requirements surface.
