# Phase 3 Roadmap – Reports and CI Integration

## Reporting
- [x] Export violation events to SARIF for PR annotations.
- [x] Upload SARIF reports in GitHub workflow.

## Metrics
- [x] Extend agent-lite to expose Prometheus metrics.
- [x] Provide example Prometheus dashboard.

## GitHub Action
- [x] Publish `warden-ci` GitHub Action with minimal workflow.
- [x] Document usage in `.github/workflows/warden-ci.yml`.

## CI and Tooling
 - [x] Integrate `cargo-audit` for dependency vulnerability checks.
 - [x] Integrate `cargo-udeps` to detect unused dependencies.
 - [x] Add coverage reports using `cargo-llvm-cov`.
 - [x] Adopt `cargo-nextest` for parallel test execution.
 - [x] Run `cargo-spellcheck` for documentation consistency.
 - [x] Use `actionlint` to validate GitHub workflow files.

## Cross-cutting
- [x] PR with violation displays SARIF annotations.
- [x] Metrics dashboard works out of the box.
