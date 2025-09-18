# Warden CI GitHub Action

Runs `cargo-warden` in CI, generates a SARIF report and uploads it for pull request annotations.

## Inputs

| Name | Description | Default |
| ---- | ----------- | ------- |
| `command` | Cargo command to run under `cargo-warden`. | `build` |

## Usage

```yaml
name: Warden CI
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: owner/warden-ci@v1
        # Runs `cargo warden --mode observe` so CI continues even without eBPF privileges.
        with:
          command: build
```

## PR Annotations

When a pull request triggers this workflow, any violations reported by
`cargo warden` are exported to `warden.sarif` and uploaded via
`github/codeql-action/upload-sarif@v3`. GitHub surfaces these findings
directly on the pull request as inline annotations and under the
Security tab, making violations easy to spot.
