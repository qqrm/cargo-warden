# warden-ci GitHub Action

Runs `cargo-warden` in CI, generates a SARIF report and uploads it for pull request annotations.

## Inputs

| Name | Description | Default |
| ---- | ----------- | ------- |
| `command` | Cargo command to run under `cargo-warden`. | `build` |

## Usage

```yaml
name: warden-ci
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
        with:
          command: build
```
