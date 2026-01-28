# CONTRIBUTING

This project exists to make **untrusted Rust builds** safer to run. Contributions must preserve a conservative security posture and keep documentation truthful.

If you are changing behavior, first read `docs/SOURCE_OF_TRUTH.md` and ensure your change aligns with the stated goal and non-goals.

## Repo layout expectations

- eBPF-side types live in `crates/bpf-api`.
- eBPF programs live in `crates/bpf-core` and must depend only on `bpf-api` for shared ABI.
- Policy parsing/validation lives in `crates/policy-core`.
- Policy compilation (to BPF map layouts) lives in `crates/policy-compiler`.
- The CLI (`crates/cli`) is wiring + UX. Avoid business logic there.

## Local development

1) Create a feature branch from `main`.

2) Run the baseline checks (workspace root):

```bash
./scripts/check_path_versions.sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
```

3) Integration checks for the CLI can be run without loading real eBPF by using the fake sandbox:

```bash
WARDEN_FAKE_SANDBOX=1 cargo test --workspace
WARDEN_FAKE_SANDBOX=1 cargo run --bin cargo-warden -- status
WARDEN_FAKE_SANDBOX=1 cargo run --bin cargo-warden -- run -- cargo build -p warden-network-build
```

Notes:
- Some CI jobs may use `cargo nextest`. If you have it installed, it can replace `cargo test` locally.
- If you modify the BPF build or distribution workflow, update `scripts/build-dist.sh` and `docs/INSTALLATION.md` together.

## Documentation standards

- Documentation must match reality. When a feature is not implemented, label it explicitly as **Roadmap**.
- `docs/SOURCE_OF_TRUTH.md` wins over every other document.
- Provide copy-pastable examples. Keep them minimal and conservative.

## Security posture rules

- Prefer deny-by-default behavior for anything that touches network, filesystem outside the workspace, and process execution.
- If you introduce an escape hatch (env var / flag), it must be:
  - explicit
  - loudly documented
  - visible in reports
  - not the default

## Submitting changes

- Keep PRs small and focused.
- Include tests for behavior changes.
- If you change CLI UX, update `README.md` and the policy cookbook (`docs/POLICY_COOKBOOK.md`).

For sensitive issues, follow `SECURITY.md`.
