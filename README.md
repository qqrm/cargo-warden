# cargo-warden

## Quickstart Overview

The quickstart covers environment setup, policy enforcement, and log inspection steps at a glance.

1. Run `./scripts/setup/repo-setup.sh` to install toolchains and dependencies.
2. Apply a policy such as `warden.toml` and execute builds with `cargo warden --policy warden.toml build`.
3. Inspect audit events via `cargo warden --observe test` or your preferred logging pipeline.

## Setup Requirements

The project requires a Linux system with the following features:

- **Kernel ≥5.13**

```bash
uname -r
```

- **BPF LSM enabled**

```bash
cat /sys/kernel/security/lsm | grep bpf
```

- **cgroup v2 mounted**

```bash
mount | grep cgroup2
```

- **Capabilities** `CAP_BPF` and `CAP_SYS_ADMIN`

```bash
capsh --print | grep -E 'cap_(bpf|sys_admin)'
```

## Building prebuilt BPF objects

Generate the prebuilt BPF artifacts with:

```bash
scripts/build-bpf.sh
```

The script installs the nightly toolchain, required components and the `bpf-linker` before placing the resulting object files under `prebuilt/<arch>`.

Generated artifacts are excluded from version control; rerun the script to refresh them.


## Sandbox Hardening

cargo-warden layers eBPF enforcement with a seccomp deny-list sourced from the active policy. When the policy runs in `enforce`
mode, the runtime programs the kernel with explicit syscall filters (for example, `clone`, `execve`, or any additional entries
declared under `[syscall] deny`). Observability remains available in `observe` mode, allowing you to iterate on syscall rules
before promoting them to enforcement.

## Local CI parity

Use `scripts/run_ci_checks.sh` to reproduce the pull request GitHub Actions checks locally. The script:

- installs missing Debian packages (`pkg-config`, `libseccomp-dev`, `protobuf-compiler`, `jq`, `xxhash`),
- installs the cargo subcommands required by the pipeline (`cargo-machete`, `cargo-audit`, `cargo-deny`, `cargo-nextest`, `cargo-udeps`, `cargo-fuzz`),
- ensures the stable toolchain has the `rustfmt`, `clippy`, and `llvm-tools-preview` components, plus a nightly toolchain for `cargo udeps` and `cargo fuzz`,
- runs the same validation commands as the CI jobs, including formatting, linting, tests, supply-chain checks, example runs, and fuzz builds.

Run it from the repository root:

```bash
scripts/run_ci_checks.sh
```

For a byte-for-byte reproduction of the GitHub Actions workflow, run it through [wrkflw](https://github.com/bahdotsh/wrkflw):

```bash
wrkflw validate
wrkflw run .github/workflows/CI.yml
```

## Repository Maintenance

Use `scripts/prune_branches.sh` to list feature branches that have been inactive for more than 48 hours. Pass `--prune` to
delete the remote branches once you have reviewed the list. Export `CARGO_WARDEN_PRUNE_AGE` (in seconds) to customise the age
threshold.

## Documentation Index

All supplemental guides, policies, and security notes now live under `DOCS/`. Start with `DOCS/INDEX.md` for a curated map of
the available references.
