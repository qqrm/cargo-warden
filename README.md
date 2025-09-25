# cargo-warden

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
