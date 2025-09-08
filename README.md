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
rustup target add bpfel-unknown-none --toolchain nightly
rustup component add rust-src --toolchain nightly
cargo install bpf-linker
scripts/build-bpf.sh
```

The script installs the required dependencies and places the resulting object files under `prebuilt/<arch>`.

Generated artifacts are excluded from version control; rerun the script to refresh them.

