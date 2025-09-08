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

