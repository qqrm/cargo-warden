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

