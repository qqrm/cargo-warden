# Event Log ABI

The eBPF layer emits `Event` records via a ring buffer. This ABI defines the layout shared between kernel and userspace.

```rust
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Event {
    pub pid: u32,
    pub tgid: u32,
    pub time_ns: u64,
    pub unit: u8,        // 0 Other, 1 BuildRs, 2 ProcMacro, 3 Rustc, 4 Linker
    pub action: u8,      // 0 Open, 1 Rename, 2 Unlink, 3 Exec, 4 Connect
    pub verdict: u8,     // 0 Allowed, 1 Denied
    pub reserved: u8,    // reserved for future use
    pub reserved_padding: [u8; 4],
    pub container_id: u64,
    pub caps: u64,       // Linux capability bitmask
    pub path_or_addr: [u8; 256], // null-terminated path or network address
    pub needed_perm: [u8; 64],   // suggested policy key (utf-8, null-terminated)
}
```

- **pid** – process identifier.
- **tgid** – thread group identifier for the process.
- **time_ns** – monotonic timestamp at which the event was captured.
- **unit** – workload category generating the event.
- **action** – operation being audited.
- **path_or_addr** – associated filesystem path or network address.
- **verdict** – allow (`0`) or deny (`1`).
- **container_id** – identifier of the container or sandbox.
- **caps** – Linux capability bitmask held by the process.
- **needed_perm** – suggested policy entry required to grant the attempted operation.
- Rename operations emit separate events for the source and destination paths when write access is denied, ensuring fake
  sandbox consumers and layout recorders observe both sides of the attempted move.

