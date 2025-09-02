# Event Log ABI

The eBPF layer emits `Event` records via a ring buffer. This ABI defines the layout shared between kernel and userspace.

```rust
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Event {
    pub pid: u32,
    pub unit: u8,        // 0 Other, 1 BuildRs, 2 ProcMacro, 3 Rustc, 4 Linker
    pub action: u8,      // 0 Open, 1 Rename, 2 Unlink, 3 Exec, 4 Connect
    pub verdict: u8,     // 0 Allowed, 1 Denied
    pub reserved: u8,    // padding for alignment, reserved for future use
    pub path_or_addr: [u8; 256], // null-terminated path or network address
}
```

- **pid** – process identifier.
- **unit** – workload category generating the event.
- **action** – operation being audited.
- **path_or_addr** – associated filesystem path or network address.
- **verdict** – allow (`0`) or deny (`1`).

