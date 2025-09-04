# Spawn Bash Example

This crate attempts to spawn `/bin/bash`.
When run under `cargo warden`, the process creation is denied and prints an error like:

```text
spawn blocked: Permission denied (os error 1)
```

To allow this, add `/bin/bash` to the exec allowlist.
