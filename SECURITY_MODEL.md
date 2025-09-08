# Security Model and Threat Considerations

## Overview
Cargo-warden isolates the Cargo build process by using Linux security features such as eBPF LSM hooks and cgroup v2. The tool allows only explicitly permitted network connections and executable launches while monitoring file system access.

## Trust Boundaries
- **Build Scripts and Procedural Macros**: Treated as untrusted code. They run under the warden policy and cannot access the network or spawn unauthorized executables.
- **Host System**: Assumed to be trusted but not infallible. Misconfiguration or kernel vulnerabilities may weaken enforcement.
- **Policy Files**: Signed or version-controlled policies are recommended to prevent tampering.

## Threat Considerations
- **Supply Chain Attacks**: Malicious dependencies may attempt to exfiltrate data or execute arbitrary commands. Warden blocks these actions unless explicitly allowed.
- **Privilege Escalation**: Attempts to escape containment via kernel exploits or capability abuse are outside warden's scope and rely on a hardened host.
- **Denial of Service**: Policies should avoid overly broad restrictions that could disrupt legitimate builds.

## Future Work
Future iterations may integrate seccomp and additional kernel features to tighten the sandbox and expose metrics for audit trails.
