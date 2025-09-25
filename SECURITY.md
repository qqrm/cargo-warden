# SECURITY POLICY

## Supported Versions

Cargo-warden is currently in active development. We respond to vulnerability reports for the latest `main` branch and the most recent tagged release. Older versions may not receive fixes unless a maintainer explicitly backports a patch.

## Reporting a Vulnerability

1. **Do not** open a public GitHub issue for security vulnerabilities.
2. Submit a private advisory through the GitHub Security Advisory workflow for `qqrm/cargo-warden` or email the maintainers at `security@cargo-warden.dev`.
3. Include as much detail as possible:
   - Affected components or crates
   - Steps to reproduce the issue
   - Potential impact and any available mitigations
   - Suggested fixes, if you have them
4. Expect an acknowledgement within three business days. If you do not receive a response, follow up on the same channel to ensure the report was received.

## Vulnerability Handling Process

1. Triage and reproduce the reported issue.
2. Coordinate on a fix in a private branch, adding regression tests whenever possible.
3. Prepare a security advisory with mitigation steps and patch availability.
4. Release patched versions and notify reporters before public disclosure.

## Safe Disclosure Guidelines

- Limit distribution of exploit details until a fix is available.
- Avoid discussing vulnerabilities in public chats, issues, or pull requests before coordinated disclosure.
- Credit reporters in the advisory when they consent to disclosure.

Thank you for helping us keep cargo-warden users safe.
