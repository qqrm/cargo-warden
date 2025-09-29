# DOCUMENTATION_INDEX

The documentation set is grouped under the `DOCS/` directory to keep the repository root focused on source code. Use the followi
ng guide to discover the most relevant references:

- `DOCS/CONTRIBUTING.md` – Contribution workflow, validation requirements, and communication guidelines.
- `DOCS/END_TO_END_TUTORIAL.md` – Step-by-step walkthrough for enforcing policies and observing audit events.
- `DOCS/EVENT_LOG_ABI.md` – Reference for the on-disk layout of audit log entries.
- `DOCS/POLICY_SCHEMA.md` – Complete schema for authoring policies consumed by cargo-warden.
- `DOCS/SECURITY.md` – Responsible disclosure process and security contact information.
- `DOCS/SECURITY_MODEL.md` – Threat model and design assumptions for the agent.

The repository root retains `README.md` and `SPEC.md` because they are consumed by crates and tooling at fixed locations. All o
ther Markdown documentation now lives under `DOCS/`.
