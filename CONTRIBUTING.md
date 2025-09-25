# CONTRIBUTING

Thank you for helping us harden cargo-warden. This document explains how to set up your environment, propose changes, and keep the security posture intact.

## Getting Started

1. Install the required toolchain and repository tooling by running:

```bash
./repo-setup.sh
```

2. Configure GitHub CLI access so you can inspect workflows and automation:

```bash
gh auth status
gh run list --limit 5
```

3. Fetch the latest changes and create a fresh feature branch from `main` for every task. Branch names should be short, hyphenated English descriptions (for example, `policy-validator-fix`).

## Development Workflow

1. Keep commits focused and include descriptive English messages.
2. Follow the project layout and module boundaries documented in `SPEC.md` and the crate-level READMEs.
3. Write code in English, and prefer small, reviewable changes.
4. Update or add tests whenever behaviour changes. Remove dead code instead of suppressing warnings.

## Mandatory Checks

Every contribution must pass the full validation suite before you submit it for review. Run all commands from the workspace root:

```bash
cargo fmt --all
cargo check --tests --benches
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo machete
./scripts/check_path_versions.sh
```

Resolve any failures before continuing. If you add new tooling, document it in this file and in the relevant crate README.

## Documentation Standards

- Markdown files use uppercase filenames with underscores (for example, `END_TO_END_TUTORIAL.md`).
- Always start headings with `#` and specify the language for code blocks (` ```bash `, ` ```rust `, and so on).
- Keep documentation in English and update references when APIs or CLI flows change.

## Workflow Automation

Mirror the CI pipelines locally to match GitHub Actions:

```bash
wrkflw validate
wrkflw run .github/workflows/ci.yml
```

Refer to recent workflow history with:

```bash
gh run list --limit 5
```

Escalate flakes or infrastructure issues with logs so maintainers can triage quickly.

## Repository Hygiene

- Audit remote feature branches with `scripts/prune_branches.sh`. The script skips protected branches, tolerates `null`
  timestamps in the API payload, and deletes candidates when you pass `--prune`.
- Adjust the inactivity threshold by exporting `CARGO_WARDEN_PRUNE_AGE` (in seconds).

## Reviewing and Merging

1. Open draft pull requests early if you need feedback, but keep automated checks green before requesting review.
2. Mention any deviations from the standard workflow and justify them in the PR description.
3. Ensure your branch is rebased on top of the latest `main` before final review.
4. After approval, maintainers will merge using the standard fast-forward workflow.

## Communication

- Use GitHub issues or discussions for feature requests and bug reports.
- Keep discussions respectful and actionable.
- For security-sensitive reports, follow the process documented in `SECURITY.md`.

We appreciate every contribution that makes cargo-warden more reliable and secure.
