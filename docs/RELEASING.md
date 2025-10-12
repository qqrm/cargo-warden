# Releasing cargo-warden

This guide outlines how to publish the `cargo-warden` workspace to [crates.io](https://crates.io/) and validate that the published binaries can be installed with `cargo install`.

## Prerequisites

1. **crates.io access** – ensure the maintainer performing the release is an owner of every crate in the workspace.
2. **API token** – create a crates.io API token and configure it locally:

   ```bash
   cargo login
   ```

3. **Clean checkout** – start from a clean tree that is up to date with the `main` branch.
4. **Toolchain** – use the stable toolchain unless the release notes require otherwise.

## 1. Select the release version

Update the workspace version numbers and changelog entries.

1. Choose the semantic version to publish.
2. Update `Cargo.toml` files with the new version. The [`cargo-set-version`](https://crates.io/crates/cargo-edit) subcommand from `cargo-edit` keeps dependency versions consistent:

   ```bash
   cargo set-version <new-version>
   ```

   Run the command once per crate that exposes a public version. Commit the changes together with the release notes.
3. Update `CHANGELOG.md` with a section describing the release.

## 2. Verify the workspace

Before publishing, run the full validation suite from a clean state:

```bash
cargo fmt
cargo check
cargo clippy --all-targets --all-features
cargo test
cargo machete
./scripts/check_path_versions.sh
```

These commands must complete without warnings or errors.

## 3. Dry-run the publication

Use `cargo publish --dry-run` to validate each crate in dependency order. Publish the low-level crates first:

```bash
for krate in \
  bpf-api bpf-core bpf-host sandbox-runtime policy-core policy-compiler \
  agent-lite event-reporting testkits cli; do
  (cd crates/$krate && cargo publish --dry-run)
done
```

Review the output carefully and address any packaging warnings.

## 4. Publish to crates.io

Once the dry-run succeeds, publish the crates for real, reusing the same order. Wait for each crate to become available before publishing the dependents (usually a few minutes):

```bash
for krate in \
  bpf-api bpf-core bpf-host sandbox-runtime policy-core policy-compiler \
  agent-lite event-reporting testkits cli; do
  (cd crates/$krate && cargo publish --allow-dirty --no-verify)
  sleep 60
  cargo search cargo-warden --limit 1 >/dev/null
  echo "Published $krate"
done
```

Remove `--allow-dirty` if the tree is clean; it is shown above to allow publishing from a release automation container where generated files may appear.

## 5. Tag the release

After the crates have been published, create an annotated tag and push it to GitHub:

```bash
git tag -a v<new-version> -m "cargo-warden <new-version>"
git push origin v<new-version>
```

Attach release notes to the corresponding GitHub release. Include links to the changelog, crates.io, and the prebuilt BPF artifact bundle.

## 6. Verify installation via cargo

Test the freshly published binary from a clean environment (for example, using a container or VM):

```bash
cargo install cargo-warden --version <new-version>
```

Run the smoke-test workflow to ensure the binary works end-to-end:

```bash
cargo warden init example-policy
cargo warden status
```

Point the binary at the downloaded BPF bundle or run against the fake sandbox for development testing.

## 7. Update downstream artifacts

1. Update distribution packages (Docker images, distro packages) to depend on the new version.
2. Refresh the `prebuilt/` directory if shipping precompiled BPF objects with downstream bundles.
3. Notify maintainers and users via the project communication channels.

## 8. Record the release

Update the release history in `CHANGELOG.md` and link to the GitHub release. Close the milestone associated with the release.

