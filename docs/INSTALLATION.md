# Installation

## Kernel prerequisites

Ensure the host kernel satisfies the minimum requirements before attempting to
run the sandbox:

```bash
uname -r
```

Version `5.13` or newer is required for the BPF LSM hooks. Verify the runtime
capabilities for the user running the sandbox:

```bash
capsh --print | grep CapEff
```

The capability set must include both `cap_bpf` and `cap_sys_admin`. When the
binary runs under a unit file or container, add the capabilities explicitly.

## System dependencies

Install the userland dependencies required to compile and run the sandbox.
On Debian-based distributions:

```bash
sudo apt-get update
sudo apt-get install libseccomp-dev pkg-config
```

The development package pulls in the shared library (`libseccomp2`) used at
runtime. Package maintainers targeting minimal images should ensure the
runtime environment includes `libseccomp2` alongside the CLI binary.

## Installing from crates.io

After publishing a release, install the CLI directly with `cargo install`:

```bash
cargo install cargo-warden --version <published-version>
```

Run `cargo warden --help` to confirm the binary is on the PATH. Follow the next sections to download or rebuild the BPF artifact bundle before running the sandbox.

## Fetching prebuilt BPF artifacts

Every push to `main` triggers the `Build BPF Artifacts` workflow. Download the
`prebuilt.tar.gz` bundle and accompanying `manifest.json` from the workflow
summary. Verify the checksum for the target architecture before packaging:

```bash
jq -r '.artifacts[] | select(.architecture == env.ARCH) | .sha256' manifest.json \
  | tee checksum.txt
sha256sum -c checksum.txt --ignore-missing
```

Set `ARCH` to the destination architecture (`x86_64` or `aarch64`) before
running the command.

Install the object files under the data directory of your package. The runtime
searches in the following order:

1. `WARDEN_BPF_OBJECT` (full path to a single object file)
2. `WARDEN_BPF_DIST_DIR` (directory containing `manifest.json`)
3. `${XDG_DATA_HOME:-$HOME/.local/share}/cargo-warden/bpf`
4. `/usr/share/cargo-warden/bpf`
5. The workspace `prebuilt/` directory (for local development only)

## Regenerating artifacts

Downstream packagers can rebuild the bundle directly from source:

```bash
cargo build -p warden-bpf-core --release
```

The crate's build script invokes the nightly toolchain, emits a fresh manifest,
and copies the object into each architecture directory under `prebuilt/`.
Export `WARDEN_BPF_USE_PREBUILT=1` to skip the rebuild step when packaging
existing artifacts. Copy the directory into the package payload and ship the
`manifest.json` file alongside the architecture directories. Point
`WARDEN_BPF_DIST_DIR` at the installation prefix when testing the packaged
build.
