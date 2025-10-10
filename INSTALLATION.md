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

1. `QQRM_BPF_OBJECT` (full path to a single object file)
2. `QQRM_BPF_DIST_DIR` (directory containing `manifest.json`)
3. `${XDG_DATA_HOME:-$HOME/.local/share}/cargo-warden/bpf`
4. `/usr/share/cargo-warden/bpf`
5. The workspace `prebuilt/` directory (for local development only)

## Regenerating artifacts

Downstream packagers can rebuild the bundle directly from source:

```bash
./scripts/build-bpf.sh
```

The script validates the kernel version, checks for the required capabilities,
installs tooling, and emits a fresh manifest and object files under `prebuilt/`.
Copy the directory into the package payload and ship the `manifest.json` file
alongside the architecture directories. Point `QQRM_BPF_DIST_DIR` at the
installation prefix when testing the packaged build.
