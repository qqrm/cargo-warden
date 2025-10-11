#!/usr/bin/env bash
set -euo pipefail

TARGET="bpfel-unknown-none"
ARCHES=(x86_64 aarch64)
STACK_SIZE=4096
MANIFEST_NAME="manifest.json"

ensure_kernel_support() {
    local kernel_version
    kernel_version="$(uname -r | cut -d- -f1)"
    if [ "$(printf '%s\n' "5.13" "$kernel_version" | sort -V | head -n1)" != "5.13" ]; then
        echo "error: linux kernel $kernel_version is older than the required 5.13" >&2
        exit 1
    fi

    if command -v capsh >/dev/null 2>&1; then
        local capabilities
        capabilities="$(capsh --print 2>/dev/null | tr '[:upper:]' '[:lower:]')"
        for capability in cap_bpf cap_sys_admin; do
            if ! grep -q "$capability" <<<"$capabilities"; then
                echo "warning: current session is missing $capability; loading artifacts may fail" >&2
            fi
        done
    else
        echo "warning: capsh not found; skipping capability inspection" >&2
    fi
}

ensure_kernel_support

if ! command -v jq >/dev/null 2>&1; then
    echo "error: jq is required to generate the checksum manifest" >&2
    exit 1
fi

rustup toolchain install nightly >/dev/null
rustup component add rust-src llvm-tools-preview --toolchain nightly >/dev/null
LLVM_LIB="$(rustc +nightly --print sysroot)/lib"
export LD_LIBRARY_PATH="$LLVM_LIB:${LD_LIBRARY_PATH:-}"
if ! command -v bpf-linker >/dev/null 2>&1; then
    if command -v cargo-binstall >/dev/null 2>&1; then
        cargo binstall --no-confirm bpf-linker >/dev/null 2>&1 || cargo install bpf-linker >/dev/null 2>&1
    else
        cargo install bpf-linker >/dev/null 2>&1
    fi
fi

rm -rf prebuilt
declare -A CHECKSUMS

for arch in "${ARCHES[@]}"; do
    RUSTFLAGS="-C link-arg=--llvm-args=-bpf-stack-size=$STACK_SIZE" \
        cargo +nightly rustc -p warden-bpf-core --release --target "$TARGET" -Z build-std=core -- --emit=obj
    mkdir -p "prebuilt/$arch"
    cp "target/$TARGET/release/deps/warden_bpf_core.o" "prebuilt/$arch/warden-bpf-core.o"
    CHECKSUMS["$arch"]="$(sha256sum "prebuilt/$arch/warden-bpf-core.o" | awk '{print $1}')"
done

pkg_version="$(cargo metadata --format-version 1 --no-deps | jq -r '.packages[] | select(.name=="warden-bpf-core") | .version')"
generated_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

cat >"prebuilt/$MANIFEST_NAME" <<MANIFEST
{
  "package": "warden-bpf-core",
  "version": "$pkg_version",
  "kernel_min": "5.13",
  "generated_at": "$generated_at",
  "target": "$TARGET",
  "artifacts": [
    {
      "architecture": "x86_64",
      "file": "x86_64/warden-bpf-core.o",
      "sha256": "${CHECKSUMS[x86_64]}"
    },
    {
      "architecture": "aarch64",
      "file": "aarch64/warden-bpf-core.o",
      "sha256": "${CHECKSUMS[aarch64]}"
    }
  ]
}
MANIFEST
