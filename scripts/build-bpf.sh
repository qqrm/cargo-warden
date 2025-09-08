#!/usr/bin/env bash
set -euo pipefail

TARGET="bpfel-unknown-none"
ARCHES=(x86_64 aarch64)
STACK_SIZE=4096

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

for arch in "${ARCHES[@]}"; do
    RUSTFLAGS="-C link-arg=--llvm-args=-bpf-stack-size=$STACK_SIZE" \
        cargo +nightly rustc -p bpf-core --release --target "$TARGET" -Z build-std=core -- --emit=obj
    mkdir -p "prebuilt/$arch"
    cp "target/$TARGET/release/deps/bpf_core.o" "prebuilt/$arch/bpf-core.o"
done
