#!/usr/bin/env bash
set -euo pipefail

TARGET="bpfel-unknown-none"
ARCHES=(x86_64 aarch64)
STACK_SIZE=4096

rustup target add "$TARGET" --toolchain nightly >/dev/null 2>&1 || true
rustup component add rust-src --toolchain nightly >/dev/null 2>&1 || true
command -v bpf-linker >/dev/null 2>&1 || cargo install bpf-linker >/dev/null 2>&1

for arch in "${ARCHES[@]}"; do
    RUSTFLAGS="-C link-arg=--llvm-args=-bpf-stack-size=$STACK_SIZE" \
        cargo +nightly rustc -p bpf-core --release --target "$TARGET" -Z build-std=core -- --emit=obj
    mkdir -p "prebuilt/$arch"
    cp "target/$TARGET/release/deps/bpf_core.o" "prebuilt/$arch/bpf-core.o"
done
