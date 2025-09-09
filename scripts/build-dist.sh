#!/usr/bin/env bash
set -euo pipefail

# Build release binaries for CLI and agent
cargo build --release -p cargo-warden -p agent-lite

# Determine version from CLI crate
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' crates/cli/Cargo.toml)
ARCH=$(uname -m)
OUTDIR=dist
mkdir -p "$OUTDIR"

# Choose agent artifact: binary if available, otherwise library
AGENT_PATH="target/release/agent-lite"
if [[ ! -f "$AGENT_PATH" ]]; then
    AGENT_PATH="target/release/libagent_lite.rlib"
fi

TARFILE="$OUTDIR/cargo-warden-$VERSION-$ARCH.tar.gz"
tar -C target/release -czf "$TARFILE" cargo-warden $(basename "$AGENT_PATH")
echo "Created $TARFILE"
