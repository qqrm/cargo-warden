#!/usr/bin/env bash
set -euo pipefail

# Run network-build example
printf '== network-build ==\n'
(
    cd examples/network-build
    WARDEN_OFFLINE=1 cargo run -p cargo-warden -- build
)

# Build spawn-bash example
printf '\n== spawn-bash ==\n'
(
    cd examples/spawn-bash
    cargo build
)
