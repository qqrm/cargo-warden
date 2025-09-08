#!/usr/bin/env bash
set -euo pipefail

# Run network-build example
printf '== network-build ==\n'
(
    cd examples/network-build
    WARDEN_OFFLINE=1 cargo run -p cargo-warden -- build
)

printf '\n== spawn-bash ==\n'
(
    cd examples/spawn-bash
    cargo run -p cargo-warden -- run -- cargo run
)

