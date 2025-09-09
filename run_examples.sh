#!/usr/bin/env bash
set -euo pipefail

# Build network-build example
printf '== network-build ==\n'
(
    cd examples/network-build
    cargo build
)

# Build spawn-bash example
printf '\n== spawn-bash ==\n'
(
    cd examples/spawn-bash
    cargo build
)
