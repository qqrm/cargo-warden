#!/usr/bin/env bash
set -euo pipefail

cargo deny fetch
cargo deny check --disable-fetch
