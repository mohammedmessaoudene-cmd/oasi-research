#!/usr/bin/env sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cargo test --locked --all-targets
python3 -I -B tools/verify_release.py .
