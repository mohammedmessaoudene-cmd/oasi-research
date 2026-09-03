#!/usr/bin/env sh
set -eu
root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
exec python3 -I -B "$root/tools/build_article_v0_4_1_verified.py" --root "$root" "$@"
