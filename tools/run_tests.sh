#!/usr/bin/env sh
set -eu
if [ "$#" -ne 1 ] || { [ "$1" != "pre-doi" ] && [ "$1" != "post-doi" ]; }; then
  echo "usage: sh tools/run_tests.sh pre-doi|post-doi" >&2
  exit 2
fi
OASI_RELEASE_PHASE="--$1"
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
export PYTHONDONTWRITEBYTECODE=1
if [ "${CARGO_TARGET_DIR+x}" != x ]; then
  OASI_TEST_TARGET="$(mktemp -d)"
  export CARGO_TARGET_DIR="$OASI_TEST_TARGET"
  cleanup_oasi_target() {
    if [ -n "${OASI_TEST_TARGET:-}" ] && [ "$OASI_TEST_TARGET" != "/" ]; then
      rm -rf -- "$OASI_TEST_TARGET"
    fi
  }
  trap cleanup_oasi_target EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
fi
[ "$(rustc --version)" = "rustc 1.97.1 (8bab26f4f 2026-07-14)" ] || {
  echo "exact rustc 1.97.1 qualification build is required" >&2
  exit 2
}
[ "$(cargo --version)" = "cargo 1.97.1 (c980f4866 2026-06-30)" ] || {
  echo "exact cargo 1.97.1 qualification build is required" >&2
  exit 2
}
rustc --version --verbose | grep -Fx 'host: x86_64-unknown-linux-gnu' >/dev/null || {
  echo "rust host pin mismatch" >&2
  exit 2
}
python3 -I -B -c 'import platform, sqlite3, sys; import cryptography, yaml; expected={"implementation":"cpython","python":"3.12.3","pyyaml":"6.0.1","cryptography":"41.0.7","sqlite":"3.45.1"}; observed={"implementation":sys.implementation.name,"python":platform.python_version(),"pyyaml":yaml.__version__,"cryptography":cryptography.__version__,"sqlite":sqlite3.sqlite_version}; raise SystemExit(0 if observed == expected else "qualification Python runtime pin mismatch: observed=%r expected=%r" % (observed, expected))'
cargo test --offline --locked --all-targets
python3 -I -B -m unittest discover -s experiments/s5/tests -v
python3 -I -B -m unittest discover -s experiments/s6/tests -v
python3 -I -B experiments/s5/red_green_verifier_test.py
python3 -I -B experiments/s6/red_green_verifier_test.py
python3 -I -B tools/verify_experiments.py .
python3 -I -B tools/verify_release.py . "$OASI_RELEASE_PHASE"
