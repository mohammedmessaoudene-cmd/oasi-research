#!/usr/bin/env python3
"""Compare deterministic categorical outcomes while excluding host timings."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


FIELDS = (
    "schema",
    "effect_count",
    "double_effect",
    "delivered_exactly_once",
    "delivery_lost",
    "deterministic_terminal",
    "replay_accepted",
    "cross_generation_accepted",
    "altered_signature_accepted",
    "disposition",
    "network_calls",
    "real_effect",
    "ambiguous_post_effect",
    "pre_effect_uncertainty",
    "effect_expected",
    "sink_profile",
    "sink_idempotency_supported",
    "sink_query_supported",
    "sink_transaction_supported",
    "b3_idempotency_request_honored",
)


def load(path: Path) -> dict[tuple[object, object, object], tuple[object, ...]]:
    rows: dict[tuple[object, object, object], tuple[object, ...]] = {}
    with path.open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            row = json.loads(line)
            key = (row.get("mechanism"), row.get("case"), row.get("repetition"))
            if key in rows:
                raise SystemExit(f"duplicate tuple at {path}:{line_number}: {key!r}")
            rows[key] = tuple(row.get(field) for field in FIELDS)
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("sealed", type=Path)
    parser.add_argument("rerun", type=Path)
    args = parser.parse_args()
    sealed = load(args.sealed)
    rerun = load(args.rerun)
    missing = sorted(repr(key) for key in sealed.keys() - rerun.keys())
    extra = sorted(repr(key) for key in rerun.keys() - sealed.keys())
    mismatches = sorted(
        repr(key) for key in sealed.keys() & rerun.keys()
        if sealed[key] != rerun[key]
    )
    result = {
        "categorical_mismatches": len(mismatches),
        "extra_tuples": len(extra),
        "missing_tuples": len(missing),
        "pass": not missing and not extra and not mismatches,
        "rerun_rows": len(rerun),
        "sealed_rows": len(sealed),
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
