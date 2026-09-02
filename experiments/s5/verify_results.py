#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import statistics


MECHANISMS = ("B0_DIRECT", "B1_AUTH_STATELESS", "B2_AT_LEAST_ONCE", "B3_IDEMPOTENT", "OASI")
CASES = ("nominal", "replay", "cross_generation", "altered_signature", "crash_prepared", "crash_consumed", "crash_after_effect_before_result", "torn_write")


def nearest_rank(values: list[int], percentile: float) -> int:
    ordered = sorted(values)
    rank = max(1, math.ceil(percentile * len(ordered)))
    return ordered[min(rank - 1, len(ordered) - 1)]


def wilson(successes: int, total: int) -> list[float]:
    z = 1.959963984540054
    p = successes / total
    denominator = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    margin = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    return [round(max(0.0, center - margin), 9), round(min(1.0, center + margin), 9)]


def aggregate(records: list[dict[str, object]]) -> dict[str, object]:
    cells: dict[str, object] = {}
    for mechanism in MECHANISMS:
        for case in CASES:
            rows = [r for r in records if r["mechanism"] == mechanism and r["case"] == case]
            if len(rows) != 30:
                raise ValueError(f"cell count {mechanism}|{case}={len(rows)}")
            walls = [int(r["wall_ns"]) for r in rows]
            cpus = [int(r["cpu_ns"]) for r in rows]
            doubles = sum(bool(r["double_effect"]) for r in rows)
            exact = sum(bool(r["delivered_exactly_once"]) for r in rows)
            cells[f"{mechanism}|{case}"] = {
                "runs": len(rows), "double_effects": doubles,
                "double_effect_rate": round(doubles / len(rows), 9),
                "double_effect_wilson95": wilson(doubles, len(rows)),
                "delivered_exactly_once": exact, "delivery_rate": round(exact / len(rows), 9),
                "delivery_wilson95": wilson(exact, len(rows)),
                "replay_accepted": sum(bool(r["replay_accepted"]) for r in rows),
                "cross_generation_accepted": sum(bool(r["cross_generation_accepted"]) for r in rows),
                "altered_signature_accepted": sum(bool(r["altered_signature_accepted"]) for r in rows),
                "wall_ns_mean": round(statistics.fmean(walls), 3),
                "wall_ns_p50": nearest_rank(walls, .50), "wall_ns_p95": nearest_rank(walls, .95),
                "wall_ns_p99": nearest_rank(walls, .99),
                "cpu_ns_mean": round(statistics.fmean(cpus), 3),
                "heap_peak_bytes_max": max(int(r["python_heap_peak_bytes"]) for r in rows),
                "rss_delta_bytes_max": max(int(r["rss_delta_bytes"]) for r in rows),
                "artifact_bytes_mean": round(statistics.fmean(int(r["artifact_bytes"]) for r in rows), 3),
            }
    b3 = [r for r in records if r["mechanism"] == "B3_IDEMPOTENT"]
    oasi = [r for r in records if r["mechanism"] == "OASI"]
    b3_double = sum(bool(r["double_effect"]) for r in b3)
    oasi_double = sum(bool(r["double_effect"]) for r in oasi)
    b3_delivery = sum(bool(r["delivered_exactly_once"]) for r in b3)
    oasi_delivery = sum(bool(r["delivered_exactly_once"]) for r in oasi)
    advantage = oasi_double < b3_double and oasi_delivery >= b3_delivery
    return {"cells": cells, "comparison_to_b3": {"b3_double_effects": b3_double,
            "oasi_double_effects": oasi_double, "b3_exact_deliveries": b3_delivery,
            "oasi_exact_deliveries": oasi_delivery, "global_advantage_established": advantage},
            "conclusion": "OASI_ADVANTAGE_ESTABLISHED_IN_THIS_LOCAL_MODEL" if advantage else "MECHANISM_ADVANTAGE_NOT_ESTABLISHED_AGAINST_B3"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", type=Path, required=True)
    args = parser.parse_args()
    raw = args.results / "RAW_RUNS.jsonl"
    summary_path = args.results / "SUMMARY.json"
    if not raw.is_file() or not summary_path.is_file():
        raise SystemExit("missing results")
    records = [json.loads(line) for line in raw.read_text(encoding="utf-8").splitlines()]
    if len(records) != 1200:
        raise SystemExit(f"run count {len(records)}")
    keys = {(r["mechanism"], r["case"], r["repetition"]) for r in records}
    if len(keys) != 1200:
        raise SystemExit("duplicate run tuple")
    if any(r.get("network_calls") != 0 or r.get("real_effect") is not False for r in records):
        raise SystemExit("scope violation")
    oasi = [r for r in records if r["mechanism"] == "OASI"]
    if any(r["double_effect"] or r["replay_accepted"] or r["cross_generation_accepted"] or r["altered_signature_accepted"] for r in oasi):
        raise SystemExit("OASI safety violation")
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    if summary.get("raw_sha256") != hashlib.sha256(raw.read_bytes()).hexdigest():
        raise SystemExit("raw hash mismatch")
    recomputed = aggregate(records)
    for field in ("cells", "comparison_to_b3", "conclusion"):
        if summary.get(field) != recomputed[field]:
            raise SystemExit(f"aggregate mismatch {field}")
    result = {"schema": "oasi.s5.independent-verification.v1", "status": "PASS",
              "runs": 1200, "cells": 40, "oasi_safety_violations": 0,
              "network_calls": 0, "conclusion": recomputed["conclusion"],
              "raw_sha256": hashlib.sha256(raw.read_bytes()).hexdigest()}
    output = args.results / "INDEPENDENT_VERIFY_RESULT.json"
    output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

