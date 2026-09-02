#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
import sys
from collections import defaultdict
from pathlib import Path


ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
EXP = ROOT / "experiments"
ERRORS: list[str] = []


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> dict[str, object]:
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    except Exception as exc:
        ERRORS.append(f"invalid JSON {path.relative_to(ROOT).as_posix()}: {type(exc).__name__}")
        return {}


def load_jsonl(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    number = 0
    try:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            parsed = json.loads(line, object_pairs_hook=unique_object)
            if not isinstance(parsed, dict):
                raise ValueError("row is not an object")
            rows.append(parsed)
    except Exception as exc:
        ERRORS.append(f"invalid JSONL {path.relative_to(ROOT).as_posix()}:{number}: {type(exc).__name__}")
    return rows


def verify_manifest(root: Path, name: str) -> None:
    manifest_path = root / name
    if not manifest_path.is_file():
        ERRORS.append(f"missing manifest: {manifest_path.relative_to(ROOT).as_posix()}")
        return
    seen: set[str] = set()
    ordered: list[str] = []
    for line in manifest_path.read_text(encoding="ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\\]+)", line)
        if not match:
            ERRORS.append(f"bad manifest grammar: {manifest_path.relative_to(ROOT).as_posix()}")
            continue
        expected, relative = match.groups()
        candidate = root / relative
        if relative in seen or Path(relative).is_absolute() or ".." in Path(relative).parts:
            ERRORS.append(f"unsafe or duplicate manifest path: {relative}")
            continue
        seen.add(relative)
        ordered.append(relative)
        if not candidate.is_file() or sha256(candidate) != expected:
            ERRORS.append(f"manifest mismatch: {candidate.relative_to(ROOT).as_posix()}")
    if ordered != sorted(ordered):
        ERRORS.append(f"manifest is not in ordinal path order: {manifest_path.relative_to(ROOT).as_posix()}")
    observed = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file()
        and path != manifest_path
        and "__pycache__" not in path.relative_to(root).parts
        and path.suffix not in {".pyc", ".pyo"}
    }
    if seen != observed:
        missing = sorted(observed - seen)
        extra = sorted(seen - observed)
        ERRORS.append(
            f"manifest coverage mismatch: {manifest_path.relative_to(ROOT).as_posix()} "
            f"missing={missing[:5]} extra={extra[:5]}"
        )


def totals(rows: list[dict[str, object]], mechanism: str) -> dict[str, int]:
    selected = [row for row in rows if row.get("mechanism") == mechanism]
    return {
        "rows": len(selected),
        "effects": sum(int(row.get("effect_count", -1)) for row in selected),
        "doubles": sum(row.get("double_effect") is True for row in selected),
        "exact": sum(row.get("delivered_exactly_once") is True for row in selected),
        "lost": sum(row.get("delivery_lost") is True for row in selected),
        "replay": sum(row.get("replay_accepted") is True for row in selected),
    }


def verify_campaign(name: str, expected_rows: int, expected_cells: int) -> list[dict[str, object]]:
    base = EXP / name
    results = base / "results"
    verify_manifest(results, "RESULT_MANIFEST.sha256")
    rows = load_jsonl(results / "RAW_RUNS.jsonl")
    if len(rows) != expected_rows:
        ERRORS.append(f"{name} row count: {len(rows)} != {expected_rows}")
    identities = [(row.get("mechanism"), row.get("case"), row.get("repetition")) for row in rows]
    if len(identities) != len(set(identities)):
        ERRORS.append(f"{name} duplicate cell/repetition identity")
    cells = {(row.get("mechanism"), row.get("case")) for row in rows}
    if len(cells) != expected_cells:
        ERRORS.append(f"{name} cell count: {len(cells)} != {expected_cells}")
    common_fields = {
        "altered_signature_accepted", "artifact_bytes", "case", "cpu_ns",
        "cross_generation_accepted", "delivered_exactly_once",
        "deterministic_terminal", "disposition", "double_effect", "effect_count",
        "mechanism", "network_calls", "python_heap_peak_bytes", "real_effect",
        "repetition", "replay_accepted", "rss_delta_bytes", "schema", "seed", "wall_ns",
    }
    s6_fields = {
        "ambiguous_post_effect", "b3_idempotency_request_honored", "delivery_lost",
        "effect_expected", "pre_effect_uncertainty", "sink_idempotency_supported",
        "sink_profile", "sink_query_supported", "sink_transaction_supported",
    }
    required_fields = common_fields | (s6_fields if name == "s6" else set())
    if any(set(row) != required_fields for row in rows):
        ERRORS.append(f"{name} raw row property set drift")
    expected_schema = f"oasi.{name}.run.v1"
    if any(row.get("schema") != expected_schema for row in rows):
        ERRORS.append(f"{name} raw row schema drift")
    if any(
        row.get("real_effect") is not False
        or row.get("network_calls") != 0
        or row.get("deterministic_terminal") is not True
        for row in rows
    ):
        ERRORS.append(f"{name} scope sentinel violation")
    if name == "s6" and any(
        row.get("sink_profile") != "NON_COOPERATIVE_APPEND_ONLY_V1"
        or row.get("sink_idempotency_supported") is not False
        or row.get("sink_query_supported") is not False
        or row.get("sink_transaction_supported") is not False
        or row.get("b3_idempotency_request_honored") is not False
        for row in rows
    ):
        ERRORS.append("s6 non-cooperative sink sentinel drift")
    grouped: dict[tuple[object, object], list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        grouped[(row.get("mechanism"), row.get("case"))].append(row)
    for identity, group in grouped.items():
        repetitions = {row.get("repetition") for row in group}
        if repetitions != set(range(1, 31)):
            ERRORS.append(f"{name} repetition grid drift: {identity!r}")
    summary = load_json(results / "SUMMARY.json")
    if summary.get("raw_sha256") != sha256(results / "RAW_RUNS.jsonl"):
        ERRORS.append(f"{name} summary raw hash mismatch")
    checker = load_json(results / "INDEPENDENT_VERIFY_RESULT.json")
    if checker.get("status") != "PASS" or checker.get("runs") != expected_rows:
        ERRORS.append(f"{name} sealed aggregate checker result mismatch")
    categorical = (
        "effect_count", "double_effect", "delivered_exactly_once", "delivery_lost",
        "replay_accepted", "cross_generation_accepted", "altered_signature_accepted",
        "disposition",
    )
    by_cell: dict[tuple[object, object], set[tuple[object, ...]]] = defaultdict(set)
    for row in rows:
        by_cell[(row.get("mechanism"), row.get("case"))].add(tuple(row.get(field) for field in categorical))
    if any(len(outcomes) != 1 for outcomes in by_cell.values()):
        ERRORS.append(f"{name} categorical outcomes are not invariant as documented")
    if any(summary.get(field) != expected for field, expected in {
        "fixture_only": True,
        "guest_or_qemu_measured": False,
        "local_only": True,
        "measured_runs": expected_rows,
        "network_calls": 0,
        "production_claim": False,
        "real_effect": False,
        "repetitions_per_cell": 30,
    }.items()):
        ERRORS.append(f"{name} summary scope or count drift")
    mechanisms = {row.get("mechanism") for row in rows}
    cases = {row.get("case") for row in rows}
    if set(summary.get("mechanisms", [])) != mechanisms or set(summary.get("cases", [])) != cases:
        ERRORS.append(f"{name} summary mechanism/case grid drift")
    summary_cells = summary.get("cells", {})
    expected_cell_names = {f"{mechanism}|{case}" for mechanism, case in cells}
    if not isinstance(summary_cells, dict) or set(summary_cells) != expected_cell_names:
        ERRORS.append(f"{name} summary cell set drift")
    else:
        for (mechanism, case), group in grouped.items():
            cell = summary_cells[f"{mechanism}|{case}"]
            expected_counts = {
                "runs": len(group),
                "double_effects": sum(row.get("double_effect") is True for row in group),
                "delivered_exactly_once": sum(row.get("delivered_exactly_once") is True for row in group),
                "replay_accepted": sum(row.get("replay_accepted") is True for row in group),
                "cross_generation_accepted": sum(row.get("cross_generation_accepted") is True for row in group),
                "altered_signature_accepted": sum(row.get("altered_signature_accepted") is True for row in group),
            }
            if name == "s6":
                expected_counts["delivery_lost"] = sum(row.get("delivery_lost") is True for row in group)
            if not isinstance(cell, dict) or any(cell.get(field) != value for field, value in expected_counts.items()):
                ERRORS.append(f"{name} summary categorical aggregate drift: {mechanism}|{case}")
    return rows


verify_manifest(EXP, "MANIFEST.sha256")

pins = load_json(EXP / "EXECUTED_SOURCE_PINS.json")
broker = EXP / "common" / "oasi_broker.py"
expected_broker = pins.get("common", {}).get("oasi_broker.py", {}) if isinstance(pins.get("common"), dict) else {}
if not broker.is_file() or sha256(broker) != expected_broker.get("sha256") or broker.stat().st_size != expected_broker.get("size"):
    ERRORS.append("executed broker byte identity mismatch")

relocation = pins.get("relocation_delta", {})
declared_delta = set(relocation.get("files", [])) if isinstance(relocation, dict) else set()
observed_delta: set[str] = set()
for campaign in ("s5", "s6"):
    campaign_pins = pins.get(campaign, {})
    if not isinstance(campaign_pins, dict):
        ERRORS.append(f"missing executed source pins: {campaign}")
        continue
    for relative, identity in campaign_pins.items():
        public_relative = f"{campaign}/{relative}"
        candidate = EXP / public_relative
        if not isinstance(identity, dict) or not candidate.is_file():
            ERRORS.append(f"invalid or missing executed source pin: {public_relative}")
            continue
        if sha256(candidate) != identity.get("sha256") or candidate.stat().st_size != identity.get("size"):
            observed_delta.add(public_relative)
if observed_delta != declared_delta:
    ERRORS.append(
        f"executed/public source delta declaration mismatch: "
        f"observed={sorted(observed_delta)} declared={sorted(declared_delta)}"
    )

for name in ("s5", "s6"):
    source = (EXP / name / "experiment.py").read_text(encoding="utf-8")
    mutant = (EXP / name / "red_green_verifier_test.py").read_text(encoding="utf-8")
    if "/mnt/" in source or "\\Users\\" in source or "/mnt/" in mutant or "\\Users\\" in mutant:
        ERRORS.append(f"{name} private path remains")
    if 'Path(__file__).resolve().parents[1] / "common"' not in source:
        ERRORS.append(f"{name} relocatable common path missing")

s5 = verify_campaign("s5", 1200, 40)
s6 = verify_campaign("s6", 1500, 50)

expected_s5 = {
    "B0_DIRECT": {"rows": 240, "effects": 330, "doubles": 90, "exact": 150, "lost": 0, "replay": 30},
    "B1_AUTH_STATELESS": {"rows": 240, "effects": 270, "doubles": 90, "exact": 90, "lost": 0, "replay": 30},
    "B2_AT_LEAST_ONCE": {"rows": 240, "effects": 210, "doubles": 30, "exact": 150, "lost": 0, "replay": 0},
    "B3_IDEMPOTENT": {"rows": 240, "effects": 180, "doubles": 0, "exact": 180, "lost": 0, "replay": 0},
    "OASI": {"rows": 240, "effects": 120, "doubles": 0, "exact": 120, "lost": 0, "replay": 0},
}
expected_s6 = {
    "B0_DIRECT": {"rows": 300, "effects": 420, "doubles": 120, "exact": 180, "lost": 0, "replay": 30},
    "B1_AUTH_STATELESS": {"rows": 300, "effects": 360, "doubles": 120, "exact": 120, "lost": 0, "replay": 30},
    "B2_AT_LEAST_ONCE": {"rows": 300, "effects": 300, "doubles": 60, "exact": 180, "lost": 0, "replay": 0},
    "B3_IDEMPOTENT_UNAVAILABLE": {"rows": 300, "effects": 300, "doubles": 60, "exact": 180, "lost": 0, "replay": 0},
    "OASI": {"rows": 300, "effects": 150, "doubles": 0, "exact": 150, "lost": 90, "replay": 0},
}
for mechanism, expected in expected_s5.items():
    if totals(s5, mechanism) != expected:
        ERRORS.append(f"S5 totals drift: {mechanism}")
for mechanism, expected in expected_s6.items():
    if totals(s6, mechanism) != expected:
        ERRORS.append(f"S6 totals drift: {mechanism}")

# Reviewer-2 finding: the S6 B2 and B3-U categorical records must remain
# transparently identical. If this changes, the published interpretation and
# review must be repeated rather than silently keeping the old conclusion.
fields = (
    "case", "repetition", "effect_count", "double_effect", "delivered_exactly_once",
    "delivery_lost", "replay_accepted", "cross_generation_accepted",
    "altered_signature_accepted", "disposition",
)
indexed: dict[str, dict[tuple[object, object], tuple[object, ...]]] = {}
for mechanism in ("B2_AT_LEAST_ONCE", "B3_IDEMPOTENT_UNAVAILABLE"):
    indexed[mechanism] = {
        (row.get("case"), row.get("repetition")): tuple(row.get(field) for field in fields[2:])
        for row in s6 if row.get("mechanism") == mechanism
    }
if indexed["B2_AT_LEAST_ONCE"] != indexed["B3_IDEMPOTENT_UNAVAILABLE"]:
    ERRORS.append("S6 B2/B3-U equivalence drift requires new review")

s6_summary = load_json(ROOT / "public_evidence" / "S6_SCIENCE_SUMMARY.json")
if s6_summary.get("status") != "DIAGNOSTIC_POLICY_TRADEOFF_MECHANISM_SPECIFIC_ADVANTAGE_NOT_ESTABLISHED":
    ERRORS.append("S6 public diagnostic boundary missing")
s5_summary = load_json(ROOT / "public_evidence" / "S5_SCIENCE_SUMMARY.json")
if s5_summary.get("status") != "NEGATIVE_MECHANISM_ADVANTAGE_NOT_ESTABLISHED":
    ERRORS.append("S5 public negative boundary missing")

public_text = re.sub(
    r"\s+", " ",
    (ROOT / "SCIENTIFIC_RESULTS_S5_S6.md").read_text(encoding="utf-8"),
).lower()
for phrase in (
    "mechanism_specific_advantage_not_established",
    "deterministic trace simulations",
    "not treated as independent population sampling",
    "policy-matched at-most-once baseline",
    "cannot inspect per-run databases",
):
    if phrase not in public_text:
        ERRORS.append(f"scientific boundary phrase missing: {phrase}")

if any(EXP.rglob("__pycache__")) or any(EXP.rglob("*.pyc")) or any(EXP.rglob("*.pyo")):
    ERRORS.append("experiment cache or bytecode present")

result = {
    "pass": not ERRORS,
    "errors": ERRORS,
    "s5_records": len(s5),
    "s6_records": len(s6),
    "publication_verdict": "MECHANISM_SPECIFIC_ADVANTAGE_NOT_ESTABLISHED; BOUNDED_SAFETY_AVAILABILITY_TRADEOFF_OBSERVED",
}
print(json.dumps(result, indent=2, sort_keys=True))
raise SystemExit(0 if not ERRORS else 1)
