#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import random
import shutil
import socket
import sqlite3
import statistics
import sys
import time
import tracemalloc

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

S1_BROKER = Path(__file__).resolve().parents[1] / "common"
if str(S1_BROKER) not in sys.path:
    sys.path.insert(0, str(S1_BROKER))
from oasi_broker import Ledger, ProtocolError  # noqa: E402

MECHANISMS = (
    "B0_DIRECT", "B1_AUTH_STATELESS", "B2_AT_LEAST_ONCE",
    "B3_IDEMPOTENT_UNAVAILABLE", "OASI",
)
CASES = (
    "nominal", "replay", "cross_generation", "altered_signature",
    "crash_prepared", "crash_consumed_before_effect", "disconnect_before_effect",
    "disconnect_after_effect", "ack_lost_after_effect", "torn_write_after_effect",
)
PRIMARY_AMBIGUOUS_POST_EFFECT_CASES = ("disconnect_after_effect", "ack_lost_after_effect")
PRE_EFFECT_UNCERTAINTY_CASES = (
    "crash_prepared", "crash_consumed_before_effect", "disconnect_before_effect",
)
ROOT_SEED = 20260903
WARMUPS = 5
REPETITIONS = 30
FIXTURE_PRIVATE_SEED = bytes.fromhex(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
)
FIXTURE_PUBLIC_KEY = bytes.fromhex(
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
)


class ExperimentError(RuntimeError):
    pass


class AuthReject(ExperimentError):
    pass


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def atomic_json(path: Path, value: object) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, sort_keys=True, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def make_frame(generation: int, context: str, attempt: int, seed: int) -> dict[str, object]:
    body = canonical_json({
        "algorithm": "ed25519-rfc8032-fixture-only", "generation": generation,
        "context": context, "attempt": attempt,
        "payload": hashlib.sha256(f"NOOP:{seed}".encode()).hexdigest(),
    })
    signature = Ed25519PrivateKey.from_private_bytes(FIXTURE_PRIVATE_SEED).sign(body)
    return {"body": body, "signature": signature}


def verify_frame(frame: dict[str, object], generation: int, context: str, attempt: int) -> None:
    body, signature = bytes(frame["body"]), bytes(frame["signature"])
    try:
        Ed25519PublicKey.from_public_bytes(FIXTURE_PUBLIC_KEY).verify(signature, body)
    except InvalidSignature as exception:
        raise AuthReject("signature") from exception
    decoded = json.loads(body)
    if decoded.get("generation") != generation:
        raise AuthReject("generation")
    if decoded.get("context") != context or decoded.get("attempt") != attempt:
        raise AuthReject("context_attempt")


class NonCooperativeSink:
    """Append-only fixture: payload in, no key, query, transaction, or dedup API."""

    def __init__(self, path: Path):
        self.path = path
        with sqlite3.connect(path) as connection:
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute(
                "CREATE TABLE effects(sequence INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL)"
            )

    def apply(self, payload: str) -> None:
        with sqlite3.connect(self.path) as connection:
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("INSERT INTO effects(payload) VALUES(?)", (payload,))

    def count_for_observer_only(self) -> int:
        with sqlite3.connect(self.path) as connection:
            return int(connection.execute("SELECT COUNT(*) FROM effects").fetchone()[0])


class StateStore:
    def __init__(self, path: Path):
        self.path = path
        self.seal = path.with_suffix(path.suffix + ".sha256")
        if path.exists():
            self.verify_seal()
            return
        with sqlite3.connect(path) as connection:
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("CREATE TABLE jobs(job_key TEXT PRIMARY KEY, state TEXT NOT NULL)")
        self._seal()

    def _seal(self) -> None:
        digest = hashlib.sha256(self.path.read_bytes()).hexdigest()
        temporary = self.seal.with_suffix(self.seal.suffix + ".tmp")
        with temporary.open("w", encoding="ascii", newline="\n") as handle:
            handle.write(digest + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, self.seal)

    def verify_seal(self) -> None:
        if not self.seal.is_file():
            raise ExperimentError("coordinator seal missing")
        if self.seal.read_text(encoding="ascii").strip() != hashlib.sha256(self.path.read_bytes()).hexdigest():
            raise ExperimentError("coordinator seal mismatch")

    def prepare(self, key: str) -> None:
        self.verify_seal()
        with sqlite3.connect(self.path) as connection:
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("INSERT INTO jobs(job_key,state) VALUES(?, 'READY')", (key,))
        self._seal()

    def state(self, key: str) -> str:
        self.verify_seal()
        with sqlite3.connect(self.path) as connection:
            row = connection.execute("SELECT state FROM jobs WHERE job_key=?", (key,)).fetchone()
        return "ABSENT" if row is None else str(row[0])

    def result(self, key: str) -> None:
        self.verify_seal()
        with sqlite3.connect(self.path) as connection:
            connection.execute("PRAGMA synchronous=FULL")
            changed = connection.execute(
                "UPDATE jobs SET state='RESULT' WHERE job_key=? AND state='READY'", (key,)
            ).rowcount
            if changed != 1:
                raise ExperimentError("invalid result transition")
        self._seal()

    def corrupt(self) -> None:
        with self.path.open("ab") as handle:
            handle.write(b"TORN")
            handle.flush()
            os.fsync(handle.fileno())


def directory_bytes(path: Path) -> int:
    return sum(item.stat().st_size for item in path.iterdir() if item.is_file())


def rss_bytes() -> int:
    try:
        for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
    except OSError:
        pass
    return 0


def mutate_signature(frame: dict[str, object]) -> dict[str, object]:
    signature = bytearray(bytes(frame["signature"]))
    signature[0] ^= 1
    return {"body": bytes(frame["body"]), "signature": bytes(signature)}


def base_outcome() -> dict[str, object]:
    return {"disposition": "COMPLETE", "replay_accepted": False,
            "cross_generation_accepted": False, "altered_signature_accepted": False}


def run_stateless(mechanism: str, case: str, sink: NonCooperativeSink,
                  frame: dict[str, object], generation: int, context: str) -> dict[str, object]:
    authenticated = mechanism == "B1_AUTH_STATELESS"

    def dispatch(candidate: dict[str, object], expected_generation: int) -> None:
        if authenticated:
            verify_frame(candidate, expected_generation, context, 1)
        sink.apply("NOOP")

    result = base_outcome()
    if case == "nominal":
        dispatch(frame, generation)
    elif case == "replay":
        dispatch(frame, generation); dispatch(frame, generation)
        result["replay_accepted"] = True
    elif case == "cross_generation":
        try:
            dispatch(frame, generation + 1); result["cross_generation_accepted"] = True
        except AuthReject:
            result["disposition"] = "REJECTED_BINDING"
    elif case == "altered_signature":
        try:
            dispatch(mutate_signature(frame), generation); result["altered_signature_accepted"] = True
        except AuthReject:
            result["disposition"] = "REJECTED_SIGNATURE"
    elif case in PRE_EFFECT_UNCERTAINTY_CASES:
        dispatch(frame, generation)
        result["disposition"] = "RECOVERED_BY_REDISPATCH"
    elif case in ("disconnect_after_effect", "ack_lost_after_effect", "torn_write_after_effect"):
        dispatch(frame, generation); dispatch(frame, generation)
        result["disposition"] = "AMBIGUOUS_RECOVERED_BY_REDISPATCH"
    else:
        raise ExperimentError("unknown case")
    return result


def run_coordinated(case: str, run_dir: Path, sink: NonCooperativeSink,
                    frame: dict[str, object], generation: int, context: str,
                    key: str) -> dict[str, object]:
    result = base_outcome()
    if case == "cross_generation":
        try:
            verify_frame(frame, generation + 1, context, 1); result["cross_generation_accepted"] = True
        except AuthReject:
            result["disposition"] = "REJECTED_BINDING"
        return result
    if case == "altered_signature":
        try:
            verify_frame(mutate_signature(frame), generation, context, 1); result["altered_signature_accepted"] = True
        except AuthReject:
            result["disposition"] = "REJECTED_SIGNATURE"
        return result
    verify_frame(frame, generation, context, 1)
    store_path = run_dir / "coordinator.sqlite"
    store = StateStore(store_path)
    store.prepare(key)
    if case in PRE_EFFECT_UNCERTAINTY_CASES:
        store = StateStore(store_path)
        sink.apply("NOOP"); store.result(key)
        result["disposition"] = "RECOVERED_FROM_READY"
    elif case in PRIMARY_AMBIGUOUS_POST_EFFECT_CASES:
        sink.apply("NOOP")
        store = StateStore(store_path)
        sink.apply("NOOP"); store.result(key)
        result["disposition"] = "AMBIGUOUS_RECOVERED_FROM_READY"
    elif case == "torn_write_after_effect":
        sink.apply("NOOP"); store.corrupt()
        try:
            StateStore(store_path)
            raise ExperimentError("torn coordinator accepted")
        except ExperimentError as exception:
            if "seal mismatch" not in str(exception):
                raise
        result["disposition"] = "BLOCKED_TORN_COORDINATOR"
    else:
        sink.apply("NOOP"); store.result(key)
        if case == "replay":
            store = StateStore(store_path)
            if store.state(key) != "RESULT":
                raise ExperimentError("lost result")
            result["disposition"] = "REPLAY_REJECTED_RESULT_EXISTS"
    return result


def run_oasi(case: str, run_dir: Path, sink: NonCooperativeSink,
             frame: dict[str, object], generation: int, context: str) -> dict[str, object]:
    result = base_outcome()
    if case == "cross_generation":
        try:
            verify_frame(frame, generation + 1, context, 1); result["cross_generation_accepted"] = True
        except AuthReject:
            result["disposition"] = "REJECTED_BINDING"
        return result
    if case == "altered_signature":
        try:
            verify_frame(mutate_signature(frame), generation, context, 1); result["altered_signature_accepted"] = True
        except AuthReject:
            result["disposition"] = "REJECTED_SIGNATURE"
        return result
    verify_frame(frame, generation, context, 1)
    ledger_path = run_dir / "oasi-ledger.sqlite"
    ledger = Ledger(ledger_path)
    try:
        ledger.prepare()
        if case == "crash_prepared":
            ledger.close(); ledger = Ledger(ledger_path)
            if ledger.recovery_action() != "ABORT_WITHOUT_EFFECT":
                raise ExperimentError("prepared recovery drift")
            result["disposition"] = "ABORT_WITHOUT_EFFECT"
        elif case in ("crash_consumed_before_effect", "disconnect_before_effect"):
            ledger.consume(); ledger.close(); ledger = Ledger(ledger_path)
            if ledger.recovery_action() != "BLOCK_NO_REDISPATCH":
                raise ExperimentError("pre-effect ambiguity recovery drift")
            result["disposition"] = "BLOCK_NO_REDISPATCH_DELIVERY_LOST"
        elif case in PRIMARY_AMBIGUOUS_POST_EFFECT_CASES:
            ledger.consume(); sink.apply("NOOP"); ledger.close(); ledger = Ledger(ledger_path)
            if ledger.recovery_action() != "BLOCK_NO_REDISPATCH":
                raise ExperimentError("post-effect ambiguity recovery drift")
            result["disposition"] = "BLOCK_NO_REDISPATCH"
        elif case == "torn_write_after_effect":
            ledger.consume(); sink.apply("NOOP"); ledger.close()
            with ledger_path.open("ab") as handle:
                handle.write(b"TORN"); handle.flush(); os.fsync(handle.fileno())
            try:
                Ledger(ledger_path)
                raise ExperimentError("torn OASI ledger accepted")
            except ProtocolError as exception:
                if "seal mismatch" not in str(exception):
                    raise
            result["disposition"] = "BLOCKED_TORN_LEDGER"
            ledger = None
        else:
            ledger.consume(); sink.apply("NOOP")
            ledger.record_result(hashlib.sha256(b"NOOP").hexdigest()); ledger.terminal()
            if case == "replay":
                try:
                    ledger.consume(); result["replay_accepted"] = True
                except ProtocolError:
                    result["disposition"] = "REPLAY_REJECTED_TERMINAL"
    finally:
        if ledger is not None:
            ledger.close()
    return result


def validate_record(record: dict[str, object]) -> list[str]:
    errors: list[str] = []
    if record.get("mechanism") not in MECHANISMS: errors.append("mechanism")
    if record.get("case") not in CASES: errors.append("case")
    if not isinstance(record.get("effect_count"), int): errors.append("effect_count")
    if record.get("double_effect") != (int(record.get("effect_count", -1)) > 1): errors.append("double_effect")
    if record.get("real_effect") is not False or record.get("network_calls") != 0: errors.append("scope")
    if any(record.get(name) is not False for name in (
        "sink_idempotency_supported", "sink_transaction_supported", "sink_query_supported"
    )):
        errors.append("sink-capability-drift")
    if record.get("mechanism") == "OASI":
        if record.get("double_effect") is True: errors.append("OASI_DOUBLE_EFFECT")
        if record.get("replay_accepted") is True: errors.append("OASI_REPLAY_ACCEPTED")
        if record.get("cross_generation_accepted") is True: errors.append("OASI_CROSS_GENERATION_ACCEPTED")
        if record.get("altered_signature_accepted") is True: errors.append("OASI_ALTERED_SIGNATURE_ACCEPTED")
    return errors


def run_one(mechanism: str, case: str, repetition: int, seed: int, scratch: Path) -> dict[str, object]:
    run_dir = scratch / f"{case}-{repetition:02d}-{mechanism}"
    run_dir.mkdir(parents=True)
    generation = 200000 + seed
    context = hashlib.sha256(f"OASI:S6:{case}:{repetition}".encode()).hexdigest()
    key = f"{generation}:{context}:1"
    frame = make_frame(generation, context, 1, seed)
    sink = NonCooperativeSink(run_dir / "effect.sqlite")
    rss_before = rss_bytes(); tracemalloc.start()
    cpu_start, wall_start = time.process_time_ns(), time.perf_counter_ns()
    if mechanism in ("B0_DIRECT", "B1_AUTH_STATELESS"):
        outcome = run_stateless(mechanism, case, sink, frame, generation, context)
    elif mechanism in ("B2_AT_LEAST_ONCE", "B3_IDEMPOTENT_UNAVAILABLE"):
        outcome = run_coordinated(case, run_dir, sink, frame, generation, context, key)
    else:
        outcome = run_oasi(case, run_dir, sink, frame, generation, context)
    wall_ns, cpu_ns = time.perf_counter_ns() - wall_start, time.process_time_ns() - cpu_start
    _, heap_peak = tracemalloc.get_traced_memory(); tracemalloc.stop()
    rss_after = rss_bytes()
    effect_count = sink.count_for_observer_only()
    effect_expected = case not in ("cross_generation", "altered_signature")
    record = {
        "schema": "oasi.s6.run.v1", "mechanism": mechanism, "case": case,
        "repetition": repetition, "seed": seed,
        "sink_profile": "NON_COOPERATIVE_APPEND_ONLY_V1",
        "sink_idempotency_supported": False, "sink_transaction_supported": False,
        "sink_query_supported": False, "b3_idempotency_request_honored": False,
        "effect_count": effect_count, "effect_expected": effect_expected,
        "double_effect": effect_count > 1, "delivered_exactly_once": effect_count == 1,
        "delivery_lost": effect_expected and effect_count == 0,
        "ambiguous_post_effect": case in PRIMARY_AMBIGUOUS_POST_EFFECT_CASES,
        "pre_effect_uncertainty": case in PRE_EFFECT_UNCERTAINTY_CASES,
        "deterministic_terminal": outcome["disposition"] in {
            "COMPLETE", "REJECTED_BINDING", "REJECTED_SIGNATURE", "RECOVERED_BY_REDISPATCH",
            "AMBIGUOUS_RECOVERED_BY_REDISPATCH", "RECOVERED_FROM_READY",
            "AMBIGUOUS_RECOVERED_FROM_READY", "BLOCKED_TORN_COORDINATOR",
            "REPLAY_REJECTED_RESULT_EXISTS", "REPLAY_REJECTED_TERMINAL",
            "ABORT_WITHOUT_EFFECT", "BLOCK_NO_REDISPATCH", "BLOCK_NO_REDISPATCH_DELIVERY_LOST",
            "BLOCKED_TORN_LEDGER",
        },
        "wall_ns": wall_ns, "cpu_ns": cpu_ns, "python_heap_peak_bytes": heap_peak,
        "rss_delta_bytes": rss_after - rss_before, "artifact_bytes": directory_bytes(run_dir),
        "network_calls": 0, "real_effect": False, **outcome,
    }
    errors = validate_record(record)
    if errors:
        raise ExperimentError("record violation: " + ",".join(errors))
    shutil.rmtree(run_dir)
    return record


def nearest_rank(values: list[int], percentile: float) -> int:
    ordered = sorted(values)
    return ordered[min(max(1, math.ceil(percentile * len(ordered))) - 1, len(ordered) - 1)]


def wilson(successes: int, total: int) -> list[float]:
    z, p = 1.959963984540054, successes / total
    denominator = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    margin = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    return [round(max(0.0, center - margin), 9), round(min(1.0, center + margin), 9)]


def aggregate(records: list[dict[str, object]]) -> dict[str, object]:
    cells: dict[str, object] = {}
    for mechanism in MECHANISMS:
        for case in CASES:
            rows = [r for r in records if r["mechanism"] == mechanism and r["case"] == case]
            walls, cpus = [int(r["wall_ns"]) for r in rows], [int(r["cpu_ns"]) for r in rows]
            doubles = sum(bool(r["double_effect"]) for r in rows)
            exact = sum(bool(r["delivered_exactly_once"]) for r in rows)
            lost = sum(bool(r["delivery_lost"]) for r in rows)
            cells[f"{mechanism}|{case}"] = {
                "runs": len(rows), "double_effects": doubles,
                "double_effect_rate": round(doubles / len(rows), 9),
                "double_effect_wilson95": wilson(doubles, len(rows)),
                "delivered_exactly_once": exact, "delivery_rate": round(exact / len(rows), 9),
                "delivery_wilson95": wilson(exact, len(rows)),
                "delivery_lost": lost, "delivery_lost_rate": round(lost / len(rows), 9),
                "delivery_lost_wilson95": wilson(lost, len(rows)),
                "replay_accepted": sum(bool(r["replay_accepted"]) for r in rows),
                "cross_generation_accepted": sum(bool(r["cross_generation_accepted"]) for r in rows),
                "altered_signature_accepted": sum(bool(r["altered_signature_accepted"]) for r in rows),
                "wall_ns_mean": round(statistics.fmean(walls), 3),
                "wall_ns_p50": nearest_rank(walls, .50), "wall_ns_p95": nearest_rank(walls, .95),
                "wall_ns_p99": nearest_rank(walls, .99), "cpu_ns_mean": round(statistics.fmean(cpus), 3),
                "heap_peak_bytes_max": max(int(r["python_heap_peak_bytes"]) for r in rows),
                "rss_delta_bytes_max": max(int(r["rss_delta_bytes"]) for r in rows),
                "artifact_bytes_mean": round(statistics.fmean(int(r["artifact_bytes"]) for r in rows), 3),
            }
    b3_primary = [r for r in records if r["mechanism"] == "B3_IDEMPOTENT_UNAVAILABLE" and r["case"] in PRIMARY_AMBIGUOUS_POST_EFFECT_CASES]
    oasi_primary = [r for r in records if r["mechanism"] == "OASI" and r["case"] in PRIMARY_AMBIGUOUS_POST_EFFECT_CASES]
    b3_pre = [r for r in records if r["mechanism"] == "B3_IDEMPOTENT_UNAVAILABLE" and r["case"] in PRE_EFFECT_UNCERTAINTY_CASES]
    oasi_pre = [r for r in records if r["mechanism"] == "OASI" and r["case"] in PRE_EFFECT_UNCERTAINTY_CASES]
    b3_primary_double = sum(bool(r["double_effect"]) for r in b3_primary)
    oasi_primary_double = sum(bool(r["double_effect"]) for r in oasi_primary)
    b3_pre_loss = sum(bool(r["delivery_lost"]) for r in b3_pre)
    oasi_pre_loss = sum(bool(r["delivery_lost"]) for r in oasi_pre)
    safety_advantage = oasi_primary_double == 0 and b3_primary_double > 0
    availability_tradeoff = oasi_pre_loss > b3_pre_loss
    conclusion = (
        "BOUNDED_SAFETY_ADVANTAGE_ESTABLISHED_NON_COOPERATIVE_FIXTURE_WITH_AVAILABILITY_TRADEOFF"
        if safety_advantage and availability_tradeoff else "S6_HYPOTHESIS_NOT_ESTABLISHED"
    )
    return {
        "cells": cells,
        "primary_comparison_to_b3": {
            "scope": list(PRIMARY_AMBIGUOUS_POST_EFFECT_CASES),
            "b3_double_effects": b3_primary_double, "oasi_double_effects": oasi_primary_double,
            "b3_runs": len(b3_primary), "oasi_runs": len(oasi_primary),
            "bounded_safety_advantage_established": safety_advantage,
        },
        "availability_tradeoff": {
            "scope": list(PRE_EFFECT_UNCERTAINTY_CASES),
            "b3_delivery_losses": b3_pre_loss, "oasi_delivery_losses": oasi_pre_loss,
            "tradeoff_observed": availability_tradeoff,
        },
        "conclusion": conclusion,
    }


def deny_network() -> None:
    def denied(*_args: object, **_kwargs: object) -> None:
        raise ExperimentError("network denied")
    socket.create_connection = denied  # type: ignore[assignment]
    socket.getaddrinfo = denied  # type: ignore[assignment]
    socket.socket.connect = denied  # type: ignore[assignment]
    socket.socket.connect_ex = denied  # type: ignore[assignment]


def run_campaign(output: Path, scratch: Path, preregistration: Path) -> None:
    if output.exists() or scratch.exists():
        raise ExperimentError(f"refusing replay or stale scratch: {output} {scratch}")
    output.mkdir(parents=True); scratch.mkdir(parents=True)
    shutil.copyfile(preregistration, output / "PREREGISTRATION_LOCKED.md")
    deny_network()
    partial = output / "RAW_RUNS.jsonl.partial"
    records: list[dict[str, object]] = []
    warmups_done = 0
    with partial.open("x", encoding="utf-8", newline="\n") as handle:
        for case_index, case in enumerate(CASES):
            for mechanism in MECHANISMS:
                for warmup in range(1, WARMUPS + 1):
                    seed = ROOT_SEED + case_index * 1000 + 900 + warmup
                    run_one(mechanism, case, -warmup, seed, scratch); warmups_done += 1
            for repetition in range(1, REPETITIONS + 1):
                order = list(MECHANISMS)
                random.Random(f"{ROOT_SEED}:{case}:{repetition}").shuffle(order)
                seed = ROOT_SEED + case_index * 1000 + repetition
                for mechanism in order:
                    record = run_one(mechanism, case, repetition, seed, scratch)
                    records.append(record)
                    handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
                    handle.flush(); os.fsync(handle.fileno())
            checkpoint = output / "CAMPAIGN_CHECKPOINT.json"
            if checkpoint.exists(): checkpoint.unlink()
            atomic_json(checkpoint, {
                "schema": "oasi.s6.campaign-checkpoint.v1",
                "completed_cases": list(CASES[:case_index + 1]),
                "measured_runs": len(records), "warmups_done": warmups_done,
            })
    raw = output / "RAW_RUNS.jsonl"
    os.replace(partial, raw)
    summary = {
        "schema": "oasi.s6.scientific-local-summary.v1",
        "mechanisms": list(MECHANISMS), "cases": list(CASES),
        "warmups_per_cell": WARMUPS, "repetitions_per_cell": REPETITIONS,
        "measured_runs": len(records), "raw_sha256": hashlib.sha256(raw.read_bytes()).hexdigest(),
        "local_only": True, "fixture_only": True, "network_calls": 0, "real_effect": False,
        "guest_or_qemu_measured": False, "production_claim": False, **aggregate(records),
    }
    atomic_json(output / "SUMMARY.json", summary)
    shutil.rmtree(scratch)
    print(json.dumps({"status": "CAMPAIGN_COMPLETE", "runs": len(records),
                      "conclusion": summary["conclusion"]}, sort_keys=True))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--scratch", type=Path, required=True)
    parser.add_argument("--preregistration", type=Path, required=True)
    args = parser.parse_args()
    run_campaign(args.output, args.scratch, args.preregistration)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
