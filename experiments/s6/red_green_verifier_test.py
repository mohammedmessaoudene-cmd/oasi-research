#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main() -> int:
    source = Path(__file__).resolve().parent / "results"
    with tempfile.TemporaryDirectory(prefix="oasi-s6-mutant-") as temporary:
        target = Path(temporary) / "results"
        shutil.copytree(source, target)
        raw = target / "RAW_RUNS.jsonl"
        rows = [json.loads(line) for line in raw.read_text(encoding="utf-8").splitlines()]
        for row in rows:
            if row["mechanism"] == "OASI":
                row["effect_count"] = 2
                row["double_effect"] = True
                break
        raw.write_text(
            "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
            encoding="utf-8",
        )
        verifier = Path(__file__).with_name("verify_results.py")
        result = subprocess.run(
            [sys.executable, str(verifier), "--results", str(target)],
            check=False,
            capture_output=True,
            text=True,
        )
        combined = result.stdout + result.stderr
        if result.returncode == 0 or "OASI safety violation" not in combined:
            print("FAIL_RED_GREEN_MUTANT_ACCEPTED")
            return 1
        print(f"PASS_RED_GREEN_MUTANT_REJECTED rc={result.returncode} reason=OASI_safety_violation")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
