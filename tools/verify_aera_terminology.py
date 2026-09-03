#!/usr/bin/env python3
"""Fail-closed verifier for the v0.2.2 AERA terminology correction."""

from __future__ import annotations

import argparse
import json
import os
import stat
import tempfile
from pathlib import Path


DEPRECATED_LONG_FORMS = (
    "Attested Epoch-bound Runtime " + "Authority",
    "Atomic Embodiment Runtime " + "Assurance",
)
TEXT_SUFFIXES = {".cff", ".json", ".md", ".py", ".rs", ".sh", ".tex", ".toml", ".txt"}
EXCLUDED_PARTS = {".git", "target", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
ALLOWED_HISTORICAL_EXACT = {
    "AERA_TERMINOLOGY_ERRATUM.md",
    "paper/v0.4.1/CORRIGENDUM_V0_4_1.md",
}


def is_link_or_reparse(path: Path) -> bool:
    status = os.lstat(path)
    attributes = getattr(status, "st_file_attributes", 0)
    return stat.S_ISLNK(status.st_mode) or bool(
        attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def historical_or_erratum(relative: str) -> bool:
    return (
        relative.startswith("paper/v0.3/")
        or relative.startswith("paper/v0.4/")
        or relative in ALLOWED_HISTORICAL_EXACT
    )


def verify(root: Path) -> list[str]:
    errors: list[str] = []
    required = {
        "AERA_SPECIFICATION.md": (
            "AERA has no normative long-form expansion.",
            "AERA core predicate",
            "AERA reference runtime",
        ),
        "README.md": ("AERA is an unexpanded project identifier.",),
        "paper/v0.4.1/source/main.tex": ("a stable project identifier rather than a normative acronym expansion",),
    }
    for relative, snippets in required.items():
        path = root / relative
        if not path.is_file() or is_link_or_reparse(path):
            errors.append(f"missing or unsafe normative terminology file: {relative}")
            continue
        text = path.read_text(encoding="utf-8")
        for snippet in snippets:
            if snippet not in text:
                errors.append(f"canonical terminology missing: {relative}: {snippet}")

    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        relative_path = path.relative_to(root)
        if EXCLUDED_PARTS.intersection(relative_path.parts):
            continue
        relative = relative_path.as_posix()
        if is_link_or_reparse(path):
            errors.append(f"unsafe reparse or symlink in terminology scan: {relative}")
            continue
        text = path.read_text(encoding="utf-8", errors="strict")
        if historical_or_erratum(relative):
            continue
        for phrase in DEPRECATED_LONG_FORMS:
            if phrase in text:
                errors.append(f"deprecated AERA long form in active file: {relative}: {phrase}")
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="oasi-aera-terminology-") as temporary:
        root = Path(temporary)
        fixtures = {
            "AERA_SPECIFICATION.md": (
                "AERA has no normative long-form expansion.\n"
                "AERA core predicate\nAERA reference runtime\n"
            ),
            "README.md": "AERA is an unexpanded project identifier.\n",
            "paper/v0.4.1/source/main.tex": (
                "AERA is a stable project identifier rather than a normative acronym expansion.\n"
            ),
            "paper/v0.4/source/main.tex": DEPRECATED_LONG_FORMS[1] + "\n",
            "AERA_TERMINOLOGY_ERRATUM.md": " / ".join(DEPRECATED_LONG_FORMS) + "\n",
        }
        for relative, content in fixtures.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8", newline="\n")
        if verify(root):
            raise SystemExit("green terminology fixture was rejected")
        (root / "README_FR.md").write_text(DEPRECATED_LONG_FORMS[0] + "\n", encoding="utf-8")
        failures = verify(root)
        if len(failures) != 1 or "README_FR.md" not in failures[0]:
            raise SystemExit("red terminology fixture was not rejected exactly once")
    print(json.dumps({"status": "PASS_RED_GREEN_TERMINOLOGY_SELF_TEST"}, sort_keys=True))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    root = Path(args.root).resolve(strict=True)
    errors = verify(root)
    print(json.dumps({"errors": errors, "pass": not errors}, indent=2, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
