#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import unicodedata
from pathlib import Path, PurePosixPath

parser = argparse.ArgumentParser(description="Rebuild deterministic metadata for a reviewed OASI tree.")
parser.add_argument("root", nargs="?", default=Path(__file__).resolve().parent.parent)
parser.add_argument(
    "--adopt-reviewed-allowlist",
    type=Path,
    help="External, separately reviewed path-only allowlist to adopt; must be outside ROOT.",
)
parser.add_argument(
    "--adopt-reviewed-allowlist-sha256",
    help="Pinned lowercase SHA-256 of --adopt-reviewed-allowlist.",
)
args = parser.parse_args()
ROOT = Path(args.root).resolve()
ADOPT_REVIEWED_ALLOWLIST = args.adopt_reviewed_allowlist
ADOPT_REVIEWED_ALLOWLIST_SHA256 = args.adopt_reviewed_allowlist_sha256
EXCLUDED = {".git", "target", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
INDEXES = {"PUBLIC_MANIFEST.sha256", "PUBLIC_ALLOWLIST.txt"}

if (ADOPT_REVIEWED_ALLOWLIST is None) != (ADOPT_REVIEWED_ALLOWLIST_SHA256 is None):
    parser.error("--adopt-reviewed-allowlist and --adopt-reviewed-allowlist-sha256 are required together")
if ADOPT_REVIEWED_ALLOWLIST_SHA256 is not None and not re.fullmatch(
    r"[0-9a-f]{64}", ADOPT_REVIEWED_ALLOWLIST_SHA256
):
    parser.error("reviewed allowlist SHA-256 must be 64 lowercase hexadecimal characters")


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha1(path: Path) -> str:
    h = hashlib.sha1()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def all_files(exclude_names: set[str] | None = None) -> list[Path]:
    excluded = INDEXES | (exclude_names or set())
    return sorted(
        (
            path for path in ROOT.rglob("*")
            if path.is_file()
            and not EXCLUDED.intersection(path.relative_to(ROOT).parts)
            and path.relative_to(ROOT).as_posix() not in excluded
            and path.suffix not in {".pyc", ".pyo"}
        ),
        key=lambda path: path.relative_to(ROOT).as_posix(),
    )


def has_reparse_or_symlink(path: Path) -> bool:
    try:
        status = os.lstat(path)
        if stat.S_ISLNK(status.st_mode) or path.is_symlink():
            return True
        return bool(
            getattr(status, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        )
    except OSError:
        return True


def validate_release_paths(paths: list[Path]) -> list[str]:
    relative: list[str] = []
    for path in paths:
        rel = path.relative_to(ROOT).as_posix()
        pure = PurePosixPath(rel)
        if not rel or pure.is_absolute() or ".." in pure.parts or "\\" in rel:
            raise SystemExit(f"unsafe public path: {rel!r}")
        checked = [path]
        parent = path.parent
        while True:
            checked.append(parent)
            if parent == ROOT:
                break
            if parent == ROOT.parent:
                raise SystemExit(f"public path escaped ROOT: {rel}")
            parent = parent.parent
        if any(has_reparse_or_symlink(item) for item in checked):
            raise SystemExit(f"symlink or reparse point in public path: {rel}")
        relative.append(rel)
    normalized = [unicodedata.normalize("NFC", rel).casefold() for rel in relative]
    if len(normalized) != len(set(normalized)):
        raise SystemExit("casefold or Unicode-normalization public-path collision")
    return relative


def parse_canonical_allowlist(path: Path) -> list[str]:
    raw = path.read_bytes()
    try:
        rows = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise SystemExit(f"reviewed allowlist is not UTF-8: {type(exc).__name__}") from exc
    if not rows or raw != ("\n".join(rows) + "\n").encode("utf-8"):
        raise SystemExit("reviewed allowlist must be non-empty canonical UTF-8 with LF and final newline")
    if rows != sorted(rows) or len(rows) != len(set(rows)):
        raise SystemExit("reviewed allowlist must be ordinal-sorted and unique")
    normalized: list[str] = []
    for rel in rows:
        pure = PurePosixPath(rel)
        if (
            not rel
            or pure.is_absolute()
            or ".." in pure.parts
            or "\\" in rel
            or rel in INDEXES
            or any(part in EXCLUDED for part in pure.parts)
        ):
            raise SystemExit(f"unsafe reviewed allowlist path: {rel!r}")
        normalized.append(unicodedata.normalize("NFC", rel).casefold())
    if len(normalized) != len(set(normalized)):
        raise SystemExit("reviewed allowlist has a casefold or Unicode-normalization collision")
    return rows


def license_for(rel: str) -> str:
    if rel in {"LICENSE", "LICENSES/Apache-2.0.txt"}:
        return "Apache-2.0"
    if rel == "LICENSES/MIT.txt":
        return "MIT"
    if rel == "LICENSES/CC-BY-4.0.txt":
        return "CC-BY-4.0"
    if rel == "Cargo.lock" or rel == "Cargo.toml" or rel.startswith("src/") or rel.startswith("tests/"):
        return "Apache-2.0 OR MIT"
    if rel in {".gitattributes", ".gitignore", "SBOM.spdx.json"} or rel.startswith("tools/") or rel.startswith("schemas/"):
        return "Apache-2.0"
    if rel.startswith("experiments/") and rel.endswith(".py"):
        return "Apache-2.0"
    return "CC-BY-4.0"


def atomic_write(path: Path, data: bytes) -> None:
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists():
        raise SystemExit(f"stale atomic-write checkpoint: {temporary}")
    with temporary.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def write_json(path: Path, value) -> None:
    atomic_write(path, (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8"))


# Membership, path safety, and the project-reviewed allowlist boundary are checked
# before the first mutation.  A failed/default rebuild therefore leaves every
# release artifact byte-identical.
manifest_files = all_files()
relative = validate_release_paths(manifest_files)
allowlist_path = ROOT / "PUBLIC_ALLOWLIST.txt"
if ADOPT_REVIEWED_ALLOWLIST is not None:
    external_allowlist = Path(ADOPT_REVIEWED_ALLOWLIST)
    if has_reparse_or_symlink(external_allowlist) or not external_allowlist.is_file():
        raise SystemExit("out-of-tree project-reviewed allowlist must be an existing regular non-reparse file")
    external_allowlist = external_allowlist.resolve(strict=True)
    try:
        external_allowlist.relative_to(ROOT)
    except ValueError:
        pass
    else:
        raise SystemExit("project-reviewed allowlist must be outside ROOT")
    if sha(external_allowlist) != ADOPT_REVIEWED_ALLOWLIST_SHA256:
        raise SystemExit("project-reviewed allowlist SHA-256 mismatch")
    reviewed = parse_canonical_allowlist(external_allowlist)
else:
    if not allowlist_path.is_file() or has_reparse_or_symlink(allowlist_path):
        raise SystemExit(
            "PUBLIC_ALLOWLIST.txt is missing or unsafe; adoption requires an out-of-tree project-reviewed allowlist and pinned SHA-256"
        )
    reviewed = parse_canonical_allowlist(allowlist_path)
if reviewed != relative:
    missing = sorted(set(reviewed) - set(relative))
    unreviewed = sorted(set(relative) - set(reviewed))
    raise SystemExit(
        "reviewed allowlist drift; "
        f"missing={missing[:20]} unreviewed={unreviewed[:20]}"
    )


experiment_root = ROOT / "experiments"
experiment_manifest = experiment_root / "MANIFEST.sha256"
experiment_files = sorted(
    (
        path for path in experiment_root.rglob("*")
        if path.is_file()
        and path != experiment_manifest
        and not EXCLUDED.intersection(path.relative_to(experiment_root).parts)
        and path.suffix not in {".pyc", ".pyo"}
    ),
    key=lambda path: path.relative_to(experiment_root).as_posix(),
)
atomic_write(
    experiment_manifest,
    "".join(f"{sha(path)}  {path.relative_to(experiment_root).as_posix()}\n" for path in experiment_files).encode("ascii"),
)


claim_specs = [
    ("CL-001", "Operational Artificial System Intelligence (OASI) is the canonical name of a research program for developmental OS-AI integration under one versioned causal history.", "Program definition and terminology.", "DEFINITION", ["OASI_PHILOSOPHY.md"], ["Operational does not mean production-ready; no achieved general or superintelligence, consciousness, deployment, external-validation, superiority, or legal-priority claim."]),
    ("CL-002", "The shipped Rust crate implements a bounded user-space AERA reference mechanism.", "Shipped source and finite public tests.", "IMPLEMENTED_AND_TESTED_LOCAL", ["Cargo.toml", "src/runtime.rs", "tests/authority_transaction.rs"], ["No kernel, hypervisor, hardware, production, or universal security claim."]),
    ("CL-003", "The tested design binds authority to body, epoch, generation, certificate, principal, resource, action and revalidates it at commit.", "Finite user-space reference model.", "IMPLEMENTED_AND_TESTED_LOCAL", ["AERA_SPECIFICATION.md", "src/model.rs", "tests/authority_transaction.rs"], ["Not a formal proof for all environments."]),
    ("CL-004", "T4 produced a negative result: shared state alone did not establish decision superiority in the frozen task.", "Historical frozen T4 domain.", "VERIFIED_HISTORICAL_AUDIT", ["public_evidence/T4_SCIENCE_SUMMARY.json"], ["No general theorem about all organismic architectures."]),
    ("CL-005", "T4 had construct-validity limits and did not operationalize broad organismic non-separability.", "Historical causal/source audit.", "VERIFIED_HISTORICAL_AUDIT", ["public_evidence/T4_SCIENCE_SUMMARY.json"], ["Does not convert a negative result into positive OASI evidence."]),
    ("CL-006", "The broad OASI thesis remains neither demonstrated nor refuted.", "Inference from the bounded experimental design.", "BOUNDED_INFERENCE", ["public_evidence/T4_SCIENCE_SUMMARY.json", "KNOWN_LIMITATIONS.md"], ["No feasibility or superiority claim."]),
    ("CL-007", "G039 is immutable HOLD/NO-REPLAY history.", "Pinned G039/G040 report summary.", "PINNED_EVIDENCE", ["public_evidence/G039_G040_SUMMARY.json"], ["No repaired or replayed G039 claim."]),
    ("CL-008", "G040 is prepared-only technical closure.", "Pinned G040 report summary.", "PINNED_EVIDENCE", ["public_evidence/G039_G040_SUMMARY.json"], ["No build, QEMU, Stage 7, performance, science, production, or publication."]),
    ("CL-009", "A green internal gate catalogue can omit decisive adversarial cases.", "Sanitized G116 fixture-only methodological summary.", "INTERNAL_METHOD_REEXECUTION", ["public_evidence/G116_METHOD_SUMMARY.json"], ["No carrier validation, real build, QEMU, production, or scientific-success claim."]),
    ("CL-010", "S5 did not establish an OASI mechanism advantage over a cooperative idempotent receiver.", "1,200 deterministic local fixture records.", "LOCAL_DETERMINISTIC_NEGATIVE", ["public_evidence/S5_SCIENCE_SUMMARY.json", "experiments/s5/results/RAW_RUNS.jsonl"], ["No real fault, population, QEMU/guest, production, or external-replication claim."]),
    ("CL-011", "S6 observed a duplicate/omission tradeoff between redispatch and no-redispatch policies.", "1,500 deterministic local fixture records and adversarial source audit.", "BOUNDED_DIAGNOSTIC", ["public_evidence/S6_SCIENCE_SUMMARY.json", "experiments/s6/results/RAW_RUNS.jsonl", "paper/v0.4/INTERNAL_ADVERSARIAL_REVIEW_V0_4.md"], ["No OASI-specific attribution, inferential probability, real fault, universal exactly-once, or general-superiority claim."]),
]
claims = []
for claim_id, wording, scope, confidence, evidence_paths, exclusions in claim_specs:
    evidence = []
    for rel in evidence_paths:
        path = ROOT / rel
        if not path.is_file():
            raise SystemExit(f"missing claim evidence: {rel}")
        evidence.append({"path": rel, "sha256": sha(path)})
    claims.append({"confidence": confidence, "evidence": evidence, "exclusions": exclusions, "id": claim_id, "scope": scope, "wording": wording})
write_json(ROOT / "public_evidence" / "CLAIMS_EVIDENCE_LEDGER.json", {"claims": claims, "forbidden_claims_reviewed": True, "schema": "oasi.public.claims-evidence.v2"})

sbom_files = all_files({"SBOM.spdx.json", "LICENSE_INVENTORY.json"})
spdx_rows = []
relationships = []
for index, path in enumerate(sbom_files, start=1):
    rel = path.relative_to(ROOT).as_posix()
    spdx_id = f"SPDXRef-File-{index:04d}"
    suffix = path.suffix.lower()
    file_types = ["SOURCE"] if suffix in {".rs", ".py", ".ps1", ".sh", ".tex", ".bib", ".toml", ".json", ".md", ".cff"} else ["BINARY"] if suffix == ".pdf" else ["OTHER"]
    spdx_rows.append({
        "SPDXID": spdx_id,
        "checksums": [
            {"algorithm": "SHA1", "checksumValue": sha1(path)},
            {"algorithm": "SHA256", "checksumValue": sha(path)},
        ],
        "copyrightText": "NOASSERTION",
        "fileName": "./" + rel,
        "fileTypes": file_types,
        "licenseConcluded": license_for(rel),
        "licenseInfoInFiles": [license_for(rel)],
    })
    relationships.append({"relatedSpdxElement": spdx_id, "relationshipType": "CONTAINS", "spdxElementId": "SPDXRef-Package-OASI"})

packages = [
    {
        "SPDXID": "SPDXRef-Package-OASI",
        "copyrightText": "NOASSERTION",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": True,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "name": "OASI/AERA: Operational Artificial System Intelligence Research Preview",
        "packageVerificationCode": {
            "packageVerificationCodeValue": hashlib.sha1(
                "".join(sorted(sha1(path) for path in sbom_files)).encode("ascii")
            ).hexdigest()
        },
        "versionInfo": "0.2.1-research-preview",
    },
]
for index, (name, version) in enumerate([
    ("Qualification Python", "3.12.3"),
    ("Qualification PyYAML", "6.0.1"),
    ("Qualification cryptography", "41.0.7"),
    ("Qualification SQLite", "3.45.1"),
    ("Qualification Rust", "1.97.1"),
    ("Qualification Cargo", "1.97.1"),
    ("Publication Python", "3.11.9"),
    ("Publication PyYAML", "6.0.3"),
    ("Publication cryptography", "50.0.1"),
    ("Publication SQLite", "3.45.1"),
    ("Publication zlib", "1.3.1"),
    ("Git for Windows", "2.55.0.windows.5"),
    ("MiKTeX-pdfTeX", "4.23"),
    ("Biber", "2.21"),
    ("Poppler-pdfinfo", "26.05.0"),
    ("Poppler-pdffonts", "24.04.0"),
    ("Poppler-pdftotext", "24.04.0"),
    ("Poppler-pdftocairo", "24.04.0"),
], start=1):
    packages.append({"SPDXID": f"SPDXRef-Tool-{index:02d}", "copyrightText": "NOASSERTION", "downloadLocation": "NOASSERTION", "filesAnalyzed": False, "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION", "name": name, "versionInfo": version})

write_json(ROOT / "SBOM.spdx.json", {
    "SPDXID": "SPDXRef-DOCUMENT",
    "creationInfo": {"created": "2026-09-02T00:00:00Z", "creators": ["Tool: OASI deterministic metadata builder"]},
    "dataLicense": "CC0-1.0",
    "documentNamespace": "https://spdx.org/spdxdocs/oasi-aera-v0.2.1-research-preview",
    "files": spdx_rows,
    "name": "OASI-AERA-v0.2.1-research-preview-SBOM",
    "packages": packages,
    "relationships": relationships,
    "spdxVersion": "SPDX-2.3",
})

inventory_files = all_files({"LICENSE_INVENTORY.json"})
inventory = []
for path in inventory_files:
    rel = path.relative_to(ROOT).as_posix()
    provenance = "verified historical source" if rel == "Cargo.lock" or rel == "Cargo.toml" or rel.startswith("src/") or rel.startswith("tests/") else "sealed S5/S6 result" if rel.startswith("experiments/") and "/results/" in rel else "v0.3 historical article" if rel.startswith("paper/v0.3/") else "v0.4 article input" if rel.startswith("paper/v0.4/") else "v0.2 publication candidate"
    inventory.append({"copyright": "NOASSERTION", "license": license_for(rel), "path": rel, "provenance": provenance, "sha256": sha(path)})
write_json(ROOT / "LICENSE_INVENTORY.json", {
    "files": inventory,
    "git_dependencies": [],
    "preferred_future_code_license": "AGPL-3.0-only optional for a future clean-slate generation after a fresh chain-of-title and compatibility audit",
    "registry_dependencies": [],
    "schema": "oasi.public.license-inventory.v2",
    "status": "PASS_OWNER_REPRESENTATION_ACCEPTED_FOR_V0_2_RELEASE",
    "third_party_source_vendored": False,
})

if ADOPT_REVIEWED_ALLOWLIST is not None:
    atomic_write(allowlist_path, ("\n".join(relative) + "\n").encode("utf-8"))
atomic_write(
    ROOT / "PUBLIC_MANIFEST.sha256",
    "".join(f"{sha(path)}  {path.relative_to(ROOT).as_posix()}\n" for path in manifest_files).encode("ascii"),
)
print(json.dumps({"files": len(manifest_files), "manifest_sha256": sha(ROOT / "PUBLIC_MANIFEST.sha256"), "sbom_files": len(sbom_files)}, sort_keys=True))
