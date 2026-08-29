#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent).resolve()
EXCLUDED = {".git", "target", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
INDEXES = {"PUBLIC_MANIFEST.sha256", "PUBLIC_ALLOWLIST.txt"}


def sha(path: Path) -> str:
    h = hashlib.sha256()
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
            and path.name not in excluded
            and path.suffix not in {".pyc", ".pyo"}
        ),
        key=lambda path: path.relative_to(ROOT).as_posix(),
    )


def license_for(rel: str) -> str:
    if rel in {"LICENSE", "LICENSES/Apache-2.0.txt", "LICENSES/MIT.txt", "LICENSES/CC-BY-4.0.txt"}:
        return "LicenseRef-License-Document"
    if rel == "Cargo.lock" or rel == "Cargo.toml" or rel.startswith("src/") or rel.startswith("tests/"):
        return "Apache-2.0 OR MIT"
    if rel in {".gitattributes", ".gitignore", "SBOM.spdx.json"} or rel.startswith("tools/") or rel.startswith("schemas/"):
        return "Apache-2.0"
    return "CC-BY-4.0"


def write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")


claim_specs = [
    ("CL-001", "OASI is a research program for developmental OS-AI integration.", "Program definition.", "DEFINITION", ["OASI_PHILOSOPHY.md"], ["Not a completed system or scientific validation."]),
    ("CL-002", "The shipped Rust crate implements a bounded user-space AERA reference mechanism.", "Shipped source and finite public tests.", "REPRODUCED_LOCAL", ["Cargo.toml", "src/runtime.rs", "tests/authority_transaction.rs"], ["No kernel, hypervisor, hardware, production, or universal security claim."]),
    ("CL-003", "The tested design binds authority to body, epoch, generation, certificate, principal, resource, and action and revalidates it at commit.", "Finite user-space reference model.", "REPRODUCED_LOCAL", ["AERA_SPECIFICATION.md", "src/model.rs", "tests/authority_transaction.rs"], ["Not a formal proof for all environments."]),
    ("CL-004", "T4 produced a negative result: shared state alone did not establish decision superiority in the frozen task.", "Historical frozen T4 domain.", "VERIFIED_HISTORICAL_AUDIT", ["public_evidence/T4_SCIENCE_SUMMARY.json"], ["No general theorem about all organismic architectures."]),
    ("CL-005", "T4 had construct-validity limits and did not operationalize broad organismic non-separability.", "Historical causal/source audit.", "VERIFIED_HISTORICAL_AUDIT", ["public_evidence/T4_SCIENCE_SUMMARY.json"], ["Does not convert a negative result into positive OASI evidence."]),
    ("CL-006", "The broad OASI thesis remains neither demonstrated nor refuted.", "Inference from the bounded experimental design.", "BOUNDED_INFERENCE", ["public_evidence/T4_SCIENCE_SUMMARY.json", "KNOWN_LIMITATIONS.md"], ["No feasibility or superiority claim."]),
    ("CL-007", "G039 is immutable HOLD/NO-REPLAY history.", "Pinned G039/G040 report summary.", "PINNED_EVIDENCE", ["public_evidence/G039_G040_SUMMARY.json"], ["No repaired or replayed G039 claim."]),
    ("CL-008", "G040 is prepared-only technical closure.", "Pinned G040 report summary.", "PINNED_EVIDENCE", ["public_evidence/G039_G040_SUMMARY.json"], ["No build, QEMU, Stage 7, performance, science, production, or publication."]),
    ("CL-009", "A green internal gate catalogue can omit decisive adversarial cases.", "Sanitized G116 fixture-only methodological summary.", "INTERNALLY_REPRODUCED_METHOD", ["public_evidence/G116_METHOD_SUMMARY.json"], ["No carrier validation, real build, QEMU, production, or scientific-success claim."]),
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
        "checksums": [{"algorithm": "SHA256", "checksumValue": sha(path)}],
        "copyrightText": "NOASSERTION",
        "fileName": "./" + rel,
        "fileTypes": file_types,
        "licenseConcluded": license_for(rel),
        "licenseInfoInFiles": [license_for(rel)],
    })
    relationships.append({"relatedSpdxElement": spdx_id, "relationshipType": "CONTAINS", "spdxElementId": "SPDXRef-Package-OASI"})

packages = [
    {"SPDXID": "SPDXRef-Package-OASI", "copyrightText": "NOASSERTION", "downloadLocation": "NOASSERTION", "filesAnalyzed": True, "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION", "name": "OASI-AERA research preview", "versionInfo": "0.1.0-research-preview"},
]
for index, (name, version) in enumerate([
    ("Python", "3.11.9"), ("Rust", "1.97.1"), ("Cargo", "1.97.1"),
    ("Git for Windows", "2.55.0.windows.5"), ("MiKTeX-pdfTeX", "4.23"),
    ("Biber", "2.21"), ("Poppler-pdfinfo", "26.05.0"), ("Poppler-pdffonts", "24.04.0"),
], start=1):
    packages.append({"SPDXID": f"SPDXRef-Tool-{index:02d}", "copyrightText": "NOASSERTION", "downloadLocation": "NOASSERTION", "filesAnalyzed": False, "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION", "name": name, "versionInfo": version})

write_json(ROOT / "SBOM.spdx.json", {
    "SPDXID": "SPDXRef-DOCUMENT",
    "creationInfo": {"created": "2026-08-28T00:00:00Z", "creators": ["Tool: OASI deterministic metadata builder"]},
    "dataLicense": "CC0-1.0",
    "documentNamespace": "https://spdx.org/spdxdocs/oasi-aera-v0.1.0-research-preview-local-candidate",
    "files": spdx_rows,
    "name": "OASI-AERA-v0.1.0-research-preview-SBOM",
    "packages": packages,
    "relationships": relationships,
    "spdxVersion": "SPDX-2.3",
})

inventory_files = all_files({"LICENSE_INVENTORY.json"})
inventory = []
for path in inventory_files:
    rel = path.relative_to(ROOT).as_posix()
    provenance = "verified historical source" if rel == "Cargo.lock" or rel == "Cargo.toml" or rel.startswith("src/") or rel.startswith("tests/") else "v0.3 article input" if rel.startswith("paper/v0.3/") else "publication candidate"
    inventory.append({"copyright": "NOASSERTION", "license": license_for(rel), "path": rel, "provenance": provenance, "sha256": sha(path)})
write_json(ROOT / "LICENSE_INVENTORY.json", {
    "files": inventory,
    "git_dependencies": [],
    "preferred_future_code_license": "AGPL-3.0-only optional for a future clean-slate generation after a fresh chain-of-title and compatibility audit",
    "registry_dependencies": [],
    "schema": "oasi.public.license-inventory.v2",
    "status": "PASS_OWNER_REPRESENTATION_ACCEPTED_FOR_RELEASE",
    "third_party_source_vendored": False,
})

manifest_files = all_files()
relative = [path.relative_to(ROOT).as_posix() for path in manifest_files]
(ROOT / "PUBLIC_ALLOWLIST.txt").write_text("\n".join(relative) + "\n", encoding="utf-8", newline="\n")
(ROOT / "PUBLIC_MANIFEST.sha256").write_text("".join(f"{sha(path)}  {path.relative_to(ROOT).as_posix()}\n" for path in manifest_files), encoding="ascii", newline="\n")
print(json.dumps({"files": len(manifest_files), "manifest_sha256": sha(ROOT / "PUBLIC_MANIFEST.sha256"), "sbom_files": len(sbom_files)}, sort_keys=True))
