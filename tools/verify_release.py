#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
import unicodedata
from pathlib import Path, PurePosixPath

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
ARCHIVE_MODE = "--archive-mode" in sys.argv[2:]
EXCLUDED = {".git", "target", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
GENERATED_INDEXES = {"PUBLIC_MANIFEST.sha256", "PUBLIC_ALLOWLIST.txt"}
SBOM_EXCLUDED = GENERATED_INDEXES | {"SBOM.spdx.json", "LICENSE_INVENTORY.json"}
ERRORS: list[str] = []

REQUIRED_PUBLIC_ARTIFACTS = {
    "README.md", "README_FR.md", "OASI_PHILOSOPHY.md", "ARCHITECTURE.md",
    "AERA_SPECIFICATION.md", "CLAIMS_AND_EVIDENCE.md", "KNOWN_LIMITATIONS.md",
    "NEGATIVE_RESULTS.md", "SECURITY.md", "THREAT_MODEL.md", "REPRODUCIBILITY.md",
    "CONTRIBUTING.md", "AUTHORS.md", "AI_ASSISTED_DEVELOPMENT.md",
    "OWNER_RIGHTS_AND_PROVENANCE_DECLARATION.md", "AFFILIATION_STATEMENT.md",
    "LICENSING_DECISION.md",
    "THIRD_PARTY_NOTICES.md", "LICENSING.md", "COPYRIGHT.md", "CITATION.cff",
    "RELEASE_NOTES.md", "PUBLICATION_STATUS.md", "Cargo.toml", "Cargo.lock",
    "LICENSE", "LICENSES/Apache-2.0.txt", "LICENSES/MIT.txt",
    "LICENSES/CC-BY-4.0.txt", "LICENSE_INVENTORY.json", "SBOM.spdx.json",
    "paper/v0.3/OASI_SCIENTIFIC_ARTICLE_PREPRINT_V0_3.pdf",
    "paper/v0.3/CLAIMS_AND_EVIDENCE_V0_3.md", "paper/v0.3/LICENSE.md",
    "paper/v0.3/source/main.tex", "paper/v0.3/source/references.bib",
    "public_evidence/CLAIMS_EVIDENCE_LEDGER.json",
    "public_evidence/G039_G040_SUMMARY.json",
    "public_evidence/G116_METHOD_SUMMARY.json",
    "public_evidence/R3_ENGINEERING_SUMMARY.json",
    "public_evidence/T4_SCIENCE_SUMMARY.json",
    "public_evidence/SOURCE_PROVENANCE.json",
    "tools/build_article.ps1", "tools/build_article.sh",
}


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def strict_json(path: Path):
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_pairs)
    except Exception as exc:
        ERRORS.append(f"invalid strict JSON: {path.relative_to(ROOT).as_posix()}: {type(exc).__name__}")
        return {}


def public_files() -> list[Path]:
    return sorted(
        (
            path for path in ROOT.rglob("*")
            if path.is_file()
            and not EXCLUDED.intersection(path.relative_to(ROOT).parts)
            and path.name not in GENERATED_INDEXES
            and path.suffix not in {".pyc", ".pyo"}
        ),
        key=lambda path: path.relative_to(ROOT).as_posix(),
    )


def has_reparse_or_symlink(path: Path) -> bool:
    try:
        if path.is_symlink() or stat.S_ISLNK(os.lstat(path).st_mode):
            return True
        attributes = getattr(os.lstat(path), "st_file_attributes", 0)
        return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    except OSError:
        return True


files = public_files()
if ARCHIVE_MODE and (ROOT / ".git").exists():
    ERRORS.append("hidden Git history present in release archive")
observed_artifacts = {path.relative_to(ROOT).as_posix() for path in files}
for required in sorted(REQUIRED_PUBLIC_ARTIFACTS - observed_artifacts):
    ERRORS.append(f"required public artifact missing: {required}")

manifest_path = ROOT / "PUBLIC_MANIFEST.sha256"
allowlist_path = ROOT / "PUBLIC_ALLOWLIST.txt"
if not manifest_path.is_file() or not allowlist_path.is_file():
    ERRORS.append("manifest or allowlist missing")
else:
    observed = {path.relative_to(ROOT).as_posix(): digest(path) for path in files}
    manifest: dict[str, str] = {}
    for line in manifest_path.read_text(encoding="ascii").splitlines():
        parts = line.split("  ", 1)
        if len(parts) != 2 or not re.fullmatch(r"[0-9a-f]{64}", parts[0]):
            ERRORS.append("invalid manifest grammar")
            continue
        if parts[1] in manifest:
            ERRORS.append("duplicate manifest path")
        manifest[parts[1]] = parts[0]
    if manifest != observed:
        ERRORS.append("manifest does not equal observed public files")
    allowlist = allowlist_path.read_text(encoding="utf-8").splitlines()
    if allowlist != sorted(observed) or len(allowlist) != len(set(allowlist)):
        ERRORS.append("allowlist does not equal sorted unique public files")

portable_paths: list[str] = []
for path in files + [manifest_path, allowlist_path]:
    if not path.is_file():
        continue
    rel = path.relative_to(ROOT).as_posix()
    portable_paths.append(rel)
    pure = PurePosixPath(rel)
    if pure.is_absolute() or ".." in pure.parts or "\\" in rel:
        ERRORS.append(f"unsafe path: {rel}")
    checked = [path]
    parent = path.parent
    while parent != ROOT.parent:
        checked.append(parent)
        if parent == ROOT:
            break
        parent = parent.parent
    if any(has_reparse_or_symlink(item) for item in checked):
        ERRORS.append(f"symlink or reparse path: {rel}")

normalized = [unicodedata.normalize("NFC", rel).casefold() for rel in portable_paths]
if len(normalized) != len(set(normalized)):
    ERRORS.append("casefold or Unicode-normalization path collision")

patterns = {
    "windows_user_path": rb"[A-Za-z]:\\Users\\",
    "private_project_path": rb"(?i)(?:D:\\(?:OS|iascript)\\|/mnt/[cd]/)",
    "private_key": rb"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY",
    "live_secret": rb"(?i)(?:api[_-]?key|access[_-]?token|password|cookie)\s*[:=]\s*[^\s<]{8,}",
    "github_token": rb"(?i)\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b",
    "operational_authority": rb"(?i)(?:authorization_id|attempt_id|authority_receipt|consumption_receipt)\s*[:=]",
    "browser_conversation": rb"https://chatgpt\.com/c/",
    "private_conversation": b"(?i)(?:system" + b" message|assistant" + b" reasoning|conversation avec (?:chat" + b"gpt|gemini))",
}
email_re = re.compile(rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
allowed_emails = {b"mohammed.messaoudene@univ-temouchent.edu.dz"}
for path in files + [manifest_path, allowlist_path]:
    if not path.is_file():
        continue
    rel = path.relative_to(ROOT).as_posix()
    data = path.read_bytes()
    for name, pattern in patterns.items():
        if re.search(pattern, data):
            ERRORS.append(f"{name}: {rel}")
    for email in email_re.findall(data):
        if email.lower() not in allowed_emails:
            ERRORS.append(f"undeclared email: {rel}")

for candidate in files:
    if candidate.suffix.lower() == ".json":
        strict_json(candidate)

claims_path = ROOT / "public_evidence" / "CLAIMS_EVIDENCE_LEDGER.json"
if claims_path.is_file():
    claims = strict_json(claims_path)
    ids = [row.get("id") for row in claims.get("claims", [])]
    if not ids or len(ids) != len(set(ids)):
        ERRORS.append("claim IDs missing or duplicated")
    for row in claims.get("claims", []):
        for evidence in row.get("evidence", []):
            candidate = ROOT / evidence.get("path", "")
            if not candidate.is_file() or digest(candidate) != evidence.get("sha256"):
                ERRORS.append(f"claim evidence mismatch: {row.get('id')}")
else:
    ERRORS.append("claims ledger missing")

readme = (ROOT / "README.md").read_text(encoding="utf-8") if (ROOT / "README.md").is_file() else ""
mandatory = [
    "RESEARCH PROTOTYPE",
    "OASI COMPLETE SYSTEM: NOT DEMONSTRATED",
    "T4 SCIENTIFIC RESULT: NEGATIVE / CONSTRUCT-VALIDITY LIMITED",
    "AERA: BOUNDED USER-SPACE REFERENCE CONTRIBUTION",
    "NOT PRODUCTION READY",
    "NO GENERAL SUPERIORITY CLAIM",
    "NO DARPA, IEEE, UNIVERSITY, OR OTHER INSTITUTIONAL ENDORSEMENT",
]
for phrase in mandatory:
    if phrase not in readme:
        ERRORS.append(f"mandatory banner phrase missing: {phrase}")

joined_text = "\n".join(
    path.read_text(encoding="utf-8", errors="ignore")
    for path in files
    if path.suffix.lower() in {".md", ".txt", ".cff", ".json", ".toml", ".tex", ".bib"}
)
negative_markers = ("NOT ", "NO ", "NEVER ", "EXCLUDED", "FORBIDDEN", "NEGATIVE", "DOES NOT", "WITHOUT")
text_lines = joined_text.splitlines()
for phrase in (
    "OASI COMPLETE SYSTEM: DEMONSTRATED", "OASI IS CONSCIOUS",
    "OASI REPLACES WINDOWS", "OASI REPLACES LINUX",
    "GENERAL SUPERIORITY DEMONSTRATED", "DARPA VALIDATED", "IEEE VALIDATED",
    "G116 PRODUCTION CARRIER: VALIDATED",
):
    for line in text_lines:
        upper = line.upper()
        if phrase in upper and not any(marker in upper for marker in negative_markers):
            ERRORS.append(f"forbidden public claim: {phrase}")
            break
for pattern in (
    r"(?i)complete\s+OASI.{0,80}(?:demonstrated|established|validated|proven)",
    r"(?i)OASI.{0,80}(?:production[- ]ready|ready\s+for\s+production)",
    r"(?i)(?:general|universal).{0,40}superiority.{0,40}(?:demonstrated|proven|validated)",
):
    for line in text_lines:
        if re.search(pattern, line) and not any(marker in line.upper() for marker in negative_markers):
            ERRORS.append(f"inflated public claim pattern: {pattern}")
            break
if any(marker in joined_text for marker in ("TO_BE_RESERVED_OR_SET", "TO_BE_SET_AT_PUBLICATION")) or re.search(
    r"(?i)10\.5281/zenodo\.(?:todo|tbd|placeholder|x+)", joined_text
):
    ERRORS.append("unresolved DOI placeholder")

status_text = (ROOT / "PUBLICATION_STATUS.md").read_text(encoding="utf-8")
if "PASS_OWNER_REPRESENTATION_ACCEPTED_FOR_RELEASE" not in status_text:
    ERRORS.append("owner representation release status missing")
owner_path = ROOT / "OWNER_RIGHTS_AND_PROVENANCE_DECLARATION.md"
owner_text = owner_path.read_text(encoding="utf-8") if owner_path.is_file() else ""
for required in (
    "Mohammed Messaoudene", "personal research initiative", "personal computer",
    "No other human coauthor or code contributor", "not a judicial or institutional determination",
):
    if required not in owner_text:
        ERRORS.append(f"owner representation field missing: {required}")

# The owner declaration is a bounded representation, not permission to silently
# introduce a different human contributor in another active public document.
# Reject explicit contributor declarations so a conflict cannot be hidden by
# leaving the required owner sentence intact.
for text_path in files:
    if text_path.suffix.lower() not in {".md", ".txt", ".cff", ".json", ".toml", ".tex", ".bib"}:
        continue
    rel = text_path.relative_to(ROOT).as_posix()
    for line in text_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if re.match(
            r"(?i)^\s*(?:additional\s+human\s+contributor|human\s+co-?author|co-?author|contributor)\s*:",
            line,
        ):
            ERRORS.append(f"conflicting human contributor declaration: {rel}")
            break

g_summary = strict_json(ROOT / "public_evidence" / "G039_G040_SUMMARY.json")
if g_summary.get("g039", {}).get("status") != "TERMINAL_HOLD_G039_MANIFEST_FORMAT_INCOMPATIBLE_NO_REPLAY":
    ERRORS.append("G039 boundary changed")
g040 = g_summary.get("g040", {})
if g040.get("status") != "PASS_G040_PREPARED_ONLY_CLOSURE":
    ERRORS.append("G040 boundary changed")
for field in (
    "role_receipt_created", "execution_binding_created", "materialization_performed",
    "build_started", "qemu_started", "stage7_started",
    "performance_or_science_read", "production_or_publication",
):
    if g040.get(field) is not False:
        ERRORS.append(f"G040 forbidden effect asserted: {field}")

t4 = strict_json(ROOT / "public_evidence" / "T4_SCIENCE_SUMMARY.json")
for field, expected in {
    "scientific_verdict": "T4_CONSTRUCT_VALIDITY_FAILURE_CONFIRMED",
    "t4_result": "SCIENTIFIC_NEGATIVE_CONFIRMED",
    "mechanism_status": "MECHANISM_NOT_IDENTIFIED",
    "broad_oasi_claim": "NOT_REFUTED_AND_NOT_DEMONSTRATED",
    "t5_authorized": False,
    "t5_executed": False,
}.items():
    if t4.get(field) != expected:
        ERRORS.append(f"T4 boundary changed: {field}")

g116 = strict_json(ROOT / "public_evidence" / "G116_METHOD_SUMMARY.json")
if set(g116) != {
    "schema", "status", "source_scope", "declared_internal_catalogue",
    "reproduced_omitted_attack_classes", "bounded_conclusion", "non_claims",
}:
    ERRORS.append("G116 summary exact property set changed")
if g116.get("status") != "METHODOLOGICAL_EXAMPLE_ONLY":
    ERRORS.append("G116 methodological boundary missing")
for field, value in g116.get("non_claims", {}).items():
    if value is not False:
        ERRORS.append(f"G116 forbidden promotion: {field}")

inventory_path = ROOT / "LICENSE_INVENTORY.json"
inventory = strict_json(inventory_path)
if inventory.get("status") != "PASS_OWNER_REPRESENTATION_ACCEPTED_FOR_RELEASE":
    ERRORS.append("license inventory owner-representation status missing")
mapped = {row.get("path") for row in inventory.get("files", [])}
expected_inventory = {path.relative_to(ROOT).as_posix() for path in files if path.name != "LICENSE_INVENTORY.json"}
if mapped != expected_inventory:
    ERRORS.append("license inventory does not cover exact public file set")
for row in inventory.get("files", []):
    candidate = ROOT / row.get("path", "")
    if not candidate.is_file() or digest(candidate) != row.get("sha256"):
        ERRORS.append(f"license inventory hash mismatch: {row.get('path')}")

official_license_hashes = {
    "LICENSE": "074e6e32c86a4c0ef8b3ed25b721ca23aca83df277cd88106ef7177c354615ff",
    "LICENSES/Apache-2.0.txt": "074e6e32c86a4c0ef8b3ed25b721ca23aca83df277cd88106ef7177c354615ff",
    "LICENSES/MIT.txt": "b05785f9f18e6716bab63424b11454513b9943a222595b70411009202fc592b5",
    "LICENSES/CC-BY-4.0.txt": "9ba9550ad48438d0836ddab3da480b3b69ffa0aac7b7878b5a0039e7ab429411",
}
for rel, expected_hash in official_license_hashes.items():
    candidate = ROOT / rel
    if not candidate.is_file() or digest(candidate) != expected_hash:
        ERRORS.append(f"official license text mismatch: {rel}")

cargo_toml = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
if 'license = "Apache-2.0 OR MIT"' not in cargo_toml:
    ERRORS.append("historical Rust license expression changed")

sbom_path = ROOT / "SBOM.spdx.json"
sbom = strict_json(sbom_path)
sbom_files = {row.get("fileName", "").removeprefix("./") for row in sbom.get("files", [])}
expected_sbom = {path.relative_to(ROOT).as_posix() for path in files if path.name not in SBOM_EXCLUDED}
if sbom_files != expected_sbom:
    ERRORS.append("SBOM does not cover exact non-self-referential file set")
for row in sbom.get("files", []):
    rel = row.get("fileName", "").removeprefix("./")
    checksums = {item.get("algorithm"): item.get("checksumValue") for item in row.get("checksums", [])}
    candidate = ROOT / rel
    if not candidate.is_file() or checksums.get("SHA256") != digest(candidate):
        ERRORS.append(f"SBOM hash mismatch: {rel}")
versions = {row.get("name"): row.get("versionInfo") for row in sbom.get("packages", [])}
for name, version in {
    "OASI-AERA research preview": "0.1.0-research-preview",
    "Python": "3.11.9", "Rust": "1.97.1", "Cargo": "1.97.1",
    "Git for Windows": "2.55.0.windows.5", "MiKTeX-pdfTeX": "4.23", "Biber": "2.21",
}.items():
    if versions.get(name) != version:
        ERRORS.append(f"SBOM toolchain pin missing: {name} {version}")

cff = (ROOT / "CITATION.cff").read_text(encoding="utf-8")
for value in (
    "cff-version: 1.2.0", "0009-0007-4665-2548", "0.1.0-research-preview",
    "OASI: An Organismic Computing Architecture for Body-Bound Runtime Assurance and Developmental OS-AI Integration",
):
    if value not in cff:
        ERRORS.append(f"CITATION.cff field missing: {value}")

result = {"pass": not ERRORS, "files_checked": len(files), "errors": ERRORS}
print(json.dumps(result, indent=2, sort_keys=True))
raise SystemExit(0 if not ERRORS else 1)
