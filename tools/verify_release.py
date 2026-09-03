#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import unicodedata
from pathlib import Path, PurePosixPath

try:
    import yaml
except ImportError as exc:
    raise SystemExit("PyYAML is required for structured CITATION.cff validation") from exc

parser = argparse.ArgumentParser(description="Verify the bounded OASI public release tree.")
parser.add_argument("root", nargs="?", default=".")
parser.add_argument("--archive-mode", action="store_true")
parser.add_argument("--expected-software-doi")
parser.add_argument("--expected-article-doi")
phase = parser.add_mutually_exclusive_group(required=True)
phase.add_argument(
    "--pre-doi",
    action="store_true",
    help="Require DOI fields to be absent before Zenodo reservation instead of requiring current DOI values.",
)
phase.add_argument(
    "--post-doi",
    action="store_true",
    help="Require the final, distinct software and article DOI records.",
)
args = parser.parse_args()
ROOT = Path(args.root).resolve()
ARCHIVE_MODE = args.archive_mode
PRE_DOI = args.pre_doi
EXCLUDED = {".git", "target", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
GENERATED_INDEXES = {"PUBLIC_MANIFEST.sha256", "PUBLIC_ALLOWLIST.txt"}
SBOM_EXCLUDED = GENERATED_INDEXES | {"SBOM.spdx.json", "LICENSE_INVENTORY.json"}
ERRORS: list[str] = []
HISTORICAL_DOIS = {
    "10.5281/zenodo.22151556",
    "10.5281/zenodo.22151560",
    "10.5281/zenodo.22262138",
    "10.5281/zenodo.22262143",
}
DOI_RE = re.compile(r"10\.5281/zenodo\.[0-9]+")
if PRE_DOI:
    if args.expected_software_doi is not None or args.expected_article_doi is not None:
        parser.error("DOI pins are forbidden in --pre-doi mode")
else:
    if args.expected_software_doi is None or args.expected_article_doi is None:
        parser.error("--post-doi requires both external expected DOI pins")
    for label, value in (
        ("software", args.expected_software_doi),
        ("article", args.expected_article_doi),
    ):
        if DOI_RE.fullmatch(value) is None or value in HISTORICAL_DOIS:
            parser.error(f"invalid or historical expected {label} DOI pin")
    if args.expected_software_doi == args.expected_article_doi:
        parser.error("expected software and article DOI pins must be distinct")

ARTICLE_PDF_REL = "paper/v0.4.1/OASI_SCIENTIFIC_ARTICLE_PREPRINT_V0_4_1.pdf"
ARTICLE_SOURCE_MANIFEST_REL = "paper/v0.4.1/ARTICLE_SOURCE_MANIFEST.sha256"
ARTICLE_BUILD_RECEIPT_REL = "paper/v0.4.1/BUILD_RECEIPT.json"
ARTICLE_BUILD_DEFINITION_RELS = (
    "tools/build_article_v0_4_1.ps1",
    "tools/build_article_v0_4_1.sh",
    "tools/build_article_v0_4_1_verified.py",
)
ARTICLE_FIGURE_NAMES = (
    "fig1_layered_vs_organismic",
    "fig2_cognition_reflex_aera",
    "fig3_authority_lifecycle",
    "fig4_evidence_ladder",
)
ARTICLE_SOURCE_RELS = tuple(sorted((
    "paper/v0.4.1/source/main.tex",
    "paper/v0.4.1/source/references.bib",
    *(f"paper/v0.4.1/source/figures/{name}.tex" for name in ARTICLE_FIGURE_NAMES),
)))
ARTICLE_PROMOTED_RELS = tuple(sorted((
    ARTICLE_PDF_REL,
    *(
        f"paper/v0.4.1/source/figures/{name}.{suffix}"
        for name in ARTICLE_FIGURE_NAMES
        for suffix in ("pdf", "svg")
    ),
)))
EXPECTED_ARTICLE_TOOLCHAIN = {
    "biber": "biber version: 2.21",
    "pdffonts": "pdffonts version 24.04.0",
    "pdfinfo": "pdfinfo version 26.05.0",
    "pdflatex": "MiKTeX-pdfTeX 4.23 (MiKTeX 25.12)",
    "pdftocairo": "pdftocairo version 24.04.0",
    "pdftotext": "pdftotext version 24.04.0",
    "python": "3.11.9",
}
ARTICLE_PACKAGE_WARNING = "Package epstopdf Warning: Shell escape feature is not enabled."
FIGURE_PACKAGE_WARNING = "Package shellesc Warning: Shell escape disabled on input line 73."

REQUIRED_PUBLIC_ARTIFACTS = {
    "README.md", "README_FR.md", "OASI_PHILOSOPHY.md", "ARCHITECTURE.md",
    "AERA_SPECIFICATION.md", "AERA_TERMINOLOGY_ERRATUM.md",
    "CLAIMS_AND_EVIDENCE.md", "KNOWN_LIMITATIONS.md",
    "NEGATIVE_RESULTS.md", "SECURITY.md", "THREAT_MODEL.md", "REPRODUCIBILITY.md",
    "INDEPENDENT_REPRODUCTION.md",
    "CONTRIBUTING.md", "AUTHORS.md", "AI_ASSISTED_DEVELOPMENT.md",
    "OWNER_RIGHTS_AND_PROVENANCE_DECLARATION.md", "AFFILIATION_STATEMENT.md",
    "LICENSING_DECISION.md", "V0_2_PROVENANCE_ADDENDUM.md",
    "THIRD_PARTY_NOTICES.md", "LICENSING.md", "COPYRIGHT.md", "CITATION.cff",
    "RELEASE_NOTES.md", "PUBLICATION_STATUS.md", "TOOLCHAIN_PROVENANCE.json",
    "Cargo.toml", "Cargo.lock",
    "LICENSE", "LICENSES/Apache-2.0.txt", "LICENSES/MIT.txt",
    "LICENSES/CC-BY-4.0.txt", "LICENSE_INVENTORY.json", "SBOM.spdx.json",
    "paper/v0.3/OASI_SCIENTIFIC_ARTICLE_PREPRINT_V0_3.pdf",
    "paper/v0.3/CLAIMS_AND_EVIDENCE_V0_3.md", "paper/v0.3/LICENSE.md",
    "paper/v0.3/source/main.tex", "paper/v0.3/source/references.bib",
    "paper/v0.4/OASI_SCIENTIFIC_ARTICLE_PREPRINT_V0_4.pdf",
    "paper/v0.4/ARTICLE_SOURCE_MANIFEST.sha256",
    "paper/v0.4/BUILD_RECEIPT.json",
    "paper/v0.4/CLAIMS_AND_EVIDENCE_V0_4.md", "paper/v0.4/LICENSE.md",
    "paper/v0.4/INTERNAL_ADVERSARIAL_REVIEW_V0_4.md",
    "paper/v0.4/RESPONSE_TO_INTERNAL_ADVERSARIAL_REVIEW_V0_4.md",
    "paper/v0.4/source/main.tex", "paper/v0.4/source/references.bib",
    "paper/v0.4.1/OASI_SCIENTIFIC_ARTICLE_PREPRINT_V0_4_1.pdf",
    "paper/v0.4.1/ARTICLE_SOURCE_MANIFEST.sha256",
    "paper/v0.4.1/BUILD_RECEIPT.json",
    "paper/v0.4.1/ABSTRACT_FR.md", "paper/v0.4.1/README.md",
    "paper/v0.4.1/CLAIMS_AND_EVIDENCE_V0_4_1.md",
    "paper/v0.4.1/CORRIGENDUM_V0_4_1.md", "paper/v0.4.1/LICENSE.md",
    "paper/v0.4.1/source/main.tex", "paper/v0.4.1/source/references.bib",
    "SCIENTIFIC_RESULTS_S5_S6.md",
    "experiments/README.md", "experiments/LICENSE.md",
    "experiments/ENVIRONMENT.json", "experiments/DATA_DICTIONARY.md",
    "experiments/EXECUTED_SOURCE_PINS.json", "experiments/MANIFEST.sha256",
    "experiments/INTERPRETATION_NOTICE.md", "experiments/QUALIFICATION.md",
    "experiments/QUALIFICATION_RECEIPT.json",
    "experiments/common/oasi_broker.py",
    "experiments/s5/experiment.py", "experiments/s5/verify_results.py",
    "experiments/s5/red_green_verifier_test.py", "experiments/s5/PROTOCOL.md",
    "experiments/s5/TEST_EVIDENCE.md", "experiments/s5/tests/test_experiment.py",
    "experiments/s5/results/CAMPAIGN_CHECKPOINT.json",
    "experiments/s5/results/INDEPENDENT_VERIFY_RESULT.json",
    "experiments/s5/results/PREREGISTRATION_LOCKED.md",
    "experiments/s5/results/RAW_RUNS.jsonl", "experiments/s5/results/SUMMARY.json",
    "experiments/s5/results/SCIENTIFIC_REPORT.md",
    "experiments/s5/results/RESULT_MANIFEST.sha256",
    "experiments/s6/experiment.py", "experiments/s6/verify_results.py",
    "experiments/s6/red_green_verifier_test.py", "experiments/s6/PROTOCOL.md",
    "experiments/s6/TEST_EVIDENCE.md", "experiments/s6/tests/test_experiment.py",
    "experiments/s6/results/CAMPAIGN_CHECKPOINT.json",
    "experiments/s6/results/INDEPENDENT_VERIFY_RESULT.json",
    "experiments/s6/results/PREREGISTRATION_LOCKED.md",
    "experiments/s6/results/RAW_RUNS.jsonl", "experiments/s6/results/SUMMARY.json",
    "experiments/s6/results/SCIENTIFIC_REPORT.md",
    "experiments/s6/results/RESULT_MANIFEST.sha256",
    "public_evidence/CLAIMS_EVIDENCE_LEDGER.json",
    "public_evidence/G039_G040_SUMMARY.json",
    "public_evidence/G116_METHOD_SUMMARY.json",
    "public_evidence/R3_ENGINEERING_SUMMARY.json",
    "public_evidence/T4_SCIENCE_SUMMARY.json",
    "public_evidence/S5_SCIENCE_SUMMARY.json",
    "public_evidence/S6_SCIENCE_SUMMARY.json",
    "public_evidence/SOURCE_PROVENANCE.json",
    "schemas/claim.schema.json",
    "tools/build_article.ps1", "tools/build_article.sh", "tools/build_article_verified.py",
    "tools/build_article_v0_4_1.ps1", "tools/build_article_v0_4_1.sh",
    "tools/build_article_v0_4_1_verified.py", "tools/verify_aera_terminology.py",
    "tools/build_deterministic_zip.py", "tools/compare_experiment_categories.py",
    "tools/rebuild_release_metadata.py", "tools/run_tests.ps1", "tools/run_tests.sh",
    "tools/verify_archive.py", "tools/verify_experiments.py", "tools/verify_release.py",
}


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def digest_sha1(path: Path) -> str:
    h = hashlib.sha1()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def license_for(rel: str) -> str:
    if rel in {"LICENSE", "LICENSES/Apache-2.0.txt"}:
        return "Apache-2.0"
    if rel == "LICENSES/MIT.txt":
        return "MIT"
    if rel == "LICENSES/CC-BY-4.0.txt":
        return "CC-BY-4.0"
    if rel in {"Cargo.lock", "Cargo.toml"} or rel.startswith("src/") or rel.startswith("tests/"):
        return "Apache-2.0 OR MIT"
    if rel in {".gitattributes", ".gitignore", "SBOM.spdx.json"} or rel.startswith("tools/") or rel.startswith("schemas/"):
        return "Apache-2.0"
    if rel.startswith("experiments/") and rel.endswith(".py"):
        return "Apache-2.0"
    return "CC-BY-4.0"


def provenance_for(rel: str) -> str:
    if rel in {"Cargo.lock", "Cargo.toml"} or rel.startswith("src/") or rel.startswith("tests/"):
        return "verified historical source"
    if rel.startswith("experiments/") and "/results/" in rel:
        return "sealed S5/S6 result"
    if rel.startswith("paper/v0.3/"):
        return "v0.3 historical article"
    if rel.startswith("paper/v0.4/"):
        return "v0.4 historical article"
    if rel.startswith("paper/v0.4.1/"):
        return "v0.4.1 terminology-corrected article input"
    return "v0.2.2 publication candidate"


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


def resolve_local_json_pointer(root_schema: object, reference: str) -> object | None:
    if not reference.startswith("#/"):
        return None
    current = root_schema
    for raw_part in reference[2:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def json_schema_violations(
    value: object,
    schema: object,
    root_schema: object,
    location: str,
) -> list[str]:
    """Validate the dependency-free JSON-Schema subset used by claim.schema.json."""
    if not isinstance(schema, dict):
        return [f"{location}: schema node is not an object"]
    if "$ref" in schema:
        reference = schema["$ref"]
        target = resolve_local_json_pointer(root_schema, reference) if isinstance(reference, str) else None
        if target is None:
            return [f"{location}: unresolved local schema reference"]
        return json_schema_violations(value, target, root_schema, location)

    violations: list[str] = []
    expected_type = schema.get("type")
    type_matches = {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
        "null": value is None,
    }
    if isinstance(expected_type, str) and not type_matches.get(expected_type, False):
        return [f"{location}: expected type {expected_type}"]

    if "enum" in schema and value not in schema["enum"]:
        violations.append(f"{location}: value outside enum")

    if isinstance(value, str):
        minimum = schema.get("minLength")
        if isinstance(minimum, int) and len(value) < minimum:
            violations.append(f"{location}: string shorter than minLength")
        pattern = schema.get("pattern")
        if isinstance(pattern, str) and re.search(pattern, value) is None:
            violations.append(f"{location}: string does not match pattern")

    if isinstance(value, list):
        minimum = schema.get("minItems")
        if isinstance(minimum, int) and len(value) < minimum:
            violations.append(f"{location}: array shorter than minItems")
        item_schema = schema.get("items")
        if item_schema is not None:
            for index, item in enumerate(value):
                violations.extend(
                    json_schema_violations(item, item_schema, root_schema, f"{location}[{index}]")
                )

    if isinstance(value, dict):
        required = schema.get("required", [])
        if isinstance(required, list):
            for field in required:
                if isinstance(field, str) and field not in value:
                    violations.append(f"{location}: missing required property {field}")
        properties = schema.get("properties", {})
        if isinstance(properties, dict):
            if schema.get("additionalProperties") is False:
                for field in value:
                    if field not in properties:
                        violations.append(f"{location}: additional property {field}")
            for field, child_schema in properties.items():
                if field in value:
                    violations.extend(
                        json_schema_violations(
                            value[field], child_schema, root_schema, f"{location}.{field}"
                        )
                    )
    return violations


def portable_public_relative_path(value: object) -> bool:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        return False
    if unicodedata.normalize("NFC", value) != value or re.match(r"^[A-Za-z]:", value):
        return False
    candidate = PurePosixPath(value)
    return (
        not candidate.is_absolute()
        and candidate.as_posix() == value
        and all(part not in {"", ".", ".."} for part in candidate.parts)
    )


def claim_schema_validator_self_test(claim_schema: object) -> list[str]:
    valid = {
        "id": "CL-999",
        "wording": "Synthetic validator self-test claim.",
        "evidence": [{"path": "fixture.txt", "sha256": "0" * 64}],
        "scope": "Validator self-test only.",
        "exclusions": ["Not publication evidence."],
        "confidence": "DEFINITION",
    }
    if json_schema_violations(valid, claim_schema, claim_schema, "self-test.valid"):
        return ["claim schema validator rejected its valid self-test fixture"]
    mutants = [
        {**valid, "id": "invalid"},
        {**valid, "confidence": "UNDECLARED"},
        {**valid, "exclusions": []},
        {**valid, "unexpected": True},
        {**valid, "evidence": [{"path": "fixture.txt", "sha256": "ABC"}]},
    ]
    failures = []
    for index, mutant in enumerate(mutants, start=1):
        if not json_schema_violations(mutant, claim_schema, claim_schema, f"self-test.mutant[{index}]"):
            failures.append(f"claim schema validator accepted invalid self-test mutant {index}")
    if not portable_public_relative_path("public_evidence/fixture.json"):
        failures.append("portable public-path validator rejected its valid self-test path")
    for index, invalid_path in enumerate(
        ("../fixture.json", "/fixture.json", "C:/fixture.json", "a\\fixture.json", "a//fixture.json"),
        start=1,
    ):
        if portable_public_relative_path(invalid_path):
            failures.append(f"portable public-path validator accepted invalid self-test path {index}")
    return failures


def public_files() -> list[Path]:
    return sorted(
        (
            path for path in ROOT.rglob("*")
            if path.is_file()
            and not EXCLUDED.intersection(path.relative_to(ROOT).parts)
            and path.relative_to(ROOT).as_posix() not in GENERATED_INDEXES
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


def file_metric(path: Path) -> dict[str, object] | None:
    if not path.is_file():
        return None
    return {"sha256": digest(path), "size": path.stat().st_size}


def valid_sha256(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def validate_article_warning_summary(
    summary: object, expected_line: str, expected_package: str, label: str
) -> None:
    expected_keys = {
        "accepted_package_warning_first_lines", "latex_warning_lines",
        "overfull_hbox", "overfull_vbox", "package_warning_first_lines",
        "package_warning_lines", "package_warning_packages",
        "package_warning_policy", "underfull_hbox", "underfull_vbox",
    }
    if not isinstance(summary, dict) or set(summary) != expected_keys:
        ERRORS.append(f"article build warning-summary property set mismatch: {label}")
        return
    expected = {
        "accepted_package_warning_first_lines": [expected_line],
        "latex_warning_lines": 0,
        "overfull_hbox": 0,
        "overfull_vbox": 0,
        "package_warning_first_lines": [expected_line],
        "package_warning_lines": 1,
        "package_warning_packages": [expected_package],
        "package_warning_policy": "EXACT_FIRST_LINE_ALLOWLIST",
    }
    for field, value in expected.items():
        if summary.get(field) != value:
            ERRORS.append(f"article build warning policy mismatch: {label}: {field}")
    for field in ("underfull_hbox", "underfull_vbox"):
        value = summary.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            ERRORS.append(f"article build warning count invalid: {label}: {field}")


def validate_article_pdf_receipt(
    validation: object, expected_pages: int, expected_pdf_version: str, label: str
) -> None:
    if not isinstance(validation, dict):
        ERRORS.append(f"article build PDF validation missing: {label}")
        return
    for field, expected in {
        "all_fonts_embedded": True,
        "encrypted": False,
        "javascript": False,
        "pages": expected_pages,
    }.items():
        actual = validation.get(field)
        mismatch = actual is not expected if isinstance(expected, bool) else actual != expected
        if mismatch:
            ERRORS.append(f"article build PDF validation mismatch: {label}: {field}")
    font_count = validation.get("font_count")
    if not isinstance(font_count, int) or isinstance(font_count, bool) or font_count < 1:
        ERRORS.append(f"article build PDF font count invalid: {label}")
    if validation.get("pdf_version") != expected_pdf_version:
        ERRORS.append(f"article build PDF version mismatch: {label}")
    if not valid_sha256(validation.get("text_sha256")):
        ERRORS.append(f"article build PDF text hash invalid: {label}")


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
    manifest_raw = manifest_path.read_bytes()
    expected_manifest_raw = "".join(
        f"{observed[relative]}  {relative}\n" for relative in sorted(observed)
    ).encode("ascii")
    if manifest_raw != expected_manifest_raw:
        ERRORS.append("manifest is not the exact ordinal canonical byte representation")
    manifest: dict[str, str] = {}
    for line in manifest_raw.decode("ascii").splitlines():
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
    expected_allowlist_raw = ("\n".join(sorted(observed)) + "\n").encode("utf-8")
    if allowlist_path.read_bytes() != expected_allowlist_raw:
        ERRORS.append("allowlist is not the exact ordinal canonical byte representation")

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
    claim_schema = strict_json(ROOT / "schemas" / "claim.schema.json")
    ERRORS.extend(claim_schema_validator_self_test(claim_schema))
    expected_ledger_keys = {"claims", "forbidden_claims_reviewed", "schema"}
    if not isinstance(claims, dict) or set(claims) != expected_ledger_keys:
        ERRORS.append("claims ledger top-level property set mismatch")
        claim_rows: list[object] = []
    else:
        if claims.get("schema") != "oasi.public.claims-evidence.v2":
            ERRORS.append("claims ledger schema identifier mismatch")
        if claims.get("forbidden_claims_reviewed") is not True:
            ERRORS.append("claims ledger forbidden-claims review is not true")
        candidate_rows = claims.get("claims")
        if not isinstance(candidate_rows, list) or not candidate_rows:
            ERRORS.append("claims ledger claims must be a non-empty array")
            claim_rows = []
        else:
            claim_rows = candidate_rows
    ids = [row.get("id") for row in claim_rows if isinstance(row, dict)]
    if len(ids) != len(claim_rows) or len(ids) != len(set(ids)):
        ERRORS.append("claim IDs missing or duplicated")
    for index, row in enumerate(claim_rows):
        for violation in json_schema_violations(row, claim_schema, claim_schema, f"claims[{index}]"):
            ERRORS.append(f"claim schema violation: {violation}")
        if not isinstance(row, dict):
            continue
        for evidence in row.get("evidence", []):
            if not isinstance(evidence, dict):
                continue
            evidence_path = evidence.get("path")
            if not portable_public_relative_path(evidence_path):
                ERRORS.append(f"claim evidence path is not portable and relative: {row.get('id')}")
                continue
            if evidence_path not in observed_artifacts:
                ERRORS.append(f"claim evidence is outside the public artifact set: {row.get('id')}")
                continue
            candidate = ROOT.joinpath(*PurePosixPath(evidence_path).parts)
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
    "OASI GUARANTEES EXACTLY-ONCE", "S6 PROVES OASI SUPERIORITY",
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
if "PASS_OWNER_REPRESENTATION_ACCEPTED_FOR_V0_2_RELEASE" not in status_text:
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

s5_summary = strict_json(ROOT / "public_evidence" / "S5_SCIENCE_SUMMARY.json")
if s5_summary.get("status") != "NEGATIVE_MECHANISM_ADVANTAGE_NOT_ESTABLISHED":
    ERRORS.append("S5 negative publication boundary missing")
if s5_summary.get("raw_sha256") != "9a089564929e989fc1e7e1bab44ff9a2e11633e8e93f53b1904bea523e31a0fd":
    ERRORS.append("S5 raw pin changed")
s6_summary = strict_json(ROOT / "public_evidence" / "S6_SCIENCE_SUMMARY.json")
if s6_summary.get("status") != "DIAGNOSTIC_POLICY_TRADEOFF_MECHANISM_SPECIFIC_ADVANTAGE_NOT_ESTABLISHED":
    ERRORS.append("S6 diagnostic publication boundary missing")
if s6_summary.get("raw_sha256") != "e21c6c9cd551b599768ef9451e07d7f1b079b95d598ef1068840c8b8fb5503a9":
    ERRORS.append("S6 raw pin changed")

experiment_verifier = ROOT / "tools" / "verify_experiments.py"
if experiment_verifier.is_file():
    checked = subprocess.run(
        [sys.executable, "-I", "-B", str(experiment_verifier), str(ROOT)],
        check=False,
        capture_output=True,
        text=True,
    )
    if checked.returncode != 0:
        ERRORS.append("S5/S6 experiment verifier failed: " + checked.stdout.strip().replace("\n", " ")[:500])

terminology_verifier = ROOT / "tools" / "verify_aera_terminology.py"
if terminology_verifier.is_file():
    checked = subprocess.run(
        [sys.executable, "-I", "-B", str(terminology_verifier), str(ROOT)],
        check=False,
        capture_output=True,
        text=True,
    )
    if checked.returncode != 0:
        ERRORS.append("AERA terminology verifier failed: " + checked.stdout.strip().replace("\n", " ")[:500])

inventory_path = ROOT / "LICENSE_INVENTORY.json"
inventory = strict_json(inventory_path)
expected_inventory_metadata = {
    "git_dependencies": [],
    "preferred_future_code_license": "AGPL-3.0-only optional for a future clean-slate generation after a fresh chain-of-title and compatibility audit",
    "registry_dependencies": [],
    "schema": "oasi.public.license-inventory.v2",
    "status": "PASS_OWNER_REPRESENTATION_ACCEPTED_FOR_V0_2_RELEASE",
    "third_party_source_vendored": False,
}
if not isinstance(inventory, dict) or set(inventory) != {"files", *expected_inventory_metadata}:
    ERRORS.append("license inventory top-level property set mismatch")
for field, expected in expected_inventory_metadata.items():
    if inventory.get(field) != expected:
        ERRORS.append(f"license inventory metadata mismatch: {field}")
inventory_rows = inventory.get("files", [])
if not isinstance(inventory_rows, list):
    ERRORS.append("license inventory files must be a list")
    inventory_rows = []
mapped_paths = [row.get("path") for row in inventory_rows if isinstance(row, dict)]
mapped = set(mapped_paths)
expected_inventory = {
    path.relative_to(ROOT).as_posix()
    for path in files
    if path.relative_to(ROOT).as_posix() != "LICENSE_INVENTORY.json"
}
if len(inventory_rows) != len(expected_inventory) or len(mapped_paths) != len(inventory_rows):
    ERRORS.append("license inventory file-row cardinality mismatch")
if len(mapped_paths) != len(set(mapped_paths)):
    ERRORS.append("license inventory file paths are duplicated")
if mapped_paths != sorted(mapped_paths):
    ERRORS.append("license inventory file paths are not ordinally sorted")
if mapped != expected_inventory:
    ERRORS.append("license inventory does not cover exact public file set")
for index, row in enumerate(inventory_rows):
    if not isinstance(row, dict) or set(row) != {"copyright", "license", "path", "provenance", "sha256"}:
        ERRORS.append(f"license inventory row property set mismatch: {index}")
        continue
    rel = row.get("path")
    if not portable_public_relative_path(rel) or rel not in expected_inventory:
        ERRORS.append(f"license inventory path is not a public relative file: {index}")
        continue
    if row.get("license") != license_for(rel):
        ERRORS.append(f"license inventory license mismatch: {rel}")
    if row.get("provenance") != provenance_for(rel):
        ERRORS.append(f"license inventory provenance mismatch: {rel}")
    if row.get("copyright") != "NOASSERTION":
        ERRORS.append(f"license inventory copyright mismatch: {rel}")
    candidate = ROOT.joinpath(*PurePosixPath(rel).parts)
    if not candidate.is_file() or digest(candidate) != row.get("sha256"):
        ERRORS.append(f"license inventory hash mismatch: {rel}")

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
expected_document_keys = {
    "SPDXID", "creationInfo", "dataLicense", "documentNamespace", "files",
    "name", "packages", "relationships", "spdxVersion",
}
if set(sbom) != expected_document_keys:
    ERRORS.append("SBOM document exact property set mismatch")
for field, expected in {
    "SPDXID": "SPDXRef-DOCUMENT",
    "dataLicense": "CC0-1.0",
    "documentNamespace": "https://spdx.org/spdxdocs/oasi-aera-v0.2.2-research-preview",
    "name": "OASI-AERA-v0.2.2-research-preview-SBOM",
    "spdxVersion": "SPDX-2.3",
}.items():
    if sbom.get(field) != expected:
        ERRORS.append(f"SBOM document field mismatch: {field}")
if sbom.get("creationInfo") != {
    "created": "2026-09-03T00:00:00Z",
    "creators": ["Tool: OASI deterministic metadata builder"],
}:
    ERRORS.append("SBOM creationInfo mismatch")

expected_sbom_order = sorted(
    path.relative_to(ROOT).as_posix()
    for path in files
    if path.relative_to(ROOT).as_posix() not in SBOM_EXCLUDED
)
raw_sbom_files = sbom.get("files", [])
if not isinstance(raw_sbom_files, list):
    ERRORS.append("SBOM files must be a list")
    raw_sbom_files = []
if len(raw_sbom_files) != len(expected_sbom_order):
    ERRORS.append("SBOM file-row cardinality mismatch")
observed_sbom_names: list[str] = []
observed_file_ids: list[str] = []
expected_relationships: set[tuple[str, str, str]] = set()
for index, row in enumerate(raw_sbom_files, start=1):
    if not isinstance(row, dict):
        ERRORS.append(f"SBOM file row {index} is not an object")
        continue
    if set(row) != {
        "SPDXID", "checksums", "copyrightText", "fileName", "fileTypes",
        "licenseConcluded", "licenseInfoInFiles",
    }:
        ERRORS.append(f"SBOM file row property set mismatch: {index}")
    file_name = row.get("fileName")
    rel = file_name[2:] if isinstance(file_name, str) and file_name.startswith("./") else ""
    observed_sbom_names.append(rel)
    expected_id = f"SPDXRef-File-{index:04d}"
    observed_file_ids.append(row.get("SPDXID", ""))
    if row.get("SPDXID") != expected_id:
        ERRORS.append(f"SBOM file SPDXID/order mismatch: {rel or index}")
    if index <= len(expected_sbom_order) and rel != expected_sbom_order[index - 1]:
        ERRORS.append(f"SBOM file ordinal order mismatch: {rel or index}")
    checksum_rows = row.get("checksums", [])
    checksums: dict[str, str] = {}
    if not isinstance(checksum_rows, list) or len(checksum_rows) != 2:
        ERRORS.append(f"SBOM checksum cardinality mismatch: {rel or index}")
    else:
        for checksum in checksum_rows:
            if not isinstance(checksum, dict) or set(checksum) != {"algorithm", "checksumValue"}:
                ERRORS.append(f"SBOM checksum property set mismatch: {rel or index}")
                continue
            algorithm = checksum.get("algorithm")
            if algorithm in checksums:
                ERRORS.append(f"SBOM duplicate checksum algorithm: {rel or index}")
            checksums[algorithm] = checksum.get("checksumValue")
    if set(checksums) != {"SHA1", "SHA256"}:
        ERRORS.append(f"SBOM checksum algorithm set mismatch: {rel or index}")
    candidate = ROOT / rel
    if not rel or not candidate.is_file() or checksums.get("SHA256") != digest(candidate):
        ERRORS.append(f"SBOM hash mismatch: {rel or index}")
    if not rel or not candidate.is_file() or checksums.get("SHA1") != digest_sha1(candidate):
        ERRORS.append(f"SBOM SHA1 mismatch: {rel or index}")
    suffix = candidate.suffix.lower() if rel else ""
    expected_types = (
        ["SOURCE"]
        if suffix in {".rs", ".py", ".ps1", ".sh", ".tex", ".bib", ".toml", ".json", ".md", ".cff"}
        else ["BINARY"] if suffix == ".pdf" else ["OTHER"]
    )
    if row.get("fileTypes") != expected_types:
        ERRORS.append(f"SBOM fileTypes mismatch: {rel or index}")
    expected_license = license_for(rel)
    if row.get("licenseConcluded") != expected_license or row.get("licenseInfoInFiles") != [expected_license]:
        ERRORS.append(f"SBOM file license mismatch: {rel or index}")
    if row.get("copyrightText") != "NOASSERTION":
        ERRORS.append(f"SBOM file copyright mismatch: {rel or index}")
    expected_relationships.add(("SPDXRef-Package-OASI", "CONTAINS", expected_id))
if observed_sbom_names != expected_sbom_order or len(observed_sbom_names) != len(set(observed_sbom_names)):
    ERRORS.append("SBOM does not contain each expected file exactly once in ordinal order")
if len(observed_file_ids) != len(set(observed_file_ids)):
    ERRORS.append("SBOM duplicate file SPDXID")

raw_packages = sbom.get("packages", [])
if not isinstance(raw_packages, list):
    ERRORS.append("SBOM packages must be a list")
    raw_packages = []
package_ids = [row.get("SPDXID") for row in raw_packages if isinstance(row, dict)]
package_names = [row.get("name") for row in raw_packages if isinstance(row, dict)]
if len(raw_packages) != len(package_ids) or len(package_ids) != len(set(package_ids)):
    ERRORS.append("SBOM package rows or SPDXIDs are invalid/duplicated")
if len(package_names) != len(set(package_names)):
    ERRORS.append("SBOM duplicate package name")
project_matches = [
    row for row in raw_packages
    if isinstance(row, dict) and row.get("name") == "OASI/AERA: Operational Artificial System Intelligence Research Preview"
]
if len(project_matches) != 1:
    ERRORS.append("SBOM must contain exactly one OASI project package")
project_package = project_matches[0] if len(project_matches) == 1 else {}
expected_verification_code = hashlib.sha1(
    "".join(sorted(digest_sha1(ROOT / rel) for rel in expected_sbom_order)).encode("ascii")
).hexdigest()
actual_verification_code = project_package.get("packageVerificationCode", {}).get(
    "packageVerificationCodeValue"
)
if actual_verification_code != expected_verification_code:
    ERRORS.append("SBOM package verification code mismatch")
expected_tool_packages = [
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
]
if len(raw_packages) != 1 + len(expected_tool_packages):
    ERRORS.append("SBOM package cardinality mismatch")
expected_project_keys = {
    "SPDXID", "copyrightText", "downloadLocation", "filesAnalyzed",
    "licenseConcluded", "licenseDeclared", "name", "packageVerificationCode", "versionInfo",
}
if set(project_package) != expected_project_keys:
    ERRORS.append("SBOM project package property set mismatch")
if project_package and {
    "SPDXID": project_package.get("SPDXID"),
    "copyrightText": project_package.get("copyrightText"),
    "downloadLocation": project_package.get("downloadLocation"),
    "filesAnalyzed": project_package.get("filesAnalyzed"),
    "licenseConcluded": project_package.get("licenseConcluded"),
    "licenseDeclared": project_package.get("licenseDeclared"),
    "name": project_package.get("name"),
    "versionInfo": project_package.get("versionInfo"),
} != {
    "SPDXID": "SPDXRef-Package-OASI",
    "copyrightText": "NOASSERTION",
    "downloadLocation": "NOASSERTION",
    "filesAnalyzed": True,
    "licenseConcluded": "NOASSERTION",
    "licenseDeclared": "NOASSERTION",
    "name": "OASI/AERA: Operational Artificial System Intelligence Research Preview",
    "versionInfo": "0.2.2-research-preview",
}:
    ERRORS.append("SBOM project package fields mismatch")
if set(project_package.get("packageVerificationCode", {})) != {"packageVerificationCodeValue"}:
    ERRORS.append("SBOM packageVerificationCode property set mismatch")
for index, (name, version) in enumerate(expected_tool_packages, start=1):
    expected_id = f"SPDXRef-Tool-{index:02d}"
    matches = [row for row in raw_packages if isinstance(row, dict) and row.get("name") == name]
    if len(matches) != 1:
        ERRORS.append(f"SBOM tool package cardinality mismatch: {name}")
        continue
    row = matches[0]
    if set(row) != {
        "SPDXID", "copyrightText", "downloadLocation", "filesAnalyzed",
        "licenseConcluded", "licenseDeclared", "name", "versionInfo",
    } or row != {
        "SPDXID": expected_id,
        "copyrightText": "NOASSERTION",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "name": name,
        "versionInfo": version,
    }:
        ERRORS.append(f"SBOM tool package mismatch: {name} {version}")

raw_relationships = sbom.get("relationships", [])
observed_relationships: list[tuple[str, str, str]] = []
if not isinstance(raw_relationships, list):
    ERRORS.append("SBOM relationships must be a list")
else:
    for index, row in enumerate(raw_relationships, start=1):
        if not isinstance(row, dict) or set(row) != {"spdxElementId", "relationshipType", "relatedSpdxElement"}:
            ERRORS.append(f"SBOM relationship property set mismatch: {index}")
            continue
        observed_relationships.append(
            (row.get("spdxElementId"), row.get("relationshipType"), row.get("relatedSpdxElement"))
        )
if len(observed_relationships) != len(set(observed_relationships)) or set(observed_relationships) != expected_relationships:
    ERRORS.append("SBOM CONTAINS relationships are missing, duplicated, or unexpected")

toolchain = strict_json(ROOT / "TOOLCHAIN_PROVENANCE.json")
qualification = toolchain.get("qualification_environment", {})
publication = toolchain.get("publication_environment", {})
if set(toolchain) != {"schema", "qualification_environment", "publication_environment", "limitations"}:
    ERRORS.append("toolchain provenance exact property set mismatch")
if toolchain.get("schema") != "oasi.public.toolchain-provenance.v1":
    ERRORS.append("toolchain provenance schema mismatch")
expected_qualification = {
    "role": "Historical S5/S6 qualification and full Rust test execution in isolated WSL1",
    "network_during_tests": False,
    "operating_system": "Ubuntu 24.04 user space on WSL1",
    "kernel": "4.4.0-26100-Microsoft",
    "architecture": "x86_64",
    "python_implementation": "CPython",
    "python": "3.12.3",
    "pyyaml": "6.0.1",
    "cryptography": "41.0.7",
    "sqlite": "3.45.1",
    "rustc": "1.97.1",
    "rustc_full": "rustc 1.97.1 (8bab26f4f 2026-07-14)",
    "cargo": "1.97.1",
    "cargo_full": "cargo 1.97.1 (c980f4866 2026-06-30)",
    "rust_host": "x86_64-unknown-linux-gnu",
    "rust_distribution_sha256": "88f28fa9af20594179f85d6df67078dfd6fa93e2f6da5e1e9b0ac4997988ca4f",
}
if not isinstance(qualification, dict) or set(qualification) != set(expected_qualification) | {"rust_tests"}:
    ERRORS.append("qualification toolchain exact property set mismatch")
for field, expected in expected_qualification.items():
    if qualification.get(field) != expected:
        ERRORS.append(f"qualification toolchain provenance mismatch: {field}")
if qualification.get("rust_tests") != {
    "command": "cargo test --offline --locked --all-targets",
    "passed": 33,
    "failed": 0,
}:
    ERRORS.append("qualification Rust test summary mismatch")
expected_publication = {
    "role": "Metadata, document, and release-asset construction",
    "operating_system": "Windows",
    "python_implementation": "CPython",
    "python": "3.11.9",
    "pyyaml": "6.0.3",
    "cryptography": "50.0.1",
    "sqlite": "3.45.1",
    "zlib": "1.3.1",
    "git_for_windows": "2.55.0.windows.5",
    "miktex_pdftex": "4.23",
    "biber": "2.21",
    "poppler_pdfinfo": "26.05.0",
    "poppler_pdffonts": "24.04.0",
    "poppler_pdftotext": "24.04.0",
    "poppler_pdftocairo": "24.04.0",
}
if not isinstance(publication, dict) or set(publication) != set(expected_publication):
    ERRORS.append("publication toolchain exact property set mismatch")
for field, expected in expected_publication.items():
    if publication.get(field) != expected:
        ERRORS.append(f"publication toolchain provenance mismatch: {field}")

qualification_receipt = strict_json(ROOT / "experiments" / "QUALIFICATION_RECEIPT.json")
if set(qualification_receipt) != {
    "schema", "date_utc", "classification", "scope", "environment",
    "rust_toolchain_source", "checks", "categorical_comparator_fields",
    "fresh_outputs_retained_in_release", "receipt_limit",
}:
    ERRORS.append("qualification receipt exact property set mismatch")
for field, expected in {
    "schema": "oasi.s5-s6.public-runner-qualification.v1",
    "date_utc": "2026-09-02",
    "classification": "project-controlled local qualification; not external replication",
    "scope": "Linux/WSL1 x86_64, fixture-only, offline",
    "fresh_outputs_retained_in_release": False,
}.items():
    if qualification_receipt.get(field) != expected:
        ERRORS.append(f"qualification receipt mismatch: {field}")
expected_receipt_environment = {
    "architecture": "x86_64",
    "kernel": "4.4.0-26100-Microsoft",
    "python": "CPython 3.12.3",
    "pyyaml": "6.0.1",
    "cryptography": "41.0.7",
    "sqlite": "3.45.1",
    "rustc": "1.97.1 (8bab26f4f 2026-07-14)",
    "cargo": "1.97.1 (c980f4866 2026-06-30)",
    "rust_host": "x86_64-unknown-linux-gnu",
}
if qualification_receipt.get("environment") != expected_receipt_environment:
    ERRORS.append("qualification receipt environment mismatch")
if qualification_receipt.get("rust_toolchain_source") != {
    "url": "https://static.rust-lang.org/dist/rust-1.97.1-x86_64-unknown-linux-gnu.tar.xz",
    "bytes": 201303968,
    "sha256": "88f28fa9af20594179f85d6df67078dfd6fa93e2f6da5e1e9b0ac4997988ca4f",
    "checksum_match": True,
    "network_used_by_test_execution": False,
}:
    ERRORS.append("qualification receipt Rust source mismatch")
expected_receipt_checks = {
    "rust_all_targets": {
        "command": "cargo test --offline --locked --all-targets",
        "exit_code": 0,
        "tests_passed": 33,
        "tests_failed": 0,
    },
    "s5_unit": {"tests_passed": 6, "tests_failed": 0},
    "s6_unit": {"tests_passed": 7, "tests_failed": 0},
    "s5_mutant": {"expected_rejection_observed": True},
    "s6_mutant": {"expected_rejection_observed": True},
    "s5_fresh_campaign": {
        "records": 1200,
        "detached_checker_exit_code": 0,
        "raw_sha256": "5193886c704a4e4a70638b6f38459c1d2b500a06d7b20f60c802556c532b3204",
        "categorical_missing": 0,
        "categorical_extra": 0,
        "categorical_mismatches": 0,
    },
    "s6_fresh_campaign": {
        "records": 1500,
        "detached_checker_exit_code": 0,
        "raw_sha256": "8e6f5b50cb733c8c5c3235aeb4d18359fc6294120256193c7989d5fc7c99a44b",
        "categorical_missing": 0,
        "categorical_extra": 0,
        "categorical_mismatches": 0,
    },
}
if qualification_receipt.get("checks") != expected_receipt_checks:
    ERRORS.append("qualification receipt check matrix mismatch")
expected_comparator_fields = [
    "schema", "effect_count", "double_effect", "delivered_exactly_once",
    "delivery_lost", "deterministic_terminal", "replay_accepted",
    "cross_generation_accepted", "altered_signature_accepted", "disposition",
    "network_calls", "real_effect", "ambiguous_post_effect",
    "pre_effect_uncertainty", "effect_expected", "sink_profile",
    "sink_idempotency_supported", "sink_query_supported",
    "sink_transaction_supported", "b3_idempotency_request_honored",
]
if qualification_receipt.get("categorical_comparator_fields") != expected_comparator_fields:
    ERRORS.append("qualification receipt comparator field set/order mismatch")
if qualification_receipt.get("receipt_limit") != (
    "The hashes identify ephemeral project-controlled reruns. The rerun files are not shipped, "
    "so this receipt is auditable as a declared execution record but is not an independent reproduction certificate."
):
    ERRORS.append("qualification receipt limitation mismatch")

# Cross-record consistency is checked explicitly; matching hard-coded literals in
# separate JSON documents is not accepted as sufficient provenance on its own.
if isinstance(qualification, dict):
    for provenance_field, receipt_field in {
        "kernel": "kernel",
        "architecture": "architecture",
        "pyyaml": "pyyaml",
        "cryptography": "cryptography",
        "sqlite": "sqlite",
        "rust_host": "rust_host",
    }.items():
        if qualification.get(provenance_field) != expected_receipt_environment.get(receipt_field):
            ERRORS.append(f"qualification provenance/receipt mismatch: {provenance_field}")
    if qualification.get("rustc_full", "").removeprefix("rustc ") != expected_receipt_environment.get("rustc"):
        ERRORS.append("qualification provenance/receipt mismatch: rustc_full")
    if qualification.get("cargo_full", "").removeprefix("cargo ") != expected_receipt_environment.get("cargo"):
        ERRORS.append("qualification provenance/receipt mismatch: cargo_full")

cff = (ROOT / "CITATION.cff").read_text(encoding="utf-8")


class UniqueKeyLoader(yaml.SafeLoader):
    pass


def construct_unique_mapping(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ValueError(f"duplicate CFF key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    construct_unique_mapping,
)
try:
    cff_document = yaml.load(cff, Loader=UniqueKeyLoader)
except Exception as exc:
    ERRORS.append(f"CITATION.cff structured parse failed: {type(exc).__name__}")
    cff_document = {}
if not isinstance(cff_document, dict):
    ERRORS.append("CITATION.cff root is not a mapping")
    cff_document = {}
expected_top = {
    "cff-version": "1.2.0",
    "message": "If you use this research preview, please cite the aggregate release and the accompanying article.",
    "title": "OASI/AERA: Operational Artificial System Intelligence Research Preview",
    "type": "software",
    "version": "0.2.2-research-preview",
    "repository-code": "https://github.com/mohammedmessaoudene-cmd/oasi-research",
    "abstract": (
        "Operational Artificial System Intelligence (OASI) is a research program investigating a "
        "system-level architecture in which operation, artificial embodiment, memory, cognition, "
        "authority, and development are coordinated through one versioned causal history and "
        "constitutionally mediated effects. This aggregate research preview contains a bounded "
        "user-space AERA reference runtime, negative T4 and S5 results, and a diagnostic S6 "
        "safety-availability tradeoff. Operational denotes system operation, not production readiness, "
        "and the name does not claim achieved general or superintelligence, consciousness, deployment, "
        "external validation, or superiority."
    ),
}
for field, expected in expected_top.items():
    if cff_document.get(field) != expected:
        ERRORS.append(f"CITATION.cff top-level mismatch: {field}")
if cff_document.get("keywords") != [
    "OASI", "Operational Artificial System Intelligence", "AERA", "runtime assurance", "operating systems",
    "developmental systems", "negative results",
]:
    ERRORS.append("CITATION.cff keyword set/order mismatch")
expected_cff_keys = {
    "cff-version", "message", "title", "type", "authors", "version",
    "repository-code", "abstract", "keywords", "preferred-citation",
}
if PRE_DOI:
    if set(cff_document) != expected_cff_keys:
        ERRORS.append("CITATION.cff pre-DOI top-level property set mismatch")
else:
    expected_cff_keys.update({"date-released", "url", "identifiers"})
    if set(cff_document) != expected_cff_keys:
        ERRORS.append("CITATION.cff post-DOI top-level property set mismatch")
    if cff_document.get("date-released") != "2026-09-03":
        ERRORS.append("CITATION.cff post-DOI release date mismatch")
authors = cff_document.get("authors", [])
if not isinstance(authors, list) or len(authors) != 1:
    ERRORS.append("CITATION.cff must contain exactly one declared author")
else:
    if authors[0] != {
        "family-names": "Messaoudene",
        "given-names": "Mohammed",
        "orcid": "https://orcid.org/0009-0007-4665-2548",
        "affiliation": "Belhadj Bouchaib University of Ain Temouchent, Algeria",
    }:
        ERRORS.append("CITATION.cff author metadata mismatch")
preferred_document = cff_document.get("preferred-citation", {})
expected_preferred_keys = {"type", "title", "authors", "year", "version"}
if not PRE_DOI:
    expected_preferred_keys.add("doi")
if not isinstance(preferred_document, dict) or set(preferred_document) != expected_preferred_keys:
    ERRORS.append("CITATION.cff preferred-citation property set mismatch")
expected_preferred = {
    "type": "article",
    "title": "OASI: Operational Artificial System Intelligence — An Organismic Computing Architecture for Body-Bound Runtime Assurance and Developmental OS–AI Integration",
    "authors": [{
        "family-names": "Messaoudene",
        "given-names": "Mohammed",
        "orcid": "https://orcid.org/0009-0007-4665-2548",
    }],
    "year": 2026,
    "version": "0.4.1-preprint",
}
for field, expected in expected_preferred.items():
    if not isinstance(preferred_document, dict) or preferred_document.get(field) != expected:
        ERRORS.append(f"CITATION.cff preferred-citation mismatch: {field}")
software_url = cff_document.get("url", "")
software_match = re.fullmatch(
    r"https://doi\.org/(10\.5281/zenodo\.[0-9]+)",
    software_url if isinstance(software_url, str) else "",
)
software_doi = software_match.group(1) if software_match else ""
preferred_doi_value = preferred_document.get("doi", "") if isinstance(preferred_document, dict) else ""
preferred_doi_match = re.fullmatch(
    r"10\.5281/zenodo\.[0-9]+",
    preferred_doi_value if isinstance(preferred_doi_value, str) else "",
)
preprint_doi = preferred_doi_match.group(0) if preferred_doi_match else ""
if PRE_DOI:
    if any(field in cff_document for field in ("url", "date-released", "identifiers")) or software_doi:
        ERRORS.append("CITATION.cff current software DOI must be absent in pre-DOI mode")
    if isinstance(preferred_document, dict) and "doi" in preferred_document or preprint_doi:
        ERRORS.append("CITATION.cff current preprint DOI must be absent in pre-DOI mode")
    if any(doi in cff for doi in HISTORICAL_DOIS):
        ERRORS.append("CITATION.cff historical version DOI presented in current citation metadata")
else:
    if not software_doi or software_doi in HISTORICAL_DOIS:
        ERRORS.append("CITATION.cff current software DOI is missing or historical")
    if not preprint_doi or preprint_doi in HISTORICAL_DOIS:
        ERRORS.append("CITATION.cff current preprint DOI is missing or historical")
    if software_doi and preprint_doi and software_doi == preprint_doi:
        ERRORS.append("CITATION.cff software and article DOI values must be distinct")
    if software_doi != args.expected_software_doi:
        ERRORS.append("CITATION.cff software DOI does not match the external expected pin")
    if preprint_doi != args.expected_article_doi:
        ERRORS.append("CITATION.cff article DOI does not match the external expected pin")
    identifiers = cff_document.get("identifiers", [])
    identifier_pairs: list[tuple[str, str]] = []
    if not isinstance(identifiers, list) or len(identifiers) != 1:
        ERRORS.append("CITATION.cff identifiers must contain exactly one software DOI record")
    else:
        for index, identifier in enumerate(identifiers, start=1):
            if not isinstance(identifier, dict) or set(identifier) != {"type", "value"}:
                ERRORS.append(f"CITATION.cff identifier property set mismatch: {index}")
                continue
            if identifier.get("type") != "doi" or not isinstance(identifier.get("value"), str):
                ERRORS.append(f"CITATION.cff identifier type/value mismatch: {index}")
                continue
            identifier_pairs.append((identifier["type"], identifier["value"]))
    expected_identifiers = {("doi", software_doi)}
    if len(identifier_pairs) != len(set(identifier_pairs)) or set(identifier_pairs) != expected_identifiers:
        ERRORS.append("CITATION.cff identifiers do not exactly identify the software DOI")

phase_documents = {
    "README.md": "DOI will be inserted only after Zenodo assigns it.",
    "README_FR.md": "DOI sera inséré seulement après son attribution par Zenodo.",
    "PUBLICATION_STATUS.md": "V0_2_2_PRE_DOI_TERMINOLOGY_CORRECTION_CANDIDATE",
    "RELEASE_NOTES.md": "final DOI values are intentionally absent",
}
phase_texts = {
    relative: (ROOT / relative).read_text(encoding="utf-8")
    for relative in phase_documents
    if (ROOT / relative).is_file()
}
if set(phase_texts) != set(phase_documents):
    ERRORS.append("active DOI-phase document missing")
elif PRE_DOI:
    for relative, marker in phase_documents.items():
        if marker not in phase_texts[relative]:
            ERRORS.append(f"active document pre-DOI marker missing: {relative}")
else:
    for relative, marker in phase_documents.items():
        text = phase_texts[relative]
        if marker in text:
            ERRORS.append(f"active document retains pre-DOI wording: {relative}")
        if not software_doi or software_doi not in text:
            ERRORS.append(f"active document lacks current software DOI: {relative}")
        if not preprint_doi or preprint_doi not in text:
            ERRORS.append(f"active document lacks current article DOI: {relative}")
    if "V0_2_2_POST_DOI_RELEASE_CANDIDATE" not in phase_texts["PUBLICATION_STATUS.md"]:
        ERRORS.append("post-DOI publication-state marker missing")

# The article PDF and generated figures are release artifacts only when their
# deterministic A/B build receipt is internally complete and matches the tree.
article_manifest_path = ROOT / ARTICLE_SOURCE_MANIFEST_REL
article_receipt_path = ROOT / ARTICLE_BUILD_RECEIPT_REL
article_pdf_path = ROOT / ARTICLE_PDF_REL
article_manifest_data = article_manifest_path.read_bytes() if article_manifest_path.is_file() else b""
article_manifest_entries: dict[str, str] = {}
article_manifest_order: list[str] = []
if not article_manifest_data:
    ERRORS.append("article source manifest missing or empty")
else:
    try:
        article_manifest_text = article_manifest_data.decode("ascii")
    except UnicodeDecodeError:
        ERRORS.append("article source manifest is not ASCII")
        article_manifest_text = ""
    if article_manifest_text and not article_manifest_data.endswith(b"\n"):
        ERRORS.append("article source manifest lacks final newline")
    if ARTICLE_SOURCE_MANIFEST_REL in article_manifest_text or ARTICLE_BUILD_RECEIPT_REL in article_manifest_text:
        ERRORS.append("article source manifest contains an auto-reference")
    lines = article_manifest_text.splitlines()
    if len(lines) != 6:
        ERRORS.append("article source manifest must contain exactly six entries")
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\s]+)", line)
        if not match:
            ERRORS.append("article source manifest grammar invalid")
            continue
        expected_hash, relative = match.groups()
        if relative in article_manifest_entries:
            ERRORS.append(f"article source manifest duplicate path: {relative}")
            continue
        article_manifest_order.append(relative)
        article_manifest_entries[relative] = expected_hash
    if tuple(article_manifest_order) != ARTICLE_SOURCE_RELS:
        ERRORS.append("article source manifest path set/order mismatch")
    for relative in ARTICLE_SOURCE_RELS:
        source_path = ROOT / PurePosixPath(relative)
        if not source_path.is_file() or article_manifest_entries.get(relative) != digest(source_path):
            ERRORS.append(f"article source manifest hash mismatch: {relative}")

article_receipt = strict_json(article_receipt_path) if article_receipt_path.is_file() else {}
expected_receipt_keys = {
    "article", "build_definitions", "builds", "comparison",
    "expected_article_doi", "fixed_build_time_utc", "phase",
    "promoted_outputs", "schema", "source_date_epoch", "source_manifest",
    "status", "toolchain",
}
if not isinstance(article_receipt, dict) or set(article_receipt) != expected_receipt_keys:
    ERRORS.append("article build receipt exact property set mismatch")
if article_receipt_path.is_file() and ARTICLE_BUILD_RECEIPT_REL in article_receipt_path.read_text(
    encoding="utf-8", errors="ignore"
):
    ERRORS.append("article build receipt contains an auto-reference")
if article_receipt.get("schema") != "oasi.article-build-receipt.v1":
    ERRORS.append("article build receipt schema mismatch")
if article_receipt.get("status") != "PASS_REPRODUCIBLE_ARTICLE_BUILD":
    ERRORS.append("article build receipt status mismatch")
if article_receipt.get("fixed_build_time_utc") != "2026-09-03T00:00:00Z":
    ERRORS.append("article build receipt fixed time mismatch")
if article_receipt.get("source_date_epoch") != 1788393600:
    ERRORS.append("article build receipt SOURCE_DATE_EPOCH mismatch")
if article_receipt.get("toolchain") != EXPECTED_ARTICLE_TOOLCHAIN:
    ERRORS.append("article build receipt toolchain mismatch")

expected_phase = "pre-doi" if PRE_DOI else "final"
expected_doi = None if PRE_DOI else preprint_doi
if article_receipt.get("phase") != expected_phase:
    ERRORS.append("article build receipt phase mismatch")
if article_receipt.get("expected_article_doi") != expected_doi or (not PRE_DOI and not expected_doi):
    ERRORS.append("article build receipt DOI binding mismatch")

manifest_metric = file_metric(article_manifest_path)
expected_manifest_receipt = (
    {"path": ARTICLE_SOURCE_MANIFEST_REL, **manifest_metric}
    if manifest_metric is not None else None
)
if article_receipt.get("source_manifest") != expected_manifest_receipt:
    ERRORS.append("article build receipt source-manifest metric mismatch")

definition_metrics = {
    relative: metric
    for relative in ARTICLE_BUILD_DEFINITION_RELS
    if (metric := file_metric(ROOT / PurePosixPath(relative))) is not None
}
if set(definition_metrics) != set(ARTICLE_BUILD_DEFINITION_RELS):
    ERRORS.append("article build definition file missing")
if article_receipt.get("build_definitions") != definition_metrics:
    ERRORS.append("article build definition metric mismatch")

promoted_metrics = {
    relative: metric
    for relative in ARTICLE_PROMOTED_RELS
    if (metric := file_metric(ROOT / PurePosixPath(relative))) is not None
}
if set(promoted_metrics) != set(ARTICLE_PROMOTED_RELS):
    ERRORS.append("article generated output file missing")
if article_receipt.get("promoted_outputs") != promoted_metrics:
    ERRORS.append("article promoted-output metrics mismatch")
article_metric = file_metric(article_pdf_path)
if article_receipt.get("article") != article_metric:
    ERRORS.append("article build receipt primary PDF metric mismatch")

if article_receipt.get("comparison") != {
    "article_byte_identical": True,
    "figure_pdf_svg_byte_identical": True,
    "output_set_identical": True,
}:
    ERRORS.append("article build receipt A/B comparison flags mismatch")

builds = article_receipt.get("builds", {})
if not isinstance(builds, dict) or set(builds) != {"A", "B"}:
    ERRORS.append("article build receipt must contain exactly builds A and B")
    builds = {}
validations: dict[str, object] = {}
for build_label in ("A", "B"):
    build = builds.get(build_label, {})
    if not isinstance(build, dict) or set(build) != {"outputs", "validation"}:
        ERRORS.append(f"article build receipt build property set mismatch: {build_label}")
        continue
    if build.get("outputs") != promoted_metrics:
        ERRORS.append(f"article build receipt output mismatch: {build_label}")
    validation = build.get("validation", {})
    validations[build_label] = validation
    if not isinstance(validation, dict) or set(validation) != {"article", "figures"}:
        ERRORS.append(f"article build receipt validation property set mismatch: {build_label}")
        continue
    article_validation = validation.get("article", {})
    expected_article_validation_keys = {
        "all_fonts_embedded", "biber_log_policy", "biber_warning_or_error_lines",
        "bibliography_sha256", "encrypted", "font_count", "javascript",
        "latex_log_sha256", "latex_warnings", "pages", "pdf_version", "text_sha256",
    }
    if not isinstance(article_validation, dict) or set(article_validation) != expected_article_validation_keys:
        ERRORS.append(f"article PDF receipt property set mismatch: {build_label}")
    validate_article_pdf_receipt(article_validation, 13, "1.7", f"{build_label}/article")
    if article_validation.get("biber_log_policy") != "NO_WARN_OR_ERROR_LINES":
        ERRORS.append(f"article Biber warning policy mismatch: {build_label}")
    if article_validation.get("biber_warning_or_error_lines") != 0:
        ERRORS.append(f"article Biber warning/error count nonzero: {build_label}")
    for hash_field in ("bibliography_sha256", "latex_log_sha256"):
        if not valid_sha256(article_validation.get(hash_field)):
            ERRORS.append(f"article build diagnostic hash invalid: {build_label}: {hash_field}")
    validate_article_warning_summary(
        article_validation.get("latex_warnings"),
        ARTICLE_PACKAGE_WARNING,
        "epstopdf",
        f"{build_label}/article",
    )

    figure_validations = validation.get("figures", {})
    if not isinstance(figure_validations, dict) or set(figure_validations) != set(ARTICLE_FIGURE_NAMES):
        ERRORS.append(f"article figure validation set mismatch: {build_label}")
        continue
    for figure in ARTICLE_FIGURE_NAMES:
        figure_validation = figure_validations.get(figure, {})
        if not isinstance(figure_validation, dict) or set(figure_validation) != {"latex_warnings", "pdf", "svg"}:
            ERRORS.append(f"article figure receipt property set mismatch: {build_label}/{figure}")
            continue
        validate_article_warning_summary(
            figure_validation.get("latex_warnings"),
            FIGURE_PACKAGE_WARNING,
            "shellesc",
            f"{build_label}/{figure}",
        )
        figure_pdf = figure_validation.get("pdf", {})
        if not isinstance(figure_pdf, dict) or set(figure_pdf) != {
            "all_fonts_embedded", "encrypted", "font_count", "javascript",
            "pages", "pdf_version", "text_sha256",
        }:
            ERRORS.append(f"article figure PDF property set mismatch: {build_label}/{figure}")
        validate_article_pdf_receipt(figure_pdf, 1, "1.5", f"{build_label}/{figure}")
        expected_svg_metric = promoted_metrics.get(
            f"paper/v0.4.1/source/figures/{figure}.svg"
        )
        expected_svg = (
            {**expected_svg_metric, "xml_root": "svg"}
            if isinstance(expected_svg_metric, dict) else None
        )
        if figure_validation.get("svg") != expected_svg:
            ERRORS.append(f"article figure SVG validation mismatch: {build_label}/{figure}")

if validations.get("A") != validations.get("B"):
    ERRORS.append("article build A/B validation records differ")

main_source_path = ROOT / "paper/v0.4.1/source/main.tex"
main_source = main_source_path.read_text(encoding="utf-8") if main_source_path.is_file() else ""
reproducibility_path = ROOT / "REPRODUCIBILITY.md"
reproducibility = (
    reproducibility_path.read_text(encoding="utf-8")
    if reproducibility_path.is_file() else ""
)
primary_test_phase = "pre-doi" if PRE_DOI else "post-doi"
primary_test_block = f"```text\nsh tools/run_tests.sh {primary_test_phase}\n```"
if primary_test_block not in reproducibility:
    ERRORS.append("REPRODUCIBILITY primary test command does not match selected DOI phase")
pre_doi_boundary = "will be inserted only after Zenodo assigns it"
if PRE_DOI:
    if pre_doi_boundary not in main_source:
        ERRORS.append("article source pre-DOI boundary missing")
elif not preprint_doi or preprint_doi not in main_source or pre_doi_boundary in main_source:
    ERRORS.append("article source final DOI binding mismatch")

result = {"pass": not ERRORS, "files_checked": len(files), "errors": ERRORS}
print(json.dumps(result, indent=2, sort_keys=True))
raise SystemExit(0 if not ERRORS else 1)
