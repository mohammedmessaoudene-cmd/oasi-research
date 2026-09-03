#!/usr/bin/env python3
"""Build and verify the OASI v0.4 article reproducibly.

The normative article inputs are main.tex, references.bib, and the four TikZ
figure sources.  Generated figure PDF/SVG files and the article PDF are built
twice in independent temporary directories.  Nothing in the repository is
changed unless every build, byte comparison, and content check passes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unicodedata
import xml.etree.ElementTree as ET
from pathlib import Path, PurePosixPath


SOURCE_DATE_EPOCH = "1788307200"
FIXED_BUILD_TIME_UTC = "2026-09-02T00:00:00Z"
ARTICLE_TITLE = (
    "OASI: Operational Artificial System Intelligence — An Organismic Computing "
    "Architecture for Body-Bound Runtime Assurance and Developmental OS–AI Integration"
)
ARTICLE_AUTHOR = "Mohammed Messaoudene"
ARTICLE_REL = "paper/v0.4/OASI_SCIENTIFIC_ARTICLE_PREPRINT_V0_4.pdf"
SOURCE_MANIFEST_REL = "paper/v0.4/ARTICLE_SOURCE_MANIFEST.sha256"
RECEIPT_REL = "paper/v0.4/BUILD_RECEIPT.json"
SOURCE_PREFIX = PurePosixPath("paper/v0.4/source")
FIGURE_NAMES = (
    "fig1_layered_vs_organismic",
    "fig2_cognition_reflex_aera",
    "fig3_authority_lifecycle",
    "fig4_evidence_ladder",
)
NORMATIVE_SOURCE_RELS = (
    "paper/v0.4/source/main.tex",
    "paper/v0.4/source/references.bib",
    *(f"paper/v0.4/source/figures/{name}.tex" for name in FIGURE_NAMES),
)
BUILD_DEFINITION_RELS = (
    "tools/build_article_verified.py",
    "tools/build_article.ps1",
    "tools/build_article.sh",
)
PRIVATE_TEXT_PATTERNS = (
    re.compile(r"(?i)[a-z]:[\\/]users[\\/]"),
    re.compile(r"(?i)[a-z]:[\\/](?:os|iascript)[\\/]"),
    re.compile(r"(?i)/home/[^/]+/"),
    re.compile(r"(?i)/mnt/[a-z]/"),
    re.compile(r"(?i)https://chatgpt\.com/c/"),
)
DOI_RE = re.compile(r"^10\.\d{4,9}(?:\.\d+)?/[A-Za-z0-9:/_;.()\[\]\\-]+$")
ALLOWED_PACKAGE_WARNING_FIRST_LINES = (
    "Package epstopdf Warning: Shell escape feature is not enabled.",
    "Package shellesc Warning: Shell escape disabled on input line 73.",
)


class BuildFailure(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def metric(data: bytes) -> dict[str, object]:
    return {"sha256": sha256_bytes(data), "size": len(data)}


def is_link_or_reparse(path: Path) -> bool:
    status = os.lstat(path)
    attributes = getattr(status, "st_file_attributes", 0)
    return stat.S_ISLNK(status.st_mode) or bool(
        attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def assert_plain_path(path: Path, root: Path) -> None:
    current = path
    while True:
        if is_link_or_reparse(current):
            raise BuildFailure(f"symlink or reparse point rejected: {path.name}")
        if current == root:
            return
        if current == current.parent:
            raise BuildFailure("path escaped repository root")
        current = current.parent


def assert_no_private_text(text: str, label: str) -> None:
    for pattern in PRIVATE_TEXT_PATTERNS:
        if pattern.search(text):
            raise BuildFailure(f"private path or conversation reference in {label}")


def source_snapshot(root: Path, phase: str, expected_article_doi: str | None) -> dict[str, bytes]:
    source_dir = root / SOURCE_PREFIX
    expected_figure_sources = {f"{name}.tex" for name in FIGURE_NAMES}
    observed_figure_sources = {path.name for path in (source_dir / "figures").glob("*.tex")}
    if observed_figure_sources != expected_figure_sources:
        raise BuildFailure(
            "unexpected normative figure set: "
            f"expected={sorted(expected_figure_sources)} observed={sorted(observed_figure_sources)}"
        )

    snapshot: dict[str, bytes] = {}
    for relative in NORMATIVE_SOURCE_RELS:
        path = root / PurePosixPath(relative)
        if not path.is_file():
            raise BuildFailure(f"missing normative article source: {relative}")
        assert_plain_path(path, root)
        data = path.read_bytes()
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise BuildFailure(f"non-UTF-8 article source: {relative}") from exc
        assert_no_private_text(text, relative)
        snapshot[relative] = data

    main_text = snapshot["paper/v0.4/source/main.tex"].decode("utf-8")
    for name in FIGURE_NAMES:
        reference = f"figures/{name}.pdf"
        if reference not in main_text:
            raise BuildFailure(f"article does not reference generated figure: {reference}")

    placeholders = ("TO_BE_RESERVED_OR_SET", "TO_BE_SET_AT_PUBLICATION", "DOI_TBD", "DOI_TODO")
    if any(marker in main_text for marker in placeholders):
        raise BuildFailure("unresolved DOI placeholder in article source")

    if phase == "pre-doi":
        required = "will be inserted only after Zenodo assigns it"
        if required not in main_text:
            raise BuildFailure("pre-DOI source boundary is absent")
    else:
        if expected_article_doi is None or not DOI_RE.fullmatch(expected_article_doi):
            raise BuildFailure("final phase requires a syntactically valid --expected-article-doi")
        if expected_article_doi == "10.5281/zenodo.22151556":
            raise BuildFailure("final v0.4 DOI cannot reuse the prior v0.3 DOI")
        if expected_article_doi not in main_text:
            raise BuildFailure("expected final article DOI is absent from source")
        if "will be inserted only after Zenodo assigns it" in main_text:
            raise BuildFailure("final source still contains the pre-DOI boundary")
    return snapshot


def manifest_bytes(snapshot: dict[str, bytes]) -> bytes:
    lines = [f"{sha256_bytes(snapshot[relative])}  {relative}\n" for relative in sorted(snapshot)]
    text = "".join(lines)
    assert_no_private_text(text, SOURCE_MANIFEST_REL)
    if SOURCE_MANIFEST_REL in text or RECEIPT_REL in text:
        raise BuildFailure("source manifest contains an auto-reference")
    return text.encode("ascii")


def sanitize_output(text: str, roots: list[Path]) -> str:
    clean = text
    for root in roots:
        for form in {str(root), root.as_posix()}:
            clean = re.sub(re.escape(form), "<BUILD>", clean, flags=re.IGNORECASE)
    clean = re.sub(r"(?i)[a-z]:[\\/]users[\\/][^\\/\s]+", "<USER_HOME>", clean)
    clean = re.sub(r"(?i)/home/[^/\s]+", "<USER_HOME>", clean)
    return clean


def run_checked(
    command: list[str], cwd: Path, environment: dict[str, str], roots: list[Path], timeout: int = 300
) -> str:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise BuildFailure(f"command timeout: {Path(command[0]).name}") from exc
    output = completed.stdout.decode("utf-8", errors="replace")
    if completed.returncode != 0:
        safe = sanitize_output(output, roots)
        tail = "\n".join(safe.splitlines()[-30:])
        raise BuildFailure(f"command failed ({Path(command[0]).name}, rc={completed.returncode}):\n{tail}")
    return output


def find_tools() -> dict[str, str]:
    names = ("pdflatex", "biber", "pdfinfo", "pdffonts", "pdftotext", "pdftocairo")
    tools: dict[str, str] = {}
    for name in names:
        resolved = shutil.which(name)
        if resolved is None:
            raise BuildFailure(f"required build tool missing: {name}")
        tools[name] = resolved
    return tools


def version_line(output: str, tool: str) -> str:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if tool == "pdflatex":
        for line in lines:
            if re.match(r"(?i)^(?:miktex-)?pdftex\s+\d", line):
                return line
        raise BuildFailure("pdflatex version banner not recognized")
    aliases = {
        "biber": ("biber",),
        "pdfinfo": ("pdfinfo",),
        "pdffonts": ("pdffonts",),
        "pdftotext": ("pdftotext",),
        "pdftocairo": ("pdftocairo",),
    }[tool]
    for line in lines:
        lowered = line.lower()
        if "version" in lowered and any(alias in lowered for alias in aliases):
            return line
    if lines:
        return lines[0]
    raise BuildFailure(f"empty version output: {tool}")


def tool_versions(
    tools: dict[str, str], root: Path, environment: dict[str, str]
) -> dict[str, str]:
    commands = {
        "pdflatex": [tools["pdflatex"], "--version"],
        "biber": [tools["biber"], "--version"],
        "pdfinfo": [tools["pdfinfo"], "-v"],
        "pdffonts": [tools["pdffonts"], "-v"],
        "pdftotext": [tools["pdftotext"], "-v"],
        "pdftocairo": [tools["pdftocairo"], "-v"],
    }
    versions = {
        name: version_line(run_checked(command, root, environment, [root], 60), name)
        for name, command in commands.items()
    }
    versions["python"] = platform.python_version()
    return versions


def latex_command(tools: dict[str, str], pdflatex_version: str, source_name: str) -> list[str]:
    command = [tools["pdflatex"]]
    if "miktex" in pdflatex_version.lower():
        command.extend(("--disable-installer", "--disable-write18"))
    else:
        command.append("-no-shell-escape")
    command.extend(("-interaction=nonstopmode", "-halt-on-error", "-file-line-error", source_name))
    return command


def warning_summary(log_text: str) -> dict[str, object]:
    package_warning_lines = re.findall(r"(?im)^Package [^\r\n]+ Warning:[^\r\n]*", log_text)
    package_names = sorted(
        set(
            match.group(1)
            for line in package_warning_lines
            if (match := re.match(r"(?i)^Package ([^\s]+) Warning:", line))
        )
    )
    return {
        "latex_warning_lines": len(re.findall(r"(?im)^LaTeX Warning:", log_text)),
        "package_warning_lines": len(package_warning_lines),
        "package_warning_packages": package_names,
        "package_warning_first_lines": package_warning_lines,
        "underfull_hbox": len(re.findall(r"Underfull \\hbox", log_text)),
        "underfull_vbox": len(re.findall(r"Underfull \\vbox", log_text)),
        "overfull_hbox": len(re.findall(r"Overfull \\hbox", log_text)),
        "overfull_vbox": len(re.findall(r"Overfull \\vbox", log_text)),
    }


def validate_latex_log(log_text: str, label: str) -> dict[str, object]:
    forbidden = (
        r"LaTeX Warning: There were undefined references",
        r"LaTeX Warning: Label\(s\) may have changed",
        r"(?:Citation|Reference) .+ undefined",
        r"Please \(re\)run Biber",
        r"Rerun to get cross-references right",
        r"Overfull \\[hv]box",
        r"Missing character:",
        r"LaTeX Error:",
        r"Emergency stop",
        r"Fatal error occurred",
    )
    for pattern in forbidden:
        if re.search(pattern, log_text, flags=re.IGNORECASE):
            raise BuildFailure(f"forbidden LaTeX warning/error in {label}: {pattern}")
    summary = warning_summary(log_text)
    observed = set(summary["package_warning_first_lines"])
    unexpected = sorted(observed - set(ALLOWED_PACKAGE_WARNING_FIRST_LINES))
    if unexpected:
        raise BuildFailure(
            f"unapproved package warning in {label}: " + " | ".join(unexpected)
        )
    summary["package_warning_policy"] = "EXACT_FIRST_LINE_ALLOWLIST"
    summary["accepted_package_warning_first_lines"] = sorted(observed)
    return summary


def parse_pdfinfo(output: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in output.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            result[key.strip()] = value.strip()
    return result


def parse_pdffonts(output: str) -> tuple[int, bool]:
    lines = output.splitlines()
    separator = next((index for index, line in enumerate(lines) if line.startswith("---")), None)
    if separator is None:
        raise BuildFailure("unrecognized pdffonts output")
    rows = [line for line in lines[separator + 1 :] if line.strip()]
    if not rows:
        raise BuildFailure("PDF contains no inspectable fonts")
    embedded = True
    for row in rows:
        fields = row.split()
        if len(fields) < 6:
            raise BuildFailure("unrecognized pdffonts row")
        # The final five columns are emb, sub, uni, object number and generation.
        if fields[-5].lower() != "yes":
            embedded = False
    return len(rows), embedded


def normalized_pdf_text(text: str) -> str:
    text = text.replace("\u00ad", "")
    text = unicodedata.normalize("NFKC", text)
    text = re.sub("[\u2010\u2011\u2012\u2013\u2014\u2015\u2212]", "-", text)
    return re.sub(r"\s+", " ", text).strip()


def validate_pdf(
    path: Path,
    tools: dict[str, str],
    environment: dict[str, str],
    roots: list[Path],
    expected_pages: int,
    required_text: tuple[str, ...] = (),
    forbidden_text: tuple[str, ...] = (),
    require_article_metadata: bool = False,
) -> dict[str, object]:
    if not path.is_file() or path.stat().st_size == 0:
        raise BuildFailure(f"missing or empty PDF: {path.name}")
    info_output = run_checked([tools["pdfinfo"], str(path)], path.parent, environment, roots, 60)
    info = parse_pdfinfo(info_output)
    try:
        pages = int(info.get("Pages", "-1"))
    except ValueError as exc:
        raise BuildFailure(f"invalid page count: {path.name}") from exc
    if pages != expected_pages:
        raise BuildFailure(f"unexpected page count for {path.name}: {pages} != {expected_pages}")
    if not info.get("Encrypted", "").lower().startswith("no"):
        raise BuildFailure(f"encrypted PDF rejected: {path.name}")
    if info.get("JavaScript", "no").lower() != "no":
        raise BuildFailure(f"PDF JavaScript rejected: {path.name}")
    if require_article_metadata:
        if info.get("Title") != ARTICLE_TITLE:
            raise BuildFailure("article PDF title metadata mismatch")
        if info.get("Author") != ARTICLE_AUTHOR:
            raise BuildFailure("article PDF author metadata mismatch")

    fonts_output = run_checked([tools["pdffonts"], str(path)], path.parent, environment, roots, 60)
    font_count, all_embedded = parse_pdffonts(fonts_output)
    if not all_embedded:
        raise BuildFailure(f"non-embedded PDF font: {path.name}")

    text_output = run_checked([tools["pdftotext"], str(path), "-"], path.parent, environment, roots, 60)
    text = normalized_pdf_text(text_output)
    lowered = text.lower()
    assert_no_private_text(text, path.name)
    for phrase in required_text:
        if normalized_pdf_text(phrase).lower() not in lowered:
            raise BuildFailure(f"required PDF text missing from {path.name}: {phrase}")
    for phrase in forbidden_text:
        if normalized_pdf_text(phrase).lower() in lowered:
            raise BuildFailure(f"forbidden PDF text present in {path.name}: {phrase}")
    return {
        "all_fonts_embedded": all_embedded,
        "encrypted": False,
        "font_count": font_count,
        "javascript": False,
        "pages": pages,
        "pdf_version": info.get("PDF version", "UNKNOWN"),
        "text_sha256": sha256_bytes(text.encode("utf-8")),
    }


def validate_svg(path: Path, roots: list[Path]) -> dict[str, object]:
    data = path.read_bytes()
    if not data or b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        raise BuildFailure(f"unsafe or empty SVG: {path.name}")
    text = data.decode("utf-8")
    assert_no_private_text(text, path.name)
    for root in roots:
        if str(root).lower() in text.lower() or root.as_posix().lower() in text.lower():
            raise BuildFailure(f"temporary or private path embedded in SVG: {path.name}")
    try:
        document = ET.fromstring(data)
    except ET.ParseError as exc:
        raise BuildFailure(f"invalid SVG XML: {path.name}") from exc
    if not document.tag.lower().endswith("svg"):
        raise BuildFailure(f"unexpected SVG root: {path.name}")
    return {"sha256": sha256_bytes(data), "size": len(data), "xml_root": "svg"}


def write_snapshot(build_source: Path, snapshot: dict[str, bytes]) -> None:
    for relative, data in snapshot.items():
        subpath = PurePosixPath(relative).relative_to(SOURCE_PREFIX)
        destination = build_source / subpath
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)


def build_once(
    label: str,
    build_root: Path,
    snapshot: dict[str, bytes],
    tools: dict[str, str],
    versions: dict[str, str],
    environment: dict[str, str],
    phase: str,
    expected_article_doi: str | None,
    expected_pages: int,
) -> tuple[dict[str, bytes], dict[str, object]]:
    source = build_root / label / "source"
    source.mkdir(parents=True)
    write_snapshot(source, snapshot)
    roots = [build_root, source]
    pdflatex = lambda name: latex_command(tools, versions["pdflatex"], name)

    outputs: dict[str, bytes] = {}
    figure_validation: dict[str, object] = {}
    figures = source / "figures"
    for name in FIGURE_NAMES:
        run_checked(pdflatex(f"{name}.tex"), figures, environment, roots)
        pdf = figures / f"{name}.pdf"
        log = figures / f"{name}.log"
        if not log.is_file():
            raise BuildFailure(f"figure log missing: {name}")
        warnings = validate_latex_log(log.read_text(encoding="utf-8", errors="replace"), name)
        svg = figures / f"{name}.svg"
        run_checked([tools["pdftocairo"], "-svg", str(pdf), str(svg)], figures, environment, roots, 60)
        required = ("Obligation-checked compilation",) if name == "fig2_cognition_reflex_aera" else ()
        forbidden = ("Verified compilation",) if name == "fig2_cognition_reflex_aera" else ()
        pdf_validation = validate_pdf(
            pdf, tools, environment, roots, 1, required_text=required, forbidden_text=forbidden
        )
        svg_validation = validate_svg(svg, roots)
        pdf_rel = f"paper/v0.4/source/figures/{name}.pdf"
        svg_rel = f"paper/v0.4/source/figures/{name}.svg"
        outputs[pdf_rel] = pdf.read_bytes()
        outputs[svg_rel] = svg.read_bytes()
        figure_validation[name] = {
            "latex_warnings": warnings,
            "pdf": pdf_validation,
            "svg": svg_validation,
        }

    run_checked(pdflatex("main.tex"), source, environment, roots)
    run_checked([tools["biber"], "main"], source, environment, roots)
    run_checked(pdflatex("main.tex"), source, environment, roots)
    run_checked(pdflatex("main.tex"), source, environment, roots)

    main_log = source / "main.log"
    biber_log = source / "main.blg"
    bibliography = source / "main.bbl"
    for required in (main_log, biber_log, bibliography, source / "main.pdf"):
        if not required.is_file() or required.stat().st_size == 0:
            raise BuildFailure(f"required article build output missing: {required.name}")
    main_log_text = main_log.read_text(encoding="utf-8", errors="replace")
    biber_log_text = biber_log.read_text(encoding="utf-8", errors="replace")
    warnings = validate_latex_log(main_log_text, "main.tex")
    if re.search(r"(?im)^(?:WARN|ERROR) -", biber_log_text):
        raise BuildFailure("Biber warning or error in final build")

    required_text = (
        ARTICLE_TITLE,
        "locked locally before measurement but not registered in a public registry",
        "No current guest result changes the scientific tables in this manuscript",
    )
    forbidden_text = (
        "preregistered mechanism-advantage criterion therefore failed",
        "TO_BE_RESERVED_OR_SET",
        "TO_BE_SET_AT_PUBLICATION",
    )
    if phase == "pre-doi":
        required_text += ("will be inserted only after Zenodo assigns it",)
    elif expected_article_doi is not None:
        required_text += (expected_article_doi,)

    article_pdf = source / "main.pdf"
    article_validation = validate_pdf(
        article_pdf,
        tools,
        environment,
        roots,
        expected_pages,
        required_text=required_text,
        forbidden_text=forbidden_text,
        require_article_metadata=True,
    )
    article_validation["bibliography_sha256"] = sha256_path(bibliography)
    article_validation["biber_log_policy"] = "NO_WARN_OR_ERROR_LINES"
    article_validation["biber_warning_or_error_lines"] = 0
    article_validation["latex_log_sha256"] = sha256_path(main_log)
    article_validation["latex_warnings"] = warnings
    outputs[ARTICLE_REL] = article_pdf.read_bytes()
    return outputs, {"article": article_validation, "figures": figure_validation}


def compare_builds(a: dict[str, bytes], b: dict[str, bytes]) -> None:
    if set(a) != set(b):
        raise BuildFailure("A/B output sets differ")
    mismatches = [relative for relative in sorted(a) if a[relative] != b[relative]]
    if mismatches:
        raise BuildFailure("A/B byte mismatch: " + ", ".join(mismatches))


def assert_snapshot_unchanged(root: Path, snapshot: dict[str, bytes]) -> None:
    for relative, expected in snapshot.items():
        path = root / PurePosixPath(relative)
        if not path.is_file() or path.read_bytes() != expected:
            raise BuildFailure(f"source changed during build: {relative}")


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    partial = path.parent / f".{path.name}.{os.getpid()}.partial"
    if partial.exists():
        raise BuildFailure(f"stale partial output exists: {path.name}")
    try:
        with partial.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(partial, path)
        try:
            descriptor = os.open(path.parent, os.O_RDONLY)
        except OSError:
            descriptor = None
        if descriptor is not None:
            try:
                os.fsync(descriptor)
            except OSError:
                pass
            finally:
                os.close(descriptor)
    finally:
        if partial.exists():
            partial.unlink()


def build_receipt(
    phase: str,
    source_manifest: bytes,
    definition_metrics: dict[str, dict[str, object]],
    versions: dict[str, str],
    outputs: dict[str, bytes],
    validation_a: dict[str, object],
    validation_b: dict[str, object],
    expected_article_doi: str | None,
) -> bytes:
    output_metrics = {relative: metric(data) for relative, data in sorted(outputs.items())}
    receipt = {
        "article": output_metrics[ARTICLE_REL],
        "build_definitions": definition_metrics,
        "builds": {
            "A": {"outputs": output_metrics, "validation": validation_a},
            "B": {"outputs": output_metrics, "validation": validation_b},
        },
        "comparison": {
            "article_byte_identical": True,
            "figure_pdf_svg_byte_identical": True,
            "output_set_identical": True,
        },
        "expected_article_doi": expected_article_doi,
        "fixed_build_time_utc": FIXED_BUILD_TIME_UTC,
        "phase": phase,
        "promoted_outputs": output_metrics,
        "schema": "oasi.article-build-receipt.v1",
        "source_date_epoch": int(SOURCE_DATE_EPOCH),
        "source_manifest": {
            "path": SOURCE_MANIFEST_REL,
            "sha256": sha256_bytes(source_manifest),
            "size": len(source_manifest),
        },
        "status": "PASS_REPRODUCIBLE_ARTICLE_BUILD",
        "toolchain": versions,
    }
    encoded = (json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    text = encoded.decode("utf-8")
    assert_no_private_text(text, RECEIPT_REL)
    if RECEIPT_REL in text:
        raise BuildFailure("build receipt contains an auto-reference")
    return encoded


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--phase", choices=("pre-doi", "final"), default="pre-doi")
    parser.add_argument("--expected-article-doi")
    parser.add_argument("--expected-pages", type=int, default=13)
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    root = arguments.root.resolve(strict=True)
    if not root.is_dir():
        raise BuildFailure("repository root is not a directory")
    if arguments.expected_pages < 1:
        raise BuildFailure("--expected-pages must be positive")

    snapshot = source_snapshot(root, arguments.phase, arguments.expected_article_doi)
    source_manifest = manifest_bytes(snapshot)
    definition_snapshot: dict[str, bytes] = {}
    for relative in BUILD_DEFINITION_RELS:
        path = root / PurePosixPath(relative)
        if not path.is_file():
            raise BuildFailure(f"build definition missing: {relative}")
        definition_snapshot[relative] = path.read_bytes()
    definition_metrics = {
        relative: metric(data) for relative, data in sorted(definition_snapshot.items())
    }

    tools = find_tools()
    environment = os.environ.copy()
    environment.update(
        {
            "SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH,
            "FORCE_SOURCE_DATE": "1",
            "MIKTEX_ENABLE_INSTALLER": "0",
            "TZ": "UTC",
        }
    )
    versions = tool_versions(tools, root, environment)

    with tempfile.TemporaryDirectory(prefix="oasi-article-verified-") as temporary:
        build_root = Path(temporary)
        outputs_a, validation_a = build_once(
            "A",
            build_root,
            snapshot,
            tools,
            versions,
            environment,
            arguments.phase,
            arguments.expected_article_doi,
            arguments.expected_pages,
        )
        outputs_b, validation_b = build_once(
            "B",
            build_root,
            snapshot,
            tools,
            versions,
            environment,
            arguments.phase,
            arguments.expected_article_doi,
            arguments.expected_pages,
        )
        compare_builds(outputs_a, outputs_b)

    assert_snapshot_unchanged(root, snapshot)
    assert_snapshot_unchanged(root, definition_snapshot)
    receipt = build_receipt(
        arguments.phase,
        source_manifest,
        definition_metrics,
        versions,
        outputs_a,
        validation_a,
        validation_b,
        arguments.expected_article_doi,
    )

    # Every expensive and semantic check has passed.  Promote generated assets
    # with per-file atomic replacement and publish the receipt last.
    for relative, data in sorted(outputs_a.items()):
        atomic_write(root / PurePosixPath(relative), data)
    atomic_write(root / PurePosixPath(SOURCE_MANIFEST_REL), source_manifest)
    atomic_write(root / PurePosixPath(RECEIPT_REL), receipt)

    for relative, expected in outputs_a.items():
        if sha256_path(root / PurePosixPath(relative)) != sha256_bytes(expected):
            raise BuildFailure(f"post-promotion hash mismatch: {relative}")
    if sha256_path(root / PurePosixPath(SOURCE_MANIFEST_REL)) != sha256_bytes(source_manifest):
        raise BuildFailure("post-promotion source-manifest hash mismatch")
    if sha256_path(root / PurePosixPath(RECEIPT_REL)) != sha256_bytes(receipt):
        raise BuildFailure("post-promotion receipt hash mismatch")

    summary = {
        "article": {"path": ARTICLE_REL, **metric(outputs_a[ARTICLE_REL])},
        "phase": arguments.phase,
        "receipt": {"path": RECEIPT_REL, **metric(receipt)},
        "source_manifest": {"path": SOURCE_MANIFEST_REL, **metric(source_manifest)},
        "status": "PASS_REPRODUCIBLE_ARTICLE_BUILD",
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BuildFailure as exc:
        print(json.dumps({"status": "FAIL_CLOSED", "error": str(exc)}, indent=2), file=sys.stderr)
        raise SystemExit(1)
