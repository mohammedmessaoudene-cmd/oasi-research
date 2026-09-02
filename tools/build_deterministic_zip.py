#!/usr/bin/env python3
"""Build a fail-closed ZIP from an out-of-tree, project-reviewed allowlist."""
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
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


EXPECTED_TIMESTAMP = (2026, 9, 2, 0, 0, 0)
WINDOWS_FORBIDDEN_CHARS = frozenset('<>:"|?*')
WINDOWS_RESERVED_STEMS = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{number}" for number in range(1, 10)}
    | {f"LPT{number}" for number in range(1, 10)}
)
FORBIDDEN_COMPONENTS = frozenset(
    {".git", "target", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
)
FORBIDDEN_SUFFIXES = (".pyc", ".pyo")


class BoundaryError(RuntimeError):
    """A release boundary condition was not satisfied."""


@dataclass(frozen=True)
class ExpectedFile:
    sha256: str
    size: int


def absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def is_reparse(status: os.stat_result) -> bool:
    attributes = getattr(status, "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def require_plain_file(path: Path, label: str) -> os.stat_result:
    try:
        status = os.lstat(path)
    except OSError as exc:
        raise BoundaryError(f"{label} is not readable: {type(exc).__name__}") from exc
    if stat.S_ISLNK(status.st_mode) or is_reparse(status):
        raise BoundaryError(f"{label} must not be a symlink or reparse point: {path}")
    if not stat.S_ISREG(status.st_mode):
        raise BoundaryError(f"{label} is not a regular file: {path}")
    return status


def require_plain_directory(path: Path, label: str) -> os.stat_result:
    try:
        status = os.lstat(path)
    except OSError as exc:
        raise BoundaryError(f"{label} is not readable: {type(exc).__name__}") from exc
    if stat.S_ISLNK(status.st_mode) or is_reparse(status):
        raise BoundaryError(f"{label} must not be a symlink or reparse point: {path}")
    if not stat.S_ISDIR(status.st_mode):
        raise BoundaryError(f"{label} is not a directory: {path}")
    return status


def validate_portable_name(name: str) -> None:
    if not name or name != unicodedata.normalize("NFC", name):
        raise BoundaryError(f"non-canonical archive path: {name!r}")
    if name.startswith("/") or "\\" in name or re.match(r"^[A-Za-z]:", name):
        raise BoundaryError(f"unsafe archive path: {name!r}")
    components = name.split("/")
    pure = PurePosixPath(name)
    if any(component in {"", ".", ".."} for component in components) or pure.is_absolute():
        raise BoundaryError(f"unsafe archive path: {name!r}")
    for component in components:
        if component in FORBIDDEN_COMPONENTS:
            raise BoundaryError(f"forbidden release path component: {component!r}")
        if component.endswith((" ", ".")):
            raise BoundaryError(f"non-portable archive component: {component!r}")
        if any(ord(character) < 32 or character in WINDOWS_FORBIDDEN_CHARS for character in component):
            raise BoundaryError(f"non-portable archive component: {component!r}")
        if component.split(".", 1)[0].upper() in WINDOWS_RESERVED_STEMS:
            raise BoundaryError(f"reserved archive component: {component!r}")
    if name.lower().endswith(FORBIDDEN_SUFFIXES):
        raise BoundaryError(f"forbidden generated-file suffix: {name!r}")


def parse_allowlist(path: Path) -> dict[str, ExpectedFile]:
    require_plain_file(path, "allowlist")
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        raise BoundaryError(f"invalid UTF-8 allowlist: {type(exc).__name__}") from exc
    if not text or not text.endswith("\n") or "\r" in text:
        raise BoundaryError("allowlist must be non-empty canonical LF text ending in LF")

    expected: dict[str, ExpectedFile] = {}
    ordered_names: list[str] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = re.fullmatch(r"([0-9a-f]{64})  (0|[1-9][0-9]*)  (.+)", line)
        if not match:
            raise BoundaryError(
                f"allowlist line {line_number} must be '<lowercase-sha256>  <bytes>  <POSIX-path>'"
            )
        sha256, size_text, name = match.groups()
        validate_portable_name(name)
        if name in expected:
            raise BoundaryError(f"duplicate allowlist path: {name}")
        expected[name] = ExpectedFile(sha256=sha256, size=int(size_text))
        ordered_names.append(name)

    if ordered_names != sorted(ordered_names):
        raise BoundaryError("allowlist paths must be in ordinal order")
    normalized = [unicodedata.normalize("NFC", name).casefold() for name in ordered_names]
    if len(normalized) != len(set(normalized)):
        raise BoundaryError("allowlist has a Unicode-normalization or casefold collision")
    return expected


def inspect_source(root: Path) -> dict[str, Path]:
    require_plain_directory(root, "source directory")
    discovered: dict[str, Path] = {}
    stack = [root]
    while stack:
        directory = stack.pop()
        require_plain_directory(directory, "source directory entry")
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda item: item.name)
        except OSError as exc:
            raise BoundaryError(f"cannot enumerate source directory: {type(exc).__name__}") from exc
        for entry in entries:
            path = Path(entry.path)
            try:
                status = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise BoundaryError(f"cannot stat source entry: {path}: {type(exc).__name__}") from exc
            relative = path.relative_to(root).as_posix()
            validate_portable_name(relative)
            if stat.S_ISLNK(status.st_mode) or is_reparse(status):
                raise BoundaryError(f"symlink or reparse point rejected: {relative}")
            if stat.S_ISDIR(status.st_mode):
                stack.append(path)
            elif stat.S_ISREG(status.st_mode):
                discovered[relative] = path
            else:
                raise BoundaryError(f"non-regular source entry rejected: {relative}")

    normalized = [unicodedata.normalize("NFC", name).casefold() for name in discovered]
    if len(normalized) != len(set(normalized)):
        raise BoundaryError("source has a Unicode-normalization or casefold collision")
    return discovered


def same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    for attribute in ("st_dev", "st_ino"):
        a = getattr(left, attribute, 0)
        b = getattr(right, attribute, 0)
        if a and b and a != b:
            return False
    return True


def read_stable(path: Path, relative: str, expected: ExpectedFile) -> bytes:
    before = require_plain_file(path, f"source file {relative}")
    try:
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if not same_identity(before, opened) or not stat.S_ISREG(opened.st_mode):
                raise BoundaryError(f"source identity changed before read: {relative}")
            data = stream.read()
            after_read = os.fstat(stream.fileno())
    except OSError as exc:
        raise BoundaryError(f"cannot read source file {relative}: {type(exc).__name__}") from exc
    after = require_plain_file(path, f"source file {relative}")
    if not same_identity(before, after) or not same_identity(opened, after_read):
        raise BoundaryError(f"source identity changed during read: {relative}")
    if before.st_size != after.st_size or getattr(before, "st_mtime_ns", None) != getattr(after, "st_mtime_ns", None):
        raise BoundaryError(f"source metadata changed during read: {relative}")
    actual_hash = hashlib.sha256(data).hexdigest()
    if len(data) != expected.size or actual_hash != expected.sha256:
        raise BoundaryError(f"source content does not match allowlist: {relative}")
    return data


def is_within(candidate: Path, parent: Path) -> bool:
    try:
        candidate.relative_to(parent)
        return True
    except ValueError:
        return False


def canonical_mode(path: Path) -> int:
    return 0o755 if path.suffix.lower() in {".py", ".sh"} else 0o644


def write_partial(
    partial: Path,
    root: Path,
    expected: dict[str, ExpectedFile],
    discovered: dict[str, Path],
) -> None:
    with partial.open("x+b") as output_stream:
        with zipfile.ZipFile(
            output_stream,
            mode="w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
            allowZip64=False,
            strict_timestamps=True,
        ) as archive:
            archive.comment = b""
            for relative in sorted(expected):
                path = discovered[relative]
                data = read_stable(path, relative, expected[relative])
                info = zipfile.ZipInfo(relative, EXPECTED_TIMESTAMP)
                info.create_system = 3
                info.create_version = 20
                info.extract_version = 20
                info.compress_type = zipfile.ZIP_DEFLATED
                info.internal_attr = 0
                info.external_attr = (stat.S_IFREG | canonical_mode(path)) << 16
                info.extra = b""
                info.comment = b""
                archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
        output_stream.flush()
        os.fsync(output_stream.fileno())


def invoke_independent_verifier(archive: Path, allowlist: Path, source: Path) -> dict[str, object]:
    verifier = Path(__file__).resolve().with_name("verify_archive.py")
    require_plain_file(verifier, "independent archive verifier")
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            str(verifier),
            "--allowlist",
            str(allowlist),
            "--source",
            str(source),
            str(archive),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        detail = (completed.stdout + "\n" + completed.stderr).strip()
        raise BoundaryError(f"independent archive verification failed: {detail[:2000]}")
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise BoundaryError("independent archive verifier returned invalid JSON") from exc
    if result.get("pass") is not True:
        raise BoundaryError("independent archive verifier did not return pass=true")
    return result


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            value.update(chunk)
    return value.hexdigest()


def fsync_parent_when_supported(path: Path) -> None:
    """Persist the rename boundary on platforms exposing directory fsync."""
    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a deterministic release ZIP from an exact external allowlist.",
        epilog=(
            "ALLOWLIST is mandatory, must be outside SOURCE_DIR, and must be canonical UTF-8/LF. "
            "Each non-empty line is: <64 lowercase SHA-256 hex> two spaces <decimal byte size> "
            "two spaces <NFC POSIX relative path>. Lines must be unique and ordinally sorted. "
            "Every regular file under SOURCE_DIR must occur exactly once; symlinks, reparse points, "
            "special files, unsafe paths, missing files, unlisted files, VCS metadata, build outputs, "
            "caches, and Python bytecode are rejected."
        ),
    )
    parser.add_argument("source", type=Path, metavar="SOURCE_DIR")
    parser.add_argument("output", type=Path, metavar="OUTPUT.zip")
    parser.add_argument("--allowlist", required=True, type=Path, metavar="FILE")
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="permit atomic replacement of an existing regular output file (default: refuse)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = absolute(args.source)
    output = absolute(args.output)
    allowlist = absolute(args.allowlist)
    partial = output.with_name(output.name + ".partial")

    require_plain_directory(root, "source directory")
    require_plain_file(allowlist, "allowlist")
    require_plain_directory(output.parent, "output parent directory")
    if is_within(output, root) or is_within(partial, root):
        raise BoundaryError("output and partial output must be outside SOURCE_DIR")
    if is_within(allowlist, root):
        raise BoundaryError("allowlist is control input and must be outside SOURCE_DIR")
    if output.suffix.lower() != ".zip":
        raise BoundaryError("output filename must end in .zip")
    if partial.exists() or os.path.lexists(partial):
        raise BoundaryError(f"partial output already exists: {partial}")
    if output.exists() or os.path.lexists(output):
        if not args.overwrite:
            raise BoundaryError(f"output already exists (use --overwrite explicitly): {output}")
        require_plain_file(output, "existing output")

    expected = parse_allowlist(allowlist)
    discovered = inspect_source(root)
    missing = sorted(set(expected) - set(discovered))
    unlisted = sorted(set(discovered) - set(expected))
    if missing or unlisted:
        raise BoundaryError(
            "source/allowlist mismatch: "
            + json.dumps({"missing": missing, "unlisted": unlisted}, ensure_ascii=False, sort_keys=True)
        )

    # Validate every source byte before creating any output.
    for relative in sorted(expected):
        read_stable(discovered[relative], relative, expected[relative])

    write_partial(partial, root, expected, discovered)
    partial_hash = digest(partial)
    invoke_independent_verifier(partial, allowlist, root)
    if not args.overwrite and (output.exists() or os.path.lexists(output)):
        raise BoundaryError(f"output appeared during build; preserving verified partial: {output}")
    os.replace(partial, output)
    with output.open("r+b") as committed:
        os.fsync(committed.fileno())
    fsync_parent_when_supported(output.parent)
    final_result = invoke_independent_verifier(output, allowlist, root)
    if digest(output) != partial_hash:
        raise BoundaryError("archive hash changed across atomic replacement")

    print(
        json.dumps(
            {
                "allowlist": str(allowlist),
                "bytes": output.stat().st_size,
                "entries": len(expected),
                "output": str(output),
                "pass": True,
                "sha256": partial_hash,
                "verification": final_result,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BoundaryError as exc:
        print(json.dumps({"pass": False, "error": str(exc)}, indent=2, sort_keys=True), file=sys.stderr)
        raise SystemExit(1)
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        print(
            json.dumps(
                {"pass": False, "error": f"{type(exc).__name__}: {exc}"},
                indent=2,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        raise SystemExit(1)
