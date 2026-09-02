#!/usr/bin/env python3
"""Independently verify exact contents and deterministic structure of release ZIPs."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import struct
import unicodedata
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


EXPECTED_TIMESTAMP = (2026, 9, 2, 0, 0, 0)
ALLOWED_PERMISSIONS = {0o644, 0o755}
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
EOCD_SIGNATURE = b"PK\x05\x06"
LOCAL_SIGNATURE = b"PK\x03\x04"


class BoundaryError(RuntimeError):
    """An archive boundary condition was not satisfied."""


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
    if PurePosixPath(name).is_absolute() or any(component in {"", ".", ".."} for component in components):
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
        text = path.read_bytes().decode("utf-8", errors="strict")
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


def stable_digest(path: Path, relative: str, expected: ExpectedFile) -> list[str]:
    errors: list[str] = []
    try:
        before = require_plain_file(path, f"source file {relative}")
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            value = hashlib.sha256()
            size = 0
            for chunk in iter(lambda: stream.read(1 << 20), b""):
                value.update(chunk)
                size += len(chunk)
            after_read = os.fstat(stream.fileno())
        after = require_plain_file(path, f"source file {relative}")
        for attribute in ("st_dev", "st_ino"):
            first = getattr(before, attribute, 0)
            second = getattr(opened, attribute, 0)
            third = getattr(after_read, attribute, 0)
            fourth = getattr(after, attribute, 0)
            nonzero = [item for item in (first, second, third, fourth) if item]
            if nonzero and len(set(nonzero)) != 1:
                errors.append(f"source identity changed during read: {relative}")
                break
        if before.st_size != after.st_size or getattr(before, "st_mtime_ns", None) != getattr(after, "st_mtime_ns", None):
            errors.append(f"source metadata changed during read: {relative}")
        if size != expected.size:
            errors.append(f"source size mismatch: {relative}")
        if value.hexdigest() != expected.sha256:
            errors.append(f"source SHA-256 mismatch: {relative}")
    except BoundaryError as exc:
        errors.append(str(exc))
    except OSError as exc:
        errors.append(f"cannot read source file {relative}: {type(exc).__name__}")
    return errors


def inspect_source(root: Path, expected: dict[str, ExpectedFile]) -> list[str]:
    errors: list[str] = []
    discovered: dict[str, Path] = {}
    try:
        require_plain_directory(root, "source directory")
    except BoundaryError as exc:
        return [str(exc)]
    stack = [root]
    while stack:
        directory = stack.pop()
        try:
            require_plain_directory(directory, "source directory entry")
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda item: item.name)
        except (BoundaryError, OSError) as exc:
            errors.append(str(exc))
            continue
        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            try:
                validate_portable_name(relative)
                status = entry.stat(follow_symlinks=False)
                if stat.S_ISLNK(status.st_mode) or is_reparse(status):
                    raise BoundaryError(f"symlink or reparse point rejected: {relative}")
                if stat.S_ISDIR(status.st_mode):
                    stack.append(path)
                elif stat.S_ISREG(status.st_mode):
                    discovered[relative] = path
                else:
                    raise BoundaryError(f"non-regular source entry rejected: {relative}")
            except (BoundaryError, OSError) as exc:
                errors.append(str(exc))

    normalized = [unicodedata.normalize("NFC", name).casefold() for name in discovered]
    if len(normalized) != len(set(normalized)):
        errors.append("source has a Unicode-normalization or casefold collision")
    missing = sorted(set(expected) - set(discovered))
    unlisted = sorted(set(discovered) - set(expected))
    if missing:
        errors.append("source files missing: " + json.dumps(missing, ensure_ascii=False))
    if unlisted:
        errors.append("source files not allowlisted: " + json.dumps(unlisted, ensure_ascii=False))
    for relative in sorted(set(expected) & set(discovered)):
        errors.extend(stable_digest(discovered[relative], relative, expected[relative]))
    return errors


def digest_file(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            value.update(chunk)
    return value.hexdigest()


def expected_name_bytes(info: zipfile.ZipInfo) -> bytes:
    if info.flag_bits & 0x800:
        return info.filename.encode("utf-8")
    return info.filename.encode("cp437")


def dos_datetime(value: tuple[int, int, int, int, int, int]) -> tuple[int, int]:
    year, month, day, hour, minute, second = value
    return (hour << 11) | (minute << 5) | (second // 2), ((year - 1980) << 9) | (month << 5) | day


def verify_eocd(stream, archive: zipfile.ZipFile, entry_count: int, errors: list[str]) -> int | None:
    stream.seek(0, os.SEEK_END)
    archive_size = stream.tell()
    if archive_size < 22:
        errors.append("archive is too short for EOCD")
        return None
    tail_size = min(archive_size, 22 + 65535)
    stream.seek(archive_size - tail_size)
    tail = stream.read(tail_size)
    relative_offset = tail.rfind(EOCD_SIGNATURE)
    if relative_offset < 0 or relative_offset + 22 > len(tail):
        errors.append("EOCD record missing")
        return None
    eocd_offset = archive_size - tail_size + relative_offset
    fields = struct.unpack("<4s4H2LH", tail[relative_offset : relative_offset + 22])
    _, disk, central_disk, disk_entries, total_entries, central_size, central_offset, comment_size = fields
    if eocd_offset + 22 + comment_size != archive_size:
        errors.append("trailing bytes or malformed EOCD comment length")
    if disk != 0 or central_disk != 0 or disk_entries != total_entries:
        errors.append("multi-disk ZIP is not permitted")
    if total_entries != entry_count:
        errors.append("EOCD entry count mismatch")
    if central_offset != archive.start_dir:
        errors.append("EOCD central-directory offset mismatch")
    if central_offset + central_size != eocd_offset:
        errors.append("central-directory size or trailing-gap mismatch")
    if comment_size != 0:
        errors.append("archive comment is not permitted")
    return eocd_offset


def verify_local_headers(
    stream,
    archive: zipfile.ZipFile,
    infos: list[zipfile.ZipInfo],
    errors: list[str],
) -> list[int | None]:
    expected_time, expected_date = dos_datetime(EXPECTED_TIMESTAMP)
    cursor = 0
    data_offsets: list[int | None] = []
    for info in infos:
        if info.header_offset != cursor:
            errors.append(f"local-record gap or overlap before: {info.filename}")
            cursor = info.header_offset
        stream.seek(info.header_offset)
        header = stream.read(30)
        if len(header) != 30:
            errors.append(f"truncated local header: {info.filename}")
            data_offsets.append(None)
            continue
        fields = struct.unpack("<4s5H3L2H", header)
        (
            signature,
            extract_version,
            flags,
            compression,
            mod_time,
            mod_date,
            crc32,
            compressed_size,
            file_size,
            name_size,
            extra_size,
        ) = fields
        raw_name = stream.read(name_size)
        raw_extra = stream.read(extra_size)
        if signature != LOCAL_SIGNATURE:
            errors.append(f"bad local-header signature: {info.filename}")
        if extract_version != 20 or info.extract_version != 20:
            errors.append(f"extract-version drift: {info.filename}")
        if flags != info.flag_bits or flags & ~0x800:
            errors.append(f"flag drift: {info.filename}: {hex(flags)}")
        if compression != zipfile.ZIP_DEFLATED or compression != info.compress_type:
            errors.append(f"local compression drift: {info.filename}")
        if mod_time != expected_time or mod_date != expected_date:
            errors.append(f"local timestamp drift: {info.filename}")
        if crc32 != info.CRC or compressed_size != info.compress_size or file_size != info.file_size:
            errors.append(f"local/central size or CRC mismatch: {info.filename}")
        if raw_name != expected_name_bytes(info):
            errors.append(f"local/central filename mismatch: {info.filename}")
        if raw_extra or extra_size != 0:
            errors.append(f"unexpected local extra field: {info.filename}")
        data_offsets.append(info.header_offset + 30 + name_size + extra_size)
        cursor = info.header_offset + 30 + name_size + extra_size + info.compress_size
    if cursor != archive.start_dir:
        errors.append("gap, overlap, or trailing data before central directory")
    return data_offsets


def verify_archive(path: Path, expected: dict[str, ExpectedFile]) -> dict[str, object]:
    errors: list[str] = []
    infos: list[zipfile.ZipInfo] = []
    total_uncompressed = 0
    archive_hash: str | None = None
    archive_size: int | None = None
    try:
        before = require_plain_file(path, "archive")
        archive_size = before.st_size
        archive_hash = digest_file(path)
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if before.st_dev and opened.st_dev and before.st_dev != opened.st_dev:
                errors.append("archive identity changed before verification")
            if before.st_ino and opened.st_ino and before.st_ino != opened.st_ino:
                errors.append("archive identity changed before verification")
            with zipfile.ZipFile(stream, "r", allowZip64=False) as archive:
                infos = archive.infolist()
                names = [info.filename for info in infos]
                expected_names = sorted(expected)
                if names != sorted(names):
                    errors.append("entries are not in ordinal path order")
                if len(names) != len(set(names)):
                    errors.append("duplicate entry name")
                normalized = [unicodedata.normalize("NFC", name).casefold() for name in names]
                if len(normalized) != len(set(normalized)):
                    errors.append("casefold or Unicode-normalization collision")
                if names != expected_names:
                    errors.append(
                        "archive/allowlist membership mismatch: "
                        + json.dumps(
                            {
                                "missing": sorted(set(expected_names) - set(names)),
                                "unlisted": sorted(set(names) - set(expected_names)),
                            },
                            ensure_ascii=False,
                            sort_keys=True,
                        )
                    )
                if archive.comment:
                    errors.append("unexpected archive comment")

                verify_eocd(stream, archive, len(infos), errors)
                data_offsets = verify_local_headers(stream, archive, infos, errors)
                for info_index, info in enumerate(infos):
                    name = info.filename
                    try:
                        validate_portable_name(name)
                    except BoundaryError as exc:
                        errors.append(str(exc))
                    if info.is_dir():
                        errors.append(f"unexpected directory entry: {name}")
                    if info.date_time != EXPECTED_TIMESTAMP:
                        errors.append(f"timestamp drift: {name}")
                    if info.create_system != 3 or info.create_version != 20:
                        errors.append(f"creator metadata drift: {name}")
                    raw_mode = (info.external_attr >> 16) & 0xFFFF
                    if stat.S_IFMT(raw_mode) != stat.S_IFREG:
                        errors.append(f"entry is not marked as a regular file: {name}: {oct(raw_mode)}")
                    if stat.S_IMODE(raw_mode) not in ALLOWED_PERMISSIONS:
                        errors.append(f"permission drift: {name}: {oct(stat.S_IMODE(raw_mode))}")
                    if info.external_attr & 0xFFFF:
                        errors.append(f"unexpected DOS attributes: {name}")
                    if info.internal_attr != 0:
                        errors.append(f"unexpected internal attributes: {name}")
                    if info.compress_type != zipfile.ZIP_DEFLATED:
                        errors.append(f"compression drift: {name}")
                    if info.flag_bits & ~0x800:
                        errors.append(f"unexpected ZIP flags: {name}: {hex(info.flag_bits)}")
                    if info.extra or info.comment:
                        errors.append(f"unexpected central entry metadata: {name}")

                    listed = expected.get(name)
                    if listed is None:
                        continue
                    if info.file_size != listed.size:
                        errors.append(f"member size does not match allowlist: {name}")
                    value = hashlib.sha256()
                    crc32 = 0
                    measured_size = 0
                    canonical_deflate = bytearray()
                    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
                    try:
                        with archive.open(info, "r") as member:
                            for chunk in iter(lambda: member.read(1 << 20), b""):
                                value.update(chunk)
                                crc32 = zlib.crc32(chunk, crc32)
                                measured_size += len(chunk)
                                canonical_deflate.extend(compressor.compress(chunk))
                        canonical_deflate.extend(compressor.flush())
                    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                        errors.append(f"member read failure: {name}: {type(exc).__name__}")
                        continue
                    if measured_size != listed.size or value.hexdigest() != listed.sha256:
                        errors.append(f"member bytes do not match allowlist: {name}")
                    if (crc32 & 0xFFFFFFFF) != info.CRC:
                        errors.append(f"member CRC metadata mismatch: {name}")
                    data_offset = data_offsets[info_index] if info_index < len(data_offsets) else None
                    if data_offset is None:
                        errors.append(f"compressed member offset unavailable: {name}")
                    else:
                        stream.seek(data_offset)
                        compressed_bytes = stream.read(info.compress_size)
                        if compressed_bytes != canonical_deflate:
                            errors.append(f"non-canonical fixed-level DEFLATE stream: {name}")
                    total_uncompressed += measured_size

                corrupt = archive.testzip()
                if corrupt is not None:
                    errors.append(f"CRC testzip failure: {corrupt}")
            after_read = os.fstat(stream.fileno())
        after = require_plain_file(path, "archive")
        if before.st_size != after.st_size or getattr(before, "st_mtime_ns", None) != getattr(after, "st_mtime_ns", None):
            errors.append("archive metadata changed during verification")
        if opened.st_dev and after_read.st_dev and opened.st_dev != after_read.st_dev:
            errors.append("archive identity changed during verification")
        if opened.st_ino and after_read.st_ino and opened.st_ino != after_read.st_ino:
            errors.append("archive identity changed during verification")
        if archive_hash is not None and digest_file(path) != archive_hash:
            errors.append("archive bytes changed during verification")
    except BoundaryError as exc:
        errors.append(str(exc))
    except (OSError, EOFError, struct.error, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        errors.append(f"invalid ZIP: {type(exc).__name__}")

    return {
        "bytes": archive_size,
        "entries": len(infos),
        "errors": errors,
        "pass": not errors,
        "path": str(path),
        "sha256": archive_hash,
        "uncompressed_bytes": total_uncompressed,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify deterministic ZIP structure and exact allowlisted member bytes.",
        epilog=(
            "ALLOWLIST is mandatory canonical UTF-8/LF. Each line is: <64 lowercase SHA-256 hex> "
            "two spaces <decimal byte size> two spaces <NFC POSIX relative path>, in unique ordinal "
            "order. --source additionally verifies exact source membership, hashes, regular-file type, "
            "absence of symlinks/reparse points, and absence of VCS/build/cache/bytecode paths before "
            "checking the archive."
        ),
    )
    parser.add_argument("archives", type=Path, nargs="+", metavar="ARCHIVE.zip")
    parser.add_argument("--allowlist", required=True, type=Path, metavar="FILE")
    parser.add_argument("--source", type=Path, metavar="SOURCE_DIR")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    allowlist = absolute(args.allowlist)
    global_errors: list[str] = []
    try:
        expected = parse_allowlist(allowlist)
    except BoundaryError as exc:
        expected = {}
        global_errors.append(str(exc))

    source_value: str | None = None
    if args.source is not None:
        source = absolute(args.source)
        source_value = str(source)
        if expected:
            global_errors.extend(inspect_source(source, expected))
        else:
            global_errors.append("source verification skipped because allowlist is invalid")

    results = [verify_archive(absolute(argument), expected) for argument in args.archives] if expected else []
    passed = not global_errors and bool(results) and all(result["pass"] for result in results)
    print(
        json.dumps(
            {
                "allowlist": str(allowlist),
                "archives": results,
                "errors": global_errors,
                "pass": passed,
                "source": source_value,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
