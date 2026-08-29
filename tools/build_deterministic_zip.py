#!/usr/bin/env python3
from pathlib import Path
import sys
import zipfile

if len(sys.argv) != 3:
    raise SystemExit("usage: build_deterministic_zip.py SOURCE_DIR OUTPUT.zip")

root = Path(sys.argv[1]).resolve()
output = Path(sys.argv[2]).resolve()
try:
    output.relative_to(root)
except ValueError:
    pass
else:
    raise SystemExit("OUTPUT.zip must be outside SOURCE_DIR")
excluded_parts = {".git", "target", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
files = sorted(
    (
        p for p in root.rglob("*")
        if p.is_file()
        and not excluded_parts.intersection(p.relative_to(root).parts)
        and p.suffix not in {".pyc", ".pyo"}
    ),
    key=lambda p: p.relative_to(root).as_posix(),
)

with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
    for path in files:
        relative = path.relative_to(root).as_posix()
        info = zipfile.ZipInfo(relative, (2026, 1, 1, 0, 0, 0))
        info.create_system = 3
        mode = 0o755 if path.suffix in {".py", ".sh"} else 0o644
        info.external_attr = (mode & 0xFFFF) << 16
        archive.writestr(info, path.read_bytes(), zipfile.ZIP_DEFLATED, 9)

print(output)
