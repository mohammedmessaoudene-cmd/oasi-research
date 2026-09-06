"""Standard-library passive v0.3 packaging check; does not execute legacy tests."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'experimental/bounded_service'))
from verify_portable import need, load, safe_name, sha, verify


def check():
    files = {}
    for base, dirs, names in os.walk(ROOT, followlinks=False):
        if Path(base) == ROOT and '.git' in dirs:
            dirs.remove('.git')
        for name in dirs + names:
            p = Path(base) / name
            s = p.lstat()
            need(not stat.S_ISLNK(s.st_mode) and not getattr(s, 'st_file_attributes', 0) & 0x400, 'REPARSE')
        for name in names:
            p = Path(base) / name
            rel = safe_name(p.relative_to(ROOT).as_posix())
            need(p.is_file() and p.stat().st_size < 30*1024**2, 'FILE_BOUND')
            files[rel] = p.read_bytes()
    need(sum(map(len, files.values())) < 30*1024**2, 'PAYLOAD_BOUND')
    listed = []
    for line in files['PUBLIC_MANIFEST.sha256'].decode().splitlines():
        expected, name = line.split('  ', 1)
        safe_name(name)
        need(name in files and sha(files[name]) == expected, 'HASH:' + name)
        listed.append(name)
    need(listed == sorted(set(listed)), 'MANIFEST_ORDER')
    need(set(files) == set(listed) | {'PUBLIC_MANIFEST.sha256'}, 'EXACT_FILESET')
    need(files['PUBLIC_ALLOWLIST.txt'].decode().splitlines() == sorted(files), 'ALLOWLIST')
    for name, data in files.items():
        need('__pycache__' not in name and not name.endswith(('.exe', '.dll', '.pyc')), 'BINARY_OR_CACHE')
        if name.endswith('.json'):
            load(data)
    meta = {'PUBLIC_MANIFEST.sha256', 'PUBLIC_ALLOWLIST.txt', 'LICENSE_INVENTORY.json', 'SBOM.spdx.json'}
    rows = load(files['LICENSE_INVENTORY.json'])['files']
    need([r['path'] for r in rows] == sorted(set(files) - meta), 'LICENSE_COVERAGE')
    need(all(sha(files[r['path']]) == r['sha256'] for r in rows), 'LICENSE_HASH')
    sbom = load(files['SBOM.spdx.json'])
    need([r['fileName'][2:] for r in sbom['files']] == [r['path'] for r in rows], 'SBOM_COVERAGE')
    for r in sbom['files']:
        need(r['checksums'] == [{'algorithm': 'SHA256', 'checksumValue': sha(files[r['fileName'][2:]])}], 'SBOM_HASH')
    source = load(files['experimental/bounded_service/SOURCE_PROVENANCE.json'])
    for r in source['source_files']:
        raw = files['experimental/bounded_service/' + r['path']]
        need(len(raw) == r['bytes'] and sha(raw) == r['sha256'], 'FROZEN_SOURCE_COPY')
    evidence = verify(files['experimental/bounded_service/BOUNDED_SERVICE_PUBLIC_EVIDENCE.zip'])
    need(b'0.3.0-research-preview' in files['CITATION.cff'], 'CITATION_VERSION')
    need(b'\ndoi:' not in files['CITATION.cff'] and b'\nidentifiers:' not in files['CITATION.cff'], 'UNASSIGNED_DOI')
    return dict(status='PASS_V0_3_PUBLICATION_PAYLOAD', files=len(files), evidence=evidence,
                binaries_distributed=False, runtime_executed=False, legacy_suite_reexecuted=False,
                owner_license_confirmation_pending=True)


if __name__ == '__main__':
    try:
        print(json.dumps(check(), indent=2))
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print(json.dumps(dict(status='FAIL_CLOSED', reason=str(exc))))
        sys.exit(1)
