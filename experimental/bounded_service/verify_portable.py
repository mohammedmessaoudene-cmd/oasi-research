"""Passive OASI archive oracle. Standard library only; never imports the service.

Recorded paths are opaque identities, never filesystem locations to open.
Checks archive integrity and the budget/result subset, not AERA/learning correctness.
"""
import argparse
import collections
import hashlib
import io
import json
from pathlib import Path
import re
import stat
import sys
import zipfile

PREFIX = 'OASI_BOUNDED_SERVICE/'
Q = PREFIX + 'qualification_01/'
HEX = re.compile(r'[0-9a-f]{64}')
SNAP = re.compile(r'[0-9a-f]{32}\.json')
MAX_TOTAL = 64 * 1024 * 1024


def need(condition, code):
    if not condition:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, 'DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def load(raw):
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('NONFINITE_JSON')))


def safe_name(name):
    need(isinstance(name, str) and 0 < len(name) < 240, 'PATH_LENGTH')
    need(not name.startswith('/') and '\\' not in name and ':' not in name, 'UNSAFE_PATH')
    for part in name.split('/'):
        need(part not in ('', '.', '..') and part == part.rstrip(' .'), 'UNSAFE_PATH')
        need(not any(ord(c) < 32 for c in part), 'UNSAFE_PATH')
        need(not re.fullmatch(r'(?i)(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\..*)?', part), 'DEVICE_PATH')
    return name


def read_archive(raw):
    need(len(raw) <= MAX_TOTAL, 'ARCHIVE_TOO_LARGE')
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        infos = z.infolist()
        need(0 < len(infos) <= 2000, 'MEMBER_COUNT')
        names = [safe_name(i.filename) for i in infos]
        need(len(names) == len(set(n.casefold() for n in names)), 'DUPLICATE_MEMBER')
        need(sum(i.file_size for i in infos) <= MAX_TOTAL, 'EXPANSION_BOUND')
        for i in infos:
            need(not i.flag_bits & 1 and stat.S_ISREG(i.external_attr >> 16), 'MEMBER_TYPE')
            need(i.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED), 'COMPRESSION')
        files = {i.filename: z.read(i) for i in infos}  # CRC checked on each read
    manifest_name = PREFIX + 'MANIFEST.sha256'
    need(manifest_name in files, 'MISSING_MANIFEST')
    listed = []
    for line in files[manifest_name].decode('utf-8').splitlines():
        h, rel = line.split('  ', 1)
        safe_name(rel)
        need(HEX.fullmatch(h) is not None, 'MANIFEST_HASH_SYNTAX')
        name = PREFIX + rel
        need(name in files and sha(files[name]) == h, 'MANIFEST_HASH')
        listed.append(name)
    need(listed == sorted(set(listed)), 'MANIFEST_ORDER_OR_DUPLICATE')
    need(set(files) == set(listed) | {manifest_name}, 'MANIFEST_COVERAGE')
    return files


def chain_from(files):
    pointer = load(files[Q + 'workspace/current.json'])
    chain = []
    seen = set()
    while pointer is not None:
        need(isinstance(pointer, dict) and set(pointer) == {'name', 'sha256'}, 'POINTER_SCHEMA')
        name = pointer['name']
        need(isinstance(name, str) and SNAP.fullmatch(name) is not None, 'POINTER_PATH')
        need(name not in seen, 'CYCLE')
        seen.add(name)
        raw = files[Q + 'workspace/snapshots/' + name]
        need(sha(raw) == pointer['sha256'], 'SNAPSHOT_HASH')
        entry = load(raw)
        need(set(entry) == {'state', 'previous', 'event'}, 'ENVELOPE')
        chain.append((name, entry))
        pointer = entry['previous']
    actual = {n.removeprefix(Q + 'workspace/snapshots/') for n in files
              if n.startswith(Q + 'workspace/snapshots/')}
    need(actual == seen, 'ORPHAN_SNAPSHOT')
    need(len(chain) == 168, 'CAMPAIGN_SNAPSHOT_COUNT')
    return list(reversed(chain))


def verify_files(files):
    chain = chain_from(files)
    root = chain[0][1]['state']['budget']['input_root']
    need(isinstance(root, str) and len(root) > 0, 'ROOT_IDENTITY')
    rows = load(files[Q + 'fixtures/CORPUS.json'])['files']
    need(len(rows) == 13, 'CORPUS_COUNT')
    buffers = {}
    names = set()
    for row in rows:
        name = safe_name(row['path'])
        need('/' not in name and name.casefold() not in names, 'CORPUS_PATH')
        names.add(name.casefold())
        raw = files[Q + 'fixtures/' + name]
        need(type(row['bytes']) is int and len(raw) == row['bytes'] <= 524288
             and sha(raw) == row['sha256'], 'CORPUS_HASH')
        # Explicit lexical mapping; no Path.resolve, environment, or external I/O.
        separator = '\\' if '\\' in root else '/'
        buffers[root + separator + name] = raw
    old = None
    commits = {}
    learning_events = 0
    decisions = set()
    interrupted = set()
    for _, entry in chain:
        s = entry['state']
        b = s['budget']
        need(set(b) == {'schema', 'limit', 'input_root', 'reservations', 'launch_claims', 'work_started'}, 'BUDGET_SCHEMA')
        need(type(b['schema']) is int and b['schema'] == 1 and type(b['limit']) is int and b['limit'] == 16, 'BUDGET_POLICY')
        need(b['input_root'] == root, 'ROOT_BINDING')
        reservations = b['reservations']
        need(isinstance(reservations, list) and len(reservations) <= 16, 'BUDGET_OVERRUN')
        for slot, r in enumerate(reservations, 1):
            need(set(r) == {'slot', 'job', 'run', 'binding'}, 'RESERVATION_SCHEMA')
            need(type(r['slot']) is int and r['slot'] == slot and type(r['run']) is int and r['run'] >= 1, 'SLOT_ORDER')
            j = s['jobs'][r['job']]
            need(r['binding'] == sha(canonical({k: j[k] for k in ('id', 'path', 'pin', 'task')})), 'RESERVATION_BINDING')
        need(len({(r['job'], r['run']) for r in reservations}) == len(reservations), 'DOUBLE_RESERVATION')
        for field in ('launch_claims', 'work_started'):
            values = b[field]
            need(isinstance(values, list) and len(values) == len(set(values)), 'DOUBLE_START_OR_CLAIM')
            need(all(type(v) is int and 1 <= v <= len(reservations) for v in values), 'UNRESERVED_LAUNCH')
        need(set(b['work_started']) <= set(b['launch_claims']), 'START_BEFORE_CLAIM')
        if old is not None:
            for field in ('reservations', 'launch_claims', 'work_started'):
                before = old['budget'][field]
                need(b[field][:len(before)] == before and len(b[field]) >= len(before), 'HISTORY_REFUND_OR_MUTATION')
                delta = len(b[field]) - len(before)
                need(delta in (0, 1), 'MULTIPLE_ADMISSION_OR_LAUNCH')
                events = {'reservations': ('SUBMIT', 'RESUME'), 'launch_claims': ('CLAIM',), 'work_started': ('BOUNDED_WORK_START',)}
                need(not delta or entry['event'] in events[field], 'ADMISSION_EVENT')
            need(set(old['jobs']) <= set(s['jobs']), 'JOB_REMOVED')
        for key, j in s['jobs'].items():
            need(key == j['id'] and j['task'] == 'HASH_COUNT_LOCAL' and j['path'] in buffers, 'JOB_SCOPE')
            need(type(j['pin']['size']) is int and j['pin']['size'] == len(buffers[j['path']]), 'JOB_PIN_SIZE')
            slot = j['budget_slot']
            need(type(slot) is int and 1 <= slot <= len(reservations), 'JOB_SLOT')
            r = reservations[slot - 1]
            need(r['job'] == key and r['run'] in (j['run'], j['run'] + 1), 'JOB_RESERVATION')
            if j['status'] in ('RUNNING', 'PAUSED', 'PAUSE_REQUESTED', 'CANCEL_REQUESTED', 'SUCCEEDED'):
                need(slot in b['launch_claims'] and r['run'] == j['run'], 'JOB_NOT_ADMITTED')
            if j['status'] == 'INTERRUPTED' and slot in b['work_started']:
                interrupted.add((key, j['run']))
            prior = old['jobs'].get(key) if old else None
            if prior and prior['status'] == 'SUCCEEDED':
                need(j == prior, 'TERMINAL_MUTATION')
            if j['status'] == 'SUCCEEDED' and (not prior or prior['status'] != 'SUCCEEDED'):
                need(key not in commits and slot in b['work_started'] and entry['event'] == 'RESULT_COMMIT', 'DOUBLE_OR_UNSTARTED_RESULT')
                raw = buffers[j['path']]
                result = j['result']
                need(result['sha256'] == sha(raw) and type(result['bytes']) is int and result['bytes'] == len(raw), 'RESULT_MISMATCH')
                stats = dict(bytes=len(raw), newlines=raw.count(b'\n'), error_tokens=raw.count(b'ERROR'),
                             warning_tokens=raw.count(b'WARN'), nul_bytes=raw.count(b'\0'),
                             lines=raw.count(b'\n') + int(bool(raw) and not raw.endswith(b'\n')))
                need(result['statistics'] == stats and all(type(v) is int for v in result['statistics'].values()), 'COUNT_MISMATCH')
                need(result['task'] == 'HASH_COUNT_LOCAL' and result['execution_boundary'] == 'HOST_COOPERATIVE_NOT_QEMU', 'RESULT_SCOPE')
                commits[key] = slot
        learning_events += entry['event'] == 'EXECUTE_OBSERVE_LEARN'
        for d in s.get('operating', {}).get('trace', []):
            if d['stage'] == 'OBSERVE_DECIDE_GUARD':
                decisions.add((d['observation']['epoch'], d['seq']))
        old = s
    counts = [len(old['budget'][k]) for k in ('reservations', 'launch_claims', 'work_started')]
    need(counts == [16, 16, 16] and len(commits) == len(old['jobs']) == 15, 'FINAL_COUNTS')
    need(len(interrupted) == 1, 'INTERRUPTION_COUNT')
    need(learning_events == len(decisions) == 28, 'TRACE_COUNT')
    commands = [load(v) for n, v in files.items() if n.startswith(Q + 'commands/') and n.endswith('.json')]
    codes = collections.Counter(c['returncode'] for c in commands)
    need(len(commands) == 70 and codes == {0: 62, 3: 6, 75: 2}, 'COMMAND_COUNTS')
    need(not any('--task' in c['args'] and c['args'][c['args'].index('--task') + 1] == 'SHA256' for c in commands), 'COVERAGE_DRIFT')
    return dict(status='PASS_PORTABLE_BUDGET_RESULT_RECORD_CHECK', snapshots=len(chain),
                reservations=16, claims=16, work_started=16, results=15, interrupted_started_runs=1,
                corpus_files=13, decisions_counted=28, learning_events_counted=28, commands=70,
                return_codes=dict(codes), standalone_sha256_submissions=0,
                candidate_executed=False, learning_algorithm_verified=False, aera_verified=False,
                external_reproduction=False, power_loss_tested=False, scientific_advantage='NOT_ESTABLISHED')


def verify(raw):
    return verify_files(read_archive(raw))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('archive', type=Path)
    p.add_argument('--sha256', help='Optional separately obtained expected archive SHA-256')
    args = p.parse_args()
    try:
        need(args.archive.stat().st_size <= MAX_TOTAL, 'ARCHIVE_TOO_LARGE')
        for node in (args.archive.absolute(), *args.archive.absolute().parents):
            s = node.lstat()
            need(not stat.S_ISLNK(s.st_mode) and not getattr(s, 'st_file_attributes', 0) & 0x400, 'REPARSE')
        raw = args.archive.read_bytes()
        if args.sha256:
            need(sha(raw) == args.sha256, 'ARCHIVE_PIN')
        print(json.dumps(verify(raw), indent=2))
        return 0
    except (ValueError, KeyError, TypeError, IndexError, OSError, zipfile.BadZipFile) as exc:
        print(json.dumps({'status': 'FAIL_CLOSED', 'reason': str(exc)}))
        return 1


if __name__ == '__main__':
    sys.exit(main())
