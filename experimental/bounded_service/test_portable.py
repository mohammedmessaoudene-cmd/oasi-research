"""Adversarial tests of the new passive verifier, not new service executions."""
import copy
import io
import unittest
import zipfile
from pathlib import Path
from verify_portable import PREFIX, Q, canonical, chain_from, load, read_archive, sha, verify, verify_files

BASE = Path(__file__).resolve().parent
EVIDENCE = BASE / 'BOUNDED_SERVICE_PUBLIC_EVIDENCE.zip'
if not EVIDENCE.exists():
    EVIDENCE = BASE / 'evidence_prepared/BOUNDED_SERVICE_PUBLIC_EVIDENCE.zip'


def rechain(files, entries):
    files = dict(files)
    previous = None
    for name, entry in entries:
        entry['previous'] = previous
        raw = canonical(entry)
        files[Q + 'workspace/snapshots/' + name] = raw
        previous = dict(name=name, sha256=sha(raw))
    files[Q + 'workspace/current.json'] = canonical(previous)
    return files


class PortableTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = EVIDENCE.read_bytes()
        cls.files = read_archive(cls.raw)

    def mutate(self, fn, error):
        entries = copy.deepcopy(chain_from(self.files))
        fn(entries)
        with self.assertRaisesRegex(ValueError, error):
            verify_files(rechain(self.files, entries))

    def test_green(self):
        self.assertEqual(verify(self.raw)['results'], 15)

    def test_over_budget_with_rehashed_chain(self):
        def change(c):
            c[-1][1]['state']['budget']['reservations'].append(dict(slot=17, job='last_a', run=2, binding='0'*64))
        self.mutate(change, 'BUDGET_OVERRUN')

    def test_refund_even_after_rehash(self):
        def change(c):
            c[-1][1]['state']['budget']['work_started'].pop()
        self.mutate(change, 'HISTORY_REFUND_OR_MUTATION')

    def test_duplicate_start(self):
        def change(c):
            c[-1][1]['state']['budget']['work_started'].append(16)
        self.mutate(change, 'DOUBLE_START_OR_CLAIM')

    def test_wrong_binding(self):
        def change(c):
            c[-1][1]['state']['budget']['reservations'][0]['binding'] = '0'*64
        self.mutate(change, 'RESERVATION_BINDING')

    def test_wrong_result_at_first_commit(self):
        def change(c):
            for _, entry in c:
                for j in entry['state']['jobs'].values():
                    if j['status'] == 'SUCCEEDED':
                        j['result']['sha256'] = '0'*64
        self.mutate(change, 'RESULT_MISMATCH')

    def test_wrong_count_at_first_commit(self):
        def change(c):
            for _, entry in c:
                for j in entry['state']['jobs'].values():
                    if j['status'] == 'SUCCEEDED':
                        j['result']['statistics']['error_tokens'] += 1
        self.mutate(change, 'COUNT_MISMATCH')

    def test_wrong_path_even_with_new_binding(self):
        def change(c):
            for _, entry in c:
                s = entry['state']
                for j in s['jobs'].values():
                    j['path'] = '/not-a-fixture'
                for r in s['budget']['reservations']:
                    j = s['jobs'][r['job']]
                    r['binding'] = sha(canonical({k: j[k] for k in ('id', 'path', 'pin', 'task')}))
        self.mutate(change, 'JOB_SCOPE')

    def test_policy_bool_not_int(self):
        self.mutate(lambda c: c[0][1]['state']['budget'].update(schema=True), 'BUDGET_POLICY')

    def test_orphan(self):
        files = dict(self.files)
        files[Q + 'workspace/snapshots/' + 'f'*32 + '.json'] = b'{}'
        with self.assertRaisesRegex(ValueError, 'ORPHAN_SNAPSHOT'):
            verify_files(files)

    def test_fixture_corruption(self):
        files = dict(self.files)
        name = Q + 'fixtures/boundary.log'
        files[name] = files[name] + b'X'
        with self.assertRaisesRegex(ValueError, 'CORPUS_HASH'):
            verify_files(files)

    def test_unknown_coverage(self):
        files = dict(self.files)
        name = Q + 'commands/001.json'
        row = load(files[name]); row['args'] += ['--task', 'SHA256']
        files[name] = canonical(row)
        with self.assertRaisesRegex(ValueError, 'COVERAGE_DRIFT'):
            verify_files(files)

    def test_duplicate_and_nonfinite_json(self):
        for value in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}'):
            with self.assertRaises(ValueError):
                load(value)

    def test_paths(self):
        from verify_portable import safe_name
        for name in ('../x', '/x', 'a/../b', 'a\\b', 'C:/x', 'a/NUL.txt', 'a./b', 'a//b'):
            with self.assertRaises(ValueError, msg=name):
                safe_name(name)

    def test_duplicate_zip_member(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as z:
            z.writestr('a', b'1'); z.writestr('A', b'2')
        with self.assertRaisesRegex(ValueError, 'DUPLICATE_MEMBER'):
            read_archive(buf.getvalue())

    def test_manifest_tamper(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(self.raw)) as src, zipfile.ZipFile(buf, 'w') as dst:
            for info in src.infolist():
                data = src.read(info)
                if info.filename.endswith('CORPUS.json'):
                    data += b' '
                dst.writestr(info, data)
        with self.assertRaisesRegex(ValueError, 'MANIFEST_HASH'):
            read_archive(buf.getvalue())


if __name__ == '__main__':
    unittest.main(verbosity=2)
