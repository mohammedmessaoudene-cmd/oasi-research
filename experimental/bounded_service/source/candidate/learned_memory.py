"""Receipt-derived hints. Checksums detect damage, not a hostile local account.

No authorization, compiled reflex, lease or live decision is returned here.
Storage atomicity is supplied by the existing Store snapshot transaction.
"""
import hashlib
import math
import platform
import re
from pathlib import Path
from storage import Rejected, canonical

BASE = Path(__file__).parent
SCHEMA = 1
POLICY = 'sha256-local-read-cost-v1'
HEX = re.compile(r'[0-9a-f]{64}')
PAYLOAD_KEYS = {'schema', 'purpose', 'context', 'model_ns_per_byte', 'samples',
                'total_bytes', 'total_elapsed_ns', 'receipt_chain', 'result_sha256'}


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def code_identity():
    return digest({name: hashlib.sha256((BASE/name).read_bytes()).hexdigest()
                   for name in ('learned_memory.py', 'operating_loop.py', 'supervisor.py',
                                'diagnostic.py','isolated_task.py','native/model.rs', 'native/guardian_bridge.rs')})


def context_identity(sample, job, code=None):
    """Observed class only: not machine attestation or a disk durability claim."""
    cpu = sample.get('cpu_count')
    load = sample.get('memory_load_pct')
    source = sample.get('source', 'WINDOWS_LIVE')
    if type(cpu) is not int or not 1 <= cpu <= 65536:
        raise Rejected('Identité CPU non mesurée')
    if load is not None and (type(load) not in (int, float) or not math.isfinite(load) or not 0 <= load <= 100):
        raise Rejected('Identité mémoire invalide')
    if not isinstance(source, str) or not 1 <= len(source) <= 128:
        raise Rejected('Identité du capteur invalide')
    device = job['pin']['device']
    if type(device) is not int or device < 0: raise Rejected('Classe de stockage invalide')
    return digest({'policy': POLICY, 'task':job.get('task','SHA256'), 'code': code or code_identity(),
                   'system': platform.system(), 'release': platform.release(),
                   'machine_class': platform.machine(), 'python': platform.python_version(),
                   'cpu_count': cpu, 'sensor_source': source,
                   'memory_class': 'UNKNOWN' if load is None else ('PRESSURE' if load >= 85 else 'NORMAL'),
                   'device_class': digest(device)})


def accumulate(previous, context, epoch, run, seq, count, elapsed_ns):
    if not isinstance(context, str) or not HEX.fullmatch(context): raise Rejected('Contexte invalide')
    if any(type(n) is not int or n <= 0 for n in (epoch, run, seq, count, elapsed_ns)):
        raise Rejected('Provenance non entière ou non positive')
    if count > 524288 or elapsed_ns > 2**63-1: raise Rejected('Observation hors bornes')
    same = previous and (previous['context'], previous['epoch'], previous['run']) == (context, epoch, run)
    if same and seq <= previous['seq']: raise Rejected('Provenance répétée')
    prior = previous if same else {'samples': 0, 'total_bytes': 0, 'total_elapsed_ns': 0, 'receipt_chain': '0'*64}
    receipt = {'context': context, 'epoch': epoch, 'run': run, 'seq': seq, 'bytes': count, 'elapsed_ns': elapsed_ns}
    return {'context': context, 'epoch': epoch, 'run': run, 'seq': seq,
            'samples': prior['samples']+1, 'total_bytes': prior['total_bytes']+count,
            'total_elapsed_ns': prior['total_elapsed_ns']+elapsed_ns,
            'receipt_chain': digest({'previous': prior['receipt_chain'], 'receipt': receipt})}


def seal(summary, result_sha256, expected_bytes):
    # Only a full successful read under one context supplies a reusable candidate.
    if summary['total_bytes'] != expected_bytes: raise Rejected('Connaissance partielle')
    payload = {key: summary[key] for key in ('context', 'samples', 'total_bytes', 'total_elapsed_ns', 'receipt_chain')}
    payload.update(schema=SCHEMA, purpose=POLICY, result_sha256=result_sha256,
                   model_ns_per_byte=summary['total_elapsed_ns']/summary['total_bytes'])
    record = {'payload': payload, 'sha256': digest(payload)}
    if inspect_record(record, summary['context'])[0] is None: raise Rejected('Connaissance hors bornes')
    return record


def inspect_record(record, context):
    """Return an untrusted pending candidate, never an approved model."""
    if record is None: return None, 'ABSENT'
    try:
        if not isinstance(record, dict) or set(record) != {'payload', 'sha256'}: return None, 'SCHEMA_INVALID'
        p = record['payload']
        if not isinstance(p, dict) or set(p) != PAYLOAD_KEYS: return None, 'SCHEMA_INVALID'
        if type(p['schema']) is not int or p['schema'] != SCHEMA or p['purpose'] != POLICY: return None, 'SCHEMA_INVALID'
        if any(not isinstance(p[k], str) or not HEX.fullmatch(p[k]) for k in ('context', 'receipt_chain', 'result_sha256')):
            return None, 'PROVENANCE_INVALID'
        for key, limit in (('samples', 32768), ('total_bytes', 2*1024**3), ('total_elapsed_ns', 2**63-1)):
            if type(p[key]) is not int or not 1 <= p[key] <= limit: return None, 'BOUNDS_INVALID'
        cost = p['model_ns_per_byte']
        if type(cost) not in (int, float) or not math.isfinite(cost) or not .01 <= cost <= 1e6: return None, 'BOUNDS_INVALID'
        if p['samples'] > p['total_bytes'] or p['total_bytes'] > p['samples']*524288: return None, 'BOUNDS_INVALID'
        if cost != p['total_elapsed_ns']/p['total_bytes']: return None, 'SUMMARY_INCONSISTENT'
        if not isinstance(record['sha256'], str) or record['sha256'] != digest(p): return None, 'CHECKSUM_MISMATCH'
        if p['context'] != context: return None, 'CONTEXT_MISMATCH'
        return dict(p), 'PENDING_REVALIDATION'
    except (ValueError, TypeError, KeyError, OverflowError):
        return None, 'MALFORMED'


def begin_runtime(record, context, epoch, run):
    candidate, reason = inspect_record(record, context)
    return {'context': context, 'epoch': epoch, 'run': run,
            'status': 'PENDING_REVALIDATION' if candidate else ('ABSENT' if reason == 'ABSENT' else 'REVOKED'),
            'reason': reason, 'candidate': candidate, 'model_ns_per_byte': 300.0,
            'samples': 0, 'candidate_sha256': record['sha256'] if candidate else None}


def fresh_observation(runtime, count, elapsed_ns):
    """Bounded heuristic, not a statistical or hardware-stability guarantee."""
    if type(count) is not int or type(elapsed_ns) is not int or count <= 0 or elapsed_ns <= 0:
        raise Rejected('Observation fraîche invalide')
    raw = elapsed_ns/count
    measured = max(.01, min(1e6, raw))
    runtime['samples'] += 1
    if runtime['status'] == 'PENDING_REVALIDATION':
        if count < 65536:
            runtime['reason'] = 'INSUFFICIENT_FRESH_BYTES'
            return
        prior = runtime['candidate']['model_ns_per_byte']
        # Fixed before evaluation. Tolerance avoids equating noisy latency with attack.
        if .01 <= raw <= 1e6 and .25 <= raw/prior <= 4:
            runtime.update(status='REVALIDATED', reason='FRESH_RECEIPT_WITHIN_FACTOR_4',
                           model_ns_per_byte=max(prior, raw))
        else:
            runtime.update(status='REVOKED', reason='OBSERVATION_DIVERGED',
                           model_ns_per_byte=300.0, candidate=None)
    else:
        runtime['model_ns_per_byte'] = .5*runtime['model_ns_per_byte']+.5*measured
