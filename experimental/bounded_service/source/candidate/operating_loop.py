"""Observation -> learned prediction -> reflex -> published AERA gate -> receipt.

Read-only local work only. Software decision scopes are not human confirmations,
cryptographic grants or historical nonces. The host account remains trusted.
"""
import hashlib
import copy
import json
from pathlib import Path
import queue
import subprocess
import threading
import time
from storage import Busy,Rejected,canonical,safe_path
from learned_memory import code_identity, context_identity, accumulate, seal, begin_runtime, fresh_observation

BASE=Path(__file__).parent
MODEL_PIN='d40e12310c617a0e9bc3b4c2279e119479454224cfa50f4073b3d27bc1d724dd'
UNITS=(65536,262144,524288)


class AeraCore:
    """Persistent bounded pipe to the actual, unchanged published Rust model."""
    def __init__(self):
        pin=json.loads((BASE/'native/CURRENT.json').read_text(encoding='utf-8'))
        exe=safe_path(BASE/pin['executable'])
        if not exe.is_relative_to(BASE):raise Rejected('Binaire hors du paquet')
        if hashlib.sha256((BASE/'native/model.rs').read_bytes()).hexdigest()!=MODEL_PIN:raise Rejected('Source AERA modifiée')
        if hashlib.sha256((BASE/'native/guardian_bridge.rs').read_bytes()).hexdigest()!=pin['bridge_source_sha256']:raise Rejected('Adaptateur non compilé ou modifié')
        if hashlib.sha256(exe.read_bytes()).hexdigest()!=pin['sha256']:raise Rejected('Binaire AERA modifié')
        flags=getattr(subprocess,'CREATE_NO_WINDOW',0)
        self.p=subprocess.Popen([str(exe)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,creationflags=flags)
        self.lock=threading.Lock();self.responses=queue.Queue(maxsize=4)
        self.reader=threading.Thread(target=self._reader,daemon=True);self.reader.start()

    def _reader(self):
        while True:
            raw=self.p.stdout.readline(1025)
            if not raw:self.responses.put(None);return
            if len(raw)>1024 or not raw.endswith(b'\n'):self.responses.put(None);return
            self.responses.put(raw.decode('ascii').strip())

    def call(self,op,args):
        if op not in ('G','C') or any(type(x) is not int or x<0 or x>=2**64 for x in args):raise Rejected('Entrée AERA invalide')
        wire=(op+' '+' '.join(map(str,args))+'\n').encode('ascii')
        if len(wire)>1024:raise Rejected('Entrée AERA trop longue')
        with self.lock:
            try:
                self.p.stdin.write(wire);self.p.stdin.flush();result=self.responses.get(timeout=3)
            except (OSError,queue.Empty) as exc:raise Rejected('Noyau AERA indisponible : aucun fallback') from exc
            if result is None or result.startswith('ERROR'):raise Rejected('Noyau AERA : '+str(result))
            return result

    def compile(self,units,policy,resource):
        reply=self.call('C',[units,policy,1,resource,units,1_000_000_000])
        if reply!=f'COMPILED {units}':raise Rejected('Reflex non conforme')

    def validate(self,body,lease,request):return self.call('G',list(body)+list(lease)+list(request))

    def close(self):
        if self.p.stdin:
            try:self.p.stdin.close()
            except OSError:pass
        try:self.p.wait(timeout=3)
        except subprocess.TimeoutExpired:self.p.kill();self.p.wait(timeout=3)
        self.reader.join(timeout=1);self.p.stdout.close()


def resource_id(job):return int(hashlib.sha256(canonical({'id':job['id'],'path':job['path'],'pin':job['pin'],'task':job.get('task','SHA256')})).hexdigest()[:15],16)


class OperatingLoop:
    def __init__(self,store,epoch,resource_fn,learning_mode='adaptive'):
        if learning_mode not in ('adaptive','classical_cache_same_algorithm','frozen_model_300_ns_per_byte','cold_memory'):
            raise Rejected('Mode de qualification inconnu')
        self.learning_mode=learning_mode
        self.store=store;self.epoch=epoch;self.resource_fn=resource_fn;self.core=AeraCore()
        self.uid=int(hashlib.sha256(str(store.root).encode()).hexdigest()[:15],16)
        try:
            self.memory_code = code_identity()
            def init(s):
                s['operating']={'schema':1,'session_epoch':epoch,'model_ns_per_byte':300.0,
                                'model_version':0,'samples':0,'target_ms':50,'decision_seq':0,
                                'compiled_reflexes':{},'trace':[],'last_observation':None}
                s['operating']['knowledge_candidate'] = copy.deepcopy(s.get('knowledge'))
                s['operating']['learning_mode'] = self.learning_mode
                s['operating']['knowledge_status'] = 'NOT_YET_OBSERVED'
            self.edit('OPERATING_START',init)
        except BaseException:self.core.close();raise

    def edit(self,event,fn):
        for _ in range(100):
            try:return self.store.edit(event,fn)
            except Busy:time.sleep(.02)
        raise Busy('Journal occupé')

    def owns(self,s,j):
        active=s['jobs'][j['id']]
        return s['epoch']==self.epoch and active['epoch']==self.epoch and active['run']==j['run']

    @staticmethod
    def note(s,event):
        # Full history remains in immutable snapshots; this is a bounded UI tail.
        s['operating']['trace']=(s['operating']['trace']+[event])[-32:]

    def prepare(self,job):
        sample=self.resource_fn();load=sample.get('memory_load_pct')
        if load is not None and (type(load) not in (int,float) or not 0<=load<=100):raise Rejected('Capteur mémoire invalide')
        def choose(s):
            j=s['jobs'][job['id']];o=s['operating']
            if not self.owns(s,job) or j['status'] not in ('RUNNING','PAUSE_REQUESTED','PAUSED'):return {'status':'STOP'}
            if j['status']!='RUNNING':return {'status':'WAIT'}
            observation={'memory_load_pct':load,'cpu_count':sample.get('cpu_count'),
                         'source':sample.get('source','WINDOWS_LIVE'),'epoch':self.epoch}
            if load is not None and load>=95:
                if o['last_observation']!=observation:
                    self.note(s,{'stage':'REFLEX_WAIT','reason':'MEMORY_PRESSURE','observation':observation})
                    o['last_observation']=observation
                return {'status':'WAIT'}
            context = context_identity(sample, job, self.memory_code)
            runtime = j.get('runtime_learning')
            if not runtime or (runtime['epoch'], runtime['run']) != (self.epoch, job['run']):
                remembered = o['knowledge_candidate'] if self.learning_mode in ('adaptive','classical_cache_same_algorithm') else None
                runtime = begin_runtime(remembered, context, self.epoch, job['run'])
                j['runtime_learning'] = runtime
                self.note(s, {'stage': 'KNOWLEDGE_INSPECTED', 'job': job['id'], 'epoch': self.epoch,
                              'run': job['run'], 'status': runtime['status'], 'reason': runtime['reason']})
            elif runtime['context'] != context:
                runtime.update(context=context, status='REVOKED', reason='RUNTIME_CONTEXT_CHANGED',
                               model_ns_per_byte=300.0, samples=0, candidate=None)
                self.note(s, {'stage': 'KNOWLEDGE_REVOKED', 'job': job['id'], 'reason': runtime['reason']})
            o['model_ns_per_byte'] = runtime['model_ns_per_byte']
            if self.learning_mode=='frozen_model_300_ns_per_byte':
                runtime['model_ns_per_byte']=o['model_ns_per_byte']=300.0
            o['knowledge_status'] = runtime['status']; o['knowledge_reason'] = runtime['reason']
            candidates=(UNITS[0],) if load is None or load>=85 else UNITS
            eligible=[n for n in candidates if n*o['model_ns_per_byte']<=o['target_ms']*1e6]
            units=max(eligible) if eligible else min(candidates)
            predicted_ns=units*o['model_ns_per_byte'];rid=resource_id(job);cache_key=f'{rid}:{units}'
            reused=cache_key in o['compiled_reflexes']
            seq=o['decision_seq']+1
            if not reused:
                self.core.compile(units,seq,rid);o['compiled_reflexes'][cache_key]=seq
            now=time.monotonic_ns();body=[self.uid,self.epoch,job['run'],1,0]
            lease=[self.uid,self.epoch,job['run'],1,now+1_000_000_000,1,rid,units]
            request=[time.monotonic_ns(),1,rid,units]
            verdict=self.core.validate(body,lease,request)
            if verdict!='ALLOW':raise Rejected('AERA '+verdict)
            o['decision_seq']=seq;o['last_observation']=observation
            decision={'status':'ALLOW','seq':seq,'units':units,'predicted_ns':predicted_ns,
                      'model_version':o['model_version'],'reflex_reused':reused,'resource':rid,
                      'body':body,'lease':lease,'observation':observation,'job':job['id']}
            decision.update(learning_mode=self.learning_mode,knowledge_context=context, knowledge_status=runtime['status'],
                            knowledge_reason=runtime['reason'], model_ns_per_byte=runtime['model_ns_per_byte'])
            j['active_decision']=decision
            self.note(s,{'stage':'OBSERVE_DECIDE_GUARD','aera':verdict,**decision})
            return decision
        return self.edit('OBSERVE_DECIDE_GUARD',choose)

    def revalidate(self,job,decision):
        def check(s):
            j=s['jobs'][job['id']]
            if not self.owns(s,job) or j['status']!='RUNNING':return False
            if j.get('active_decision')!=decision:raise Rejected('Décision remplacée')
            body=[self.uid,s['epoch'],j['run'],1,0]
            reply=self.core.validate(body,decision['lease'],[time.monotonic_ns(),1,resource_id(j),decision['units']])
            if reply!='ALLOW':raise Rejected('Décision périmée : '+reply)
            return True
        return self.edit('PRE_READ_REVALIDATE',check)

    def feedback(self,job,decision,count,elapsed_ns):
        def learn(s):
            j=s['jobs'][job['id']];o=s['operating']
            if not self.owns(s,job):return False
            same_read=j.get('last_receipt_epoch')==self.epoch and j.get('last_receipt_run')==job['run']
            if j.get('active_decision')!=decision or (same_read and decision['seq']<=j.get('last_receipt_seq',0)):raise Rejected('Reçu périmé ou répété')
            if type(count) is not int or type(elapsed_ns) is not int or count<=0 or count>decision['units'] or elapsed_ns<=0 or elapsed_ns>2**63-1:raise Rejected('Reçu hors bornes')
            runtime = j['runtime_learning']
            if (runtime['epoch'], runtime['run'], runtime['context']) != (self.epoch, job['run'], decision['knowledge_context']):
                raise Rejected('Contexte du reçu périmé')
            before=runtime['model_ns_per_byte']; previous_status=runtime['status']
            if self.learning_mode=='frozen_model_300_ns_per_byte':
                runtime['samples']+=1  # Observation retained; decision model not trained.
            else:
                fresh_observation(runtime, count, elapsed_ns)
            o['model_ns_per_byte']=runtime['model_ns_per_byte'];o['samples']+=1;o['model_version']+=1
            o['knowledge_status']=runtime['status'];o['knowledge_reason']=runtime['reason']
            if previous_status != runtime['status']:
                self.note(s, {'stage': 'KNOWLEDGE_REVALIDATION', 'job': job['id'], 'epoch': self.epoch,
                              'run': job['run'], 'seq': decision['seq'], 'status': runtime['status'],
                              'reason': runtime['reason'], 'candidate_sha256': runtime['candidate_sha256'],
                              'fresh_ns_per_byte': elapsed_ns/count, 'model_after': runtime['model_ns_per_byte']})
            j['learning_receipts'] = accumulate(j.get('learning_receipts'), decision['knowledge_context'],
                                               self.epoch, job['run'], decision['seq'], count, elapsed_ns)
            j['last_receipt_seq']=decision['seq'];j['last_receipt_epoch']=self.epoch;j['last_receipt_run']=job['run'];j['active_decision']=None
            self.note(s,{'stage':'EXECUTE_OBSERVE_LEARN','job':job['id'],'seq':decision['seq'],
                         'bytes':count,'elapsed_ns':elapsed_ns,'model_before':before,
                         'model_after':o['model_ns_per_byte'],'model_version':o['model_version']})
            return True
        return self.edit('EXECUTE_OBSERVE_LEARN',learn)

    def result_gate(self,s,job):
        j=s['jobs'][job['id']];now=time.monotonic_ns();rid=resource_id(job)
        if j.get('task') in ('ANALYSE_JOURNAL','DIAGNOSTIC_GUARDIAN'):
            proof=j.get('isolation_coverage')
            if not proof or (proof['epoch'],proof['run'],proof['bytes'])!=(self.epoch,job['run'],j['pin']['size']):
                raise Rejected('Couverture guardian incomplète')
        lease=[self.uid,self.epoch,job['run'],1,now+1_000_000_000,1,rid,1]
        decision=self.core.validate([self.uid,s['epoch'],j['run'],1,0],lease,[time.monotonic_ns(),1,resource_id(j),1])
        if decision!='ALLOW':raise Rejected('Résultat refusé par AERA : '+decision)
        self.note(s,{'stage':'RESULT_GUARD','job':job['id'],'aera':decision,'model_version':s['operating']['model_version']})

    def isolation_receipt(self,job,decision,report,binding,count):
        def attach(s):
            j=s['jobs'][job['id']]
            if not self.owns(s,job) or j.get('active_decision')!=decision:raise Rejected('Reçu guardian périmé')
            proof=j.get('isolation_coverage')
            if not proof or (proof['epoch'],proof['run'])!=(self.epoch,job['run']):
                proof={'epoch':self.epoch,'run':job['run'],'bytes':0,'seq':0,'chain':'0'*64}
            if decision['seq']<=proof['seq']:raise Rejected('Reçu guardian répété')
            if report['binding']!=binding or report['verdict']!='PASS_ISOLATED_BLOCK' or not report['qemu_reaped']:
                raise Rejected('Reçu guardian invalide')
            proof.update(bytes=proof['bytes']+count,seq=decision['seq'],
                         chain=hashlib.sha256(canonical({'previous':proof['chain'],'binding':binding,'receipt':report})).hexdigest())
            j['isolation_coverage']=proof
            self.note(s,{'stage':'ISOLATED_GUARDIAN_RECEIPT','job':job['id'],'seq':decision['seq'],
                         'binding':binding,'bytes':count,'guest_log_sha256':report['guest_log_sha256'],
                         'epoch':self.epoch,'run':job['run'],'evidence':report['output']})
        self.edit('ISOLATED_GUARDIAN_RECEIPT',attach)

    def conserve(self, s, job, result_sha256, count):
        summary = s['jobs'][job['id']].get('learning_receipts')
        if not summary or (summary['epoch'], summary['run']) != (self.epoch, job['run']): return
        try:
            record = seal(summary, result_sha256, count)
        except Rejected as exc:
            self.note(s, {'stage': 'KNOWLEDGE_NOT_SAVED', 'reason': str(exc)})
            return  # Loss of a hint must not invalidate a successful authorized read.
        s['knowledge'] = record
        # Only a candidate for the next job; live runtime/leases stay unchanged.
        s['operating']['knowledge_candidate'] = copy.deepcopy(record)
        self.note(s, {'stage': 'KNOWLEDGE_SAVED_PENDING_REVALIDATION', 'sha256': record['sha256'],
                      'samples': summary['samples']})

    def close(self):self.core.close()
