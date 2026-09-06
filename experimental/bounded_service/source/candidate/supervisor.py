"""Read-only SHA-256 jobs with persistent state and bounded cooperative workers."""
import concurrent.futures
import ctypes
import hashlib
import os
from pathlib import Path
import stat
import threading
import time
import uuid
from storage import Store,Lock,Rejected,Busy,safe_path
import cumulative_budget as budget

ACTIVE={'RUNNING','PAUSED','PAUSE_REQUESTED','CANCEL_REQUESTED'}
TERMINAL={'SUCCEEDED','FAILED','CANCELLED'}


def file_pin(path):
    p=safe_path(path)
    if os.name=='nt':
        if ':' in str(p)[2:]:raise Rejected('Flux alternatif interdit')
        drive_type=ctypes.windll.kernel32.GetDriveTypeW
        drive_type.argtypes=[ctypes.c_wchar_p];drive_type.restype=ctypes.c_uint
        if drive_type(str(p.anchor))==4:raise Rejected('Lecteur réseau interdit')
    s=p.stat()
    if not stat.S_ISREG(s.st_mode) or s.st_size>2*1024**3:raise Rejected('Choisir un fichier régulier de 2 Gio maximum')
    return str(p),{'device':s.st_dev,'inode':s.st_ino,'size':s.st_size,'mtime_ns':s.st_mtime_ns}


def resource_sample():
    data={'cpu_count':os.cpu_count() or 1,'memory_load_pct':None}
    if os.name=='nt':
        class Mem(ctypes.Structure):
            _fields_=[('length',ctypes.c_ulong),('load',ctypes.c_ulong)]+[(n,ctypes.c_ulonglong) for n in ('total','avail','page','availpage','virtual','availvirtual','extended')]
        m=Mem();m.length=ctypes.sizeof(m)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m)):
            data.update(memory_load_pct=int(m.load),available_memory_bytes=int(m.avail))
    return data


def allowed_workers(sample,maximum):
    load=sample.get('memory_load_pct')
    if load is None:return 1,'Mémoire non mesurée : limite prudente à 1 worker'
    if load>=95:return 0,'Mémoire >=95% : nouveaux démarrages suspendus'
    if load>=85:return 1,'Mémoire >=85% : limite à 1 worker'
    return min(maximum,max(1,sample['cpu_count']),2),'Ressources disponibles ; maximum 2 workers'


class Supervisor:
    def __init__(self,root):
        self.engine=None
        for _ in range(100):
            try:self.store=Store(root);break
            except Busy:time.sleep(.02)
        else:raise Busy('Journal occupé au démarrage')

    def submit(self,path,key=None,task='SHA256'):
        name,pin=file_pin(path);key=key or uuid.uuid4().hex
        if task not in budget.TASKS:raise Rejected('TASK_OUTSIDE_SCOPE')
        if pin['size']>524288:raise Rejected('FIXTURE_SIZE_EXCEEDED')
        if task!='SHA256' and pin['size']>524288:raise Rejected('Journal : 512 Kio maximum')
        if not isinstance(key,str) or not 1<=len(key)<=80 or not all(c.isalnum() or c in '-_' for c in key):raise Rejected('Identifiant invalide')
        incident_spec=None;incident_hash=None
        if task=='INCIDENT_FIXTURE':
            from incident_controller import validate_spec
            with open(name,'rb') as f:raw=f.read(65537)
            incident_spec=validate_spec(raw);incident_hash=hashlib.sha256(raw).hexdigest()
        def insert(s):
            if key in s['jobs']:
                j=s['jobs'][key]
                if j['path']!=name or j['pin']!=pin or j.get('task','SHA256')!=task:raise Rejected('Identifiant déjà lié à une autre entrée')
                if incident_spec and j.get('expected_sha256')!=incident_hash:raise Rejected('Contenu incident modifié')
                return key
            s['jobs'][key]={'id':key,'path':name,'pin':pin,'status':'QUEUED','bytes_done':0,
                'result':None,'error':None,'run':0,'epoch':None,'submitted':time.time(),'task':task}
            if incident_spec:s['jobs'][key].update(incident_mode=incident_spec['mode'],expected_sha256=incident_hash)
            budget.reserve(s,s['jobs'][key])
            return key
        return self.store.edit('SUBMIT',insert)

    def control(self,key,action):
        def modify(s):
            j=s['jobs'][key];status=j['status']
            if j.get('mission_id') and action in ('pause','resume'):j['mission_hold']=action=='pause'
            if action=='pause':
                if status=='QUEUED':j['status']='HELD'
                elif status=='RUNNING':j['status']='PAUSE_REQUESTED'
            elif action=='resume':
                if status=='INTERRUPTED':
                    budget.reserve(s,j)
                    j['status']='QUEUED'
                elif status=='HELD':j['status']='QUEUED'
                elif status in ('PAUSED','PAUSE_REQUESTED'):j['status']='RUNNING'
            elif action=='cancel':
                if status in ('QUEUED','HELD','INTERRUPTED'):j['status']='CANCELLED'
                elif status in ACTIVE:j['status']='CANCEL_REQUESTED'
            else:raise Rejected('Commande inconnue')
        self.store.edit(action.upper(),modify)

    def pause_queue(self,value):self.store.edit('QUEUE_PAUSE',lambda s:s.update(paused=bool(value)))

    def set_workers(self,value):
        if type(value) is not int or value not in (1,2):raise Rejected('Choisir 1 ou 2 workers')
        self.store.edit('WORKER_LIMIT',lambda s:s.update(max_workers=value))

    def start(self):
        if self.engine:raise Rejected('Moteur déjà démarré')
        self.engine=Engine(self.store);return self.engine


class Engine:
    def __init__(self,store,resource_fn=resource_sample,read_hook=None,commit_hook=None,learning_mode='adaptive'):
        self.store=store;self.lock=Lock(store.root/'engine.lock');self.lock.__enter__()
        self.resource_fn=resource_fn;self.read_hook=read_hook;self.commit_hook=commit_hook
        self.stop=threading.Event();self.futures={};self.error=None;self.resources={};self.reason='Initialisation'
        try:
            def recovery(s):
                s['epoch']+=1
                for j in s['jobs'].values():
                    if j['status']=='CANCEL_REQUESTED':
                        j['status']='CANCELLED';j['error']=None
                    elif j['status'] in ACTIVE:
                        j['status']='INTERRUPTED';j['error']='Interruption : résultat non confirmé. Reprise manuelle relira le fichier.'
                return s['epoch']
            self.epoch=self._edit_retry('START_AND_RECOVER',recovery)
            from operating_loop import OperatingLoop
            self.operating=OperatingLoop(store,self.epoch,self.resource_fn,learning_mode=learning_mode)
            self.pool=concurrent.futures.ThreadPoolExecutor(max_workers=2)
            self.thread=threading.Thread(target=self._loop,name='oasi-supervisor',daemon=True);self.thread.start()
        except BaseException:
            if hasattr(self,'operating'):self.operating.close()
            self.lock.__exit__();raise

    def _edit_retry(self,event,fn):
        for _ in range(100):
            try:return self.store.edit(event,fn)
            except Busy:time.sleep(.02)
        raise Busy('Journal occupé trop longtemps')

    def _view_retry(self):
        for _ in range(100):
            try:return self.store.view()
            except Busy:time.sleep(.02)
        raise Busy('Journal occupé trop longtemps')

    def _loop(self):
        try:
            while not self.stop.is_set():
                for key,f in list(self.futures.items()):
                    if f.done():f.result();del self.futures[key]
                s=self._view_retry()
                if s['epoch']!=self.epoch:raise Rejected('Époque du moteur périmée : arrêt')
                self.resources=self.resource_fn()
                limit,self.reason=allowed_workers(self.resources,s['max_workers'])
                if not s['paused']:
                    for key,j in s['jobs'].items():
                        if len(self.futures)>=limit:break
                        if j.get('task') in ('ANALYSE_JOURNAL','DIAGNOSTIC_GUARDIAN') and any(
                            s['jobs'][f].get('task') in ('ANALYSE_JOURNAL','DIAGNOSTIC_GUARDIAN') for f in self.futures):continue
                        if j['status']=='QUEUED' and key not in self.futures:
                            def claim(state,k=key):
                                job=state['jobs'][k]
                                if state['epoch']!=self.epoch or state['paused'] or job['status']!='QUEUED':return None
                                if job.get('mission_id'):
                                    from mission_service import permitted
                                    if not permitted(state,job):return None
                                budget.claim(state,job)
                                job.update(status='RUNNING',bytes_done=0,error=None,epoch=self.epoch,run=job['run']+1)
                                return dict(job)
                            job=self._edit_retry('CLAIM',claim)
                            if job:self.futures[key]=self.pool.submit(self._work,job)
                self.stop.wait(.2)
        except BaseException as e:
            self.error=str(e);self.stop.set()
        finally:
            self.pool.shutdown(wait=True)
            self.operating.close()
            self.lock.__exit__()

    def _work(self,original):
        key=original['id'];run=original['run'];last_progress=0.;done=0;mission_started=time.perf_counter_ns()
        def owns(s):
            j=s['jobs'][key]
            return s['epoch']==self.epoch and j['epoch']==self.epoch and j['run']==run
        def transition(status,**fields):
            def change(s):
                if owns(s) and s['jobs'][key]['status'] not in TERMINAL:s['jobs'][key].update(status=status,**fields)
            self._edit_retry(status,change)
        def gate():
            def check(s):
                if not owns(s):return 'STOP'
                j=s['jobs'][key]
                if j['status']=='CANCEL_REQUESTED':j['status']='CANCELLED';return 'STOP'
                if self.stop.is_set():
                    if j['status'] not in TERMINAL:j.update(status='INTERRUPTED',error='Arrêt du moteur ; reprise explicite requise')
                    return 'STOP'
                if j['status']=='PAUSE_REQUESTED':j.update(status='PAUSED',bytes_done=done)
                if j['status']=='PAUSED':return 'WAIT'
                if j.get('mission_id'):
                    from mission_service import permitted
                    if not permitted(s,j):raise Rejected('Mission expirée, bloquée ou dépendance invalide')
                return 'RUN' if j['status']=='RUNNING' else 'STOP'
            return self._edit_retry('CONTROL_ACK',check)
        try:
            self._edit_retry('BOUNDED_WORK_START',lambda s:budget.work_start(s,original))
            path,pin=file_pin(original['path'])
            if pin!=original['pin']:raise Rejected('Fichier modifié depuis sa soumission')
            task=original.get('task','SHA256');h=hashlib.sha256();is_log=task in ('ANALYSE_JOURNAL','DIAGNOSTIC_GUARDIAN')
            diagnostic_input=bytearray() if task.startswith('DIAGNOSTIC_') or task=='INCIDENT_FIXTURE' else None
            counts={'bytes':0,'newlines':0,'error_tokens':0,'warning_tokens':0,'nul_bytes':0}
            prefix=b'';isolated_once=False;receipts=[]
            with open(path,'rb') as f:
                fs=os.fstat(f.fileno())
                if (fs.st_dev,fs.st_ino,fs.st_size,fs.st_mtime_ns)!=(pin['device'],pin['inode'],pin['size'],pin['mtime_ns']):raise Rejected('Identité du fichier changée')
                while True:
                    decision=gate()
                    if decision=='STOP':return
                    if decision=='WAIT':self.stop.wait(.1);continue
                    if done>=pin['size'] and (not is_log or isolated_once):break
                    plan=self.operating.prepare(original)
                    if plan['status']=='STOP':return
                    if plan['status']=='WAIT':self.stop.wait(.1);continue
                    if not self.operating.revalidate(original,plan):continue
                    started=time.perf_counter_ns();block=f.read(plan['units'])
                    if not block and pin['size']!=0:raise Rejected('Fin de fichier prématurée')
                    if is_log:
                        import isolated_task
                        from storage import canonical
                        binding=hashlib.sha256(canonical({'job':key,'epoch':self.epoch,'run':run,
                            'seq':plan['seq'],'offset':done,'task':task,
                            'input':hashlib.sha256(block).hexdigest(),'prefix':hashlib.sha256(prefix).hexdigest()})).hexdigest()
                        report=isolated_task.run(block,prefix,plan['units'],binding,
                                                lambda:self.operating.revalidate(original,plan))
                        if report is None:return
                        self.operating.isolation_receipt(original,plan,report,binding,len(block))
                        for k in counts:counts[k]+=report['result'][k]
                        receipts.append({'binding':binding,'guest_log_sha256':report['guest_log_sha256'],
                                         'evidence':report['output'],'wall_ns':report['wall_ns']})
                        prefix=(prefix+block)[-4:];isolated_once=True
                    if task=='HASH_COUNT_LOCAL':
                        # Same measured/guarded worker path, no QEMU or external sink.
                        # Four prefix bytes retain tokens crossing chunk boundaries.
                        joined=prefix+block
                        counts['bytes']+=len(block)
                        counts['newlines']+=block.count(b'\n')
                        counts['nul_bytes']+=block.count(b'\0')
                        counts['error_tokens']+=joined.count(b'ERROR')-prefix.count(b'ERROR')
                        counts['warning_tokens']+=joined.count(b'WARN')-prefix.count(b'WARN')
                        prefix=joined[-4:]
                    h.update(block);done+=len(block)
                    if diagnostic_input is not None:
                        if len(diagnostic_input)+len(block)>524288:raise Rejected('Diagnostic hors bornes')
                        diagnostic_input.extend(block)
                    elapsed=time.perf_counter_ns()-started
                    if block and not self.operating.feedback(original,plan,len(block),max(1,elapsed)):return
                    if self.read_hook:self.read_hook(key,done)
                    if time.monotonic()-last_progress>=.5:
                        def progress(state):
                            if owns(state):state['jobs'][key]['bytes_done']=done
                        self._edit_retry('PROGRESS',progress);last_progress=time.monotonic()
                end=os.fstat(f.fileno())
                if (end.st_dev,end.st_ino,end.st_size,end.st_mtime_ns)!=(pin['device'],pin['inode'],pin['size'],pin['mtime_ns']):raise Rejected('Fichier modifié pendant la lecture')
            if file_pin(path)[1]!=pin:raise Rejected('Fichier remplacé pendant la lecture')
            if original.get('expected_sha256') and h.hexdigest()!=original['expected_sha256']:raise Rejected('Empreinte de mission divergente')
            diagnostic_result=None;incident_result=None
            if task=='INCIDENT_FIXTURE':
                from incident_controller import run as run_incident
                incident_result=run_incident(self,original,bytes(diagnostic_input),gate)
            elif diagnostic_input is not None:
                from diagnostic import analyze
                diagnostic_result=analyze(bytes(diagnostic_input))
                if diagnostic_result['input_sha256']!=h.hexdigest():raise Rejected('Diagnostic lié à une autre entrée')
            if self.commit_hook:self.commit_hook(key)
            while True:
                decision=gate()
                if decision=='STOP':return
                if decision=='WAIT':self.stop.wait(.1);continue
                def finish(s):
                    j=s['jobs'][key]
                    if not owns(s):return 'STOP'
                    if j['status']!='RUNNING':return 'RETRY'
                    if j['result'] is not None:raise Rejected('Résultat déjà présent')
                    if j.get('mission_id'):
                        from mission_service import permitted
                        if not permitted(s,j):raise Rejected('Mission invalide au commit atomique')
                    self.operating.result_gate(s,original)
                    self.operating.conserve(s,original,h.hexdigest(),done)
                    result={'sha256':h.hexdigest(),'bytes':done}
                    if original.get('mission_id'):result['mission_measurement']={'elapsed_ns':max(1,time.perf_counter_ns()-mission_started),'run':run}
                    if task=='HASH_COUNT_LOCAL':
                        result.update(task=task,statistics={**counts,'lines':counts['newlines']+int(done>0 and not prefix.endswith(b'\n'))},
                                      execution_boundary='HOST_COOPERATIVE_NOT_QEMU')
                    if is_log:
                        result.update(task=task,statistics={**counts,'lines':counts['newlines']+int(done>0 and not prefix.endswith(b'\n'))},
                                      isolation_receipts=receipts)
                    if diagnostic_result is not None:
                        result.update(task=task,diagnostic=diagnostic_result,
                                      diagnostic_execution='HOST_ADVISORY',guardian_precheck=is_log)
                    if incident_result is not None:
                        from incident_controller import learn_at_commit
                        learn_at_commit(s,original,incident_result)
                        result.update(task=task,incident=incident_result)
                    j.update(status='SUCCEEDED',bytes_done=done,result=result,error=None)
                    return 'DONE'
                if self._edit_retry('RESULT_COMMIT',finish)!='RETRY':return
        except (Rejected,OSError) as e:
            transition('FAILED',error=str(e))

    def close(self):self.stop.set();self.thread.join(timeout=15);return not self.thread.is_alive()
