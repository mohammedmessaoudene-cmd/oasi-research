"""Bounded incident task, run by the existing Engine; actions affect owned child only."""
import copy,hashlib,json,os,queue,subprocess,sys,threading,time
from pathlib import Path
from storage import Rejected,canonical,unique_pairs
from fixture_service import validate_world

def hashobj(x):return hashlib.sha256(canonical(x)).hexdigest()
def code_identity():
    root=Path(__file__).parent
    return hashobj({n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in ('incident_controller.py','fixture_service.py','classical_policy.py','supervisor.py','storage.py')})
def validate_spec(raw):
    if len(raw)>65536:raise Rejected('incident input limit')
    try:
        s=json.loads(raw,object_pairs_hook=unique_pairs)
        if set(s)!={'schema','id','world','payloads','mode'} or type(s['schema']) is not int or s['schema']!=1:raise ValueError('schema')
        if not isinstance(s['id'],str) or not 1<=len(s['id'])<=40 or not all(c in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-' for c in s['id']):raise ValueError('id')
        validate_world(s['world'])
        if not isinstance(s['payloads'],list) or not 1<=len(s['payloads'])<=8 or any(not isinstance(p,str) or len(p)>1024 for p in s['payloads']):raise ValueError('payloads')
        if s['mode'] not in ('oasi','classical_cache','classical_no_cache'):raise ValueError('mode')
        return s
    except (ValueError,TypeError,KeyError) as exc:raise Rejected('Invalid incident spec: '+str(exc)) from exc

def domain(obs):
    # Explicit observed domain, not a claim of complete dependency discovery.
    return hashobj({'code':code_identity(),'generation':obs['generation'],'complete':obs['complete'],
                    'workers':obs['workers'],'initial':obs['config']})
def plan_from_observation(obs):
    if not obs['complete']:return None,0
    possibilities=[]
    for route in ('A','B'):
        for parallel in (1,2):
            worker=obs['workers'][route]
            if worker['available'] and parallel<=worker['capacity']:
                target={'route':route,'parallel':parallel}
                actions=[{'field':f,'value':target[f]} for f in ('parallel','route') if target[f]!=obs['config'][f]]
                possibilities.append(((len(actions),-parallel,route),actions,target))
    if not possibilities:return None,4
    _,actions,target=min(possibilities,key=lambda x:x[0]);return {'actions':actions,'target':target},4

def select(obs,knowledge,mode):
    if mode!='oasi':
        from classical_policy import decide
        return decide(obs,knowledge,mode,domain(obs))
    key=domain(obs);candidate=knowledge.get(mode,{}).get(key)
    if mode!='classical_no_cache' and candidate and candidate['status']=='ADMITTED':
        target=candidate['plan']['target'];w=obs['workers'].get(target.get('route'),{})
        if obs['complete'] and w.get('available') and 1<=target.get('parallel',0)<=w.get('capacity',0):
            return copy.deepcopy(candidate['plan']),{'mode':'REFLEX_REVALIDATED','evaluations':0,'domain':key}
    p,n=plan_from_observation(obs)
    return p,{'mode':'FRESH_PLANNING','evaluations':n,'domain':key}

class Child:
    def __init__(self,world):
        if getattr(sys,'frozen',False):cmd=[sys.executable,'--fixture-worker']
        else:cmd=[sys.executable,'-B',str(Path(__file__).with_name('fixture_service.py'))]
        self.p=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                                creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0),env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
        self.q=queue.Queue(maxsize=20);self.calls=0
        def reader():
            while True:
                b=self.p.stdout.readline(65537)
                self.q.put(b)
                if not b:break
        self.t=threading.Thread(target=reader,daemon=True);self.t.start()
        try:
            self.send(world);assert self.recv()=={'status':'READY'}
        except BaseException:self.close();raise
    def send(self,x):
        b=canonical(x)+b'\n'
        if len(b)>65536:raise Rejected('pipe size limit')
        self.p.stdin.write(b);self.p.stdin.flush()
    def recv(self):
        try:b=self.q.get(timeout=5)
        except queue.Empty as exc:raise Rejected('fixture service timeout') from exc
        if not b or len(b)>65536 or not b.endswith(b'\n'):raise Rejected('fixture service stopped or invalid reply')
        return json.loads(b,object_pairs_hook=unique_pairs)
    def call(self,r):
        if self.calls>=16:raise Rejected('RPC budget exceeded')
        self.calls+=1;self.send(r);return self.recv()
    def close(self):
        try:self.p.stdin.close()
        except (OSError,ValueError):pass
        try:self.p.wait(timeout=2)
        except subprocess.TimeoutExpired:self.p.kill();self.p.wait(timeout=2)
        self.t.join(timeout=2);self.p.stdout.close()

def run(engine,original,raw,gate):
    spec=validate_spec(raw);jobid=original['id'];started=time.monotonic();transcript=[];child=None
    def check():
        if time.monotonic()-started>60:raise Rejected('incident deadline')
        while True:
            decision=gate()
            if decision=='STOP':raise Rejected('incident interrupted; no automatic effect retry')
            if decision=='RUN':return
            if time.monotonic()-started>60:raise Rejected('incident deadline while paused')
            time.sleep(.02)
    def record(stage,entry):
        def update(state):
            j=state['jobs'][jobid]
            if state['epoch']!=engine.epoch or j['run']!=original['run'] or j['status']!='RUNNING':raise Rejected('incident ownership lost')
            j.setdefault('incident_trace',[]).append({'stage':stage,**entry})
            if len(j['incident_trace'])>32:raise Rejected('incident journal budget')
        engine._edit_retry('INCIDENT_'+stage,update)
    def rpc(request):
        check();reply=child.call(request);row={'request':request,'response':reply};transcript.append(row);record('RPC',row);return reply
    # A partially executed fixture is preserved and never automatically restarted.
    state=engine._view_retry();old=state['jobs'][jobid].get('incident_trace')
    if old:raise Rejected('incident already started: uncertain effect replay refused')
    record('START',{'scope':'OWNED_CHILD_FIXTURE_ONLY','spec_sha256':hashlib.sha256(raw).hexdigest()})
    try:
        check();child=Child(spec['world'])
        initial=rpc({'op':'serve','payloads':spec['payloads'],'expected_version':0})
        if initial['status'] not in ('SERVED','UNAVAILABLE','OVERLOAD'):raise Rejected('unexpected initial probe')
        obs=rpc({'op':'describe'})
        if obs['status']!='OBSERVATION':raise Rejected('missing observation')
        knowledge=engine._view_retry().get('incident_knowledge',{})
        plan,choice=select(obs,knowledge,spec['mode'])
        record('PLAN',{'observation':obs,'plan':plan,'choice':choice})
        if plan is None:
            return {'status':'BLOCKED','reason':'UNKNOWN_DOMAIN' if not obs['complete'] else 'NO_SAFE_WORKER',
                    'resolved':False,'actions':0,'choice':choice,'transcript':transcript,'scope':'OWNED_CHILD_FIXTURE_ONLY'}
        version=obs['version']
        for action in plan['actions']:
            fresh=rpc({'op':'describe'})
            if fresh['version']!=version or fresh['generation']!=obs['generation'] or fresh['workers']!=obs['workers'] or not fresh['complete']:raise Rejected('domain changed before action')
            # Intent durably recorded before contacting the toy service. A lost
            # response remains uncertain, never an implicit success or retry.
            record('INTENT',{'expected_version':version,'action':action})
            reply=rpc({'op':'apply','expected_version':version,**action})
            if reply['status']!='APPLIED' or reply['version']!=version+1:raise Rejected('action rejected')
            version+=1
        served=rpc({'op':'serve','payloads':spec['payloads'],'expected_version':version})
        expected=[hashlib.sha256(p.encode()).hexdigest() for p in spec['payloads']]
        if served.get('status')!='SERVED' or served.get('hashes')!=expected or served.get('count')!=len(expected) or served.get('config')!=plan['target']:raise Rejected('service result mismatch')
        check()
        proof={'status':'RESOLVED','resolved':True,'actions':len(plan['actions']),'plan':plan,'choice':choice,
               'observation':obs,'transcript':transcript,'hashes':expected,'rpc_calls':child.calls,
               'scope':'OWNED_CHILD_FIXTURE_ONLY','external_effects':0,'wall_ns':int((time.monotonic()-started)*1e9)}
        record('VERIFIED',{'receipt_sha256':hashobj(proof),'choice':choice})
        return proof
    finally:
        if child:child.close()

def learn_at_commit(state,job,proof):
    if proof['status']!='RESOLVED':return
    spec_mode=state['jobs'][job['id']]['incident_mode'];key=proof['choice']['domain']
    if spec_mode=='classical_no_cache':return
    bank=state.setdefault('incident_knowledge',{}).setdefault(spec_mode,{})
    if key not in bank and len(bank)>=64:raise Rejected('knowledge capacity reached')
    item=bank.setdefault(key,{'status':'CANDIDATE','plan':proof['plan'],'episodes':[],'receipt_hashes':[]})
    if item['plan']!=proof['plan']:raise Rejected('learned policy conflict')
    if job['id'] in item['episodes']:raise Rejected('duplicate learning episode')
    if len(item['episodes'])<32:
        item['episodes'].append(job['id']);item['receipt_hashes'].append(hashobj(proof))
    item['status']='ADMITTED' if len(item['episodes'])>=3 else 'CANDIDATE'

def execute(path,data):
    from supervisor import Supervisor,Engine
    from mission_service import retry
    from storage import safe_path
    path=safe_path(path)
    with path.open('rb') as f:raw=f.read(65537)
    spec=validate_spec(raw);s=Supervisor(data);key='incident-'+spec['id']
    def submit():return s.submit(path,key,'INCIDENT_FIXTURE')
    retry(submit);j=retry(s.store.view)['jobs'][key]
    if j['status']=='SUCCEEDED':return j['result']
    if j['status'] in ('FAILED','CANCELLED','INTERRUPTED'):raise Rejected('terminal/uncertain incident: no retry')
    e=Engine(s.store);deadline=time.monotonic()+75
    try:
        while time.monotonic()<deadline:
            j=retry(s.store.view)['jobs'][key]
            if j['status']=='SUCCEEDED':return j['result']
            if j['status'] in ('FAILED','CANCELLED','INTERRUPTED') or e.error:raise Rejected(j.get('error') or e.error or j['status'])
            time.sleep(.03)
        raise Rejected('incident execution timed out')
    finally:
        if not e.close():raise Rejected('engine not reaped')
