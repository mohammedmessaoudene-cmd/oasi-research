"""Bounded goal controller using the existing Store/Engine, never a shell agent."""
import hashlib,itertools,json,math,re,time
from pathlib import Path
from storage import Busy,Rejected,canonical,safe_path,unique_pairs
from supervisor import Supervisor,Engine,file_pin,resource_sample,allowed_workers

END={'SUCCEEDED','NEEDS_REVIEW','BLOCKED','CANCELLED'}
ID=re.compile(r'[A-Za-z0-9_-]{1,32}\Z')
def digest(v):return hashlib.sha256(canonical(v)).hexdigest()
def retry(fn):
    for _ in range(100):
        try:return fn()
        except Busy:time.sleep(.02)
    raise Rejected('Journal occupé au-delà de la borne')
def identity():
    root=Path(__file__).parent
    return digest({n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in ('mission_service.py','supervisor.py','diagnostic.py','storage.py','operating_loop.py')})
def pin_input(path):
    name,pin=file_pin(path)
    if pin['size']>524288:raise Rejected('Journal supérieur à 512 Kio')
    with open(name,'rb') as f:data=f.read(524289)
    if len(data)!=pin['size'] or file_pin(name)[1]!=pin:raise Rejected('Entrée instable')
    return name,pin,hashlib.sha256(data).hexdigest()
def acceptable(job):
    d=(job.get('result') or {}).get('diagnostic',{})
    return job['status']=='SUCCEEDED' and d.get('status') in ('SUPPORTED_FINDINGS','NO_ACTIVE_SUPPORTED_INCIDENT')
def permitted(state,job):
    mid=job.get('mission_id')
    if mid is None:return True
    m=state.get('missions',{}).get(mid)
    if not m or m['status']!='RUNNING' or job.get('dispatch_epoch')!=state['epoch']:return False
    if job['status']=='QUEUED' and job['run']>=2:return False
    if time.time()>m['deadline_utc']:return False
    node=m['nodes'][job['mission_node']]
    return all(acceptable(state['jobs'][m['nodes'][d]['job']]) and
               state['jobs'][m['nodes'][d]['job']]['result']['sha256']==m['nodes'][d]['sha256']
               for d in node['dependencies'])

def choose(ready,slots,budget,ns_per_byte):
    """Enumerate up to two ready jobs, maximize unlocked children then work admitted.
    Duration estimate is advisory, never a deadline or physical memory guarantee.
    """
    plans=[];fallback=[]
    for n in range(1,min(slots,2,len(ready))+1):
        for group in itertools.combinations(ready,n):
            size=sum(x['pin']['size'] for x in group)
            if size>budget:continue
            cost=sum(max(1,x['pin']['size'])*ns_per_byte for x in group)
            candidate=((-sum(x['dependents'] for x in group),-n,cost,tuple(x['id'] for x in group)),group)
            if cost<=250_000_000:plans.append(candidate)
            if n==1:fallback.append(candidate)
    if not plans:plans=fallback
    if not plans:return [],0
    return [n['id'] for n in min(plans,key=lambda p:p[0])[1]],len(plans)

def observe_skill(previous,context,size,elapsed_ns,result_hash):
    if size<1:return previous
    rate=elapsed_ns/size
    if not math.isfinite(rate) or not 0<rate<1e10:return {'status':'REVOKED','context':context,'reason':'MEASUREMENT_OUT_OF_RANGE'}
    if not previous or previous.get('context')!=context or previous.get('status')=='REVOKED':
        return {'context':context,'status':'CANDIDATE','samples':1,'checks':0,'ns_per_byte':rate,'reason':'FRESH_SAMPLE',
                'evidence':[{'bytes':size,'elapsed_ns':elapsed_ns,'result_sha256':result_hash}]}
    p=json.loads(json.dumps(previous));ratio=rate/p['ns_per_byte']
    if not .25<=ratio<=4:
        p.update(status='REVOKED',reason='FRESH_PREDICTION_DIVERGED');return p
    p['samples']+=1;p['checks']+=1;p['ns_per_byte']=(p['ns_per_byte']+rate)/2
    p['evidence']=(p['evidence']+[{'bytes':size,'elapsed_ns':elapsed_ns,'result_sha256':result_hash}])[-8:]
    p.update(status='ADMITTED' if p['samples']>=3 and p['checks']>=2 else 'CANDIDATE',reason='FRESH_COST_CHECKS')
    return p

class MissionService:
    def __init__(self,supervisor):self.s=supervisor
    def read(self):return retry(self.s.store.view)
    def edit(self,event,fn):return retry(lambda:self.s.store.edit(event,fn))
    def admit(self,manifest):
        path=safe_path(manifest)
        with path.open('rb') as stream:raw=stream.read(65537)
        if len(raw)>65536:raise Rejected('Manifeste supérieur à 64 Kio')
        spec=json.loads(raw,object_pairs_hook=unique_pairs)
        if set(spec)!={'schema','mission_id','files','budget_bytes','deadline_seconds'} or spec['schema']!=1:raise Rejected('Schéma de mission invalide')
        mid=spec['mission_id'];items=spec['files'];budget=spec['budget_bytes'];duration=spec['deadline_seconds']
        if not isinstance(mid,str) or not ID.fullmatch(mid):raise Rejected('Identifiant mission invalide')
        if not isinstance(items,list) or not 1<=len(items)<=32:raise Rejected('1 à 32 fichiers requis')
        if type(budget) is not int or not 1<=budget<=1048576:raise Rejected('Budget invalide')
        if type(duration) is not int or not 1<=duration<=300:raise Rejected('Délai invalide')
        nodes={}
        for item in items:
            if set(item)!={'id','path','dependencies'}:raise Rejected('Schéma de tâche invalide')
            key=item['id'];relative=item['path'];deps=item['dependencies']
            if not isinstance(key,str) or not ID.fullmatch(key) or key in nodes:raise Rejected('Identifiant tâche invalide ou dupliqué')
            if not isinstance(relative,str) or not relative or '\\' in relative or ':' in relative or relative.startswith('/') or any(v in ('','.','..') for v in relative.split('/')):raise Rejected('Chemin relatif local requis')
            if not isinstance(deps,list) or any(not isinstance(d,str) for d in deps) or len(set(deps))!=len(deps):raise Rejected('Dépendances invalides')
            name,pin,h=pin_input(path.parent/relative)
            nodes[key]={'id':key,'path':name,'pin':pin,'sha256':h,'dependencies':deps,'job':f'm-{mid}-{key}',
                        'status':'WAITING','observed':False,'predicted_ns':None,'dependents':0}
        for node in nodes.values():
            if any(d not in nodes for d in node['dependencies']):raise Rejected('Dépendance inconnue')
            for d in node['dependencies']:nodes[d]['dependents']+=1
        done=set()
        for _ in range(len(nodes)):
            new={k for k,n in nodes.items() if set(n['dependencies'])<=done};done|=new
        if len(done)!=len(nodes):raise Rejected('Graphe cyclique')
        seal=digest({'spec':spec,'nodes':nodes,'code':identity()})
        context=digest({'code':identity(),'task':'DIAGNOSTIC_LOCAL','graph':{k:n['dependencies'] for k,n in nodes.items()},
                        'sizes':{k:n['pin']['size'] for k,n in nodes.items()},'platform':'WINDOWS_HOST_ADVISORY'})
        def insert(s):
            missions=s.setdefault('missions',{})
            if mid in missions:
                if missions[mid]['seal']!=seal:raise Rejected('Identifiant lié à une autre mission')
                return mid
            if len(missions)>=8 or len(s['jobs'])+len(nodes)>200:raise Rejected('Capacité du journal atteinte')
            if any(n['job'] in s['jobs'] for n in nodes.values()):raise Rejected('Collision identifiant travail')
            missions[mid]={'seal':seal,'context':context,'code':identity(),'status':'RUNNING','reason':'ADMITTED',
                          'nodes':nodes,'budget_bytes':budget,'deadline_utc':time.time()+duration,'trace':[],
                          'last_plan':None,'summary':None,'planner_evaluations':0}
            for node in nodes.values():
                s['jobs'][node['job']]={'id':node['job'],'path':node['path'],'pin':node['pin'],'status':'HELD','bytes_done':0,
                   'result':None,'error':None,'run':0,'epoch':None,'submitted':time.time(),'task':'DIAGNOSTIC_LOCAL',
                   'mission_id':mid,'mission_node':node['id'],'expected_sha256':node['sha256'],'dispatch_epoch':None}
            return mid
        return self.edit('MISSION_ADMIT',insert)
    def tick(self,mid,sample):
        observed=self.read();mission=observed['missions'][mid]
        if mission['status'] in END:return mission
        drift=None
        if mission['code']!=identity():drift='CODE_CHANGED'
        if not drift:
            for n in mission['nodes'].values():
                if observed['jobs'][n['job']]['status'] in ('HELD','INTERRUPTED','QUEUED'):
                    try:
                        _,p,h=pin_input(n['path'])
                        if p!=n['pin'] or h!=n['sha256']:drift='INPUT_CHANGED:'+n['id'];break
                    except (Rejected,OSError):drift='INPUT_UNAVAILABLE:'+n['id'];break
        def update(s):
            m=s['missions'][mid]
            if m['status'] in END:return m
            if drift:m.update(status='BLOCKED',reason=drift);return m
            if time.time()>m['deadline_utc']:m.update(status='BLOCKED',reason='DEADLINE_EXCEEDED');return m
            nodes=m['nodes'];skills=s.setdefault('mission_skills',{});skill=skills.get(m['context'])
            failed=[];uncertain=[]
            for key,n in nodes.items():
                j=s['jobs'][n['job']]
                if j['status']=='SUCCEEDED':
                    if j['result']['sha256']!=n['sha256']:m.update(status='BLOCKED',reason='RESULT_PIN_MISMATCH');return m
                    n['status']='SUCCEEDED' if acceptable(j) else 'NEEDS_REVIEW'
                    if n['status']=='NEEDS_REVIEW':uncertain.append(key)
                    if not n['observed']:
                        timing=j['result'].get('mission_measurement')
                        if acceptable(j) and timing:skill=observe_skill(skill,m['context'],j['result']['bytes'],timing['elapsed_ns'],n['sha256']);skills[m['context']]=skill
                        n['observed']=True
                elif j['status'] in ('FAILED','CANCELLED'):n['status']=j['status'];failed.append(key)
                elif j['status']=='INTERRUPTED' and j['run']>=2:failed.append(key)
            if failed:m.update(status='BLOCKED',reason='TASK_FAILED:'+','.join(failed));return m
            if uncertain:
                m.update(status='NEEDS_REVIEW',reason='UNSUPPORTED_LOG:'+','.join(uncertain))
                m['summary']=self.summary(s,m);return m
            if all(n['status']=='SUCCEEDED' for n in nodes.values()):
                m.update(status='SUCCEEDED',reason='ALL_RESULTS_VERIFIED',summary=self.summary(s,m));return m
            if s['paused']:m['reason']='USER_QUEUE_PAUSED';return m
            limit,reason=allowed_workers(sample,2)
            active=[n for n in nodes.values() if s['jobs'][n['job']]['status'] in ('RUNNING','PAUSED','PAUSE_REQUESTED','CANCEL_REQUESTED') or
                    (s['jobs'][n['job']]['status']=='QUEUED' and s['jobs'][n['job']].get('dispatch_epoch')==s['epoch'])]
            budget=m['budget_bytes']-sum(n['pin']['size'] for n in active)
            ready=[n for n in nodes.values() if s['jobs'][n['job']]['status'] in ('HELD','INTERRUPTED','QUEUED') and n not in active and
                   not s['jobs'][n['job']].get('mission_hold',False) and
                   all(acceptable(s['jobs'][nodes[d]['job']]) for d in n['dependencies'])]
            admitted=skill and skill.get('status')=='ADMITTED' and skill['context']==m['context']
            rate=skill['ns_per_byte'] if admitted else 10000.0
            selected,evaluations=choose(sorted(ready,key=lambda n:n['id']),max(0,limit-len(active)),max(0,budget),rate)
            m['planner_evaluations']+=evaluations
            why='READY_SET_SELECTED' if selected else ('RESOURCE_PRESSURE' if limit==0 else 'WAITING_DEPENDENCY_OR_BUDGET')
            if not active and ready and all(n['pin']['size']>m['budget_bytes'] for n in ready):m.update(status='BLOCKED',reason='INPUT_BUDGET_TOO_SMALL');return m
            plan={'epoch':s['epoch'],'selected':selected,'reason':why,'resource_limit':limit,'budget_remaining':budget,
                  'model':'ADMITTED_OBSERVED_COST' if admitted else 'CONSERVATIVE_DEFAULT','rate_ns_per_byte':rate,
                  'planning_target_ms':250,'planning_target_is_not_runtime_guarantee':True,
                  'ready':[n['id'] for n in ready],'active':[n['id'] for n in active]}
            if plan!=m['last_plan']:
                m['trace']=(m['trace']+[plan])[-128:];m['last_plan']=plan
            for key in selected:
                n=nodes[key];j=s['jobs'][n['job']]
                j.update(status='QUEUED',dispatch_epoch=s['epoch'],error=None)
                n.update(status='DISPATCHED',predicted_ns=max(1,n['pin']['size'])*rate)
            m['reason']=why
            return m
        return self.edit('MISSION_OBSERVE_PLAN',update)
    @staticmethod
    def summary(s,m):
        findings=[];review=[]
        for key,n in m['nodes'].items():
            j=s['jobs'][n['job']];d=(j.get('result') or {}).get('diagnostic')
            if d:
                findings += [{'file_id':key,**f} for f in d['findings']]
                review += [{'file_id':key,**a} for a in d['abstentions']]
        return {'findings':findings,'abstentions':review,'actions_executed':0,'scope':'HOST_ADVISORY_DECLARED_DEPENDENCIES',
                'completed_files':sum(n['status']=='SUCCEEDED' for n in m['nodes'].values()),'total_files':len(m['nodes'])}

def run_mission(manifest,data,resource_fn=resource_sample,tick_hook=None):
    s=Supervisor(data);service=MissionService(s);mid=service.admit(manifest)
    if service.read()['missions'][mid]['status'] in END:return service.read()['missions'][mid]
    engine=Engine(s.store,resource_fn=resource_fn)
    try:
        while True:
            if engine.error:raise Rejected('Moteur arrêté : '+engine.error)
            m=service.tick(mid,resource_fn())
            if tick_hook:tick_hook(service,m,engine)
            if m['status'] in END:return m
            time.sleep(.1)
    finally:
        if not engine.close():raise Rejected('Moteur non récolté')
