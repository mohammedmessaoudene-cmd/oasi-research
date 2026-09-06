"""Fixed workspace budget. Cooperative fixture accounting, not human authority."""
from pathlib import Path
from storage import Rejected, canonical, safe_path
import hashlib

LIMIT=16
TASKS={'SHA256','HASH_COUNT_LOCAL'}

def new_budget(input_root):
    root=safe_path(input_root).resolve(strict=True)
    if not root.is_dir():raise Rejected('INPUT_ROOT_NOT_DIRECTORY')
    return {'schema':1,'limit':LIMIT,'input_root':str(root),
            'reservations':[],'launch_claims':[],'work_started':[]}

def binding(job):
    return hashlib.sha256(canonical({k:job[k] for k in ('id','path','pin','task')})).hexdigest()

def check(state):
    b=state.get('budget')
    if not isinstance(b,dict) or set(b)!={'schema','limit','input_root','reservations','launch_claims','work_started'}:
        raise Rejected('BUDGET_MISSING_OR_MALFORMED')
    if type(b['schema']) is not int or b['schema']!=1 or type(b['limit']) is not int or b['limit']!=LIMIT:
        raise Rejected('BUDGET_POLICY_CHANGED')
    if not isinstance(b['input_root'],str) or not Path(b['input_root']).is_absolute():raise Rejected('BUDGET_ROOT_INVALID')
    rows=b['reservations'];claims=b['launch_claims'];starts=b['work_started']
    if not isinstance(rows,list) or len(rows)>LIMIT:raise Rejected('BUDGET_EXHAUSTED_OR_INVALID')
    for seq,row in enumerate(rows,1):
        if not isinstance(row,dict) or set(row)!={'slot','job','run','binding'}:raise Rejected('RESERVATION_SCHEMA')
        if type(row['slot']) is not int or row['slot']!=seq or type(row['run']) is not int or row['run']<1:
            raise Rejected('RESERVATION_ORDER')
        job=state['jobs'].get(row['job'])
        if not job or row['binding']!=binding(job):raise Rejected('RESERVATION_BINDING')
    if len({(r['job'],r['run']) for r in rows})!=len(rows):raise Rejected('DUPLICATE_RESERVATION')
    for values in (claims,starts):
        if not isinstance(values,list) or any(type(n) is not int or not 1<=n<=len(rows) for n in values):
            raise Rejected('LAUNCH_SCHEMA')
        if len(values)!=len(set(values)):raise Rejected('REPEATED_LAUNCH')
    if not set(starts)<=set(claims):raise Rejected('START_WITHOUT_CLAIM')
    for key,job in state['jobs'].items():
        if job['id']!=key or job['task'] not in TASKS:raise Rejected('JOB_OUTSIDE_SCOPE')
        slot=job.get('budget_slot')
        if type(slot) is not int or not 1<=slot<=len(rows):raise Rejected('JOB_WITHOUT_RESERVATION')
        r=rows[slot-1]
        if r['job']!=key or r['run'] not in (job['run'],job['run']+1):raise Rejected('JOB_RESERVATION_MISMATCH')
        if job['status'] in ('RUNNING','PAUSED','PAUSE_REQUESTED','CANCEL_REQUESTED','SUCCEEDED'):
            if slot not in claims or r['run']!=job['run']:raise Rejected('UNRESERVED_EXECUTION')
        if job['status']=='SUCCEEDED' and slot not in starts:raise Rejected('RESULT_WITHOUT_START')
    return b

def transition(before,after):
    old=check(before);new=check(after)
    for field in ('schema','limit','input_root'):
        if old[field]!=new[field]:raise Rejected('BUDGET_POLICY_CHANGED')
    for field in ('reservations','launch_claims','work_started'):
        if new[field][:len(old[field])]!=old[field] or len(new[field])<len(old[field]):
            raise Rejected('BUDGET_HISTORY_REMOVED_OR_CHANGED')

def reserve(state,job):
    b=state['budget']
    if len(b['reservations'])>=LIMIT:raise Rejected('BUDGET_EXHAUSTED')
    if job['task'] not in TASKS or job['pin']['size']>524288:raise Rejected('TASK_OUTSIDE_SCOPE')
    path=safe_path(job['path']).resolve(strict=True)
    root=safe_path(b['input_root']).resolve(strict=True)
    if not path.is_relative_to(root) or path==root:raise Rejected('INPUT_OUTSIDE_SELECTED_ROOT')
    slot=len(b['reservations'])+1
    b['reservations'].append({'slot':slot,'job':job['id'],'run':job['run']+1,'binding':binding(job)})
    job['budget_slot']=slot

def claim(state,job):
    b=check(state);slot=job['budget_slot'];row=b['reservations'][slot-1]
    if slot in b['launch_claims'] or row['run']!=job['run']+1:raise Rejected('RESERVATION_ALREADY_CLAIMED')
    b['launch_claims'].append(slot)

def work_start(state,job):
    b=check(state);current=state['jobs'][job['id']];slot=job['budget_slot']
    if (current['epoch'],current['run'],current['budget_slot'],current['status'])!=(job['epoch'],job['run'],slot,'RUNNING'):
        raise Rejected('STALE_WORK_START')
    if slot not in b['launch_claims'] or slot in b['work_started']:raise Rejected('UNRESERVED_OR_REPEATED_START')
    b['work_started'].append(slot)
