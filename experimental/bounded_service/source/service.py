"""Supported local fixture CLI; no browser, network, installation or compilation."""
from pathlib import Path
import argparse,json,sys,time,threading,hashlib
sys.dont_write_bytecode=True
BASE=Path(__file__).resolve().parent
sys.path.insert(0,str(BASE/'candidate'))
from storage import Store,Rejected,Busy,safe_path
from supervisor import Supervisor,Engine

def retry(fn):
    for _ in range(150):
        try:return fn()
        except Busy:time.sleep(.02)
    raise Rejected('STATE_BUSY_TIMEOUT')

def state_summary(s):
    b=s['budget']
    return {'scope':'LOCAL_COOPERATIVE_FIXTURE','limit':b['limit'],'reserved':len(b['reservations']),
        'remaining':b['limit']-len(b['reservations']),'launch_claims':len(b['launch_claims']),
        'work_started':len(b['work_started']),'epoch':s['epoch'],
        'jobs':[{k:j.get(k) for k in ('id','path','status','run','budget_slot','bytes_done','result','error')}
                for j in s['jobs'].values()]}

def run(workspace,interrupt=False):
    supervisor=Supervisor(workspace)
    initial=retry(supervisor.store.view)
    # No needless native process when there is nothing admissible to run.
    if not any(j['status']=='QUEUED' for j in initial['jobs'].values()):
        return {'closed':True,'no_pending_work':True,**state_summary(initial)},0
    first_block=threading.Event();release=threading.Event()
    def hook(key,count):
        if interrupt:
            first_block.set()
            if not release.wait(10):raise Rejected('FIXTURE_CONTROL_TIMEOUT')
    engine=Engine(supervisor.store,read_hook=hook if interrupt else None)
    stopped=False;deadline=time.monotonic()+40
    try:
        while True:
            if first_block.is_set():
                stopped=True;engine.stop.set();release.set();break
            if engine.error:raise Rejected('ENGINE_ERROR:'+engine.error)
            s=retry(supervisor.store.view)
            if not any(j['status'] in ('QUEUED','RUNNING','PAUSED','PAUSE_REQUESTED','CANCEL_REQUESTED') for j in s['jobs'].values()):break
            if time.monotonic()>deadline:raise Rejected('COMMAND_TIME_BOUND')
            time.sleep(.02)
    finally:
        engine.stop.set();release.set()
        if not engine.close():raise Rejected('OWNED_ENGINE_NOT_CLOSED')
    if engine.error:raise Rejected('ENGINE_ERROR:'+engine.error)
    s=retry(supervisor.store.view)
    if any(j['status']=='FAILED' for j in s['jobs'].values()):raise Rejected('FAILED_WORK_ITEM')
    return {'closed':True,'controlled_interruption':stopped,**state_summary(s)},75 if stopped else 0

def main():
    p=argparse.ArgumentParser(description='OASI : analyse locale bornée, plafond cumulatif de 16 réservations par espace.')
    p.add_argument('command',choices=['init','submit','resume','run','status'])
    p.add_argument('--workspace',required=True,type=Path)
    p.add_argument('--input-root',type=Path)
    p.add_argument('--file',type=Path)
    p.add_argument('--key')
    p.add_argument('--task',default='HASH_COUNT_LOCAL')
    p.add_argument('--fixture-stop-after-reservation',action='store_true',help=argparse.SUPPRESS)
    p.add_argument('--fixture-interrupt-after-block',action='store_true',help=argparse.SUPPRESS)
    args=p.parse_args();exit_code=0
    try:
        if args.command=='init':
            if not args.input_root:raise Rejected('INPUT_ROOT_REQUIRED')
            store=Store(args.workspace,initialize=True,input_root=args.input_root)
            result=state_summary(store.view())
        elif args.command=='status':result=state_summary(Store(args.workspace).view())
        elif args.command=='run':result,exit_code=run(args.workspace,args.fixture_interrupt_after_block)
        else:
            s=Supervisor(args.workspace)
            if not args.key:raise Rejected('KEY_REQUIRED')
            if args.command=='submit':
                if not args.file:raise Rejected('FILE_REQUIRED')
                retry(lambda:s.submit(args.file,args.key,args.task))
            else:retry(lambda:s.control(args.key,'resume'))
            result=state_summary(retry(s.store.view))
            if args.fixture_stop_after_reservation:
                result['controlled_exit_after_reservation']=True;exit_code=75
        print(json.dumps({'status':'CONTROLLED_INTERRUPTION' if exit_code else 'OK',**result},ensure_ascii=False))
        return exit_code
    except (Rejected,OSError,ValueError,KeyError,TypeError) as exc:
        print(json.dumps({'status':'REFUSED_FAIL_CLOSED','reason':str(exc)},ensure_ascii=False))
        return 3
if __name__=='__main__':sys.exit(main())
