"""Bounded Windows-to-local-QEMU bridge, no shell and no fallback execution.

The host and its files are trusted. Hashes bind receipts and detect corruption;
they are not remote attestation or an authenticated network protocol.
"""
import base64,hashlib,json,os,subprocess,threading
from pathlib import Path
from storage import Lock,Rejected,canonical

ROOT=Path(__file__).resolve().parent.parent
MUTEX=threading.Lock()
COUNTS=('bytes','newlines','error_tokens','warning_tokens','nul_bytes')

def wsl_path(p):
    p=p.resolve()
    if not p.drive or len(p.drive)!=2:raise Rejected('Chemin local Windows requis')
    return '/mnt/'+p.drive[0].lower()+'/'+p.as_posix()[3:]

def validate(report,data,prefix,limit,binding):
    try:
        assert report['verdict']=='PASS_ISOLATED_BLOCK' and report['qemu_reaped'] is True
        assert report['binding']==binding and report['limit']==limit
        assert report['input_sha256']==hashlib.sha256(data).hexdigest()
        assert report['prefix_sha256']==hashlib.sha256(prefix).hexdigest()
        assert report['guardian_terminal']=={'success':True,'terminal':True,'zero_survivors':True}
        r=report['result'];assert r['bytes']==len(data)
        assert type(r['uid']) is int and r['uid']>0
        assert r['no_new_privs']==1 and r['seccomp']==2 and r['root_readonly'] is True
        assert all(type(r[k]) is int and 0<=r[k]<=len(data) for k in COUNTS)
        assert type(r['analysis_ns']) is int and r['analysis_ns']>0
        assert type(report['wall_ns']) is int and report['wall_ns']>0
        assert len(report['guest_log_sha256'])==64
        return r
    except (KeyError,TypeError,AssertionError):raise Rejected('Reçu isolation invalide')

def run(data,prefix,limit,binding,dispatch_gate):
    if os.name!='nt':raise Rejected('Ce candidat requiert Windows + WSL épinglé')
    if len(data)>limit or not 1<=limit<=524288 or len(prefix)>4:raise Rejected('Bloc hors bornes')
    # Serialize the whole guest lifecycle, not just Popen. Revalidate after wait.
    with MUTEX,Lock(ROOT/'host-executor.lock'):
        if not dispatch_gate():return None
        pins=json.loads((ROOT/'EXECUTOR_PINS.json').read_text(encoding='utf-8'))
        for name,h in pins.items():
            if hashlib.sha256((ROOT/name).read_bytes()).hexdigest()!=h:raise Rejected('Exécuteur modifié : '+name)
        req={'data':base64.b64encode(data).decode(),'prefix':base64.b64encode(prefix).decode(),
             'limit':limit,'binding':binding}
        command=['wsl','-d','DARPA-Ubuntu-24.04','--','python3','-B',wsl_path(ROOT/'isolation.py'),'--request-stdin']
        try:
            p=subprocess.run(command,input=canonical(req),capture_output=True,timeout=60,
                             creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        except (OSError,subprocess.TimeoutExpired) as exc:
            raise Rejected('Exécuteur indisponible ; aucun fallback ni retry') from exc
        if p.returncode!=0:raise Rejected('Échec guardian ; preuves conservées, aucun fallback')
        if len(p.stdout)>16384 or len(p.stderr)>16384:raise Rejected('Réponse trop longue')
        try:report=json.loads(p.stdout)
        except ValueError as exc:raise Rejected('Réponse isolation illisible') from exc
        validate(report,data,prefix,limit,binding)
        return report
