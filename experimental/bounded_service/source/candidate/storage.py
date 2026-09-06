"""Portable adaptation of OASI V2 immutable-snapshot publication, not its fixture ABI.
Derived concepts/helpers: OASI_V2_LEDGER_BRIDGE_20260904/snapshot_ledger.py.
No historical module or authority is imported. Cooperative local-process boundary.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid


class Rejected(RuntimeError): pass
class Busy(Rejected): pass


def canonical(obj):
    return json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')


def safe_path(path):
    p=Path(path).absolute()
    if str(p).startswith(('\\\\','//')):raise Rejected('Chemin réseau interdit')
    for node in (p,*p.parents):
        if node.exists() or node.is_symlink():
            s=node.lstat()
            if stat.S_ISLNK(s.st_mode) or getattr(s,'st_file_attributes',0)&0x400:
                raise Rejected('Lien/reparse point interdit: '+str(node))
    return p


class Lock:
    def __init__(self,path):self.path=Path(path);self.f=None
    def __enter__(self):
        safe_path(self.path)
        try:
            with self.path.open('xb') as f:f.write(b'0');f.flush();os.fsync(f.fileno())
        except FileExistsError:pass
        self.f=self.path.open('r+b');self.f.seek(0)
        try:
            if os.name=='nt':
                import msvcrt
                msvcrt.locking(self.f.fileno(),msvcrt.LK_NBLCK,1)
            else:
                import fcntl
                fcntl.flock(self.f.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError as e:
            self.f.close();self.f=None;raise Busy('Une autre opération utilise ce journal') from e
        return self
    def __exit__(self,*args):
        if self.f:
            if os.name=='nt':
                import msvcrt
                self.f.seek(0);msvcrt.locking(self.f.fileno(),msvcrt.LK_UNLCK,1)
            self.f.close();self.f=None


def unique_pairs(items):
    d={}
    for k,v in items:
        if k in d:raise Rejected('Clé JSON dupliquée')
        d[k]=v
    return d


def read_json(path,limit=4*1024*1024):
    safe_path(path);s=path.stat()
    if not stat.S_ISREG(s.st_mode) or s.st_size>limit:raise Rejected('Fichier de journal invalide')
    raw=path.read_bytes()
    return json.loads(raw,object_pairs_hook=unique_pairs),raw


def write_new(path,data):
    safe_path(path)
    with path.open('xb') as f:f.write(data);f.flush();os.fsync(f.fileno())


class Store:
    def __init__(self,root,max_bytes=64*1024*1024,*,initialize=False,input_root=None):
        if type(max_bytes) is not int or not 1024<=max_bytes<=64*1024*1024:
            raise Rejected('Budget global du journal invalide')
        self.max_bytes=max_bytes
        self.root=safe_path(root)
        if initialize:
            self.root.mkdir(parents=False,exist_ok=False)
        elif not self.root.is_dir() or not (self.root/'current.json').is_file():
            raise Rejected('STATE_MISSING_NO_AUTOMATIC_RESET')
        self.snap=self.root/'snapshots';safe_path(self.snap);self.snap.mkdir(exist_ok=True)
        self.lock_path=self.root/'state.lock'
        with Lock(self.lock_path):
            if not (self.root/'current.json').exists():
                if any(self.snap.iterdir()):raise Rejected('Journal incomplet : snapshots sans pointeur. Aucune réinitialisation automatique.')
                if not initialize:raise Rejected('STATE_MISSING_NO_AUTOMATIC_RESET')
                from cumulative_budget import new_budget
                self._save({'schema':1,'epoch':0,'jobs':{},'paused':False,'max_workers':2,
                            'budget':new_budget(input_root)},None,'INITIALIZE')
            self._read()

    def _read(self):
        pointer,_=read_json(self.root/'current.json',2048)
        if set(pointer)!={'name','sha256'} or not re.fullmatch(r'[0-9a-f]{32}\.json',pointer['name']):raise Rejected('Pointeur invalide')
        envelope,raw=read_json(self.snap/pointer['name'])
        if hashlib.sha256(raw).hexdigest()!=pointer['sha256']:raise Rejected('Empreinte du journal invalide : arrêt')
        if set(envelope)!={'state','previous','event'} or envelope['state'].get('schema')!=1:raise Rejected('Schéma invalide')
        from cumulative_budget import check
        check(envelope['state'])
        return envelope['state'],pointer

    def _save(self,state,previous,event):
        from cumulative_budget import check,transition
        check(state)
        if previous:
            old,_=read_json(self.snap/previous['name'])
            transition(old['state'],state)
        if len(state['jobs'])>200:raise Rejected('Limite de 200 travaux atteinte')
        if sum(1 for _ in self.snap.iterdir())>=10000:raise Rejected('Limite du journal atteinte : aucun effacement automatique')
        raw=canonical({'state':state,'previous':previous,'event':event})
        if len(raw)>4*1024*1024:raise Rejected('Journal trop volumineux')
        used=0
        for p in self.root.rglob('*'):
            # Root/ancestors were checked on entry. Rechecking every ancestor of
            # every snapshot held the cooperative lock for excessively long.
            info=p.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:
                raise Rejected('Lien/reparse dans le journal')
            if stat.S_ISREG(info.st_mode):used+=info.st_size
        # Include transient and final pointers conservatively before any write.
        if used+len(raw)+512>self.max_bytes:
            raise Rejected('Budget global du journal atteint : aucun effacement automatique')
        name=uuid.uuid4().hex+'.json';write_new(self.snap/name,raw)
        pointer={'name':name,'sha256':hashlib.sha256(raw).hexdigest()}
        temp=self.root/(uuid.uuid4().hex+'.pending');write_new(temp,canonical(pointer))
        os.replace(temp,self.root/'current.json')
        if os.name!='nt':
            fd=os.open(self.root,os.O_RDONLY)
            try:os.fsync(fd)
            finally:os.close(fd)

    def view(self):
        with Lock(self.lock_path):return self._read()[0]

    def edit(self,event,fn):
        with Lock(self.lock_path):
            state,pointer=self._read();before=canonical(state);result=fn(state)
            if canonical(state)!=before:self._save(state,pointer,event)
            return result

    def verify(self):
        with Lock(self.lock_path):
            _,pointer=self._read();seen=set();count=0
            while pointer:
                name=pointer['name']
                if not re.fullmatch(r'[0-9a-f]{32}\.json',name) or name in seen:raise Rejected('Chaîne invalide')
                seen.add(name);entry,raw=read_json(self.snap/name)
                if hashlib.sha256(raw).hexdigest()!=pointer['sha256']:raise Rejected('Historique altéré')
                pointer=entry['previous'];count+=1
            return {'snapshots_verified':count,'power_loss_validated':False}
