"""Offline, user-space build of the pinned published decision kernel adapter."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import sys

BASE=Path(__file__).parent
SOURCE=BASE.parent/'OASI_PUBLICATION_V0_2_S5_S6_20260902/artifacts/v0.2.2-post-doi-final-2cf5460/extract-A/src/model.rs'
PIN='d40e12310c617a0e9bc3b4c2279e119479454224cfa50f4073b3d27bc1d724dd'


def main():
    native=BASE/'native';src=native/'model.rs'
    raw=(SOURCE if SOURCE.exists() else src).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=PIN:raise RuntimeError('Published source drift')
    if src.exists():
        if src.read_bytes()!=raw:raise RuntimeError('Vendored source drift')
    else:
        with src.open('xb') as f:f.write(raw)
    tool=Path(os.environ['USERPROFILE'])/'.rustup/toolchains/stable-x86_64-pc-windows-gnu/bin/rustc.exe'
    linker=tool.parent.parent/'lib/rustlib/x86_64-pc-windows-gnu/bin/rust-lld.exe'
    if not tool.is_file() or not linker.is_file():raise RuntimeError('Offline Rust toolchain not available; no installation attempted')
    out=Path(tempfile.mkdtemp(prefix='native-build-',dir=BASE/'evidence'))
    target=out/'guardian_bridge.exe'
    command=[str(tool),'--edition=2024',str(native/'guardian_bridge.rs'),'-C','opt-level=1','-C','linker='+str(linker),'-o',str(target)]
    p=subprocess.run(command,capture_output=True,text=True,timeout=90)
    (out/'BUILD.log').write_text(p.stdout+p.stderr,encoding='utf-8')
    receipt={'exit_code':p.returncode,'command':command,'published_source_sha256':PIN,
             'bridge_source_sha256':hashlib.sha256((native/'guardian_bridge.rs').read_bytes()).hexdigest(),
             'rustc':subprocess.check_output([str(tool),'--version'],text=True).strip()}
    if p.returncode==0:
        receipt.update(executable=str(target.relative_to(BASE)),bytes=target.stat().st_size,
                       sha256=hashlib.sha256(target.read_bytes()).hexdigest())
        pointer=BASE/'native/CURRENT.json'
        # Local build pointer, not a historical authority or release pointer.
        temp=pointer.with_suffix('.pending')
        with temp.open('x',encoding='utf-8') as f:json.dump(receipt,f,indent=2);f.flush();os.fsync(f.fileno())
        os.replace(temp,pointer)
    (out/'BUILD_RESULT.json').write_text(json.dumps(receipt,indent=2),encoding='utf-8')
    print(json.dumps(receipt,indent=2));return p.returncode


if __name__=='__main__':sys.exit(main())
