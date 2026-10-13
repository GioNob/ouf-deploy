"""Prepare only: one immutable pinned capsule, no approval or apply input."""
import base64
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess

CAPSULE_COMMIT='1aa054279ad2d4f21bc27b65585be7dc40cb6f79'
CAPSULE_SHA='e6fe660992f5f018975de73aaf9c83dfe4df9036620257735a5f59b7cf60379d'
CAPSULE_PATH='releases/policy-token-iam-action-source-capsule-20261013.json'
ROOT_BODY=r'''
import base64,hashlib,json,sys,types
raw=sys.stdin.buffer.read(1048577)
if not 0<len(raw)<=1048576 or hashlib.sha256(raw).hexdigest()!=CAPSULE_SHA:raise SystemExit('phase=ROOT_DELIVERY reason=FULL_CAPSULE_HASH_MISMATCH')
p=json.loads(raw)
if type(p)is not dict or set(p)!={'schema','sourceCommit','loader','sources','declarationHash'} or p['schema']!='ouf.policy-token-iam-action-memory-capsule.v1':raise SystemExit('phase=ROOT_DELIVERY reason=EXACT_FULL_CAPSULE_REQUIRED')
loader=base64.b64decode(p['loader'],validate=True)
if not 0<len(loader)<=65536:raise SystemExit('phase=ROOT_DELIVERY reason=LOADER_UNBOUNDED')
sources={n:base64.b64decode(v,validate=True) for n,v in p['sources'].items()}
runtime=types.ModuleType('verified_iam_action_loader')
exec(compile(loader,'verified-iam-action-loader','exec'),runtime.__dict__)
entry,manifest=runtime.load_entry(p['sourceCommit'],sources,loader,p['declarationHash'])
raise SystemExit(entry.main(manifest))
'''

def main():
    if not re.fullmatch('[0-9a-f]{40}',CAPSULE_COMMIT) or not re.fullmatch('[0-9a-f]{64}',CAPSULE_SHA):
        raise SystemExit('phase=DELIVERY reason=FULL_CAPSULE_NOT_QUALIFIED; no sudo executed')
    preferred=Path.home()/'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh'
    gh=str(preferred) if preferred.is_file() and os.access(preferred,os.X_OK) else shutil.which('gh')
    if not gh:raise SystemExit('phase=DELIVERY reason=EXISTING_GH_UNAVAILABLE; no sudo executed')
    endpoint='repos/GioNob/ouf-deploy/contents/'+CAPSULE_PATH+'?ref='+CAPSULE_COMMIT
    try:
        result=subprocess.run([gh,'api',endpoint,'--jq','.content'],check=True,stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,timeout=30)
        if len(result.stdout)>1500000:raise ValueError()
        raw=base64.b64decode(b''.join(result.stdout.split()),validate=True)
    except Exception:raise SystemExit('phase=DELIVERY reason=FULL_CAPSULE_UNAVAILABLE; no sudo executed') from None
    if not 0<len(raw)<=1048576 or hashlib.sha256(raw).hexdigest()!=CAPSULE_SHA:
        raise SystemExit('phase=DELIVERY reason=FULL_CAPSULE_HASH_MISMATCH; no sudo executed')
    root_code='CAPSULE_SHA='+repr(CAPSULE_SHA)+'\n'+ROOT_BODY
    try:return subprocess.run(['sudo','--','/usr/bin/python3','-I','-B','-S','-c',root_code],input=raw,timeout=320).returncode
    except Exception:raise SystemExit('phase=ROOT_EXECUTION reason=FULL_REVIEW_RESULT_UNAVAILABLE; preserve output, do not automatically rerun') from None

if __name__=='__main__':raise SystemExit(main())
