"""Pinned existing-gh delivery, closed memory execution, preparation only."""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

COMMIT='4d3d10e26b584a1d6e28811754e169e93723f396'
HASHES={
    'iam_binding_candidate':'a8cf18ea78b3acc7261838711345a218e678bfaf11e498dcba6859862d6b655d',
    'iam_mapper_enrichment':'6b6cbfdfd2a4b628c35d8a7eeb087339e15e0ae49aff8be1f359f74de7e0699e',
    'iam_governance_intake':'6dd8efb3f4e1728d429eb88c8dc8654527093756ea352da17e4df2effec90c2b'}
ROOT_BODY=r'''
import base64,hashlib,json,os,sys,types
def deny(reason):raise SystemExit('phase=ROOT_DELIVERY reason='+reason)
if os.geteuid()!=0 or os.getegid()!=0 or not sys.flags.isolated or not sys.dont_write_bytecode:deny('ROOT_ISOLATED_REQUIRED')
raw=sys.stdin.buffer.read(131073)
if not 0<len(raw)<=131072:deny('DELIVERY_PAYLOAD_UNBOUNDED')
def unique(rows):
    out={}
    for k,v in rows:
        if k in out:deny('DUPLICATE_DELIVERY_KEY')
        out[k]=v
    return out
payload=json.loads(raw,object_pairs_hook=unique)
if type(payload)is not dict or set(payload)!={'sourceCommit','sources'} or payload['sourceCommit']!=COMMIT or type(payload['sources'])is not dict or set(payload['sources'])!=set(HASHES):deny('EXACT_DELIVERY_SET_REQUIRED')
sources={}
for name,expected in HASHES.items():
    data=base64.b64decode(payload['sources'][name],validate=True)
    if not 0<len(data)<=131072 or hashlib.sha256(data).hexdigest()!=expected:deny('SOURCE_HASH_MISMATCH')
    if name in sys.modules:deny('PRELOADED_SOURCE_MODULE')
    sources[name]=data
for name in HASHES:
    module=types.ModuleType(name);sys.modules[name]=module
    exec(compile(sources[name],'verified-preparation-'+name,'exec'),module.__dict__)
raise SystemExit(sys.modules['iam_governance_intake'].main({'sourceCommit':COMMIT,'sourceHashes':HASHES}))
'''
ROOT_CODE='COMMIT='+repr(COMMIT)+'\nHASHES='+repr(HASHES)+'\n'+ROOT_BODY

def existing_gh():
    preferred=Path.home()/'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh'
    if preferred.is_file() and os.access(preferred,os.X_OK):return str(preferred)
    return shutil.which('gh')

def main():
    gh=existing_gh()
    if not gh:raise SystemExit('phase=DELIVERY reason=EXISTING_GH_UNAVAILABLE; no sudo executed')
    sources={}
    for name,expected in HASHES.items():
        endpoint='repos/GioNob/ouf-deploy/contents/tools/semantic_policy_token_owner/'+name+'.py?ref='+COMMIT
        try:
            result=subprocess.run([gh,'api',endpoint,'--jq','.content'],check=True,stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,timeout=30)
            if len(result.stdout)>131072:raise ValueError()
            data=base64.b64decode(b''.join(result.stdout.split()),validate=True)
        except Exception:raise SystemExit('phase=DELIVERY reason=QUALIFIED_SOURCE_UNAVAILABLE; no sudo executed') from None
        if not 0<len(data)<=131072 or hashlib.sha256(data).hexdigest()!=expected:
            raise SystemExit('phase=DELIVERY reason=SOURCE_HASH_MISMATCH; no sudo executed')
        sources[name]=base64.b64encode(data).decode('ascii')
    payload=json.dumps({'sourceCommit':COMMIT,'sources':sources},sort_keys=True,separators=(',',':')).encode()
    if len(payload)>131072:raise SystemExit('phase=DELIVERY reason=PAYLOAD_UNBOUNDED; no sudo executed')
    try:return subprocess.run(['sudo','--','/usr/bin/python3','-I','-B','-c',ROOT_CODE],input=payload,timeout=220).returncode
    except Exception:raise SystemExit('phase=ROOT_EXECUTION reason=PREPARATION_RESULT_UNAVAILABLE; retain output, do not automatically rerun') from None

if __name__=='__main__':raise SystemExit(main())
