"""Read the exact consumed R11 guard; never starts or repairs a worker."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import traceback
import types

ROOT=Path('/etc/ouf/deploy-snapshots/semantic-resilient-lease-recovery-r11-1gpckuir')
ENTRY_HASH='0cf3275fcd959da58a2b320de49b1059159da3da00fca611236e65c8d7136ad9'

def safe_error(error):
    reason=str(error)
    return {'errorType':type(error).__name__,
            'reason':reason if re.fullmatch('[A-Z][A-Z0-9_]{0,120}',reason) else 'READ_UNPROVEN',
            'errno':error.errno if isinstance(error,OSError) else None,
            'points':[{'function':t.name,'line':t.lineno} for t in traceback.extract_tb(error.__traceback__)[-4:]]}

def instrument(entry,reader):
    facts={}
    original=entry.require
    def require(ok,code):
        if not ok:facts.update(check=code,errorType='ValueError',reason=code)
        return original(ok,code)
    entry.require=require
    for name in ('private','generation','run','native_read'):
        function=getattr(reader,name)
        def wrapped(*args,_name=name,_function=function,**kw):
            try:return _function(*args,**kw)
            except Exception as error:
                facts.update(operation=_name,**safe_error(error))
                raise
        setattr(reader,name,wrapped)
    return facts

def net_admin_only():
    libc=ctypes.CDLL(None,use_errno=True)
    for number in range(64):
        if number==12:continue
        if libc.prctl(24,number,0,0,0)!=0 and ctypes.get_errno()!=22:
            raise OSError(ctypes.get_errno(),'capability bound failed')
    if libc.prctl(38,1,0,0,0)!=0:raise OSError(ctypes.get_errno(),'no new privileges failed')
    class Header(ctypes.Structure):_fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
    class Data(ctypes.Structure):_fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
    header=Header(0x20080522,0);data=(Data*2)()
    data[0].effective=data[0].permitted=1<<12
    if libc.capset(ctypes.byref(header),data)!=0:raise OSError(ctypes.get_errno(),'capset failed')

def probe(entry,reader,adapter,limited):
    facts=instrument(entry,reader)
    try:
        if limited:net_admin_only()
        adapter.guard()
        return {'status':'GUARD_PASS','netAdminOnly':limited}
    except Exception as error:
        return {'status':'GUARD_DENIED','netAdminOnly':limited,**safe_error(error),'innerFailure':facts}

def report():
    if os.geteuid()!=0 or not sys.flags.isolated or not sys.dont_write_bytecode:
        raise ValueError('ISOLATED_ROOT_REQUIRED')
    raw=(ROOT/'activate.py').read_bytes()
    if len(raw)>131072 or hashlib.sha256(raw).hexdigest()!=ENTRY_HASH:
        raise ValueError('EXACT_R11_ENTRYPOINT_HASH_REQUIRED')
    entry=types.ModuleType('r11_diagnostic_entry');entry.__file__=str(ROOT/'activate.py')
    exec(compile(raw,entry.__file__,'exec'),entry.__dict__)
    entry.ROOT=ROOT
    reader,core=entry.readers(ROOT)
    capsule=reader.parse(reader.private(ROOT/'authorization.json'))
    entry.validate_capsule(reader,capsule)
    for name,digest in capsule['programHashes'].items():reader.private(ROOT/name,digest)
    scope=reader.parse(reader.private(ROOT/'target_bindings_r11.json',entry.MODULE_HASHES['target_bindings_r11.json']))
    entry.require(scope==capsule['targetScope'],'EXACT_TARGET_SCOPE_REQUIRED')
    entry.require(reader.parse(reader.private(entry.CLAIM))==capsule['activationClaim'],'EXACT_CONSUMED_CLAIM_REQUIRED')
    cfg,owner=entry.configuration(reader)
    _,_,recovery=entry.runtime(reader,core,owner,cfg,scope,capsule)
    row=reader.parse(reader.private(ROOT/'retry/recovery.json'))
    status=reader.parse(reader.private(ROOT/'worker-status.json'))
    full=probe(entry,reader,recovery.adapter,False)
    readfd,writefd=os.pipe();pid=os.fork()
    if pid==0:
        os.close(readfd)
        try:
            result=probe(entry,reader,recovery.adapter,True)
            os.write(writefd,json.dumps(result,sort_keys=True).encode())
        finally:os._exit(0)
    os.close(writefd)
    chunks=[]
    while True:
        data=os.read(readfd,65536)
        if not data:break
        chunks.append(data)
    os.close(readfd);_,exit_status=os.waitpid(pid,0)
    if exit_status:raise ValueError('LIMITED_GUARD_PROBE_FAILED')
    return {'worker':{key:status.get(key) for key in ('state','reason','attempts','refreshCount','setsRevoked','workerPid')},
            'recovery':{key:row.get(key) for key in ('state','reason','attempts','contextRef')},
            'rootGuard':full,'workerCapabilityGuard':json.loads(b''.join(chunks))}

def main():
    base={'schema':'ouf.provider-r11-read-only-guard-diagnosis.v1',
          'snapshot':str(ROOT),'serviceRestarted':False,'claimCreated':False,
          'leaseWrites':0,'configurationWrites':0,'dnsQueries':0,'privateValuesPrinted':False,
          'doNotRerunApply':True,'notReleaseAcceptance':True}
    try:value={**base,**report(),'status':'R11_GUARD_DIAGNOSIS_CAPTURED'};code=0
    except Exception as error:value={**base,**safe_error(error),'status':'READ_ONLY_DIAGNOSIS_BLOCKED'};code=1
    print('OUF_R11_GUARD_DIAGNOSIS='+json.dumps(value,sort_keys=True))
    return code

if __name__=='__main__':sys.exit(main())
