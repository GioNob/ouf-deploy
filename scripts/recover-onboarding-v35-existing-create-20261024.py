#!/usr/bin/env python3
"""Isolated, pinned adapter for one existing V35 candidate; never restart rollout."""
import hashlib,json,os,re,signal,stat,sys,types
from pathlib import Path

BASE='/etc/ouf/deploy-snapshots/onboarding-v35-native-code-a0ce9d7ffb2e4500'
BASE_HASHES={'apply.py':'55addc8768319abaecfd5501c489edeb6fba18aa5ca61ee1bed9b62b0f146eb2',
 'protocol.py':'034bb7572905903cca52033e9af098fdbe351d244a531302bf30831df338e43d',
 'ports.py':'a3997298bdb5ff0675bdf81506ec36600d7f6783f741aeff4ee7960d414881be',
 'quarantine.py':'69dcb537d1e8d6b4603078339fc7eb1b79a74a8357666d60f7937693a44f69c2'}
class Stop(RuntimeError):pass
def require(ok,code):
    if not ok:raise Stop(code)
def load_base():
    path=Path(BASE)/'apply.py'
    for p in path.parents:
        s=p.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and not s.st_mode&0o022,'PROTECTED_RETAINED_V35_CODE_REQUIRED')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        s=os.fstat(fd);raw=os.read(fd,131073);end=os.fstat(fd)
        fields=('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns');pin=lambda v:tuple(getattr(v,k)for k in fields)
        require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o400 and s.st_nlink==1
            and 0<len(raw)==s.st_size<=131072 and pin(s)==pin(end)==pin(path.lstat())and hashlib.sha256(raw).hexdigest()==BASE_HASHES['apply.py'],'EXACT_RETAINED_V35_CODE_BYTES_REQUIRED')
    finally:os.close(fd)
    module=types.ModuleType('verified_v35_recovery_base');module.__file__=str(path);sys.modules[module.__name__]=module
    exec(compile(raw,str(path),'exec'),module.__dict__);return module
def bootstrap():
    base=load_base();root=Path(__file__).parent;base.protected(Path(__file__))
    core=base.module('verified_v35_recovery_protocol',Path(BASE)/'protocol.py',BASE_HASHES['protocol.py'])
    ports=base.module('verified_v35_recovery_ports',Path(BASE)/'ports.py',BASE_HASHES['ports.py'])
    quarantine=base.module('verified_v35_recovery_quarantine',Path(BASE)/'quarantine.py',BASE_HASHES['quarantine.py']);ports.quarantine=quarantine
    base.module('verified_v35_recovery_sql',root/'recovery_sql.py')
    implementation=base.module('verified_v35_recovery_impl',root/'recovery.py')
    n=base.module('verified_v35_recovery_frozen_definitions',base.HELPER,base.HELPER_HASH)
    p,q,l,c,d,m,r,configuration,replacement=n.bootstrap()
    return implementation,implementation.Context(n,p,q,l,c,d,m,r,configuration,replacement,root,Path(__file__))
def main():
    ctx=None
    try:
        require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and len(sys.argv)==1,'ONE_ISOLATED_ROOT_EXISTING_V35_RECOVERY_REQUIRED')
        def cancelled(*_):raise Stop('V35_RECOVERY_INTERRUPTED_RECONCILE_ONLY')
        for sig in(signal.SIGINT,signal.SIGTERM,signal.SIGHUP):signal.signal(sig,cancelled)
        implementation,ctx=bootstrap();result=implementation.operator(ctx)
    except Exception as error:
        reason=str(error)if type(error).__name__ in ('Stop','Denied','CreationDenied','ImageCustodyDenied')and re.fullmatch('[A-Z0-9_]{1,120}',str(error))else'V35_EXISTING_CREATE_RECOVERY_UNPROVEN'
        result={'schema':'ouf.onboarding-v35-existing-create-result.v1','status':'STOP_RECONCILE','complete':False,'reasonCode':reason,
            'contextPath':str(ctx.root)if ctx else None,'runtimeEffectsMayBePartial':True,'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False,
            'automaticRollbackPerformed':False,'humanBudgetsGranted':0,'sourceActivations':0,'originalRequestRepeated':False,'credentialValuesPrinted':False,'addressesPrinted':False}
        if ctx is not None:result['retainedAndPreflightCounts']=ctx.preflight_counts
    print(json.dumps(result,sort_keys=True,separators=(',',':'),allow_nan=False),flush=True);return 0 if result.get('complete')is True else 2
if __name__=='__main__':raise SystemExit(main())
