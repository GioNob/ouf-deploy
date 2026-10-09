"""Pure, hash-pinned proposed source revision; no target authority or writes."""
import hashlib

BROKER='scripts/semantic_provider_deployment_broker.py'
RUNTIME='scripts/semantic_provider_docker_runtime.py'
ORIGINAL={BROKER:'943ebeaee7d714ea5b00e59a1bac680803bff097b7f9e7cb2f218a26c61bf140',
    RUNTIME:'acf9c5140b700fbb4448d4b8eccd3d3ae3f7e6af5e173aa0474965ad170e6141'}
LOCK_CODE='''
@contextmanager
def bounded_broker_lock(path, budget):
    """Wait only for lock acquisition; never retry a protected operation."""
    from tools.semantic_provider_lease_coordination import hold_common_lock
    path=Path(path);identity=(path.lstat().st_dev,path.lstat().st_ino)
    while True:
        budget.check()
        require((path.lstat().st_dev,path.lstat().st_ino)==identity,'BROKER_LOCK_INODE_CHANGED')
        held=hold_common_lock(path)
        try:held.__enter__()
        except BlockingIOError:
            time.sleep(budget.remaining(0.01))
            continue
        break
    try:
        budget.check()
        require((path.lstat().st_dev,path.lstat().st_ino)==identity,'BROKER_LOCK_INODE_CHANGED')
        yield
    finally:held.__exit__(None,None,None)


def retained_denial(error, args, cfg):
    reason=str(error)
    if not re.fullmatch('[A-Z][A-Z0-9_]{0,95}',reason):
        reason='BROKER_COMMON_LOCK_BUSY' if isinstance(error,BlockingIOError) else 'BROKER_OPERATION_UNPROVEN'
    report={'schema':'ouf.semantic-broker-phase-denial.v1','phase':args.mode if args.mode in ('authorize-create','record-created','cohort-ready','prepare','cleanup') else 'UNKNOWN',
        'reason':reason,'errorType':type(error).__name__, 'secretValuesPrinted':False,
        'exceptionPoints':[{'file':Path(t.filename).name,'function':t.name,'line':t.lineno}
            for t in traceback.extract_tb(error.__traceback__)[-4:]],'diagnosisSaved':False,
        'notReleaseAcceptance':True}
    if cfg is not None:
        try:
            require(args.mode in ('authorize-create','record-created','cohort-ready','prepare','cleanup'),
                'EXACT_BROKER_DENIAL_PHASE_REQUIRED')
            root=Path(cfg['candidateRoot'])
            journal=parse(private(root/'broker-state.json'))
            require(root.name==args.container_id and journal['containerId']==args.container_id,
                'OWNED_BROKER_DENIAL_DIRECTORY_REQUIRED')
            report['diagnosisSaved']=True
            create(root/('broker-denial-'+args.mode+'.json'),report)
        except Exception:report['diagnosisSaved']=False
    return report

'''

def replace_once(value,old,new):
    if value.count(old)!=1:raise ValueError('EXACT_SOURCE_REPAIR_SITE_REQUIRED')
    return value.replace(old,new,1)

def repair(sources):
    result=dict(sources)
    for name,expected in ORIGINAL.items():
        if hashlib.sha256(sources[name]).hexdigest()!=expected:raise ValueError('ORIGINAL_BROKER_SOURCE_HASH_DRIFT')
    code=sources[BROKER].decode()
    code=replace_once(code,'import argparse\n','import argparse\nfrom contextlib import contextmanager\nimport re\nimport traceback\n')
    code=replace_once(code,'class Broker:\n',LOCK_CODE+'class Broker:\n')
    code=replace_once(code,"self.lock=lambda:hold_common_lock(Path(self.template['lockFile']))",
        "self.lock=lambda:bounded_broker_lock(Path(self.template['lockFile']),self.budget)")
    code=replace_once(code,'    try:\n        cfg,raw=load(args.configuration)', '    cfg=None\n    try:\n        cfg,raw=load(args.configuration)')
    code=replace_once(code,"    except Exception:\n        print('SEMANTIC_DEPLOYMENT_BROKER=DENIED EXPLICIT_RECOVERY_REQUIRED=true NO_SECRETS_PRINTED=true',file=sys.stderr)",
        "    except Exception as error:\n        report=retained_denial(error,args,cfg)\n        print('SEMANTIC_DEPLOYMENT_BROKER_DENIAL='+json.dumps(report,sort_keys=True))\n        print('SEMANTIC_DEPLOYMENT_BROKER=DENIED EXPLICIT_RECOVERY_REQUIRED=true NO_SECRETS_PRINTED=true',file=sys.stderr)")
    result[BROKER]=code.encode()
    code=sources[RUNTIME].decode()
    code=replace_once(code,"require(result.returncode == 0, 'TWO_PHASE_BROKER_DENIED')",
        "require(result.returncode == 0, 'BROKER_PHASE_'+mode.upper().replace('-', '_')+'_DENIED')")
    result[RUNTIME]=code.encode()
    for name in ORIGINAL:compile(result[name],name,'exec')
    return result
