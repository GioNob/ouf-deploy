"""Build only; standalone metadata reader from exact existing custody source."""
import json
from pathlib import Path

def generate(root,case):
    p=Path(root)/'tools/ingestion_readiness_patch_execution'
    custody=(p/'unissued_reconcile.py').read_text().split('\ndef inspect(case):')[0]
    source=(p/'stopped_patch_snapshot.py').read_text().replace(
        'from tools.ingestion_readiness_patch_execution.unissued_reconcile import Directory,require,digest,hashed\n','')
    main='''
try:
    require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_STOPPED_PATCH_READER_REQUIRED')
    signal.signal(signal.SIGALRM,lambda *_:require(False,'FINITE_STOPPED_PATCH_READER_DEADLINE'));signal.alarm(60)
    print(encoded(inspect(CASE)).decode(),flush=True)
except (Exception,KeyboardInterrupt)as error:
    reason=str(error)
    if re.fullmatch('[A-Z][A-Z0-9_]{0,127}',reason)is None:reason='STOPPED_PATCH_METADATA_UNPROVEN_PRIVATE_DETAILS_REDACTED'
    print(encoded({'schema':'ouf.ingestion-readiness-stopped-snapshot.v1','status':'STOP_RECONCILE','reasonCode':reason,'complete':False,'readOnly':True,'automaticReplayAllowed':False,'runtimeAuthorityIssued':False,'runtimeEffectsDispatched':0,'oauthRequests':0}).decode(),flush=True)
    raise SystemExit(2)
'''
    raw=('CASE='+repr(json.loads(json.dumps(case,sort_keys=True)))+'\n'+custody+'\n'+source+main).encode()
    if len(raw)>65536:raise ValueError('BOUNDED_STOPPED_PATCH_READER_REQUIRED')
    return raw
