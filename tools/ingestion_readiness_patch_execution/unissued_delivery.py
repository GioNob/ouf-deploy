"""Build-only standalone custody reader; no old launcher is executed."""
import hashlib
import json
from pathlib import Path


def generate(root,case):
    case=json.loads(json.dumps(case,sort_keys=True,separators=(',',':'),allow_nan=False))
    source=(Path(root)/'tools/ingestion_readiness_patch_execution/unissued_reconcile.py').read_text()
    raw=('CASE='+repr(case)+'\n'+source+'\nmain(CASE)\n').encode()
    if len(raw)>65536:raise ValueError('BOUNDED_UNISSUED_READER_DELIVERY_REQUIRED')
    return raw,{'schema':'ouf.ingestion-readiness-unissued-reader-delivery.v1',
        'caseHash':hashlib.sha256(json.dumps(case,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest(),
        'readerSourceSha256':hashlib.sha256(source.encode()).hexdigest(),
        'artifactSha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'readOnly':True,
        'runtimeAuthorityIssued':False,'oauthRequests':0,'automaticReplayAllowed':False}
