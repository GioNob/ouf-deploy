"""Reproducible stdlib-only delivery; one offline timing read, no modes to apply."""
import ast
import hashlib
import json
from pathlib import Path


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


BOOTSTRAP = '''
import hashlib,json,os,signal,sys
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
try:
 if not(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and len(sys.argv)==1):raise ValueError('ISOLATED_ROOT_TIMING_INSPECTION_REQUIRED')
 if hashlib.sha256(SOURCE.encode()).hexdigest()!=DECLARATION['sourceHash']or hashlib.sha256(canonical(CASE)).hexdigest()!=DECLARATION['caseHash']or hashlib.sha256(canonical(DECLARATION)).hexdigest()!=DECLARATION_HASH:raise ValueError('SEALED_TIMING_DELIVERY_CHANGED')
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in()).throw(ValueError('TIMING_INSPECTION_FINITE_DEADLINE')));signal.alarm(30)
 namespace={'__name__':'sealed_offline_timing_inspection'}
 exec(compile(SOURCE,'<sealed-offline-timing-inspection>','exec'),namespace)
 value=namespace['inspect'](CASE)
 print(canonical(value).decode(),flush=True)
except (Exception,KeyboardInterrupt):
 print(canonical({'schema':'ouf.ingestion-human-timing-inspection-result.v1','status':'STOP_RECONCILE','reasonCode':'EXACT_RETAINED_TIMING_INPUT_OR_CUSTODY_REQUIRED','complete':False,'readOnly':True,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False,'newLoginPerformed':False,'refreshPerformed':False,'credentialValuesPrinted':False,'credentialHashesPrinted':False,'journalWrites':0,'oauthRequests':0,'contextsAndClaimsRetained':True}).decode(),flush=True)
 raise SystemExit(2)
'''


def generate(root, case):
    source = (Path(root) / 'tools/ingestion_rollout_preparation/human_timing.py').read_text()
    for node in ast.walk(ast.parse(source)):
        refs = [v.name for v in node.names] if isinstance(node, ast.Import) else []
        if isinstance(node, ast.ImportFrom):
            if node.level or node.module is None:
                raise ValueError('RELATIVE_TIMING_IMPORT_DENIED')
            refs = [node.module]
        if any(v.split('.')[0] not in {'base64', 'hashlib', 'json', 'os', 'pathlib', 're', 'stat', 'time'} for v in refs):
            raise ValueError('OFFLINE_STDLIB_ONLY_TIMING_INSPECTION_REQUIRED')
    declaration = {'schema': 'ouf.ingestion-human-timing-delivery.v1',
        'sourceHash': sha(source.encode()), 'caseHash': sha(encoded(case)),
        'bootstrapHash': sha(BOOTSTRAP.encode()), 'requiredPythonFlags': ['-I', '-B', '-S'],
        'maximumSeconds': 30, 'readOnly': True, 'runtimeAuthorityIssued': False}
    header = '\n'.join(k + '=' + repr(v) for k, v in (
        ('SOURCE', source), ('CASE', case), ('DECLARATION', declaration),
        ('DECLARATION_HASH', sha(encoded(declaration)))))
    artifact = (header + '\n' + BOOTSTRAP).encode()
    if len(artifact) > 65536:
        raise ValueError('BOUNDED_TIMING_DELIVERY_REQUIRED')
    return artifact, declaration
