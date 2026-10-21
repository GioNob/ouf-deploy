"""Sealed finite API reader: no CLI authentication or dynamic source imports."""
import ast
import hashlib
import json
from pathlib import Path


def encoded(v):
    return json.dumps(v, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(v):
    return hashlib.sha256(v).hexdigest()


BOOTSTRAP = '''
import hashlib,json,os,re,resource,signal,sys
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
api={}
try:
 if not(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode):raise ValueError('ISOLATED_ROOT_IAM_API_READER_REQUIRED')
 if not(len(sys.argv)==2 and sys.argv[1]=='read'or len(sys.argv)==3 and sys.argv[1]=='status'):raise ValueError('ONE_EXPLICIT_IAM_READ_OR_STATUS_REQUIRED')
 if hashlib.sha256(canonical(CASE)).hexdigest()!=DECLARATION['caseHash']or hashlib.sha256(canonical(DECLARATION)).hexdigest()!=DECLARATION_HASH:raise ValueError('IAM_READ_CASE_OR_DECLARATION_CHANGED')
 if {k:hashlib.sha256(v.encode()).hexdigest()for k,v in SOURCES.items()}!=DECLARATION['sourceHashes']:raise ValueError('EXACT_IAM_READER_SOURCE_BYTES_REQUIRED')
 resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in()).throw(ValueError('IAM_READ_FINITE_DEADLINE')));signal.alarm(90)
 loaded={}
 for name,source in SOURCES.items():
  namespace={'__name__':'sealed_iam_policy_'+name}
  exec(compile(source,'<sealed-iam-policy:'+name+'>','exec'),namespace);loaded[name]=namespace
 api=loaded['api'];files=loaded['files']
 if sys.argv[1]=='read':value=api['run'](CASE,files['selected'],files['recheck'],loaded['journal']['Journal'])
 else:value=api['status'](CASE,sys.argv[2],files['selected'])
 print(canonical(value).decode(),flush=True)
except (Exception,KeyboardInterrupt)as error:
 code=str(error);reason=code if type(error)is ValueError and re.fullmatch('[A-Z][A-Z0-9_]{0,127}',code)else'IAM_READ_INPUT_OR_RESPONSE_UNPROVEN_PRIVATE_DETAILS_REDACTED'
 print(canonical({'schema':'ouf.iam-current-policy-read-result.v1','status':'STOP_RECONCILE','reasonCode':reason,'checkpoint':api.get('CHECKPOINT',{'phase':'VERIFY_DELIVERY','contextPath':None}),'complete':False,'readOnly':True,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False,'newLoginPerformed':False,'refreshPerformed':False,'oauthRequests':0,'iamMutations':0,'credentialValuesPrinted':False,'credentialHashesPrinted':False,'contextsAndClaimsRetained':True}).decode(),flush=True)
 raise SystemExit(2)
'''


def generate(root, case):
    root = Path(root)
    sources = {name: (root / path).read_text() for name, path in {
        'api': 'tools/ingestion_rollout_preparation/iam_policy_read.py',
        'files': 'tools/ingestion_rollout_preparation/human_timing.py',
        'journal': 'tools/semantic_lease_recovery/recovery_journal.py'}.items()}
    allowed = {'base64', 'contextlib', 'fcntl', 'hashlib', 'http', 'io', 'ipaddress', 'json',
        'os', 'pathlib', 're', 'socket', 'stat', 'subprocess', 'sys', 'tarfile', 'tempfile', 'time', 'urllib', 'uuid'}
    for source in sources.values():
        for node in ast.walk(ast.parse(source)):
            refs = [a.name for a in node.names] if isinstance(node, ast.Import) else []
            if isinstance(node, ast.ImportFrom):
                if node.level or node.module is None:
                    raise ValueError('RELATIVE_IAM_READER_IMPORT_DENIED')
                refs = [node.module]
            if any(n.split('.')[0] not in allowed for n in refs):
                raise ValueError('STDLIB_ONLY_IAM_READER_REQUIRED')
    declaration = {'schema': 'ouf.iam-policy-reader-delivery.v1', 'caseHash': sha(encoded(case)),
        'sourceHashes': {k: sha(v.encode()) for k, v in sources.items()},
        'bootstrapHash': sha(BOOTSTRAP.encode()), 'maximumSeconds': 90,
        'maximumEngineReadRequests': 7, 'maximumAdminGets': 3, 'runtimeAuthorityIssued': False}
    raw = ('\n'.join(k + '=' + repr(v) for k, v in (
        ('SOURCES', sources), ('CASE', case), ('DECLARATION', declaration),
        ('DECLARATION_HASH', sha(encoded(declaration))))) + '\n' + BOOTSTRAP).encode()
    if len(raw) > 131072:
        raise ValueError('BOUNDED_IAM_READER_DELIVERY_REQUIRED')
    return raw, declaration
