"""Seal a metadata-only successor; retain the original API source and budget."""
import ast
import hashlib
import json
from pathlib import Path


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


BOOTSTRAP = '''
import hashlib,json,os,re,resource,signal,sys,types
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
reader={}
try:
 if not(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode):raise ValueError('ISOLATED_ROOT_IAM_CONTEXT_RECONCILIATION_REQUIRED')
 if len(sys.argv)!=2 or sys.argv[1]not in('reconcile','status'):raise ValueError('ONE_EXPLICIT_RECONCILIATION_OR_STATUS_REQUIRED')
 if hashlib.sha256(canonical(CASE)).hexdigest()!=DECLARATION['caseHash']or hashlib.sha256(canonical(DECLARATION)).hexdigest()!=DECLARATION_HASH:raise ValueError('EXACT_RECONCILIATION_CASE_AND_SOURCE_DECLARATION_REQUIRED')
 if {k:hashlib.sha256(v.encode()).hexdigest()for k,v in SOURCES.items()}!=DECLARATION['sourceHashes']:raise ValueError('EXACT_RECONCILIATION_SOURCE_BYTES_REQUIRED')
 if DECLARATION['sourceHashes']['api']!=CASE['originalReadApiSourceHash']:raise ValueError('ORIGINAL_STOPPED_READER_SOURCE_CHANGED')
 resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in()).throw(ValueError('IAM_CONTEXT_RECONCILIATION_FINITE_DEADLINE')));signal.alarm(90)
 loaded={}
 for name,source in SOURCES.items():
  namespace={'__name__':'sealed_iam_reconciliation_'+name}
  exec(compile(source,'<sealed-iam-context:'+name+'>','exec'),namespace);loaded[name]=namespace
 reader=loaded['reader'];api=types.SimpleNamespace(**loaded['api']);files=types.SimpleNamespace(**loaded['files']);Journal=loaded['journal']['Journal']
 if sys.argv[1]=='reconcile':value=reader['run'](CASE,api,files,Journal,DECLARATION['sourceHashes']['reader'])
 else:value=reader['status'](CASE,api,files,Journal)
 print(canonical(value).decode(),flush=True)
except (Exception,KeyboardInterrupt)as error:
 code=str(error);reason=code if type(error)is ValueError and re.fullmatch('[A-Z][A-Z0-9_]{0,127}',code)else'IAM_RECONCILIATION_INPUT_OR_METADATA_UNPROVEN_PRIVATE_DETAILS_REDACTED'
 print(canonical({'schema':'ouf.iam-session-context-reconcile-result.v1','status':'STOP_RECONCILE','reasonCode':reason,'checkpoint':reader.get('CHECKPOINT',{'phase':'VERIFY_DELIVERY','contextPath':None}),'complete':False,'readOnly':True,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False,'newLoginPerformed':False,'refreshPerformed':False,'oauthRequests':0,'iamMutations':0,'credentialValuesPrinted':False,'credentialHashesPrinted':False,'contextsAndClaimsRetained':True}).decode(),flush=True)
 raise SystemExit(2)
'''


def generate(root, case):
    root = Path(root)
    sources = {name: (root / path).read_text() for name, path in {
        'api': 'tools/ingestion_rollout_preparation/iam_policy_read.py',
        'reader': 'tools/ingestion_rollout_preparation/iam_session_context_reconcile.py',
        'files': 'tools/ingestion_rollout_preparation/human_timing.py',
        'journal': 'tools/semantic_lease_recovery/recovery_journal.py'}.items()}
    if sha(sources['api'].encode()) != case['originalReadApiSourceHash']:
        raise ValueError('ORIGINAL_STOPPED_IAM_READER_SOURCE_MUST_REMAIN_UNCHANGED')
    allowed = {'base64', 'contextlib', 'fcntl', 'hashlib', 'http', 'io', 'ipaddress', 'json',
        'os', 'pathlib', 're', 'socket', 'stat', 'subprocess', 'sys', 'tarfile', 'tempfile', 'time', 'urllib', 'uuid'}
    for source in sources.values():
        for node in ast.walk(ast.parse(source)):
            refs = [v.name for v in node.names] if isinstance(node, ast.Import) else []
            if isinstance(node, ast.ImportFrom):
                if node.level or node.module is None:
                    raise ValueError('RELATIVE_RECONCILIATION_IMPORT_DENIED')
                refs = [node.module]
            if any(v.split('.')[0] not in allowed for v in refs):
                raise ValueError('STDLIB_ONLY_RECONCILIATION_SOURCE_REQUIRED')
    declaration = {'schema': 'ouf.iam-session-context-reconciliation-delivery.v1',
        'caseHash': sha(encoded(case)), 'sourceHashes': {k: sha(v.encode()) for k, v in sources.items()},
        'bootstrapHash': sha(BOOTSTRAP.encode()), 'maximumSeconds': 90,
        'maximumAdditionalEngineRequests': 2, 'maximumCumulativeEngineRequests': 7,
        'maximumAdminApiRequests': 0, 'maximumCredentialFileReads': 1,
        'runtimeAuthorityIssued': False}
    raw = ('\n'.join(k + '=' + repr(v) for k, v in (
        ('SOURCES', sources), ('CASE', case), ('DECLARATION', declaration),
        ('DECLARATION_HASH', sha(encoded(declaration))))) + '\n' + BOOTSTRAP).encode()
    if len(raw) > 131072:
        raise ValueError('BOUNDED_CONTEXT_RECONCILIATION_DELIVERY_REQUIRED')
    return raw, declaration
