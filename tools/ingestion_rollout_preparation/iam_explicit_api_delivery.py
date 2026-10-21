"""Seal a separately consented one-grant admin API operation."""
import ast
import hashlib
import json
from pathlib import Path


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


BOOTSTRAP = '''
import hashlib,json,os,re,resource,signal,sys,types
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
reader={};loaded={}
try:
 if not(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode):raise ValueError('ISOLATED_ROOT_EXPLICIT_ADMIN_API_REQUIRED')
 if len(sys.argv)!=2 or sys.argv[1]not in('execute','status'):raise ValueError('ONE_EXPLICIT_ADMIN_API_OR_STATUS_REQUIRED')
 if hashlib.sha256(canonical(CASE)).hexdigest()!=DECLARATION['caseHash']or hashlib.sha256(canonical(DECLARATION)).hexdigest()!=DECLARATION_HASH:raise ValueError('EXACT_EXPLICIT_ADMIN_CASE_AND_DECLARATION_REQUIRED')
 if {k:hashlib.sha256(v.encode()).hexdigest()for k,v in SOURCES.items()}!=DECLARATION['sourceHashes']:raise ValueError('EXACT_EXPLICIT_ADMIN_SOURCE_BYTES_REQUIRED')
 if DECLARATION['sourceHashes']['api']!=CASE['reconciledCase']['originalReadApiSourceHash']or DECLARATION['sourceHashes']['process']!=CASE['reconciledSourceHash']:raise ValueError('RETAINED_READER_SOURCES_MUST_REMAIN_UNCHANGED')
 resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in()).throw(ValueError('EXPLICIT_ADMIN_FINITE_DEADLINE')));signal.alarm(240)
 for name,source in SOURCES.items():
  namespace={'__name__':'sealed_explicit_admin_'+name}
  exec(compile(source,'<sealed-explicit-admin:'+name+'>','exec'),namespace);loaded[name]=namespace
 reader=loaded['reader'];api=types.SimpleNamespace(**loaded['api']);files=types.SimpleNamespace(**loaded['files']);Journal=loaded['journal']['Journal']
 if sys.argv[1]=='execute':value=reader['run'](CASE,api,files,types.SimpleNamespace(**loaded['process']),Journal)
 else:value=reader['status'](CASE,api,files,Journal)
 print(canonical(value).decode(),flush=True)
except (Exception,KeyboardInterrupt)as error:
 code=str(error);reason=code if type(error)is ValueError and re.fullmatch('[A-Z][A-Z0-9_]{0,127}',code)else'EXPLICIT_ADMIN_INPUT_OR_OUTCOME_UNPROVEN_PRIVATE_DETAILS_REDACTED'
 counters={}
 try:
  retained=reader['status'](CASE,types.SimpleNamespace(**loaded['api']),types.SimpleNamespace(**loaded['files']),loaded['journal']['Journal'])
  counters={k:retained[k]for k in('attempts','maximumCumulativeOAuthAttempts','remainingAttempts','oauthRequestsReserved','engineRequestsReserved','adminGetsReserved')}
 except BaseException:pass
 print(canonical({'schema':'ouf.iam-explicit-api-result.v1','status':'STOP_RECONCILE','reasonCode':reason,'checkpoint':reader.get('CHECKPOINT',{'phase':'VERIFY_DELIVERY','contextPath':None}),'complete':False,'readOnly':False,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False,'authenticationOutcomeRequiresRetainedReconciliation':True,'refreshPerformed':False,'policyMutations':0,'credentialValuesPrinted':False,'credentialHashesPrinted':False,'contextsAndClaimsRetained':True,**counters}).decode(),flush=True)
 raise SystemExit(2)
'''


def generate(root, case):
    root = Path(root)
    sources = {key: (root / value).read_text() for key, value in {
        'api': 'tools/ingestion_rollout_preparation/iam_policy_read.py',
        'process': 'tools/ingestion_rollout_preparation/iam_session_context_reconcile.py',
        'reader': 'tools/ingestion_rollout_preparation/iam_explicit_api.py',
        'files': 'tools/ingestion_rollout_preparation/human_timing.py',
        'journal': 'tools/semantic_lease_recovery/recovery_journal.py'}.items()}
    if sha(sources['api'].encode()) != case['reconciledCase']['originalReadApiSourceHash'] or sha(sources['process'].encode()) != case['reconciledSourceHash']:
        raise ValueError('RETAINED_ADMIN_SOURCES_MUST_REMAIN_UNCHANGED')
    allowed = {'base64', 'contextlib', 'fcntl', 'hashlib', 'http', 'io', 'ipaddress', 'json',
        'os', 'pathlib', 're', 'select', 'socket', 'stat', 'subprocess', 'sys', 'tarfile', 'tempfile', 'termios', 'time', 'urllib', 'uuid'}
    for source in sources.values():
        for node in ast.walk(ast.parse(source)):
            refs = [v.name for v in node.names] if isinstance(node, ast.Import) else []
            if isinstance(node, ast.ImportFrom):
                if node.level or node.module is None:
                    raise ValueError('RELATIVE_EXPLICIT_ADMIN_IMPORT_DENIED')
                refs = [node.module]
            if any(v.split('.')[0] not in allowed for v in refs):
                raise ValueError('STDLIB_ONLY_EXPLICIT_ADMIN_SOURCE_REQUIRED')
    declaration = {'schema': 'ouf.iam-explicit-api-delivery.v1', 'caseHash': sha(encoded(case)),
        'sourceHashes': {k: sha(v.encode()) for k, v in sources.items()}, 'bootstrapHash': sha(BOOTSTRAP.encode()),
        'maximumSeconds': 240, 'maximumNewOAuthRequests': 1, 'maximumNewAdminGets': 4,
        'maximumNewEngineGets': 2, 'originalEngineBudgetUnchanged': True,
        'automaticLoginAllowed': False, 'refreshAllowed': False, 'runtimeAuthorityIssued': False}
    raw = ('\n'.join(k + '=' + repr(v) for k, v in (
        ('SOURCES', sources), ('CASE', case), ('DECLARATION', declaration),
        ('DECLARATION_HASH', sha(encoded(declaration))))) + '\n' + BOOTSTRAP).encode()
    if len(raw) > 131072:
        raise ValueError('BOUNDED_EXPLICIT_ADMIN_DELIVERY_REQUIRED')
    return raw, declaration
