"""Seal an unexecuted, separately reviewed client-lifetime policy successor."""
import ast
import hashlib
import json
from pathlib import Path


def encoded(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


BOOTSTRAP='''
import hashlib,json,os,re,resource,signal,sys,types
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
reader={};loaded={}
try:
 if not(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode):raise ValueError('ISOLATED_ROOT_CLIENT_LIFETIME_OPERATOR_REQUIRED')
 if len(sys.argv)!=2 or sys.argv[1]not in('execute','status'):raise ValueError('ONE_EXPLICIT_CLIENT_LIFETIME_OR_STATUS_REQUIRED')
 if hashlib.sha256(canonical(CASE)).hexdigest()!=DECLARATION['caseHash']or hashlib.sha256(canonical(DECLARATION)).hexdigest()!=DECLARATION_HASH:raise ValueError('EXACT_LIFETIME_CASE_AND_DECLARATION_REQUIRED')
 if {k:hashlib.sha256(v.encode()).hexdigest()for k,v in SOURCES.items()}!=DECLARATION['sourceHashes']:raise ValueError('EXACT_LIFETIME_SOURCE_BYTES_REQUIRED')
 if DECLARATION['sourceHashes']['admin']!=CASE['originalApiSourceHash']:raise ValueError('QUALIFIED_ADMIN_AUTHENTICATION_SOURCE_CHANGED')
 if DECLARATION['sourceHashes']['api']!=CASE['originalApiCase']['reconciledCase']['originalReadApiSourceHash']or DECLARATION['sourceHashes']['process']!=CASE['originalApiCase']['reconciledSourceHash']:raise ValueError('RETAINED_ADMIN_SOURCES_CHANGED')
 resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 def interrupted(*_):raise ValueError('CLIENT_LIFETIME_OPERATOR_INTERRUPTED_RECONCILE')
 signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGHUP,interrupted)
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in()).throw(ValueError('CLIENT_LIFETIME_FINITE_DEADLINE')));signal.alarm(240)
 for name,source in SOURCES.items():
  ns={'__name__':'sealed_client_lifetime_'+name};exec(compile(source,'<sealed-client-lifetime:'+name+'>','exec'),ns);loaded[name]=ns
 reader=loaded['reader'];api=types.SimpleNamespace(**loaded['api']);admin=types.SimpleNamespace(**loaded['admin']);files=types.SimpleNamespace(**loaded['files']);Journal=loaded['journal']['Journal']
 if sys.argv[1]=='execute':value=reader['run'](CASE,api,admin,files,types.SimpleNamespace(**loaded['process']),Journal)
 else:value=reader['status'](CASE,api,files,Journal)
 print(canonical(value).decode(),flush=True)
except (Exception,KeyboardInterrupt)as error:
 code=str(error);reason=code if type(error)is ValueError and re.fullmatch('[A-Z][A-Z0-9_]{0,127}',code)else'LIFETIME_INPUT_OR_OUTCOME_UNPROVEN_PRIVATE_DETAILS_REDACTED'
 counters={}
 try:
  v=reader['status'](CASE,types.SimpleNamespace(**loaded['api']),types.SimpleNamespace(**loaded['files']),loaded['journal']['Journal'])
  counters={k:v[k]for k in('attempts','remainingAttempts','oauthRequestsReserved','engineRequestsReserved','adminGetsReserved','clientPutsReserved')}
 except BaseException:pass
 print(canonical({'schema':'ouf.iam-client-lifetime-result.v1','status':'STOP_RECONCILE','reasonCode':reason,'checkpoint':reader.get('CHECKPOINT',{'phase':'VERIFY_DELIVERY','contextPath':None}),'complete':False,'readOnly':False,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False,'automaticRollbackAllowed':False,'credentialValuesPrinted':False,'credentialHashesPrinted':False,'contextsAndClaimsRetained':True,**counters}).decode(),flush=True)
 raise SystemExit(2)
'''


def generate(root,case):
    root=Path(root)
    sources={k:(root/v).read_text()for k,v in {
        'api':'tools/ingestion_rollout_preparation/iam_policy_read.py',
        'admin':'tools/ingestion_rollout_preparation/iam_explicit_api.py',
        'process':'tools/ingestion_rollout_preparation/iam_session_context_reconcile.py',
        'reader':'tools/ingestion_rollout_preparation/iam_lifetime_policy.py',
        'files':'tools/ingestion_rollout_preparation/human_timing.py',
        'journal':'tools/semantic_lease_recovery/recovery_journal.py'}.items()}
    if sha(sources['admin'].encode())!=case['originalApiSourceHash']:
        raise ValueError('QUALIFIED_ADMIN_AUTHENTICATION_SOURCE_MUST_REMAIN_UNCHANGED')
    allowed={'base64','contextlib','copy','fcntl','hashlib','http','io','ipaddress','json','os','pathlib',
        're','select','socket','stat','subprocess','sys','tarfile','tempfile','termios','time','urllib','uuid'}
    for source in sources.values():
        for n in ast.walk(ast.parse(source)):
            names=[v.name for v in n.names]if isinstance(n,ast.Import)else[]
            if isinstance(n,ast.ImportFrom):
                if n.level or n.module is None:raise ValueError('RELATIVE_LIFETIME_IMPORT_DENIED')
                names=[n.module]
            if any(v.split('.')[0]not in allowed for v in names):raise ValueError('STDLIB_ONLY_LIFETIME_SOURCE_REQUIRED')
    declaration={'schema':'ouf.iam-client-lifetime-delivery.v1','caseHash':sha(encoded(case)),
        'sourceHashes':{k:sha(v.encode())for k,v in sources.items()},'bootstrapHash':sha(BOOTSTRAP.encode()),
        'maximumSeconds':240,'maximumNewOAuthRequests':1,'maximumNewAdminGets':5,'maximumClientPuts':1,
        'maximumNewEngineGets':2,'humanWindowOpeningAllowed':False,'runtimeAuthorityIssued':False}
    raw=('\n'.join(k+'='+repr(v)for k,v in (('SOURCES',sources),('CASE',case),('DECLARATION',declaration),
        ('DECLARATION_HASH',sha(encoded(declaration)))))+'\n'+BOOTSTRAP).encode()
    if len(raw)>131072:raise ValueError('BOUNDED_LIFETIME_DELIVERY_REQUIRED')
    return raw,declaration
