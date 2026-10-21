"""Small isolated technical-budget controller; no native/credential/network code."""
import base64
import gzip
import hashlib
import io
import json
from pathlib import Path

def encoded(v): return json.dumps(v, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
def sha(v): return hashlib.sha256(v).hexdigest()

BOOTSTRAP = '''
import ast,base64,gzip,hashlib,io,json,os,re,signal,sys
def require(ok,code):
 if not ok:raise ValueError(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def unique(pairs):
 v={}
 for k,x in pairs:
  require(k not in v,'DUPLICATE_BUDGET_DELIVERY_FIELD');v[k]=x
 return v
phase='VERIFY_BUDGET_SOURCE';mode=None
try:
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_BUDGET_CONTROL_REQUIRED')
 require(len(sys.argv)==2 and sys.argv[1]in('prepare','grant-budget','status'),'ONE_EXPLICIT_BUDGET_MODE_REQUIRED');mode=sys.argv[1]
 require(hashlib.sha256(BOOTSTRAP.encode()).hexdigest()==DECLARATION['bootstrapHash']and hashlib.sha256(encoded(DECLARATION)).hexdigest()==DECLARATION_HASH,'BUDGET_DELIVERY_CHANGED')
 require(hashlib.sha256(encoded(CASE)).hexdigest()==DECLARATION['caseHash'],'BUDGET_CASE_CHANGED')
 signal.signal(signal.SIGALRM,lambda *_:require(False,'FINITE_BUDGET_CONTROL_DEADLINE'));signal.alarm(180)
 compressed=base64.b64decode(PACKED,validate=True);require(len(compressed)<=131072,'BOUNDED_BUDGET_PACKAGE_REQUIRED')
 with gzip.GzipFile(fileobj=io.BytesIO(compressed))as stream:raw=stream.read(262145)
 require(0<len(raw)<=262144,'BOUNDED_BUDGET_SOURCE_REQUIRED')
 sources=json.loads(raw,object_pairs_hook=unique)
 require(set(sources)=={'snapshot','budget'}and {k:hashlib.sha256(v.encode()).hexdigest()for k,v in sources.items()}==DECLARATION['sourceHashes'],'EXACT_BUDGET_SOURCE_HASHES_REQUIRED')
 compiled={}
 for name,source in sources.items():
  tree=ast.parse(source)
  for node in ast.walk(tree):
   refs=[a.name for a in node.names]if isinstance(node,ast.Import)else[]
   if isinstance(node,ast.ImportFrom):require(node.level==0 and node.module is not None,'RELATIVE_BUDGET_IMPORT_DENIED');refs=[node.module]
   for ref in refs:require(ref.split('.')[0]in('copy','fcntl','hashlib','json','math','os','pathlib','re','select','signal','stat','sys','termios','time'),'NO_NETWORK_OR_APPLICATION_BUDGET_IMPORT_ALLOWED')
   require(not(isinstance(node,ast.Call)and isinstance(node.func,ast.Name)and node.func.id=='__import__'),'DYNAMIC_BUDGET_IMPORT_DENIED')
  compiled[name]=compile(tree,'<verified-technical-budget-'+name+'>','exec')
 snapshot={'__name__':'verified_read_only_snapshot'};exec(compiled['snapshot'],snapshot)
 budget={'__name__':'verified_technical_oauth_budget'};exec(compiled['budget'],budget)
 phase='EXPLICIT_TECHNICAL_BUDGET_'+mode.upper().replace('-','_')
 result=budget['execute'](mode,CASE,snapshot)
 print(encoded(result).decode(),flush=True)
except (Exception,KeyboardInterrupt)as error:
 code=str(error);reason=code if type(error).__name__ in ('Denied','ValueError')and re.fullmatch('[A-Z][A-Z0-9_]{0,127}',code)else'BUDGET_CHECK_UNPROVEN_PRIVATE_DETAILS_REDACTED'
 print(encoded({'schema':'ouf.technical-oauth-budget-extension-result.v1','complete':False,'status':'STOP_RECONCILE','reasonCode':reason,'phase':phase,'contextsAndClaimsRetained':True,'grantMayBePartial':mode=='grant-budget','oauthRequests':0,'newLoginPerformed':False,'newHumanWindowOpened':False,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False}).decode(),flush=True)
 raise SystemExit(2)
'''

def generate(root, case):
    root = Path(root)
    snapshot = (root / 'scripts/read-ingestion-rollout-stopped-20261021.py').read_text()
    if sha(snapshot.encode()) != '57a5941574bf5beb0fcfe6e3d5465914a34673c651d74c892133be782e0a5e32':
        raise ValueError('QUALIFIED_STOPPED_READER_CHANGED')
    sources = {'snapshot': snapshot,
        'budget': (root / 'tools/ingestion_rollout_preparation/oauth_budget_extension.py').read_text()}
    declaration = {'schema': 'ouf.technical-oauth-budget-extension-delivery.v1',
        'sourceHashes': {k: sha(v.encode()) for k, v in sources.items()},
        'bootstrapHash': sha(BOOTSTRAP.encode()), 'caseHash': sha(encoded(case)),
        'credentialOrNetworkModulesAllowed': False, 'runtimeAuthorityIssued': False,
        'maximumAdditionalOAuthAttempts': 4, 'windowOpeningImplemented': False}
    compressed = io.BytesIO()
    with gzip.GzipFile(filename='', mode='wb', fileobj=compressed, mtime=0, compresslevel=9) as stream:
        stream.write(encoded(sources))
    header = '\n'.join(k + '=' + repr(v) for k, v in (
        ('PACKED', base64.b64encode(compressed.getvalue()).decode('ascii')),
        ('CASE', case), ('DECLARATION', declaration), ('DECLARATION_HASH', sha(encoded(declaration))),
        ('BOOTSTRAP', BOOTSTRAP)))
    result = (header + "\nexec(compile(BOOTSTRAP,'<verified-technical-oauth-budget-bootstrap>','exec'))\n").encode()
    if len(result) > 262144: raise ValueError('BUDGET_ARTIFACT_TOO_LARGE')
    return result, declaration
