"""Package the new explicit controller around the immutable139-source runtime.

The completed archive capsule is the authenticated source carrier, never an
entrypoint to rerun. No target, login or authority operation occurs at build.
"""
import ast
import base64
import gzip
import hashlib
import io
import json
from pathlib import Path

CORE_ARTIFACT_SHA='13335a0aa4ba672c80cc2f63ca1b3e2e9d97b111f876d61c62dbda514d8d4f31'
BOOTSTRAP='''import ast,base64,gzip,hashlib,importlib,io,json,os,re,signal,sys
def require(ok,code):
 if not ok:raise ValueError(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def unique(pairs):
 v={}
 for k,x in pairs:
  require(k not in v,'DUPLICATE_PATCH_OPERATOR_DELIVERY_FIELD');v[k]=x
 return v
mode=None
try:
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_PATCH_OPERATOR_REQUIRED')
 require(2<=len(sys.argv)<=3 and sys.argv[1]in('preflight','review','approve','initialize','step','reconcile','status'),'ONE_EXPLICIT_PATCH_OPERATOR_MODE_REQUIRED');mode=sys.argv[1]
 require(hashlib.sha256(BOOTSTRAP.encode()).hexdigest()==DELIVERY['bootstrapHash']and hashlib.sha256(encoded(DELIVERY)).hexdigest()==DELIVERY_HASH,'PATCH_OPERATOR_DELIVERY_CHANGED')
 require(hashlib.sha256(encoded(CASE)).hexdigest()==DELIVERY['caseHash'],'PATCH_OPERATOR_CASE_CHANGED')
 signal.signal(signal.SIGALRM,lambda *_:require(False,'FINITE_PATCH_OPERATOR_DEADLINE'));signal.alarm(180)
 packed=base64.b64decode(PACKED,validate=True);require(len(packed)<=786432,'BOUNDED_PATCH_OPERATOR_CAPSULE_REQUIRED')
 with gzip.GzipFile(fileobj=io.BytesIO(packed))as stream:raw=stream.read(4194305)
 require(0<len(raw)<=4194304,'BOUNDED_PATCH_OPERATOR_SOURCES_REQUIRED')
 p=json.loads(raw,object_pairs_hook=unique);require(set(p)=={'loader','sources','controller'},'CLOSED_PATCH_OPERATOR_SOURCE_PAYLOAD_REQUIRED')
 require(hashlib.sha256(p['controller'].encode()).hexdigest()==DELIVERY['controlSourceHash']==CASE['controlSourceHash'],'EXACT_PATCH_OPERATOR_CONTROL_SOURCE_REQUIRED')
 require(hashlib.sha256(p['loader'].encode()).hexdigest()==DELIVERY['nativeDeclaration']['loaderHash'],'IMMUTABLE_PATCH_NATIVE_LOADER_CHANGED')
 loader={};exec(compile(p['loader'],'<immutable-patch-native-loader>','exec'),loader)
 declaration=DELIVERY['nativeDeclaration'];require(hashlib.sha256(encoded(declaration)).hexdigest()==CASE['nativeDeclarationHash'],'PATCH_NATIVE_DECLARATION_CHANGED')
 entry,manifest=loader['load_entry'](declaration['sourceCommit'],{n:v.encode()for n,v in p['sources'].items()},p['loader'].encode(),CASE['nativeDeclarationHash'],declaration['sourcePins'])
 reader=importlib.import_module('tools.ingestion_readiness_patch_execution.custody')
 control_module=importlib.import_module('tools.ingestion_readiness_patch_execution.operator_control_v2')
 require(getattr(control_module,'__qualified_source_sha256__',None)==DELIVERY['controlSourceHash'],'SEALED_SUCCESSOR_CONTROL_REQUIRED')
 control=vars(control_module)
 result=control['execute'](entry,manifest,CASE,DELIVERY['controlSourceHash'],reader,sys.argv[1:])
 print(encoded(result).decode(),flush=True)
except (Exception,KeyboardInterrupt)as error:
 code=str(error);reason=code if re.fullmatch('[A-Z][A-Z0-9_]{0,127}',code)else'PATCH_OPERATOR_OUTCOME_UNPROVEN_PRIVATE_DETAILS_REDACTED'
 print(encoded({'schema':'ouf.ingestion-readiness-patch-operator-result.v1','status':'STOP_RECONCILE','complete':False,'reasonCode':reason,'contextsAndClaimsRetained':True,'runtimeEffectsMayBePartial':mode in('initialize','step','reconcile'),'automaticReplayAllowed':False,'oauthRequests':0,'newLoginPerformed':False,'refreshPerformed':False,'runtimeAuthorityIssued':False,'budgetReset':False}).decode(),flush=True)
 raise SystemExit(2)
'''

def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(v):return hashlib.sha256(v).hexdigest()
def core(root):
    raw=(Path(root)/'scripts/prepare-ingestion-native-archive-20261022.py').read_bytes()
    if sha(raw)!=CORE_ARTIFACT_SHA:raise ValueError('EXACT_COMPLETED_ARCHIVE_CAPSULE_SOURCE_CARRIER_REQUIRED')
    values={n.targets[0].id:ast.literal_eval(n.value)for n in ast.parse(raw).body
        if isinstance(n,ast.Assign)and isinstance(n.targets[0],ast.Name)and n.targets[0].id in ('PACKED','DELIVERY')}
    return json.loads(gzip.decompress(base64.b64decode(values['PACKED']))),values['DELIVERY']['nativeDeclaration']

def successor_core(root,source_commit,source_pins):
    from tools.ingestion_readiness_patch_execution import runtime_successor as loader
    root=Path(root);payload,old=core(root)
    sources={n:(root/loader.SOURCE_PATHS[n]).read_bytes()for n in loader.MODULES}
    for n,raw in payload['sources'].items():
        if sources[n]!=raw.encode():raise ValueError('ORIGINAL139_SOURCES_MUST_REMAIN_UNCHANGED')
    raw_loader=(root/'tools/ingestion_readiness_patch_execution/runtime_successor.py').read_bytes()
    manifest=loader.declaration(source_commit,sources,raw_loader,source_pins)
    return {'loader':raw_loader.decode(),'sources':{n:v.decode()for n,v in sources.items()}},manifest


def generate(root,case,manifest):
    root=Path(root);payload,current=successor_core(root,manifest['sourceCommit'],manifest['sourcePins'])
    if current!=manifest:raise ValueError('EXACT_SUCCESSOR144_DECLARATION_REQUIRED')
    control=(root/'tools/ingestion_readiness_patch_execution/operator_control_v2.py').read_bytes()
    if sha(control)!=case['controlSourceHash']or sha(encoded(manifest))!=case['nativeDeclarationHash']:
        raise ValueError('EXACT_SUCCESSOR_CONTROLLER_AND144_CASE_BINDINGS_REQUIRED')
    payload['controller']=control.decode()
    declaration={'schema':'ouf.ingestion-readiness-patch-operator-delivery.v2','nativeDeclaration':manifest,
        'caseHash':sha(encoded(case)),'controlSourceHash':sha(control),'bootstrapHash':sha(BOOTSTRAP.encode()),
        'runtimeAuthorityIssued':False}
    stream=io.BytesIO()
    with gzip.GzipFile(filename='',fileobj=stream,mode='wb',mtime=0)as compressed:compressed.write(encoded(payload))
    packed=base64.b64encode(stream.getvalue()).decode()
    canonical=json.loads(encoded(case))
    raw=('CASE='+repr(canonical)+'\nDELIVERY='+repr(declaration)+'\nDELIVERY_HASH='+repr(sha(encoded(declaration)))+
         '\nPACKED='+repr(packed)+'\nBOOTSTRAP='+repr(BOOTSTRAP)+'\nexec(compile(BOOTSTRAP,"<patch-successor>","exec"))\n').encode()
    if len(raw)>1048576:raise ValueError('BOUNDED_EXACT_PATCH_OPERATOR_REQUIRED')
    return raw,declaration
