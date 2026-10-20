"""Seal the frozen native loader plus a distinct explicit production bridge."""
import ast
import base64
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path

def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(v):return hashlib.sha256(v).hexdigest()
def git_blob(v):return hashlib.sha1(b'blob '+str(len(v)).encode()+b'\0'+v).hexdigest()

BOOTSTRAP='''
import ast,base64,gzip,hashlib,io,json,os,re,signal,sys
def require(ok,code):
 if not ok:raise ValueError(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def unique(pairs):
 value={}
 for k,v in pairs:
  require(k not in value,'DUPLICATE_PRODUCTION_DELIVERY_FIELD');value[k]=v
 return value
control_globals={}
try:
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_PRODUCTION_CONTROL_REQUIRED')
 shapes={'prepare':2,'status':3,'review':4,'approve':3,'initialize':3,'step':3,'reconcile':3}
 require(len(sys.argv)>=2 and sys.argv[1]in shapes and len(sys.argv)==shapes[sys.argv[1]],'EXACT_FOREGROUND_PRODUCTION_ARGUMENTS_REQUIRED')
 require(hashlib.sha256(BOOTSTRAP.encode()).hexdigest()==DELIVERY['bootstrapHash'],'PRODUCTION_BOOTSTRAP_CHANGED')
 require(hashlib.sha256(encoded(CASE)).hexdigest()==DELIVERY['caseHash'],'PRODUCTION_CASE_CHANGED')
 require(hashlib.sha256(encoded(DELIVERY)).hexdigest()==DELIVERY_HASH,'PRODUCTION_DELIVERY_DECLARATION_CHANGED')
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in()).throw(ValueError('PRODUCTION_INVOCATION_DEADLINE')));signal.alarm(300)
 compressed=base64.b64decode(PACKED,validate=True);require(len(compressed)<=786432,'BOUNDED_PRODUCTION_COMPRESSED_CLOSURE_REQUIRED')
 with gzip.GzipFile(fileobj=io.BytesIO(compressed))as stream:raw=stream.read(4194305)
 require(0<len(raw)<=4194304,'BOUNDED_PRODUCTION_SOURCE_CLOSURE_REQUIRED')
 payload=json.loads(raw,object_pairs_hook=unique)
 require(set(payload)=={'loader','sources','control'}and hashlib.sha256(payload['control'].encode()).hexdigest()==DELIVERY['controlSourceHash'],'EXACT_PRODUCTION_CONTROL_SOURCE_REQUIRED')
 require(hashlib.sha256(payload['loader'].encode()).hexdigest()==DELIVERY['nativeDeclaration']['loaderHash'],'QUALIFIED_NATIVE_LOADER_CHANGED')
 sources={n:v.encode()for n,v in payload['sources'].items()}
 require({n:hashlib.sha256(v).hexdigest()for n,v in sources.items()}==DELIVERY['nativeDeclaration']['sourceHashes'],'QUALIFIED_NATIVE_SOURCE_BYTES_CHANGED')
 loader=payload['loader'].encode();namespace={'__name__':'verified_frozen_native_loader'}
 exec(compile(loader,'<qualified-frozen-native-loader>','exec'),namespace)
 native=DELIVERY['nativeDeclaration']
 entry,manifest=namespace['load_entry'](native['sourceCommit'],sources,loader,DELIVERY['nativeDeclarationHash'],native['sourcePins'])
 require(manifest==native,'QUALIFIED_NATIVE_DECLARATION_CHANGED')
 # The separately pinned bridge is stdlib-only and executes outside tools.*;
 # native loader/entry and their114 modules remain byte-for-byte qualified.
 tree=ast.parse(payload['control'])
 for node in ast.walk(tree):
  refs=[a.name for a in node.names]if isinstance(node,ast.Import)else []
  if isinstance(node,ast.ImportFrom):
   require(node.level==0 and node.module is not None,'RELATIVE_PRODUCTION_CONTROL_IMPORT_DENIED');refs=[node.module]
  for ref in refs:require(ref.split('.')[0]in('hashlib','ipaddress','json','os','pathlib','re','stat','subprocess','sys','tempfile','time'),'STDLIB_ONLY_PRODUCTION_CONTROL_REQUIRED')
  require(not(isinstance(node,ast.Call)and isinstance(node.func,ast.Name)and node.func.id=='__import__'),'DYNAMIC_PRODUCTION_CONTROL_IMPORT_DENIED')
 control_globals={'__name__':'verified_foreground_production_control'}
 exec(compile(tree,'<qualified-production-control>','exec'),control_globals)
 result=control_globals['execute'](entry,manifest,CASE,DELIVERY['controlSourceHash'],sys.argv[1:])
 print(encoded(result).decode(),flush=True)
except (Exception,KeyboardInterrupt)as error:
 code=str(error);reason=code if type(error).__name__ in('Denied','ValueError','CandidateDenied','RuntimeDenied','PreexecDenied','PlanDenied','Paused','HumanSessionPaused')and re.fullmatch('[A-Z][A-Z0-9_]{0,127}',code)else'PRODUCTION_CHECK_OR_OUTCOME_UNPROVEN_PRIVATE_DETAILS_REDACTED'
 print(encoded({'schema':'ouf.ingestion-rollout-production-control-result.v1','status':'STOP_RECONCILE','complete':False,
  'reasonCode':reason,'checkpoint':control_globals.get('CHECKPOINT',{'phase':'VERIFY_PRODUCTION_DELIVERY','contextPath':None}),
  'contextsAndClaimsRetained':True,'automaticReplayAllowed':False,'budgetReset':False,'newLoginPerformed':False,
  'automaticRefreshPerformed':False,'credentialValuesPrinted':False,'credentialHashesPrinted':False,
  'runtimeEffectsMayBePartial':len(sys.argv)>1 and sys.argv[1]in('approve','initialize','step','reconcile'),
  'notReleaseAcceptance':True}).decode(),flush=True)
 raise SystemExit(2)
'''

def generate(root,case):
    root=Path(root);path=root/'tools/ingestion_rollout_execution/runtime.py'
    spec=importlib.util.spec_from_file_location('qualified_native_delivery_loader',path)
    runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)
    loader=path.read_bytes();sources={n:(root/p).read_bytes()for n,p in runtime.SOURCE_PATHS.items()}
    selected=case['qualifiedNativeSource'];pins=selected['gitBlobPins']
    expected={**{p:git_blob(sources[n])for n,p in runtime.SOURCE_PATHS.items()},'tools/ingestion_rollout_execution/runtime.py':git_blob(loader)}
    if expected!=pins:raise ValueError('FROZEN_QUALIFIED_NATIVE_GIT_BYTES_CHANGED')
    manifest=runtime.declaration(selected['sourceCommit'],sources,loader,selected['sourcePins'])
    if case['qualification']['sourceHashes']!=manifest['sourceHashes']:raise ValueError('QUALIFICATION_SOURCE_SET_CHANGED')
    control=(root/'tools/ingestion_rollout_preparation/production_control.py').read_bytes()
    declaration={'schema':'ouf.ingestion-rollout-production-delivery.v1','bootstrapHash':sha(BOOTSTRAP.encode()),
        'controlSourceHash':sha(control),'caseHash':sha(encoded(case)),'nativeDeclaration':manifest,
        'nativeDeclarationHash':sha(encoded(manifest)),'oneInvocationOneMode':True,'runtimeAuthorityIssued':False}
    raw=encoded({'loader':loader.decode(),'sources':{n:v.decode()for n,v in sources.items()},'control':control.decode()})
    if len(raw)>4194304:raise ValueError('PRODUCTION_SOURCE_CLOSURE_TOO_LARGE')
    compressed=io.BytesIO()
    with gzip.GzipFile(filename='',mode='wb',fileobj=compressed,mtime=0,compresslevel=9)as stream:stream.write(raw)
    if len(compressed.getvalue())>786432:raise ValueError('PRODUCTION_COMPRESSED_SOURCE_TOO_LARGE')
    header='\n'.join(k+'='+repr(v)for k,v in(
        ('PACKED',base64.b64encode(compressed.getvalue()).decode('ascii')),('CASE',case),('DELIVERY',declaration),
        ('DELIVERY_HASH',sha(encoded(declaration))),('BOOTSTRAP',BOOTSTRAP)))
    artifact=(header+"\nexec(compile(BOOTSTRAP,'<qualified-production-bootstrap>','exec'))\n").encode()
    if len(artifact)>1048576:raise ValueError('PRODUCTION_EXECUTABLE_DELIVERY_TOO_LARGE')
    return artifact,declaration
