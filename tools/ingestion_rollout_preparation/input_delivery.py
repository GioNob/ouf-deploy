"""Small closed delivery for bounded installation metadata capture.

Only read_selected/decode are extracted from the qualified inspection module.
No HUMAN session implementation, provider transport or signing code is shipped.
"""
import ast
import base64
import gzip
import hashlib
import io
import json
from pathlib import Path

ENTRY='tools.ingestion_rollout_preparation.native_inputs'
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(v):return hashlib.sha256(v).hexdigest()

BOOTSTRAP='''
import ast,base64,gzip,hashlib,importlib.abc,importlib.util,io,json,os,signal,sys
def require(ok,code):
 if not ok:raise ValueError(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def unique(pairs):
 value={}
 for k,v in pairs:
  require(k not in value,'DUPLICATE_CAPTURE_FIELD');value[k]=v
 return value
class ClosedCapture(importlib.abc.MetaPathFinder,importlib.abc.Loader):
 def find_spec(self,fullname,path=None,target=None):
  if fullname in SOURCES or fullname in PACKAGES:return importlib.util.spec_from_loader(fullname,self,is_package=fullname in PACKAGES)
  if fullname=='tools'or fullname.startswith('tools.'):raise ValueError('CAPTURE_DISK_IMPORT_FALLBACK_DENIED')
  return None
 def create_module(self,spec):return None
 def exec_module(self,module):
  if module.__name__ in PACKAGES:module.__path__=[]
  else:exec(COMPILED[module.__name__],module.__dict__)
def main():
 global SOURCES,COMPILED
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_CAPTURE_REQUIRED')
 require((len(sys.argv)==2 and sys.argv[1]=='capture')or(len(sys.argv)==3 and sys.argv[1]=='inspect'),'EXACT_CAPTURE_MODE_CONTEXT_REQUIRED')
 require(hashlib.sha256(BOOTSTRAP.encode()).hexdigest()==DECLARATION['loaderHash'],'CAPTURE_LOADER_CHANGED')
 require(hashlib.sha256(encoded(DECLARATION)).hexdigest()==CLOSURE_HASH,'CAPTURE_DECLARATION_CHANGED')
 require(hashlib.sha256(encoded(CASE)).hexdigest()==DECLARATION['caseHash'],'CAPTURE_CASE_CHANGED')
 compressed=base64.b64decode(PACKED,validate=True)
 require(len(compressed)<=262144,'BOUNDED_COMPRESSED_CAPTURE_REQUIRED')
 with gzip.GzipFile(fileobj=io.BytesIO(compressed))as stream:raw=stream.read(1048577)
 require(0<len(raw)<=1048576,'BOUNDED_CAPTURE_SOURCE_REQUIRED')
 SOURCES=json.loads(raw,object_pairs_hook=unique)
 require(set(SOURCES)==set(DECLARATION['sourceHashes']),'EXACT_CAPTURE_SOURCE_SET_REQUIRED')
 require(all(type(v)is str and hashlib.sha256(v.encode()).hexdigest()==DECLARATION['sourceHashes'][n]for n,v in SOURCES.items()),'CAPTURE_SOURCE_BYTES_CHANGED')
 require(not any(n in sys.modules for n in [*SOURCES,*PACKAGES]),'PRELOADED_CAPTURE_APPLICATION_MODULE_DENIED')
 COMPILED={}
 for name,source in SOURCES.items():
  tree=ast.parse(source)
  for node in ast.walk(tree):
   refs=[a.name for a in node.names]if isinstance(node,ast.Import)else []
   if isinstance(node,ast.ImportFrom):
    require(node.level==0 and node.module is not None,'RELATIVE_CAPTURE_IMPORT_DENIED');refs=[node.module]
   for ref in refs:require(ref in SOURCES or ref in PACKAGES or ref.split('.')[0]in STDLIB,'CAPTURE_IMPORT_OUTSIDE_SOURCE_CLOSURE')
   require(not(isinstance(node,ast.Call)and isinstance(node.func,ast.Name)and node.func.id=='__import__'),'DYNAMIC_CAPTURE_IMPORT_DENIED')
  COMPILED[name]=compile(tree,'<sealed-native-input:'+name+'>','exec')
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in()).throw(ValueError('CAPTURE_FINITE_DEADLINE')));signal.alarm(210)
 sys.meta_path.insert(0,ClosedCapture())
 module=importlib.import_module(DECLARATION['entryModule'])
 result=module.execute(sys.argv[1],sys.argv[2]if len(sys.argv)==3 else None,CASE,None,CLOSURE_HASH)
 print(encoded(result).decode(),flush=True)
try:main()
except (Exception,KeyboardInterrupt)as error:
 module=sys.modules.get('tools.ingestion_rollout_preparation.native_inputs')
 checkpoint=getattr(module,'CHECKPOINT',{'phase':'VERIFY_CAPTURE_SOURCE','contextPath':None})
 reason=str(error)if type(error).__name__ in('Denied','ValueError','CreationDenied')and str(error)in SAFE_REASONS else 'CAPTURE_CHECK_UNPROVEN_PRIVATE_DETAILS_REDACTED'
 print(encoded({'schema':'ouf.ingestion-native-input-capture-result.v1','complete':False,'status':'STOP_RECONCILE',
  'reasonCode':reason,'checkpoint':checkpoint,'contextsAndClaimsRetained':True,'automaticReplayAllowed':False,
  'budgetReset':False,'runtimeAuthorityIssued':False,'credentialValuesPrinted':False,'credentialHashesPrinted':False}).decode(),flush=True)
 raise SystemExit(2)
'''

def generate(root,case):
    root=Path(root)
    names={ENTRY:'tools/ingestion_rollout_preparation/native_inputs.py',
        'tools.ingestion_rollout_execution.contract':'tools/ingestion_rollout_execution/contract.py',
        'tools.ingestion_rollout_execution.private_file':'tools/ingestion_rollout_execution/private_file.py',
        'tools.ingestion_rollout_execution.runtime_bindings':'tools/ingestion_rollout_execution/runtime_bindings.py',
        'engine_creation':'tools/semantic_application_cutover/engine_creation.py',
        'tools.semantic_lease_recovery.recovery_journal':'tools/semantic_lease_recovery/recovery_journal.py'}
    sources={n:(root/p).read_text()for n,p in names.items()}
    inspection=(root/'tools/governed_human_successor/inspection.py').read_text()
    parsed=ast.parse(inspection)
    selected=[ast.get_source_segment(inspection,n)for n in parsed.body
        if isinstance(n,ast.FunctionDef)and n.name in('decode','read_selected')]
    if len(selected)!=2:raise ValueError('EXACT_QUALIFIED_SELECTED_READER_REQUIRED')
    sources['tools.governed_human_successor.inspection']='\n'.join([
        'import hashlib,json,os,stat','from pathlib import PurePosixPath',
        'from tools.ingestion_rollout_execution.contract import require,path',
        'from tools.ingestion_rollout_execution import private_file','FILE_METADATA={}',*selected])+'\n'
    packages=set();reasons={'CAPTURE_FINITE_DEADLINE'}
    stdlib={'copy','hashlib','json','os','pathlib','re','stat','tempfile','contextlib',
        'http','socket','fcntl','uuid','time'}
    for node in ast.walk(ast.parse(BOOTSTRAP)):
        if isinstance(node,ast.Call)and isinstance(node.func,ast.Name)and node.func.id=='require'and len(node.args)>1 and isinstance(node.args[1],ast.Constant):reasons.add(node.args[1].value)
    for name,source in sources.items():
        parts=name.split('.');packages.update('.'.join(parts[:i])for i in range(1,len(parts)))
        for node in ast.walk(ast.parse(source)):
            if isinstance(node,ast.Call)and isinstance(node.func,ast.Attribute)and node.func.attr=='require':idx=1
            elif isinstance(node,ast.Call)and isinstance(node.func,ast.Name):idx=1 if node.func.id=='require'else 0 if node.func.id in('ValueError','Denied','CreationDenied')else None
            else:idx=None
            if idx is not None and len(node.args)>idx and isinstance(node.args[idx],ast.Constant)and type(node.args[idx].value)is str:reasons.add(node.args[idx].value)
    declaration={'schema':'ouf.ingestion-native-input-capture-source-closure.v1','entryModule':ENTRY,
        'sourceHashes':{n:sha(v.encode())for n,v in sorted(sources.items())},
        'qualifiedSelectedReaderSourceHash':sha(inspection.encode()),'loaderHash':sha(BOOTSTRAP.encode()),
        'caseHash':sha(encoded(case)),'maximumEngineGets':12,'maximumSeconds':210,
        'humanSessionImplementationIncluded':False,'runtimeAuthorityIssued':False}
    raw=encoded(sources)
    if len(raw)>1048576:raise ValueError('CAPTURE_SOURCE_TOO_LARGE')
    compressed=io.BytesIO()
    with gzip.GzipFile(filename='',mode='wb',fileobj=compressed,mtime=0,compresslevel=9)as stream:stream.write(raw)
    if len(compressed.getvalue())>262144:raise ValueError('CAPTURE_COMPRESSED_SOURCE_TOO_LARGE')
    header='\n'.join(k+'='+repr(v)for k,v in(
        ('PACKED',base64.b64encode(compressed.getvalue()).decode('ascii')),('DECLARATION',declaration),
        ('CLOSURE_HASH',sha(encoded(declaration))),('CASE',case),('PACKAGES',sorted(packages)),
        ('STDLIB',sorted(stdlib)),('SAFE_REASONS',sorted(reasons)),('BOOTSTRAP',BOOTSTRAP)))
    return(header+"\nexec(compile(BOOTSTRAP,'<qualified-native-input-bootstrap>','exec'))\n").encode(),declaration
