"""Seal the complete operator dependency closure, not a disk import tree."""
import ast
import base64
import gzip
import hashlib
import io
import json
from pathlib import Path

ENTRY='tools.governed_human_successor.operator'
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()

BOOTSTRAP='''
import ast,base64,gzip,hashlib,importlib.abc,importlib.util,io,json,os,sys
def require(ok,code):
 if not ok:raise ValueError(code)
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def unique(pairs):
 value={}
 for k,v in pairs:
  require(k not in value,'DUPLICATE_SEALED_OPERATOR_FIELD');value[k]=v
 return value
class ClosedOperator(importlib.abc.MetaPathFinder,importlib.abc.Loader):
 def __init__(self,sources,compiled):self.sources,self.compiled=sources,compiled
 def find_spec(self,fullname,path=None,target=None):
  if fullname in self.sources or fullname in PACKAGES:return importlib.util.spec_from_loader(fullname,self,is_package=fullname in PACKAGES)
  if fullname=='tools'or fullname.startswith('tools.'):raise ValueError('OPERATOR_DISK_IMPORT_FALLBACK_DENIED')
  return None
 def create_module(self,spec):return None
 def exec_module(self,module):
  if module.__name__ in PACKAGES:module.__path__=[]
  else:
   module.__qualified_source_sha256__=hashlib.sha256(self.sources[module.__name__].encode()).hexdigest()
   exec(self.compiled[module.__name__],module.__dict__)
def main():
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_OPERATOR_REQUIRED')
 require(len(sys.argv)in(2,3)and sys.argv[1]in('open-window','step','status','reconcile-read'),'ONE_EXPLICIT_OPERATOR_MODE_REQUIRED')
 require((sys.argv[1]=='open-window')==(len(sys.argv)==2),'EXACT_OPERATOR_CONTROL_ARGUMENT_REQUIRED')
 require(hashlib.sha256(BOOTSTRAP.encode()).hexdigest()==DECLARATION['loaderHash'],'OPERATOR_LOADER_CHANGED')
 require(hashlib.sha256(encoded(DECLARATION)).hexdigest()==CLOSURE_HASH,'OPERATOR_DECLARATION_CHANGED')
 require(hashlib.sha256(encoded(CASE)).hexdigest()==DECLARATION['caseHash']and CONFIRMED_READ==DECLARATION['confirmedRead'],'OPERATOR_REVIEW_CASE_CHANGED')
 compressed=base64.b64decode(PACKED,validate=True)
 require(len(compressed)<=524288,'BOUNDED_COMPRESSED_OPERATOR_REQUIRED')
 with gzip.GzipFile(fileobj=io.BytesIO(compressed))as stream:raw=stream.read(2097153)
 require(0<len(raw)<=2097152,'BOUNDED_OPERATOR_SOURCE_CLOSURE_REQUIRED')
 sources=json.loads(raw,object_pairs_hook=unique)
 require(set(sources)==set(DECLARATION['sourceHashes'])and len(sources)==DECLARATION['moduleCount'],'EXACT_OPERATOR_SOURCE_SET_REQUIRED')
 require(all(type(v)is str and 0<len(v.encode())<=262144 and hashlib.sha256(v.encode()).hexdigest()==DECLARATION['sourceHashes'][n]for n,v in sources.items()),'OPERATOR_SOURCE_BYTES_CHANGED')
 require(not any(n in sys.modules for n in [*sources,*PACKAGES]),'PRELOADED_OPERATOR_APPLICATION_MODULE_DENIED')
 compiled={}
 for name,source in sources.items():
  tree=ast.parse(source,filename='<sealed-human-operator:'+name+'>')
  for node in ast.walk(tree):
   refs=[a.name for a in node.names]if isinstance(node,ast.Import)else []
   if isinstance(node,ast.ImportFrom):
    require(node.level==0 and node.module is not None,'RELATIVE_OPERATOR_IMPORT_DENIED');refs=[node.module]
   for ref in refs:require(ref in sources or ref in PACKAGES or ref.split('.')[0]in STDLIB,'OPERATOR_IMPORT_OUTSIDE_SOURCE_CLOSURE')
   if isinstance(node,ast.Call)and isinstance(node.func,ast.Name)and node.func.id=='__import__':
    require(len(node.args)>=1 and isinstance(node.args[0],ast.Constant)and node.args[0].value=='random','DYNAMIC_OPERATOR_IMPORT_DENIED')
  compiled[name]=compile(tree,'<sealed-human-operator:'+name+'>','exec')
 sys.meta_path.insert(0,ClosedOperator(sources,compiled))
 module=importlib.import_module(DECLARATION['entryModule'])
 result=module.execute(sys.argv[1],sys.argv[2]if len(sys.argv)==3 else None,CASE,CONFIRMED_READ,CLOSURE_HASH)
 print(encoded(result).decode(),flush=True)
try:main()
except (Exception,KeyboardInterrupt)as error:
 module=sys.modules.get('tools.governed_human_successor.operator')
 checkpoint=getattr(module,'CHECKPOINT',{'phase':'VERIFY_SEALED_OPERATOR','controlPath':None})
 reason=str(error)if type(error).__name__ in('Denied','PlanDenied','ValueError','HumanSessionPaused')and str(error)in SAFE_REASONS else 'OPERATOR_CHECK_OR_OUTCOME_UNPROVEN_PRIVATE_DETAILS_REDACTED'
 print(encoded({'schema':'ouf.human-explicit-successor-operator-result.v1','complete':False,
  'status':'STOP_RECONCILE','reasonCode':reason,'checkpoint':checkpoint,
  'automaticReplayAllowed':False,'budgetReset':False,'runtimeAuthorityIssued':False,
  'contextsAndClaimsRetained':True,'credentialValuesPrinted':False,'credentialHashesPrinted':False}).decode(),flush=True)
 raise SystemExit(2)
'''

def generate(root,case,confirmed_read):
    root=Path(root)
    tree=ast.parse((root/'tools/ingestion_rollout_execution/runtime.py').read_bytes())
    values={}
    for node in tree.body:
        if isinstance(node,ast.Assign)and len(node.targets)==1 and isinstance(node.targets[0],ast.Name):
            name=node.targets[0].id
            if name=='SOURCE_PATHS':values[name]=ast.literal_eval(node.value)
            if name=='STDLIB':values[name]=set(ast.literal_eval(node.value.args[0]))
    paths=values['SOURCE_PATHS'];stdlib=values['STDLIB']
    paths.update({'.'.join(p.relative_to(root).with_suffix('').parts):str(p.relative_to(root))
        for p in(root/'tools/governed_human_successor').glob('*.py')})
    packages=set()
    for name in paths:
        parts=name.split('.')
        packages.update('.'.join(parts[:i])for i in range(1,len(parts)))
    sources={};safe_reasons=set()
    def add(name):
        if name in sources:return
        source=(root/paths[name]).read_text();sources[name]=source
        for node in ast.walk(ast.parse(source)):
            refs=[v.name for v in node.names]if isinstance(node,ast.Import)else []
            if isinstance(node,ast.ImportFrom):
                if node.level or node.module is None:raise ValueError('RELATIVE_OPERATOR_IMPORT_DENIED')
                refs=[node.module]+[node.module+'.'+a.name for a in node.names if node.module+'.'+a.name in paths]
            for ref in refs:
                if ref in paths:add(ref)
                elif ref not in packages and ref.split('.')[0]not in stdlib:raise ValueError('UNAVAILABLE_OPERATOR_DEPENDENCY:'+ref)
            if isinstance(node,ast.Call)and isinstance(node.func,ast.Name):
                index=1 if node.func.id=='require'else 0 if node.func.id in('ValueError','Denied','PlanDenied','HumanSessionPaused')else None
                if index is not None and len(node.args)>index and isinstance(node.args[index],ast.Constant):
                    value=node.args[index].value
                    if type(value)is str:safe_reasons.add(value)
    add(ENTRY)
    used_packages=set()
    for name in sources:
        parts=name.split('.');used_packages.update('.'.join(parts[:i])for i in range(1,len(parts)))
    declaration={'schema':'ouf.human-explicit-operator-source-closure.v1','entryModule':ENTRY,
        'moduleCount':len(sources),'sourceHashes':{n:sha(v.encode())for n,v in sorted(sources.items())},
        'loaderHash':sha(BOOTSTRAP.encode()),'caseHash':sha(encoded(case)),
        'confirmedRead':confirmed_read,'requiredPythonFlags':['-I','-B','-S'],
        'maximumSourceBytes':2097152,'foregroundOnly':True,'runtimeAuthorityIssued':False}
    raw=encoded(sources)
    if len(raw)>2097152:raise ValueError('OPERATOR_SOURCE_CLOSURE_TOO_LARGE')
    # GzipFile emits a canonical OS-independent header on both qualified
    # Python versions; compress(mtime=0) has version-specific OS-header bytes.
    compressed=io.BytesIO()
    with gzip.GzipFile(filename='',mode='wb',fileobj=compressed,mtime=0,compresslevel=9)as stream:
        stream.write(raw)
    packed=base64.b64encode(compressed.getvalue()).decode('ascii')
    header='\n'.join(k+'='+repr(v)for k,v in(
        ('PACKED',packed),('DECLARATION',declaration),('CLOSURE_HASH',sha(encoded(declaration))),
        ('CASE',case),('CONFIRMED_READ',confirmed_read),('PACKAGES',sorted(used_packages)),
        ('STDLIB',sorted(stdlib)),('SAFE_REASONS',sorted(safe_reasons)),('BOOTSTRAP',BOOTSTRAP)))
    return (header+"\nexec(compile(BOOTSTRAP,'<qualified-human-operator-bootstrap>','exec'))\n").encode(),declaration
