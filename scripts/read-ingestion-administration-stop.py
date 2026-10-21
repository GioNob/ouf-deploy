"""Bounded read-only diagnosis of the pinned native administrative STOP.

Never calls a preparer/installer/runtime main, opens HUMAN credentials, logs in,
issues authority or dispatches owner requests. A hash-bound AST prefix ends
before the first mkdtemp/claim; an audit hook independently denies all writes,
network sockets and child processes. Runtime evidence is metadata/journal state.
"""
import ast,copy,hashlib,json,os,re,signal,stat,sys,time
from pathlib import Path

STAGE=Path('/home/oufadmin/ouf-deploy-runner/_work/ouf-deploy/ouf-ingestion-read-administrative-code-39222837925')
MANIFEST='633bbf2a17dc0395dd362694833b2264e7aef9501a06d5ce3fc54a4569e879c2'
PREPARER='76116a25164d49c0aa02343927a6b86082946c16c64646e54b690fc73c9ba22d'
ROOT=Path('/etc/ouf/deploy-snapshots')
AUTH_PLAN='f9f96e8d8c577b8e67c3e612306ab767316c5df7a8db9aafebfd5eff5959fb16'
EXPECTED_RECEIPT='3eb2fd4fff1048accdb954322faa58979bb490250c8535c1dd8512253e603587'
PREFIX_NAME='<verified-read-only-administrative-prefix>'
ROOT_NAMES=frozenset(('case.json','bootstrap.py','runtime.py','reader.py','sources.json','package.json',
 'preparation-result.json','runtime.claim.json','login-review.json','login-window-receipt.json',
 'authorization-plan.json','review.json','issuance.claim.json','decision.json','human.json','authority.json','administrative-result.json'))
class DiagDenied(Exception):pass

def require(ok,code):
 if not ok:raise DiagDenied(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def digest(v):return sha(encoded(v))
def pin(s):return tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))

def file_bytes(path,expected=None,maximum=8388608,*,private=True):
 path=Path(path);require(path.is_absolute() and path.resolve()==path,'EXACT_DIAGNOSTIC_PATH_REQUIRED')
 if private:
  for p in path.parents:
   s=p.lstat();require(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,'ROOT_ANCESTRY_REQUIRED')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  first=os.fstat(fd)
  require(stat.S_ISREG(first.st_mode)and first.st_nlink==1 and 0<first.st_size<=maximum,'BOUNDED_REGULAR_FILE_REQUIRED')
  if private:require(first.st_uid==first.st_gid==0 and stat.S_IMODE(first.st_mode)==0o600,'PRIVATE_FILE_CUSTODY_REQUIRED')
  with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(maximum+1)
  require(len(raw)==first.st_size and pin(first)==pin(os.fstat(fd))==pin(path.lstat())
    and(expected is None or sha(raw)==expected),'DIAGNOSTIC_BYTES_CHANGED')
  return raw
 finally:os.close(fd)

DENIED_EVENTS=frozenset(('os.mkdir','os.remove','os.rename','os.rmdir','os.chmod','os.chown','os.link','os.symlink',
 'os.truncate','os.utime','os.setxattr','os.removexattr','os.fork','os.forkpty','os.system','os.exec','os.posix_spawn','subprocess.Popen','socket.__new__','socket.connect','socket.bind'))
def read_only_audit(event,args):
 if event=='open':
  flags=args[2]
  if type(flags)is int and flags&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND):
   raise DiagDenied('DIAGNOSTIC_WRITE_DENIED')
 if event in DENIED_EVENTS:raise DiagDenied('DIAGNOSTIC_EXTERNAL_EFFECT_DENIED')

def readonly_prefix(raw):
 tree=ast.parse(raw)
 functions=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='run']
 require(len(functions)==1,'EXACT_PREPARER_RUN_DEFINITION_REQUIRED')
 function=copy.deepcopy(functions[0]);body=[];boundary=None
 for node in function.body:
  if isinstance(node,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='context'for t in node.targets):
   boundary=node;break
  if isinstance(node,ast.Expr)and isinstance(node.value,ast.Call)and isinstance(node.value.func,ast.Attribute)and isinstance(node.value.func.value,ast.Name)and node.value.func.value.id=='signal'and node.value.func.attr in('signal','alarm'):
   continue  # Preserve the diagnostic's one absolute watchdog.
  body.append(node)
 require(boundary is not None and ast.unparse(boundary.value)=="Path(tempfile.mkdtemp(prefix='ingestion-read-authorization-execution-', dir=root))",
  'EXACT_PRE_CLAIM_BOUNDARY_REQUIRED')
 require(body and not function.decorator_list,'NONEMPTY_UNDECORATED_PREFIX_REQUIRED')
 for node in ast.walk(ast.Module(body=body,type_ignores=[])):
  if isinstance(node,ast.Call):
   name=node.func.id if isinstance(node.func,ast.Name)else node.func.attr if isinstance(node.func,ast.Attribute)else None
   require(name not in {'write_new','mkdtemp','mkdir','execv','publish','chmod','chown','start_refresh','login'},
    'MUTATING_CALL_BEFORE_DIAGNOSTIC_BOUNDARY_DENIED')
 function.name='probe_read_only';function.body=body+[ast.Return(value=ast.Dict(
  keys=[ast.Constant(value='sourceModuleCount'),ast.Constant(value='preparedReceiptCanonicalHash')],
  values=[ast.Call(func=ast.Name(id='len',ctx=ast.Load()),args=[ast.Name(id='sources',ctx=ast.Load())],keywords=[]),
   ast.Call(func=ast.Name(id='digest',ctx=ast.Load()),args=[ast.Name(id='result',ctx=ast.Load())],keywords=[])]))]
 program=ast.fix_missing_locations(ast.Module(body=[function],type_ignores=[]))
 codes={n.value for n in ast.walk(tree)if isinstance(n,ast.Constant)and isinstance(n.value,str)
  and re.fullmatch('[A-Z][A-Z0-9_]{2,159}',n.value)}
 return compile(program,PREFIX_NAME,'exec'),codes,boundary.lineno

def safe_failure(error,codes):
 unit=None;line=None;trace=error.__traceback__
 units={PREFIX_NAME:'READ_ONLY_PREPARER_PREFIX','<verified-retained-file-helpers>':'FROZEN_FILE_HELPERS',
  '<verified-retained-decode>':'RETAINED_DECODE_HELPERS','<new-private-closed-loader>':'CLOSED_SOURCE_LOADER'}
 receipt_hash=None
 while trace:
  filename=trace.tb_frame.f_code.co_filename
  if filename in units and trace.tb_frame.f_code.co_name!='require':
   unit,line=units[filename],trace.tb_lineno
   if filename==PREFIX_NAME:
    result=trace.tb_frame.f_locals.get('result')
    if type(result)is dict and result.get('schema')=='ouf.source-revision-postboot-preparation-result.v1':
     receipt_hash=digest(result)
  trace=trace.tb_next
 name=type(error).__name__;known={'ValueError','ReadDenied','RuntimeDenied','DiagDenied','FileNotFoundError','PermissionError',
  'KeyError','TypeError','SyntaxError','JSONDecodeError','UnicodeDecodeError','ModuleNotFoundError'}
 result={'exceptionClass':name if name in known else'OTHER_ERROR','reasonCode':str(error)if str(error)in codes else'PRIVATE_DETAILS_REDACTED',
  'codeUnit':unit,'line':line,'rawErrorPrinted':False}
 if receipt_hash is not None:result['preparedReceiptCanonicalHash']=receipt_hash;result['preparedReceiptMatchesExpectedPin']=receipt_hash==EXPECTED_RECEIPT
 return result

def artifact_state(context):
 require(context.parent==ROOT and re.fullmatch('ingestion-read-authorization-execution-[A-Za-z0-9_-]{8,64}',context.name),
  'EXACT_ADMINISTRATIVE_CONTEXT_REQUIRED')
 first=context.lstat();require(stat.S_ISDIR(first.st_mode)and first.st_uid==first.st_gid==0
  and stat.S_IMODE(first.st_mode)==0o700,'PRIVATE_CONTEXT_CUSTODY_REQUIRED')
 present={name:os.path.lexists(context/name)for name in sorted(ROOT_NAMES)}
 journal=context/'authorization/recovery.json';states={};snapshot=None
 if os.path.lexists(journal):
  snapshot=file_bytes(journal,maximum=1048576);row=json.loads(snapshot)
  require(row.get('schema')=='ouf.chatbot-file-authorization-journal.v1'and type(row.get('effects'))is dict
   and len(row['effects'])<=128,'EXACT_ADMINISTRATIVE_JOURNAL_REQUIRED')
  for effect in row['effects'].values():
   require(type(effect)is dict and effect.get('state')in('CLAIMED','DISPATCHED','APPLIED'),'KNOWN_EFFECT_STATE_REQUIRED')
   state=effect['state'];states[state]=states.get(state,0)+1
  require(file_bytes(journal,maximum=1048576)==snapshot,'JOURNAL_CHANGED_DURING_DIAGNOSIS')
 require(pin(context.lstat())==pin(first),'CONTEXT_CHANGED_DURING_DIAGNOSIS')
 return {'contextPath':str(context),'artifactsPresent':present,'authorizationJournalPresent':snapshot is not None,
  'effectStateCounts':states,'iamAttemptFencePresent':os.path.lexists(context/'iam-login/attempt.json'),
  'authorityFilesNotOpened':True,'humanCredentialFilesOpened':0}

def context_inventory():
 claim=ROOT/('ingestion-read-authorization-'+digest({'sourceId':'teatri-csv-6609b245','predecessor':AUTH_PLAN})+'.claim.json')
 claim_present=os.path.lexists(claim);claimed=None;raw=None
 if claim_present:
  raw=file_bytes(claim,maximum=65536);value=json.loads(raw);claimed=Path(value['context'])
  require(value['sourceId']=='teatri-csv-6609b245'and value['automaticReplayAllowed']is False and value['budgetReset']is False,
   'EXACT_LOGICAL_CLAIM_REQUIRED')
 contexts=[]
 for context in ROOT.glob('ingestion-read-authorization-execution-*'):
  require(len(contexts)<8,'BOUNDED_ADMINISTRATIVE_CONTEXT_INVENTORY_REQUIRED');contexts.append(artifact_state(context))
 if claimed is not None:require(any(c['contextPath']==str(claimed)for c in contexts),'CLAIMED_CONTEXT_MISSING')
 if raw is not None:require(file_bytes(claim,maximum=65536)==raw,'LOGICAL_CLAIM_CHANGED')
 return {'logicalActionClaimPresent':claim_present,'contexts':sorted(contexts,key=lambda c:c['contextPath']),
  'contextCount':len(contexts),'humanCredentialFilesOpened':0}

def main():
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_REQUIRED')
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(DiagDenied('DIAGNOSTIC_TIME_BOUND_EXHAUSTED')))
 deadline=time.monotonic()+120;signal.alarm(120);sys.addaudithook(read_only_audit)
 report={'schema':'ouf.ingestion-administrative-stop-read.v1','readOnly':True,'maximumSeconds':120,
  'automaticReplayAllowed':False,'budgetReset':False,'preparerMainCalled':False,'runtimeMainCalled':False,
  'completedInstallationReadbackReplayed':False,'humanCredentialFilesOpened':0,'oauthRequests':0,'iamRequests':0,
  'ownerRequests':0,'journalWrites':0,'runtimeAuthorityIssued':False,'completedTechnicalPhases':8,'functionalMilestonesProven':4}
 manifest=json.loads(file_bytes(STAGE/'manifest.json',MANIFEST,private=False))
 raw=file_bytes(STAGE/'prepare.py',PREPARER,maximum=262144,private=False)
 require(manifest['files']['prepare.py']==PREPARER,'EXACT_PINNED_PREPARER_REQUIRED')
 program,codes,boundary=readonly_prefix(raw);report['readOnlyPrefixEndsBeforeLine']=boundary
 for name in('reader.py','runtime.py'):
  public_source=file_bytes(STAGE/name,manifest['files'][name],maximum=262144,private=False)
  codes.update(n.value for n in ast.walk(ast.parse(public_source))if isinstance(n,ast.Constant)and isinstance(n.value,str)and re.fullmatch('[A-Z][A-Z0-9_]{2,159}',n.value))
 namespace={'__name__':'verified_read_only_preparer_definitions','__file__':str(STAGE/'prepare.py')}
 exec(compile(raw,'<verified-preparer-definitions>','exec'),namespace)
 exec(program,namespace)
 try:
  report['prefixResult']=namespace['probe_read_only'](STAGE,MANIFEST);report['readOnlyPreparationPrefixPassed']=True
 except Exception as error:
  if time.monotonic()>=deadline:raise DiagDenied('DIAGNOSTIC_TIME_BOUND_EXHAUSTED')from None
  report['readOnlyPreparationPrefixPassed']=False;report['reproducedFailure']=safe_failure(error,codes)
 require(time.monotonic()<deadline,'DIAGNOSTIC_TIME_BOUND_EXHAUSTED')
 try:report['administrativeArtifacts']=context_inventory();report['artifactInventoryComplete']=True
 except Exception as error:report['artifactInventoryComplete']=False;report['inventoryFailure']=safe_failure(error,{
  'EXACT_ADMINISTRATIVE_CONTEXT_REQUIRED','PRIVATE_CONTEXT_CUSTODY_REQUIRED','EXACT_LOGICAL_CLAIM_REQUIRED',
  'BOUNDED_ADMINISTRATIVE_CONTEXT_INVENTORY_REQUIRED','CLAIMED_CONTEXT_MISSING','EXACT_ADMINISTRATIVE_JOURNAL_REQUIRED'})
 report['complete']=True;report['runtimeCompletionProven']=False;signal.alarm(0);return report

if __name__=='__main__':
 try:output=main()
 except (Exception,KeyboardInterrupt)as error:
  output={'schema':'ouf.ingestion-administrative-stop-read.v1','complete':False,'readOnly':True,
   'failure':safe_failure(error,{'ISOLATED_ROOT_REQUIRED','DIAGNOSTIC_WRITE_DENIED','DIAGNOSTIC_EXTERNAL_EFFECT_DENIED',
    'EXACT_DIAGNOSTIC_PATH_REQUIRED','ROOT_ANCESTRY_REQUIRED','BOUNDED_REGULAR_FILE_REQUIRED','PRIVATE_FILE_CUSTODY_REQUIRED',
    'DIAGNOSTIC_BYTES_CHANGED','DIAGNOSTIC_TIME_BOUND_EXHAUSTED'}),'automaticReplayAllowed':False,'budgetReset':False,
   'runtimeCompletionProven':False}
 print(encoded(output).decode());raise SystemExit(0 if output['complete']else 2)
