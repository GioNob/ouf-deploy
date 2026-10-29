"""Pinned ojz9hai3 read-only diagnosis. No HUMAN credential, OAuth or owner call.

Reproduces only the bootstrap prefix before its runtime-claim write, then pure
plan/custody checks. Audit independently forbids writes, sockets and processes.
Original execution main and credential/session methods are never called.
"""
import ast,copy,hashlib,json,os,re,signal,stat,sys,time
from pathlib import Path
CONTEXT=Path('/etc/ouf/deploy-snapshots/ingestion-read-authorization-execution-ojz9hai3')
PACKAGE='b2b01238a1c760a5e0334f0ed7770b4d03746ee9fdfc271a96798ff282327e84'
CLOSURE='4152ca6bcd44e745ea3a03dc884b67a948d1f91536a80c752a82c27afd9fc657'
PLAN='9216f0bae1056f1a6f8c8bf8627915d9a70f126e476fe6700e65f0d58112b53b'
COMMIT='37184220c2a565367a194d41e862a704f87dbdb8'
BOOTSTRAP='f4fce180cf65699a59d19082287fb566d249bf0093c94e7f1027969d8c5fa23a'
class ReadDenied(RuntimeError):pass
def require(ok,code):
 if not ok:raise ReadDenied(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(v):return hashlib.sha256(v).hexdigest()
def digest(v):return sha(encoded(v))
def pin(s):return tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def raw_read(path,expected=None,maximum=8388608):
 path=Path(path);require(path.is_absolute()and path.resolve()==path,'EXACT_PRIVATE_PATH_REQUIRED')
 for parent in path.parents:
  row=parent.lstat();require(stat.S_ISDIR(row.st_mode)and row.st_uid==0 and not row.st_mode&0o022,'ROOT_ANCESTRY_REQUIRED')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  row=os.fstat(fd);require(stat.S_ISREG(row.st_mode)and row.st_uid==row.st_gid==0
   and stat.S_IMODE(row.st_mode)==0o600 and row.st_nlink==1 and 0<row.st_size<=maximum,'PRIVATE_CUSTODY_REQUIRED')
  with os.fdopen(os.dup(fd),'rb')as f:raw=f.read(maximum+1)
  require(len(raw)==row.st_size and pin(row)==pin(os.fstat(fd))==pin(path.lstat())
   and(expected is None or sha(raw)==expected),'PRIVATE_BYTES_CHANGED')
  return raw
 finally:os.close(fd)
def read(path,expected=None,maximum=8388608):return json.loads(raw_read(path,expected,maximum))

DENIED=frozenset(('os.mkdir','os.remove','os.rename','os.rmdir','os.chmod','os.chown','os.link','os.symlink',
 'os.truncate','os.utime','os.setxattr','os.removexattr','os.fork','os.forkpty','os.system','os.exec','os.posix_spawn',
 'subprocess.Popen','socket.__new__','socket.connect','socket.bind'))
def audit(event,args):
 if event=='open':
  path,_,flags=args
  if type(flags)is int and flags&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND):
   raise ReadDenied('READ_ONLY_WRITE_DENIED')
  if isinstance(path,(str,bytes)):
   name=os.fsdecode(path);base=Path(name).name
   require(not(base=='human-access.jwt' or base.endswith(('.pem','.key','.p12','.pfx'))
    or ('human-'in name and base in('recovery.json','invocation.lock'))),'CREDENTIAL_OR_KEY_OPEN_DENIED')
 if event in DENIED:raise ReadDenied('READ_ONLY_EXTERNAL_EFFECT_DENIED')

def public_codes(raw):
 return {n.value for n in ast.walk(ast.parse(raw))if isinstance(n,ast.Constant)and isinstance(n.value,str)
  and re.fullmatch('[A-Z][A-Z0-9_]{2,159}',n.value)}

def bootstrap_prefix(raw):
 tree=ast.parse(raw);functions=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='main']
 require(len(functions)==1,'EXACT_BOOTSTRAP_MAIN_REQUIRED')
 function=copy.deepcopy(functions[0]);body=[];boundary=None
 for node in function.body:
  if isinstance(node,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='fd'for t in node.targets):
   boundary=node;break
  if isinstance(node,ast.Expr)and isinstance(node.value,ast.Call)and ast.unparse(node.value.func)=='os.umask':continue
  body.append(node)
 require(boundary is not None and ast.unparse(boundary.value)=="os.open(context / 'runtime.claim.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 384)",
  'EXACT_BOUNDARY_BEFORE_RUNTIME_CLAIM_REQUIRED')
 for node in ast.walk(ast.Module(body=body,type_ignores=[])):
  if isinstance(node,ast.Call):
   name=ast.unparse(node.func)
   require(name not in ('entry.main','os.open','os.execv','os.mkdir','os.makedirs','human.current','human.refresh_if_due'),
    'MUTATION_OR_SESSION_DISPATCH_IN_PREFIX_DENIED')
 function.name='probe_bootstrap_readonly'
 function.body=body+[ast.Return(value=ast.Dict(keys=[ast.Constant(k)for k in('entry','sources','package','case')],
  values=[ast.Name(id=k,ctx=ast.Load())for k in('entry','sources','package','case')]))]
 return compile(ast.fix_missing_locations(ast.Module(body=[function],type_ignores=[])),
  '<read-only-native-bootstrap-prefix>','exec'),boundary.lineno

def safe_failure(error,codes,modules):
 units={'<read-only-native-bootstrap-prefix>':'BOOTSTRAP_PREFIX','<verified-native-bootstrap-definitions>':'BOOTSTRAP_HELPERS'}
 units.update({'<sealed-chatbot-file-cohort:'+name+'>':name for name in modules})
 unit=None;line=None;trace=error.__traceback__
 while trace:
  if trace.tb_frame.f_code.co_filename in units and trace.tb_frame.f_code.co_name!='require':
   unit=units[trace.tb_frame.f_code.co_filename];line=trace.tb_lineno
  trace=trace.tb_next
 name=type(error).__name__
 return {'exceptionClass':name if name in {'ValueError','ReadDenied','UpdateDenied','RuntimeDenied','CandidateDenied',
  'HumanSessionPaused','AuthorizationPaused','FileNotFoundError','PermissionError','KeyError','TypeError','JSONDecodeError'}else'OTHER_ERROR',
  'reasonCode':str(error)if str(error)in codes else'PRIVATE_DETAILS_REDACTED',
  'codeUnit':unit,'line':line,'rawErrorPrinted':False}

def inventory():
 names=('case.json','bootstrap.py','runtime.py','reader.py','sources.json','package.json','preparation-result.json',
  'runtime.claim.json','authorization-plan.json','review.json','issuance.claim.json','decision.json','human.json',
  'authority.json','administrative-result.json')
 report={'artifactsPresent':{n:os.path.lexists(CONTEXT/n)for n in names},'effectStateCounts':{},
  'authorityFilesOpened':False,'humanCredentialFilesOpened':0}
 journal=CONTEXT/'authorization/recovery.json';report['authorizationJournalPresent']=os.path.lexists(journal)
 if report['authorizationJournalPresent']:
  raw=raw_read(journal,maximum=1048576);row=json.loads(raw)
  require(row.get('schema')=='ouf.chatbot-file-authorization-journal.v1'and type(row.get('effects'))is dict
   and len(row['effects'])<=128,'EXACT_AUTHORIZATION_JOURNAL_REQUIRED')
  for effect in row['effects'].values():
   state=effect.get('state');require(state in ('CLAIMED','DISPATCHED','APPLIED'),'KNOWN_EFFECT_STATE_REQUIRED')
   report['effectStateCounts'][state]=report['effectStateCounts'].get(state,0)+1
  require(raw_read(journal,maximum=1048576)==raw,'JOURNAL_CHANGED_DURING_READ')
 return report

def checks(report,codes,modules):
 report['phase']='EXACT_CHILD_PACKAGE_AND_PREPARATION'
 row=CONTEXT.lstat();require(stat.S_ISDIR(row.st_mode)and row.st_uid==row.st_gid==0
  and stat.S_IMODE(row.st_mode)==0o700,'EXACT_PRIVATE_CHILD_CONTEXT_REQUIRED')
 package=read(CONTEXT/'package.json',PACKAGE);receipt=read(CONTEXT/'preparation-result.json')
 require(package['schema']=='ouf.ingestion-read-administrative-package.v1'and package['sourceCommit']==COMMIT
  and digest(package['closure'])==CLOSURE and package['runtimeAuthorityIssued']is False,'EXACT_PREPARED_CHILD_PACKAGE_REQUIRED')
 require(receipt['schema']=='ouf.ingestion-existing-session-preparation.v1'and receipt['contextPath']==str(CONTEXT)
  and receipt['packageHash']==PACKAGE and receipt['sourceClosureHash']==CLOSURE and receipt['sourceCommit']==COMMIT
  and receipt['planHash']==PLAN and receipt['priorOAuthAttempts']==212
  and receipt['maximumCumulativeOAuthAttempts']==256 and receipt['budgetReset']is False
  and receipt['newHumanLoginAllowed']is False and receipt['runtimeAuthorityIssued']is False,
  'EXACT_PREPARED_CHILD_RECEIPT_REQUIRED')
 raw=raw_read(CONTEXT/'bootstrap.py',BOOTSTRAP,262144);codes.update(public_codes(raw))
 require(package['fileHashes']['bootstrap.py']==BOOTSTRAP,'EXACT_QUALIFIED_BOOTSTRAP_REQUIRED')
 codes.update(public_codes(raw_read(CONTEXT/'runtime.py',package['fileHashes']['runtime.py'],262144)))
 modules.update(package['closure']['declaration']['sourceHashes'])
 report['runtimeClaimPresent']=os.path.lexists(CONTEXT/'runtime.claim.json')
 if report['runtimeClaimPresent']:
  require(read(CONTEXT/'runtime.claim.json')=={'packageHash':PACKAGE,'automaticReplayAllowed':False},
   'EXACT_CONSUMED_CHILD_RUNTIME_CLAIM_REQUIRED')
 report['phase']='READ_ONLY_BOOTSTRAP_PREFIX'
 program,line=bootstrap_prefix(raw);report['prefixEndsBeforeLine']=line
 namespace={'__name__':'verified_native_bootstrap_definitions','__file__':str(CONTEXT/'bootstrap.py')}
 exec(compile(raw,'<verified-native-bootstrap-definitions>','exec'),namespace);exec(program,namespace)
 values=namespace['probe_bootstrap_readonly'](str(CONTEXT),PACKAGE)
 report['bootstrapPrefixPassed']=True
 entry,sources,case=values['entry'],values['sources'],values['case']
 modules.update(sources)
 for value in sources.values():codes.update(public_codes(value))
 report['sourceModuleCount']=len(sources)
 report['phase']='EXACT_PLAN_AND_PREDECESSOR_BINDINGS'
 plan=entry.validate_continuation(case,namespace['read'],CONTEXT)
 require(digest(plan)==PLAN,'EXACT_PREFLIGHT_PLAN_REQUIRED')
 report['planAndPredecessorBindingsPassed']=True
 report['phase']='QUALIFIED_OWNER_PRIMITIVES'
 require(entry.primitives(sources).bindings==plan['helperBindings'],'QUALIFIED_OWNER_PRIMITIVES_CHANGED')
 report['ownerPrimitivesPassed']=True
 report['phase']='READ_ONLY_EXECUTABLE_AND_STDLIB_BINDINGS'
 closure=package['closure']
 for program in closure['executables'].values():
  require(entry.authority.governance.executable(program['path'])=={k:program[k]for k in ('path','sha256')},
   'APPROVED_NATIVE_PROGRAM_CHANGED')
 library=entry.authority.stdlib_binding()
 require(digest(library)==closure['stdlibHash']and len(library['fileHashes'])==closure['stdlibFileCount'],
  'APPROVED_PYTHON_STDLIB_CHANGED')
 report['executableAndStdlibHashesPassed']=True
 report['opensslVersionExecutionProven']=False
 report['phase']='READ_ONLY_EXISTING_PUBLIC_ROLE_AUTHORITY'
 entry.authority.current_authorities(int(time.time())+910)
 report['publicRoleAuthorityWindowPassed']=True
 report['phase']='PURE_READ_ONLY_CHECKS_PASSED_NO_SESSION_OR_NETWORK_REPLAY'
 report['allReadOnlyChecksPassed']=True

def main():
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_REQUIRED')
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ReadDenied('FINITE_READ_DEADLINE_EXHAUSTED')))
 signal.alarm(120);sys.addaudithook(audit)
 report={'schema':'ouf.ingestion-existing-session-stop-read.v1','contextPath':str(CONTEXT),'readOnly':True,
  'maximumSeconds':120,'automaticReplayAllowed':False,'budgetReset':False,'completedTechnicalPhases':8,
  'functionalMilestonesProven':4,'runtimeMainCalled':False,'preparerMainCalled':False,
  'humanCredentialFilesOpened':0,'oauthRequests':0,'iamRequests':0,'ownerRequests':0,'journalWrites':0,
  'privateKeyFilesOpened':0,'processDispatches':0,'runtimeAuthorityIssuedByDiagnostic':False,'allReadOnlyChecksPassed':False,
  'completedInstallationReadbackReplayed':False,'runtimeCompletionProven':False}
 codes=public_codes(globals()['__qualified_source_bytes__']);modules=set()
 try:checks(report,codes,modules)
 except (Exception,KeyboardInterrupt)as error:report['failure']=safe_failure(error,codes,modules)
 try:report['artifacts']=inventory();report['artifactInventoryComplete']=True
 except Exception as error:
  report['artifactInventoryComplete']=False;report['inventoryFailure']=safe_failure(error,codes,modules)
 signal.alarm(0);report['complete']=True;return report
