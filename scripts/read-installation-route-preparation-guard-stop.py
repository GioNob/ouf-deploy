"""Exact sealed public HUMAN guard source only; no credential journal or execution."""
import ast,base64,hashlib,json,os,re,signal,stat,sys,time
from pathlib import Path
CONTEXT=Path('/etc/ouf/deploy-snapshots/installation-binding-apply-execution-46iexg9c')
PACKAGE='de440e91d204e30bd99daea42e4a19c9affee97e3044cf6ae2fa8bf613592efc'
CLOSURE='2fb31db4ffd6188bcdd0bb7b8cc71aaf284b0f5581413ca3a05081624442e56d'
SOURCE='9600d850e5d4b4b42004e68028a5aa6e49c20d35'
ARTIFACTS=('candidate-review.json','execution-plan.json','review.json','decision.json','human.json','authority.json','issuance.claim.json','recovery.json','update-result.json')
def require(ok,code):
 if not ok:raise ValueError(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(v):return hashlib.sha256(v).hexdigest()
def digest(v):return sha(encoded(v))
def read(path,expected=None,maximum=8388608):
 path=Path(path);require(path.is_absolute()and path.resolve()==path,'EXACT_PRIVATE_PATH_REQUIRED')
 for parent in path.parents:
  row=parent.lstat();require(stat.S_ISDIR(row.st_mode)and row.st_uid==0 and not row.st_mode&0o022,'PRIVATE_ROOT_ANCESTRY_REQUIRED')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  row=os.fstat(fd);require(stat.S_ISREG(row.st_mode)and row.st_uid==row.st_gid==0
   and stat.S_IMODE(row.st_mode)==0o600 and row.st_nlink==1 and 0<row.st_size<=maximum,'PRIVATE_CUSTODY_REQUIRED')
  with os.fdopen(os.dup(fd),'rb')as f:raw=f.read(maximum+1)
  pin=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  require(len(raw)==row.st_size and pin(row)==pin(os.fstat(fd))==pin(path.lstat())
   and(expected is None or sha(raw)==expected),'PRIVATE_BYTES_CHANGED');return raw
 finally:os.close(fd)
def parsed(path,expected=None,maximum=8388608):return json.loads(read(path,expected,maximum))
EXPECTED='137867b997194d0b72f794d868dc9a80692a0c35e776b96b50359ce3ed3f45a2'
def inspect_source(raw):
 require(type(raw)is bytes and 0<len(raw)<=262144,'BOUNDED_SOURCE_REQUIRED')
 tree=ast.parse(raw)
 methods=[n for n in ast.walk(tree)if isinstance(n,ast.FunctionDef)and n.name=='_check_identity_and_budget']
 require(len(methods)<=8,'BOUNDED_METHOD_COUNT_REQUIRED')
 views=[]
 for method in methods:
  body=ast.dump(ast.Module(body=method.body,type_ignores=[]),include_attributes=False)
  text=ast.unparse(method);require(len(text.encode())<=32768,'BOUNDED_PUBLIC_METHOD_REQUIRED')
  views.append({'bodyAstSha256':sha(body.encode()),'matchesExpectedFrozenGuard':sha(body.encode())==EXPECTED,'methodSource':text})
 return {'methodCount':len(methods),'methods':views,'extensionAlreadyPresent':b'_explicit_264_identity'in raw,
  'expectedFrozenGuardBodyAstSha256':EXPECTED,'humanSourceSha256':sha(raw)}
def main():
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_REQUIRED')
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('SOURCE_READ_DEADLINE')));signal.alarm(60)
 package=parsed(CONTEXT/'package.json',PACKAGE);closure=package['closure'];decl=closure['declaration']
 require(package['sourceCommit']==SOURCE and digest(closure)==CLOSURE and decl['moduleCount']==219
  and decl['entryModule']=='tools.installation_binding_apply.entry'and package['declarationHash']==digest(decl),'EXACT_SEALED219_PACKAGE_REQUIRED')
 sources=parsed(CONTEXT/'sources.json',package['fileHashes']['sources.json'])
 require(len(sources)==219 and set(sources)==set(decl['sourceHashes']),'EXACT219_SOURCE_SET_REQUIRED')
 decoded={k:base64.b64decode(v,validate=True)for k,v in sources.items()}
 require(all(sha(v)==decl['sourceHashes'][k]for k,v in decoded.items()),'EXACT219_SOURCE_BYTES_REQUIRED')
 claim=CONTEXT.parent/('installation-route-reconcile-preparation-'+PACKAGE+'.claim.json')
 result={'schema':'ouf.installation-route-preparation-guard-stop-read.v1','complete':True,'readOnly':True,
  'contextPath':str(CONTEXT),'packageHash':PACKAGE,'sourceClosureHash':CLOSURE,'sourceModuleCount':219,
  'pythonVersion':list(sys.version_info[:3]),**inspect_source(decoded['tools.chatbot_file_cohort.human_session']),
  'newPreparationClaimPresent':os.path.lexists(claim),'credentialJournalsOpened':0,'bearerFilesOpened':0,
  'authorityFilesOpened':False,'privateKeyFilesOpened':0,'sourceExecuted':False,'oauthRequests':0,
  'ownerRequests':0,'engineCalls':0,'gatewayWrites':0,'journalWrites':0,'processDispatches':0,
  'currentHumanStateRequeried':False,'automaticReplayAllowed':False,'budgetReset':False,
  'runtimeAuthorityIssued':False,'completedTechnicalPhases':8,'functionalMilestonesProven':4}
 signal.alarm(0);return result
if __name__=='__main__':
 try:result=main()
 except(Exception,KeyboardInterrupt)as error:
  result={'schema':'ouf.installation-route-preparation-guard-stop-read.v1','complete':False,
   'exceptionClass':type(error).__name__,'reason':'PRIVATE_DETAILS_REDACTED','automaticReplayAllowed':False,'budgetReset':False}
 print(encoded(result).decode(),flush=True);raise SystemExit(0 if result['complete']else 2)
