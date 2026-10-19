"""Exact sealed public HUMAN guard source only; no credential journal or execution."""
import ast,base64,hashlib,json,os,re,signal,stat,sys,time
from pathlib import Path
CONTEXT=Path('/etc/ouf/deploy-snapshots/mcp-ingestion-read-transport-execution-wiqedn9w')
PACKAGE='4c63051ba4f22d3f83c33b96a5cc150824a6aadf79b9a6948ff09972b8c601be'
CLOSURE='2eb74254682d3fec8e49f2c5c08acaa83ff87b1f5d736b38124b7380e2a99a76'
SOURCE='c9d3ca870c95518c94f754640cd68dc8462c609e'
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
def selected_guard(raw):
 require(type(raw)is bytes and 0<len(raw)<=262144,'BOUNDED_SEALED_HUMAN_SOURCE_REQUIRED')
 tree=ast.parse(raw)
 classes=[n for n in tree.body if isinstance(n,ast.ClassDef)and n.name=='HumanSession']
 require(len(classes)==1,'EXACT_HUMAN_SESSION_CLASS_REQUIRED')
 methods=[n for n in classes[0].body if isinstance(n,ast.FunctionDef)and n.name=='_check_identity_and_budget']
 require(len(methods)==1,'EXACT_IDENTITY_BUDGET_GUARD_REQUIRED')
 method=methods[0]
 guards=[n for n in ast.walk(method)if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id=='require'
  and len(n.args)==2 and isinstance(n.args[1],ast.Constant)and n.args[1].value=='RENEWED_HUMAN_WINDOW_CUMULATIVE_HISTORY_REQUIRED']
 require(len(guards)==1,'EXACT_RENEWAL_GUARD_REQUIRED')
 # Public source expressions only: never evaluate a condition or inspect any
 # live row. All values below are AST source text authenticated by packageHash.
 text=ast.unparse(method)
 require(len(text.encode())<=32768,'BOUNDED_PUBLIC_GUARD_SOURCE_REQUIRED')
 return {'methodSource':text,'renewalGuardExpression':ast.unparse(guards[0].args[0])}
def main():
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_REQUIRED')
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('SOURCE_READ_DEADLINE')));signal.alarm(60)
 package=parsed(CONTEXT/'package.json',PACKAGE)
 require(package['sourceCommit']==SOURCE and digest(package['closure'])==CLOSURE
  and package['closure']['declaration']['moduleCount']==188,'EXACT_WIQEDN9W188_PACKAGE_REQUIRED')
 require(not any(os.path.lexists(CONTEXT/n)for n in ARTIFACTS),'LATER_MCP_ARTIFACTS_REQUIRE_RECONCILIATION')
 require(parsed(CONTEXT/'runtime.claim.json')=={'packageHash':PACKAGE,'automaticReplayAllowed':False},'EXACT_CONSUMED_RUNTIME_CLAIM_REQUIRED')
 sources=parsed(CONTEXT/'sources.json',package['fileHashes']['sources.json'])
 name='tools.chatbot_file_cohort.human_session';raw=base64.b64decode(sources[name],validate=True)
 require(sha(raw)==package['closure']['declaration']['sourceHashes'][name],'EXACT_SEALED_HUMAN_BYTES_REQUIRED')
 result={'schema':'ouf.human-renewal-guard-source-read.v1','complete':True,'readOnly':True,
  'contextPath':str(CONTEXT),'humanSourceSha256':sha(raw),**selected_guard(raw),
  'credentialJournalsOpened':0,'bearerFilesOpened':0,'privateKeyFilesOpened':0,'sourceExecuted':False,
  'oauthRequests':0,'ownerRequests':0,'engineCalls':0,'processDispatches':0,'journalWrites':0,
  'automaticReplayAllowed':False,'budgetReset':False,'completedTechnicalPhases':8,'functionalMilestonesProven':4}
 signal.alarm(0);return result
if __name__=='__main__':
 try:result=main()
 except(Exception,KeyboardInterrupt)as error:
  result={'schema':'ouf.human-renewal-guard-source-read.v1','complete':False,'exceptionClass':type(error).__name__,
   'reason':'PRIVATE_DETAILS_REDACTED','automaticReplayAllowed':False,'budgetReset':False}
 print(encoded(result).decode(),flush=True);raise SystemExit(0 if result['complete']else 2)
