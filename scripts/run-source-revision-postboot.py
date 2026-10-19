"""Hash-bound root dispatcher for PREPARATION ONLY. Never invoke executor.main."""
import hashlib,json,os,re,signal,stat,sys,types,traceback
from pathlib import Path
NAMES={'reader.py','owner.py','boot_reader.py','bootstrap.py','policy.py','prepare.py','executor.py','run.py','guard_selection.json','selection.json','configuration.py','entry.py','login.py'}
def require(ok,code):
 if not ok:raise ValueError(code)
def parse(raw):
 def unique(pairs):
  result={}
  for k,v in pairs:
   require(k not in result,'DUPLICATE_PREPARATION_FIELD');result[k]=v
  return result
 return json.loads(raw,object_pairs_hook=unique)
def verified(path,sha):
 require(re.fullmatch('[a-f0-9]{64}',sha),'EXACT_PREPARATION_HASH_REQUIRED')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  st=os.fstat(fd);require(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and 0<st.st_size<=262144,'BOUNDED_PREPARATION_MEMBER_REQUIRED')
  with os.fdopen(os.dup(fd),'rb') as f:raw=f.read(262145)
  pin=lambda s:tuple(getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  require(len(raw)==st.st_size and pin(st)==pin(os.fstat(fd))==pin(Path(path).lstat()) and hashlib.sha256(raw).hexdigest()==sha,'PREPARATION_MEMBER_CHANGED')
  return raw
 finally:os.close(fd)
def handoff(result,executor_raw,reader):
 """Fresh isolated process only after a complete, privately verified preparation."""
 require(result['postbootSuccessorPrepared']is True and result['nativePlanCompilationProven']is True and result['runtimeAuthorityIssued']is False and result['readyForExecution']is False,'COMPLETE_PREPARATION_BEFORE_NATIVE_GATES')
 context=Path(result['contextPath']);receipt_sha=reader.digest(result)
 reader.read(context/'postboot-preparation-result.json',receipt_sha)
 binding=result['executorCodeBinding'];code=Path(binding['directory']);require(code==context/'executor-code','EXACT_SUCCESSOR_CODE_DIRECTORY')
 package=parse(reader.read(code/'package.json',binding['packageSha256']))
 require(package['sourceCommit']==binding['sourceCommit'] and package['executorSha256']==hashlib.sha256(executor_raw).hexdigest(),'EXACT_NATIVE_EXECUTOR_SUCCESSOR')
 reader.read(code/'execute.py',package['executorSha256'],262144)
 verifier="import hashlib,os,sys; from pathlib import Path; p=Path(sys.argv[1])/'execute.py'; fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK); raw=os.read(fd,262145); os.close(fd); expected=sys.argv.pop(); assert hashlib.sha256(raw).hexdigest()==expected, 'PINNED_NATIVE_EXECUTOR_CHANGED'; sys.argv=[str(p)]+sys.argv[1:]; exec(compile(raw,'<verified-postboot-native-executor>','exec'),{'__name__':'__main__','__file__':str(p)})"
 print(json.dumps({'schema':'ouf.postboot-preparation-to-native-gates.v1','contextPath':str(context),'preparationResultSha256':receipt_sha,'runtimeAuthorityIssued':False,'freshProcessRequired':True}),flush=True)
 os.execv('/usr/bin/python3',['/usr/bin/python3','-u','-I','-B','-S','-c',verifier,str(code),binding['sourceCommit'],binding['packageSha256'],receipt_sha,package['executorSha256']])


def main(directory,manifest_sha):
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_PREPARATION_REQUIRED')
 signal.alarm(300);directory=Path(directory)
 manifest=parse(verified(directory/'manifest.json',manifest_sha))
 require(manifest['schema']=='ouf.source-revision-postboot-code.v1' and set(manifest['files'])==NAMES and re.fullmatch('[a-f0-9]{40}',manifest['sourceCommit']),'EXACT_PREPARATION_CODE_CLOSURE_REQUIRED')
 raw={name:verified(directory/name,sha) for name,sha in manifest['files'].items()}
 modules={}
 for name in ('reader','owner','boot_reader','bootstrap','policy','prepare'):
  m=types.ModuleType('verified_postboot_'+name);m.__file__=str(directory/(name+'.py'))
  exec(compile(raw[name+'.py'],'<verified-postboot-'+name+'>','exec'),m.__dict__);modules[name]=m
 selection=parse(raw['selection.json']);selection['successorSourceCommit']=manifest['sourceCommit']
 result=modules['prepare'].run(selection,modules['reader'],modules['owner'],modules['boot_reader'],modules['bootstrap'],modules['policy'],parse(raw['guard_selection.json']),raw['executor.py'],raw['configuration.py'],{'tools.source_revision_update.entry':raw['entry.py'],'tools.source_revision_update.login':raw['login.py']})
 if selection.get('continueToNativeGates')is True:handoff(result,raw['executor.py'],modules['reader'])
if __name__=='__main__':
 try:
  require(len(sys.argv)==3,'EXACT_POSTBOOT_ARGUMENTS_REQUIRED');main(*sys.argv[1:])
 except (Exception,KeyboardInterrupt) as error:
  # No error messages/locals: imported libraries can contain protected values.
  print(json.dumps({'schema':'ouf.source-revision-postboot-stop.v1','complete':False,'exceptionClass':type(error).__name__,
   'frames':[{'file':Path(f.filename).name,'function':f.name,'line':f.lineno} for f in traceback.extract_tb(error.__traceback__)[-5:]],
   'runtimeAuthorityIssued':False,'automaticRetry':False,'budgetReset':False,'reconciliationRequired':True,
   'completedTechnicalPhases':8,'functionalMilestonesProven':4}),flush=True)
  raise SystemExit(2)
