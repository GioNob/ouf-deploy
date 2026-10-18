"""Hash-bound root dispatcher for PREPARATION ONLY. Never invoke executor.main."""
import hashlib,json,os,re,signal,stat,sys,types,traceback
from pathlib import Path
NAMES={'reader.py','owner.py','boot_reader.py','bootstrap.py','policy.py','prepare.py','executor.py','run.py','guard_selection.json','selection.json'}
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
 modules['prepare'].run(selection,modules['reader'],modules['owner'],modules['boot_reader'],modules['bootstrap'],modules['policy'],parse(raw['guard_selection.json']),raw['executor.py'])
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
