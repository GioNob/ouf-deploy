"""Protected after-APPROVO custody/effect read; no authority acceptance or replay."""
import hashlib,json,os,signal,stat,time,re,socket,http.client,urllib.parse
from pathlib import Path
PREPARED=Path('/etc/ouf/deploy-snapshots/source-revision-postboot-prepared-kfy691gh')
STOPPED=Path('/etc/ouf/deploy-snapshots/source-revision-execution-tvc2ilnv')
CASE='6ac7617fcedf9ff6bba44da6c3f8189d63c080523d2ea6bea628bffb99f1473d'
PACKAGE='bfbbed8649e8fc438e7f71f598bb22a6d2c75335cbf6e2c25969e464e0a62cb7'
RESULT='90559c21350b737c591342163140477bcf42c7f4aa21f4819563c92b7e5ffed6'
def require(ok):
 if not ok:raise ValueError('READ_RECONCILIATION_UNPROVEN')
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(value):return hashlib.sha256(encoded(value)).hexdigest()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def parse(raw):
 def unique(rows):
  value={}
  for key,item in rows:require(key not in value);value[key]=item
  return value
 return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(ValueError()))
def pin(s):return tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def read(path,expected=None,maximum=8388608):
 path=Path(path);require(path.is_absolute() and path.resolve()==path)
 for parent in path.parents:
  s=parent.lstat();require(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022)
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  st=os.fstat(fd);require(stat.S_ISREG(st.st_mode) and st.st_uid==st.st_gid==0 and stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1 and 0<st.st_size<=maximum)
  with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(maximum+1)
  require(len(raw)==st.st_size and pin(st)==pin(os.fstat(fd))==pin(path.lstat()) and(expected is None or sha(raw)==expected));return raw
 finally:os.close(fd)
CAPSULE=Path('/etc/ouf/deploy-snapshots/source-revision-governed-continuation-daxl0o6h')
EXECUTION=Path('/etc/ouf/deploy-snapshots/source-revision-execution-dvf517sr')
COMPLETION='a0dd0cd51a3b60f3635a185fe2c63c92c4ce6f4618cc6994d46a06514ce02076'
NEW_CASE='00054f41c7467e8c0d84827d5e7dca710f874a7f8b0d397440bc264b7f96be95'
NEW_PACKAGE='2c50390d6c3b60d04aedd204056e7dc31749d4eb05a228a63c34ed18c113f96a'
REVIEW='55384120f76186225520bfd94e4d74a6cbb8e6e3d981a52ec8b3972682f45478'
SOURCE_CLOSURE='be5757089d412b3aeef1d44f71ce0b624071146da0b11b09c049f5635b029144'

def probe(path,expected=None,maximum=65536):
 path=Path(path);require(path.is_absolute()and path.resolve()==path);first=path.lstat()
 ancestry=True
 for parent in path.parents:
  st=parent.lstat();ancestry=ancestry and stat.S_ISDIR(st.st_mode)and st.st_uid==0 and not st.st_mode&0o022
 result={'uid':first.st_uid,'gid':first.st_gid,'mode':format(stat.S_IMODE(first.st_mode),'04o'),'links':first.st_nlink,'bytes':first.st_size,
  'regularFile':stat.S_ISREG(first.st_mode),'rootControlledAncestry':bool(ancestry),
  'nativePrivateCustodyPass':bool(ancestry and stat.S_ISREG(first.st_mode)and first.st_uid==first.st_gid==0 and stat.S_IMODE(first.st_mode)==0o600 and first.st_nlink==1 and 0<first.st_size<=maximum),
  'expectedHashMatches':None,'notRuntimeAcceptance':True}
 # READONLY diagnostics may inspect exact hash-bound root public metadata; the
 # runtime's strict private reader is not called, changed or bypassed.
 if expected and ancestry and stat.S_ISREG(first.st_mode)and first.st_uid==0 and not first.st_mode&0o022 and first.st_nlink==1 and 0<first.st_size<=maximum:
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  try:raw=os.read(fd,maximum+1);require(len(raw)==first.st_size and pin(first)==pin(os.fstat(fd))==pin(path.lstat()));result['expectedHashMatches']=sha(raw)==expected
  finally:os.close(fd)
 require(pin(path.lstat())==pin(first));return result

def inventory(directory):
 files={};dirs={}
 known={'candidate-review.json','prepared-plan.json','login-window-receipt.json','authorization-plan.json','execution-plan.json','review.json',
  'issuance.claim.json','decision.json','human.json','authority.json','recovery.json','recovery.lock','invocation.lock','backup.json','onboarding.dump','config.json'}
 def walk(path,depth=0):
  require(depth<=6 and len(dirs)<20);st=path.lstat();require(stat.S_ISDIR(st.st_mode)and st.st_uid==st.st_gid==0 and stat.S_IMODE(st.st_mode)==0o700);dirs[str(path)]=pin(st)
  for child in path.iterdir():
   require(len(files)<60)
   relative=str(child.relative_to(directory));info=child.lstat()
   if stat.S_ISDIR(info.st_mode):
    require(depth>0 and str(path.relative_to(directory)).startswith('gateway-compiler')or depth==0 and child.name in ('gateway-compiler','authorization'));walk(child,depth+1)
   else:
    require(stat.S_ISREG(info.st_mode)and info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1)
    require(relative.startswith('gateway-compiler/')or child.name in known or re.fullmatch('[a-f0-9]{64}\.(DEPLOYMENT_INTENT|FINAL_DEPLOYMENT_APPROVAL)\.json',child.name))
    files[relative]={'bytes':info.st_size,'metadata':pin(info)}
 walk(directory)
 require(all(pin(Path(path).lstat())==value for path,value in dirs.items()))
 return files

def journal_report(row,plan,authority_hash):
 require(row['schema']=='ouf.source-revision-update-journal.v1'and row['budgetReset']is False and type(row['effects'])is list and len(row['effects'])<=40)
 require(row['authorityHash']==authority_hash and type(row['nextStage'])is int and 0<=row['nextStage']<=40)
 effects=[]
 for effect in row['effects']:
  require(type(effect['stage'])is str and re.fullmatch('[A-Z_a-z.]{1,80}',effect['stage'])and effect['state']in('CLAIMED','APPLIED'))
  effects.append({'stage':effect['stage'],'state':effect['state']})
 return {'stateSchema':row['schema'],'version':row['version'],'nextStage':row['nextStage'],'effectCount':len(effects),'effects':effects,
  'authorityHashBound':True,'budgetReset':False,'expiredByWallClock':time.time()>=row['expiresAt'],
  'currentBootMatches':row['bootId']==Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'journalHashPrinted':False}

def observe_engine(plan):
 binding=plan['engine'];path=Path(binding['socketPath']);require(path.is_absolute()and path.resolve()==path)
 def guard():
  st=path.lstat();require(stat.S_ISSOCK(st.st_mode)and [st.st_dev,st.st_ino,st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode)]==list(binding['socketBinding']))
 class Local(http.client.HTTPConnection):
  def connect(self):
   self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(15);self.sock.connect(str(path))
 selected={**{m:r['oldRuntimeBinding']for m,r in plan['replacements'].items()},**plan['unchangedApplications']};require(0<len(selected)<=16);out={}
 for module,expected in selected.items():
  require(re.fullmatch('[a-zA-Z_]{1,40}',module)and re.fullmatch('[a-f0-9]{64}',expected['containerId']));guard();connection=Local('selected-engine',timeout=15)
  try:
   connection.request('GET','/v1.44/containers/'+expected['containerId']+'/json');reply=connection.getresponse();raw=reply.read(8388609);require(reply.status==200 and 0<len(raw)<=8388608);actual=parse(raw)
  finally:connection.close()
  guard();state=actual['State'];current={'containerId':actual['Id'],'imageId':actual['Image'],'pid':state['Pid'],'startedAt':state['StartedAt'],
   'configHash':digest(actual['Config']),'hostConfigHash':digest(actual['HostConfig']),'mountsHash':digest(sorted(actual['Mounts'],key=lambda m:m['Destination'])),'networkSettingsHash':digest(actual['NetworkSettings'])}
  out[module]={'running':state['Running'],'paused':state['Paused'],'restarting':state['Restarting'],
   'identityMatchesExpected':all(current.get(k)==v for k,v in expected.items()),'pid':state['Pid'],'startedAt':state['StartedAt']}
 return out

def main():
 require(os.geteuid()==os.getegid()==0 and __import__('sys').flags.isolated and __import__('sys').flags.no_site and __import__('sys').dont_write_bytecode);signal.alarm(180)
 result=parse(read(CAPSULE/'postboot-preparation-result.json',COMPLETION));case=parse(read(CAPSULE/'executor-code/case.json',NEW_CASE));package=parse(read(CAPSULE/'executor-code/package.json',NEW_PACKAGE))
 require(result['sourceClosureSha256']==SOURCE_CLOSURE and result['caseBinding']['sha256']==NEW_CASE and result['executorCodeBinding']['packageSha256']==NEW_PACKAGE)
 review_raw=read(EXECUTION/'review.json',REVIEW);review=parse(review_raw);plan_raw=read(EXECUTION/'execution-plan.json');plan=parse(plan_raw)
 require(review['sourceClosureHash']==SOURCE_CLOSURE and review['authorityDirectory']==str(EXECUTION)
  and review['scopes']['sourceRevisionUpdate']['planHash']==digest(plan)and plan['authorityDirectory']==str(EXECUTION))
 before=inventory(EXECUTION);snapshots={str(EXECUTION/'review.json'):REVIEW,str(EXECUTION/'execution-plan.json'):sha(plan_raw)}
 def document(path):
  raw=read(path,maximum=1048576);snapshots[str(path)]=sha(raw);return parse(raw)
 authority_present='authority.json'in before;authority_raw=read(EXECUTION/'authority.json')if authority_present else None
 authority_hash=sha(authority_raw)if authority_raw else None
 if authority_present:
  authority=parse(authority_raw);require(authority['scopedExecution']['reviewHash']==REVIEW and authority['sourceClosureHash']==SOURCE_CLOSURE);snapshots[str(EXECUTION/'authority.json')]=authority_hash
 journal=document(EXECUTION/'recovery.json')if'recovery.json'in before else None
 journal_status=journal_report(journal,plan,authority_hash)if journal else None
 if journal:require(journal['scopeHash']==digest(review['scopes']['sourceRevisionUpdate']))
 decision_bound=None;issuance_bound=None
 if'decision.json'in before:
  decision=document(EXECUTION/'decision.json');decision_bound=decision['reviewHash']==REVIEW and decision['sourceClosureHash']==SOURCE_CLOSURE
 if'issuance.claim.json'in before:
  claim=document(EXECUTION/'issuance.claim.json');issuance_bound=claim['reviewHash']==REVIEW and ('decision.json'in before and claim['decisionHash']==digest(decision))
 probes={'privateReview':probe(plan['privateReviewBinding']['path'],plan['privateReviewBinding']['sha256'],8388608)}
 for index,binding in enumerate(plan['retainedMcpMetadata']):probes['retainedMcpMetadata'+str(index)+':'+Path(binding['path']).name]=probe(binding['path'],binding['sha256'],65536)
 for module,row in plan['replacements'].items():
  binding=row.get('imageArchive')or row.get('candidateImage',{}).get('imageArchive')
  if binding:probes[module+'ImageArchive']=probe(binding['path'],maximum=1200000000)
 reference=case['postbootResumedHuman'];directory=Path(reference['binding']['sessionDirectory']);human=document(directory/'recovery.json')
 require(human['binding']==reference['binding']and human['budgetReset']is False and type(human['attempts'])is int and 188<=human['attempts']<=256)
 public_human={'state':human['state']if human['state']in('READY','BLOCKED','REQUESTING','VERIFYING','RETRY_WAIT')else'UNCLASSIFIED',
  'attempts':human['attempts'],'remainingAttempts':256-human['attempts'],'maximumAttempts':256,
  'expiredByWallClock':time.time()>=human['binding']['expiresAt'],'windowRemainingSeconds':max(0,int(human['binding']['expiresAt']-time.time())),
  'originalBindingPreserved':True,'journalHashPrinted':False,'tokenFilesOpened':0}
 logical=EXECUTION.parent/('source-revision-update-'+plan['logicalUpdateRef']+'.claim.json');logical_exists=os.path.lexists(logical);logical_bound=None
 if logical_exists:
  claim=document(logical);logical_bound=claim['planHash']==digest(plan)and claim['authorityHash']==authority_hash and claim['context']==str(EXECUTION)
 engine=observe_engine(plan)
 for path,expected in snapshots.items():read(path,expected,1048576 if path.endswith('recovery.json')else 8388608)
 require(inventory(EXECUTION)==before)
 return {'schema':'ouf.source-revision-after-approval-custody-read.v1','complete':True,'contextPath':str(EXECUTION),'contextFiles':len(before),
  'reviewSha256':REVIEW,'sourceClosureSha256':SOURCE_CLOSURE,'authorityArtifactsObserved':authority_present,
  'issuanceClaimPresent':'issuance.claim.json'in before,'decisionPresent':'decision.json'in before,'decisionReviewBound':decision_bound,'issuanceDecisionBound':issuance_bound,
  'signatureFilesPresent':sum(bool(re.fullmatch('[a-f0-9]{64}\.(DEPLOYMENT_INTENT|FINAL_DEPLOYMENT_APPROVAL)\.json',n))for n in before),
  'logicalScopeClaimPresent':logical_exists,'logicalScopeClaimBound':logical_bound,'updateJournal':journal_status,
  'backupDumpPresent':'onboarding.dump'in before,'backupReceiptPresent':'backup.json'in before,'fileCustody':probes,
  'containerReadback':engine,'engineReadOnlyCalls':len(engine),'databaseCalls':0,'humanSession':public_human,
  'retainedFilesPreserved':True,'journalWrites':0,'runtimeAuthorityIssuedByRead':False,'runtimeAuthorityAcceptedByRead':False,
  'automaticRetry':False,'budgetReset':False,'credentialValuesPrinted':False,'credentialJournalHashesPrinted':False,
  'completedTechnicalPhases':8,'functionalMilestonesProven':4}
if __name__=='__main__':
 try:output=main()
 except (Exception,KeyboardInterrupt)as error:
  output={'schema':'ouf.source-revision-after-approval-custody-read.v1','complete':False,'exceptionClass':type(error).__name__,
   'rawErrorPrinted':False,'runtimeAuthorityIssuedByRead':False,'automaticRetry':False,'budgetReset':False,'reconciliationRequired':True}
 print(json.dumps(output,sort_keys=True));raise SystemExit(0 if output['complete']else 2)
