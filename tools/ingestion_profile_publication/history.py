"""Completed owner7 history as authenticated files; no retained main or authority replay."""
import base64,hashlib,json,os,stat
from pathlib import Path
CONTEXT=Path('/etc/ouf/deploy-snapshots/ingestion-owner-recovery-execution-d6o9cpwd')
PLAN='e5f69f89aa40b8c9b963134d38a6aecaf864499346f9e366539c1eb1aefa0938'
RESULT='7d3902327a9b3641129f4416b66324c4cf727d0e54708216f9df098388a15618'
EXPORT='dd31d2b7de5ae66582275e5ac841584ff784065aa6e362ed0279d45fb6cdbc66'
TR=Path('/etc/ouf/deploy-snapshots/ingestion-owner-reference-execution-tr33g8bg')
TR_PACKAGE='afff187c6c97fe697ab448b6d88bdd24092c1fd00b0aef01f268e9982e96b5a5'
SOURCE='948242095f031673df01338a3c1eb313fd3c64e6'
RECOVERY_HASHES={'entry': 'eaad2c0172b165c537e97e987f200a34d10b67a7cdaa55876d05edd1816d06dd', 'authority': '7d6a6a5ce24e85ff429e81914bd1e68aaeb7e89dc7cf1c926627425966444675', 'owner': '6d0804fea64e0b924aadadeb3ef763e2d0278a209ace0a5869cad0655f2901d0', 'native': '49a62d0a6aa87d9e9e66b0f214fe4b0544c1b5397dda9c714eb49a00dd4f759e', 'login': '2bc05f5f89d95d27d1580b1d10591d7748642dad8336ba236000ec3fd2a61c59', 'reconcile': 'd64a56cdc0804913efe75780e91de579f4bba785673edc64febd5ec07dd80e4b'}
H_SUFFIX_BYTES=12394
H_SUFFIX_SHA256='f46402a278dbff5306baf7f5d18ccd9c8fa036d66f471900d167db28e95663b8'
BOOTSTRAP_SHA256='30ff6820098719bd5904864e8dc0b4868c0d1049713386950685ea9686ea28c7'
RUNTIME_SHA256='33bc29155bf9b8fed8ec30123041c493f0a8a975389a4f32a6e9c6ab731bb21d'

def require(ok,code):
 if not ok:raise ValueError(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(v):return hashlib.sha256(v).hexdigest()
def digest(v):return sha(encoded(v))
def read(path,expected=None,maximum=8388608):
 path=Path(path);require(path.is_absolute()and path.resolve()==path,'EXACT_PRIVATE_PATH_REQUIRED')
 for parent in path.parents:
  s=parent.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022,'PRIVATE_ROOT_ANCESTRY_REQUIRED')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(fd);require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1 and 0<s.st_size<=maximum,'PRIVATE_CUSTODY_REQUIRED')
  with os.fdopen(os.dup(fd),'rb')as f:raw=f.read(maximum+1)
  pin=lambda v:tuple(getattr(v,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  require(len(raw)==s.st_size and pin(s)==pin(os.fstat(fd))==pin(path.lstat())and(expected is None or sha(raw)==expected),'PRIVATE_BYTES_CHANGED');return raw
 finally:os.close(fd)
def parsed(path,expected=None):return json.loads(read(path,expected))
def write_new(path,raw):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  with os.fdopen(os.dup(fd),'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
 finally:os.close(fd)
 fd=os.open(Path(path).parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)


def verified():
 result=parsed(CONTEXT/'update-result.json',RESULT);plan=parsed(CONTEXT/'execution-plan.json',PLAN)
 require(result['complete']is True and result['status']=='OWNER_REFERENCE_ACTIVATED_AND_EXPORTED'
  and result['planHash']==PLAN and result['ownerPayloadReadbackProven']is True and result['ownerPosts']==3 and result['projectionExports']==1
  and result['activeProjectionWrites']==result['gatewayWrites']==result['containerLifecycleOperations']==result['directDatabaseCalls']==0
  and result['oauthAttemptsAfter']==276 and result['maximumCumulativeOAuthAttempts']==288
  and result['active']['revision']==result['active']['generation']==7,'EXACT_COMPLETED_OWNER7_RESULT_REQUIRED')
 package=parsed(CONTEXT/'package.json');ph=digest(package);decl=package['closure']['declaration']
 require(package['sourceCommit']==SOURCE and decl['entryModule']=='tools.ingestion_owner_recovery.entry'and decl['moduleCount']==238
  and decl['bootstrapBindings']['mode']=='INGESTION_OWNER_REFERENCE_RECOVERY_APPLY'
  and package['declarationHash']==digest(decl),'EXACT_COMPLETED238_PACKAGE_REQUIRED')
 raw={n:read(CONTEXT/n,h)for n,h in package['fileHashes'].items()}
 require(set(raw)=={'case.json','bootstrap.py','runtime.py','reader.py','sources.json'}and sha(raw['bootstrap.py'])==BOOTSTRAP_SHA256
  and sha(raw['runtime.py'])==RUNTIME_SHA256,'EXACT_COMPLETED_PACKAGE_BYTES_REQUIRED')
 require(parsed(CONTEXT/'runtime.claim.json')=={'packageHash':ph,'automaticReplayAllowed':False},'COMPLETED_RUNTIME_CLAIM_MUST_REMAIN_CONSUMED')
 tr=parsed(TR/'package.json',TR_PACKAGE);trraw={n:read(TR/n,h)for n,h in tr['fileHashes'].items()}
 old={n:base64.b64decode(v,validate=True)for n,v in json.loads(trraw['sources.json']).items()}
 require(len(old)==232 and set(old)==set(tr['closure']['declaration']['sourceHashes'])
  and all(sha(v)==tr['closure']['declaration']['sourceHashes'][n]for n,v in old.items()),'EXACT_PINNED232_PREFIX_HISTORY_REQUIRED')
 sources={n:base64.b64decode(v,validate=True)for n,v in json.loads(raw['sources.json']).items()};h='tools.chatbot_file_cohort.human_session'
 require(len(sources)==238 and set(sources)==set(decl['sourceHashes'])and all(sha(v)==decl['sourceHashes'][n]for n,v in sources.items()),'COMPLETED238_SOURCE_HASH_DRIFT')
 require(set(sources)==set(old)|{'tools.ingestion_owner_recovery.'+n for n in RECOVERY_HASHES}
  and all(sources[n]==v for n,v in old.items()if n!=h)
  and all(sha(sources['tools.ingestion_owner_recovery.'+n])==v for n,v in RECOVERY_HASHES.items())
  and sources[h][:-H_SUFFIX_BYTES]==old[h]and sha(sources[h][-H_SUFFIX_BYTES:])==H_SUFFIX_SHA256,'EXACT_QUALIFIED238_SOURCE_PROVENANCE_REQUIRED')
 case=json.loads(raw['case.json']);require(case['originalBinding']==json.loads(trraw['case.json'])['originalBinding']
  and digest(case)==package['executionPins']['caseSha256']and package['executionPins']==decl['bootstrapBindings']
  and package['executionPins']['executorSha256']==BOOTSTRAP_SHA256 and raw['reader.py']==trraw['reader.py'],'ORIGINAL_SELECTION_BINDING_DRIFT')
 require(plan['humanBinding']['retryProfile']['id']=='ouf.human.ingestion-owner-recovery288.v7'
  and plan['humanBinding']['retryProfile']['maximumAttempts']==288 and plan['humanBinding']['expiresAt']==result['humanWindowExpiresAt']==1792450664,
  'EXACT_SUCCESSFUL_HUMAN288_BINDING_REQUIRED')
 receipt=parsed(CONTEXT/'login-window-receipt.json')
 require(receipt['schema']=='ouf.ingestion-owner-recovery-budget288-receipt.v1'and receipt['directory']==plan['humanBinding']['sessionDirectory']
  and receipt['oauthAttemptsAfter']==276 and receipt['maximumCumulativeOAuthAttempts']==288 and receipt['expiresAt']==1792450664 and receipt['budgetReset']is False,
  'EXACT_SUCCESSFUL276_LOGIN_RECEIPT_REQUIRED')
 review=parsed(CONTEXT/'review.json');decision=parsed(CONTEXT/'decision.json');journal=parsed(CONTEXT/'recovery.json')
 scope=review['scopes']['ingestionOwnerReference'];stages=['VERIFY_INPUTS','CREATE_REVISION','VALIDATE_ENVIRONMENT','ACTIVATE_EXPECTED','EXPORT_ACTIVE','VERIFY_FINAL']
 require(scope['planHash']==PLAN and review['sourceClosureHash']==digest(package['closure'])and decision['reviewHash']==digest(review)and decision['sourceClosureHash']==digest(package['closure'])
  and decision['schema']=='ouf.semantic-scoped-terminal-decision.v1'and decision['state']=='ACTIVE'and decision['decision']=='APPROVE_EXACT_FINITE_SCOPED_ACTION'
  and review['authenticatedHuman']==plan['humanBinding']and decision['humanSessionHash']==digest(plan['humanBinding'])
  and journal['scopeHash']==digest(scope)and journal['incidentState']=='RECOVERED'and journal['nextStage']==6
  and len(journal['effects'])==6 and [e['stage']for e in journal['effects']]==stages
  and all(e['state']=='APPLIED'and e['intentHash']==digest({'planHash':PLAN,'stage':e['stage']})for e in journal['effects']),
  'EXACT_COMPLETED_OWNER_JOURNAL_REQUIRED')
 fence=parsed(CONTEXT.parent/('ingestion-owner-reference-'+plan['logicalRef']+'.claim.json'))
 require(fence=={'context':str(CONTEXT),'scopeHash':digest(scope),'authorityHash':journal['authorityHash'],'automaticReplayAllowed':False,'budgetReset':False},'COMPLETED_OWNER_EFFECT_FENCE_REQUIRED')
 require(journal['effects'][3]['evidence']['active']==result['active']and journal['effects'][4]['evidence']['projectionBinding']==result['projectionBinding'],'COMPLETED_OWNER_EFFECT_RESULTS_REQUIRED')
 exported=read(CONTEXT/'owner-active-projection.json',EXPORT)
 require(result['projectionBinding']=={'path':str(CONTEXT/'owner-active-projection.json'),'sha256':EXPORT},'EXACT_AUTHORITATIVE_EXPORT_REQUIRED')
 projection=json.loads(exported);expected=dict(plan['sourceProjection'],revision=7,checksum=result['active']['checksum'])
 require(projection==expected and result['active']['checksum']==plan['bindingPlan']['candidatePayloadChecksum'],'EXACT_OWNER7_PROJECTION_DELTA_REQUIRED')
 return {'result':result,'plan':plan,'package':package,'raw':raw,'sources':sources,'case':case,'exported':exported}
