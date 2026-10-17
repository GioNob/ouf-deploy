"""One native GET per selected CSV job; no login, worker or retry."""
import base64,hashlib,json,os,re,signal,stat,time,urllib.error,urllib.request
from pathlib import Path
from urllib.parse import urlsplit
BOOT=Path('/etc/ouf/deploy-snapshots/semantic-mcp-update-executor-code-yrvtskkt/execute.py')
BOOT_HASH='b02d9737af6d143903910654d34e91a1a82a52b6082d2429d5dbfd070d160af2'
ROOT=Path('/etc/ouf/deploy-snapshots/csv-materialization-recovery-gxclmpxg')
def require(ok):
 if not ok:raise ValueError('EXACT_NATIVE_JOB_DIAGNOSTIC_BINDING_REQUIRED')
def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
def main():
 require(os.geteuid()==os.getegid()==0);signal.alarm(120)
 raw=BOOT.read_bytes();require(hashlib.sha256(raw).hexdigest()==BOOT_HASH)
 ns={'__name__':'verified_native_job_reader'};exec(compile(raw,'<verified-native-job-reader>','exec'),ns);read=ns['read']
 review=read(ROOT/'review.json',8388608);issued=read(ROOT/'authority.json',131072)
 require(review['authorityDirectory']==str(ROOT)and review['sourceClosure']['declaration']['sourceCommit']=='5536a3e011c88ac442b6828112bc045f304d58ca'
  and review['scopes']['policyTokenFiniteWorkerSession']==issued['policyTokenFiniteWorkerSession'])
 require(not any((ROOT/name).exists()for name in('native-retry-review.json','native-retry-decision.json','materialization-proof.json')))
 binding=review['nativeRecoveryPlanBinding'];require(binding=={'path':'/etc/ouf/deploy-snapshots/teatri-recovery-review-j9zv_7sz/prepared-plan.json','sha256':'eed179bb8d9179c772bbf722c78963ee288b4313728ed0a903d80ad3bbcdf5ae'})
 plan=read(binding['path'],8388608,binding['sha256']);jobs=plan['jobs']
 require(len(jobs)==11 and len({j['jobId']for j in jobs})==11)
 original=read(ns['CONTEXT']/'review.json',8388608,ns['REVIEW']);bundle=original['scopes']['finiteActionProcess']['bundle']
 prepared=read(bundle['path'],8388608,bundle['sha256'])['prepared'];selection=prepared['authorization']['plan']['selection']
 origin=selection['origin'];u=urlsplit(origin);require(u.scheme=='https'and u.hostname and not u.username and not u.password and not u.query and not u.fragment and u.path in('','/'))
 hb=review['authenticatedHuman'];require(all(hb[k]==selection[k]for k in('issuer','tenant','subject')))
 path=Path(hb['tokenPath']);require(path.is_absolute()and path.resolve()==path)
 for parent in path.parents:
  s=parent.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022)
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(fd);require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1 and 0<s.st_size<=16384)
  token=os.read(fd,16385);require(len(token)==s.st_size)
  require((s.st_ino,s.st_size,s.st_mtime_ns)==(os.fstat(fd).st_ino,os.fstat(fd).st_size,os.fstat(fd).st_mtime_ns))
 finally:os.close(fd)
 parts=token.strip().split(b'.');require(len(parts)==3)
 claims=json.loads(base64.urlsafe_b64decode(parts[1]+b'='*(-len(parts[1])%4)))
 require(claims.get('sub')==selection['subject']and claims.get('iss')==selection['issuer']
  and claims.get('tenant_id')==selection['tenant']and claims.get('ouf_actor_type')=='HUMAN'
  and 'udp.materialization.retry'in claims.get('scope','').split())
 worker=issued['policyTokenFiniteWorkerSession'];journal=Path(worker['fenceBinding']['value']['journalPath'])
 before={name:read(journal/name,131072)for name in('recovery.json','owner-session.json','owner-admission.json','owner-status.json','owner-session-review.json','owner-first-grant.json')}
 row=before['recovery.json'];require(before['owner-session.json']==worker and row['controlledCumulativeGrantAttempts']==316+row['attempts'])
 status={'schema':'ouf.csv-native-job-review-diagnostic.v1','readOnly':True,'credentialFilesRead':1,'credentialValuesPrinted':False,
  'grantRequests':0,'oauthRequests':0,'maximumGatewayGets':11,'jobMutations':0,'automaticRetry':False,'budgetReset':False,
  'tokenExpiredAtRead':time.time()>=claims['exp'],'attempts':row['attempts'],'publications':row['publicationCount'],
  'cumulative':row['controlledCumulativeGrantAttempts'],'workerState':row['state'],
  'recordHashes':{name:digest(value)for name,value in before.items()},'reviewHash':digest(review),'authorityHash':digest(issued),
  'nativeRetryReviewAbsent':True}
 if status['tokenExpiredAtRead']:
  status.update(complete=True,httpStatus=None,reason='EXISTING_HUMAN_ACCESS_TOKEN_EXPIRED_NO_RENEWAL');print(json.dumps(status,sort_keys=True));return
 class NoRedirect(urllib.request.HTTPRedirectHandler):
  def redirect_request(self,*args,**kwargs):return None
 results=[]
 for job in jobs:
  require(re.fullmatch('[0-9a-f-]{36}',job['jobId']))
  request=urllib.request.Request(origin.rstrip('/')+'/api/udp/v1/governance/materialization/jobs/'+job['jobId'],
   headers={'Authorization':'Bearer '+token.strip().decode('ascii'),'Accept':'application/json'},method='GET')
  try:
   with urllib.request.build_opener(NoRedirect()).open(request,timeout=10)as response:
    raw=response.read(16385);require(response.status==200 and 0<len(raw)<=16384);value=json.loads(raw)
  except urllib.error.HTTPError as error:
   results.append({'jobId':job['jobId'],'httpStatus':error.code,'failedChecks':['NATIVE_GET_REFUSED']});continue
  expected={**{k:job[k]for k in('jobId','handoffId','sourceId','ingestionRunId','integrityAttempts','safeFailureCode')},
   'state':'QUARANTINED','stateVersion':job['jobVersion'],'intakeState':'DURABLE','retryEligible':True,
   'contractReady':True,'contractCheck':'READY','verifiedBaselineHash':job['baselineHash']}
  checks={key:value.get(key)==item for key,item in expected.items()}
  checks['snapshotHashFormat']=bool(re.fullmatch('sha256:[0-9a-f]{64}',str(value.get('snapshotHash',''))))
  allowed=set(expected)|{'attempts','snapshotHash'}
  observed={key:item for key,item in value.items()if key in allowed and(type(item)in(str,int,bool)or item is None)}
  require(all(type(v)is not str or len(v)<=256 for v in observed.values()))
  results.append({'jobId':job['jobId'],'httpStatus':200,'failedChecks':[key for key,ok in checks.items()if not ok],
   'observed':{key:item for key,item in observed.items()if key in checks and not checks[key]}})
 status.update(complete=True,reviewedJobs=len(results),allJobsReady=all(r['httpStatus']==200 and not r['failedChecks']for r in results),
  jobs=results,recordsStable=all(read(journal/name,131072)==item for name,item in before.items()))
 print(json.dumps(status,sort_keys=True))
if __name__=='__main__':main()
