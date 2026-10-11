"""Read protected R12 readiness, retained reason and budgets; never recover/apply.

Safe projections only. Paused/failed states are valid diagnostic observations,
never readiness or authority. Journal files and every consumed claim are read.
"""
import hashlib,json,math,os,re,stat,sys,time,types
from pathlib import Path
HASHES={'prepare':'693ec0196a60d3a9f6adee96571947306df4a0cffb449905c3dcf8c09a34da1b',
 'custody':'cb9ff64684243d563da79d327eb7d7e325dbea6a3922c91a0b7791a3ceec9baf'}
AUTH_HASH='9730f8006a4257cbd2bf7576e6d0e49e41258360e0ca367f3e37852d57826e2b'
ERROR_TYPES={'ValueError','RuntimeError','PermissionError','FileNotFoundError','TimeoutError','ReadDenied','Permanent','Temporary','OSError','CalledProcessError'}
def require(ok,why):
 if not ok:raise ValueError(why)
def code(value):return value if type(value) is str and re.fullmatch('[A-Z][A-Z0-9_]{0,120}',value) else 'UNPROJECTED'
def number(value):
 return type(value) is int and 0<=value<=2**63-1 or type(value) is float and math.isfinite(value) and 0<=value<=2**63-1
def projection(value,depth=0):
 require(type(value) is dict,'DIAGNOSTIC_OBJECT_REQUIRED')
 out={k:code(value[k]) for k in ('status','state','reason','phase') if k in value}
 if 'timeAccountingProfile' in value:out['timeAccountingProfile']=value['timeAccountingProfile'] if value['timeAccountingProfile']=='ouf.lease-cumulative-recovery-time.v1' else 'UNPROJECTED'
 for k in ('workerPid','refreshCount','attempts','renewals','version','publicationCount','errno'):
  if type(value.get(k)) is int and 0<=value[k]<=2**63-1:out[k]=value[k]
 for k in ('recoveryBudgetRemainingSeconds','startedWall','startedMonotonic','lastWall','lastMonotonic','healthyWallSeconds','healthyMonotonicSeconds','nextWall','nextMonotonic'):
  if number(value.get(k)):out[k]=value[k]
 for k in ('ready','live','setsRevoked','doNotRerunApply','startAuthorized','containerLifecycleAuthorized','automaticReplayAllowed'):
  if type(value.get(k)) is bool:out[k]=value[k]
 if value.get('errorType') in ERROR_TYPES:out['errorType']=value['errorType']
 if type(value.get('flowAddressCounts')) is list and len(value['flowAddressCounts'])==2 and all(type(n) is int and 0<=n<=256 for n in value['flowAddressCounts']):out['flowAddressCounts']=value['flowAddressCounts']
 if depth<6 and type(value.get('exceptionChain')) is list:
  out['exceptionChain']=[projection(v,depth+1) for v in value['exceptionChain'][:6] if type(v) is dict]
 return out

def worker_checks(worker,incident):
 return {'schemaMatches':worker.get('schema')=='ouf.provider-resilient-worker-status.v1',
  'leaseActive':worker.get('status')=='LEASE_ACTIVE','stateActive':worker.get('state')=='ACTIVE',
  'ready':worker.get('ready') is True,'incidentMatches':worker.get('incidentRef')==incident,
  'applyReplayDisabled':worker.get('doNotRerunApply') is True,'startNotAuthorized':worker.get('startAuthorized') is False,
  'twoRenewalsObserved':type(worker.get('refreshCount')) is int and worker['refreshCount']>=2,
  'workerPidPresent':type(worker.get('workerPid')) is int and worker['workerPid']>0}
def modules(sources):
 require(type(sources) is dict and set(sources)==set(HASHES),'EXACT_R12_DIAGNOSIS_SOURCE_SET_REQUIRED')
 for name,h in HASHES.items():require(type(sources[name]) is bytes and len(sources[name])<=131072 and hashlib.sha256(sources[name]).hexdigest()==h,'R12_DIAGNOSIS_SOURCE_HASH_MISMATCH')
 out={}
 for name in HASHES:
  m=types.ModuleType('sealed_r12_diagnosis_'+name);exec(compile(sources[name],'sealed-r12-diagnosis-'+name,'exec'),m.__dict__);out[name]=m
 return out

def main():
 report={'schema':'ouf.r12-protected-readiness-diagnosis.v1','protectedFileWrites':0,'serviceLifecycleOperations':0,
  'containerLifecycleOperations':0,'imageImports':0,'importJournalWrites':0,'databaseQueries':0,'databaseWrites':0,
  'dnsQueries':0,'providerCalls':0,'firewallWrites':0,'newClaimCreated':False,'budgetReset':False,'r12Touched':False,
  'commonLeaseLockAcquired':False,'signaturesIssued':0,'privateValuesPrinted':False,'productionApplyReady':False,
  'applicationCutoverAuthorized':False,'notReleaseAcceptance':True,'diagnosisGrantsRecoveryAuthority':False,
  'readConsistencyMode':'BEFORE_AFTER_OBSERVATIONS_NOT_ATOMIC_TRANSITION_AUTHORITY'}
 phase='VERIFY_SEALED_DIAGNOSTIC_AND_RETAINED_AUTHORITY'
 try:
  require(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode and len(sys.argv)==1,'ISOLATED_ROOT_R12_DIAGNOSIS_REQUIRED')
  m=modules(globals().get('__r12_diagnosis_sources__'));prepare,custody=m['prepare'],m['custody']
  def read(path,expected=None,optional=False):
   try:raw=custody.file_bytes(path,0,{0o600},expected=expected)
   except FileNotFoundError:
    require(optional,'REQUIRED_PROTECTED_DIAGNOSTIC_FILE_ABSENT');return None,None
   value=json.loads(raw);require(type(value) is dict,'DIAGNOSTIC_OBJECT_REQUIRED');return raw,value
  auth_raw,auth=read(prepare.R12/'authorization.json',AUTH_HASH)
  require(auth['schema']=='ouf.provider-resilient-r12-authorization.v1' and auth['programHashes']==prepare.R12_PROGRAMS
   and prepare.digest({k:v for k,v in auth.items() if k!='contextRef'})==auth['contextRef'],'EXACT_RETAINED_R12_CAPSULE_REQUIRED')
  claim_raw,claim=read(prepare.R12_CLAIM);invocation_raw,invocation=read(prepare.R12/'worker-invocation-claim.json')
  require(claim==auth['activationClaim'],'RETAINED_R12_CLAIM_DRIFT')
  for name,h in prepare.R12_PROGRAMS.items():custody.file_bytes(prepare.R12/name,0,{0o600},expected=h)
  boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
  report.update(authorizationHash=AUTH_HASH,incidentRef=prepare.R12_INCIDENT,
   hostBootMatches=auth.get('hostBootId')==boot,invocationContextMatches=invocation.get('contextRef')==auth['contextRef'],
   invocationBootMatches=invocation.get('hostBootId')==boot,revocationMarkerPresent=os.path.lexists(prepare.R12/'revoked'),
   startupWindowExpired=time.time()>=auth['executionExpiresAt'],startupWindowIsNotWorkerLifetime=True,
   installedProgramCountVerified=len(prepare.R12_PROGRAMS),defaultMaxRecoveryAttempts=128,defaultMaxRecoverySeconds=86400)
  phase='READ_PROTECTED_WORKER_REASON_AND_EXISTING_RECOVERY_BUDGET'
  worker_raw,worker=read(prepare.R12/'worker-status.json')
  journal_raw,journal=read(prepare.R12/'retry/recovery.json')
  report.update(workerBefore=projection(worker),journalBefore=projection(journal),workerReadinessChecks=worker_checks(worker,prepare.R12_INCIDENT),
   journalContextMatchesAuthorization=journal.get('contextRef')==auth['contextRef'],journalGenerationMatchesAuthorization=journal.get('generationRef')==auth['generationRef'],
   invocationPidMatchesWorker=type(worker.get('workerPid')) is int and invocation.get('pid')==worker['workerPid'])
  denial_raw,denial=read(prepare.R12/'worker-denial.json',optional=True)
  report['workerDenialPresent']=denial is not None
  if denial is not None:report['workerDenial']=projection(denial)
  # Retained sealed reader is used only for bound READ commands and lease facts.
  raw=custody.file_bytes(prepare.R10/'reader.py',0,{0o600},expected=prepare.PROGRAMS['reader.py'])
  retained=types.ModuleType('sealed_r12_diagnostic_native_reader');retained.__file__=str(prepare.R10/'reader.py')
  exec(compile(raw,'sealed-r12-diagnostic-native-reader','exec'),retained.__dict__)
  human=retained.parse(retained.private(retained.CONTEXT/'human-approval-binding.json'))
  cfg=retained.parse(retained.private(retained.CONTEXT/'execution-configuration.json',human['configurationHash']))
  phase='READ_CURRENT_NATIVE_SERVICE_AND_LEASE_NO_MUTATION'
  props=['LoadState','ActiveState','SubState','MainPID','Restart','NRestarts','Result','ExecMainCode','ExecMainStatus','ExecStart']
  raw=prepare.native(retained,cfg['commandBindings']['systemctl'],['show',prepare.UNIT,'--no-pager','--property='+','.join(props)])
  service=dict(line.split('=',1) for line in raw.decode().splitlines() if '=' in line)
  report['service']={k:service[k] for k in props if k!='ExecStart' and k in service and re.fullmatch('[A-Za-z0-9_-]{0,64}',service[k])}
  report['serviceInvocationBindingsMatch']=service.get('MainPID')==str(invocation.get('pid')) and str(prepare.R12/'activate.py') in service.get('ExecStart','') and AUTH_HASH in service.get('ExecStart','')
  try:
   scope=retained.collect_cutover();lease=scope['lease']
   report['nativeLease']={'journalState':code(lease.get('journalState'))}
   report['nativeLease'].update({k:lease[k] for k in ('leaseAuthorized','providerSetsEmpty','journalAndMembershipConsistent','nativeStructureVerified') if type(lease.get(k)) is bool})
   if type(lease.get('flowCount')) is int and 0<=lease['flowCount']<=2:report['nativeLease']['flowCount']=lease['flowCount']
   report['nativeLease']['flows']=[{k:f[k] for k in ('inetAddressCount','bridgeAddressCount','approvedAddressCount','minRemainingTtlSeconds','leaseSeconds') if type(f.get(k)) is int and 0<=f[k]<=2**31-1} for f in lease.get('flows',[])[:2]]
   report['nativeLeaseReadStatus']='CAPTURED_READ_ONLY'
  except Exception as e:
   report['nativeLeaseReadStatus']='UNPROVEN_READ_ONLY';report['nativeLeaseReadReason']=code(str(e))
  phase='FINAL_PROTECTED_CUSTODY_AND_STATUS_OBSERVATION'
  worker_last_raw,worker_last=read(prepare.R12/'worker-status.json');journal_last_raw,journal_last=read(prepare.R12/'retry/recovery.json')
  report.update(workerAfter=projection(worker_last),journalAfter=projection(journal_last),
   workerChangedDuringRead=worker_last_raw!=worker_raw,journalChangedDuringRead=journal_last_raw!=journal_raw,
   workerReadinessChecksAfter=worker_checks(worker_last,prepare.R12_INCIDENT))
  require(read(prepare.R12/'authorization.json',AUTH_HASH)[0]==auth_raw and read(prepare.R12_CLAIM)[0]==claim_raw
   and read(prepare.R12/'worker-invocation-claim.json')[0]==invocation_raw,'IMMUTABLE_R12_BINDINGS_CHANGED_DURING_DIAGNOSIS')
  for name,h in prepare.R12_PROGRAMS.items():custody.file_bytes(prepare.R12/name,0,{0o600},expected=h)
  report['status']='R12_PRIVATE_READINESS_AND_BUDGET_CAPTURED_NO_RECOVERY_AUTHORITY';code_value=0
 except Exception as e:
  report.update(status='R12_PRIVATE_DIAGNOSIS_BLOCKED',phase=phase,reason=code(str(e)));code_value=1
 print('OUF_R12_READINESS_DIAGNOSIS='+json.dumps(report,sort_keys=True));return code_value
if __name__=='__main__':raise SystemExit(main())
