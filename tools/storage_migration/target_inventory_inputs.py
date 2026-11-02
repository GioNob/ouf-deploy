"""Continue from retained control14 metadata; do not repeat the thirteen-ID scan."""
import os,re,stat,subprocess,sys,time
from pathlib import Path
from tools.storage_migration import target_inventory_reconciliation as base
from tools.storage_migration.minio_input_observation import InputBinding as Binding
from tools.storage_migration import target_inventory_credentials as prior
Capture=base.Capture;require=base.require;decode=base.decode;digest=base.digest;attrs=base.attrs
SCOPE=Path('/etc/ouf/deploy-snapshots/seaweedfs-inventory-inputs-20261102-v1')
PREVIOUS=Path('/etc/ouf/deploy-snapshots/seaweedfs-inventory-credentials-20261102-v1')
FAILED={'automaticReplayAllowed': False, 'credentialPreflight': {'filesOpened': 0, 'metadataCandidates': 5, 'rawValuesSpooled': False, 'sourceBytesRead': 0}, 'cumulativeControlAttempts': 15, 'cumulativeDirectEngineGets': 50, 'directEngineGets': 1, 'phase': 'CREDENTIAL_PREFLIGHT', 'reasonCode': 'PRIVATE_BOUNDED_REGULAR_CREDENTIAL_SOURCE_REQUIRED', 'runtimeAuthorityIssued': False, 'scopeConsumed': True, 'status': 'STOP_RECONCILE', 'targetApplyAuthorized': False}
PROFILE={'schema':'ouf.storage-input-observation-control.v1','maximumAttempts':1,'maximumSeconds':600,'previousControlAttempts':15,'previousEngineGets':50,'maximumEngineGets':2,'maximumEngineResponseBytes':2097152,'maximumCredentialFiles':5,'maximumSecretFileBytes':4096,'maximumConfigEnvBytes':65536,'maximumCredentialBytesRead':81920,'maximumS3Requests':10000,'maximumS3Records':25000,'maximumS3Seconds':300,'maximumPrivateInventoryBytes':67108864,'sourcePayloadLimitBytes':327680,'inputReadPolicy':'DECLARED_EXISTING_REGULAR_BOUNDED_STABLE_NO_SYMLINK_NO_CUSTODY_ADMISSION','maximumMetadataCandidates':9,'metadataPreflightAllCandidates':True,'inputPermissionsModified':False,'objectBodiesRead':0,'sqlRequests':0,'containerLifecycleOperations':0,'automaticReplayAllowed':False,'runtimeAuthorityIssued':False,'migrationAuthorized':False}
class Engine(base.Engine):
 def bind(self,ids,seed):
  super().bind(ids,seed);self.allowed={'/v1.44/containers/'+base.ROSTER['minio']['containerId']+'/json'}
 def get(self,path):
  require(self.gets<2,'TWO_FRESH_MINIO_READS_ONLY');return super().get(path)
def observation(view):
 rows=view['mounts'];require(type(rows) is list and len(rows)<=64 and all(type(r) is dict and set(r)=={'Type','Name','Source','Destination','RW'} and type(r['Destination']) is str and r['Destination'].startswith('/') and type(r['RW']) is bool for r in rows),'TYPED_INVENTORY_MOUNT_OBSERVATIONS_REQUIRED')
 require(len({r['Destination'] for r in rows})==len(rows),'UNIQUE_INVENTORY_MOUNT_DESTINATIONS_REQUIRED')
 # Observation comparison only. Preserve raw snapshots and all frozen runtime
 # binding/source hashes; no native creation/admission contract is normalized.
 return {**view,'mounts':sorted(rows,key=lambda r:r['Destination'])}
def history(control):
 frames=base.history_frames(PREVIOUS,('capture.claim.json','storage-baseline.claim.json','predecessor-reconciliation.json','result.json'))
 def read(name):return decode(control.read(PREVIOUS/name,0,0,0o600,32768,'metadataReads'))
 require(read('result.json')==FAILED and read('storage-baseline.claim.json')=={'profile':prior.PROFILE,'automaticReplayAllowed':False},'EXACT_CONSUMED_CONTROL15_PREFLIGHT_STOP_REQUIRED')
 require(read('capture.claim.json')=={'schema':'ouf.m2-discovery-custody-capture-claim.v1','automaticReplayAllowed':False},'EXACT_CONTROL15_CLAIM_REQUIRED')
 inherited,host,seed,mapping,private=prior.history(control);frames.update(inherited)
 link=read('predecessor-reconciliation.json');require(link['control14ResultHash']==digest(prior.FAILED) and link['previousControlAttempts']==14 and link['previousEngineGets']==49,'EXACT_CONTROL15_LINEAGE_REQUIRED')
 control.put('control15-reconciliation.json',{'control15ResultHash':digest(FAILED),'previousControlAttempts':15,'previousEngineGets':50,'credentialFileContentsReadByControl15':0,'priorS3Requests':0,'oldScopeRearmed':False})
 return frames,host,seed,mapping,private
def capture(control,engine):
 control.phase='RETAINED_HISTORY'
 frames,host,seed,mapping,private=history(control)
 def stable():
  control.check();require(all(attrs(Path(p).lstat())==v for p,v in frames.items()),'ALL_FIFTEEN_PRIOR_SCOPES_MUST_REMAIN_UNCHANGED')
 control.phase='MINIO_PIN';stable();engine.bind([base.ROSTER[r]['containerId'] for r in sorted(base.ROSTER)],seed)
 path='/v1.44/containers/'+base.ROSTER['minio']['containerId']+'/json';doc=engine.get(path);old=next(r for r in host['bindings'] if r['role']=='minio')
 require(observation({'role':'minio',**base.filtered_binding(doc)})==observation(old) and doc['Config']['Env']==seed['observations'][mapping['minio']]['Config']['Env'],'EXACT_MINIO_RETAINED_BINDING_AND_ENVIRONMENT_REQUIRED')
 pid,env=base.minio_admission(doc,private['roles']['minio']['nativeImageId'],base.ROSTER['minio']['containerId']);pin=base.process_pin(pid)
 require(pin==host['minioProcessPin']==seed['processPins'][mapping['minio']],'EXACT_RETAINED_MINIO_PROCESS_GENERATION_REQUIRED')
 Capture.ancestors(base.BACKEND);s=base.BACKEND.lstat();require(stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o500 and s.st_nlink==1 and 0<s.st_size<=33554432,'ORIGINAL_ROOT_READER_REQUIRED')
 with base.BACKEND.open('rb') as f:require(base.file_sha(f)==base.BACKEND_SHA,'EXACT_ORIGINAL_READER_SHA_REQUIRED')
 binding=Binding(pid);descriptors=[]
 try:
  control.phase='CREDENTIAL_PREFLIGHT'
  try:
   control.inputMetadata=binding.preflight(env);control.put('credential-input-metadata.private.json',control.inputMetadata)
   require(not binding.policy_blocked,'CREDENTIAL_INPUT_METADATA_REVIEW_REQUIRED')
   values,sources=binding.resolve(env)
  except Exception:
   control.credentialStatus={'filesOpened':binding.opened,'sourceBytesRead':binding.bytes,'metadataCandidates':len(binding.probes),'rawValuesSpooled':False};raise
  control.credentialStatus=sources;control.put('credential-binding.private.json',sources)
  for value in values:descriptors.append(base.sealed_descriptor(value))
  stable();binding.stable();require(base.process_pin(pid)==pin,'MINIO_GENERATION_CHANGED')
  control.put('inventory-config.private.json',{'endpoint':'http://127.0.0.1:9000','region':binding.region,'allowLoopbackHttp':True,'accessKeyFd':descriptors[0],'secretKeyFd':descriptors[1]})
  timeout=min(320,int(control.until-time.monotonic()));require(timeout>=10,'CREDENTIAL_CONTINUATION_DEADLINE')
  control.phase='S3_METADATA'
  result=subprocess.run(['/usr/bin/nsenter','--net=/proc/'+str(pid)+'/ns/net','--',str(base.BACKEND),str(control.scope/'inventory-config.private.json'),str(control.scope/'s3')],pass_fds=descriptors,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','GOMEMLIMIT':'256MiB','GOMAXPROCS':'1'},stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
  require(len(result.stdout)<=4096 and len(result.stderr)<=4096,'MINIMIZED_SDK_RESULT_REQUIRED');report=decode(result.stdout)
  require(type(report.get('complete')) is bool and report.get('objectBodiesRead')==report.get('targetWrites')==0 and type(report.get('requests')) is int and type(report.get('records')) is int,'TYPED_READ_ONLY_SDK_RESULT_REQUIRED')
  control.lastSdkReport=report;control.phase='POSTCHECK'
  complete=result.returncode==0 and report['complete'];fd=os.open(control.scope/'s3/inventory.private.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  with os.fdopen(fd,'rb') as f:
   info=os.fstat(f.fileno());require(stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1 and 0<info.st_size<=67108864,'PRIVATE_BOUNDED_INVENTORY_REQUIRED');inventory_sha=base.file_sha(f);require(attrs(info)==attrs(os.fstat(f.fileno())),'PRIVATE_INVENTORY_CHANGED')
  post=engine.get(path)
  before_binding=observation(base.filtered_binding(doc));after_binding=observation(base.filtered_binding(post))
  changed=[k for k in before_binding if before_binding[k]!=after_binding.get(k)]
  control.put('postcheck.private.json',{'changedBindingFields':changed,'processGenerationStable':base.process_pin(pid)==pin})
  require(not changed,'MINIO_METADATA_CHANGED_DURING_S3_INVENTORY');require(base.process_pin(pid)==pin,'MINIO_PROCESS_CHANGED_DURING_S3_INVENTORY');binding.stable();stable()
  available=re.search(r'^MemAvailable:\s+([0-9]+) kB$',host['memoryInfo'],re.M);require(available is not None,'RETAINED_MEMORY_METADATA_REQUIRED')
  return {'status':'PRIVATE_STORAGE_BASELINE_CAPTURED_NOT_ADMITTED' if complete else 'PRIVATE_STORAGE_BASELINE_PARTIAL_REVIEW_REQUIRED','s3Complete':complete,'readerFailureCategory':report['failureCategory'],'privateInventorySha256':inventory_sha,'retainedHostBaselineHash':digest(host),'hostBaselineFromControl':14,'memoryAvailableBytes':int(available[1])*1024,'storageDataFreeBytes':host['capacity'][0]['freeBytes'],'storageDataTotalBytes':host['capacity'][0]['totalBytes'],'capacityAndMemoryObservedAtControl':14,'retainedContainerSnapshots':13,'otherTwelveContainerBindingsRefreshed':False,'inventorySummary':report['summary'],'records':report['records'],'s3Requests':report['requests'],'credentialSources':sources,'credentialValuesSpooled':False,'directEngineGets':engine.gets,'cumulativeDirectEngineGets':50+engine.gets,'cumulativeControlAttempts':16,'allFifteenPriorScopesPreserved':True,'credentialInputMetadata':binding.public_metadata(),'credentialSourceCustodyAdmitted':False,'thirteenInspectScanReplayed':False,'automaticReplayAllowed':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'pointInTimeSnapshotProven':False,'externalConsumersProvenAbsent':False,'releaseAcceptance':False}
 finally:
  for fd in descriptors:os.close(fd)
  binding.close()
def main():
 control=None;engine=None
 try:
  require(not sys.argv[1:] and os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ROOT_ISOLATED_NO_ARGUMENT_ENTRY_REQUIRED');os.umask(0o077)
  control=Capture(SCOPE);control.until=time.monotonic()+600;control.put('storage-baseline.claim.json',{'profile':PROFILE,'automaticReplayAllowed':False});engine=Engine(control)
  report=capture(control,engine);control.put('result.json',report);code=0 if report['s3Complete'] else 1
 except Exception as error:
  reason=str(error) if type(error) is base.Stop and re.fullmatch('[A-Z0-9_]{1,128}',str(error)) else 'CREDENTIAL_CONTINUATION_UNPROVEN'
  report={'status':'STOP_RECONCILE','reasonCode':reason,'scopeConsumed':os.path.lexists(SCOPE),'directEngineGets':engine.gets if engine else 0,'cumulativeDirectEngineGets':50+(engine.gets if engine else 0),'cumulativeControlAttempts':16 if control else 15,'automaticReplayAllowed':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False}
  if control:
   report['phase']=getattr(control,'phase','ENTRY');report['credentialInputMetadata']=getattr(control,'inputMetadata',None);report['credentialPreflight']=getattr(control,'credentialStatus',None)
   if hasattr(control,'lastSdkReport'):report.update(s3Requests=control.lastSdkReport['requests'],records=control.lastSdkReport['records'],readerReportedCompleteBeforeStop=control.lastSdkReport['complete'])
  if control:
   try:control.put('result.json',report)
   except Exception:pass
  code=1
 print(base.json.dumps(report,sort_keys=True));return code
if __name__=='__main__':raise SystemExit(main())
