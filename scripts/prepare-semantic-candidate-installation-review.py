"""One bounded target review from delivered bytes and completed custody.

No repeated root creation, credential reads, key access, signatures, service or
database mutations. This produces review inputs, never an executable installer.
"""
import base64
import hashlib
import os
from pathlib import Path
import shutil
import subprocess

CAPSULE_COMMIT='5640ceeb256e384b348cd5c900d71c6b8febe185'
CAPSULE_PATH='releases/policy-token-root-bound-migration-capsule-20261013.json'
CAPSULE_SHA='7b01bfb3012d1825e2a7c37ac159ee13c751194ea71cf56f63d57c6b20a153be'

ROOT_BODY=r'''
import base64,hashlib,json,os,re,signal,stat,subprocess,sys,types,zipfile
from pathlib import Path
PACKAGE_DIRECTORY=Path('/home/oufadmin/ouf-semantic-candidates-20261014.fADvCV9u')
PACKAGES={
 'semantic':('78954f106ea1248c624bf71596785af0b2980480cd58020eb0accd5d1f2df1c6','bdfe0f75a5fc4790a5c5ff36e201c3d99713ecc0'),
 'mcp':('6db692b78f1fde7bc3a30a8727afd4f581b2f8574f00c2fc117b71ea59b2aab4','d43f5604976b07c66d58c5180d871c5656c44d4d'),
 'gateway':('74b4f974adf74401cd592df26ce62dbea9399c8c025b124ee0e11e6d06f9d73a','23b02bd2195d36499b6618750d52dd49d65c9a60')}
IMAGE='sha256:1e2dac4a6619f511056abc91dd153ce7687efc25aec25aa77a6f66c9f2f67cfd'
ROOT_HASH='8b7698791f95d84454a65eb9e80ad3061e9d4c32d6efc427930859320e1f8b0d'
ROOT_SOURCE='9b78689d3bc4144a005abd5ab7cf8365a7c99e67a0057dfc84d2d27447479623'
CONSUMER_HASH='603a7e11a9e3d5c444accd4f198d30cb721a5f816a4b00d7d200cadde068c325'
CID='7ae83be8c1fe9fe25774b7d748e35153652b29b2501886f89daeabb83bd1a147'
OLD_IMAGE='sha256:f6525f2512c72a600ebcbc7060d55355d86e0627487b655e7c5c6288a0be7fc6'

def check(ok,reason):
 if not ok:raise ValueError(reason)

def file_identity(info):
 return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)

def delivered_package(module):
 expected,commit=PACKAGES[module]
 path=PACKAGE_DIRECTORY/(module+'.zip')
 directory=os.open(PACKAGE_DIRECTORY,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:
  parent=os.fstat(directory)
  check(stat.S_IMODE(parent.st_mode)==0o700 and parent.st_uid!=0,'EXACT_OPERATOR_PACKAGE_DIRECTORY_REQUIRED')
  fd=os.open(module+'.zip',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
  try:
   before=os.fstat(fd)
   check(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==parent.st_uid
     and 0<before.st_size<=536870912,'BOUNDED_OPERATOR_ARCHIVE_REQUIRED')
   with os.fdopen(os.dup(fd),'rb')as stream:
    digest=hashlib.sha256()
    for chunk in iter(lambda:stream.read(1048576),b''):digest.update(chunk)
    check(digest.hexdigest()==expected,'DELIVERED_ARCHIVE_SHA256_MISMATCH')
    stream.seek(0)
    with zipfile.ZipFile(stream)as archive:
     names=archive.namelist()
     check(0<len(names)<=32 and len(set(names))==len(names),'ARCHIVE_ENTRY_SCHEMA_DRIFT')
     member=archive.getinfo('candidate-manifest.json')
     check(member.file_size<=16384,'MANIFEST_SIZE_LIMIT')
     manifest=json.loads(archive.read(member))
     check(manifest.get('schema')=='ouf.semantic-proposal-unsigned-candidate.v1'
       and manifest.get('module')==module and manifest.get('sourceCommit')==commit,'EXACT_CANDIDATE_MANIFEST_REQUIRED')
     check(all(manifest.get(k)is False for k in ('runtimeAuthorityIssued','signatureIssued','targetApplyAuthorized','r12Touched','budgetReset'))
       and manifest.get('notReleaseAcceptance')is True and type(manifest.get('vpsOperations'))is int
       and manifest['vpsOperations']==0,'UNSIGNED_NO_AUTHORITY_CANDIDATE_REQUIRED')
     check(module!='semantic' or manifest.get('imageId')==IMAGE,'NEW_REGISTRY_IMAGE_BINDING_MISMATCH')
   check(file_identity(before)==file_identity(os.fstat(fd))
     ==file_identity(os.stat(module+'.zip',dir_fd=directory,follow_symlinks=False)),'OPERATOR_ARCHIVE_CHANGED_DURING_READ')
   check(file_identity(parent)==file_identity(os.fstat(directory))
     ==file_identity(PACKAGE_DIRECTORY.lstat()),'OPERATOR_DIRECTORY_CHANGED_DURING_READ')
   return {'archivePath':str(path),'archiveSha256':expected,'manifest':manifest,
     'archiveIdentity':{'device':before.st_dev,'inode':before.st_ino,'size':before.st_size},
     'rootCustodyEstablished':False}
  finally:os.close(fd)
 finally:os.close(directory)

def registry_metadata():
 # --format omits Config.Env and command strings rather than retrieving them.
 template='{"id":{{json .Id}},"image":{{json .Image}},"pid":{{json .State.Pid}},"startedAt":{{json .State.StartedAt}},"running":{{json .State.Running}},"restartPolicy":{{json .HostConfig.RestartPolicy}},"mounts":{{json .Mounts}}}'
 reply=subprocess.run(['/usr/bin/docker','inspect','--type','container','--format',template,CID],
   stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=15,
   env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
 check(reply.returncode==0 and 0<len(reply.stdout)<=65536,'CURRENT_REGISTRY_METADATA_UNAVAILABLE')
 result=json.loads(reply.stdout)
 check(result.get('id')==CID and result.get('image')==OLD_IMAGE and result.get('running')is True
   and type(result.get('pid'))is int and result['pid']>0,'RETAINED_REGISTRY_GENERATION_CHANGED')
 return result

def execute(report):
 report['phase']='SEALED_COMPONENT_READ'
 raw=sys.stdin.buffer.read(1048577)
 check(0<len(raw)<=1048576 and hashlib.sha256(raw).hexdigest()==CAPSULE_SHA,'ROOT_BOUND_COMPONENT_HASH_MISMATCH')
 payload=json.loads(raw)
 check(set(payload)=={'schema','sourceCommit','loader','sources','declarationHash'},'EXACT_COMPONENT_CAPSULE_REQUIRED')
 loader=base64.b64decode(payload['loader'],validate=True)
 runtime=types.ModuleType('verified_migration_loader')
 exec(compile(loader,'verified-migration-loader','exec'),runtime.__dict__)
 entry,manifest=runtime.load_entry(payload['sourceCommit'],
   {n:base64.b64decode(v,validate=True)for n,v in payload['sources'].items()},loader,payload['declarationHash'])
 import iam_owner_action as owner
 import migration_root_custody as roots
 import legacy_retirement as legacy
 binding=roots.binding
 report['phase']='EXACT_DELIVERED_CANDIDATE_READ'
 packages={module:delivered_package(module)for module in PACKAGES}
 report['phase']='EXISTING_INSTALLATION_AND_RETAINED_INPUTS_READ'
 with binding.protected_parent()as directory:
  intake,plan,snapshot,profile=owner.inputs(directory)
  host_raw=binding.read_member(directory,'policy-token-migration-host-inputs-'+legacy.HOST_HASH+'.private.json')
  check(binding.sha(host_raw)==legacy.HOST_HASH,'RETAINED_MIGRATION_HOST_HASH_MISMATCH')
  consumer=binding.read_member(directory,'policy-token-consumer-review-'+CONSUMER_HASH+'.private.json')
  check(binding.sha(consumer)==CONSUMER_HASH,'RETAINED_CONSUMER_EVIDENCE_HASH_MISMATCH')
  report['phase']='COMPLETED_ROOT_LEDGER_AND_CURRENT_UNIT_READ'
  with roots.completed_roots(host_raw,ROOT_HASH,ROOT_SOURCE)as identities:
   before_units=legacy.read_units()
   check(legacy.boot_identity()==binding.decode(host_raw)['kernelBootId'],'MIGRATION_BOOT_CHANGED')
   report['phase']='CURRENT_REGISTRY_AND_EXECUTING_SOURCE_READ'
   native=registry_metadata()
   library=owner.stdlib_binding()
   # Root body, capsule, executables and actual stdlib are all review inputs.
   source={'capsuleHash':CAPSULE_SHA,'declaration':manifest,'executingRootBodyHash':ROOT_BODY_HASH,
     'executables':intake['executablesProposedNotAccepted'],'stdlib':library}
   review={'schema':'ouf.semantic-candidate-installation-input-review.v1',
     'sourceClosureHash':binding.sha(binding.encoded(source)),'sourceClosure':source,
     'packages':packages,'completedRootEvidenceHash':ROOT_HASH,'rootCreationSourceClosureHash':ROOT_SOURCE,
     'completedRoots':identities,'retainedHostInputsHash':legacy.HOST_HASH,
     'retainedConsumerReviewHash':CONSUMER_HASH,'consumerObservationIsHistorical':True,
     'governanceIntakeHash':owner.INTAKE_HASH,'authorityProfile':intake['authorityProfile'],
     'trustPolicy':intake['trustPolicy'],'currentLegacyUnits':before_units,'currentRegistry':native,
     'completeRealizedOciProven':False,'currentDatabaseRead':False,'migrationAdmissionGranted':False,
     'mcpGatewayRuntimeBindingsProven':False,'newOwnerReceiptKeyCustodyProven':False,
     'credentialFilesRead':0,'privateKeyReads':0,'signaturesIssued':0,'runtimeOperations':0,
     'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'notReleaseAcceptance':True,
     'fullOwnerInstallerQualified':False,'budgetReset':False,'r12Touched':False}
   report['phase']='SAME_GENERATION_AND_CUSTODY_FINAL_CHECK'
   final_native=registry_metadata();final_units=legacy.read_units()
   if final_native!=native or final_units!=before_units:
    error=ValueError('TARGET_CHANGED_DURING_INSTALLATION_REVIEW')
    error.safe_diagnostics={'registryChangedFields':[key for key in native if final_native.get(key)!=native[key]],
      'legacyUnitsChanged':[unit for unit in before_units if final_units.get(unit)!=before_units[unit]]}
    raise error
   owner.inputs(directory)
   for module,record in packages.items():
    p=Path(record['archivePath']);info=p.lstat()
    check({'device':info.st_dev,'inode':info.st_ino,'size':info.st_size}==record['archiveIdentity'],
      'DELIVERED_PACKAGE_IDENTITY_CHANGED_BEFORE_PUBLICATION')
   body=binding.encoded(review);digest=binding.sha(body)
   name='semantic-candidate-installation-input-review-'+digest+'.private.json'
   report['phase']='PRIVATE_REVIEW_PUBLICATION'
   report.update(privateEvidenceHash=digest,privateEvidencePath=str(binding.PARENT/name),
     privateReviewPublicationOutcomeMayBePartial=True)
   wrote=owner.publish(directory,name,body)
   report.update(status='CURRENT_INSTALLATION_INPUTS_RECORDED_NOT_APPLY_READY',
     privateEvidenceHash=digest,privateEvidencePath=str(binding.PARENT/name),privateEvidenceWrites=int(wrote),
     sourceClosureHash=review['sourceClosureHash'],completedRootEvidenceHash=ROOT_HASH,
     privateReviewPublicationOutcomeMayBePartial=False,
     rootCreationClaimReplayed=False,verifiedCandidateCount=len(packages),
     currentRegistryGenerationObserved=True,completedRootCount=len(identities),
     retainedConsumerEvidenceReused=True,currentLegacyUnitCount=len(before_units))

def main_root():
 report={'schema':'ouf.semantic-candidate-installation-input-review-receipt.v1','status':'BLOCKED','phase':'ROOT_ENTRY',
   'privateEvidenceWrites':0,'credentialFilesRead':0,'privateKeyReads':0,'signaturesIssued':0,
   'runtimeOperations':0,'iamCalls':0,'databaseCalls':0,'rootDirectoriesCreated':0,
   'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'notReleaseAcceptance':True,
   'budgetReset':False,'r12Touched':False,'fullOwnerInstallerQualified':False}
 try:
  check(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
    'ROOT_ISOLATED_NO_SITE_PROCESS_REQUIRED')
  def expired(*_):raise ValueError('FINITE_REVIEW_DEADLINE')
  signal.signal(signal.SIGALRM,expired);signal.alarm(240)
  execute(report);code=0
 except Exception as error:
  reason=str(error)
  report.update(reason=reason if re.fullmatch('[A-Z][A-Z0-9_]{0,127}',reason)else type(error).__name__,
    evidenceLocation=report.get('privateEvidencePath','retained completed-root and delivery inputs'),
    automaticRetry=False,preserveExistingEvidence=True)
  if isinstance(error,OSError):report['errno']=error.errno
  if type(getattr(error,'safe_diagnostics',None))is dict:report['safeDiagnostics']=error.safe_diagnostics
  code=1
 finally:signal.alarm(0)
 print(json.dumps(report,sort_keys=True));return code
if __name__=='__main__':raise SystemExit(main_root())
'''

def main():
 preferred=Path.home()/'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh'
 gh=str(preferred)if preferred.is_file()and os.access(preferred,os.X_OK)else shutil.which('gh')
 if not gh:raise SystemExit('phase=DELIVERY reason=EXISTING_GH_UNAVAILABLE; no sudo executed')
 try:
  reply=subprocess.run([gh,'api','repos/GioNob/ouf-deploy/contents/'+CAPSULE_PATH+'?ref='+CAPSULE_COMMIT,'--jq','.content'],
    check=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30)
  if len(reply.stdout)>1500000:raise ValueError()
  raw=base64.b64decode(b''.join(reply.stdout.split()),validate=True)
  if not 0<len(raw)<=1048576 or hashlib.sha256(raw).hexdigest()!=CAPSULE_SHA:raise ValueError()
 except Exception:raise SystemExit('phase=DELIVERY reason=PINNED_COMPONENT_UNAVAILABLE_OR_HASH_MISMATCH; no sudo executed')from None
 bootstrap='CAPSULE_SHA='+repr(CAPSULE_SHA)+'\nROOT_BODY_HASH='+repr(hashlib.sha256(ROOT_BODY.encode()).hexdigest())+'\n'+ROOT_BODY
 try:return subprocess.run(['sudo','--','/usr/bin/python3','-I','-B','-S','-c',bootstrap],input=raw,timeout=300).returncode
 except Exception:raise SystemExit('phase=ROOT_REVIEW reason=RESULT_UNAVAILABLE; preserve evidence, no automatic rerun')from None

if __name__=='__main__':raise SystemExit(main())
