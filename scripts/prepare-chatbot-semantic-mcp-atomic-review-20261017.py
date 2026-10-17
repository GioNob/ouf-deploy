#!/usr/bin/env python3
"""Installation-specific private candidate only. No signing, grants or lifecycle effects."""
import hashlib,importlib.util,json,os,re,signal,stat,sys,tempfile,time,zipfile
from pathlib import Path

ZIP_SHA='0d15454fbf7914c1b8270cfee67fd3c97db1419d2e29e1ec81f43e867085161c'
IMAGE_SHA='sha256:e61bc9e3bd6f7e2bbf25cca285bfd4319d1addf43b67918961a7a90fc37e78f8'
TAR_SHA='6a86142d73de255ba8037fe8a36e7c2408071f11645119d31f8ca5ffff73a543'
SOURCE='f00e7e3bfcaee9272b9b6d204a7fa3ea79a563a4'
BINARY_SHA='07efce1f1360da9ddf1ded5c03ab626cde4b5a913b1893d2eb0dd37eed34d66e'
MIGRATION_SHA='fe9ab352cbf649efecc708b08a9f61ff3c9aadb358211ebd763011ee9fd695b5'
READER_SHA='cff7fa19d332ba07e2675a6effb336e7877e7b6f24a907b01977f1fb1441ecdb'
CUSTODY_SHA='9391a7d497943bd0412d96405d51359cd11a2b0db7106d30f272d28e8f0fc6b2'
PROFILE={'path':'/etc/ouf/deploy-snapshots/semantic-creation-issuer-install-USjonf22/installation-authority-profile.json','sha256':'7fb7880d58e43ab40f9f53dac07a5dbad462d12e3a96f3b1287c6763b1d7ce18'}
POLICY={'path':'/etc/ouf/deploy-snapshots/semantic-trust-policy-preparation-20261004-172336/trust-policy.json','sha256':'21122630e52cb63c3744fee89f5c81ed926dad55231190243ca11be6d481bd42'}
MEMBERS={'package/Dockerfile.resolved','package/SHA256SUMS','package/image.docker.tar','package/ouf-mcp',
 'package/package-record.json','package/source-inventory.json','package/source.tar','package/trivy-image.json','migration-continuity.json'}
class PreparationDenied(Exception):pass
def require(ok,reason):
 if not ok:raise PreparationDenied(reason)
def raw_json(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(v):return hashlib.sha256(v).hexdigest()
def digest(v):return sha(raw_json(v))
def emit(check,**values):
 fixed=dict(schema='ouf.chatbot-semantic-mcp-update-review.v2',check=check,readOnly=False,
  newPrivateReviewOnly=True,acceptanceGranted=False,budgetReset=False,automaticRetry=False)
 require(not set(fixed)&set(values),'RESERVED_OUTPUT_FIELD');print(json.dumps({**fixed,**values},sort_keys=True),flush=True)
def pin(s):return tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_nlink','st_mode','st_size','st_mtime_ns','st_ctime_ns'))
def bounded_input(path,expected,maximum):
 path=Path(path);require(path.is_absolute(),'ABSOLUTE_INPUT_REQUIRED')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  before=os.fstat(fd);require(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<before.st_size<=maximum,'BOUNDED_REGULAR_INPUT_REQUIRED')
  data=bytearray()
  while len(data)<=maximum:
   block=os.read(fd,min(1048576,maximum+1-len(data)))
   if not block:break
   data.extend(block)
  require(len(data)==before.st_size and pin(before)==pin(os.fstat(fd))==pin(path.lstat())and sha(data)==expected,'EXACT_INPUT_BYTES_REQUIRED')
  return bytes(data)
 finally:os.close(fd)
def dependency(path,expected,name):
 raw=bounded_input(path,expected,1048576)
 spec=importlib.util.spec_from_loader(name,loader=None);module=importlib.util.module_from_spec(spec)
 exec(compile(raw,'<sealed-mcp-update:'+name+'>','exec'),module.__dict__)
 return module

def validate_zip(z):
 rows=z.infolist();require(len(rows)==len(MEMBERS)and {r.filename for r in rows}==MEMBERS,'EXACT_PACKAGE_MEMBER_SET_REQUIRED')
 require(sum(r.file_size for r in rows)<=134217728,'PACKAGE_EXPANSION_BOUND_EXHAUSTED')
 for row in rows:
  mode=row.external_attr>>16
  require(not row.is_dir()and not row.flag_bits&1 and stat.S_IFMT(mode)in(0,stat.S_IFREG)
   and row.compress_type in(zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED)and 0<row.file_size<=67108864,'PACKAGE_LINK_OR_SIZE_DENIED')

def package_records(directory,expected_migrations):
 directory=Path(directory);base=directory/'package'
 sums=(base/'SHA256SUMS').read_text();entries={}
 for line in sums.splitlines():
  match=re.fullmatch('([0-9a-f]{64})  ([A-Za-z0-9_.-]+)',line)
  require(match is not None and match[2]not in entries,'UNAMBIGUOUS_PACKAGE_HASH_LIST_REQUIRED')
  entries[match[2]]=match[1]
 require(set(entries)=={Path(p).name for p in MEMBERS if p.startswith('package/')and not p.endswith('/SHA256SUMS')},'COMPLETE_PACKAGE_HASH_LIST_REQUIRED')
 for name,expected in entries.items():require(sha((base/name).read_bytes())==expected,'PACKAGE_MEMBER_HASH_DRIFT')
 require(entries['image.docker.tar']==TAR_SHA and entries['ouf-mcp']==BINARY_SHA,'PINNED_IMAGE_AND_BINARY_REQUIRED')
 rec=json.loads((base/'package-record.json').read_bytes());scan=json.loads((base/'trivy-image.json').read_bytes())
 require(rec.get('schema')=='ouf.unsigned-offline-candidate-package.v1'and rec.get('module')=='mcp'
  and rec.get('sourceCommit')==SOURCE and rec.get('imageId')==IMAGE_SHA and rec.get('runtimeUser')=='10005:10005'
  and rec.get('imageScanGate')=='PASS_HIGH_CRITICAL_UNKNOWN_INCLUDING_UNFIXED'
  and rec.get('signatureIssued')is False and rec.get('targetApplyAuthorized')is False
  and scan.get('Metadata',{}).get('ImageID')==IMAGE_SHA,'QUALIFIED_UNSIGNED_IMAGE_REQUIRED')
 require(not [v for r in scan.get('Results',[])for v in r.get('Vulnerabilities',[])if v.get('Severity')in('HIGH','CRITICAL','UNKNOWN')],'IMAGE_SCAN_GATE_FAILED')
 continuity=json.loads((directory/'migration-continuity.json').read_bytes())
 require(continuity.get('before')==expected_migrations and continuity.get('candidate')==expected_migrations+[{'version':13,'checksum':MIGRATION_SHA}]
  and continuity.get('historicalSourcesUnchanged')is True,'EXACT_THIRTEENTH_MIGRATION_REQUIRED')
 return rec,continuity

def expected_roles(reader):
 return {**{k:True for k in ('applicationRoleExists','applicationCanCreateInSchema','applicationCanInsertMigration',
  'applicationCanReferenceAttempts','applicationCanReferenceWindows','applicationCanExecuteImmutableTrigger',
  'retentionRoleExists','retentionRoleNoLogin','retentionFunctionOwnedByRetentionRole','newSessionTableAbsent')},
  **{k:False for k in ('applicationSuperuser','applicationCreateRole','retentionRoleSuperuser','applicationCanSetRetentionRole','applicationCanUseRetentionRole')},
  'retentionRoleMembers':0,'retentionFunctionHash':'95c25f228184ee59e6f2f9deb31575d67a257da8ce91aa148c0e0507b020cc47',
  'serverVersionNum':170011,'migrationCount':12,'migrations':reader.EXPECTED_MIGRATIONS}

def compile_plan(observed,reader,audit,record,continuity,output,profile,policy):
 require(observed['rolePreflight']==expected_roles(reader),'TARGET_ROLE_FACTS_CHANGED')
 facts=observed['claimFacts'];require(facts['claimCount']==1,'ONE_EXACT_PREDECESSOR_REQUIRED');claim=facts['claims'][0]
 require(claim=={'actorType':'HUMAN','actualToolCalls':1,'admissionContextPresent':True,
  'attemptId':'9d676b80-8f5f-4160-ac9e-57f0935f78be','dispatchState':'ACKNOWLEDGED','expectedDenialCodeProven':True,
  'lockVersion':2,'manifestChecksum':'09981c1cd01f47bed227250b70448dd24d2a66e4d36e7878df4f6235b783fd4a',
  'requestHash':'b8bc4ccb0f8fe48764ecf87340fd2ff209520c0b5b947a3ee6a1e461fc57a112',
  'reservationState':'RECONCILED','reservedToolCalls':1,'servicePrincipalId':'ouf-chatgpt','state':'FAILED'},'PREDECESSOR_OR_WORKLOAD_DRIFT')
 p=observed['prepared'];module=observed['module'];binding=next(r for r in p['databasePlan']['modules']if r['module']=='mcp')
 app=binding['user'];admin=p['databasePlan']['mcpAuditRoleAdministration']['admin']
 require(all(type(x)is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,62}',x)for x in(app,admin,binding['database'])),'EXACT_RETAINED_SQL_BINDINGS_REQUIRED')
 request=module['creationRequest'];networks=request['NetworkingConfig']['EndpointsConfig']
 require(len(networks)==1 and request['HostConfig']['NetworkMode']in networks and request['User']=='10005:10005','REVIEWED_SINGLE_NETWORK_MCP_REQUIRED')
 require(profile.get('schema')=='ouf.semantic-existing-installation-authority-bindings.v1'and profile.get('policyBinding')==POLICY,'EXISTING_AUTHORITY_PROFILE_REQUIRED')
 authorities=profile['authorities'];require(authorities.get('installationRef')==policy.get('installationRef')and authorities.get('entityRef')==policy.get('entityRef')and authorities['intentIssuerRef']==authorities['approvalIssuerRef'],'EXISTING_INSTALLER_CONTEXT_REQUIRED')
 keys=[k for k in policy['keys']if k['keyRef']==profile['keyRefs']['installer']]
 require(len(keys)==1 and keys[0]['state']=='ACTIVE'and keys[0]['issuerRef']==authorities['intentIssuerRef']
  and set(keys[0]['roles'])=={'DEPLOYMENT_INTENT','FINAL_DEPLOYMENT_APPROVAL'}and keys[0]['notBefore']<=time.time()<keys[0]['expiresAt'],'CURRENT_EXISTING_INSTALLER_ROLES_REQUIRED')
 return {'schema':'ouf.mcp-one-component-update-private-review.v2','authorityDirectory':str(output),
  'sourceReviewHash':observed['sourceReviewHash'],'sourceAuthorityHash':observed['sourceAuthorityHash'],
  'oldRuntimeBinding':observed['runtimeBinding'],'oldNativeConfig':observed['mcp']['Config'],
  'oldNativeHostConfig':observed['mcp']['HostConfig'],'oldNativeMounts':observed['mcp']['Mounts'],
  'oldNativeNetworks':observed['mcp']['NetworkSettings']['Networks'],
  'engine':p['engine'],'programs':observed['programs'],'retainedApplicationCreationRequest':request,
  'database':{'binding':binding,'postgresRuntimeBinding':p['databasePlan']['postgresRuntimeBinding'],
   'backupReader':admin,'before':continuity['before'],'after':continuity['candidate'],
   'freshBackupRequired':True,'maximumBackupBytes':1073741824,'automaticRestoreAllowed':False,'nativePackagedMigratorRequired':True},
  'temporaryPrivilege':{'role':'ouf_mcp_retention_owner','member':app,'beforeMembers':0,'beforeMembership':False,
   'maximumGrantAttempts':1,'temporaryInherit':True,'temporarySet':True,'superuserGrantAllowed':False,
   'applicationMustRemainStopped':True,'cleanupRequiredBeforeApplicationStart':True,'afterMembers':0},
  'rolePreflight':observed['rolePreflight'],'retainedClaim':claim,'imagePackage':record,'imageAudit':audit,
  'imageImport':{'archivePath':str(output/'candidate.tagless.tar'),'maximumAttempts':1,'retagAllowed':False},
  'history':{'previousTokenSessionMustRemainExpired':True,'tokenRenewalAuthorized':False,'budgetReset':False,
   'semanticCommandKey':reader.KEY,'humanSubject':reader.SUBJECT,'tenant':p['authorization']['plan']['selection']['tenant'],
   'priorToolCalls':1,'maximumNewToolCalls':1,'maximumCumulativeToolCalls':2,
   'claimRearmOrDeletionAllowed':False,'semanticProposeDispatchedByPreparation':False},
  'installationAuthority':{'profile':PROFILE,'policy':POLICY,'installerKeyRef':profile['keyRefs']['installer'],
   'authorities':authorities,'privateKeysRead':False,'newKeysAllowed':False},
  'pendingGates':['AUTHENTICATED_PRODUCTION_ENTRYPOINT_AND_REAL_MCP_BOOTSTRAP','CURRENT_AUTHENTICATED_EXACT_INFRASTRUCTURE_REVIEW',
   'FRESH_OWNER_RECEIPT_ABSENCE','SEPARATE_FINITE_REPROCESSING_DECISION','EXISTING_ROLE_SIGNATURES',
   'FINAL_RUNTIME_PROFILE_AND_PUBLIC_METADATA_MOUNT','CURRENT_AUTHORIZATION_AND_OWNER_POLICY'],
  'maximumExecutionSeconds':900,'maximumMigrationStartAttempts':1,'automaticRollbackAllowed':False,
  'applicationAcceptanceGranted':False,'readyForExecution':False,'runtimeAuthorityIssued':False,
  'completedTechnicalPhases':8,'functionalMilestonesProven':0}


PARENT_REVIEW={'path':'/etc/ouf/deploy-snapshots/semantic-mcp-update-review-8eoy5rm0/review.json',
 'sha256':'02590e54312e90c27093adfa1bea057a2111c4702cf3e50507a7af07d4833c9a'}
TOKEN_CONTEXT=Path('/etc/ouf/deploy-snapshots/semantic-token-execution-usx0tsem')
TOKEN_AUTHORITY='ccac6ea4c195de2c65937fb0df581adee5a610f167cb2c125662733932312eed'
TOKEN_JOURNAL=Path('/etc/ouf/deploy-snapshots/chatbot-file-intake-9f754dbcf7caf450d1d1eef50c0288f2102cfac191a65cfc60a5c1fcbf60ba5e/attempt-f8d38137fc4cca9d36910c19/semantic-functional-worker-beefc7f2ee79fa70c5b416d6d3efe68d3b08d15f9bb07c96c3e837995b627803')
TOKEN_HASHES={'owner-admission.json':'652bb9dec981208f5a5de047be9a9cd6e49216cae5012b5d7a5b62cc0a70c97b',
 'owner-session.json':'eb262363a384e3bf10a935fbe893568d10590ea4d62c17c5540008c2de819c7b',
 'owner-status.json':'42b53c8f4e5f8e44669dd90e6e1fb4d1ccdfc87f4c178a26a467301afa7a6b39',
 'recovery.json':'f06a7e0d3bcd3ccb8f05b1fcd744b6f33ba003b4d74fa472c9e7950ee00d27ac'}

def retained_context(reader):
 parent=reader.read(PARENT_REVIEW['path'],8388608,PARENT_REVIEW['sha256'])
 require(parent.get('schema')=='ouf.mcp-one-component-update-private-review.v1'
  and parent.get('readyForExecution')is False and parent.get('runtimeAuthorityIssued')is False
  and parent.get('imagePackage',{}).get('sourceCommit')=='1cbc496e1632ec3b1f2f0d9bf1e1f59a308278ef',
  'EXACT_UNEXECUTED_PARENT_REVIEW_REQUIRED')
 authority=reader.read(TOKEN_CONTEXT/'authority.json',131072,TOKEN_AUTHORITY)
 records={name:reader.read(TOKEN_JOURNAL/name,131072,expected)for name,expected in TOKEN_HASHES.items()}
 row=records['recovery.json'];session=records['owner-session.json'];last=records['owner-status.json']
 require(authority.get('expiresAt')==1792169238 and time.time()>=authority['expiresAt']
  and authority.get('policyTokenFiniteWorkerSession')==session
  and session.get('fenceBinding',{}).get('value',{}).get('journalPath')==str(TOKEN_JOURNAL)
  and row.get('workerSessionHash')==digest(session),'EXACT_EXPIRED_TOKEN_SESSION_REQUIRED')
 require(row.get('state')==last.get('state')=='CANCELLED'
  and row.get('reason')==last.get('reason')=='CANCELLED_BY_OWNER'
  and type(row.get('attempts'))is int and row['attempts']==last.get('attempts')==59
  and row.get('publicationCount')==last.get('publications')==59
  and row.get('controlledPredecessorGrantAttempts')==69 and row.get('controlledCumulativeGrantAttempts')==128
  and session.get('maximumCumulativeGrantAttempts')==197
  and records['owner-admission.json'].get('state')=='BLOCKED','EXACT_CANCELLED_TOKEN_HISTORY_REQUIRED')
 for name,expected in TOKEN_HASHES.items():reader.read(TOKEN_JOURNAL/name,131072,expected)
 return {'parentRuntimeBinding':parent['oldRuntimeBinding'],'workerEvidence':{
  'journalPath':str(TOKEN_JOURNAL),'authorityHash':TOKEN_AUTHORITY,'recordHashes':TOKEN_HASHES,
  'state':'CANCELLED','reason':'CANCELLED_BY_OWNER','attempts':59,'publications':59,
  'priorControlledGrantAttempts':69,'controlledCumulativeGrantAttempts':128,
  'expiredSessionCumulativeCeiling':197,'remainingCapacityUnderExpiredCeiling':69,
  'remainingCapacityAutomaticallyUsable':False,'tokenRenewalAuthorized':False,
  'humanSessionCumulativeBudgetProven':False,'legacyHistoryComplete':False,'budgetReset':False}}

def write_new(path,raw):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  with os.fdopen(os.dup(fd),'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
 finally:os.close(fd)

def prepare(directory,artifact,reader,custody,engine_info):
 output=Path(directory);require(output.is_dir()and not list(output.iterdir()),'EMPTY_PRIVATE_CANDIDATE_REQUIRED')
 write_new(output/'candidate.zip',artifact)
 with zipfile.ZipFile(output/'candidate.zip')as z:
  validate_zip(z);(output/'package').mkdir(mode=0o700)
  for name in sorted(MEMBERS):write_new(output/name,z.read(name))
 rec,continuity=package_records(output,reader.EXPECTED_MIGRATIONS)
 observed=reader.observe(report=False)
 retained=retained_context(reader)
 require(retained['parentRuntimeBinding']==observed['runtimeBinding'],'PARENT_REVIEW_RUNTIME_DRIFT')
 remaining=180-(time.monotonic()-STARTED);require(remaining>0,'PREPARATION_DEADLINE_EXHAUSTED');signal.alarm(max(1,int(remaining)))
 profile=reader.read(PROFILE['path'],131072,PROFILE['sha256']);policy=reader.read(POLICY['path'],131072,POLICY['sha256'])
 info=engine_info(observed['prepared']['engine'])
 require(type(info)is dict and type(info.get('DriverStatus')or[])is list,'NATIVE_IMAGE_STORE_PROFILE_REQUIRED')
 status=dict(info.get('DriverStatus')or[])
 containerd=info.get('Driver')=='overlayfs'and status.get('driver-type')=='io.containerd.snapshotter.v1'
 classic=info.get('Driver')=='overlay2'and status.get('driver-type')!='io.containerd.snapshotter.v1'
 require(containerd or classic,'QUALIFIED_NATIVE_IMAGE_STORE_REQUIRED')
 with (output/'package/image.docker.tar').open('rb')as src:
  audit=custody.archive(src,TAR_SHA,IMAGE_SHA,SOURCE)
  with (output/'candidate.tagless.tar').open('x+b')as dest:
   os.chmod(dest.name,0o600);derivation=custody.tagless_archive(src,dest,audit,containerd=containerd);dest.flush();os.fsync(dest.fileno())
 with (output/'candidate.tagless.tar').open('rb')as src:audit=custody.archive(src,derivation['derivedArchiveSha256'],IMAGE_SHA,SOURCE)
 require(not audit['repositoryTags'],'TAGLESS_CANDIDATE_REQUIRED')
 if containerd:audit['nativeIdentity']=custody.native_identity(audit)
 plan=compile_plan(observed,reader,audit,rec,continuity,output,profile,policy)
 plan['predecessorPrivateReview']=PARENT_REVIEW
 plan['retainedTokenWorker']=retained['workerEvidence']
 plan['migrationContract']={'command':'migrate-semantic-reprocessing','singleDatabaseTransaction':True,
  'grantDdlChecksumRevokeAtomic':True,'committedMembershipAllowed':False,
  'sourceCommit':SOURCE,'qualifiedRun':38937982021,'ambiguousCommitRequiresReadback':True}
 plan['executorQualification']={'sourceCommit':'d2e91c5c75ab2df52127836c201647c845063db8',
  'run':38941859703,'signedFixtureTests':11,'nativeStages':16,
  'replacementProcess':'SYNTHETIC_BUSYBOX_HTTP_204','productionEntrypointProven':False,
  'realMcpBootstrapProven':False,'targetDeploymentProven':False}
 plan['imageImport']['nativeImageId']=custody.runtime_image_id(audit)
 plan['nativeImageStore']={k:info.get(k)for k in('ServerVersion','Driver','DriverStatus','CgroupDriver')}
 plan['sourceClosure']={'preparerSha256':sha(Path(__file__).read_bytes()),'readerSha256':READER_SHA,'custodySha256':CUSTODY_SHA}
 write_new(output/'review.json',raw_json(plan))
 return plan

STARTED=time.monotonic()
def main():
 require(os.geteuid()==0 and sys.flags.isolated and len(sys.argv)==4,'ROOT_ISOLATED_PREPARATION_REQUIRED');signal.alarm(180);os.umask(0o077)
 emit('BEGIN',maximumSeconds=180,maximumEngineReads=5,maximumSqlSessions=1,credentialFilesRead=0,
  existingConfigurationWrites=0,serviceMutations=0,databaseMutations=0,grantRequests=0,privateKeysRead=0)
 reader=dependency(Path(sys.argv[2]).resolve(),READER_SHA,'sealed_preflight')
 custody=dependency(Path(sys.argv[3]).resolve(),CUSTODY_SHA,'sealed_image_custody')
 artifact=bounded_input(Path(sys.argv[1]).resolve(),ZIP_SHA,20000000)
 parent=reader.CONTEXT.parent
 for ancestor in(parent,*parent.parents):
  s=ancestor.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and not s.st_mode&0o022,'ROOT_REVIEW_ANCESTRY_REQUIRED')
 output=Path(tempfile.mkdtemp(prefix='semantic-mcp-atomic-update-review-',dir=parent))
 # GET /info is the only additional Engine observation; no POST/exec/import.
 def info(engine):
  return reader.engine_info(engine)
 plan=prepare(output,artifact,reader,custody,info)
 emit('END',complete=True,reviewPath=str(output/'review.json'),reviewSha256=digest(plan),
  candidateNativeImageId=plan['imageImport']['nativeImageId'],
  predecessorReviewSha256=PARENT_REVIEW['sha256'],controlledCumulativeGrantAttempts=128,
  humanSessionCumulativeBudgetProven=False,readyForExecution=False,runtimeAuthorityIssued=False,
  humanApprovalGranted=False,credentialFilesRead=0,privateKeysRead=0,grantRequests=0,serviceMutations=0,databaseMutations=0,
  completedTechnicalPhases=8,functionalMilestonesProven=0,temporaryMembershipGranted=False,existingConfigurationWrites=0)
if __name__=='__main__':
 try:main()
 except Exception as error:
  reason=str(error)if type(error)is PreparationDenied else type(error).__name__
  emit('STOP',reason=reason if re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,100}',reason)else'UNCLASSIFIED',
   exceptionMessagePrinted=False,runtimeAuthorityIssued=False)
  sys.exit(2)
