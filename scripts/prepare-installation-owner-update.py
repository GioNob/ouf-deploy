"""Retained-host213 preparation: preserve completed209, audit one new Onboarding image; no apply/login."""
import ast,base64,gzip,hashlib,io,json,os,re,signal,stat,sys,tarfile,tempfile,time,zipfile
from pathlib import Path,PurePosixPath
COMPLETED=Path('/etc/ouf/deploy-snapshots/installation-ingestion-binding-execution-ofjxmhff')
PLAN_HASH='6bebb5d19b337d4156bd63be78e4068c7117ecec3f3199ef142046cb20d695e9'
SOURCE='b0f5e3dacbe59ebf87e22dd6af2575e41249f51d'
OLD_SOURCE='be388e1462778438a208c2e00e166370fee32189'
STAGE=Path('/home/oufadmin/ouf-deploy-runner/_work/ouf-deploy/ouf-installation-owner-39266502171')
MANIFEST='174c354c604d02267a2c3172ca2c06a2af1f15075c5abcb1a8034769bcdc3fc0'
IMAGE='sha256:4790f4e8739282c33a8b5151e2f6c080a0db3284d226934160105538068a9035'
MIGRATIONS={'src/main/resources/db/migration/V10__runtime_projection_schema_surveillance.sql': 'd340ba46341f1afcb203908a91c2146b5379b980', 'src/main/resources/db/migration/V11__trusted_human_protected_operations.sql': '5e85b30cd75bb5dcea7c97c0e51849cc8a7f1255', 'src/main/resources/db/migration/V12__semantic_gap_workflow.sql': 'b6e6f4fc770a634ae457f7b987cb811a2c308464', 'src/main/resources/db/migration/V13__managed_file_quarantine.sql': '0d6c4203612fbb52f8bdb1e94cddaead6eefda1b', 'src/main/resources/db/migration/V14__schema_mapping_governance.sql': '27c87d093f2fd83b6df65598150e642d203c88b6', 'src/main/resources/db/migration/V15__authorization_policy_registry.sql': 'e25b2409050418ec00099ad539fcb00de9570f61', 'src/main/resources/db/migration/V16__authorization_admin_lifecycle.sql': '73366c05f99482cca1be652a99d904dbce5d775d', 'src/main/resources/db/migration/V17__geopackage_profiles.sql': '6770c43d096fdb2f3eaee0b78ef426f43cbf5679', 'src/main/resources/db/migration/V18__access_profiles.sql': 'fff44792dc9a1e295d87a2380c5350c9795741d5', 'src/main/resources/db/migration/V19__access_semantic_proposals.sql': '2f0999a657a919afcacd2d15372c42a75ea33e97', 'src/main/resources/db/migration/V1__onboarding_core.sql': '168b129896d0dcd5725197aae71698206b0213a3', 'src/main/resources/db/migration/V20__authorization_bootstrap_latch.sql': 'cd04ed35fab0f36cabc338f1eca6954ad56e15a3', 'src/main/resources/db/migration/V21__installation_configuration_lifecycle.sql': 'd1b1535b56046e8165b4b9cef561a9ccb8e4f260', 'src/main/resources/db/migration/V22__installation_environment_validation.sql': 'f3f2d6a08c9191b802f1844202b4dfad9eb9fcf5', 'src/main/resources/db/migration/V23__installation_projection_export_audit.sql': '52c4f1cc866695e1d80ea4d7e70463b476c4d273', 'src/main/resources/db/migration/V24__installation_environment_validation_correlation.sql': '0520bd2b20a182f1a9083a779311f2b4c2b2627e', 'src/main/resources/db/migration/V25__candidate_installation_projection_export.sql': 'e4abfd9f482ecdbfddfb2af609cceecfee43d362', 'src/main/resources/db/migration/V26__protected_superadmin_role.sql': 'b90638b45822813f69ce1758cf025a3ade360f31', 'src/main/resources/db/migration/V27__authorization_permission_proposals.sql': '73fc1571dd60c2fbb952d4f3b561ee688517416d', 'src/main/resources/db/migration/V28__nominal_superadmin.sql': '11c4f9e7c14944857622ed7af99853a1d614c16d', 'src/main/resources/db/migration/V29__ouf_role_catalogue.sql': 'bc254ff38407450a8338ce0cfa4a0ae70196d67d', 'src/main/resources/db/migration/V2__validation_engine.sql': '1e92cb36bfb1002d7062e8674aaa6235a061bb0d', 'src/main/resources/db/migration/V30__managed_file_onboarding_idempotency.sql': 'ab94663abb455a66e348b9d2148c3c7d9b2a381e', 'src/main/resources/db/migration/V31__managed_file_upload_idempotency.sql': '6cc231d30f709b464353d6c7428d2c693ddb1d0e', 'src/main/resources/db/migration/V32__managed_onboarding_review_handoff.sql': 'b0555213ae6bf72d0814f2dfd64816c62b88713d', 'src/main/resources/db/migration/V33__managed_review_activation_progress.sql': '0f07b0c5905d2ca211e34ca56cb29bffba859935', 'src/main/resources/db/migration/V34__source_property_revision.sql': 'a6ee2ca93ae6b271e770e133e08da557bb379a09', 'src/main/resources/db/migration/V3__technical_discovery.sql': '19f147178cd149a2ed7241df4d4f614a8d6438ea', 'src/main/resources/db/migration/V4__mapping_workspace.sql': '5bd8c7b937e12030a3c3ffdc007059cedff77a2f', 'src/main/resources/db/migration/V5__managed_file_profiles.sql': '6862db82411d06306260166442925ccbea50cab8', 'src/main/resources/db/migration/V6__initial_ingestion_and_pull_scheduler.sql': 'b25b216ab1a257edd327c4ceb77b123843190c80', 'src/main/resources/db/migration/V7__restore_onboarding_boundary.sql': '6e599f823604843409099498197120963101a738', 'src/main/resources/db/migration/V8__managed_file_preview.sql': '8fc9833897c3c88e5d7c39012d81e3a9388d5e40', 'src/main/resources/db/migration/V9__managed_file_contract_hardening.sql': '13cdba365197ee82c520ce74f1a294d9375dc181'}

def require(ok,code):
 if not ok:raise ValueError(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(v):return hashlib.sha256(v).hexdigest()
def digest(v):return sha(encoded(v))
def read(path,expected=None,maximum=8388608):
 path=Path(path);require(path.is_absolute()and path.resolve()==path,'EXACT_PRIVATE_PATH_REQUIRED')
 for parent in path.parents:
  st=parent.lstat();require(stat.S_ISDIR(st.st_mode)and st.st_uid==0 and not st.st_mode&0o022,'PRIVATE_ROOT_ANCESTRY_REQUIRED')
 return file_bytes(path,expected,maximum,private=True)
def file_bytes(path,expected,maximum,private=False):
 path=Path(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  st=os.fstat(fd);require(stat.S_ISREG(st.st_mode)and st.st_nlink==1 and 0<st.st_size<=maximum
   and(not private or st.st_uid==st.st_gid==0 and stat.S_IMODE(st.st_mode)==0o600),'BOUNDED_CUSTODIED_MEMBER_REQUIRED')
  with os.fdopen(os.dup(fd),'rb')as f:raw=f.read(maximum+1)
  pin=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  require(len(raw)==st.st_size and pin(st)==pin(os.fstat(fd))==pin(path.lstat())and(expected is None or sha(raw)==expected),'EXACT_MEMBER_BYTES_CHANGED');return raw
 finally:os.close(fd)
def parsed(path,expected=None,maximum=8388608):return json.loads(read(path,expected,maximum))
def write_new(path,raw):
 path=Path(path);fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  with os.fdopen(os.dup(fd),'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
 finally:os.close(fd)
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def copy_archive(source,target,wanted):
 fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  before=os.fstat(fd);require(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<before.st_size<=1200000000,'BOUNDED_ARCHIVE_REQUIRED')
  out=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);h=hashlib.sha256();count=0
  try:
   with os.fdopen(os.dup(fd),'rb')as inp,os.fdopen(os.dup(out),'wb')as stream:
    for raw in iter(lambda:inp.read(1048576),b''):
     count+=len(raw);require(count<=1200000000,'ARCHIVE_COPY_LIMIT');h.update(raw);stream.write(raw)
    stream.flush();os.fsync(stream.fileno())
  finally:os.close(out)
  pin=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  require(count==before.st_size and pin(before)==pin(os.fstat(fd))==pin(Path(source).lstat())and h.hexdigest()==wanted,'CANDIDATE_ARCHIVE_CHANGED')
 finally:os.close(fd)

def completed():
 plan=parsed(COMPLETED/'installation-plan.json',PLAN_HASH);package=parsed(COMPLETED/'package.json');package_hash=digest(package)
 require(package['sourceCommit']=='7e0eddca54df18b3b01f5059b19feea50b7b645b'
  and package['closure']['declaration']['moduleCount']==209 and package['closure']['declaration']['entryModule']=='tools.installation_binding_plan.entry'
  and package['declarationHash']==digest(package['closure']['declaration'])
  and plan['bindings']['sourceClosureHash']==digest(package['closure']),'EXACT_COMPLETED209_PLAN_CLOSURE_REQUIRED')
 require(parsed(COMPLETED/'runtime.claim.json')=={'packageHash':package_hash,'automaticReplayAllowed':False},'COMPLETED209_RUNTIME_CLAIM_REQUIRED')
 require(set(package['fileHashes'])=={'case.json','bootstrap.py','runtime.py','reader.py','sources.json'},'EXACT_COMPLETED209_FIVE_MEMBERS_REQUIRED')
 for name,wanted in package['fileHashes'].items():
  require(Path(name).name==name,'SAFE_COMPLETED_MEMBER_REQUIRED');read(COMPLETED/name,wanted)
 require(sha(read(COMPLETED/'runtime.py'))==package['closure']['declaration']['loaderHash'],'COMPLETED209_LOADER_CHANGED')
 case=parsed(COMPLETED/'case.json',package['fileHashes']['case.json']);report=parsed(COMPLETED/'planning-result.json');login=parsed(COMPLETED/'login-window-receipt.json')
 require(report['schema']=='ouf.installation-ingestion-binding-planning-result.v1'and report['complete']is True
  and report['planHash']==PLAN_HASH and report['contextPath']==str(COMPLETED)and report['expectedActiveRevision']==5
  and report['sourcePayloadChecksum']=='e9bea44bf977b17c94d9a9d1a1f2f2ddfff188360df3dbe11d20ee31460298b4'
  and report['candidatePayloadChecksum']=='ded675196fa5b7f9c398b249f737ff19df26d66e81afa65ddcf9a5ecfb034a98'
  and report['oauthAttemptsAfter']==243 and report['ownerApplyAuthorized']is False
  and report['ownerMutationRequests']==report['activeProjectionWrites']==report['projectionExports']==report['gatewayWrites']==0
  and report['budgetReset']is False and report['automaticReplayAllowed']is False
  and plan['ownerApplyAuthorized']is False and plan['installationActivationAllowed']is False
  and plan['gatewayWritesAllowed']is False and plan['atomicOwnerActivePreconditionSupportProven']is False,
  'EXACT_COMPLETED_PLAN_ONLY243_RESULT_REQUIRED')
 binding=plan['bindings']['humanBinding']
 require(login['schema']=='ouf.installation-binding-scope-login-receipt.v1'and login['reviewHash']=='2f973bf92defd736e313861b0efafbb0a0d0fb6a7c17bd536f4b71d97d256c71'
  and login['directory']==binding['sessionDirectory']and login['expiresAt']==binding['expiresAt']==1792425259
  and login['oauthAttemptsAfter']==243 and login['priorOAuthAttempts']==236 and login['maximumCumulativeOAuthAttempts']==256
  and login['requestedInstallationScopeCount']==4 and login['oldRefreshReplayed']is False and login['budgetReset']is False,
  'EXACT_COMPLETED_INSTALLATION_SCOPE_LOGIN_REQUIRED')
 row=parsed(Path(binding['sessionDirectory'])/'recovery.json',maximum=65536)
 require(row['binding']==binding and row['state']=='READY'and type(row['attempts'])is int and 243<=row['attempts']<=252
  and row['budgetReset']is False and time.time()>=row['lastObservedAt']and time.time()+1200<binding['expiresAt']
  and not os.path.lexists(Path(binding['sessionDirectory'])/'successor-window.claim.json'),'CURRENT_EXISTING_HUMAN_BUDGET_WINDOW_OR_STATE_UNAVAILABLE')
 sources=parsed(COMPLETED/'sources.json',package['fileHashes']['sources.json']);sources={n:base64.b64decode(v,validate=True)for n,v in sources.items()}
 hashes=package['closure']['declaration']['sourceHashes'];require(len(sources)==209 and set(sources)==set(hashes)and all(sha(raw)==hashes[n]for n,raw in sources.items()),'COMPLETED209_SOURCE_HASH_DRIFT')
 return package,case,plan,report,row,sources

def migration_proof(jar,inventory,image_jar_hash):
 require(sha(jar)==image_jar_hash,'EXPORTED_JAR_AND_IMAGE_JAR_DIFFER')
 actual={x['path']:x['sha']for x in inventory['tree']if x['path'].startswith('src/main/resources/db/migration/')}
 require(inventory['truncated']is False and actual==MIGRATIONS and 0<len(actual)<=256,'CANDIDATE_MIGRATIONS_DIFFER_FROM_INSTALLED_SOURCE')
 with zipfile.ZipFile(io.BytesIO(jar))as archive:
  items=archive.infolist();require(len(items)<=20000 and len({v.filename for v in items})==len(items),'UNIQUE_BOUNDED_JAR_MEMBERS_REQUIRED')
  selected={v.filename:v for v in items if v.filename.startswith('BOOT-INF/classes/db/migration/')and not v.is_dir()}
  require(set(selected)=={'BOOT-INF/classes/'+p.removeprefix('src/main/resources/')for p in MIGRATIONS},'EXACT_INSTALLED_MIGRATION_SET_REQUIRED')
  for path,wanted in MIGRATIONS.items():
   member=selected['BOOT-INF/classes/'+path.removeprefix('src/main/resources/')]
   require(0<member.file_size<=1048576 and member.flag_bits&1==0,'BOUNDED_UNENCRYPTED_MIGRATION_REQUIRED')
   raw=archive.read(member);require(hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==wanted,'CANDIDATE_JAR_MIGRATION_BYTES_CHANGED')
 return {'schema':'ouf.installation-owner-unchanged-migrations.v1','sourceCommit':SOURCE,'installedSourceCommit':OLD_SOURCE,
  'migrationFilesUnchanged':True,'migrationFileCount':len(MIGRATIONS),'migrationSourceSetHash':digest(MIGRATIONS),
  'imageJarBound':True,'imageJarSha256':image_jar_hash,'databaseMigrationsAllowed':False}

def image_jar_hash(path,audit):
 found=None;count=0
 with tarfile.open(path,mode='r:')as outer:
  for layer in audit['layerMembers']:
   member=outer.getmember(layer)
   with outer.extractfile(member)as stream,tarfile.open(fileobj=stream,mode='r|*')as inner:
    for item in inner:
     count+=1;require(count<=250000,'BOUNDED_IMAGE_LAYER_ENTRIES_REQUIRED')
     name=item.name.removeprefix('./').rstrip('/');parts=PurePosixPath(name).parts
     require(not name.startswith('/')and '..'not in parts,'SAFE_LAYER_PATH_REQUIRED')
     if name in('app/.wh.application.jar','app/.wh..wh..opq','.wh.app','.wh..wh..opq'):found=None
     if name=='app':require(item.isdir(),'REGULAR_APPLICATION_DIRECTORY_REQUIRED')
     if name=='app/application.jar':
      require(item.isfile()and 0<item.size<=268435456,'REGULAR_BOUNDED_IMAGE_JAR_REQUIRED')
      with inner.extractfile(item)as f:
       h=hashlib.sha256();size=0
       for raw in iter(lambda:f.read(1048576),b''):size+=len(raw);require(size<=268435456,'BOUNDED_IMAGE_JAR_REQUIRED');h.update(raw)
      require(size==item.size,'COMPLETE_IMAGE_JAR_REQUIRED');found=h.hexdigest()
 require(found is not None,'AUTHORITATIVE_IMAGE_JAR_NOT_FOUND');return found

def main(delivery,commit):
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_REQUIRED')
 require(set(delivery)=={'prepare','entry','authority','owner','native','runtime','bootstrap'}and re.fullmatch('[0-9a-f]{40}',commit),'EXACT_ONBOARDING_UPDATE_DELIVERY_REQUIRED')
 os.umask(0o077);signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('FINITE_OWNER_PREPARATION_DEADLINE')));signal.alarm(300)
 print('OUF_MCP_INGESTION_PHASE=VERIFY_COMPLETED_INSTALLATION_PLAN_AS_FILES',flush=True)
 package,case,plan,result,row,sources=completed()
 for name in('entry','authority','owner','native'):sources['tools.installation_owner_update.'+name]=delivery[name]
 memory={'__name__':'qualified213_loader'};exec(compile(delivery['runtime'],'<qualified213-loader>','exec'),memory)
 compiled=memory['compile_sources'](sources);require(len(sources)==213,'EXACT213_SOURCE_CLOSURE_REQUIRED')
 finder=memory['MemoryLoader'](compiled,sources);sys.meta_path.insert(0,finder)
 import image_custody
 from engine_creation import Engine
 manifest=json.loads(file_bytes(STAGE/'qualified-package.json',MANIFEST,8388608))
 require(manifest['schema']=='ouf.installation-owner-staged-package.v1'and manifest['sourceCommit']==SOURCE
  and manifest['runtimeAuthorityIssued']is False and manifest['targetApplyAuthorized']is False,'EXACT_AUTHENTICATED_ONBOARDING_STAGE_REQUIRED')
 candidate=json.loads(file_bytes(STAGE/'candidate-manifest.json',manifest['files']['candidate-manifest.json'],8388608))
 require(candidate==manifest['candidateManifest']and candidate['sourceCommit']==SOURCE and candidate['module']=='onboarding'
  and candidate['imageId']==IMAGE and candidate['scanGate']=='PASS_HIGH_CRITICAL_UNKNOWN_INCLUDING_UNFIXED','EXACT_SCANNED_ONBOARDING_CANDIDATE_REQUIRED')
 for name in('package-record.json','trivy-image.json','Dockerfile.resolved','SHA256SUMS'):file_bytes(STAGE/name,manifest['files'][name],8388608)
 inventory=json.loads(file_bytes(STAGE/'source-inventory.json',manifest['files']['source-inventory.json'],8388608))
 logical=digest({'oldContainerId':'3197c8d5ae9acc00a2e99d54bc969db1d199623960b5efed09c891ba0a3138c8','candidateSourceCommit':SOURCE,
  'candidateImageId':IMAGE,'profile':'ouf.installation-binding-owner-update.v1'})
 parent=COMPLETED.parent;require(not os.path.lexists(parent/('installation-owner-preparation-'+logical+'.claim.json')),'OWNER_UPDATE_ALREADY_PREPARED_NO_REPLAY')
 destination=Path(tempfile.mkdtemp(prefix='installation-owner-update-execution-',dir=parent))
 claim={'context':str(destination),'candidateSourceCommit':SOURCE,'completedInstallationPlanHash':PLAN_HASH,'sourceCommit':commit,
  'priorOAuthAttempts':row['attempts'],'maximumCumulativeOAuthAttempts':256,'budgetReset':False,'automaticReplayAllowed':False}
 claim_path=parent/('installation-owner-preparation-'+logical+'.claim.json');write_new(claim_path,encoded(claim))
 print('OUF_MCP_INGESTION_PHASE=COPY_AUDIT_ONBOARDING_IMAGE_AND_UNCHANGED_MIGRATIONS',flush=True)
 copy_archive(STAGE/'image.docker.tar',destination/'original-image.docker.tar',manifest['files']['image.docker.tar'])
 with(destination/'original-image.docker.tar').open('rb')as f:audit=image_custody.archive(f,manifest['files']['image.docker.tar'],IMAGE,SOURCE)
 jar=file_bytes(STAGE/'application.jar',manifest['files']['application.jar'],268435456)
 proof=migration_proof(jar,inventory,image_jar_hash(destination/'original-image.docker.tar',audit));write_new(destination/'migration-evidence.json',encoded(proof))
 old=parsed(case['installedPlanBinding']['path'],case['installedPlanBinding']['sha256'])
 engine=Engine(old['engine']['socketPath'],tuple(old['engine']['socketBinding']));status,info=engine.request('GET','/v1.44/info');require(status==200,'RETAINED_ENGINE_INFO_REQUIRED')
 containerd=any(k=='driver-type'and v=='io.containerd.snapshotter.v1'for k,v in(info.get('DriverStatus')or[]))
 require(containerd==('nativeIdentity'in old['replacements']['onboarding']['imageAudit']),'RETAINED_IMAGE_STORE_PROFILE_CHANGED')
 with(destination/'original-image.docker.tar').open('rb')as inp:
  fd=os.open(destination/'candidate-image.docker.tar',os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'w+b')as output:derived=image_custody.tagless_archive(inp,output,audit,containerd=containerd);os.fsync(output.fileno())
 with(destination/'candidate-image.docker.tar').open('rb')as f:audited=image_custody.archive(f,derived['derivedArchiveSha256'],IMAGE,SOURCE)
 if containerd:audited['nativeIdentity']=image_custody.native_identity(audited)
 image={'imageAudit':audited,'imageArchive':{'path':str(destination/'candidate-image.docker.tar'),'sha256':derived['derivedArchiveSha256']}}
 write_new(destination/'image-custody.json',encoded(image));write_new(destination/'candidate-provenance.json',encoded({'manifest':manifest,'derivedArchive':derived}))
 case={**case,'humanBinding':plan['bindings']['humanBinding'],'priorOAuthAttempts':row['attempts'],
  'completedInstallationPlanBinding':{'path':str(COMPLETED/'installation-plan.json'),'sha256':PLAN_HASH},
  'imageBinding':{'path':str(destination/'image-custody.json'),'sha256':digest(image)},
  'candidateMigrationEvidenceBinding':{'path':str(destination/'migration-evidence.json'),'sha256':digest(proof)},
  'preparationClaimBinding':{'path':str(claim_path),'sha256':digest(claim)}}
 members={'case.json':encoded(case),'bootstrap.py':delivery['bootstrap'],'runtime.py':delivery['runtime'],
  'reader.py':read(COMPLETED/'reader.py',package['fileHashes']['reader.py']),
  'sources.json':encoded({n:base64.b64encode(v).decode()for n,v in sorted(sources.items())})}
 pins={**package['sourcePins'],'ouf-deploy':commit,'ouf-onboarding':SOURCE};execution={'executorSha256':sha(delivery['bootstrap']),'caseSha256':digest(case),'mode':'INSTALLATION_OWNER_UPDATE'}
 declaration=memory['declaration'](commit,sources,delivery['runtime'],pins,execution);closure={**package['closure'],'declaration':declaration}
 fresh={'schema':'ouf.mcp-ingestion-read-transport-package.v1','sourceCommit':commit,'sourcePins':pins,'executionPins':execution,
  'closure':closure,'declarationHash':digest(declaration),'fileHashes':{n:sha(raw)for n,raw in members.items()},'runtimeAuthorityIssued':False}
 for name,raw in members.items():write_new(destination/name,raw)
 write_new(destination/'package.json',encoded(fresh))
 report={'schema':'ouf.installation-owner-update-preparation.v1','contextPath':str(destination),'sourceCommit':commit,'candidateSourceCommit':SOURCE,
  'packageHash':digest(fresh),'sourceClosureHash':digest(closure),'candidateImageId':image_custody.runtime_image_id(audited),'migrationEvidenceHash':digest(proof),
  'sourceModuleCount':213,'priorOAuthAttempts':row['attempts'],'maximumCumulativeOAuthAttempts':256,'humanWindowExpiresAt':row['binding']['expiresAt'],
  'runtimeAuthorityIssued':False,'newHumanLoginAllowed':False,'budgetReset':False,'automaticReplayAllowed':False,
  'completedInstallationReadbackReplayed':False,'completedMcpReadbackReplayed':False,'completedInstallationPlanReplayed':False,
  'imageRebuilt':False,'installationBindingApplied':False,'databaseMigrationsPerformed':0,'gatewayWrites':0,
  'completedTechnicalPhases':8,'functionalMilestonesProven':4}
 write_new(destination/'preparation-result.json',encoded(report));print('OUF_INSTALLATION_OWNER_PREPARED='+encoded(report).decode(),flush=True)
 signal.alarm(0);os.execv(sys.executable,[sys.executable,'-I','-B','-S',str(destination/'bootstrap.py'),str(destination),digest(fresh)])
