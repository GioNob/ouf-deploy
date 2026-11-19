"""Exact generation31 additive current view; historical qualification is immutable.

Checks current hosted image, cohort and runtime bytes before exposing generation31.
All preceding plan fields and qualification history remain canonically immutable.
"""
from __future__ import annotations
import copy,hashlib,io,json,zipfile
from pathlib import Path,PurePosixPath
BASE_PLAN_CANONICAL_SHA='7671b526b3c2ba6d0d32a7b49af690bb24157917c3b908bf5502ad0a58e986ea'
PLAN_PATH='releases/minio-seaweedfs-plan-20261102.json'
LOCK_PATH='releases/seaweedfs-452-generation31-candidate-lock-20261103.json'
LOCK_SHA='19cd03cccee7c6cc2f54f8665e48f5541b9594789ed84442c387616629041eba'
IMAGE_PATH='evidence/seaweedfs-452-generation31-image-hosted-20261103.json'
IMAGE_SHA='428dd1bd4f083d0160dd98ca2862dd1f3ef09de055f39d7be9dd30dd6f59cbc0'
MANIFEST_PATH='releases/seaweedfs-452-generation31-build-manifest-20261103.json'
MANIFEST_SHA='9a2a00893a07a33e432ac35f6d06da79fd27181ebf16d2fbc4b45f5f9e697719'
COHORT_PATH='evidence/seaweedfs-452-generation31-cohort-hosted-20261103.json'
RUNTIME_PATH='evidence/seaweedfs-generation31-runtime-hosted-20261103.json'
COHORT_SHA='a092a73c1a2e1ba20375bbc9a40d9d1a510a03abfe3eb91d7a2bd5c2d04d2d38'
RUNTIME_SHA='ff19d07d485e287492593f8439e426b293be8dc2669ba064e93dff9d0b60b0a3'
BINARY_SHA='5b7e3dcf61d6b3b7b2b44135dd0db980e43e3d96e5e7e87210c543f790448b02'

def require(ok,reason):
    if not ok:raise ValueError(reason)
def sha(b):return hashlib.sha256(b).hexdigest()
def canonical(v):return (json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False)+'\n').encode()
def read_bound(root,path,expected,maximum=64*1024*1024):
    require(isinstance(expected,str) and len(expected)==64,'ACTUAL31_HOSTED_PIN_REQUIRED')
    rel=PurePosixPath(path);require(not rel.is_absolute() and all(p not in ('','.','..') for p in rel.parts),'BOUND31_SAFE_PATH_REQUIRED')
    p=root/path;require(p.is_file() and not p.is_symlink() and p.resolve().is_relative_to(root.resolve()),'BOUND31_REGULAR_FILE_REQUIRED')
    data=p.read_bytes();require(len(data)<=maximum and sha(data)==expected,'BOUND31_FILE_BYTES_CHANGED:'+path);return data

def restore_generation29_plan(plan):
    require(plan['currentQualification']['generation']==31,'EXACT_GENERATION31_VIEW_REQUIRED')
    require(plan['generation29Qualification']=={'status':'HISTORICAL_HOSTED_IMAGE_COHORT_RUNTIME_PASS_NOT_ADMITTED','historicalQualificationField':'historicalQualification29','oldRuntimeEvidenceTransferred':False},'HISTORICAL29_ALIAS_REQUIRED')
    require(plan['generation31Qualification']=={'status':'HOSTED_IMAGE_COHORT_RUNTIME_PASS_NOT_ADMITTED','currentQualificationField':'currentQualification','oldRuntimeEvidenceTransferred':False},'CURRENT31_ALIAS_REQUIRED')
    require(plan['nextGenerationPrototype']=={'status':'IN_DEVELOPMENT_NOT_QUALIFIED','qualifiedGenerationRetained':31,'progressCreditAdded':0,'runtimeProofTransferred':False},'NEXT_PROTOTYPE_NOT_QUALIFIED_REQUIRED')
    restored=copy.deepcopy(plan)
    restored['currentQualification']=restored.pop('historicalQualification29')
    restored['generation29Qualification']=restored.pop('historicalGeneration29QualificationAlias')
    restored['nextGenerationPrototype']=restored.pop('historicalNextGenerationPrototypeBefore31')
    del restored['generation31Qualification']
    require(sha(canonical(restored))==BASE_PLAN_CANONICAL_SHA,'ALL_PRE31_PLAN_HISTORY_AND_PROGRESS_IMMUTABLE')
    return restored

def bounded_zip(data, *, metadata_only=False):
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        names=z.namelist();require(names and len(names)==len(set(names)) and len(names)<=128,'BOUND31_ZIP_MEMBER_SET_REQUIRED')
        require(sum(i.file_size for i in z.infolist())<=64*1024*1024,'BOUND31_ZIP_SIZE_REQUIRED')
        require(all('/' not in n and '\\' not in n and n not in ('.','..') for n in names),'BOUND31_FLAT_ARCHIVE_REQUIRED')
        members={n:z.read(n) for n in names}
    sums={}
    for line in members['SHA256SUMS'].decode().splitlines():
        digest,name=line.split('  ',1);name=name.removeprefix('./')
        require(name not in sums,'BOUND31_ZIP_DUPLICATE_CHECKSUM')
        if name in members:require(digest==sha(members[name]),'BOUND31_ZIP_CHECKSUM_CHANGED')
        else:require(metadata_only,'BOUND31_ZIP_MEMBER_MISSING')
        sums[name]=digest
    if not metadata_only:require(set(sums)==set(members)-{'SHA256SUMS','provenance.json'},'BOUND31_COMPLETE_ARCHIVE_CHECKSUMS_REQUIRED')
    return members

def validate_image31(root):
    lb=read_bound(root,LOCK_PATH,LOCK_SHA);ab=read_bound(root,IMAGE_PATH,IMAGE_SHA);mb=read_bound(root,MANIFEST_PATH,MANIFEST_SHA)
    lock,image,manifest=map(json.loads,[lb,ab,mb])
    require(lock['generation']==image['generation']==manifest['generation']==31,'EXACT31_GENERATION_REQUIRED')
    require(lock['orderedPatchCount']==len(manifest['orderedPatches'])==31,'EXACT31_PATCH_SEQUENCE_REQUIRED')
    for p in manifest['orderedPatches']:read_bound(root,p['path'],p['sha256'])
    require(lock['buildProfile']['binarySha256']==manifest['build']['binarySha256']==image['byteReadback']['binarySha256']==BINARY_SHA,'EXACT31_BINARY_REQUIRED')
    require(lock['buildProfile']['binaryModuleRows']==234 and lock['buildProfile']['compiledPackages']==1740,'EXACT31_COMPILED_INVENTORY_REQUIRED')
    require(image['candidateLockSha256']==LOCK_SHA and image['buildManifestSha256']==MANIFEST_SHA,'EXACT31_RECEIPT_LOCK_MANIFEST_BINDING_REQUIRED')
    require(image['status']=='HOSTED_PASS_BYTES_REVERIFIED_NOT_ADMITTED' and len(image['jobs'])==4 and all(j['conclusion']=='success' for j in image['jobs']),'ACTUAL31_IMAGE_JOBS_PASS_REQUIRED')
    require(image['runId']==lock['qualification']['runId']==41712811559 and image['producerCommit']==lock['producerCommit']=='5d0d456bec5073192b8a1a86e35bb0dcbd97a6b5','EXACT31_PRODUCER_REQUIRED')
    require(image['rawSeverityCounts']==dict.fromkeys(('CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'),0) and image['scanAndSpdxInventoriesMatchBinary'] and image['scannedBinaryComponents']==236 and image['spdxRecords']==238,'EXACT31_FRESH_SCAN_INVENTORY_REQUIRED')
    require(image['publisherSignatureVerifiedByHostedReader'] is True and image['localCryptographicSignatureVerificationClaimed'] is False,'EXACT31_PROVENANCE_SCOPE_REQUIRED')
    for doc in (lock,image):
        require(doc['releaseAdmitted'] is False and doc['runtimeAuthorityIssued'] is False and doc['targetOperations']==0 and doc['dependencyMaintenance']=={'status':'OPEN','allDependenciesMaintained':False},'EXACT31_NO_AUTHORITY_OR_MAINTENANCE_CLOSURE')
    for path,item in image['preservedFiles'].items():
        data=read_bound(root,path,item['sha256']);require(len(data)==item['bytes'],'EXACT31_PRESERVED_IMAGE_SIZE_REQUIRED')
    archives={}
    for key in ('buildEvidenceArtifact','independentReadback'):
        item=image[key];data=read_bound(root,item['path'],item['digest'].removeprefix('sha256:'));require(len(data)==item['bytes'],'EXACT31_ARCHIVE_SIZE_REQUIRED');archives[key]=bounded_zip(data,metadata_only=(key=='independentReadback'))
    build=archives['buildEvidenceArtifact'];require(sha(build['production-deps.txt'])==lock['buildProfile']['compiledPackagesSha256'] and len(build['production-deps.txt'].decode().splitlines())==1740,'EXACT31_COMPILED_GRAPH_REQUIRED')
    require(build['kafka-tidy.diff']==build['tidy.diff']==b'' and build['remaining-direct-sdk-v1-importers.txt']==b'','EXACT31_TIDY_AND_SDK_CLOSURE_REQUIRED')
    for name,digest in image['buildEvidenceArtifact']['verification']['files'].items():require(sha(build[name])==digest,'EXACT31_BUILD_MEMBER_BINDING_REQUIRED')
    for doc in (image,lock):require(doc['modifiedMplSource']=={'archiveSha256':'2767531e9510840ba159cdbb9062633dad51d4d2b5984b7d57c1aabcb38d177e','manifestSha256':'0b65ee710cf88f9bd2b76c0918377f10b71c6225d8937732ae6871e875569d53'},'EXACT31_LOCAL_MPL_SOURCE_REQUIRED')
    modules={line.split()[1] for line in build['build-info.txt'].decode().splitlines() if line.strip().startswith('dep\t')}
    require(len(modules)==234,'EXACT31_BINARY_MODULE_COUNT_REQUIRED')
    removed={'github.com/boltdb/bolt','github.com/facebookgo/clock','github.com/facebookgo/stats','github.com/google/btree','github.com/mitchellh/mapstructure','github.com/rcrowley/go-metrics','github.com/armon/go-metrics','github.com/Shopify/sarama','github.com/aws/aws-sdk-go'}
    retained={'github.com/envoyproxy/protoc-gen-validate','github.com/mitchellh/colorstring','go.opencensus.io','gopkg.in/yaml.v3','go.mongodb.org/mongo-driver','github.com/GoogleCloudPlatform/opentelemetry-operations-go/detectors/gcp'}
    require(not modules.intersection(removed) and retained.issubset(modules),'EXACT31_LIFECYCLE_BINARY_SCOPE_REQUIRED')
    return lock,image,manifest,archives

def checksum_members(members, manifest='SHA256SUMS'):
    checks={}
    for line in members[manifest].decode('utf-8').splitlines():
        digest,name=line.split('  ',1);name=name.removeprefix('./')
        require(name not in checks and name in members,'EXACT31_CHECKSUM_MEMBER_REQUIRED')
        require(sha(members[name])==digest,'EXACT31_MEMBER_CHECKSUM_CHANGED')
        checks[name]=digest
    require(set(checks)==set(members)-{manifest},'EXACT31_CHECKSUM_CLOSURE_REQUIRED')
    return checks

def validate_cohort_runtime31(root,lock,image):
    cohort=json.loads(read_bound(root,COHORT_PATH,COHORT_SHA))
    runtime=json.loads(read_bound(root,RUNTIME_PATH,RUNTIME_SHA))
    for doc in (cohort,runtime):
        require(doc['generation']==31 and doc['runId']==41715991128 and doc['sourceCommit']=='9ead15c56717c2e301eeb1a2bc1af38b007bfdb8','EXACT31_B_SOURCE_REQUIRED')
        require(doc['binarySha256']==BINARY_SHA and doc['candidateLockSha256']==LOCK_SHA and doc['ociManifestDigest']==lock['image']['manifestDigest'],'EXACT31_B_IDENTITY_REQUIRED')
        require(doc['releaseAdmitted'] is False and doc['runtimeAuthorityIssued'] is False and doc['targetOperations']==doc['gatesClosed']==doc['acceptanceTestsPassed']==0,'EXACT31_B_NO_AUTHORITY_REQUIRED')
        require(doc['dependencyMaintenance']=={'status':'OPEN','allDependenciesMaintained':False} and doc['modifiedMplSource']==lock['modifiedMplSource'],'EXACT31_B_LIMITS_AND_MPL_REQUIRED')
    require(cohort['producerRunId']==image['runId'] and cohort['producerCommit']==image['producerCommit'],'EXACT31_COHORT_PRODUCER_REQUIRED')
    require(cohort['finalWorkflowConclusion']==runtime['wholeWorkflowConclusion']=='success' and runtime['runtimeJobId']==126197618474,'EXACT31_HOSTED_SUCCESS_REQUIRED')
    require(len(cohort['cohortJobs'])==2 and all(j['conclusion']=='success' for j in cohort['cohortJobs']),'EXACT31_COHORT_JOBS_REQUIRED')
    require(cohort['licenceReview']==cohort['durableImageCustody']=='OPEN' and cohort['redistributionAccepted'] is False,'EXACT31_LEGAL_AUTHORITY_OPEN_REQUIRED')
    for path,item in cohort['retainedRawEvidence'].items():
        require(len(read_bound(root,path,item['sha256']))==item['bytes'],'EXACT31_COHORT_RAW_SIZE_REQUIRED')
    artifact=cohort['artifact'];data=read_bound(root,artifact['path'],artifact['sha256'])
    require(len(data)==artifact['bytes']==123479,'EXACT31_COHORT_ARCHIVE_REQUIRED')
    # The exact ZIP is pinned before reading names; its producer directory is retained.
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        require(len(archive.infolist())==11 and len(set(archive.namelist()))==11 and sum(i.file_size for i in archive.infolist())<2*1024*1024,'EXACT31_COHORT_MEMBER_COUNT_REQUIRED')
        cm={name:archive.read(name) for name in archive.namelist()}
    checksum_members(cm)
    require(cm['seaweedfs-452-generation31-candidate-lock-20261103.json']==read_bound(root,LOCK_PATH,LOCK_SHA),'EXACT31_COPIED_LOCK_REQUIRED')
    require(sha(cm['cohort-receipt.json'])==cohort['cohortReceiptSha256']==runtime['cohortReceiptSha256'],'EXACT31_INNER_RECEIPT_REQUIRED')
    require(sha(cm['licence-rebinding.json'])==cohort['legalTextRebindingSha256'],'EXACT31_LEGAL_REBINDING_REQUIRED')
    for name,key in [('modified-raftstore-source.tar.gz','archiveSha256'),('modified-raftstore-source-manifest.json','manifestSha256')]:
        require(sha(cm[name])==lock['modifiedMplSource'][key],'EXACT31_MPL_BYTES_REQUIRED')
    require(cohort['checks']['exactModuleDownloadRecords']==234 and cohort['checks']['moduleLegalTexts']==324 and cohort['checks']['mplSourceArchives']==7 and cohort['checks']['modifiedLocalMplFiles']==6,'EXACT31_COHORT_COUNTS_REQUIRED')
    prefix='evidence/seaweedfs-generation31-runtime-hosted-41715991128/'
    raw={}
    for item in runtime['rawEvidence']['files']:
        require(item['path'].startswith(prefix),'EXACT31_RUNTIME_PATH_REQUIRED')
        name=item['path'][len(prefix):];require(name not in raw,'EXACT31_RAW_DUPLICATE')
        raw[name]=read_bound(root,item['path'],item['sha256'])
        require(len(raw[name])==item['bytes'],'EXACT31_RUNTIME_RAW_SIZE_REQUIRED')
    require(len(raw)==runtime['members']==62,'EXACT31_RUNTIME_MEMBER_COUNT_REQUIRED')
    checksum_members(raw)
    for name,value in cm.items():require(raw['cohort/'+name]==value,'EXACT31_RUNTIME_COHORT_COPY_REQUIRED')
    for path,digest in runtime['sourceHashesVerified'].items():read_bound(root,path,digest)
    require(len(runtime['sourceHashesVerified'])==15 and json.loads(raw['source-sha256.json'])==runtime['sourceHashesVerified'],'EXACT31_SOURCE_MANIFEST_REQUIRED')
    jobs=runtime['hostedJobMetadata'];jobs=json.loads(read_bound(root,jobs['path'],jobs['sha256']))
    require(len(jobs['jobs'])==3 and all(j['conclusion']=='success' for j in jobs['jobs']),'EXACT31_ALL_JOBS_REQUIRED')
    result=json.loads(raw['runtime-result.json'])
    for field in ('binarySha256','candidateLockSha256','cohortReceiptSha256','ociManifestDigest'):
        require(result[field]==runtime[field],'EXACT31_RUNTIME_RESULT_IDENTITY_REQUIRED')
    require(result['status']=='SYNTHETIC_COLD_MIME_IDENTITY_TLS_EGRESS_PASS_NOT_ACCEPTANCE' and result['octetStreamBeforeAndAfterRestore']=='PASS','EXACT31_RUNTIME_RESULT_PASS_REQUIRED')
    require(result['identityS3Cases']==len(runtime['identity']['s3Cases'])==23 and result['tlsNegatives']==len(runtime['identity']['tlsNegatives'])==2 and result['egressProbes']==len(runtime['identity']['egress'])==2,'EXACT31_RUNTIME_CASE_COUNTS_REQUIRED')
    require(runtime['all12ContainersDistinct'] and runtime['coldAndIdentitySequential'] and runtime['maximumConcurrentContainers']==4,'EXACT31_CONTAINER_BOUNDARY_REQUIRED')
    cold=runtime['coldRecovery'];require(cold['objects']==5 and cold['bytes']==8388702 and cold['backupFiles']==110 and cold['backupBytes']==8417282 and cold['octetStreamCompatibility']['status']=='PASS','EXACT31_COLD_RESULT_REQUIRED')
    return cohort,runtime,raw

def current_view31(history,lock,image,cohort,runtime):
    current=copy.deepcopy(history['currentQualification'])
    current.update(generation=31,candidateLock=LOCK_PATH,candidateLockSha256=LOCK_SHA,
        qualifiedImagePatchCount=31,repositoryPatchCount=31,binarySha256=BINARY_SHA,
        ociManifestDigest=lock['image']['manifestDigest'],imageConfigDigest=lock['image']['configDigest'],
        qualificationRunId=image['runId'],imageReceipt=IMAGE_PATH,imageReceiptSha256=IMAGE_SHA,
        cohortReceipt=COHORT_PATH,cohortReceiptSha256=COHORT_SHA,cohortRunId=cohort['runId'],
        runtimeReceipt=RUNTIME_PATH,runtimeReceiptSha256=RUNTIME_SHA,runtimeRunId=runtime['runId'],runtimeJobId=runtime['runtimeJobId'],
        buildProfile='OUF_STANDARD_WITHOUT_ELASTIC_RCLONE_KAFKA_OPENBAO',excludedBuildTags=['elastic','rclone','kafka','openbao','vault'])
    current['syntheticRuntime']['backupBytes']=runtime['coldRecovery']['backupBytes']
    current['mimeCorrection']['status']='EXACT_GENERATION31_SYNTHETIC_REGRESSION_PASS'
    current['dependencyLifecycle']={
        'status':'OPEN','allDependenciesMaintained':False,'compiledModules':234,'compiledPackages':1740,
        'historicalGeneration29InventoryReference':'historicalQualification29.dependencyLifecycle.widerInventoryAssessment',
        'archivedModulesRemovedFromGeneration29Binary':['github.com/boltdb/bolt','github.com/facebookgo/clock','github.com/facebookgo/stats','github.com/google/btree','github.com/mitchellh/mapstructure','github.com/rcrowley/go-metrics'],
        'remainingArchivedCompiledModules':['github.com/envoyproxy/protoc-gen-validate','github.com/mitchellh/colorstring','go.opencensus.io','gopkg.in/yaml.v3'],
        'additionalLifecycleFindings':{'go.mongodb.org/mongo-driver':{'state':'DEPRECATED_MAJOR_SECURITY_FIXES_OBSERVED_PIN_OLDER','compiledPin':'v1.17.9','laterSecurityReleaseObserved':'v1.17.10','laterReleaseMonth':'2026-09','absolutelyUnmaintainedClaimed':False},'github.com/GoogleCloudPlatform/opentelemetry-operations-go/detectors/gcp':{'state':'DECLARED_NO_LONGER_MAINTAINED'}},
        'unknownOriginAssumedMaintained':False,'widerMaintenanceAssessment':'OPEN','nextGeneration32QualificationTransferred':False,
        'targetKafkaOpenBaoFeatureBinding':'OPEN','moduleGraphEradicationClaimed':False}
    current['modifiedMplSource']=copy.deepcopy(lock['modifiedMplSource'])
    return current

def validate_tree31(root,plan,historical_validator):
    history=restore_generation29_plan(plan)
    historical_result=historical_validator(root,history)
    lock,image,manifest,archives=validate_image31(root)
    cohort,runtime,raw=validate_cohort_runtime31(root,lock,image)
    require(plan['currentQualification']==current_view31(history,lock,image,cohort,runtime),'EXACT31_CURRENT_VIEW_REQUIRED')
    historical_result.update(candidateLockSha256=LOCK_SHA,repositoryPatchCount=31,qualifiedImagePatchCount=31,
        currentGeneration=31,historicalGeneration29QualifiedImagePatchCount=29,
        generation31ImageReceiptSha256=IMAGE_SHA,generation31CohortReceiptSha256=COHORT_SHA,
        generation31RuntimeReceiptSha256=RUNTIME_SHA,generation31MimeRegression='PASS_SYNTHETIC_ONLY',
        currentBinaryModules=234,currentCompiledPackages=1740,historicalProofTransferredToGeneration31=False)
    return historical_result
