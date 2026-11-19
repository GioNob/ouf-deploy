#!/usr/bin/env python3
"""Stage one exact diagnostic CI ZIP and bind private execution inputs. No runtime I/O.

Three named retained metadata files are read; no owner configuration content. The image custody module is a pure helper;
no consumed controller or entrypoint is imported or executed. No Engine socket,
namespace, credential, signing key, IAM, SQL, route or application is accessed.
"""
import copy,ipaddress,gzip,hashlib,importlib.util,json,os,re,shutil,signal,stat,sys,zipfile
from pathlib import Path

INPUT_ROOT=Path('/etc/ouf/deploy-snapshots/onboarding-profile-recovery-current-inputs-20261027-v1')
DATABASE_PLAN=Path('/etc/ouf/deploy-snapshots/onboarding-budget-v35-54d86bbcd2ea47fd/native-plan-v1/execution-plan.json')
DATABASE_PLAN_HASH='b17c2c99cc791cced8ee00ed190e30b75c518ae84e2dd4a9ae7eef521390c8bd'
INSTALLED_SOURCE='a5ed8b05c264a8221783a6e323ba00117aed891d'
INSTALLED_IMAGE='sha256:074bd16ec8ebd98cbf1ee085af9767a5f7e322072a541e85bd37925002fa5df2'
INPUT_HASH='1ce0ce1cd27195565393798d4d06246047c5b46c12cef39bc31aee4ed7aff82c'
ROOT=Path('/etc/ouf/deploy-snapshots/onboarding-profile-recovery-image-plan-1ce0ce1cd2719556-v1')
SOURCE='6ea5242f711761a384fa1b23667971601bc2c38b'
TESTED='e42c398af3ab6989a956925445c478f8eb9f2446'
IMAGE='sha256:24b89e0430513b441453467a57cca983fcef2dbb6733fe29dc0fa34b1be67463'
ZIP_HASH='afc1da28317b06845c8a37d81c529e931cb3d11415f13b9842fb3633a0e8d3d0'
ARCHIVE_HASH='e3868e3e6582150da2d94e3f4c467ef5140a54bbad2a69aa6a4306b43938c3c9'
CASE_HASH='bf9a2477a808e38d3b960ce085fadda20a1f196857c4fc70a5a6fee153e6ffbb'
MEMBERS={'image.tar.gz','manifest.json','SHA256SUMS'}
HELPER_HASHES={'image_custody':'5d0fc0edb1ebd9386326eadbbee08f2cf0a9fd1e122940c0661b5ac5e3655ed8','plan_helper':'09b892a89f7cd7fa31fbc891822445ed09554e9362e397bb9b12b98316e1d8dd','retained_mac':'cb5dbbee4a80ce71860dfe5d32362a662d98898c58fd82009e69c5eb6ac1f7ce'}
COUNTS={'privateMetadataReads':0,'ciZipReads':0,'nativeArchivesPrepared':0,'engineGets':0,'containerWrites':0,'imageImports':0}

class Stop(RuntimeError):pass
def require(ok,code):
    if not ok:raise Stop(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def digest(v):return sha(encoded(v))
def decode(raw):
    def unique(rows):
        out={}
        for k,v in rows:require(k not in out,'DUPLICATE_PLAN_KEY');out[k]=v
        return out
    return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:require(False,'NONFINITE_PLAN_JSON'))
def frame(s):return tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def ancestry(path):
    require(path.is_absolute()and path.resolve()==path,'CANONICAL_PLAN_PATH_REQUIRED')
    for part in(path,*path.parents):
        s=part.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and not s.st_mode&0o022,'ROOT_PLAN_ANCESTRY_REQUIRED')
def sync(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
def put(path,value):
    raw=value if isinstance(value,bytes)else encoded(value)
    require(len(raw)<=64*1024*1024,'BOUNDED_PLAN_OUTPUT_REQUIRED')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
    with os.fdopen(fd,'wb')as out:
        os.fchmod(out.fileno(),0o400);out.write(raw);out.flush();os.fsync(out.fileno())
    sync(path.parent)
def private(root,path,expected=None):
    require(COUNTS['privateMetadataReads']<3,'THREE_EXACT_PRIVATE_PLAN_READS_ONLY')
    COUNTS['privateMetadataReads']+=1;put(root/('private-read-'+str(COUNTS['privateMetadataReads'])+'-claim.json'),{'path':str(path),'attemptNotCompletion':True})
    ancestry(path.parent);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd);require(stat.S_ISREG(before.st_mode)and before.st_uid==before.st_gid==0 and before.st_nlink==1 and stat.S_IMODE(before.st_mode)in(0o400,0o600)and 0<before.st_size<=6*1024*1024,'PROTECTED_CAPTURE_METADATA_REQUIRED')
        raw=b''
        while len(raw)<before.st_size:
            part=os.read(fd,min(65536,before.st_size-len(raw)));require(part,'COMPLETE_CAPTURE_METADATA_REQUIRED');raw+=part
        require(frame(before)==frame(os.fstat(fd))==frame(path.lstat()),'CAPTURE_METADATA_CHANGED')
        require(expected is None or sha(raw)==expected,'EXACT_CAPTURE_BYTES_REQUIRED')
        return decode(raw),{'path':str(path),'metadata':list(frame(before)),'sha256':sha(raw)}
    finally:os.close(fd)
def helper(name,folder):
    require(name in HELPER_HASHES,'NAMED_PURE_HELPER_ONLY');ancestry(folder)
    path=folder/(name+'.py');fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd);raw=os.read(fd,131073)
        require(stat.S_ISREG(before.st_mode)and before.st_uid==before.st_gid==0 and stat.S_IMODE(before.st_mode)==0o400 and before.st_nlink==1
            and 0<len(raw)==before.st_size<=131072 and sha(raw)==HELPER_HASHES[name]and frame(before)==frame(os.fstat(fd))==frame(path.lstat()),'ROOT_SEALED_PURE_HELPER_REQUIRED')
    finally:os.close(fd)
    spec=importlib.util.spec_from_file_location('mcp_plan_'+name,folder/(name+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def source_case(folder):
    path=folder/'case.json';ancestry(folder);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd);raw=os.read(fd,131073)
        require(stat.S_ISREG(before.st_mode)and before.st_uid==before.st_gid==0 and stat.S_IMODE(before.st_mode)==0o400 and before.st_nlink==1
            and 0<len(raw)==before.st_size<=131072 and sha(raw)==CASE_HASH and frame(before)==frame(os.fstat(fd))==frame(path.lstat()),'ROOT_SEALED_CI_IMAGE_CASE_REQUIRED')
        return decode(raw)
    finally:os.close(fd)
def stage_zip(root,path):
    COUNTS['ciZipReads']+=1;put(root/'zip-read-claim.json',{'sha256':ZIP_HASH,'maximumBytes':212905775,'attemptNotCompletion':True})
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb')as stream:
        before=os.fstat(fd);require(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_size==212905775,'EXACT_CI_ZIP_SIZE_REQUIRED')
        h=hashlib.sha256()
        for block in iter(lambda:stream.read(1048576),b''):h.update(block)
        require(h.hexdigest()==ZIP_HASH,'EXACT_CI_ZIP_DIGEST_REQUIRED');stream.seek(0);hashes={}
        with zipfile.ZipFile(stream)as z:
            rows=z.infolist();require(len(rows)==3 and{r.filename for r in rows}==MEMBERS,'EXACT_CI_ZIP_MEMBER_SET_REQUIRED')
            for row in rows:
                maximum=212904147 if row.filename=='image.tar.gz'else 131072
                require(not row.is_dir()and stat.S_IFMT(row.external_attr>>16)in(0,stat.S_IFREG)and 0<row.file_size<=maximum,'BOUNDED_REGULAR_CI_MEMBER_REQUIRED')
                h=hashlib.sha256();size=0;outfd=os.open(root/row.filename,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
                with z.open(row)as src,os.fdopen(outfd,'wb')as out:
                    os.fchmod(out.fileno(),0o400)
                    while block:=src.read(1048576):
                        size+=len(block);require(size<=maximum,'ZIP_EXPANSION_BOUND');h.update(block);out.write(block)
                    out.flush();os.fsync(out.fileno())
                require(size==row.file_size,'COMPLETE_CI_MEMBER_REQUIRED');hashes[row.filename]=h.hexdigest()
        require(frame(before)==frame(os.fstat(fd))==frame(path.lstat()),'CI_ZIP_CHANGED_DURING_STAGING')
    require((root/'SHA256SUMS').read_text()==ARCHIVE_HASH+'  image.tar.gz\n'and hashes['image.tar.gz']==ARCHIVE_HASH,'EXACT_ARCHIVE_CHECKSUM_REQUIRED')
    manifest=decode((root/'manifest.json').read_bytes())
    require(manifest['schema']=='ouf.onboarding-tested-image.v1'and manifest['reviewedSourceCommit']==SOURCE and manifest['testedCommit']==TESTED
        and manifest['testedTree']=='b2b4ca04043a818f39fd8a9743972b7e6130c16e'and manifest['workflowRunId']=='40533881204'
        and manifest['imageId']==IMAGE and manifest['imageRevisionLabel']==TESTED and manifest['archiveBytes']==212904147
        and manifest['archiveSha256']==ARCHIVE_HASH and manifest['targetApplyAuthorized']is False and manifest['sourceSchemaMigration']=='V36__managed_profile_recovery_sessions.sql'and manifest['humanBudgetGranted']is False,'EXACT_CI_IMAGE_SOURCE_MANIFEST_REQUIRED')
    return {'schema':'ouf.onboarding-profile-recovery-image-staged.v1','reviewedSourceCommit':SOURCE,'testedCommit':TESTED,'applicationSourceEquivalent':True,
        'qualifiedInCiOnly':True,'artifactId':12747244692,'workflowRun':40533881204,
        'artifactZipSha256':ZIP_HASH,'configurationImageId':IMAGE,'fileHashes':hashes,'capturedInputsHash':INPUT_HASH,'targetUpdateAuthorized':False}
def validate_capture(inputs,result):
    require(inputs['schema']=='ouf.onboarding-profile-recovery-current-inputs.v1'and result['schema']=='ouf.onboarding-profile-recovery-current-input-capture-result.v1'
        and result['status']=='ONBOARDING_PROFILE_RECOVERY_CURRENT_INPUTS_CAPTURED_NOT_AUTHORIZED'and result['complete']is True
        and result['inputsHash']==INPUT_HASH and result['counts']==inputs['counts']=={'bytes':526335,'engineGets':3,'privateMetadataReads':4}
        and all(result[k]==0 for k in('containerWrites','imageImports','sourceActivations','acquisitionsExecuted','sqlSessions','oauthRequests','credentialFileReads')) and result['runtimeAuthorityIssued']is False and result['automaticReplayAllowed']is False
        and result['budgetReset']is False and inputs['retainedInstalledSource']==INSTALLED_SOURCE
        and inputs['retainedReviewHash']=='d77154b3e734c0b249f315fe10961d99baa380d4625d920b917cbe7c270b134b'
        and inputs['retainedAuthorityHash']=='fa906ab28f8268e7b62a8df59c9825b8c2524bf28da44821801db7b916c1f4ce'
        and inputs['retainedNativeBindingHash']=='1bda483e8138353f4ada203a6b19fa532344393b5e0f995c963d01c90584eb78'
        and result['retainedCandidateIdentityObserved']is True and result['retainedProcessGenerationMatched']is True
        and all(result[k]is False for k in('currentApplicationPolicyOrLabelsObserved','currentJobOrBudgetStateObserved','currentReadinessObserved','continuationAuthorized','historicalAuthorityReused')),
        'EXACT_COMPLETED_CAPTURE_REQUIRED')
    info=inputs['engineInfo'];require(info['ServerVersion']=='29.8.1'and ['driver-type','io.containerd.snapshotter.v1']in(info.get('DriverStatus')or[]),'QUALIFIED_NATIVE_ENGINE_PROFILE_REQUIRED')
    actual=inputs['onboardingObservation'];require(actual['State']['Running']is True and actual['State']['Pid']==inputs['onboardingProcessPin']['pid']and actual['Image']==INSTALLED_IMAGE,'CAPTURED_RUNNING_OWNER_REQUIRED')
    require(actual['Config'].get('User')in('10003','10003:10003'),'RETAINED_OWNER_UID_REQUIRED')
    peer=inputs['engineBinding'].get('peerCredentials')
    require(type(peer)is list and len(peer)==3 and all(type(v)is int for v in peer)and peer[0]>=1 and peer[1:]==[0,0],'EXACT_CAPTURED_ROOT_PEER_TUPLE_REQUIRED')
    return actual
def conditional_plan(inputs,frozen,audit,p,mac,case):
    require(frozen['schema']=='ouf.onboarding-v35-frozen-native-plan.v1'and frozen['runtimeAuthorityIssued']is False and frozen['targetApplyAuthorized']is False,'RETAINED_V35_PROPOSAL_METADATA_ONLY')
    old=inputs['onboardingObservation'];request=p.config_copy(old);image=audit['imageConfig'];retained=frozen['replacements']['onboarding']
    for key in('Env','Entrypoint','Cmd','User','WorkingDir','Healthcheck'):
        require(request.get(key)==retained['request'].get(key),'SAME_CLASSIFIED_OWNER_LAUNCH_CONFIGURATION_REQUIRED')
    overlays=frozen['nativeFlywayConfiguration']['ownerOverlays'];profile=frozen['boundDatabaseProfile']
    require(type(overlays)is list and len(overlays)==1 and overlays[0]['binding']['path']=='/opt/ouf/secrets/onboarding-ths.yaml','ONLY_NAMED_RETAINED_OWNER_OVERLAY_METADATA')
    require(profile['schema']=='ouf.current-onboarding-database-snapshot-profile.v1'and profile['runtimeBindingProfile']=='ouf.runtime-binding.native-mount-order.v1','EXACT_RETAINED_NATIVE_DATABASE_PROFILE_REQUIRED')
    require(request['User']in(image['User'],image['User'].split(':')[0])and request['Entrypoint']==image['Entrypoint']and request.get('Cmd')==image.get('Cmd'),'EXACT_RETAINED_OWNER_LAUNCH_REQUIRED')
    name=old['Name'].removeprefix('/');require(re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,160}',name),'BOUND_OWNER_NAME_REQUIRED')
    host=copy.deepcopy(old['HostConfig']);restore=copy.deepcopy(host['RestartPolicy']);host['RestartPolicy']={'Name':'no','MaximumRetryCount':0}
    require(host.get('AutoRemove')is False and type(host.get('Memory'))is int and host['Memory']>=0 and(host.get('OomKillDisable')is None or type(host['OomKillDisable'])is bool),'EXACT_RETAINED_HOST_POLICY_REQUIRED')
    endpoint=next(iter(old['NetworkSettings']['Networks'].values()));network=p.network(old,[name,*(endpoint.get('Aliases')or[])],preserve_mac=True)
    ipam=copy.deepcopy(endpoint.get('IPAMConfig')or{});require(type(ipam)is dict and set(ipam)<={'IPv4Address','IPv6Address','LinkLocalIPs'},'CLOSED_RETAINED_ENDPOINT_ALLOCATION')
    for source,target,version in(('IPAddress','IPv4Address',4),('GlobalIPv6Address','IPv6Address',6)):
        address=endpoint.get(source)
        if address:
            parsed=ipaddress.ip_address(address);require(parsed.version==version and not parsed.is_unspecified and not parsed.is_multicast and ipam.get(target)in(None,'',address),'RETAINED_STATIC_ENDPOINT_MISMATCH');ipam[target]=address
    network['request']['EndpointsConfig'][network['name']]['IPAMConfig']=ipam
    for port,bindings in(host.get('PortBindings')or{}).items():
        if any(row.get('HostPort')in(None,'','0')for row in bindings):
            actual=(old['NetworkSettings'].get('Ports')or{}).get(port)
            require(type(actual)is list and len(actual)==len(bindings)and all(type(r)is dict and str(r.get('HostPort','')).isdigit()and 1<=int(r['HostPort'])<=65535 for r in actual),'ALREADY_ALLOCATED_PUBLISHED_PORT_REQUIRED');host['PortBindings'][port]=copy.deepcopy(actual)
    request.update(Image=audit['nativeIdentity']['nativeImageId'],HostConfig=host,NetworkingConfig=network['request'])
    labels=request.get('Labels')or{};defaults=image.get('Labels')or{}
    require(all(k.startswith('org.opencontainers.image.')for k in set(defaults)-set(labels)),'ONLY_QUALIFIED_IMAGE_LABEL_DEFAULTS')
    readiness=copy.deepcopy(retained['readiness']);require(type(readiness['readinessPort'])is int and 1<=readiness['readinessPort']<=65535 and readiness['readinessPath']=='/actuator/health/readiness','RETAINED_OWNER_READINESS_ENDPOINT_REQUIRED')
    legacy=mac.policy(old)if old['Config'].get('MacAddress')else{'profile':'NO_LEGACY_CONFIG_MAC_CHANGE_RETAIN_EXACT_V1','originalConfigHash':digest(old['Config']),'originalEndpointSetHash':digest(old['NetworkSettings']['Networks']),'originalHashesRewritten':False}
    replacement={'name':name,'retiredName':name+'-retained-profile-recovery-'+INPUT_HASH[:12],'request':request,
        'network':{'name':network['name'],'id':network['id']},'oldBinding':p.stable_binding(old),'restoreRestartPolicy':restore,
        'oldNativeHostConfig':copy.deepcopy(old['HostConfig']),'runtimeLabelProjection':{'expectedLabels':{**defaults,**labels}},'readiness':readiness,
        'retainedResourcePolicy':{'memoryBytes':host['Memory'],'autoRemove':False,'oomKillDisable':host.get('OomKillDisable'),'resourcePolicyChanged':False}}
    if host.get('OomKillDisable')is None:replacement['runtimeHostProjection']={'profile':'DOCKER_ENABLED_OOM_DEFAULT_NULL_FALSE_V1','requestedOomKillDisable':None,'materializedOomKillDisable':False,'retainedMemoryBytes':host['Memory']}
    return {'schema':'ouf.onboarding-profile-recovery-conditional-native-plan.v1','kind':'FROZEN_CONDITIONAL_PROPOSAL_NOT_EXECUTABLE',
        'capturedInputsHash':INPUT_HASH,'reviewedSourceCommit':SOURCE,'testedCommit':TESTED,'bootId':inputs['bootId'],
        'engineBinding':copy.deepcopy(inputs['engineBinding']),'onboardingProcessPin':copy.deepcopy(inputs['onboardingProcessPin']),
        'onboardingReplacement':replacement,'legacyConfigMacDetachPolicy':legacy,'boundDatabaseProfile':copy.deepcopy(profile),
        'candidateApplicationFacts':copy.deepcopy(case['application']),'ciDeliveryCommit':case['deliveryCommit'],'ciImageCustodyCaseHash':CASE_HASH,
        'retainedDatabasePlanHash':DATABASE_PLAN_HASH,'nativeFlywayConfiguration':copy.deepcopy(frozen['nativeFlywayConfiguration']),
        'databaseMigration':{'from':35,'to':36,'owner':'EXPLICIT_FUTURE_REVIEWED_APPLICATION_FLYWAY','requiredHistoryVersions':list(range(1,36)),
            'script':'V36__managed_profile_recovery_sessions.sql','sha256':'028ffbf6004ac27ad9e8e3e4c16eda60bbf39121e2f848d28259e60bf6858f46','flywayChecksum':-317278534,
            'priorHistoryMustMatchExact35':True,'automaticMigrationAuthorized':False},
        'retainedCaptureCounts':copy.deepcopy(inputs['counts']),'retainedDiagnosticApplyCounts':copy.deepcopy(inputs['retainedDiagnosticApplyCounts']),
        'retainedDiagnosticOperationalStateProof':copy.deepcopy(inputs['retainedDiagnosticOperationalStateProof']),
        'retainedCapturedHistorySeals':copy.deepcopy(inputs['historySeals']),
        'futureRequirements':['CURRENT_OWNER_AND_PEER_TUPLE','CURRENT_OTHER_COMPONENT_GENERATIONS','CURRENT_OWNER_CONFIGURATION_CONTENT_AND_PRECEDENCE',
            'EXACT_35_HISTORY_AND_QUIESCED_OPERATIONAL_STATE','VERIFIED_QUIESCED_BACKUP','NEW_CONCRETE_TERMINAL_REVIEW_AND_FINITE_SIGNED_AUTHORITY',
            'EXACT_36_HISTORY_AND_MONOTONIC_OPERATIONAL_STATE'],
        'freshDatabaseAdmissionRequiredAtApply':True,'freshOwnerConfigurationContentRequiredAtApply':True,'backupMustBeQuiescedAndVerified':True,
        'newJobOrHumanBudgetAuthorized':False,'sourceActivationAuthorized':False,'databaseRestoreAuthorized':False,'currentRuntimeRevalidated':False,
        'databaseAdmissionProven':False,'mountSourceContentIdentityProven':False,'executionEntryQualified':False,'runtimeAuthorityIssued':False,
        'targetApplyAuthorized':False,'automaticRollbackAllowed':False,'automaticReplayAllowed':False,'budgetReset':False,'applicationE2EProven':False,'releaseAcceptance':False}

def prepare(download,folder,*,root=ROOT,input_root=INPUT_ROOT,database_plan=DATABASE_PLAN):
    require(os.geteuid()==os.getegid()==0,'ROOT_IMAGE_INPUTS_REQUIRED');ancestry(root.parent)
    require(not os.path.lexists(root),'IMAGE_INPUT_SCOPE_CONSUMED_NO_REPLAY');root.mkdir(mode=0o700);os.chmod(root,0o700);sync(root.parent)
    put(root/'claim.json',{'schema':'ouf.onboarding-profile-recovery-image-inputs-claim.v1','capturedInputsHash':INPUT_HASH,'maximumSeconds':300,'engineGets':0,'containerWrites':0,'imageImports':0,'automaticReplayAllowed':False})
    inputs,sealed=private(root,input_root/'inputs.json',INPUT_HASH);result,result_seal=private(root,input_root/'result.json')
    actual=validate_capture(inputs,result)
    frozen,database_seal=private(root,database_plan,DATABASE_PLAN_HASH)
    require(shutil.disk_usage(root).free>=2*1024*1024*1024,'TWO_GIB_FREE_FOR_EXACT_IMAGE_CUSTODY_REQUIRED')
    receipt=stage_zip(root,download);put(root/'staged-receipt.json',receipt)
    custody=helper('image_custody',folder)
    expanded=root/'expanded.tar';fd=os.open(expanded,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
    with os.fdopen(fd,'w+b')as output,gzip.open(root/'image.tar.gz','rb')as zipped:
        os.fchmod(output.fileno(),0o400);total=0
        while block:=zipped.read(1048576):
            total+=len(block);require(total<=600*1024*1024,'BOUNDED_IMAGE_GZIP_EXPANSION');output.write(block)
        output.flush();os.fsync(output.fileno());output.seek(0);checksum,_=custody.hashed(output,600*1024*1024)
        require(checksum=='8c39b0787e3fe614bca4235e33fb61260c7ee99361afc4abfe5654469cb95a8f','EXACT_ORIGINAL_EXPANDED_ARCHIVE_REQUIRED')
        audit=custody.archive(output,checksum,IMAGE,TESTED)
        require(audit['imageConfig'].get('User')=='10003:10003'and audit['imageConfig'].get('Entrypoint')==['java','-jar','/app/application.jar'],'EXACT_TESTED_OWNER_LAUNCH_REQUIRED')
        target=root/'native.tar';outfd=os.open(target,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
        with os.fdopen(outfd,'w+b')as out:
            os.fchmod(out.fileno(),0o400);derived=custody.tagless_archive(output,out,audit,containerd=True);out.flush();os.fsync(out.fileno());native_metadata=list(frame(os.fstat(out.fileno())))
        audit['nativeIdentity']=custody.native_identity(audit)
    require(custody.runtime_image_id(audit)=='sha256:e4690481db28e3e70335704de89e563dcf32ecf70e4a0caea1bdc30c48aa4359'
        and derived['derivedArchiveSha256']=='1553453fcdfd6166a38234194a81f8f6d04bb41a9552453fc51fb5c831e216a2'and derived['archiveBytes']==444241920,'EXACT_NATIVE_BYTES_REQUIRED')
    COUNTS['nativeArchivesPrepared']+=1
    proposal=conditional_plan(inputs,frozen,audit,helper('plan_helper',folder),helper('retained_mac',folder),source_case(folder));put(root/'execution-plan.json',proposal)
    private_inputs={'schema':'ouf.onboarding-profile-recovery-private-execution-inputs.v1','capturedInputsHash':INPUT_HASH,
        'bootId':inputs['bootId'],'engineBinding':inputs['engineBinding'],'engineInfoHash':digest(inputs['engineInfo']),
        'currentOnboarding':actual,'currentProcessPin':inputs['onboardingProcessPin'],'stagedReceipt':receipt,
        'reviewedSourceCommit':SOURCE,'testedCommit':TESTED,'imageAudit':audit,'nativeImageId':custody.runtime_image_id(audit),
        'nativeArchive':{'path':str(target),'sha256':derived['derivedArchiveSha256'],'bytes':derived['archiveBytes'],'metadata':native_metadata},
        'historySeals':[sealed,result_seal,database_seal],'conditionalNativePlanHash':digest(proposal),'conditionalLifecyclePlanCompiled':True,'lifecyclePlanCompiled':False,'executionEntryQualified':False,'currentRuntimeRevalidated':False,
        'mountSourceContentIdentityProven':False,'runtimeAuthorityIssued':False,'targetUpdateAuthorized':False,
        'automaticReplayAllowed':False,'budgetReset':False,'applicationE2EProven':False,'releaseAcceptance':False}
    for seal in(sealed,result_seal,database_seal):require(list(frame(Path(seal['path']).lstat()))==seal['metadata'],'ORIGINAL_CAPTURE_SEAL_CHANGED')
    put(root/'execution-inputs.json',private_inputs)
    output={'schema':'ouf.onboarding-profile-recovery-image-plan-prepared.v1','status':'ONBOARDING_PROFILE_RECOVERY_IMAGE_AND_CONDITIONAL_PLAN_PREPARED_NOT_AUTHORIZED','complete':True,
        'contextPath':str(root),'inputsHash':INPUT_HASH,'executionInputsHash':digest(private_inputs),'nativeImageId':private_inputs['nativeImageId'],
        'conditionalNativePlanHash':digest(proposal),'conditionalLifecyclePlanCompiled':True,'databaseAdmissionProven':False,'newMigrationVersion':36,
        'ownerConfigurationContentReads':0,'sourceActivations':0,'acquisitionsExecuted':0,'humanBudgetsGranted':0,
        'reviewedSourceCommit':SOURCE,'testedCommit':TESTED,'counts':dict(COUNTS),'credentialFileReads':0,'oauthRequests':0,'sqlSessions':0,
        'lifecyclePlanCompiled':False,'executionEntryQualified':False,'currentRuntimeRevalidated':False,'runtimeAuthorityIssued':False,
        'continuationAuthorized':False,'applicationE2EProven':False,'releaseAcceptance':False,'automaticReplayAllowed':False,'budgetReset':False}
    put(root/'result.json',output);return output
def main():
    try:
        require(len(sys.argv)==2 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_IMAGE_PLAN_ENTRY_REQUIRED')
        signal.signal(signal.SIGALRM,lambda *_:require(False,'FINITE_IMAGE_INPUT_TIMEOUT'));signal.alarm(300)
        print(encoded(prepare(Path(sys.argv[1]),Path(__file__).resolve().parent)).decode(),flush=True);return 0
    except Exception as error:
        reason=str(error)if isinstance(error,Stop)and re.fullmatch('[A-Z0-9_]{1,120}',str(error))else'IMAGE_PLAN_UNPROVEN'
        print(encoded({'schema':'ouf.onboarding-profile-recovery-image-plan-prepared.v1','status':'STOP_RECONCILE','reasonCode':reason,'complete':False,'privateStagingMayBePartial':True,'counts':COUNTS,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False,'applicationE2EProven':False,'releaseAcceptance':False}).decode(),flush=True);return 2
    finally:signal.alarm(0)
if __name__=='__main__':raise SystemExit(main())
