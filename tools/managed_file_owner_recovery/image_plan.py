"""One exact V38 image and a conditional single-owner plan. No runtime ports."""
import copy,hashlib,importlib.util,os,shutil
from pathlib import Path

HERE=Path(__file__).resolve().parent
COMMON=HERE/'common_image_plan.py'
if not COMMON.exists():COMMON=HERE.parent/'managed_csv_recovery/image_plan.py'
assert hashlib.sha256(COMMON.read_bytes()).hexdigest()=='d95720bd315b2f7e08378ecc60250088b4173601705297ca65a904f9316a3375'
spec=importlib.util.spec_from_file_location('retained_common_image_plan',COMMON);common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
Stop,require,encoded,digest,decode,frame,ancestry,sync,put,load_module=(getattr(common,k)for k in('Stop','require','encoded','digest','decode','frame','ancestry','sync','put','load_module'))

class Scope(common.Scope):
    def __init__(self,root):
        self.root=Path(root);ancestry(self.root.parent)
        require(not os.path.lexists(self.root),'OWNER_IMAGE_PLAN_SCOPE_CONSUMED_NO_REPLAY')
        self.root.mkdir(mode=0o700);self.root.chmod(0o700);sync(self.root.parent)
        self.counts={'privateMetadataReads':0,'privateMetadataBytes':0,'ciZipReads':0,'nativeArchivesPrepared':0,'engineGets':0,'containerWrites':0,'imageImports':0};self.seals=[]
        put(self.root/'claim.json',{'schema':'ouf.managed-file-owner-image-plan-claim.v1','maximumSeconds':300,'privateMetadataReads':3,'ciZipReads':1,'engineGets':0,'sqlSessions':0,'containerWrites':0,'imageImports':0,'automaticReplayAllowed':False})

def validate_capture(inputs,result,info,case):
    require(result==case['captureResult']and digest(result)==case['captureResultHash']and result['complete']is True
        and result['inputsHash']==case['captureHash']and result['contextPath']==case['captureRoot'],'EXACT_SUCCESSFUL_CONSUMED_OWNER_CAPTURE_REQUIRED')
    require(digest(inputs)==case['captureHash']and inputs['schema']=='ouf.managed-file-owner-recovery-current-inputs.v1'
        and inputs['targetRoles']==['onboarding']and inputs['unchangedPeers']==12
        and all(inputs[k]is False for k in('databaseSchemaObservedByThisCapture','currentJobOrBudgetStateObserved','runtimeAuthorityIssued','targetApplyAuthorized','nativePlanPrepared','automaticReplayAllowed','budgetReset')),
        'EXACT_METADATA_ONLY_OWNER_INPUTS_REQUIRED')
    require(info['ServerVersion']=='29.8.1'and ['driver-type','io.containerd.snapshotter.v1']in(info.get('DriverStatus')or[]),'QUALIFIED_NATIVE_ENGINE_PROFILE_REQUIRED')
    cohort=inputs['currentObservations'];require(len(cohort)==13 and set(cohort)==set(inputs['currentProcessPins'])
        and len({v['Id']for v in cohort.values()})==13 and 'onboarding'in cohort,'EXACT_COHORT13_REQUIRED')
    review=inputs['retainedSuccessfulReview'];retained=review['nativePlan']['proposal']
    require(digest(review)==inputs['retainedReviewHash']==case['retainedReviewHash']and review['bootId']==inputs['bootId']
        and retained['engineBinding']==inputs['engineBinding']and retained['boundDatabaseProfile']==inputs['boundDatabaseProfile'],
        'SAME_SUCCESSFUL_RETAINED_OWNER_REVIEW_REQUIRED')
    previous=inputs['retainedSuccessfulResult'];actual=cohort['onboarding']
    require(digest(previous)==case['retainedApplyResultHash']and previous['complete']is True
        and previous['nativeImageId']==actual['Image']==case['installedNativeImageId']
        and previous['nativeBindingHash']==digest(common_binding(actual))
        and previous['generation']==inputs['currentProcessPins']['onboarding']
        and previous['humanBudgetsGranted']==previous['resumes']==0,'EXACT_CAPTURED_INSTALLED_OWNER_REQUIRED')
    require(inputs['retainedOwnershipReadHash']==result['retainedOwnershipReadHash']==case['ownershipReadHash']
        and digest(inputs['retainedOwnershipReadResult'])==case['ownershipReadHash'],'EXACT_CONSUMED_OWNERSHIP_PROVENANCE_REQUIRED')
    return cohort,retained

def common_binding(actual):
    return {'containerId':actual['Id'],'imageId':actual['Image'],'name':actual['Name'],'pid':actual['State']['Pid'],'startedAt':actual['State']['StartedAt'],
        'configHash':digest(actual['Config']),'hostConfigHash':digest(actual['HostConfig']),'mountsHash':digest(sorted(actual['Mounts'],key=lambda v:v['Destination'])),
        'networkSettingsHash':digest(actual['NetworkSettings']),'profile':'ouf.acquisition-read.mount-set-binding.v1'}

def compile_plan(inputs,result,info,receipt,archive,p,mac,case):
    cohort,retained=validate_capture(inputs,result,info,case)
    require(digest(receipt)==case['imageReceiptHash']and receipt['sourceCommit']==case['candidateSourceCommit']
        and receipt['nativeImageId']==case['candidateNativeImageId']and receipt['imageRebuilt']is False
        and receipt['imageImported']is False and receipt['targetApplyAuthorized']is False,'EXACT_QUALIFIED_V38_IMAGE_REQUIRED')
    facts=receipt['application'];oldfacts=retained['candidateApplicationFacts']
    require(len(facts['migrations'])==38 and facts['migrations'][:36]==oldfacts['migrations']
        and facts['migrations'][36:]==case['additionalMigrations']and facts['databaseMigrationRequired']is True
        and facts['applicationYamlSha256']==oldfacts['applicationYamlSha256']
        and facts['managedProfileRole']==oldfacts['managedProfileRole'],'ALL_36_MIGRATIONS_YAML_ROLE_AND_TWO_EXACT_ADDITIONS_REQUIRED')
    actual=cohort['onboarding'];image=receipt['imageAudit']['imageConfig']
    require(all(v['State']['Running']is True and v['State']['Paused']is False and v['State']['Restarting']is False for v in cohort.values()),'CAPTURED_COHORT_RUNNING_REQUIRED')
    request=p.config_copy(actual);previous=retained['replacements']['onboarding'] if 'replacements'in retained else retained['readReplacements']['onboarding']
    require(all(request.get(k)==previous['request'].get(k)for k in('Entrypoint','Cmd','User','WorkingDir','Healthcheck'))
        and p.env(request)==p.env(previous['request']),'RETAIN_COMPLETE_INSTALLED_OWNER_REQUEST_REQUIRED')
    require(request['User']in(image['User'],image['User'].split(':')[0])and request['Entrypoint']==image['Entrypoint']
        and request.get('Cmd')==image.get('Cmd')and set(p.env(image))<=set(p.env(actual['Config'])),'QUALIFIED_UNCHANGED_OWNER_LAUNCH_REQUIRED')
    host=copy.deepcopy(actual['HostConfig']);restore=copy.deepcopy(host['RestartPolicy'])
    require(host.get('AutoRemove')is False and type(host.get('Memory'))is int and host['Memory']>=0
        and(host.get('OomKillDisable')is None or type(host['OomKillDisable'])is bool),'EXACT_RETAINED_RESOURCE_POLICY_REQUIRED')
    host['RestartPolicy']={'Name':'no','MaximumRetryCount':0};request.update(Image=receipt['nativeImageId'],HostConfig=host)
    defaults=image.get('Labels')or{};labels=actual['Config'].get('Labels')or{}
    require(all(k.startswith('org.opencontainers.image.')for k in set(defaults)-set(labels)),'NO_UNREVIEWED_IMAGE_LABEL_ADDITIONS')
    replacement={'name':actual['Name'].removeprefix('/'),'retiredName':actual['Name'].removeprefix('/')+'-retained-owner-v38-'+case['captureHash'][:12],
        'request':request,'restoreRestartPolicy':restore,'oldBinding':p.stable_binding(actual),'oldNativeHostConfig':copy.deepcopy(actual['HostConfig']),
        'network':common.retain_allocations(actual,request,p),'imageAudit':copy.deepcopy(receipt['imageAudit']),'nativeArchive':copy.deepcopy(archive),
        'readiness':copy.deepcopy(previous['readiness']),'runtimeLabelProjection':{'expectedLabels':{**defaults,**labels}},
        'retainedRoleKey':'onboarding','oldRetainedStopped':True,'oldMustBeStoppedAndDetachedBeforeNewStarts':True}
    replacement['legacyConfigMacDetachPolicy']=mac.policy(actual)if actual['Config'].get('MacAddress')else{
        'profile':'NO_LEGACY_CONFIG_MAC_CHANGE_RETAIN_EXACT_V1','originalConfigHash':digest(actual['Config']),
        'originalEndpointSetHash':digest(actual['NetworkSettings']['Networks']),'originalHashesRewritten':False}
    if host.get('OomKillDisable')is None:replacement['runtimeHostProjection']={'profile':'DOCKER_ENABLED_OOM_DEFAULT_NULL_FALSE_V1','requestedOomKillDisable':None,'materializedOomKillDisable':False,'retainedMemoryBytes':host['Memory']}
    return {'schema':'ouf.managed-file-owner-recovery-conditional-native-plan.v1','kind':'FROZEN_CONDITIONAL_PROPOSAL_NOT_EXECUTABLE',
        'capturedInputsHash':case['captureHash'],'bootId':inputs['bootId'],'engineBinding':copy.deepcopy(inputs['engineBinding']),'engineInfoHash':digest(info),
        'currentRootProcessPins':copy.deepcopy(inputs['currentRootProcessPins']),'currentProcessPins':copy.deepcopy(inputs['currentProcessPins']),
        'existingApplications':{r:p.stable_binding(v)for r,v in cohort.items()},'unchangedApplications':{r:p.stable_binding(v)for r,v in cohort.items()if r!='onboarding'},
        'targetRoles':['onboarding'],'replacements':{'onboarding':replacement},'boundDatabaseProfile':copy.deepcopy(retained['boundDatabaseProfile']),
        'nativeFlywayConfiguration':copy.deepcopy(retained['nativeFlywayConfiguration']),'candidateApplicationFacts':copy.deepcopy(facts),
        'databaseMigration':{'from':36,'to':38,'newMigrations':2,'newMigrationFacts':copy.deepcopy(case['additionalMigrations'])},
        'retainedCaptureAccounting':copy.deepcopy(result['captureAccounting']),'retainedOwnershipReadHash':case['ownershipReadHash'],
        'futureRequirements':['NEW_CURRENT_RUNTIME_NETWORK_OWNER_ADMISSION','EXACT_SCHEMA36_HISTORY_AND_FAILED5_ZERO_RECOVERY_STATE',
            'CURRENT_OVERLAY_PROCESS_ROOT_AND_SCOPE_PRECEDENCE','VERIFIED_QUIESCED_BACKUP','NEW_CONCRETE_HUMAN_REVIEW_AND_FINITE_SIGNED_AUTHORITY',
            'PRESERVE_ALL_RETAINED_OPERATIONAL_ROWS_AND_EMPTY_NEW_OWNER_RECEIPTS','SEPARATE_HUMAN_OWNERSHIP_THEN_BUDGET_THEN_RESUME'],
        'executionEntryQualified':False,'currentRuntimeRevalidated':False,'databaseAdmissionProven':False,'currentJobOrBudgetStateObserved':False,
        'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'imageImportAuthorized':False,'newGrantsAuthorized':False,
        'humanOwnershipOrBudgetOrResumeAuthorized':False,'sourceActivationAuthorized':False,'databaseRestoreAuthorized':False,
        'automaticRollbackAllowed':False,'automaticReplayAllowed':False,'budgetReset':False,'applicationE2EProven':False,'releaseAcceptance':False}

def prepare(scope,case,receipt,zip_path,p,mac,custody,unpack):
    root=Path(case['captureRoot']);inputs=scope.private(root/'inputs.json',case['captureHash'])
    result=scope.private(root/'result.json',case['captureResultHash']);info=scope.private(root/'engine-get-1-response.json')
    validate_capture(inputs,result,info,case)
    require(digest(receipt)==case['imageReceiptHash'],'EXACT_IMAGE_RECEIPT_REQUIRED')
    require(shutil.disk_usage(scope.root).free>=2*1024*1024*1024,'TWO_GIB_FREE_IMAGE_CUSTODY_REQUIRED')
    require(scope.counts['ciZipReads']==0,'ONE_EXACT_ZIP_ONLY')
    archive=common.stage_native(scope,'onboarding',zip_path,receipt,unpack,custody)
    plan=compile_plan(inputs,result,info,receipt,archive,p,mac,case);put(scope.root/'execution-plan.json',plan)
    private={'schema':'ouf.managed-file-owner-recovery-private-execution-inputs.v1','capturedInputsHash':case['captureHash'],
        'currentCapture':inputs,'conditionalNativePlanHash':digest(plan),'nativeArchives':{'onboarding':archive},'imageAudits':{'onboarding':receipt['imageAudit']},
        'historySeals':scope.seals,'conditionalLifecyclePlanCompiled':True,'executionEntryQualified':False,'runtimeAuthorityIssued':False,
        'targetUpdateAuthorized':False,'currentRuntimeRevalidated':False,'automaticReplayAllowed':False,'budgetReset':False,'applicationE2EProven':False,'releaseAcceptance':False}
    for seal in scope.seals:require(list(frame(Path(seal['path']).lstat()))==seal['metadata'],'RETAINED_METADATA_SEAL_CHANGED')
    put(scope.root/'execution-inputs.json',private)
    output={'schema':'ouf.managed-file-owner-recovery-image-plan-result.v1','status':'MANAGED_FILE_OWNER_RECOVERY_IMAGE_AND_CONDITIONAL_PLAN_PREPARED_NOT_AUTHORIZED',
        'complete':True,'contextPath':str(scope.root),'capturedInputsHash':case['captureHash'],'executionInputsHash':digest(private),'conditionalNativePlanHash':digest(plan),
        'counts':dict(scope.counts),'cohortSize':13,'targetRoles':['onboarding'],'unchangedPeers':12,'candidateNativeImageId':receipt['nativeImageId'],
        'candidateSourceCommit':receipt['sourceCommit'],'databaseMigration':{'from':36,'to':38,'newMigrations':2},'retainedCaptureAccounting':result['captureAccounting'],
        'conditionalLifecyclePlanCompiled':True,'executionEntryQualified':False,'currentRuntimeRevalidated':False,'databaseAdmissionProven':False,
        'currentJobOrBudgetStateObserved':False,'runtimeAuthorityIssued':False,'targetUpdateAuthorized':False,'ownerConfigurationContentReads':0,
        'credentialFileReads':0,'signingKeyReads':0,'sqlSessions':0,'iamRequests':0,'oauthRequests':0,'gatewayRequests':0,'registryWorkerTouched':False,
        'newGrantsGranted':0,'humanOwnershipReceiptsCreated':0,'humanBudgetsGranted':0,'resumes':0,'newJobs':0,'uploads':0,'acquisitionsExecuted':0,'sourceActivations':0,
        'historicalAuthorityReused':False,'automaticReplayAllowed':False,'budgetReset':False,'applicationE2EProven':False,'releaseAcceptance':False}
    put(scope.root/'result.json',output);return output
