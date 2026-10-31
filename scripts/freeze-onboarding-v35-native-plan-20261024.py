#!/usr/bin/env python3
"""Verify current retained configuration and freeze a proposal, never apply it.

Reuses the exact original configuration verifier and replacement compiler with
the sealed named-custody reader. Four exact GETs, one owner configuration file,
no SQL, signing key, Docker write, old entrypoint or grant/activation.
"""
import ast,copy,hashlib,ipaddress,json,os,re,signal,stat,sys,tarfile,time,types,zipfile
from pathlib import Path
from urllib.parse import urlsplit
HELPER='/etc/ouf/deploy-snapshots/onboarding-budget-v35-54d86bbcd2ea47fd/prepare.py'
HELPER_HASH='1ce4105cb54b6e9dd6ab7579f605b6270a51607f91ee871224be176ad5da83b7'
PROPOSAL='/etc/ouf/deploy-snapshots/onboarding-budget-v35-54d86bbcd2ea47fd/review-inputs-v1/review-inputs.json'
PROPOSAL_HASH='d52bb83265daff3d07ce04131249c0ab7465315ef35e83af13115ad79c5a1a0e'
CONFIG_HASH='d3bb5a29d4e0e626cd34c797326e868050c3c16421901357faa8c73b48e83018'
REPLACEMENT_HASH='df3261a259b405f73e646b93f178d24435246cb3b32dcd214dfef61cf645f3f5'
OWNER_OVERLAY='/opt/ouf/secrets/onboarding-ths.yaml'
SCOPE='native-plan-v1'
STAGES=('VERIFY_CURRENT_ADMISSION_AND_SIGNED_REVIEW','IMPORT_EXACT_IMAGE','DISABLE_OLD_RESTART','STOP_OLD_ONBOARDING',
 'VERIFY_QUIESCED_BACKUP','DETACH_OLD_ENDPOINT','RENAME_OLD','CREATE_REPLACEMENT','START_REVIEWED_V35_REPLACEMENT',
 'VERIFY_READINESS_AND_EXACT_V35_HISTORY','VERIFY_RETAINED_SOURCE_COUNTERS_AND_ZERO_BUDGET_SESSIONS','RESTORE_RESTART_POLICY','VERIFY_FINAL')
COUNTS={'engineGetAttempts':0,'ownerConfigurationFileContentReads':0}
class Stop(RuntimeError):pass
def require(ok,reason):
    if not ok:raise Stop(reason)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(v):return hashlib.sha256(encoded(v)).hexdigest()
def protected_source(path,expected):
    p=Path(path);require(p.is_absolute()and p.resolve()==p,'EXACT_PROTECTED_PLANNER_SOURCE_REQUIRED')
    for parent in p.parents:
        s=parent.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022,'ROOT_SOURCE_ANCESTRY_REQUIRED')
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        s=os.fstat(fd);identity=lambda v:tuple(getattr(v,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
        require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o400
            and s.st_nlink==1 and 0<s.st_size<=131072,'PRIVATE_PLANNER_SOURCE_REQUIRED')
        raw=os.read(fd,131073);require(len(raw)==s.st_size and hashlib.sha256(raw).hexdigest()==expected
            and identity(s)==identity(os.fstat(fd))==identity(p.lstat()),'EXACT_PLANNER_SOURCE_BYTES_REQUIRED')
    finally:os.close(fd)
    return raw
def definitions(raw,names,namespace):
    tree=ast.parse(raw);selected=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in names]
    require({n.name for n in selected}==set(names)and len(selected)==len(names),'EXACT_ORIGINAL_FUNCTION_DEFINITIONS_REQUIRED')
    exec(compile(ast.Module(body=selected,type_ignores=[]),'<pinned-original-onboarding-definitions>','exec'),namespace)
    return types.SimpleNamespace(**{n:namespace[n]for n in names})
def bootstrap():
    raw=protected_source(HELPER,HELPER_HASH);p=types.ModuleType('verified_v35_review_input_definitions');p.__file__=HELPER
    exec(compile(raw,HELPER,'exec'),p.__dict__)
    q,l,c,d,m,r=p.bootstrap();m.raw(str(Path(__file__).resolve()),131072)
    root=Path(__file__).resolve().parent
    config=protected_source(root/'configuration.py',CONFIG_HASH)
    replacement=protected_source(root/'replacement.py',REPLACEMENT_HASH)
    return p,q,l,c,d,m,r,config,replacement
def configuration_verifier(raw,d,p,m,expected,jar):
    from tools.chatbot_file_cohort.gateway import private_config
    def selected(path):
        require(path==OWNER_OVERLAY==expected['path'],'ONLY_EXACT_RETAINED_OWNER_OVERLAY_MAY_BE_READ')
        require(COUNTS['ownerConfigurationFileContentReads']<2,'TWO_BOUND_OWNER_CONFIGURATION_READS_ONLY')
        COUNTS['ownerConfigurationFileContentReads']+=1
        return private_config(path,expected)
    def jar_file(path,checksum,maximum):
        require(path==jar['path']and checksum==jar['sha256']and maximum==268435456,'ONLY_EXACT_CANDIDATE_JAR_MAY_BE_READ')
        return p.hash_file(m,path,maximum,checksum)
    namespace={'hashlib':hashlib,'json':json,'os':os,'Path':Path,'re':re,'urlsplit':urlsplit,'zipfile':zipfile,
        'require':require,'env':lambda rows:d.environment({'Config':{'Env':rows}}),'private_file':jar_file,'private_config':selected}
    return definitions(raw,('application_json_metadata','owner_json_overlay','overlay_text','additional_location','verify'),namespace)
def image_configuration(m,contract):
    name='blobs/sha256/'+contract['imageId'][7:];found=None
    with m.opened(Path(m.PACKAGE)/'image.tar.gz',contract['archiveBytes'])as(fd,_),os.fdopen(os.dup(fd),'rb')as stream,tarfile.open(fileobj=stream,mode='r|gz')as archive:
        for row in archive:
            if row.name not in(name,contract['imageId'][7:]+'.json'):continue
            require(found is None and row.isfile()and 0<row.size<=1048576,'ONE_EXACT_IMAGE_CONFIG_REQUIRED')
            raw=archive.extractfile(row).read(1048577);require(hashlib.sha256(raw).hexdigest()==contract['imageId'][7:],'EXACT_IMAGE_CONFIG_HASH_REQUIRED')
            found=m.decode(raw)
    require(type(found)is dict and found['os']=='linux'and found['architecture']=='amd64'
        and found['config']['User']=='10003:10003','EXACT_NONROOT_IMAGE_CONFIGURATION_REQUIRED')
    return found['config']
def compile_replacement(raw,actual,saved,contract,manifest,config):
    from engine_creation import requested_host_config_matches
    from image_custody import runtime_image_id
    from tools.ingestion_readiness_patch_execution import runtime_bindings
    compiler=definitions(raw,('replacement',),{'copy':copy,'ipaddress':ipaddress,'re':re,'require':require,'digest':digest,
        'runtime':lambda row:runtime_bindings.observed(row,runtime_bindings.SORTED),'runtime_image_id':runtime_image_id,
        'requested_host_config_matches':requested_host_config_matches})
    selected={'module':'onboarding','name':saved['name'],'creationRequest':saved['request'],'restoreRestartPolicy':saved['restoreRestartPolicy']}
    image={'imageAudit':{'imageId':contract['imageId'],'imageConfig':config,'sourceCommit':manifest['reviewedSourceCommit']},
        'imageArchive':{'path':str(Path(HELPER).parent/'image.tar.gz'),'sha256':contract['archiveSha256']}}
    case={'deployedSourceCommits':{'onboarding':'b0f5e3dacbe59ebf87e22dd6af2575e41249f51d'},
        'candidateSourceCommits':{'onboarding':manifest['testedCommit']},'readiness':{'onboarding':saved['readiness']}}
    result=compiler.replacement(selected,actual,image,case,'onboarding')
    require(result['request']['Env']==actual['Config']['Env'],'CURRENT_ENVIRONMENT_MUST_BE_BYTE_EQUIVALENT')
    return result
def freeze(p,q,l,c,d,m,r,config_raw,replacement_raw):
    from tools.ingestion_readiness_patch_execution import runtime_bindings
    require(not os.path.lexists(Path(p.PACKAGE)/SCOPE),'V35_NATIVE_PLAN_ALREADY_CLAIMED_NO_REPLAY')
    root=r.exclusive_root(p.PACKAGE,SCOPE)
    m.new_file(root,'claim.json',{'schema':'ouf.onboarding-v35-native-plan-claim.v1','proposalHash':PROPOSAL_HASH,
        'maximumEngineGets':4,'maximumSeconds':90,'maximumOwnerConfigurationFileContentReads':2,'sqlAllowed':False,
        'runtimeEffectsAllowed':False,'automaticReplayAllowed':False,'budgetReset':False})
    files=m.Facts();proposal=files.json(PROPOSAL,PROPOSAL_HASH);completion=files.json(Path(PROPOSAL).parent/'complete.json')
    require(proposal['schema']=='ouf.onboarding-v35-private-review-inputs.v1'and proposal['kind']=='PROPOSAL_NOT_EXECUTABLE_AUTHORITY'
        and proposal['targetApplyAuthorized']is False and proposal['runtimeAuthorityIssued']is False
        and completion['privateReviewInputsHash']==PROPOSAL_HASH and completion['complete']is True,'EXACT_COMPLETED_V35_REVIEW_INPUTS_REQUIRED')
    for ref in proposal['retainedFiles']:files.json(ref['path'],ref['sha256'])
    history=proposal['historyAssessment'];schema=proposal['schemaAssessment']
    require(history['all34SqlMigrationChecksumsMatchCandidate']is True and history['allHistoryRowsSuccessful']is True
        and history['nonSqlHistoryTypesRecognized']is True and history['v35AlreadyRecorded']is False
        and all(schema.values())and proposal['capacitySnapshotHasHeadroom']is True,'RETAINED_V35_PREREQUISITE_ASSESSMENT_REQUIRED')
    inputs=files.json(d.INPUT,d.INPUT_HASH);require(inputs['bootId']==Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'SAME_CURRENT_PLAN_BOOT_REQUIRED')
    old=files.json(proposal['currentOwnerPlanBinding']['path'],proposal['currentOwnerPlanBinding']['sha256'])
    require(old['authorityDirectory']==q.OWNER and old['schema']=='ouf.installation-binding-owner-update-plan.v1','EXACT_RETAINED_B0_OWNER_PLAN_REQUIRED')
    contract,manifest,image,jar=p.packaged(m,files)
    # The package path is explicit; do not repurpose the old metadata helper's
    # package constant, whose consumed scopes and staged image remain untouched.
    class CurrentImageFiles:
        PACKAGE=p.PACKAGE
        opened=staticmethod(m.opened)
        decode=staticmethod(m.decode)
    config=image_configuration(CurrentImageFiles,contract)
    engine=m.Engine(inputs['engineBinding'],{v['containerId']for v in inputs['currentBindings'].values()},root)
    def current(name):
        require(engine.calls<4,'FOUR_EXACT_NATIVE_PLAN_ENGINE_GETS_ONLY')
        try:row,ref=engine.get(inputs['currentBindings'][name]['containerId'])
        finally:COUNTS['engineGetAttempts']=engine.calls
        require(runtime_bindings.observed(row,runtime_bindings.NATIVE)==inputs['currentBindings'][name]
            and m.process(row)==inputs['currentProcessIdentities'][name]and row['RestartCount']==inputs['restartCounts'][name],
            'CURRENT_PLAN_APPLICATION_GENERATION_CHANGED')
        return row,ref
    actual,appref=current('onboarding');postgres,pgref=current('postgres')
    overlays=old['nativeFlywayConfiguration']['ownerOverlays'];require(len(overlays)==1 and overlays[0]['binding']['path']==OWNER_OVERLAY,
        'ONE_PREVIOUSLY_BOUND_NAMED_OWNER_CONFIGURATION_REQUIRED')
    verify=configuration_verifier(config_raw,d,p,m,overlays[0]['binding'],jar)
    identity=proposal['boundDatabaseProfile']['identity']
    binding={'user':identity['runtimeRole'],'database':identity['database'],'schema':identity['schema']}
    candidate={'jar':{'path':jar['path'],'sha256':jar['sha256']}}
    configuration=verify.verify(actual,candidate,postgres,binding,identity['postgresPort'],contract['applicationYamlSha256'])
    require(configuration==old['nativeFlywayConfiguration'],'CURRENT_CONFIGURATION_MUST_MATCH_COMPLETED_OWNER_CLASSIFICATION')
    replacement=compile_replacement(replacement_raw,actual,old['replacements']['onboarding'],contract,manifest,config)
    require(m.lifecycle_declaration(actual)=='NO_RECOGNIZED_MANAGER_LABEL','CURRENT_MANAGER_DECLARATION_REQUIRES_REVIEW')
    logical=digest({'oldRuntimeBinding':inputs['currentBindings']['onboarding'],'candidateArchive':image['sha256'],
        'selectedSourceConfiguration':d.CONFIGURATION,'proposalHash':PROPOSAL_HASH})
    plan={'schema':'ouf.onboarding-v35-frozen-native-plan.v1','kind':'FROZEN_PROPOSAL_NOT_EXECUTABLE_AUTHORITY',
        'proposalHash':PROPOSAL_HASH,'inputHash':d.INPUT_HASH,'logicalOperationRef':logical,'bootId':inputs['bootId'],
        'proposedAuthorityDirectory':'/etc/ouf/deploy-snapshots/onboarding-v35-apply-'+logical,
        'sourceClosure':{'plannerSha256':hashlib.sha256(m.raw(str(Path(__file__).resolve()),131072)).hexdigest(),
            'configurationSha256':CONFIG_HASH,'replacementCompilerSha256':REPLACEMENT_HASH,'protectedHelperSha256':HELPER_HASH},
        'engine':inputs['engineBinding'],'replacements':{'onboarding':replacement},
        'unchangedApplications':{k:v for k,v in inputs['currentBindings'].items()if k!='onboarding'},
        'nativeFlywayConfiguration':configuration,'boundDatabaseProfile':proposal['boundDatabaseProfile'],
        'databaseMigration':{**proposal['proposedMigration'],'from':34,'to':35,'owner':'EXPLICIT_REVIEWED_APPLICATION_FLYWAY'},
        'databaseBeforeSnapshotBinding':{'path':str(Path(p.SNAPSHOT)),'sha256':p.SNAPSHOT_HASH},
        'retainedSource':{'sourceId':d.SOURCE,'version':d.VERSION,'configurationHash':d.CONFIGURATION,'attempts':3,'generation':4,'phase':'PAUSED'},
        'stages':[{'ordinal':i,'name':name,'intentHash':digest({'logicalOperationRef':logical,'stage':name})}for i,name in enumerate(STAGES)],
        'currentRuntimeObservations':{'onboarding':appref,'postgres':pgref},'capturedAt':int(time.time()),
        'backupMustBeQuiescedAndVerified':True,'existingEnvironmentMountsEndpointAndOtherLabelsPreserved':True,
        'migrationConfigurationChanged':False,'freshDatabaseAdmissionRequiredAtApply':True,'newBudgetOrActivationAuthorized':False,
        'applyEntryQualified':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'databaseAdmissionProven':False,
        'lifecycleMutationAuthorized':False,'automaticRollbackAllowed':False,'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False,
        'retainedFiles':list(files.files.values())}
    current('postgres');current('onboarding');files.recheck()
    require(configuration==verify.verify(actual,candidate,postgres,binding,identity['postgresPort'],contract['applicationYamlSha256']),
        'OWNER_CONFIGURATION_CHANGED_DURING_PLAN_FREEZE')
    m.new_file(root,'execution-plan.json',plan)
    result={'schema':'ouf.onboarding-v35-native-plan-result.v1','status':'ONBOARDING_V35_CURRENT_CONFIGURATION_AND_PLAN_FROZEN','complete':True,
        'privatePlanPath':str(root/'execution-plan.json'),'privatePlanHash':digest(plan),'stageCount':len(STAGES),
        **COUNTS,'maximumEngineGets':4,'maximumOwnerConfigurationFileContentReads':2,
        'allCurrentConfigurationPrecedenceResolved':True,'namedExistingCustodyVerified':True,'ownerConfigurationHashMatchesRetained':True,
        'packagedSpringConfigurationVerified':True,'currentOnboardingAndPostgresStable':True,'exactReplacementRequestCompiled':True,
        'environmentMountsEndpointAndOtherLabelsPreserved':True,'migrationConfigurationChanged':False,
        'newMigrationVersion':35,'newMigrationFlywayChecksum':1095739786,'selectedReadinessAttempts':3,'selectedReadinessGeneration':4,
        'databaseAdmissionProven':False,'databaseSnapshotFreshForApplyProven':False,'applyEntryQualified':False,
        'lifecycleMutationAuthorized':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
        'sqlSessionAttempts':0,'containerExecAttempts':0,'imageLoaded':False,'databaseMigrations':0,'sourceActivations':0,
        'humanBudgetsGranted':0,'bearerFilesOpened':0,'privateSigningKeysRead':0,'credentialValuesPrinted':False,'addressesPrinted':False,
        'ownerConfigurationMayContainSensitiveValues':True,'ownerConfigurationValuesRetainedPrivately':True,
        'otherCredentialFilesOpened':0,'originalRequestRepeated':False,'retainedContextWrites':0,'runtimeEffectsDispatched':0,
        'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}
    m.new_file(root,'complete.json',result);return result
def main():
    try:
        require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
            and len(sys.argv)==1,'ONE_ISOLATED_ROOT_NATIVE_PLAN_FREEZE_REQUIRED')
        signal.signal(signal.SIGALRM,lambda *_:(_ for _ in()).throw(Stop('NATIVE_PLAN_FREEZE_DEADLINE')));signal.alarm(90)
        result=freeze(*bootstrap())
    except Exception as error:
        reason=str(error)if type(error).__name__in('Stop','Denied','PlanDenied')and re.fullmatch('[A-Z0-9_]{1,120}',str(error))else'CURRENT_NATIVE_PLAN_UNPROVEN'
        result={'schema':'ouf.onboarding-v35-native-plan-result.v1','status':'STOP_RECONCILE','complete':False,'reasonCode':reason,
            'attemptsNotCompletion':dict(COUNTS),'privatePreparationMayBePartial':True,'sqlSessionAttempts':0,'runtimeEffectsDispatched':0,
            'imageLoaded':False,'databaseMigrations':0,'sourceActivations':0,'humanBudgetsGranted':0,'targetApplyAuthorized':False,
            'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}
    finally:signal.alarm(0)
    print(encoded(result).decode(),flush=True);return 0 if result.get('complete')is True else 2
if __name__=='__main__':raise SystemExit(main())
