"""Deterministic one-Ingestion review from the authenticated private input bundle."""
import copy
import image_custody
from tools.ingestion_readiness_patch_execution import contract as c, runtime_bindings, runtime_guard
from tools.ingestion_readiness_patch_execution import owner_read, database_read, image_import, gateway_transport, readiness, human_reader

def compile_review(bundle,binding,human_binding,execution_context,*,human_read_profile=None):
    c.require(bundle.get('schema')=='ouf.ingestion-readiness-patch-native-inputs.v1'
        and bundle.get('kind')=='PRIVATE_NATIVE_INPUTS_NOT_EXECUTABLE_AUTHORITY'
        and all(bundle.get(k) is False for k in ('nativeRuntimeExecutorQualified','targetApplyAuthorized',
            'runtimeAuthorityIssued','automaticReplayAllowed','budgetReset','sourceActivationAllowed','releaseAcceptance'))
        and binding.get('sha256')==c.digest(bundle) and c.path(binding['path']), 'EXACT_UNAUTHORIZED_PATCH_INPUT_BUNDLE_REQUIRED')
    frames={'ingestion':copy.deepcopy(bundle['ingestionFrame'])};image=bundle['candidate']
    before=bundle['beforeIngestion'];rootfs=image['RootFS']
    c.require(rootfs['Type']=='layers' and type(rootfs['Layers']) is list and rootfs['Layers']
              and all(type(v) is str and v.startswith('sha256:') and c.hashed(v[7:]) for v in rootfs['Layers']),
              'EXACT_CANDIDATE_ROOTFS_REQUIRED')
    archive=bundle['candidateFileBindings']['image.tar.gz']
    packet={'schema':'ouf.ingestion-readiness-patch-private-packet.v1','nativeInputs':copy.deepcopy(bundle),
        'frames':frames,'expectedRuntimeBindings':{'ingestion':runtime_bindings.observed(before,runtime_bindings.SORTED)},
        'candidate':{'nativeImageId':image_custody.runtime_image_id(bundle['nativeArchiveAudit']),'configurationImageId':image['Id'],
            'sourceCommit':image['Config']['Labels']['org.opencontainers.image.revision'],
            'imageConfig':copy.deepcopy(image['Config']),'rootfs':{'type':'layers','diff_ids':copy.deepcopy(rootfs['Layers'])},
            'nativeArchiveBinding':{k:archive[k] for k in ('path','sha256','metadata')}},
        'retainedGatewayConfig':{k:bundle['unchangedGatewayTransportProfile']['config'][k] for k in ('path','sha256','metadata')},
        'routeDraft':{'beforeRoutes':copy.deepcopy(bundle['unchangedGatewayRoutes']),
                      'afterRoutes':copy.deepcopy(bundle['unchangedGatewayRoutes'])},
        'runtimeAuthorityIssued':False,'targetApplyAuthorized':False}
    native={'schema':'ouf.ingestion-readiness-patch-execution-review.v1','profile':c.PROFILE,
        'preparedInputs':copy.deepcopy(bundle),'preparedInputsHash':c.digest(bundle),
        'preparedInputsBinding':copy.deepcopy(binding),'packetBinding':{'path':c.path(execution_context)+'/packet.json','sha256':c.digest(packet)},
        'executionContext':execution_context,'humanBinding':copy.deepcopy(human_binding),
        'logicalOperationRef':bundle['finiteIntentContract']['logicalOperationRef'],'stages':c.stages(bundle),
        'maximumExecutionSeconds':900,'maximumEffectAttemptsPerStage':1,'maximumGatewayPuts':0,
        'maximumSecretCreations':0,'maximumImageImports':1,'readinessPolicy':copy.deepcopy(c.READINESS),
        **{k:False for k in c.FORBIDDEN},'runtimeAuthorityIssued':False,'nativeProfilePublished':False,
        'completedTechnicalPhases':8,'functionalMilestonesProven':4,'notReleaseAcceptance':True,
        'engineBinding':copy.deepcopy(bundle['engineBinding']),
        'runtimeGuardProfile':{'schema':'ouf.ingestion-readiness-patch-runtime-guard.v1',
            'beforeContainers':{'ingestion':copy.deepcopy(before)},
            'unchangedApplications':copy.deepcopy(bundle['unchangedApplications'])},
        'ownerControlProfile':copy.deepcopy(bundle['ownerControlProfile']),
        'databaseControlProfile':copy.deepcopy(bundle['databaseControlProfile']),
        'imageImportProfile':copy.deepcopy(bundle['imageImportProfile']),
        'gatewayTransportProfile':copy.deepcopy(bundle['unchangedGatewayTransportProfile']),
        'ingestionReadinessProfile':copy.deepcopy(bundle['ingestionReadinessProfile']),
        'maximumOwnerGetAttempts':512,'maximumDatabaseReadSessions':128,'maximumGatewayGetAttempts':512,
        'maximumIngestionReadinessGets':128,'maximumDirectEngineGets':4096,
        'maximumDirectEnginePosts':6+len(frames['ingestion']['requestTemplate']['NetworkingConfig']['EndpointsConfig']),
        'nativeExecutorQualified':False,'representativeQualificationRequired':True}
    if human_read_profile is not None:native['humanReadProfile']=copy.deepcopy(human_read_profile)
    validate_profiles(native,packet);c.scope(native)
    return native,packet

def validate_profiles(review,packet):
    runtime_guard.validate_profile(review['runtimeGuardProfile'],packet)
    owner=owner_read.validate_profile(review['ownerControlProfile'])
    db=database_read.validate_profile(review['databaseControlProfile'])
    image_import.validate_profile(review['imageImportProfile'],packet)
    gateway_transport.validate_profile(review['gatewayTransportProfile'])
    readiness.validate_profile(review['ingestionReadinessProfile'])
    c.require(review['engineBinding']==db['engineBinding']==review['imageImportProfile']['engineBinding']
        and all(db[k]==review['imageImportProfile'][k] for k in ('dockerExecutable','dockerConfigDirectory','dockerConfigIdentity')),
        'SAME_PATCH_ENGINE_AND_CREDENTIAL_FREE_CLI_REQUIRED')
    pin=review['runtimeGuardProfile']['unchangedApplications']['onboarding']
    # Both encodings are checked against their own live inspect at execution.
    # Preserve their hashes; never rewrite sorted/native mount-order bindings.
    common=set(pin['binding'])-{'mountsHash'}
    c.require(all(owner['runtimeBinding'][k]==pin['binding'][k] for k in common)
        and owner['restartCount']==pin['restartCount']
        and (owner['runtimeBindingProfile']!=pin['bindingProfile']
             or owner['runtimeBinding']==pin['binding']), 'SAME_UNCHANGED_OWNER_PROFILE_REQUIRED')
    ids={p['binding']['containerId'] for p in review['runtimeGuardProfile']['unchangedApplications'].values()}
    ids.add(packet['expectedRuntimeBindings']['ingestion']['containerId'])
    c.require(db['postgresRuntimeBinding']['containerId'] not in ids,'DISTINCT_POSTGRES_RUNTIME_REQUIRED')
    if review.get('humanReadProfile') is not None:
        p=human_reader.validate(review['humanReadProfile'])
        c.require(p['expectedBinding']==review['humanBinding'] and p['minimumCumulativeAttempts']>=292,
                  'PATCH_HUMAN_CANNOT_RESET292_HISTORY')

def validate_review(review,packet):
    c.scope(review)
    profile=review.get('humanReadProfile')
    expected,expected_packet=compile_review(review['preparedInputs'],review['preparedInputsBinding'],
        review['humanBinding'],review['executionContext'],human_read_profile=profile)
    c.require(c.encoded(review)==c.encoded(expected) and c.encoded(packet)==c.encoded(expected_packet),
              'EXACT_DETERMINISTIC_PATCH_REVIEW_AND_PACKET_REQUIRED')
    return review
