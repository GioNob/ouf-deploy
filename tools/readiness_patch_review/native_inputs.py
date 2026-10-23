"""Offline projection of retained, completed review into one-Ingestion native inputs.

This is a private preparation artifact, never an executor or an authority issuer.
No runtime port, HUMAN session, key or bearer is opened by this program.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import sys
import types

COMPILER_SHA = '7d81a5dd8f23c1f3cb927c6a5195daf1b1f55340b8abb0aedf2cafad3322e5ae'
PROFILE = 'ouf.ingestion-readiness-patch-native-inputs.v1'


def require(ok, code):
    if not ok:
        raise ValueError(code)


def load(root):
    fd = os.open(root / 'compiler.py', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        raw = os.read(fd, 65537)
        require(hashlib.sha256(raw).hexdigest() == COMPILER_SHA, 'QUALIFIED_REVIEW_COMPILER_REQUIRED')
    finally:
        os.close(fd)
    module = types.ModuleType('qualified_review_compiler')
    exec(compile(raw, '<qualified-review-compiler>', 'exec'), module.__dict__)
    return module, module.load_support(root)


def stage_contract(io, review):
    stages = review['stages']
    endpoints = review['frame']['requestTemplate']['NetworkingConfig']['EndpointsConfig']
    require(type(endpoints) is dict and 1 <= len(endpoints) <= 8
            and len({e['NetworkID'] for e in endpoints.values()}) == len(endpoints),
            'BOUNDED_DISTINCT_PATCH_NETWORKS_REQUIRED')
    names = ['VERIFY_CURRENT_GATES', 'IMPORT_INGESTION_IMAGE', 'ingestion.DISABLE_OLD_RESTART',
             'ingestion.STOP_OLD'] + ['ingestion.DETACH_NETWORK.' + str(i) for i in range(1, len(endpoints) + 1)]
    names += ['ingestion.RENAME_OLD', 'ingestion.CREATE_REPLACEMENT', 'ingestion.START_REPLACEMENT',
              'ingestion.READINESS', 'VERIFY_FINAL', 'ingestion.RESTORE_RESTART', 'VERIFY_RESTORED_FINAL']
    require([s['name'] for s in stages] == names
            and all(s['intentHash'] == io.digest(s['intent']) for s in stages),
            'EXACT_RETAINED_ORDERED_PATCH_INTENTS_REQUIRED')
    reads = {'VERIFY_CURRENT_GATES', 'ingestion.READINESS', 'VERIFY_FINAL', 'VERIFY_RESTORED_FINAL'}
    require(all(s['kind'] == ('READ' if s['name'] in reads else 'EFFECT') for s in stages),
            'EXACT_PATCH_READ_EFFECT_BOUNDARY_REQUIRED')
    require(review['kind'] == 'PRIVATE_TEMPLATE_NOT_EXECUTABLE_AUTHORITY'
            and review['nativeRuntimeExecutorQualified'] is False
            and review['requiresSeparateNativeExecutorQualification'] is True
            and review['freshInfrastructureConsentRequired'] is True
            and review['freshHumanOwnerDatabaseGatesRequired'] is True
            and review['runtimeAuthorityIssued'] is review['targetApplyAuthorized'] is False
            and review['automaticReplayAllowed'] is review['automaticRollbackAllowed'] is False
            and review['budgetReset'] is review['releaseAcceptance'] is False
            and review['sourceActivationAllowed'] is review['explicitJobDispatchAllowed'] is False
            and all(type(review[k]) is int and review[k] == 0 for k in
                    ('migrationChanges', 'gatewayLifecycleOperations', 'gatewayWrites', 'grantChanges', 'ownerMutations')),
            'PREPARATION_CANNOT_GRANT_OR_EXPAND_PATCH_AUTHORITY')
    old_id, image = review['oldContainerId'], review['candidateMetadata']['imageId']
    logical = io.digest({'operation': 'INGESTION_READINESS_WORKLOAD_PATCH',
                         'oldContainerId': old_id, 'candidateImageId': image})
    require(review['logicalOperationRef'] == logical, 'SAME_PATCH_LOGICAL_OPERATION_REQUIRED')
    return {'schema': 'ouf.ingestion-readiness-patch-finite-intents.v1',
            'logicalOperationRef': logical, 'stages': copy.deepcopy(stages),
            'maximumExecutionSeconds': 900, 'maximumReadAttempts': 128,
            'maximumEffectAttemptsPerStage': 1, 'maximumImageImports': 1,
            'maximumEnginePosts': 6 + len(endpoints), 'maximumGatewayWrites': 0,
            'maximumSecretCreations': 0, 'maximumOwnerMutations': 0,
            'budgetReset': False, 'automaticReplayAllowed': False, 'automaticRollbackAllowed': False,
            'runtimeAuthorityIssued': False, 'nativeRuntimeExecutorQualified': False}


def project(io, review, snapshot, retained, packet, candidate):
    contract = stage_contract(io, review)
    before = snapshot['runtimeBefore']
    require(set(before) == {'ingestion', 'gateway', 'onboarding', 'mcp', 'udp', 'postgres'}
            and len({v['Id'] for v in before.values()}) == 6
            and before['ingestion']['Id'] == review['oldContainerId'],
            'SIX_DISTINCT_CAPTURED_RUNTIME_GENERATIONS_REQUIRED')
    native = retained['executionReview']
    for name, pin in native['runtimeGuardProfile']['unchangedApplications'].items():
        require(name in ('onboarding', 'mcp', 'udp')
                and io.stable(before[name], pin['bindingProfile']) == pin['binding']
                and before[name]['RestartCount'] == pin['restartCount'],
                'RETAINED_UNCHANGED_APPLICATION_BINDING_REQUIRED')
    require(set(native['runtimeGuardProfile']['unchangedApplications']) == {'onboarding', 'mcp', 'udp'},
            'EXACT_THREE_RETAINED_UNCHANGED_APPLICATIONS_REQUIRED')
    db = native['databaseControlProfile']
    require(io.stable(before['postgres'], db['runtimeBindingProfile']) == db['postgresRuntimeBinding']
            and before['postgres']['RestartCount'] == db['postgresRestartCount'],
            'RETAINED_POSTGRES_GENERATION_REQUIRED')
    owner = native['ownerControlProfile']
    require(io.stable(before['onboarding'], owner['runtimeBindingProfile']) == owner['runtimeBinding']
            and before['onboarding']['RestartCount'] == owner['restartCount'],
            'RETAINED_ONBOARDING_OWNER_GENERATION_REQUIRED')
    for value in before.values():
        require(value['State']['Running'] is True and value['State']['Paused'] is False
                and value['State']['Restarting'] is False and value['State']['Pid'] > 0,
                'CAPTURED_RUNNING_GENERATIONS_REQUIRED')
    import_profile = copy.deepcopy(native['imageImportProfile'])
    import_profile['archive'] = copy.deepcopy(review['candidateFileBindings']['image.tar.gz'])
    require(native['engineBinding'] == db['engineBinding'] == import_profile['engineBinding'],
            'SINGLE_RETAINED_ENGINE_CHANNEL_REQUIRED')
    gateway = copy.deepcopy(native['gatewayTransportProfile'])
    require({k: gateway['config'][k] for k in ('path', 'sha256', 'metadata')} == packet['retainedGatewayConfig'],
            'COMPLETED_GATEWAY_STAGED_CONFIG_REQUIRED')
    routes = packet['routeDraft']['afterRoutes']
    require(type(routes) is dict and len(routes) == 82 and all(k in routes for k in
            ('mcp-ingestion-history', 'mcp-ingestion-status')), 'EXACT_COMPLETED_GATEWAY_ROUTE_MAP_REQUIRED')
    require(candidate['Id'] == review['candidateMetadata']['imageId']
            and candidate['Os'] == 'linux' and candidate['Architecture'] == 'amd64'
            and candidate['Config']['Labels']['org.opencontainers.image.revision']
                == review['candidateMetadata']['sourceCommit'], 'EXACT_REVIEWED_CANDIDATE_INSPECT_REQUIRED')
    return {'schema': PROFILE, 'kind': 'PRIVATE_NATIVE_INPUTS_NOT_EXECUTABLE_AUTHORITY',
            'finiteIntentContract': contract, 'candidate': copy.deepcopy(candidate),
            'candidateFileBindings': copy.deepcopy(review['candidateFileBindings']),
            'ingestionFrame': copy.deepcopy(review['frame']),
            'beforeIngestion': copy.deepcopy(before['ingestion']),
            'unchangedApplications': {name: {'binding': io.stable(before[name]),
                'restartCount': before[name]['RestartCount'], 'bindingProfile': 'ouf.runtime-binding.native-mount-order.v1'}
                for name in ('gateway', 'onboarding', 'mcp', 'udp')},
            'engineBinding': copy.deepcopy(native['engineBinding']),
            'ownerControlProfile': copy.deepcopy(owner), 'databaseControlProfile': copy.deepcopy(db),
            'imageImportProfile': import_profile,
            'ingestionReadinessProfile': copy.deepcopy(native['ingestionReadinessProfile']),
            'unchangedGatewayTransportProfile': gateway, 'unchangedGatewayRoutes': copy.deepcopy(routes),
            'gatewayNamespaceSelection': {'containerId': before['gateway']['Id'],
                'pid': before['gateway']['State']['Pid'], 'startedAt': before['gateway']['State']['StartedAt'],
                'namespaceFdMustBeBoundUnderFreshAuthority': True},
            'retainedIssuerProfile': copy.deepcopy(retained['issuerProfile']),
            'historicalSourceClosure': copy.deepcopy(retained['sourceClosure']),
            'historicalQualificationReusableForNewExecutor': False,
            'sourceClosureMustCoverNewExecutor': True, 'freshHumanProfileRequired': True,
            'capturedFrameProofOnly': True, 'otherPrivateFileCustodyReverified': False,
            'requiresNativeExecutorImplementationAndQualification': True,
            'nativeRuntimeExecutorQualified': False, 'targetApplyAuthorized': False,
            'runtimeAuthorityIssued': False, 'automaticReplayAllowed': False, 'budgetReset': False,
            'sourceActivationAllowed': False, 'configuredNormalRuntimeWorkMayResumeOnStart': True,
            'releaseAcceptance': False}


def run(compiler, support, case):
    io = support['input_reader']
    require(case['schema'] == 'ouf.readiness-patch-native-input-case.v1', 'EXACT_NATIVE_INPUT_CASE_REQUIRED')
    base = Path(case['snapshotRoot']);parent = base.lstat()
    require(parent.st_uid == 0 and not parent.st_mode & 0o022 and str(base.resolve()) == str(base),
            'ROOT_NATIVE_INPUT_PARENT_REQUIRED')
    target = base / ('ingestion-readiness-native-inputs-' + io.digest(case))
    require(not os.path.lexists(target), 'NATIVE_INPUT_CONTEXT_EXISTS_DO_NOT_REPLAY')
    reads = []
    def read(path, pin=None):
        value, raw = io.read_json(path, pin, root_owned=True);reads.append((path, raw));return value
    review_root = Path(case['reviewContext'])
    review = read(review_root / 'review.json')
    completed = read(review_root / 'complete.json')
    require(io.digest(review) == completed['reviewHash'] == case['reviewHash']
            and completed['complete'] is True and completed['runtimeAuthorityIssued'] is False,
            'EXACT_COMPLETED_PATCH_REVIEW_REQUIRED')
    snapshot = read(Path(review['inputContext']) / 'snapshot.json')
    require(io.digest(snapshot) == review['inputSnapshotHash'] == case['inputSnapshotHash'],
            'EXACT_RECONCILED_NATIVE_INPUT_SNAPSHOT_REQUIRED')
    root = Path(snapshot['case']['retainedContext'])
    retained = read(root / 'review.json', snapshot['retainedReviewHash'])
    read(root / 'recovery.json', snapshot['retainedJournalHash'])
    ref = retained['executionReview']['packetBinding'];packet = read(ref['path'])
    require(io.digest(packet) == ref['sha256'], 'EXACT_COMPLETED_ROLLOUT_PACKET_REQUIRED')
    custody = {}
    for name, old in review['candidateFileBindings'].items():
        require(name in snapshot['case']['files'], 'CLOSED_CANDIDATE_CUSTODY_REQUIRED')
        custody[name] = compiler.binding(io, old['path'], old['sha256'], snapshot['case']['files'][name]['maximumBytes'])
        require(custody[name] == old, 'CANDIDATE_CUSTODY_SEAL_CHANGED')
    require(set(custody) == {'image.tar.gz', 'metadata.json', 'image-inspect.json', 'trivy-image.json'},
            'COMPLETE_CANDIDATE_CUSTODY_REQUIRED')
    images = read(custody['image-inspect.json']['path'], custody['image-inspect.json']['sha256'])
    require(type(images) is list and len(images) == 1, 'EXACT_CANDIDATE_INSPECT_REQUIRED')
    bundle = project(io, review, snapshot, retained, packet, images[0])
    bundle['parentReviewHash'] = case['reviewHash'];bundle['parentReviewContext'] = case['reviewContext']
    bundle['inputSnapshotHash'] = case['inputSnapshotHash']
    for path, raw in reads:
        require(io.read_json(path, root_owned=True)[1] == raw, 'RETAINED_INPUT_CHANGED_DURING_NATIVE_PREPARATION')
    os.mkdir(target, 0o700);io.sync_directory(base)
    io.write_private(target / 'claim.json', {'caseHash': io.digest(case), 'runtimeAuthorityIssued': False})
    io.sync_directory(target)
    io.write_private(target / 'native-inputs.json', bundle)
    io.write_private(target / 'complete.json', {'complete': True, 'bundleHash': io.digest(bundle),
                                             'runtimeAuthorityIssued': False})
    io.sync_directory(target)
    return {'schema': 'ouf.readiness-patch-native-input-result.v1',
            'status': 'NATIVE_EXECUTION_INPUTS_PREPARED_NO_AUTHORITY', 'complete': True,
            'contextPath': str(target), 'bundleHash': io.digest(bundle),
            'logicalOperationRef': bundle['finiteIntentContract']['logicalOperationRef'],
            'plannedStages': len(bundle['finiteIntentContract']['stages']),
            'nativeRuntimeExecutorQualified': False, 'runtimeAuthorityIssued': False,
            'engineRequests': 0, 'oauthRequests': 0, 'credentialFilesOpened': 0,
            'runtimeEffectsDispatched': 0, 'privateValuesPrinted': False,
            'liveRuntimeReverified': False, 'ownerControlReverified': False, 'databaseAdmissionProven': False,
            'automaticReplayAllowed': False, 'budgetReset': False, 'releaseAcceptance': False,
            'completedTechnicalPhases': 8, 'functionalMilestonesProven': 4}


if __name__ == '__main__':
    try:
        def deadline(*_):
            raise TimeoutError()
        signal.signal(signal.SIGALRM, deadline);signal.alarm(55)
        require(len(sys.argv) == 3, 'EXACT_NATIVE_INPUT_CASE_AND_HASH_REQUIRED')
        compiler, support = load(Path(__file__).resolve().parent)
        case, _ = support['input_reader'].read_json(sys.argv[1], sys.argv[2])
        print(json.dumps(run(compiler, support, case), sort_keys=True), flush=True)
    except Exception as error:
        reason = str(error)
        if not (type(error) is ValueError or type(error).__name__ == 'Stop') or not re.fullmatch('[A-Z][A-Z0-9_]{0,127}', reason):
            reason = 'NATIVE_INPUT_PREPARATION_UNCONFIRMED_' + type(error).__name__
        print(json.dumps({'schema': 'ouf.readiness-patch-native-input-result.v1', 'status': 'STOP_RECONCILE',
                          'reasonCode': reason,
                          'automaticReplayAllowed': False, 'runtimeAuthorityIssued': False,
                          'runtimeEffectsDispatched': 0, 'privatePreparationMayBePartial': True}), flush=True)
        sys.exit(1)
