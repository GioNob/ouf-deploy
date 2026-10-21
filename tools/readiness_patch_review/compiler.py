"""Offline, single-use review template for one retained Ingestion image replacement."""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import sys
import time
import types

SUPPORT = {
    'input_reader': 'c97ae9fd8af1a554df372abd3342e7057c14fc0a7d40acffb82181625e3e9e4d',
    'frozen_frames': 'cdf903c96241570b1fba21b784279fbaa1ec1c11d93cfb8dc9c9acaa35182f6c',
    'frozen_replacement': 'fd69d6736da0eec13787d4947e1b02a93574da4c6b296517e82389a5f8455352',
}

IMAGE_INSPECT_PROFILE = 'docker-inspect-empty-non-image-fields.v1'
# Docker Engine API history, v1.46/v1.50: these are container-only
# fields historically serialized in image inspect, never image defaults.
INSPECT_BOOLEAN_FIELDS = frozenset(('AttachStdin', 'AttachStdout', 'AttachStderr',
                                    'Tty', 'OpenStdin', 'StdinOnce', 'NetworkDisabled'))
INSPECT_STRING_FIELDS = frozenset(('Hostname', 'Domainname', 'Image', 'MacAddress'))
INSPECT_FIELDS = INSPECT_BOOLEAN_FIELDS | INSPECT_STRING_FIELDS | {'StopTimeout'}


def empty_image_inspect_field(config, key):
    if key not in config:
        return True
    value = config[key]
    if key in INSPECT_BOOLEAN_FIELDS:
        return type(value) is bool and value is False
    if key in INSPECT_STRING_FIELDS:
        return type(value) is str and value == ''
    return key == 'StopTimeout' and value is None


class Stop(Exception):
    pass


def require(ok, code):
    if not ok:
        raise Stop(code)


def load_support(root):
    loaded = {}
    for name, expected in SUPPORT.items():
        path = root / (name + '.py')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            raw = os.read(fd, 65537)
            require(0 < len(raw) <= 65536 and hashlib.sha256(raw).hexdigest() == expected,
                    'QUALIFIED_COMPILER_SUPPORT_BYTES_REQUIRED')
        finally:
            os.close(fd)
        module = types.ModuleType(name)
        module.__file__ = str(path)
        sys.modules[name] = module
        exec(compile(raw, str(path), 'exec'), module.__dict__)
        loaded[name] = module
    return loaded


def binding(io, path, expected, maximum):
    opened = io.regular(path, maximum, root_owned=True)
    try:
        h = hashlib.sha256()
        total = 0
        while True:
            raw = os.read(opened[0], 1048576)
            if not raw:
                break
            total += len(raw)
            require(total <= maximum, 'CANDIDATE_CUSTODY_BYTE_LIMIT')
            h.update(raw)
        require(total == opened[1].st_size and h.hexdigest() == expected, 'CANDIDATE_FILE_CUSTODY_CHANGED')
        p = Path(path)
        ancestors = []
        names = ['/'] + ['/' + '/'.join(p.parts[1:i]) for i in range(2, len(p.parts))]
        for fd, name in zip(opened[2], names):
            s = os.fstat(fd)
            ancestors.append({'path': name, 'identity': [s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode]})
        return {'path': str(path), 'sha256': expected, 'metadata': list(io.signature(opened[1])),
                'ancestors': ancestors}
    finally:
        io.close_checked(opened)


def build(io, frames, replacement, case, snapshot, old_review, old_row, packet, candidate):
    require(case.get('imageDefaultCompatibilityProfile') == IMAGE_INSPECT_PROFILE,
            'RECONCILED_IMAGE_INSPECT_PROFILE_REQUIRED')
    native = old_review['executionReview']
    require(old_row['nextStage'] == len(native['stages']) == len(old_row['effects']) == 28
            and old_row['budgetReset'] is False
            and all(e['state'] == 'APPLIED' and e['stage'] == native['stages'][i]['name']
                    and e['intentHash'] == native['stages'][i]['intentHash']
                    for i, e in enumerate(old_row['effects'])), 'COMPLETED_ROLLOUT_SEQUENCE_REQUIRED')
    meta = snapshot['candidateMetadata']
    require(meta['sourceCommit'] == case['candidateSourceCommit']
            and meta['baselineSourceCommit'] == case['baselineSourceCommit']
            and meta['imageId'] == case['candidateImageId']
            and meta['migrationChanges'] == 0,
            'EXACT_CAPTURED_PATCH_CANDIDATE_REQUIRED')
    actual = snapshot['runtimeBefore']['ingestion']
    i = next(i for i, stage in enumerate(native['stages']) if stage['name'] == 'ingestion.START_REPLACEMENT')
    process = old_row['effects'][i]['nativeResource']
    require(actual['Id'] == case['oldIngestionId'] == process['containerId'], 'EXACT_CAPTURED_INGESTION_REQUIRED')
    old_frame = packet['frames']['ingestion']
    old_defaults = packet['candidate']['imageConfig']
    replacement.validate(old_frame, actual, old_defaults,
                         packet['expectedRuntimeBindings']['ingestion']['containerId'],
                         created_id=actual['Id'], process=process, restart_restored=True)
    require(candidate['Id'] == meta['imageId'] and candidate['Config']['User'] == '10002:10002'
            and candidate['Config']['Entrypoint'] == ['java', '-jar', '/app/app.jar']
            and candidate['Os'] == 'linux' and candidate['Architecture'] == 'amd64', 'EXACT_CANDIDATE_IMAGE_REQUIRED')
    new_defaults = candidate['Config']
    # Preserve the installed process/environment contract. A new inherited field
    # or a changed base-image default requires a separately qualified review.
    for key in set(old_defaults) | set(new_defaults):
        require(re.fullmatch('[A-Za-z][A-Za-z0-9]{0,63}', key), 'CLOSED_IMAGE_DEFAULT_FIELD_REQUIRED')
        if key in INSPECT_FIELDS:
            require(actual.get('Platform') == 'linux'
                    and all(empty_image_inspect_field(value, key) for value in (old_defaults, new_defaults)),
                    'NONEMPTY_OR_UNTYPED_IMAGE_INSPECT_FIELD_' + key)
        elif key == 'Labels':
            old_labels = {k: v for k, v in (old_defaults.get(key) or {}).items()
                          if k != 'org.opencontainers.image.revision'}
            new_labels = {k: v for k, v in (new_defaults.get(key) or {}).items()
                          if k != 'org.opencontainers.image.revision'}
            require(old_labels == new_labels, 'CANDIDATE_IMAGE_LABEL_DEFAULTS_CHANGED')
        elif key == 'ArgsEscaped':
            # Preserve the qualified Linux image-only omission rule. The field
            # is Windows-specific; the retained explicit process arrays remain exact.
            if key not in actual['Config'] and actual.get('Platform') == 'linux':
                require(all(key not in value or type(value[key]) is bool for value in (old_defaults, new_defaults))
                        and all(k in actual['Config'] for k in ('Entrypoint', 'Cmd')),
                        'CANDIDATE_IMAGE_ARGS_ESCAPED_CHANGED')
            else:
                require(old_defaults.get(key) == new_defaults.get(key), 'CANDIDATE_IMAGE_ARGS_ESCAPED_CHANGED')
        elif key == 'Env':
            require(frames.environment(old_defaults.get(key) or [])
                    == frames.environment(new_defaults.get(key) or []), 'CANDIDATE_IMAGE_ENV_DEFAULTS_CHANGED')
        else:
            require(old_defaults.get(key) == new_defaults.get(key), 'CANDIDATE_IMAGE_DEFAULT_CHANGED_' + key)
    config = copy.deepcopy(actual['Config'])
    host = copy.deepcopy(actual['HostConfig'])
    require(host.get('AutoRemove') is not True and host.get('Privileged') is not True
            and not host.get('Links') and not host.get('VolumesFrom') and not host.get('ContainerIDFile')
            and not str(host.get('PidMode', '')).startswith('container:')
            and not str(host.get('IpcMode', '')).startswith('container:'), 'RETAINABLE_INDEPENDENT_INGESTION_REQUIRED')
    endpoints = frames.endpoints(actual)
    legacy_mac = config.pop('MacAddress', None)
    if config.get('Hostname') == actual['Id'][:12]:
        config['Hostname'] = ''
    config['Image'] = candidate['Id']
    config['Labels'] = {**(config.get('Labels') or {}), 'org.opencontainers.image.revision': meta['sourceCommit']}
    restore = copy.deepcopy(host['RestartPolicy'])
    require(restore == old_frame['restoreRestartPolicy'] and restore in (
        frames.NO_RESTART, {'Name': 'unless-stopped', 'MaximumRetryCount': 0}), 'EXACT_RESTORE_POLICY_REQUIRED')
    host['RestartPolicy'] = copy.deepcopy(frames.NO_RESTART)
    request = {**config, 'HostConfig': host, 'NetworkingConfig': {'EndpointsConfig': endpoints}}
    frame = {'schema': 'ouf.ingestion-local-docker-frame-template.v1', 'module': 'ingestion',
             'name': old_frame['name'], 'requestTemplate': request, 'restoreRestartPolicy': restore,
             'oldMounts': copy.deepcopy(actual['Mounts']), 'preserveObservedAddressesAndMacs': True,
             'resolveGatewaySecretAfterNativeAuthorityRequired': False,
             'legacyContainerMacMovedToExplicitEndpoints': bool(legacy_mac),
             'nativeCreationRoundTripQualified': False, 'runtimeAuthorityIssued': False, 'targetApplyAuthorized': False}
    logical = io.digest({'operation': 'INGESTION_READINESS_WORKLOAD_PATCH',
                         'oldContainerId': actual['Id'], 'candidateImageId': candidate['Id']})
    retained_name = old_frame['name'] + '-retained-' + logical[:12]
    require(len(retained_name) <= 200 and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]*', retained_name),
            'BOUNDED_RETAINED_NAME_REQUIRED')
    stages = []
    def add(name, kind, intent):
        stages.append({'name': name, 'kind': kind, 'intent': intent, 'intentHash': io.digest(intent)})
    add('VERIFY_CURRENT_GATES', 'READ', {'currentHumanOwnerDatabaseAndRuntimeBindingsRequired': True,
        'dedicatedWorkloadRouteMustBeVerified': True, 'archiveCustodyRequired': True})
    add('IMPORT_INGESTION_IMAGE', 'EFFECT', {'nativeImageId': candidate['Id'],
        'archiveSha256': meta['imageArchiveSha256'], 'maximumArchiveBytes': meta['imageArchiveBytes']})
    add('ingestion.DISABLE_OLD_RESTART', 'EFFECT', {'oldContainerId': actual['Id'], 'restartPolicy': frames.NO_RESTART})
    add('ingestion.STOP_OLD', 'EFFECT', {'oldContainerId': actual['Id'], 'timeoutSeconds': 30})
    for index, endpoint in enumerate(endpoints.values(), 1):
        add('ingestion.DETACH_NETWORK.' + str(index), 'EFFECT', {'oldContainerId': actual['Id'],
             'networkId': endpoint['NetworkID'], 'force': False})
    add('ingestion.RENAME_OLD', 'EFFECT', {'oldContainerId': actual['Id'], 'retainedName': retained_name})
    add('ingestion.CREATE_REPLACEMENT', 'EFFECT', {'name': frame['name'], 'requestTemplate': request})
    add('ingestion.START_REPLACEMENT', 'EFFECT', {'createdIdMustComeFromDurableCreateResponse': True})
    add('ingestion.READINESS', 'READ', {'firstProcessMustMatch': True, 'validateOnlySchemaAndReadinessRequired': True})
    add('VERIFY_FINAL', 'READ', {'freshOwnerDatabaseGates': True, 'allOtherRuntimeBindingsUnchanged': True,
                               'dedicatedWorkloadRouteUnchanged': True})
    add('ingestion.RESTORE_RESTART', 'EFFECT', {'createdIdMustComeFromDurableCreateResponse': True, 'restartPolicy': restore})
    add('VERIFY_RESTORED_FINAL', 'READ', {'exactNewProcessAndRestoredPolicyRequired': True,
                                       'freshOwnerDatabaseGates': True, 'allOtherRuntimeBindingsUnchanged': True})
    return {'schema': 'ouf.ingestion-readiness-patch-review.v1', 'kind': 'PRIVATE_TEMPLATE_NOT_EXECUTABLE_AUTHORITY',
            'imageDefaultCompatibilityProfile': IMAGE_INSPECT_PROFILE,
            'emptyImageInspectFieldsChecked': sorted(INSPECT_FIELDS & (set(old_defaults) | set(new_defaults))),
            'logicalOperationRef': logical, 'inputContext': case['inputContext'],
            'oldContainerId': actual['Id'], 'candidateMetadata': meta, 'frame': frame, 'stages': stages,
            'otherRuntimeBefore': {k: v for k, v in snapshot['runtimeBefore'].items() if k != 'ingestion'},
            'fullPriorIngestionFrameMatched': True, 'migrationChanges': 0, 'gatewayLifecycleOperations': 0,
            'gatewayWrites': 0, 'grantChanges': 0, 'ownerMutations': 0, 'sourceActivationAllowed': False,
            'explicitJobDispatchAllowed': False, 'configuredNormalRuntimeWorkMayResumeOnStart': True,
            'requiresSeparateNativeExecutorQualification': True, 'nativeRuntimeExecutorQualified': False,
            'freshInfrastructureConsentRequired': True, 'freshHumanOwnerDatabaseGatesRequired': True,
            'proposedMaximumRuntimeSeconds': 900, 'runtimeAuthorityIssued': False, 'targetApplyAuthorized': False,
            'automaticReplayAllowed': False, 'automaticRollbackAllowed': False, 'budgetReset': False,
            'releaseAcceptance': False}


def run(support, case):
    io, frames, replacement = (support[n] for n in ('input_reader', 'frozen_frames', 'frozen_replacement'))
    require(case['schema'] == 'ouf.readiness-patch-review-case.v1', 'EXACT_REVIEW_CASE_REQUIRED')
    root = Path(case['inputContext'])
    base = Path(case['snapshotRoot'])
    parent = base.lstat()
    require(parent.st_uid == 0 and not parent.st_mode & 0o022 and str(base.resolve()) == str(base),
            'ROOT_REVIEW_PARENT_REQUIRED')
    target = base / ('ingestion-readiness-patch-review-' + io.digest(case))
    require(not os.path.lexists(target), 'REVIEW_ALREADY_EXISTS_DO_NOT_REPLAY')
    predecessor = case.get('predecessorReviewCaseHash', '')
    require(re.fullmatch('[a-f0-9]{64}', predecessor)
            and predecessor != io.digest(case), 'DISTINCT_RECONCILED_REVIEW_CASE_REQUIRED')
    require(not os.path.lexists(base / ('ingestion-readiness-patch-review-' + predecessor)),
            'PREDECESSOR_REVIEW_EXISTS_RECONCILE_REQUIRED')
    snapshot, snapshot_raw = io.read_json(root / 'snapshot.json', root_owned=True)
    completed, _ = io.read_json(root / 'complete.json', root_owned=True)
    require(io.digest(snapshot['case']) == case['inputCaseHash'] == completed['caseHash']
            and io.digest(snapshot) == completed['snapshotHash'] and completed['complete'] is True
            and completed['runtimeAuthorityIssued'] is False, 'EXACT_COMPLETED_INPUT_SNAPSHOT_REQUIRED')
    require(completed['snapshotHash'] == case.get('reconciledInputSnapshotHash'),
            'EXACT_RECONCILED_INPUT_SNAPSHOT_REQUIRED')
    retained = Path(snapshot['case']['retainedContext'])
    old_review, before_review = io.read_json(retained / 'review.json', snapshot['retainedReviewHash'], root_owned=True)
    old_row, before_row = io.read_json(retained / 'recovery.json', snapshot['retainedJournalHash'], root_owned=True)
    packet_ref = old_review['executionReview']['packetBinding']
    packet, _ = io.read_json(packet_ref['path'], root_owned=True)
    require(io.digest(packet) == packet_ref['sha256'], 'RETAINED_PACKET_BYTES_CHANGED')
    custody = {name: binding(io, root / name, pin['sha256'], pin['maximumBytes'])
               for name, pin in snapshot['case']['files'].items()}
    meta, _ = io.read_json(root / 'metadata.json', custody['metadata.json']['sha256'], root_owned=True)
    inspect, _ = io.read_json(root / 'image-inspect.json', custody['image-inspect.json']['sha256'], root_owned=True)
    require(meta == snapshot['candidateMetadata'] and len(inspect) == 1, 'CANDIDATE_METADATA_CHANGED')
    proposal = build(io, frames, replacement, case, snapshot, old_review, old_row, packet, inspect[0])
    proposal['candidateFileBindings'] = custody
    proposal['sourceSupportSha256'] = SUPPORT
    proposal['inputSnapshotHash'] = completed['snapshotHash']
    proposal['inputObservedAtUnix'] = snapshot['observedAtUnix']
    require(io.read_json(root / 'snapshot.json', root_owned=True)[1] == snapshot_raw
            and io.read_json(retained / 'review.json', root_owned=True)[1] == before_review
            and io.read_json(retained / 'recovery.json', root_owned=True)[1] == before_row,
            'RETAINED_INPUT_CHANGED_DURING_COMPILATION')
    require(not os.path.lexists(base / ('ingestion-readiness-patch-review-' + predecessor)),
            'PREDECESSOR_REVIEW_EXISTS_RECONCILE_REQUIRED')
    os.mkdir(target, 0o700)
    io.sync_directory(base)
    io.write_private(target / 'claim.json', {'caseHash': io.digest(case), 'state': 'COMPILING_TEMPLATE',
                                           'runtimeAuthorityIssued': False})
    io.sync_directory(target)
    io.write_private(target / 'review.json', proposal)
    io.write_private(target / 'complete.json', {'reviewHash': io.digest(proposal), 'complete': True,
                                               'runtimeAuthorityIssued': False})
    io.sync_directory(target)
    return {'schema': 'ouf.readiness-patch-review-result.v1', 'status': 'REVIEW_TEMPLATE_PREPARED_NO_AUTHORITY',
            'imageDefaultCompatibilityProfile': IMAGE_INSPECT_PROFILE,
            'complete': True, 'contextPath': str(target), 'reviewHash': io.digest(proposal),
            'logicalOperationRef': proposal['logicalOperationRef'], 'candidateImageId': meta['imageId'],
            'plannedStages': len(proposal['stages']), 'fullPriorIngestionFrameMatched': True,
            'liveRuntimeReverified': False, 'ownerControlReverified': False, 'databaseAdmissionProven': False,
            'gatewayLifecycleOperations': 0, 'gatewayWrites': 0, 'migrationChanges': 0,
            'engineRequests': 0, 'oauthRequests': 0, 'credentialFilesOpened': 0,
            'privateValuesPrinted': False, 'privateReviewWritten': True,
            'nativeRuntimeExecutorQualified': False, 'freshInfrastructureConsentRequired': True,
            'runtimeAuthorityIssued': False, 'runtimeEffectsDispatched': 0,
            'sourceActivationAllowed': False, 'automaticReplayAllowed': False, 'releaseAcceptance': False}


if __name__ == '__main__':
    try:
        def deadline(*_):
            raise Stop('REVIEW_COMPILATION_DEADLINE')
        signal.signal(signal.SIGALRM, deadline)
        signal.alarm(55)
        require(len(sys.argv) == 3 and re.fullmatch('[a-f0-9]{64}', sys.argv[2]), 'EXACT_CASE_AND_HASH_REQUIRED')
        support = load_support(Path(__file__).resolve().parent)
        case, _ = support['input_reader'].read_json(sys.argv[1], sys.argv[2])
        print(json.dumps(run(support, case), sort_keys=True), flush=True)
    except Exception as error:
        io_stop = sys.modules.get('input_reader')
        code = str(error) if isinstance(error, (Stop, io_stop.Stop if io_stop else Stop)) else 'REVIEW_UNCONFIRMED_' + type(error).__name__
        print(json.dumps({'schema': 'ouf.readiness-patch-review-result.v1', 'status': 'STOP_RECONCILE',
                          'reasonCode': code, 'automaticReplayAllowed': False,
                          'runtimeAuthorityIssued': False, 'runtimeEffectsDispatched': 0,
                          'privateReviewMayBePartial': True}), flush=True)
        sys.exit(1)
