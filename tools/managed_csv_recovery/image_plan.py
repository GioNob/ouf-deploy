"""Exact-image custody and a conditional plan; no runtime ports or authority.

Reuses the Teatri custody/config/network helpers and the qualified V36
replacement rules. Public ZIP bytes and retained private metadata are the
only inputs. A later controller must independently admit the current target.
"""
import copy
import gzip
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import stat


class Stop(ValueError):
    pass


def require(value, code):
    if not value:
        raise Stop(code)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(raw):
    def unique(rows):
        value = {}
        for key, item in rows:
            require(key not in value, 'UNIQUE_PLAN_METADATA_KEYS_REQUIRED'); value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: require(False, 'FINITE_PLAN_METADATA_REQUIRED'))


def frame(row):
    return tuple(getattr(row, key) for key in ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def ancestry(path):
    require(path.is_absolute() and path.resolve() == path, 'CANONICAL_PLAN_ANCESTRY_REQUIRED')
    for parent in (path, *path.parents):
        row = parent.lstat()
        require(stat.S_ISDIR(row.st_mode) and row.st_uid == row.st_gid == 0 and not row.st_mode & 0o022,
                'ROOT_PROTECTED_PLAN_ANCESTRY_REQUIRED')


def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def put(path, value):
    raw = value if isinstance(value, bytes) else encoded(value)
    require(len(raw) <= 16*1024*1024, 'BOUNDED_PRIVATE_PLAN_OUTPUT_REQUIRED')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, 'wb') as output:
        os.fchmod(output.fileno(), 0o400); output.write(raw); output.flush(); os.fsync(output.fileno())
    sync(path.parent)


class Scope:
    def __init__(self, root):
        self.root = Path(root); ancestry(self.root.parent)
        require(not os.path.lexists(self.root), 'IMAGE_PLAN_SCOPE_CONSUMED_NO_REPLAY')
        self.root.mkdir(mode=0o700); self.root.chmod(0o700); sync(self.root.parent)
        self.counts = {'privateMetadataReads': 0, 'privateMetadataBytes': 0, 'ciZipReads': 0,
                       'nativeArchivesPrepared': 0, 'engineGets': 0, 'containerWrites': 0, 'imageImports': 0}
        self.seals = []
        put(self.root/'claim.json', {'schema': 'ouf.managed-csv-image-plan-claim.v1', 'maximumSeconds': 300,
                                    'privateMetadataReads': 3, 'ciZipReads': 2, 'engineGets': 0,
                                    'containerWrites': 0, 'imageImports': 0, 'automaticReplayAllowed': False})

    def private(self, path, expected=None):
        require(self.counts['privateMetadataReads'] < 3, 'THREE_PRIVATE_PLAN_METADATA_READS_ONLY')
        self.counts['privateMetadataReads'] += 1
        put(self.root/('private-read-%d-claim.json' % self.counts['privateMetadataReads']), {'path': str(path), 'attemptNotCompletion': True})
        path = Path(path); ancestry(path.parent)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0 and before.st_nlink == 1
                    and stat.S_IMODE(before.st_mode) in (0o400, 0o600) and 0 < before.st_size <= 6*1024*1024,
                    'PROTECTED_PLAN_METADATA_REQUIRED')
            raw = b''
            while len(raw) < before.st_size:
                block = os.read(fd, min(65536, before.st_size-len(raw)))
                require(block, 'COMPLETE_PLAN_METADATA_REQUIRED'); raw += block
            require(frame(before) == frame(os.fstat(fd)) == frame(path.lstat()), 'PRIVATE_PLAN_METADATA_CHANGED')
            self.counts['privateMetadataBytes'] += len(raw)
            require(expected is None or sha(raw) == expected, 'EXACT_CAPTURE_METADATA_HASH_REQUIRED')
            self.seals.append({'path': str(path), 'sha256': sha(raw), 'metadata': list(frame(before))})
            return decode(raw)
        finally:
            os.close(fd)


def load_module(folder, filename, expected=None):
    path = folder/filename
    require(expected is None or sha(path.read_bytes()) == expected, 'PINNED_REUSED_HELPER_REQUIRED')
    spec = importlib.util.spec_from_file_location('managed_csv_'+filename.replace('.', '_'), path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def validate_capture(inputs, result, review, case):
    require(result == case['captureResult'] and result['complete'] is True and result['inputsHash'] == case['captureHash']
            and result['contextPath'] == case['captureRoot'] and result['runtimeAuthorityIssued'] is False,
            'EXACT_SUCCESSFUL_CONSUMED_CAPTURE_RECEIPT_REQUIRED')
    require(digest(inputs) == case['captureHash'] and inputs['schema'] == 'ouf.managed-csv-recovery-current-inputs.v1'
            and inputs['counts'] == result['counts'] and inputs['captureAccounting'] == result['captureAccounting']
            and inputs['targets'] == result['targetRoles'] == ['onboarding', 'mcp']
            and inputs['currentJobOrBudgetStateObserved'] is False and inputs['runtimeAuthorityIssued'] is False
            and inputs['automaticReplayAllowed'] is False and inputs['budgetReset'] is False,
            'EXACT_METADATA_ONLY_CAPTURE_REQUIRED')
    cohort = inputs['currentObservations']; targets = inputs['resolvedTargetRoles']
    require(len(cohort) == 13 and set(cohort) == set(inputs['currentProcessPins'])
            and set(targets) == {'onboarding', 'mcp'} and targets['onboarding'] == 'onboarding'
            and targets['mcp'] in cohort and targets['mcp'] != 'onboarding', 'EXACT_CAPTURED_TARGET_MAP_REQUIRED')
    require(review['schema'] == 'ouf.onboarding-profile-recovery-update-review.v1'
            and digest(review) == case['retainedReviewHash'] and review['bootId'] == inputs['bootId']
            and review['nativePlan']['proposal']['engineBinding'] == inputs['engineBinding'],
            'SAME_COMPLETED_V36_REVIEW_METADATA_REQUIRED')
    return cohort, targets


def retain_allocations(actual, request, p):
    """Same V36 IP/port preservation, shared by the two replacement requests."""
    name = actual['Name'].removeprefix('/')
    require(re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,160}', name), 'BOUNDED_RETAINED_OWNER_NAME_REQUIRED')
    endpoint = next(iter(actual['NetworkSettings']['Networks'].values()))
    network = p.network(actual, [name, *(endpoint.get('Aliases') or [])], preserve_mac=True)
    ipam = copy.deepcopy(endpoint.get('IPAMConfig') or {})
    require(type(ipam) is dict and set(ipam) <= {'IPv4Address', 'IPv6Address', 'LinkLocalIPs'}, 'CLOSED_RETAINED_ENDPOINT_ALLOCATION')
    for source, target, version in [('IPAddress', 'IPv4Address', 4), ('GlobalIPv6Address', 'IPv6Address', 6)]:
        address = endpoint.get(source)
        if address:
            parsed = ipaddress.ip_address(address)
            require(parsed.version == version and not parsed.is_unspecified and not parsed.is_multicast
                    and ipam.get(target) in (None, '', address), 'RETAINED_STATIC_ENDPOINT_MISMATCH')
            ipam[target] = address
    network['request']['EndpointsConfig'][network['name']]['IPAMConfig'] = ipam
    for port, bindings in (request['HostConfig'].get('PortBindings') or {}).items():
        if any(row.get('HostPort') in (None, '', '0') for row in bindings):
            allocated = (actual['NetworkSettings'].get('Ports') or {}).get(port)
            require(type(allocated) is list and len(allocated) == len(bindings)
                    and all(type(row) is dict and str(row.get('HostPort', '')).isdigit()
                            and 1 <= int(row['HostPort']) <= 65535 for row in allocated), 'ALREADY_ALLOCATED_PUBLISHED_PORT_REQUIRED')
            request['HostConfig']['PortBindings'][port] = copy.deepcopy(allocated)
    request['NetworkingConfig'] = network['request']
    return {'name': network['name'], 'id': network['id']}


def compile_plan(inputs, result, review, receipts, archives, p, mac, case):
    cohort, targets = validate_capture(inputs, result, review, case)
    retained = review['nativePlan']['proposal']; replacements = {}
    require(inputs['engineInfo']['ServerVersion'] == '29.8.1'
            and ['driver-type', 'io.containerd.snapshotter.v1'] in (inputs['engineInfo'].get('DriverStatus') or []),
            'QUALIFIED_NATIVE_ENGINE_PROFILE_REQUIRED')
    for role in ('onboarding', 'mcp'):
        actual = cohort[targets[role]]; image = receipts[role]['imageAudit']['imageConfig']
        require(actual['State']['Running'] is True and actual['State']['Paused'] is False
                and actual['State']['Restarting'] is False, 'CAPTURED_RUNNING_TARGET_REQUIRED')
        if role == 'mcp':
            replacement = p.mcp_replacement(actual, {'Id': receipts[role]['nativeImageId'], 'Config': image}, case['captureHash'])
            request = replacement['request']
        else:
            request = p.config_copy(actual)
            previous = retained['onboardingReplacement']
            for key in ('Entrypoint', 'Cmd', 'User', 'WorkingDir', 'Healthcheck'):
                require(request.get(key) == previous['request'].get(key), 'SAME_CLASSIFIED_OWNER_LAUNCH_REQUIRED')
            require(p.env(request) == p.env(previous['request']), 'SAME_CLASSIFIED_OWNER_ENV_REQUIRED')
            require(request['User'] in (image['User'], image['User'].split(':')[0])
                    and request['Entrypoint'] == image['Entrypoint'] and request.get('Cmd') == image.get('Cmd'),
                    'QUALIFIED_OWNER_LAUNCH_REQUIRED')
            host = copy.deepcopy(actual['HostConfig']); restore = copy.deepcopy(host['RestartPolicy'])
            host['RestartPolicy'] = {'Name': 'no', 'MaximumRetryCount': 0}
            request.update(Image=receipts[role]['nativeImageId'], HostConfig=host)
            replacement = {'name': actual['Name'].removeprefix('/'), 'request': request,
                           'restoreRestartPolicy': restore, 'oldBinding': p.stable_binding(actual),
                           'oldNativeHostConfig': copy.deepcopy(actual['HostConfig']), 'readiness': copy.deepcopy(previous['readiness'])}
        require(set(p.env(image)) <= set(p.env(actual['Config'])), 'NO_NEW_IMAGE_ENV_DEFAULT_KEYS')
        defaults = image.get('Labels') or {}; labels = actual['Config'].get('Labels') or {}
        require(all(key.startswith('org.opencontainers.image.') for key in set(defaults)-set(labels)), 'NO_UNREVIEWED_IMAGE_LABEL_ADDITIONS')
        host = request['HostConfig']
        require(host.get('AutoRemove') is False and type(host.get('Memory')) is int and host['Memory'] >= 0
                and (host.get('OomKillDisable') is None or type(host['OomKillDisable']) is bool), 'EXACT_RETAINED_RESOURCE_POLICY_REQUIRED')
        replacement.update(retiredName=replacement['name']+'-retained-csv-control-'+case['captureHash'][:12],
                           network=retain_allocations(actual, request, p), imageAudit=copy.deepcopy(receipts[role]['imageAudit']),
                           nativeArchive=copy.deepcopy(archives[role]), retainedRoleKey=targets[role],
                           oldRetainedStopped=True, oldMustBeStoppedAndDetachedBeforeNewStarts=True,
                           runtimeLabelProjection={'expectedLabels': {**defaults, **labels}},
                           retainedResourcePolicy={'memoryBytes': host['Memory'], 'autoRemove': False,
                                                   'oomKillDisable': host.get('OomKillDisable'), 'resourcePolicyChanged': False})
        replacement['legacyConfigMacDetachPolicy'] = mac.policy(actual) if actual['Config'].get('MacAddress') else {
            'profile': 'NO_LEGACY_CONFIG_MAC_CHANGE_RETAIN_EXACT_V1', 'originalConfigHash': digest(actual['Config']),
            'originalEndpointSetHash': digest(actual['NetworkSettings']['Networks']), 'originalHashesRewritten': False}
        if host.get('OomKillDisable') is None:
            replacement['runtimeHostProjection'] = {'profile': 'DOCKER_ENABLED_OOM_DEFAULT_NULL_FALSE_V1',
                                                   'requestedOomKillDisable': None, 'materializedOomKillDisable': False,
                                                   'retainedMemoryBytes': host['Memory']}
        replacements[role] = replacement
    application = receipts['onboarding']['application']
    require(application['migrations'] == retained['candidateApplicationFacts']['migrations']
            and len(application['migrations']) == 36
            and application['applicationYamlSha256'] == retained['candidateApplicationFacts']['applicationYamlSha256'],
            'ALL_36_INSTALLED_MIGRATIONS_AND_PACKAGED_YAML_UNCHANGED_REQUIRED')
    target_keys = set(targets.values())
    return {'schema': 'ouf.managed-csv-control-conditional-plan.v1', 'kind': 'FROZEN_CONDITIONAL_PROPOSAL_NOT_EXECUTABLE',
            'capturedInputsHash': case['captureHash'], 'bootId': inputs['bootId'], 'engineBinding': copy.deepcopy(inputs['engineBinding']),
            'engineInfoHash': digest(inputs['engineInfo']), 'currentRootProcessPins': copy.deepcopy(inputs['currentRootProcessPins']),
            'currentProcessPins': copy.deepcopy(inputs['currentProcessPins']), 'targetRoleKeys': targets,
            'existingApplications': {role: p.stable_binding(actual) for role, actual in cohort.items()},
            'unchangedApplications': {role: p.stable_binding(actual) for role, actual in cohort.items() if role not in target_keys},
            'replacements': replacements, 'boundDatabaseProfile': copy.deepcopy(retained['boundDatabaseProfile']),
            'nativeFlywayConfiguration': copy.deepcopy(retained['nativeFlywayConfiguration']),
            'candidateApplicationFacts': copy.deepcopy(application), 'databaseMigration': {'from': 36, 'to': 36, 'newMigrations': 0},
            'retainedCaptureAccounting': copy.deepcopy(inputs['captureAccounting']),
            'futureRequirements': ['NEW_CURRENT_RUNTIME_ADMISSION', 'EXACT_36_HISTORY_AND_MONOTONIC_OPERATIONAL_STATE',
                                   'CURRENT_OWNER_CONFIGURATION_CONTENT_AND_PRECEDENCE', 'VERIFIED_QUIESCED_BACKUP',
                                   'NEW_CONCRETE_TERMINAL_REVIEW_AND_FINITE_SIGNED_AUTHORITY', 'SEPARATE_HUMAN_JOB_BUDGET_AND_RESUME'],
            'executionEntryQualified': False, 'currentRuntimeRevalidated': False, 'databaseAdmissionProven': False,
            'runtimeAuthorityIssued': False, 'targetApplyAuthorized': False, 'newGrantsAuthorized': False,
            'humanBudgetsOrResumeAuthorized': False, 'databaseRestoreAuthorized': False, 'automaticRollbackAllowed': False,
            'automaticReplayAllowed': False, 'budgetReset': False, 'applicationE2EProven': False, 'releaseAcceptance': False}


def stage_native(scope, role, zip_path, receipt, unpack, custody):
    require(scope.counts['ciZipReads'] < 2, 'TWO_EXACT_IMAGE_ZIP_READS_ONLY')
    scope.counts['ciZipReads'] += 1
    put(scope.root/(role+'-zip-read-claim.json'), {'sha256': receipt['artifactZipSha256'], 'attemptNotCompletion': True})
    path = Path(zip_path); fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    work = scope.root/role; work.mkdir(mode=0o700)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0 and before.st_nlink == 1
                and stat.S_IMODE(before.st_mode) == 0o400 and before.st_size == receipt['artifactZipBytes'], 'PROTECTED_EXACT_CI_ZIP_REQUIRED')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            checksum, size = custody.hashed(stream, receipt['artifactZipBytes'])
        require(size == receipt['artifactZipBytes'] and checksum == receipt['artifactZipSha256'], 'EXACT_CI_ZIP_BYTES_REQUIRED')
        manifest, compressed = unpack(path, work, receipt)
        require(compressed == receipt['imageArchiveSha256'], 'EXACT_QUALIFIED_COMPRESSED_ARCHIVE_REQUIRED')
        expanded = work/'expanded.tar'; outfd = os.open(expanded, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        with os.fdopen(outfd, 'w+b') as output, gzip.open(work/'image.tar.gz', 'rb') as zipped:
            os.fchmod(output.fileno(), 0o400); count = 0
            while block := zipped.read(1048576):
                count += len(block); require(count <= receipt['maximumExpandedBytes'], 'BOUNDED_IMAGE_EXPANSION_REQUIRED'); output.write(block)
            output.flush(); os.fsync(output.fileno()); output.seek(0)
            expanded_hash, expanded_bytes = custody.hashed(output, receipt['maximumExpandedBytes'])
            require(expanded_hash == receipt['expandedArchiveSha256'] and expanded_bytes == receipt['expandedArchiveBytes'], 'EXACT_EXPANDED_CI_ARCHIVE_REQUIRED')
            binding = receipt['imageAudit']['qualifiedCiSourceBinding']
            audit = custody.archive(output, expanded_hash, receipt['configurationImageId'], receipt['testedCommit'], ci_source_binding=binding)
            audit['nativeIdentity'] = custody.native_identity(audit)
            require(audit == receipt['imageAudit'], 'EXACT_QUALIFIED_IMAGE_AUDIT_REQUIRED')
            target = scope.root/(role+'-native.tar'); nativefd = os.open(target, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
            with os.fdopen(nativefd, 'w+b') as native:
                os.fchmod(native.fileno(), 0o400); derived = custody.tagless_archive(output, native, audit, containerd=True)
                native.flush(); os.fsync(native.fileno()); metadata = list(frame(os.fstat(native.fileno())))
            require(custody.runtime_image_id(audit) == receipt['nativeImageId']
                    and derived['derivedArchiveSha256'] == receipt['derivedArchiveSha256']
                    and derived['archiveBytes'] == receipt['nativeArchiveBytes'], 'EXACT_QUALIFIED_NATIVE_ARCHIVE_REQUIRED')
        require(frame(before) == frame(os.fstat(fd)) == frame(path.lstat()), 'CI_ZIP_CHANGED_DURING_STAGING')
    finally:
        os.close(fd)
    scope.counts['nativeArchivesPrepared'] += 1; sync(scope.root)
    return {'path': str(target), 'sha256': derived['derivedArchiveSha256'], 'bytes': derived['archiveBytes'], 'metadata': metadata}


def prepare(scope, case, receipts, zips, p, mac, custody, unpack):
    captured = Path(case['captureRoot'])
    inputs = scope.private(captured/'inputs.json', case['captureHash'])
    result = scope.private(captured/'result.json')
    review = scope.private(Path(case['retainedReviewPath']), case['retainedReviewHash'])
    validate_capture(inputs, result, review, case)
    require(shutil.disk_usage(scope.root).free >= 2*1024*1024*1024, 'TWO_GIB_FREE_IMAGE_CUSTODY_REQUIRED')
    archives = {role: stage_native(scope, role, zips[role], receipts[role], unpack, custody) for role in ('onboarding', 'mcp')}
    plan = compile_plan(inputs, result, review, receipts, archives, p, mac, case)
    put(scope.root/'execution-plan.json', plan)
    private = {'schema': 'ouf.managed-csv-control-private-execution-inputs.v1', 'capturedInputsHash': case['captureHash'],
               'currentCapture': inputs, 'conditionalNativePlanHash': digest(plan), 'nativeArchives': archives,
               'imageAudits': {role: receipts[role]['imageAudit'] for role in receipts}, 'historySeals': scope.seals,
               'conditionalLifecyclePlanCompiled': True, 'executionEntryQualified': False,
               'runtimeAuthorityIssued': False, 'targetUpdateAuthorized': False, 'currentRuntimeRevalidated': False,
               'automaticReplayAllowed': False, 'budgetReset': False, 'applicationE2EProven': False, 'releaseAcceptance': False}
    for seal in scope.seals:
        require(list(frame(Path(seal['path']).lstat())) == seal['metadata'], 'RETAINED_METADATA_SEAL_CHANGED')
    put(scope.root/'execution-inputs.json', private)
    output = {'schema': 'ouf.managed-csv-control-image-plan-result.v1',
              'status': 'MANAGED_CSV_CONTROL_IMAGES_AND_CONDITIONAL_PLAN_PREPARED_NOT_AUTHORIZED', 'complete': True,
              'contextPath': str(scope.root), 'capturedInputsHash': case['captureHash'], 'executionInputsHash': digest(private),
              'conditionalNativePlanHash': digest(plan), 'counts': dict(scope.counts), 'cohortSize': 13, 'unchangedPeers': 11,
              'candidateNativeImageIds': {role: receipts[role]['nativeImageId'] for role in receipts}, 'newDatabaseMigrations': 0,
              'retainedCaptureAccounting': inputs['captureAccounting'], 'conditionalLifecyclePlanCompiled': True,
              'executionEntryQualified': False, 'databaseAdmissionProven': False, 'currentRuntimeRevalidated': False,
              'runtimeAuthorityIssued': False, 'targetUpdateAuthorized': False, 'ownerConfigurationContentReads': 0,
              'credentialFileReads': 0, 'installationSigningKeysRead': False, 'sqlSessions': 0, 'oauthRequests': 0,
              'gatewayRequests': 0, 'registryWorkerTouched': False, 'newGrantsGranted': 0, 'humanBudgetsGranted': 0,
              'resumes': 0, 'acquisitionsExecuted': 0, 'sourceActivations': 0, 'historicalAuthorityReused': False,
              'automaticReplayAllowed': False, 'budgetReset': False, 'applicationE2EProven': False, 'releaseAcceptance': False}
    put(scope.root/'result.json', output)
    return output
