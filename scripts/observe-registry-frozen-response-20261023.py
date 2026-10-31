#!/usr/bin/env python3
"""One separately claimed current response observation, never prepare replay."""
import ast
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys

CAPSULE = '/home/oufadmin/ouf-registry-postboot-review.lxyqYEvL/capsule.py'
CAPSULE_HASH = 'd841407bf3d010aa9e3f7a789ed6ecf4acfd16acaba5797ef29cdc8cbeb3d2d5'
DECLARATION_HASH = 'c7a7f720c624d97dde0d0cbb3a9e74f0df0fc7cf73934e28959a6d01fb953f85'
CLOSURE_HASH = 'b371d59a022a8e5c635a45b5cb4a7d95e236aded33d46d96a2e7009bcad66081'
SCHEMA = 'ouf.semantic-registry-frozen-response-result.v1'
STAGE = 'VERIFY_LAUNCH'


class Stop(RuntimeError): pass


def require(ok, code):
    if not ok: raise Stop(code)


def encoded(value): return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
def digest(value): return hashlib.sha256(encoded(value)).hexdigest()
def metadata(s): return [s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def retained(path=CAPSULE):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == 654291,
                'EXACT_RETAINED_RESOLVER_CAPSULE_REQUIRED')
        with os.fdopen(os.dup(fd), 'rb') as stream: raw = stream.read(654292)
        require(len(raw) == before.st_size and hashlib.sha256(raw).hexdigest() == CAPSULE_HASH
                and metadata(before) == metadata(os.fstat(fd)) == metadata(os.stat(path, follow_symlinks=False)),
                'RETAINED_RESOLVER_CAPSULE_CHANGED')
    finally: os.close(fd)
    values = {}
    for node in ast.parse(raw).body:
        if isinstance(node, ast.Assign):
            require(len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                    and node.targets[0].id not in values, 'UNIQUE_RETAINED_CAPSULE_FIELDS_REQUIRED')
            values[node.targets[0].id] = ast.literal_eval(node.value)
    require(set(values) == {'CASE', 'DELIVERY', 'DELIVERY_HASH', 'PACKED', 'BOOTSTRAP'}, 'EXACT_RETAINED_CAPSULE_FIELDS_REQUIRED')
    declaration = values['DELIVERY']; manifest = declaration['nativeDeclaration']
    require(digest(declaration) == values['DELIVERY_HASH'] == DECLARATION_HASH and digest(manifest) == CLOSURE_HASH
            and digest(values['CASE']) == declaration['caseHash'], 'EXACT_RETAINED_DECLARATION_REQUIRED')
    with gzip.GzipFile(fileobj=io.BytesIO(base64.b64decode(values['PACKED'], validate=True))) as stream:
        raw = stream.read(12582913)
    require(0 < len(raw) <= 12582912, 'BOUNDED_RETAINED_SOURCE_PAYLOAD_REQUIRED')
    payload = json.loads(raw); loader = payload['loader'].encode(); sources = {k: v.encode() for k, v in payload['sources'].items()}
    require(hashlib.sha256(loader).hexdigest() == manifest['loaderHash'] and len(sources) == 134
            and set(sources) == set(manifest['sourceHashes']) and all(
                hashlib.sha256(v).hexdigest() == manifest['sourceHashes'][k] for k, v in sources.items()),
            'EXACT_RETAINED_SOURCE_CLOSURE_REQUIRED')
    return values['CASE'], manifest, loader, sources


def shape(value, reference):
    """Closed comparisons only; no actual IDs, hashes, keys or free text."""
    require(type(value) is dict, 'OBJECT_FROZEN_RESPONSE_REQUIRED')
    known = ('DRAFT', 'IN_REVIEW', 'APPROVED', 'PUBLISHED', 'ACTIVE', 'READY', 'REJECTED', 'CANCELLED', 'PAUSED', 'DISABLED')
    state = value.get('state')
    def view(row):
        if type(row) is not dict: return {'object': False}
        config = row.get('configuration')
        checksum = None
        if type(config) is dict:
            checksum = 'sha256:' + hashlib.sha256(json.dumps(config, sort_keys=True, separators=(',', ':'),
                ensure_ascii=False, allow_nan=False).encode()).hexdigest() == reference['configurationHash']
        return {'object': True, 'sourceIdPresent': 'sourceId' in row, 'sourceIdMatches': row.get('sourceId') == reference['sourceId'],
            'versionIdPresent': 'onboardingVersionId' in row, 'versionIdMatches': row.get('onboardingVersionId') == reference['onboardingVersionId'],
            'configurationHashPresent': 'configurationHash' in row, 'configurationHashMatches': row.get('configurationHash') == reference['configurationHash'],
            'snakeSourceIdPresent': 'source_id' in row, 'snakeSourceIdMatches': row.get('source_id') == reference['sourceId'],
            'snakeVersionIdPresent': 'onboarding_version_id' in row, 'snakeVersionIdMatches': row.get('onboarding_version_id') == reference['onboardingVersionId'],
            'snakeConfigurationHashPresent': 'configuration_hash' in row, 'snakeConfigurationHashMatches': row.get('configuration_hash') == reference['configurationHash'],
            'statePresent': 'state' in row, 'stateAcceptedByCurrentVerifier': row.get('state') in ('IN_REVIEW', 'APPROVED'),
            'configurationObject': type(config) is dict, 'configurationChecksumMatches': checksum,
            'semanticBindingsList': type(config) is dict and type(config.get('semanticReferenceBindings')) is list}
    # Only these predeclared envelope names are inspected, never arbitrary keys.
    return {'top': view(value), 'knownState': state if type(state) is str and state in known else 'OTHER_OR_ABSENT',
        'data': view(value.get('data')), 'version': view(value.get('version')), 'result': view(value.get('result')),
        'bundleObject': type(value.get('bundle')) is dict, 'codePresent': 'code' in value, 'errorPresent': 'error' in value}


def observation_root(parent, claim, boot):
    return Path(parent) / ('semantic-registry-frozen-response-' + digest({
        'retainedPreparationClaimHash': digest(claim), 'boot': boot, 'purpose': 'FROZEN_RESPONSE_SHAPE_V1'}))


def observe():
    global STAGE
    require(os.geteuid() == os.getegid() == 0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
            and len(sys.argv) == 1 and re.fullmatch('[0-9a-f]{64}', globals().get('__verified_diagnostic_sha256__', '')),
            'VERIFIED_ISOLATED_ROOT_RESPONSE_OBSERVER_REQUIRED')
    STAGE = 'VERIFY_RETAINED_CAPSULE'
    case, manifest, loader, sources = retained()
    ns = {}; exec(compile(loader, '<verified-retained-loader>', 'exec'), ns)
    _, actual = ns['load_entry'](manifest['sourceCommit'], sources, loader, CLOSURE_HASH, manifest['sourcePins'])
    require(actual == manifest, 'EXACT_RETAINED_PRELOAD_REQUIRED')
    from tools.semantic_registry_recovery_execution import postboot_prepare as p, caller_configuration, caller_lookup, original_tls
    from tools.semantic_live_route_diagnostic import reader as transport
    from tools.ingestion_readiness_patch_execution import runtime_guard
    from engine_creation import Engine
    files = p.Files(maximum_reads=192); boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    preparation = case['preparation']; STAGE = 'RECONCILE_CONSUMED_PREPARATIONS'
    prior = p.reconcile_prior_preparation(preparation, files, boot)
    require(prior['priorAttemptCounts'] == {'engineGets': 22, 'adminGets': 3, 'frozenConfigurationGets': 0,
        'resolverCalls': 3, 'tlsAttemptMarkers': 3}, 'ALL_OLD_PREPARATIONS_AND_DIAGNOSTICS_REQUIRED')
    prep_root = p.prepared_root(preparation, manifest, boot)
    claim, _ = files.json(str(prep_root / 'claim.json'))
    require(claim == {'schema': p.SCHEMA, 'caseHash': digest(preparation), 'sourceClosureHash': CLOSURE_HASH,
        'bootId': boot, 'maximumEngineGets': 12, 'maximumAdminGets': 1, 'maximumFrozenGets': 1,
        'automaticReplayAllowed': False, 'runtimeAuthorityIssued': False, 'maximumTlsHandshakes': 1,
        'maximumMetadataReads': 192}, 'EXACT_CONSUMED_RESOLVER_PREPARATION_CLAIM_REQUIRED')
    for n in range(1, 7):
        marker, _ = files.json(str(prep_root / ('engine-get-' + str(n) + '.json')))
        require(set(marker) == {'requestPathHash', 'attempt'} and marker['attempt'] == n
                and re.fullmatch('[0-9a-f]{64}', marker['requestPathHash']), 'EXACT_SIX_RESOLVER_PREPARATION_ENGINE_MARKERS_REQUIRED')
    require(files.json(str(prep_root / 'admin-get.json'))[0] == {
        'method': 'GET', 'operation': '/apisix/admin/routes', 'maximumAttempts': 1}, 'EXACT_PRIOR_ADMIN_MARKER_REQUIRED')
    tls, _ = files.json(str(prep_root / 'tls-handshake.json'))
    require(set(tls) == {'originHash', 'caProfileHash', 'maximumAttempts', 'httpRequests', 'bearersSent'}
            and tls['maximumAttempts'] == 1 and tls['httpRequests'] == tls['bearersSent'] == 0,
            'EXACT_PRIOR_TLS_INTENT_REQUIRED')
    ref = preparation['frozenReference']
    require(files.json(str(prep_root / 'frozen-get.json'))[0] == {'method': 'GET', 'path': p.FROZEN_PATH,
        'referenceHash': digest(ref), 'maximumAttempts': 1}, 'EXACT_CONSUMED_FROZEN_GET_MARKER_REQUIRED')
    def not_advanced():
        for name in ['engine-get-' + str(n) + '.json' for n in range(7, 13)] + ['source', 'prepared.json', 'review.json']:
            try: (prep_root / name).lstat()
            except FileNotFoundError: continue
            require(False, 'CONSUMED_PREPARATION_ADVANCED')
    not_advanced()
    recovery = preparation['resolverRecovery']
    old, _ = files.json(recovery['failedObservation']['path'], recovery['failedObservation']['sha256'])
    corrected, _ = files.json(recovery['correctedObservation']['path'], recovery['correctedObservation']['sha256'])
    inputs, _ = files.json(preparation['retainedInputs']['path'], preparation['retainedInputs']['sha256'])
    proposal = inputs['proposal']; review, _ = files.json(str(Path(preparation['patchContext']) / 'review.json'), proposal['retainedPatchReviewHash'])
    program = review['executionReview']['gatewayTransportProfile']['pythonExecutable']; transport.verify_program(program)
    root = observation_root(p.PARENT, claim, boot); STAGE = 'CLAIM_RESPONSE_OBSERVATION'
    for parent in (root.parent, *root.parent.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022, 'PROTECTED_RESPONSE_PARENT_REQUIRED')
    try: os.mkdir(root, 0o700)
    except FileExistsError: require(False, 'FROZEN_RESPONSE_OBSERVATION_ALREADY_CLAIMED_DO_NOT_REPLAY')
    p.publish(root, 'claim.json', {'schema': SCHEMA, 'bootId': boot, 'retainedPreparationClaimHash': digest(claim),
        'scriptSha256': globals()['__verified_diagnostic_sha256__'], 'maximumEngineGets': 2,
        'maximumFrozenGets': 1, 'maximumResolverCalls': 1, 'maximumTlsConnections': 1,
        'priorAttemptCounts': {'engineGets': 28, 'adminGets': 4, 'frozenConfigurationGets': 1, 'resolverCalls': 5, 'tlsIdentityIntentMarkers': 4},
        'cumulativeEngineGetCeiling': 30, 'cumulativeFrozenGetCeiling': 2, 'cumulativeResolverCallCeiling': 6,
        'automaticReplayAllowed': False, 'budgetReset': False})
    engine = Engine(proposal['engineBinding']['socketPath'], tuple(proposal['engineBinding']['socketBinding']))
    cid = old['callerPin']['binding']['containerId']; path = '/v1.44/containers/' + cid + '/json'; count = 0
    def get():
        nonlocal count
        require(count < 2, 'TWO_CURRENT_CALLER_GETS_ONLY'); count += 1
        p.publish(root, 'engine-get-' + str(count) + '.json', {'requestPathHash': digest(path), 'attempt': count})
        status, value = engine.request('GET', path)
        require(status == 200 and value.get('Id') == cid, 'CURRENT_EXACT_CALLER_REQUIRED')
        runtime_guard.unchanged(value, old['callerPin']); return value
    STAGE = 'SEAL_CURRENT_CALLER_REQUEST'
    caller = get(); origin, target, configuration = caller_configuration.configuration(caller)
    ca, ca_source = original_tls.system_ca(files)
    require(digest(origin) == tls['originHash'] == corrected['originHash'] and digest(ca) == tls['caProfileHash'] == corrected['caProfileHash']
            and origin == old['origin'] and ca_source == old['caSource'], 'SAME_AUTHENTICATED_ORIGIN_AND_CA_REQUIRED')
    lookup, _ = caller_lookup.capture(caller)
    require(lookup['files'] == corrected['callerViews'], 'SAME_TARGET_PROVEN_CALLER_LOOKUP_FILES_REQUIRED')
    token_source, _ = files.seal(p.mounted_source(caller, target), 16384)
    profile = {'callerConfiguration': configuration, 'callerLookup': lookup, 'origin': origin, 'tokenTarget': target,
        'tokenSource': token_source, 'pythonExecutable': program, 'ca': ca,
        'peerCertificateSha256': corrected['result']['peerCertificateSha256']}
    caller_configuration.verify(caller, profile)
    STAGE = 'OBSERVE_ONE_CURRENT_FROZEN_RESPONSE'
    p.publish(root, 'frozen-get.json', {'method': 'GET', 'path': p.FROZEN_PATH, 'referenceHash': digest(ref),
        'maximumAttempts': 1, 'resolverSource': 'SIGNED_CALLER_FILES', 'retainedPeerPinUsed': True})
    value = p.read_frozen(profile, caller, ref)
    # Retain the canonical complete parsed object before *any* shape checks.
    p.publish(root, 'response.json', value)
    STAGE = 'VERIFY_UNCHANGED_CONTEXT'
    get(); caller_configuration.verify(caller, profile); caller_lookup.capture(caller, lookup)
    transport.verify_program(program); require(original_tls.resolve_system_ca() == ca_source, 'COMPILED_CA_SELECTION_CHANGED')
    not_advanced(); require(p.reconcile_prior_preparation(preparation, files, boot) == prior, 'OLD_PREPARATION_PROOF_CHANGED')
    files.verify(); require(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == boot, 'CURRENT_BOOT_CHANGED')
    projection = shape(value, ref)
    p.publish(root, 'observation.json', {'responseHash': digest(value), 'shape': projection, 'referenceHash': digest(ref)})
    return {'schema': SCHEMA, 'status': 'CURRENT_FROZEN_RESPONSE_OBSERVED', 'complete': True,
        'shape': projection, 'httpStatus': 200, 'originalServiceBearerUsed': True,
        'privateResponsePath': str(root / 'response.json'), 'privateResponseCanonicalHash': digest(value),
        'previousResponseRecovered': False, 'currentObservationOnly': True, 'oldClaimsRetained': True,
        'engineGets': count, 'adminGets': 0, 'frozenConfigurationGets': 1,
        'cumulativeEngineGetCeiling': 30, 'cumulativeFrozenGetCeiling': 2, 'cumulativeResolverCallCeiling': 6,
        'priorTlsIdentityIntentMarkers': 4, 'maximumNewTlsConnections': 1,
        'oauthRequests': 0, 'databaseCalls': 0, 'runtimeEffectsDispatched': 0, 'runtimeAuthorityIssued': False,
        'addressesPrinted': False, 'credentialValuesPrinted': False, 'rawResponsePrinted': False,
        'automaticReplayAllowed': False, 'budgetReset': False, 'readOnlyRuntime': True,
        'rootCauseEstablished': False, 'serviceReadinessEstablished': False, 'releaseAcceptance': False}


if __name__ == '__main__':
    def expired(*_): require(False, 'FROZEN_RESPONSE_OBSERVATION_DEADLINE')
    signal.signal(signal.SIGALRM, expired); signal.alarm(45)
    try: result = observe()
    except (Exception, KeyboardInterrupt) as error:
        code = str(error) if isinstance(error, Stop) else ''
        result = {'schema': SCHEMA, 'status': 'STOP_RECONCILE', 'complete': False,
            'reasonCode': code if re.fullmatch('[A-Z][A-Z0-9_]{0,127}', code) else 'CURRENT_FROZEN_RESPONSE_UNPROVEN',
            'stage': STAGE, 'exceptionClass': type(error).__name__ if type(error).__name__ in (
                'Stop', 'RecoveryDenied', 'Denied', 'OSError', 'PermissionError', 'FileNotFoundError', 'TimeoutError',
                'KeyError', 'TypeError', 'ValueError', 'RuntimeError', 'JSONDecodeError') else 'OTHER',
            'contextsAndClaimsRetained': True, 'automaticReplayAllowed': False, 'budgetReset': False,
            'runtimeEffectsDispatched': 0, 'runtimeAuthorityIssued': False, 'oauthRequests': 0, 'releaseAcceptance': False}
    signal.alarm(0); print(encoded(result).decode(), flush=True)
    raise SystemExit(0 if result['complete'] else 2)
