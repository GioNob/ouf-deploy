"""Correct one pre-Engine label-domain failure; preserve the consumed predecessor.

Inventory aliases carry no role authority. The already captured public roster
binds each role to one exact container ID, full configuration hash and process
pin. The old reader, capsule and scope stay unchanged. Metadata candidates only.
"""
import json, os, re, stat
from pathlib import Path
from .retained_mount_capture import (RetainedCapture, RetainedEngine, identity,
    SEED, SEED_HASH, OUTPUT as PREDECESSOR, RETAINED, ROLES, LIMITS)
from .custody_capture import attrs, decode, digest, encoded, process_pin, require, Stop

OUTPUT = Path('/etc/ouf/deploy-snapshots/m2-retained-mount-role-correction-0922ad73-20261101-v1')
PREDECESSOR_HASH = '0922ad7330417ed9da7a472cad266174ace344c12fa7c5c420f8083ca1fe8d2c'
PREDECESSOR_SOURCE_SHA256 = 'f6cb51659af47a9d7557514da34b8bf502443bc3fc77c0b1a01078a2604fcc48'
PUBLIC_ROSTER_HASH = 'a5161311451021f936692274c6ad91cecb7a40ca2e0017da533765905fd0f674'
PROFILE = {'schema':'ouf.retained-mount-role-correction-profile.v1',
    'predecessorControlAttempts':1, 'maximumCorrectiveControlAttempts':1,
    'maximumCumulativeControlAttempts':2, 'predecessorEngineGetAttempts':0,
    'maximumCumulativeEngineGetAttempts':20, 'maximumCorrectiveSeconds':90,
    'predecessorClockResumed':False, 'predecessorClockReset':False,
    'automaticReplayAllowed':False, 'partialOutputPreserved':True,
    'runtimeBudgetsGranted':False}
ROSTER = {'mcp': {'containerId': '756f70a813a0a01218b9d9a07d56c01702364b67943181b8cc339be98d96531a', 'nativeBindingHash': 'd5750f01ee879ba43c28d97385ffd835c3e2836a48e6346d6bce5293a4831c19', 'generation': {'namespaces': {'mnt': [4, 4026533223], 'net': [4, 4026533228]}, 'pid': 3305562, 'startTicks': 85434936}}, 'onboarding': {'containerId': '63a6e12202e700b8439d73e19e9375067a53021bc58b80d09f3a7f2bde2446ad', 'nativeBindingHash': 'c6f72349b8b3a9f7d11f7b9c63fe0f67a159e3be3ea56f9b2a349a9e8f48a2d7', 'generation': {'namespaces': {'mnt': [4, 4026532358], 'net': [4, 4026532422]}, 'pid': 3556687, 'startTicks': 91092970}}, 'postgres': {'containerId': '50b36d71620ad00fee1bae45aaf0bf652b9171dc09f567fa552798daf12614ea', 'nativeBindingHash': 'bf415c693941f5758c57052b6ed733a9b39d5e55e8b114e19f496175414cf856', 'generation': {'namespaces': {'mnt': [4, 4026532488], 'net': [4, 4026532493]}, 'pid': 27732, 'startTicks': 2999147}}, 'minio': {'containerId': '5856be83ef3baa11fbed0f7a1639b54ac88f009738f8938c8707541b3677da34', 'nativeBindingHash': '74071a3af2183a1d4d321eab4d78857ecfcb30bff0673efe35a7318ba0073493', 'generation': {'namespaces': {'mnt': [4, 4026532614], 'net': [4, 4026532621]}, 'pid': 27736, 'startTicks': 2999147}}, 'keycloak': {'containerId': '5c3967a7a0cf1a054ba1fec702ddc0b97cf96d1e45bd45d45d27b393f6a1f273', 'nativeBindingHash': '1aba1e0db278b47ae57921b9c8ba18e7c0f72b15140de4fc28f98b18ed8b1694', 'generation': {'namespaces': {'mnt': [4, 4026532552], 'net': [4, 4026532557]}, 'pid': 27735, 'startTicks': 2999147}}, 'semantic': {'containerId': '790c62742c92eabc095d4ab22f2070e0c40a41e4a219685a7d8120e4661e4e5d', 'nativeBindingHash': '46b5e7dec97ebb90d0cd1b9a7e6c51a377f4449a56f435ae0550441a2bc98180', 'generation': {'namespaces': {'mnt': [4, 4026532883], 'net': [4, 4026533095]}, 'pid': 1600272, 'startTicks': 45983165}}, 'gateway-owner': {'containerId': '8daa3d7a4afcffeb39bf8c63c0891abf1679d8ce43880d3f29ff41b3f2f7e6e9', 'nativeBindingHash': 'a63036c59e5d62c520bc706b3580bca7b02647610e1e540b2dd860f4671ac220', 'generation': {'namespaces': {'mnt': [4, 4026532698], 'net': [4, 4026532703]}, 'pid': 27739, 'startTicks': 2999147}}, 'udp': {'containerId': '946fd69972ada2e310c32f72da27f19a04e7a2043dc330f116e8ba1c507e6e3b', 'nativeBindingHash': 'e3b678315aee32f56dd461bbd793eb724af8ded5e62c7613c16ff26ccd42379c', 'generation': {'namespaces': {'mnt': [4, 4026532893], 'net': [4, 4026532898]}, 'pid': 66601, 'startTicks': 3929670}}, 'ingestion-evidence-read': {'containerId': 'a00f1dddf3ce24c789994efc4d696d985964def0fc9f1e87640cf7231046d63f', 'nativeBindingHash': '401696709abbd763a5be8f380aebf71331a15771229eb3eb8fce7bbf8572799a', 'generation': {'namespaces': {'mnt': [4, 4026532766], 'net': [4, 4026532771]}, 'pid': 2695170, 'startTicks': 71605835}}, 'caddy': {'containerId': 'a75bd1cbb287518509fc24cd1ec4cf712ae93211ef125fa2ba2bb31ad5353ad3', 'nativeBindingHash': '4036440e354e1dcc367c3c28ee1e5f76c1367094bee15b6813e82b841f556461', 'generation': {'namespaces': {'mnt': [4, 4026532936], 'net': [4, 4026532941]}, 'pid': 27762, 'startTicks': 2999148}}, 'udp-evidence-read': {'containerId': 'ae0f27485b800e8ef5ea2d1ba74dd9af9a224caa67df43609eca774d65917b4f', 'nativeBindingHash': 'b58743547f027e6a7d241b7668a4e8b7d28f10a590742d88579a312ba02f93ee', 'generation': {'namespaces': {'mnt': [4, 4026533157], 'net': [4, 4026533162]}, 'pid': 2696660, 'startTicks': 71609227}}, 'apisix': {'containerId': 'd36bef2faf3d25c6aaaadd72bfb6ebe0a85b2838ae6bf477a5471f8b68d9d912', 'nativeBindingHash': '67b344c1d30e10b2458c0e76c8ee7cfdafc2fdf893724529f6a10138881c1555', 'generation': {'namespaces': {'mnt': [4, 4026532653], 'net': [4, 4026532675]}, 'pid': 856013, 'startTicks': 25388511}}, 'ingestion': {'containerId': 'd69c3f763d75f8c8f8db382fef0159a4dd5a3b99ee62ae8737a24421f4285c14', 'nativeBindingHash': '237e925bed3224bdfb478f218e5e220e3e5fadd012005d0443901e2f96ac98bc', 'generation': {'namespaces': {'mnt': [4, 4026532363], 'net': [4, 4026532368]}, 'pid': 1228064, 'startTicks': 35227200}}}


def stable_binding(actual):
    # Original 8af878ec producer contract, including mount sorting by destination.
    return {'containerId':actual['Id'], 'imageId':actual['Image'], 'name':actual['Name'],
        'pid':actual['State']['Pid'], 'startedAt':actual['State']['StartedAt'],
        'configHash':digest(actual['Config']), 'hostConfigHash':digest(actual['HostConfig']),
        'mountsHash':digest(sorted(actual['Mounts'], key=lambda v:v['Destination'])),
        'networkSettingsHash':digest(actual['NetworkSettings']),
        'profile':'ouf.acquisition-read.mount-set-binding.v1'}


def reconcile_predecessor(c, root):
    root = Path(root); c.guarded(); c.ancestors(root/'result.json')
    before = attrs(root.lstat())
    require(stat.S_ISDIR(before[2]) and before[3:5] == [0,0]
        and stat.S_IMODE(before[2]) == 0o700
        and {v.name for v in root.iterdir()} == {'capture.claim.json','result.json'},
        'EXACT_UNMODIFIED_FAILED_CAPTURE_DIRECTORY_REQUIRED')
    claim = decode(c.read(root/'capture.claim.json',0,0,0o600,4096,'metadataReads'))
    result = decode(c.read(root/'result.json',0,0,0o600,4096,'metadataReads'))
    require(claim == {'schema':'ouf.m2-discovery-custody-capture-claim.v1','automaticReplayAllowed':False}
        and digest(result) == PREDECESSOR_HASH,
        'EXACT_PRE_ENGINE_LABEL_FAILURE_REQUIRED_NO_REPLAY')
    require(before == attrs(root.lstat()), 'FAILED_CAPTURE_DIRECTORY_CHANGED')
    # This exact reason has one call site in the pinned old source: before
    # roots(), Engine construction, GETs and mount metadata. Old result had no
    # counters/clock; this inference is source-derived, not measured telemetry.
    c.put('predecessor-reconciliation.json',{
        'schema':'ouf.retained-mount-failed-predecessor-reconciliation.v1',
        'predecessorScope':str(root),'predecessorResultHash':PREDECESSOR_HASH,
        'predecessorSourceSha256':PREDECESSOR_SOURCE_SHA256,
        'predecessorEngineGets':0,'predecessorMountedMetadataReads':0,
        'zeroEffectsBasis':'EXACT_FAILURE_POINT_IN_PINNED_SOURCE_NOT_REPORTED_COUNTERS',
        'predecessorClockAvailable':False,'predecessorPreserved':True,
        'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'profile':PROFILE})
    return before


def select_roles(seed, roster):
    require(seed.get('schema') == 'ouf.m2-discovery-current-private-bindings.v1',
        'ORIGINAL_PRIVATE_COHORT_SCHEMA_REQUIRED')
    require(all(seed.get(k) is False for k in ('historicalAuthorityReused','runtimeAuthorityIssued',
        'automaticReplayAllowed','budgetReset')), 'UNADMITTED_COHORT_REQUIRED')
    observations, pins = seed['observations'], seed['processPins']
    require(type(observations) is dict and type(pins) is dict and len(observations) == 13
        and set(observations) == set(pins) and set(roster) == ROLES,
        'THIRTEEN_INVENTORY_ALIAS_AND_PIN_DOMAIN_REQUIRED')
    ids = [v.get('Id') for v in observations.values()]
    wanted = [v['containerId'] for v in roster.values()]
    require(all(type(cid) is str and re.fullmatch('[a-f0-9]{64}',cid) for cid in ids+wanted)
        and len(set(ids)) == len(set(wanted)) == 13 and set(ids) == set(wanted),
        'EXACT_THIRTEEN_UNIQUE_PUBLIC_ROSTER_IDS_REQUIRED')
    mapping = {}
    for role, expected in sorted(roster.items()):
        alias, = [alias for alias,row in observations.items() if row['Id'] == expected['containerId']]
        row, generation = observations[alias], pins[alias]
        require(digest(stable_binding(row)) == expected['nativeBindingHash']
            and generation == expected['generation'] and row['State']['Pid'] == generation['pid']
            and row['State']['Running'] is True and row['State']['Paused'] is False
            and row['State']['Restarting'] is False,
            'EXACT_PUBLIC_ROSTER_FULL_BINDING_AND_GENERATION_REQUIRED')
        mapping[role] = alias
    require(len(set(mapping.values())) == 13, 'ONE_TO_ONE_ID_SELECTED_ROLE_MAPPING_REQUIRED')
    return mapping


def collect(c, seed_path=SEED, seed_hash=SEED_HASH, *, predecessor_root=PREDECESSOR,
        roster=ROSTER, engine_factory=RetainedEngine, pin=process_pin,
        boot_path=Path('/proc/sys/kernel/random/boot_id')):
    predecessor_metadata = reconcile_predecessor(c, predecessor_root)
    seed = decode(c.read(seed_path,0,0,0o600,2097152,'metadataReads'))
    require(digest(seed) == seed_hash, 'EXACT_ORIGINAL_PRIVATE_SEED_HASH_REQUIRED')
    role_map = select_roles(seed,roster)
    # Require this exact regression, not an alternative cause hidden by the
    # old compound guard. No arbitrary seed can obtain a corrective pass.
    require(set(seed['observations']) != ROLES, 'EXACT_INVENTORY_LABEL_REGRESSION_REQUIRED')
    observations = {r:seed['observations'][alias] for r,alias in role_map.items()}
    pins = {r:seed['processPins'][alias] for r,alias in role_map.items()}
    def roots():
        c.guarded()
        require(set(seed['rootProcessPins']) == {'pid1','engine'}
            and seed['rootProcessPins']['pid1']['pid'] == 1
            and seed['rootProcessPins']['engine']['pid'] == seed['engineBinding']['peerCredentials'][0]
            and boot_path.read_text().strip() == seed['bootId']
            and all(pin(v['pid']) == v for v in seed['rootProcessPins'].values()),
            'RETAINED_CAPTURE_BOOT_OR_ROOT_GENERATION_CHANGED')
        require(all(pin(pins[r]['pid']) == pins[r] for r in RETAINED),
            'RETAINED_CAPTURE_PROCESS_GENERATION_CHANGED')
        require(attrs(Path(predecessor_root).lstat()) == predecessor_metadata
            and {v.name for v in Path(predecessor_root).iterdir()} == {'capture.claim.json','result.json'},
            'FAILED_PREDECESSOR_CHANGED_DURING_CORRECTION')
    roots(); engine = engine_factory(c, seed['engineBinding'], [observations[r]['Id'] for r in sorted(RETAINED)])
    proofs = {}
    for role in sorted(RETAINED):
        prior = observations[role]; actual = engine.get(prior['Id']); roots()
        require(identity(actual) == identity(prior), 'RETAINED_CAPTURE_REVIEWED_CONFIGURATION_CHANGED')
        proofs[role] = {'containerId': actual['Id'], 'imageId': actual['Image'],
            'runtimeIdentityHash': digest(identity(actual)), 'processPin': pins[role], 'mounts': c.mounts(actual)}
    for role in sorted(RETAINED):
        actual = engine.get(proofs[role]['containerId']); roots()
        require(digest(identity(actual)) == proofs[role]['runtimeIdentityHash'], 'RETAINED_CAPTURE_CHANGED_DURING_TWO_PASSES')
    for path, (before, static) in c.observed.items():
        fd = c.node(path)
        try:
            after = attrs(os.fstat(fd))
            require(after == before if static else after[:5] == before[:5], 'RETAINED_MOUNT_SOURCE_CHANGED_DURING_CAPTURE')
        finally: os.close(fd)
    roots(); require(c.counts['engineGets'] == 20, 'EXACT_TWENTY_RETAINED_GETS_REQUIRED')
    require(all(attrs(Path(p).lstat()) == v for p, v in c.seals.items()), 'RETAINED_CAPTURE_SEED_CHANGED')
    record = {'schema': 'ouf.m2-retained-mount-custody-candidates.v1', 'seedHash': seed_hash,
        'bootId': seed['bootId'], 'peers': proofs, 'limits': LIMITS, 'budgetProfile': PROFILE, 'publicRosterHash':PUBLIC_ROSTER_HASH,
        'inventoryRoleMap':role_map,'predecessorResultHash':PREDECESSOR_HASH,
        'observedMetadataIsExpectedPolicy': False, 'mountFileContentsObserved': False, 'mutableContentsObserved': False,
        'runtimeAuthorityIssued': False, 'targetApplyAuthorized': False, 'releaseAcceptance': False}
    require(len(encoded(record)) <= 8388608, 'BOUNDED_PRIVATE_RETAINED_CANDIDATES_REQUIRED')
    c.put('retained-mounts.private.json', record)
    return {'schema': 'ouf.m2-retained-mount-role-correction-result.v1', 'status': 'PRIVATE_MOUNT_CANDIDATES_CAPTURED_NOT_ADMITTED',
        'scope': str(c.scope), 'candidateHash': digest(record), 'counts': dict(c.counts), 'selectedRetainedPeers': 10,
        'predecessorPreserved':True,'predecessorResultHash':PREDECESSOR_HASH,
        'predecessorEngineGetAttempts':0,'cumulativeEngineGetAttempts':c.counts['engineGets'],
        'cumulativeControlAttempts':2,'automaticReplayAllowed':False,
        'retainedRuntimeImageIds': {r: proofs[r]['imageId'] for r in sorted(proofs)},
        'completePrivateCustodyProven': False, 'mountFileContentsObserved': False, 'mutableContentsObserved': False,
        'privateInputPathsOrValuesPrinted': False,
        'runtimeAuthorityIssued': False, 'targetApplyAuthorized': False, 'releaseAcceptance': False}



def main():
    c = None
    try:
        c = RetainedCapture(OUTPUT); result = collect(c); c.put('result.json',result); code = 0
    except Exception as error:
        reason = str(error) if type(error) is Stop and re.fullmatch('[A-Z0-9_]{1,128}',str(error)) else 'RETAINED_MOUNT_ROLE_CORRECTION_UNPROVEN'
        result = {'schema':'ouf.m2-retained-mount-role-correction-result.v1','status':'STOP_RECONCILE',
            'reasonCode':reason,'scopeConsumed':os.path.lexists(OUTPUT),
            'counts':dict(c.counts) if c is not None else {},
            'predecessorResultHash':PREDECESSOR_HASH,
            'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'automaticReplayAllowed':False}
        if c is not None:
            try:c.put('result.json',result)
            except Exception:pass
        code = 1
    print(json.dumps(result,sort_keys=True)); return code

if __name__ == '__main__': raise SystemExit(main())
