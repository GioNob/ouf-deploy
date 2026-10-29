"""Compile private Docker creation intent from a sealed file-secret declaration.

No engine call, privilege, signature, admission, image import or authority is
granted here. The target applicator must reauthenticate/reobserve at each effect.
"""
import copy
import hashlib
import json
import re
import ipaddress


DEFAULT_RESOURCES = {'profile': 'semantic-cutover-v1', 'memoryBytes': 2147483648,
                     'memorySwapBytes': 2147483648, 'nanoCpus': 2000000000,
                     'pidsLimit': 512, 'controlReserveBytes': 2147483648,
                     'freeDiskReserveBytes': 10737418240}


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def compile_creation(declaration, expected_hash, host, resources=None):
    """Plan only. Host facts support feasibility, never runtime admission.

    The same IP/MAC requires a later explicitly governed old-peer detach; this
    request must never be issued while the original endpoint owns that identity.
    Resource limits are proposed technical deltas, not measured application SLOs.
    """
    require(type(expected_hash) is str and re.fullmatch('[a-f0-9]{64}', expected_hash)
            and digest(declaration) == expected_hash, 'SEALED_DECLARATION_HASH_REQUIRED')
    require(declaration.get('schema') == 'ouf.discovery.private-file-secret-runtime-declaration.v1'
            and all(declaration.get(k) is False for k in
                    ('productionApplyReady', 'applicationCutoverAuthorized', 'completeReplacementOciProven')),
            'UNAPPLIED_FILE_SECRET_DECLARATION_REQUIRED')
    image = declaration['candidateImageId']
    require(type(image) is str and re.fullmatch('sha256:[a-f0-9]{64}', image), 'EXACT_CANDIDATE_IMAGE_REQUIRED')
    original = declaration['retainedNativeCreationFrame']
    live = host['semantic']
    require(host.get('status') == 'CURRENT_CUTOVER_HOST_METADATA_CAPTURED'
            and live['containerId'] == original['Id'] and live['imageId'] == original['Image']
            and live['generation'] == {k:original['State'][k] for k in ('Pid','StartedAt','Running')}
            and original['State']['Running'] is True
            and live['installedConfigHash'] == digest(original['Config'])
            and live['installedHostConfigHash'] == digest(original['HostConfig'])
            and live['installedMountsHash'] == digest(original['Mounts'])
            and live['networkSettingsHash'] == digest(original['NetworkSettings']),
            'CURRENT_RETAINED_FRAME_REQUIRED')
    config, proposed = copy.deepcopy(declaration['candidateConfig']), copy.deepcopy(declaration['proposedHostConfig'])
    require(config.get('User') == '10001:10001', 'EXACT_NON_ROOT_CANDIDATE_REQUIRED')
    env = {}
    require(type(config.get('Env')) is list and len(config['Env']) <= 256, 'BOUNDED_CANDIDATE_ENV_REQUIRED')
    for row in config['Env']:
        require(type(row) is str and '=' in row and len(row) <= 65536, 'BOUNDED_CANDIDATE_ENV_REQUIRED')
        key, value = row.split('=', 1)
        require(key not in env, 'DUPLICATE_CANDIDATE_ENV_DENIED')
        env[key] = value
    secret = declaration['databaseSecretProjection']
    require(secret.get('readOnly') is True and secret.get('directoryUid') == 10001
            and secret.get('directoryGid') == 10001 and secret.get('directoryMode') == 0o500
            and secret.get('file',{}).get('name') == 'OUF_SEM_DB_PASSWORD'
            and secret['file'].get('uid') == secret['file'].get('gid') == 10001
            and secret['file'].get('mode') == 0o400, 'EXACT_PRIVATE_SECRET_PROJECTION_REQUIRED')
    require('OUF_SEM_DB_PASSWORD' not in env and 'SPRING_DATASOURCE_PASSWORD' not in env
            and env.get('SPRING_CONFIG_IMPORT') == 'configtree:' + secret['targetDirectory'] + '/',
            'MANDATORY_FILE_SECRET_CONFIGTREE_REQUIRED')
    require(proposed.get('Privileged') is False and proposed.get('Runtime') == 'runc'
            and proposed.get('NetworkMode') not in ('host','none')
            and not str(proposed.get('NetworkMode','')).startswith('container:')
            and not proposed.get('ContainerIDFile'), 'RETAINED_RUNTIME_SCOPE_REQUIRED')
    require(proposed.get('RestartPolicy') == {'Name':'no','MaximumRetryCount':0}, 'RESTART_AUTHORITY_NOT_GRANTED')
    before = original['HostConfig']
    require(set(proposed) == set(before)
            and all(proposed[k] == v for k,v in before.items() if k not in ('Binds','RestartPolicy')),
            'ONLY_PREVIOUSLY_DECLARED_HOST_DELTAS_ALLOWED')
    additions = declaration['hostDelta']['appendedReadOnlyBinds']
    require(type(additions) is list and len(additions) == 4
            and proposed['Binds'] == list(before.get('Binds') or []) + additions,
            'EXACT_FOUR_READONLY_INPUT_ADDITIONS_REQUIRED')
    require(len(declaration['roleOwnedReadOnlyMounts']) == 3
            and all(m.get('readOnly') is True and m.get('uid') == m.get('gid') == 10001
                    and m.get('mode') == 0o400 for m in declaration['roleOwnedReadOnlyMounts']),
            'EXACT_RETAINED_ROLE_INPUT_METADATA_REQUIRED')
    expected = [m['source']+':'+m['target']+':ro' for m in declaration['roleOwnedReadOnlyMounts']]
    expected.append(secret['sourceDirectory']+':'+secret['targetDirectory']+':ro')
    require(additions == expected and len(set(additions)) == 4, 'INPUT_PROJECTION_BINDING_DRIFT')
    for source, target in [(m['source'],m['target']) for m in declaration['roleOwnedReadOnlyMounts']] + [(secret['sourceDirectory'],secret['targetDirectory'])]:
        require(all(type(p) is str and re.fullmatch('/[A-Za-z0-9_./-]+',p)
                    and '..' not in p.split('/') for p in (source,target)), 'EXACT_INPUT_PATH_REQUIRED')
    targets = [m['Destination'] for m in original['Mounts']] + [m['target'] for m in declaration['roleOwnedReadOnlyMounts']] + [secret['targetDirectory']]
    require(len(targets) == len(set(targets))
            and not any(a != b and (a.startswith(b.rstrip('/')+'/') or b.startswith(a.rstrip('/')+'/'))
                        for a in targets for b in targets), 'MOUNT_SHADOWING_DENIED')
    profile = copy.deepcopy(DEFAULT_RESOURCES if resources is None else resources)
    require(set(profile) == set(DEFAULT_RESOURCES) and type(profile['profile']) is str
            and re.fullmatch('[A-Za-z0-9_-]{1,64}',profile['profile'])
            and all(type(profile[k]) is int and 0 < profile[k] <= 107374182400
                    for k in profile if k != 'profile')
            and profile['memorySwapBytes'] == profile['memoryBytes']
            and profile['nanoCpus'] <= 8000000000 and profile['pidsLimit'] <= 4096,
            'FINITE_VERSIONED_RESOURCE_PROFILE_REQUIRED')
    available = host['resources']
    require(all(type(available.get(k)) is int and available[k] > 0 for k in ('MemAvailableBytes','rootFilesystemFreeBytes'))
            and available['MemAvailableBytes'] >= profile['memoryBytes'] + profile['controlReserveBytes']
            and available['rootFilesystemFreeBytes'] >= profile['freeDiskReserveBytes'],
            'HOST_RESOURCE_HEADROOM_UNPROVEN')
    deltas = {'Memory':profile['memoryBytes'], 'MemorySwap':profile['memorySwapBytes'],
              'NanoCpus':profile['nanoCpus'], 'PidsLimit':profile['pidsLimit']}
    changes = {k:{'previous':proposed.get(k),'following':v} for k,v in deltas.items()}
    proposed.update(deltas)
    networks = original['NetworkSettings']['Networks']
    require(type(networks) is dict and len(networks) == 1, 'EXACT_ONE_RETAINED_NETWORK_REQUIRED')
    name, endpoint = next(iter(networks.items()))
    try:
        address = ipaddress.IPv4Address(endpoint['IPAddress'])
    except (KeyError, ValueError):
        raise ValueError('EXACT_RETAINED_IPV4_IDENTITY_REQUIRED') from None
    require(not address.is_multicast and not address.is_unspecified, 'EXACT_RETAINED_IPV4_IDENTITY_REQUIRED')
    require(type(name) is str and re.fullmatch('[A-Za-z0-9_.-]{1,128}', name)
            and re.fullmatch('[a-f0-9]{64}',endpoint['NetworkID'])
            and re.fullmatch(r'[0-9]+(?:\.[0-9]+){3}',endpoint['IPAddress'])
            and re.fullmatch('[a-f0-9]{2}(?::[a-f0-9]{2}){5}',endpoint['MacAddress'])
            and not endpoint.get('GlobalIPv6Address'), 'EXACT_RETAINED_IPV4_IDENTITY_REQUIRED')
    # Preserve only declared aliases, not Docker's per-container generated aliases.
    aliases = endpoint.get('Aliases') or []
    require(type(aliases) is list and len(aliases) <= 16
            and all(type(a) is str and re.fullmatch('[A-Za-z0-9_.-]{1,128}',a) for a in aliases),
            'BOUNDED_RETAINED_NETWORK_ALIASES_REQUIRED')
    aliases = [a for a in aliases if a not in (original['Id'],original['Id'][:12])]
    require(config.get('MacAddress') in (None,'',endpoint['MacAddress']), 'CANDIDATE_MAC_IDENTITY_DRIFT')
    # Modern Engine APIs carry MAC identity on EndpointSettings instead of Config.
    config.pop('MacAddress', None)
    request = {**config,'Image':image,'HostConfig':proposed,'NetworkingConfig':{'EndpointsConfig':{
        name:{'NetworkID':endpoint['NetworkID'],'IPAMConfig':{'IPv4Address':endpoint['IPAddress']},
              'MacAddress':endpoint['MacAddress'],'Aliases':aliases}}}}
    public = {'schema':'ouf.semantic-creation-plan.v1','status':'PLAN_ONLY_NOT_AUTHORITY',
        'declarationHash':expected_hash,'candidateImageId':image,'creationRequestHash':digest(request),
        'retainedContainerId':original['Id'],'resourceProfile':profile,'resourceDeltas':changes,
        'apiConfigProjection':'IMAGE_ID_EXPLICIT_MAC_IN_ENDPOINT_SETTINGS',
        'completeRealizedOciProven':False,'applicationCutoverAuthorized':False,
        'productionApplyReady':False,'observationsAreHistorical':True,
        'r12MayBeReplayed':False,'databaseRestoreAuthorized':False,
        'requiredBeforeEffects':['FRESH_ARTIFACT_CRYPTO_AND_SECURITY_VERIFICATION',
            'FRESH_DECLARATION_SECRET_COMMAND_AND_HOST_CUSTODY','NEW_SOURCE_BOUND_TRANSITION_AUTHORITY',
            'COORDINATE_R12_STOP_REVOKE_AND_RETAIN_CUMULATIVE_HISTORY',
            'QUIESCE_PRODUCERS_AND_FENCED_FRESH_BACKUP',
            'EXCLUSIVE_OLD_ENDPOINT_RELEASE_NO_CONCURRENT_IP_MAC_REUSE',
            'COMPLETE_NEW_OCI_RECIPROCAL_PEER_SIGNED_TRANSPORT_AND_DISTINCT_WORKER',
            'MIGRATION_AWARE_RECOVERY_NO_BLIND_PREVIOUS_SNAPSHOT_RESTORE'],
        'requiredBeforeAcceptance':['CURRENT_IAM_PROVIDER_AND_APPLICATION_READINESS',
            'PRESERVE_CINEMA_AND_PROVE_CSV_BUNDLE_RUN_ACK_OBJECT_SEARCH_CHAIN']}
    return request, public
