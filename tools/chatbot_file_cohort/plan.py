"""Compile the four non-Registry replacements in one reviewed file cohort.

Pure transformation: no discovery, credentials, process execution or authority.
The full installer supplies protected current observations and authenticates the
resulting plan hash before any effect. Registry keeps its existing owner path.
"""
from copy import deepcopy
import hashlib
import json
import re

PROFILE = 'ouf.chatbot-file-cohort.install.v1'
MODULES = ('udp', 'onboarding', 'ingestion', 'mcp')
USERS = {'udp':'10004:10004', 'onboarding':'10003:10003',
         'ingestion':'10002:10002', 'mcp':'10005:10005'}
NO_RESTART = {'Name':'no', 'MaximumRetryCount':0}
IMAGE = re.compile(r'sha256:[0-9a-f]{64}')
HASH = re.compile(r'[0-9a-f]{64}')
COMMIT = re.compile(r'[0-9a-f]{40}')


class PlanDenied(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise PlanDenied(reason)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def sha(value):
    return type(value) is str and HASH.fullmatch(value) is not None


def environment(entries):
    require(type(entries) is list and len(entries) <= 256, 'BOUNDED_ENVIRONMENT_REQUIRED')
    result = {}
    for entry in entries:
        require(type(entry) is str and '=' in entry and len(entry) <= 65536,
                'EXACT_ENVIRONMENT_ENTRY_REQUIRED')
        name, value = entry.split('=', 1)
        require(re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', name) is not None
                and name not in result and '\x00' not in value, 'ENVIRONMENT_NAME_OR_VALUE_INVALID')
        result[name] = value
    return result


def runtime_pin(actual):
    require(type(actual) is dict and sha(actual.get('Id'))
            and IMAGE.fullmatch(actual.get('Image', '')) is not None,
            'EXACT_OLD_CONTAINER_REQUIRED')
    state = actual.get('State', {})
    require(state.get('Running') is True and state.get('Paused') is False
            and state.get('Status') == 'running' and type(state.get('Pid')) is int
            and state['Pid'] > 1 and type(state.get('StartedAt')) is str
            and state['StartedAt'] != '0001-01-01T00:00:00Z', 'CURRENT_OLD_GENERATION_REQUIRED')
    return {'containerId':actual['Id'], 'imageId':actual['Image'],
            'pid':state['Pid'], 'startedAt':state['StartedAt'],
            **{name+'Hash':digest(actual[key]) for name, key in (
                ('config','Config'), ('hostConfig','HostConfig'),
                ('mounts','Mounts'), ('networkSettings','NetworkSettings'))}}


def creation_host_config(observed):
    """Spell out Docker's proven null-to-false OOM default before approval.

    Native Engine v1.44 create/inspect qualified the exact representation:
    OomKillDisable=null becomes false. No observed field is discarded.
    The documented default roundtrip is compared by host_config_matches;
    an explicit true is never rewritten to false.
    """
    require(type(observed) is dict, 'EXACT_OBSERVED_HOST_CONFIG_REQUIRED')
    result=deepcopy(observed)
    if 'OomKillDisable' in result:
        value=result['OomKillDisable']
        require(value is None or type(value) is bool, 'BOOLEAN_OR_DEFAULT_OOM_CONTROL_REQUIRED')
        if value is None:result['OomKillDisable']=False
    return result


def host_config_matches(expected, actual):
    """Compare requested fields; only Docker's default OOM forms are equivalent.

    Moby daemon_unix.go assigns false at create, then may restore nil when the
    kernel lacks OomKillDisable. Both mean no disable requested. Explicit true,
    a missing key or another type is never accepted as this default. The native
    dictionaries and their signed/generation hashes are never rewritten.
    """
    # One owner comparator also covers created/started Registry phases. The
    # only extra equivalence is requested Mounts=[] versus omitempty null/absent;
    # exact Binds and independently realized mount projections remain required.
    from engine_creation import started_host_config_matches
    return started_host_config_matches(expected,actual)


def compile_replacement(module, old, image, package, cohort_id, env_changes):
    require(module in MODULES and re.fullmatch(r'[a-z0-9-]{1,60}', cohort_id or '') is not None,
            'EXACT_COHORT_MODULE_AND_ID_REQUIRED')
    require(old.get('Name') == '/ouf-'+module, 'SELECTED_CONTAINER_NAME_DRIFT')
    pin = runtime_pin(old)
    package_image=image.get('Id')
    if 'archiveAudit' in image:
        from image_custody import runtime_image_id
        audit=image['archiveAudit']
        require(runtime_image_id(audit)==image.get('Id') and audit['sourceCommit']==package.get('sourceCommit')
                and audit['imageConfig']==image.get('Config'),'EXACT_PACKAGE_NATIVE_IMAGE_BINDING_REQUIRED')
        package_image=audit['imageId']
    require(package.get('module') == module and COMMIT.fullmatch(package.get('sourceCommit', ''))
            and package.get('artifactKind') == 'DOCKER_SAVE'
            and package.get('imageId') == package_image
            and IMAGE.fullmatch(image.get('Id', '')) is not None
            and package.get('scanGate') == 'PASS_HIGH_CRITICAL_UNKNOWN_INCLUDING_UNFIXED',
            'EXACT_QUALIFIED_IMAGE_PACKAGE_REQUIRED')
    config, host = deepcopy(old['Config']), creation_host_config(old['HostConfig'])
    candidate = image['Config']
    require(config.get('User') == candidate.get('User') == USERS[module],
            'MODULE_RUNTIME_USER_DRIFT')
    require(host.get('RestartPolicy') in (NO_RESTART, {'Name':'unless-stopped','MaximumRetryCount':0}),
            'UNREVIEWED_RESTART_POLICY_DENIED')
    require(host.get('AutoRemove') is not True and host.get('Privileged') is not True
            and not host.get('Links') and not host.get('VolumesFrom') and not host.get('ContainerIDFile')
            and not str(host.get('PidMode', '')).startswith('container:')
            and not str(host.get('IpcMode', '')).startswith('container:'),
            'NON_INDEPENDENT_CONTAINER_REQUIRES_REVIEW')
    networks = old['NetworkSettings'].get('Networks')
    require(type(networks) is dict and set(networks) == {'ouf-backend'}
            and host.get('NetworkMode') == 'ouf-backend', 'EXACT_EXISTING_BACKEND_NETWORK_REQUIRED')
    network = networks['ouf-backend']
    require(sha(network.get('NetworkID')) and not network.get('IPAMConfig'),
            'STATIC_ENDPOINT_REASSIGNMENT_REQUIRES_REVIEW')
    # Preserve current mounted secrets/data and their access mode. New mounts
    # cannot be smuggled in with an image; they require a separately reviewed plan.
    require(type(old.get('Mounts')) is list and len(old['Mounts']) <= 32,
            'BOUNDED_EXISTING_MOUNTS_REQUIRED')
    declared = set((candidate.get('Volumes') or {}).keys())
    current = {m.get('Destination') for m in old['Mounts']}
    require(declared <= current, 'NEW_IMAGE_VOLUME_REQUIRES_REVIEW')
    values = environment(config.get('Env') or [])
    require(type(env_changes) is dict and set(env_changes) <= {'set', 'remove'}
            and type(env_changes.get('set', {})) is dict
            and type(env_changes.get('remove', [])) is list, 'EXPLICIT_ENVIRONMENT_DELTA_REQUIRED')
    additions, removals = env_changes.get('set', {}), env_changes.get('remove', [])
    require(len(set(removals)) == len(removals) and not (set(removals) & set(additions))
            and set(removals) <= set(values), 'ENVIRONMENT_DELTA_CONFLICT')
    environment([k+'='+v for k, v in additions.items() if type(k) is str and type(v) is str])
    require(all(type(k) is str and type(v) is str for k, v in additions.items()),
            'ENVIRONMENT_DELTA_TYPE_INVALID')
    values.update(additions)
    for name in removals:
        del values[name]
    config['Env'] = [name+'='+value for name, value in sorted(values.items())]
    config['Image'] = image['Id']
    # Use the new package's reviewed process contract. Preserve application
    # configuration, mounts, network and resource limits from the exact old CID.
    for key in ('Entrypoint', 'Cmd', 'WorkingDir'):
        config[key] = deepcopy(candidate.get(key))
    require(type(config.get('Entrypoint')) is list and config['Entrypoint'],
            'PACKAGED_ENTRYPOINT_REQUIRED')
    require(not config.get('Healthcheck') or config['Healthcheck'] == candidate.get('Healthcheck'),
            'EXISTING_HEALTHCHECK_REQUIRES_EXACT_REVIEW')
    if config.get('Hostname') == old['Id'][:12]:
        config['Hostname'] = ''
    config['Labels'] = {**(config.get('Labels') or {}),
                        'org.opencontainers.image.revision':package['sourceCommit'],
                        'it.ouf.file-cohort':cohort_id}
    host['RestartPolicy'] = deepcopy(NO_RESTART)
    aliases = network.get('Aliases') or []
    require(type(aliases) is list and all(type(a) is str and re.fullmatch(r'[A-Za-z0-9_.-]{1,253}', a)
            for a in aliases), 'EXISTING_NETWORK_ALIAS_INVALID')
    aliases = sorted((set(aliases) - {old['Id'], old['Id'][:12]}) | {'ouf-'+module})
    request = {**config, 'HostConfig':host,
               'NetworkingConfig':{'EndpointsConfig':{'ouf-backend':{
                   'NetworkID':network['NetworkID'], 'Aliases':aliases}}}}
    require(len(encoded(request)) <= 262144, 'BOUNDED_COHORT_CREATION_REQUEST_REQUIRED')
    return {'module':module, 'name':'ouf-'+module,
            'retiredName':'ouf-'+module+'-before-'+cohort_id,
            'sourceCommit':package['sourceCommit'], 'modulePackageHash':digest(package),
            'oldRuntimeBinding':pin, 'oldHostConfig':deepcopy(old['HostConfig']),
            'oldMounts':deepcopy(old['Mounts']), 'creationRequest':request,
            'creationRequestHash':digest(request),
            'environmentDelta':deepcopy(env_changes),
            'readinessPath':'/health/ready' if module == 'mcp' else '/actuator/health/readiness',
            'restoreRestartPolicy':deepcopy(old['HostConfig']['RestartPolicy']),
            'automaticRollbackAllowed':False, 'databaseRestoreAuthorized':False}


def compile_cohort(manifest, observed, images, packages, env_changes, gateway_plan_hash,
                   database_plan_hash, authorization_plan_hash, acceptance_plan_hash=None):
    require(manifest.get('schema') == 'ouf.chatbot-file-cohort-package.v1'
            and sha(gateway_plan_hash) and sha(database_plan_hash) and sha(authorization_plan_hash),
            'COMPLETE_COHORT_OWNER_PLANS_REQUIRED')
    require(acceptance_plan_hash is None or sha(acceptance_plan_hash),
            'EXACT_ACCEPTANCE_OBSERVATION_PLAN_HASH_REQUIRED')
    require(set(observed) == set(images) == set(env_changes) == set(MODULES)
            and set(packages) == {'semantic','gateway',*MODULES}, 'COMPLETE_SIX_MODULE_COHORT_REQUIRED')
    locks = {p.get('cohortSourceLockSha256') for p in packages.values()}
    require(len(locks) == 1 and sha(next(iter(locks))), 'ONE_COHORT_SOURCE_LOCK_REQUIRED')
    rows = manifest.get('modules')
    require(type(rows) is list and len(rows) == 6
            and {r.get('module') for r in rows} == set(packages)
            and manifest.get('sourceLockSha256') == next(iter(locks)), 'MANIFEST_SOURCE_LOCK_BINDING_REQUIRED')
    for row in rows:
        require({k:v for k, v in row.items() if k != 'files'} == packages[row['module']],
                'MODULE_BYTES_OUTSIDE_COHORT_MANIFEST_DENIED')
    replacements = [compile_replacement(m, observed[m], images[m], packages[m], manifest['cohortId'], env_changes[m])
                    for m in MODULES]
    require(len({r['oldRuntimeBinding']['containerId'] for r in replacements}) == 4,
            'DUPLICATE_REPLACEMENT_CONTAINER_DENIED')
    return {'schema':'ouf.chatbot-file-cohort-installation-plan.v1', 'profile':PROFILE,
            'cohortManifestHash':digest(manifest), 'cohortSourceLockSha256':next(iter(locks)),
            'registryModulePackageHash':digest(packages['semantic']),
            'gatewayModulePackageHash':digest(packages['gateway']),
            'replacements':replacements,
            'order':['REGISTRY_VERIFY_HOLD','UDP','ONBOARDING','GATEWAY_ROUTES','INGESTION','MCP','RELEASE'],
            'gatewayPlanHash':gateway_plan_hash, 'databasePlanHash':database_plan_hash,
            'authorizationPlanHash':authorization_plan_hash,
            **({'acceptancePlanHash':acceptance_plan_hash} if acceptance_plan_hash is not None else {}),
            'oldContainersRetained':True, 'automaticRollbackAllowed':False,
            'databaseRestoreAuthorized':False, 'runtimeAuthorityIssued':False,
            'notReleaseAcceptance':True}


def public_review(plan):
    """No environment values, database contents or mounted credential bytes."""
    return {'schema':'ouf.chatbot-file-cohort-public-review.v1', 'planHash':digest(plan),
            'cohortManifestHash':plan['cohortManifestHash'], 'order':plan['order'],
            'modules':[{'module':r['module'], 'sourceCommit':r['sourceCommit'],
                        'oldImage':r['oldRuntimeBinding']['imageId'],
                        'newImage':r['creationRequest']['Image'],
                        'environmentKeysSet':sorted(r['environmentDelta'].get('set', {})),
                        'environmentKeysRemoved':sorted(r['environmentDelta'].get('remove', [])),
                        'mountCount':len(r['oldMounts']), 'oldContainerRetained':True}
                       for r in plan['replacements']],
            'runtimeAuthorityIssued':False, 'notReleaseAcceptance':True}
