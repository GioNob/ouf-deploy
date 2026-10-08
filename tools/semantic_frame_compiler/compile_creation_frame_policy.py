"""Compile a reviewed frame template without consuming an observed OCI document.

This pure compiler emits the existing observer's v1 policy. It does not review
the template, authenticate its inputs, issue signatures or authorize execution.
The calling authority must authenticate template, launch and Docker context
independently before signing the result. Never derive a template from the OCI
document being checked.
"""
import copy
import hashlib
import json
from pathlib import PurePosixPath
import re


class Denied(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise Denied(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def path(value):
    require(type(value) is str and value.startswith('/') and len(value) <= 4096
            and '\x00' not in value and '..' not in value.split('/')
            and str(PurePosixPath(value)) == value, 'CONTEXT_PATH_REQUIRED')
    return value


def environment(rows):
    require(type(rows) is list and len(rows) <= 256, 'LAUNCH_ENV_REQUIRED')
    result = {}
    for row in rows:
        require(type(row) is str and '=' in row and len(row) <= 16384
                and '\x00' not in row, 'LAUNCH_ENV_REQUIRED')
        name, value = row.split('=', 1)
        require(re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', name) and name not in result,
                'LAUNCH_ENV_REQUIRED')
        result[name] = value
    return result


def docker_context(value):
    """Derive only bounded Docker paths from independently authenticated inputs."""
    fields = {'schema', 'containerId', 'bundleParent', 'metadataParent',
              'networkNamespaceParent', 'networkNamespaceName', 'cgroupDriver', 'rootfsPath', 'storageParent'}
    require(type(value) is dict and set(value) == fields
            and value['schema'] == 'ouf.semantic-docker-frame-context.v1', 'EXACT_CONTEXT_REQUIRED')
    cid = value['containerId']
    require(type(cid) is str and re.fullmatch('[0-9a-f]{64}', cid), 'CONTAINER_ID_REQUIRED')
    # Parent paths remain installer inputs, not values copied from an OCI frame.
    parents = {k: path(value[k]) for k in
               ('bundleParent', 'metadataParent', 'networkNamespaceParent')}
    require(len(set(parents.values())) == 3, 'CONTEXT_PARENTS_DISTINCT_REQUIRED')
    storage, rootfs = path(value['storageParent']), path(value['rootfsPath'])
    require(parents['metadataParent'] == storage + '/containers', 'DOCKER_METADATA_PARENT_REQUIRED')
    require(rootfs == parents['bundleParent'] + '/' + cid + '/rootfs'
            or PurePosixPath(rootfs).is_relative_to(storage) and rootfs != storage,
            'ROOTFS_CONTEXT_OUTSIDE_APPROVED_STORAGE')
    name = value['networkNamespaceName']
    require(name is None or type(name) is str and re.fullmatch('[0-9a-f]{12,64}', name), 'NETWORK_CONTEXT_REQUIRED')
    require(value['cgroupDriver'] in ('systemd', 'cgroupfs'), 'CGROUP_DRIVER_REQUIRED')
    cgroup = 'system.slice:docker:' + cid if value['cgroupDriver'] == 'systemd' else '/docker/' + cid
    return {'rootfs': rootfs,
            'network': None if name is None else parents['networkNamespaceParent'] + '/' + name,
            'cgroup': cgroup, 'hostname': cid[:12],
            **{k: parents['metadataParent'] + '/' + cid + '/' + filename for k, filename in
               (('hosts', 'hosts'), ('hostnameFile', 'hostname'), ('resolv', 'resolv.conf'))}}


def compile_policy(template, launch, context):
    """Resolve seven closed placeholders; retain every other OCI field exactly.

    launch is independently compiled from verified image and launch inputs.
    It supplies application identity/arguments/environment/resources/mounts.
    This function deliberately has no actual-OCI argument and no file I/O.
    """
    require(len(canonical(template)) <= 131072 and len(canonical(launch)) <= 131072,
            'COMPILER_INPUT_UNBOUNDED')
    require(type(template) is dict and set(template) == {'schema', 'expectedOci', 'approvedHooks'}
            and template['schema'] == 'ouf.semantic-creation-frame-template.v1', 'EXACT_TEMPLATE_REQUIRED')
    fields = {'schema', 'manifest', 'startup', 'sources'}
    require(type(launch) is dict and set(launch) == fields
            and launch['schema'] == 'ouf.semantic-creation-frame-launch.v1', 'EXACT_LAUNCH_REQUIRED')
    bound = docker_context(context)
    oci = copy.deepcopy(template['expectedOci'])
    require(type(oci) is dict and type(oci.get('root')) is dict
            and type(oci.get('linux')) is dict and type(oci.get('process')) is dict,
            'OCI_TEMPLATE_REQUIRED')
    require(oci['root'].get('path') == '$OUF_ROOTFS'
            and oci.get('hostname') == '$OUF_HOSTNAME'
            and oci['linux'].get('cgroupsPath') == '$OUF_CGROUPS', 'CLOSED_TEMPLATE_SLOTS_REQUIRED')
    oci['root']['path'] = bound['rootfs']
    oci['hostname'] = bound['hostname']
    oci['linux']['cgroupsPath'] = bound['cgroup']
    namespaces = oci['linux'].get('namespaces')
    require(type(namespaces) is list and all(type(v) is dict for v in namespaces), 'NETWORK_TEMPLATE_REQUIRED')
    networks = [v for v in namespaces if v.get('type') == 'network']
    require(len(networks) == 1 and networks[0].get('path') == '$OUF_NETWORK_NAMESPACE', 'NETWORK_TEMPLATE_REQUIRED')
    if bound['network'] is None:
        # Docker can request a fresh private namespace which runc creates.
        # Its identity is observed later; this grants no namespace acceptance.
        del networks[0]['path']
    else:
        networks[0]['path'] = bound['network']
    mounts = oci.get('mounts')
    require(type(mounts) is list and all(type(v) is dict for v in mounts), 'MOUNT_TEMPLATE_REQUIRED')
    slots = {'/etc/hosts': ('$OUF_HOSTS', 'hosts'),
             '/etc/hostname': ('$OUF_HOSTNAME_FILE', 'hostnameFile'),
             '/etc/resolv.conf': ('$OUF_RESOLV', 'resolv')}
    for target, (sentinel, field) in slots.items():
        found = [v for v in mounts if v.get('destination') == target]
        require(len(found) == 1 and found[0].get('type') == 'bind'
                and found[0].get('source') == sentinel, 'MOUNT_TEMPLATE_REQUIRED')
        found[0]['source'] = bound[field]
    manifest, startup, sources = (copy.deepcopy(launch[k]) for k in ('manifest', 'startup', 'sources'))
    require(type(startup) is dict and set(startup) == {'uid', 'gid', 'umask', 'cwd', 'args', 'env'},
            'EXACT_STARTUP_REQUIRED')
    # This is the one documented Docker-derived environment value. No general
    # substitution facility is available to alter commands or other variables.
    for rows in (oci['process'].get('env'), startup['env']):
        values = environment(rows)
        require(values.get('HOSTNAME') == '$OUF_HOSTNAME', 'HOSTNAME_ENV_SLOT_REQUIRED')
        rows[rows.index('HOSTNAME=$OUF_HOSTNAME')] = 'HOSTNAME=' + bound['hostname']
    process = oci['process']
    require(type(startup['uid']) is int and type(startup['gid']) is int
            and startup['uid'] > 0 and startup['gid'] > 0, 'NONROOT_LAUNCH_REQUIRED')
    require(type(process.get('user')) is dict
            and process['user'].get('uid') == startup['uid']
            and process['user'].get('gid') == startup['gid']
            and process['user'].get('umask') == startup['umask']
            and canonical(process.get('args')) == canonical(startup['args'])
            and process.get('cwd') == startup['cwd']
            and environment(process.get('env')) == environment(startup['env']), 'INDEPENDENT_LAUNCH_DRIFT')
    require(type(manifest) is dict and {'user', 'readOnlyRoot', 'memoryBytes', 'pidsLimit', 'mounts'} <= set(manifest)
            and manifest['user'] == str(startup['uid']) + ':' + str(startup['gid'])
            and type(manifest['readOnlyRoot']) is bool
            and oci['root'].get('readonly', False) is manifest['readOnlyRoot'], 'MANIFEST_DRIFT')
    resources = oci['linux'].get('resources') or {}
    memory, pids = resources.get('memory') or {}, resources.get('pids') or {}
    require(type(manifest['memoryBytes']) is int and type(manifest['pidsLimit']) is int
            and memory.get('limit') == memory.get('swap') == manifest['memoryBytes']
            and pids.get('limit') == manifest['pidsLimit'], 'RESOURCE_LAUNCH_DRIFT')
    declared = manifest['mounts']
    require(type(declared) is list and type(sources) is list and 1 <= len(sources) <= 32
            and len(sources) == len(declared), 'EXACT_SOURCE_SET_REQUIRED')
    require(all(type(v) is dict and set(v) == {'source', 'target', 'readOnly'} for v in declared)
            and all(type(v) is dict and set(v) == {'source', 'target', 'readOnly', 'uid', 'gid', 'mode', 'maxBytes', 'sha256'} for v in sources),
            'EXACT_SOURCE_SET_REQUIRED')
    pairs = {(v['source'], v['target']) for v in declared}
    require(len(pairs) == len(declared) and pairs == {(v['source'], v['target']) for v in sources}, 'EXACT_SOURCE_SET_REQUIRED')
    for source in sources:
        path(source['source']); path(source['target'])
        require(source['readOnly'] is True and type(source['uid']) is int and source['uid'] >= 0
                and type(source['gid']) is int and source['gid'] >= 0
                and type(source['mode']) is int and 0 <= source['mode'] <= 0o777
                and type(source['maxBytes']) is int and 1 <= source['maxBytes'] <= 1048576
                and type(source['sha256']) is str and re.fullmatch('[0-9a-f]{64}', source['sha256']), 'SOURCE_BINDING_REQUIRED')
        found = [v for v in mounts if v.get('destination') == source['target']]
        require(len(found) == 1 and found[0].get('type') == 'bind'
                and found[0].get('source') == source['source']
                and bool({'ro', 'rro'} & set(found[0].get('options') or [])), 'SOURCE_MOUNT_DRIFT')
    require(canonical(oci.get('hooks') or {}) == canonical(template['approvedHooks']), 'HOOK_TEMPLATE_DRIFT')
    result = {'schema': 'ouf.semantic-configured-creation-frame-policy.v1', 'expectedOci': oci,
              'manifest': manifest, 'startup': startup, 'approvedHooks': copy.deepcopy(template['approvedHooks']), 'sources': sources}
    require(b'$OUF_' not in canonical(result), 'UNRESOLVED_TEMPLATE_SLOT')
    require(len(canonical(result)) <= 131072, 'COMPILED_POLICY_UNBOUNDED')
    return result


def compilation_receipt(template, launch, context, policy):
    """Hashes only: do not print policy, source paths or process environment."""
    return {'schema': 'ouf.semantic-creation-frame-compilation.v1',
            **{name + 'Hash': hashlib.sha256(canonical(value)).hexdigest() for name, value in
               (('template', template), ('launch', launch), ('context', context), ('policy', policy))},
            'observedOciUsed': False, 'inputsAuthenticated': False, 'templateApproved': False,
            'kernelEnforcementObserved': False, 'signaturesIssued': 0,
            'acceptanceGranted': False, 'startAuthorized': False}
