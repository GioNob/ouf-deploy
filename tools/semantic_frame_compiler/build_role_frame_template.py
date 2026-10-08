"""Apply independently sealed role inputs to a reviewed Engine baseline.

No target OCI is accepted. This does not approve the baseline, authenticate
inputs, sign policy or authorize start. Root mode and all other Engine fields
remain exactly those of the independently reviewed baseline.
"""
import copy

from compile_creation_frame_policy import canonical, compile_policy, path, require


def build_role_template(template, baseline_launch, launch, approved_user):
    # Validation context only; its output is discarded. No target paths needed.
    context = {'schema': 'ouf.semantic-docker-frame-context.v1',
               'containerId': 'a' * 64, 'bundleParent': '/run/approved/bundles',
               'metadataParent': '/var/lib/approved/containers',
               'networkNamespaceParent': '/run/approved/netns',
               'networkNamespaceName': None, 'cgroupDriver': 'systemd',
               'rootfsPath': '/var/lib/approved/rootfs', 'storageParent': '/var/lib/approved'}
    compile_policy(template, baseline_launch, context)
    require(type(launch) is dict and set(launch) == {'schema', 'manifest', 'startup', 'sources'},
            'EXACT_LAUNCH_REQUIRED')
    startup, manifest = launch['startup'], launch['manifest']
    require(type(startup) is dict and type(manifest) is dict, 'EXACT_LAUNCH_REQUIRED')
    require(type(approved_user) is dict and set(approved_user) <= {'uid', 'gid', 'umask', 'additionalGids'}
            and {'uid', 'gid'} <= set(approved_user)
            and approved_user['uid'] == startup.get('uid')
            and approved_user['gid'] == startup.get('gid')
            and approved_user.get('umask') == startup.get('umask'), 'APPROVED_USER_REQUIRED')
    if 'additionalGids' in approved_user:
        groups = approved_user['additionalGids']
        require(type(groups) is list and len(groups) <= 32
                and all(type(g) is int and 0 <= g < 2**32 for g in groups)
                and len(set(groups)) == len(groups), 'APPROVED_USER_REQUIRED')
    result = copy.deepcopy(template)
    oci = result['expectedOci']
    require(manifest.get('readOnlyRoot') is baseline_launch['manifest']['readOnlyRoot'],
            'ROOT_MODE_REQUIRES_DISTINCT_REVIEWED_BASELINE')
    oci['process']['user'] = copy.deepcopy(approved_user)
    for name in ('args', 'cwd', 'env'):
        require(name in startup, 'EXACT_STARTUP_REQUIRED')
        oci['process'][name] = copy.deepcopy(startup[name])
    resources = oci['linux']['resources']
    resources['memory']['limit'] = resources['memory']['swap'] = manifest.get('memoryBytes')
    resources['pids']['limit'] = manifest.get('pidsLimit')
    baseline_sources = {v['target'] for v in baseline_launch['sources']}
    old_sources = [m for m in oci['mounts'] if m['destination'] in baseline_sources]
    require(old_sources and all(canonical(m['options']) == canonical(old_sources[0]['options'])
                               for m in old_sources), 'DISTINCT_MOUNT_OPTIONS_REQUIRE_REVIEW')
    options = copy.deepcopy(old_sources[0]['options'])
    require('ro' in options or 'rro' in options, 'READ_ONLY_MOUNT_OPTIONS_REQUIRED')
    retained = [m for m in oci['mounts'] if m['destination'] not in baseline_sources]
    default_mounts = [m for m in retained if m['type'] != 'bind']
    engine_mounts = [m for m in retained if m['type'] == 'bind']
    require({m['destination'] for m in engine_mounts} == {'/etc/hosts', '/etc/hostname', '/etc/resolv.conf'},
            'UNKNOWN_BASELINE_BIND_MOUNT')
    role_mounts = []
    declared = manifest.get('mounts')
    require(type(declared) is list and 1 <= len(declared) <= 32, 'EXACT_SOURCE_SET_REQUIRED')
    reserved = {m['destination'] for m in retained}
    for m in declared:
        require(type(m) is dict and set(m) == {'source', 'target', 'readOnly'}
                and m['readOnly'] is True, 'EXACT_SOURCE_SET_REQUIRED')
        source, target = path(m['source']), path(m['target'])
        require(target not in reserved and not any(target.startswith(v + '/') or v.startswith(target + '/')
                    for v in reserved), 'SOURCE_MOUNT_SHADOWING_DENIED')
        role_mounts.append({'destination': target, 'type': 'bind', 'source': source,
                            'options': copy.deepcopy(options)})
        reserved.add(target)
    # This bounded constructor models the depth-only ordering exercised by the
    # CI Engine: user mounts precede its fixed network mounts at equal depth.
    # It is not an approved contract for an arbitrary target Engine/version.
    binds = role_mounts + engine_mounts
    binds.sort(key=lambda m: m['destination'].count('/'))
    oci['mounts'] = default_mounts + binds
    compile_policy(result, launch, context)
    return result
