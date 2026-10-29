"""Compile the complete discovery OCI proposal using the unchanged file compiler.

No observed replacement OCI, IO, key bytes or acceptance authority is an input.
The two independently selected directories are checked before projection. All
immutable files, process fields, resources and closed Docker slots still pass
the existing compiler. This new schema cannot enter old file-only observers.
"""
import copy

from tools.semantic_frame_compiler.compile_creation_frame_policy import compile_policy as compile_files
from tools.semantic_frame_compiler.compile_creation_frame_policy import canonical, environment, require
from tools.m2_discovery_installation_profile.native_profile import DiscoveryProfile, FILE_ROLES, JAVA, digest, manifest_bindings


def compile_policy(template, launch, context, *, execution_profile):
    require(type(execution_profile) is DiscoveryProfile, 'EXACT_TYPED_DISCOVERY_PROFILE_REQUIRED')
    profile_hash = execution_profile.verify(execution_profile.request)
    require(type(template) is dict and type(launch) is dict and len(canonical(template)) <= 131072
            and len(canonical(launch)) <= 131072, 'BOUNDED_INDEPENDENT_DISCOVERY_FRAME_REQUIRED')
    selection = execution_profile.selection
    fs, tree, token = (selection[k] for k in ('files', 'configtree', 'renewable_token'))
    wanted_files = [{k: v for k, v in fs[role].items() if k != 'metadataHash'} for role in FILE_ROLES]
    bindings = manifest_bindings(fs, tree, token)
    require(launch.get('sources') == wanted_files and launch.get('manifest', {}).get('mounts') == bindings,
            'EXACT_DISCOVERY_FILES_AND_DIRECTORY_ROLES_REQUIRED')
    request = execution_profile.request
    startup = launch.get('startup', {})
    env = environment(startup.get('env')); expected = environment(request['Env'])
    require(env.pop('HOSTNAME', None) == '$OUF_HOSTNAME' and env == expected
            and startup.get('args') == request['Entrypoint'] + request['Cmd']
            and startup.get('uid') == startup.get('gid') == 10001 and startup.get('cwd') == request['WorkingDir'],
            'DISCOVERY_FRAME_AND_SIGNED_LAUNCH_DRIFT')
    host = request['HostConfig']; manifest = launch['manifest']
    require(type(host.get('ReadonlyRootfs', False)) is bool and manifest.get('readOnlyRoot') == host.get('ReadonlyRootfs', False)
            and manifest.get('memoryBytes') == host['Memory'] and manifest.get('pidsLimit') == host['PidsLimit'],
            'DISCOVERY_FRAME_AND_SIGNED_RESOURCE_DRIFT')
    oci = template.get('expectedOci', {}); mounts = oci.get('mounts')
    require(type(mounts) is list and all(type(m) is dict for m in mounts), 'DISCOVERY_OCI_MOUNT_TEMPLATE_REQUIRED')
    require(len({m.get('destination') for m in mounts}) == len(mounts), 'DUPLICATE_DISCOVERY_OCI_MOUNT_DENIED')
    engine_targets = {'/etc/hosts', '/etc/hostname', '/etc/resolv.conf'}
    require({m.get('destination') for m in mounts if m.get('type') == 'bind'} == engine_targets | {b['target'] for b in bindings},
            'EXACT_DISCOVERY_OCI_BIND_MOUNT_SET_REQUIRED')
    for b in bindings:
        selected = [m for m in mounts if m.get('destination') == b['target']]
        require(len(selected) == 1 and selected[0].get('type') == 'bind' and selected[0].get('source') == b['source']
                and type(selected[0].get('options')) is list and bool({'ro', 'rro'} & set(selected[0]['options']))
                and not {'rw', 'shared', 'rshared', 'slave', 'rslave'} & set(selected[0]['options']),
                'EXACT_PRIVATE_READONLY_DISCOVERY_OCI_BIND_REQUIRED')
    resources = oci.get('linux', {}).get('resources', {})
    require(resources.get('cpu') == {'period': 100000, 'quota': host['NanoCpus'] // 10000}
            and oci.get('process', {}).get('noNewPrivileges') is True
            and oci.get('process', {}).get('capabilities') == {}, 'DISCOVERY_CPU_OR_PROCESS_HARDENING_DRIFT')
    full_args = request['Entrypoint'] + request['Cmd']
    require(oci.get('process', {}).get('args') == full_args, 'DISCOVERY_GATE_COMMAND_DRIFT')
    projected_template, projected_launch = copy.deepcopy(template), copy.deepcopy(launch)
    dirs = {tree['target'], token['target']}
    projected_template['expectedOci']['mounts'] = [m for m in projected_template['expectedOci']['mounts'] if m['destination'] not in dirs]
    projected_launch['manifest']['mounts'] = bindings[:-2]
    # Only the two exact signed argv lists contain the literal application gate.
    # No environment, key path or other data is exempt from closed-slot scanning.
    projected_template['expectedOci']['process']['args'] = copy.deepcopy(JAVA)
    projected_launch['startup']['args'] = copy.deepcopy(JAVA)
    result = compile_files(projected_template, projected_launch, context)
    resolved = {m['destination']: m for m in result['expectedOci']['mounts']}
    result['expectedOci']['mounts'] = [copy.deepcopy(m) if m['destination'] in dirs else resolved[m['destination']] for m in mounts]
    result['expectedOci']['process']['args'] = copy.deepcopy(full_args)
    result['startup']['args'] = copy.deepcopy(full_args)
    result.update(schema='ouf.semantic-configured-discovery-seven-mount-frame-proposal.v1',
                  executionProfileHash=profile_hash, manifest=copy.deepcopy(manifest),
                  fileBindings=copy.deepcopy(fs), configtree=copy.deepcopy(tree), renewableToken=copy.deepcopy(token))
    checked = copy.deepcopy(result)
    for process in (checked['expectedOci']['process'], checked['startup']):
        require(process['args'] == full_args, 'DISCOVERY_GATE_COMMAND_DRIFT')
        process['args'] = copy.deepcopy(JAVA)
    require(b'$OUF_' not in canonical(checked) and len(canonical(result)) <= 131072,
            'UNRESOLVED_OR_UNBOUNDED_DISCOVERY_FRAME')
    return result


def compilation_receipt(template, launch, context, policy):
    return {'schema': 'ouf.semantic-discovery-frame-compilation.v1',
            **{name + 'Hash': digest(v) for name, v in (('template', template), ('launch', launch), ('context', context), ('policy', policy))},
            'fileRoles': list(FILE_ROLES), 'directoryCount': 2, 'observedOciUsed': False,
            'inputsAuthenticated': False, 'credentialCustodyProven': False, 'providerAdmissionProven': False,
            'nativeExecutorIntegrated': False, 'signaturesIssued': 0, 'startAuthorized': False,
            'runtimeAuthorityIssued': False, 'targetApplyAuthorized': False, 'releaseAcceptance': False}
