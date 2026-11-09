"""Independent OCI expectation for the retained, discovery-disabled Registry.

Consumes the saved pre-CREATE request and the pinned Docker 29 baseline, never
an observed OCI. This is a peer identity recipe, not a mount custody policy,
rootfs seal, signature, runtime profile or permission to start a workload.
"""
import copy
import hashlib
import json
import re

from tools.semantic_frame_compiler.compile_creation_frame_policy import (
    canonical, compile_policy, docker_context, environment, path, require,
)

BASELINE_SHA = 'ea86df348ace963d41d3a24ab3b9bea693c3b3ba36e181a1aaec5f7e97333b63'
ENGINE = {'serverVersion': '29.8.1', 'storageDriver': 'overlayfs',
          'cgroupDriver': 'systemd', 'backend': 'containerd-overlayfs'}
GATE = 'OUF_APPLICATION_GATE=0; trap "OUF_APPLICATION_GATE=1" USR1; while [ "$OUF_APPLICATION_GATE" = 0 ]; do sleep 1 & wait "$!"; done; exec "$@"'
ENTRY = ['/bin/sh', '-c', GATE, 'ouf-gated-application']
JAVA = ['java', '-XX:MaxRAMPercentage=75', '-jar', '/app/application.jar']


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def readonly_binds(host):
    bindings = []
    for row in host.get('Mounts') or []:
        require(type(row) is dict and set(row) == {'Type', 'Source', 'Target', 'ReadOnly'}
                and row['Type'] == 'bind' and row['ReadOnly'] is True,
                'EXACT_READONLY_BIND_DECLARATION_REQUIRED')
        bindings.append({'source': path(row['Source']), 'target': path(row['Target'])})
    for row in host.get('Binds') or []:
        require(type(row) is str and len(row.split(':')) == 3 and row.split(':')[2] == 'ro',
                'EXACT_READONLY_BIND_DECLARATION_REQUIRED')
        source, target, _ = row.split(':')
        bindings.append({'source': path(source), 'target': path(target)})
    require(len(bindings) == 4 and len({b['source'] for b in bindings}) == 4
            and len({b['target'] for b in bindings}) == 4, 'FOUR_DISTINCT_RETAINED_BINDS_REQUIRED')
    for a in bindings:
        require(a['source'] != '/' and a['target'] != '/' and a['target'] not in
                ('/etc/hosts', '/etc/hostname', '/etc/resolv.conf'), 'ENGINE_MOUNT_SHADOW_DENIED')
        require(not any(a['target'].startswith(b['target'] + '/') or
                        b['target'].startswith(a['target'] + '/') for b in bindings if a != b),
                'RETAINED_BIND_SHADOW_DENIED')
    return bindings


def host_profile(host, baseline):
    """Explicit Docker inspect defaults; unknown fields do not disappear."""
    empty = ('ContainerIDFile VolumeDriver VolumesFrom CapAdd Dns DnsOptions DnsSearch ExtraHosts '
             'GroupAdd Links Cgroup PidMode UTSMode UsernsMode Isolation CgroupParent '
             'BlkioWeightDevice BlkioDeviceReadBps BlkioDeviceWriteBps BlkioDeviceReadIOps '
             'BlkioDeviceWriteIOps CpusetCpus CpusetMems Devices DeviceCgroupRules DeviceRequests '
             'Ulimits StorageOpt Sysctls Annotations Tmpfs').split()
    zeros = ('CpuShares BlkioWeight CpuPeriod CpuQuota CpuRealtimePeriod CpuRealtimeRuntime '
             'MemoryReservation CpuCount CpuPercent IOMaximumIOps IOMaximumBandwidth '
             'KernelMemory KernelMemoryTCP OomScoreAdj').split()
    false = 'AutoRemove Privileged PublishAllPorts ReadonlyRootfs'.split()
    selected = {'Binds', 'Mounts', 'LogConfig', 'NetworkMode', 'PortBindings', 'RestartPolicy',
                'ConsoleSize', 'CapDrop', 'SecurityOpt', 'CgroupnsMode', 'IpcMode', 'ShmSize',
                'Runtime', 'Memory', 'MemorySwap', 'NanoCpus', 'PidsLimit', 'OomKillDisable',
                'MemorySwappiness', 'MaskedPaths', 'ReadonlyPaths', 'Init'}
    require(type(host) is dict and not set(host) - set(empty) - set(zeros) - set(false) - selected,
            'UNKNOWN_RETAINED_HOST_PROPERTY')
    require(all(host.get(k) in (None, '', [], {}) for k in empty)
            and all(type(host.get(k, 0)) is int and host.get(k, 0) == 0 for k in zeros)
            and all(host.get(k, False) is False for k in false), 'UNREVIEWED_HOST_OVERRIDE')
    require(host.get('CapDrop') == ['ALL'] and host.get('SecurityOpt') == ['no-new-privileges:true']
            and host.get('Runtime', 'runc') == 'runc' and host.get('IpcMode', 'private') == 'private'
            and host.get('CgroupnsMode', 'private') == 'private' and host.get('ShmSize', 67108864) == 67108864
            and host.get('RestartPolicy') == {'Name': 'no', 'MaximumRetryCount': 0}
            and host.get('ConsoleSize', [0, 0]) == [0, 0] and not host.get('PortBindings')
            and host.get('Init') in (None, False) and host.get('OomKillDisable') in (None, False)
            and host.get('MemorySwappiness') is None, 'EXACT_RETAINED_HARDENING_REQUIRED')
    require(all(host.get(k) is None or host[k] == baseline['linux'][v]
                for k, v in [('MaskedPaths', 'maskedPaths'), ('ReadonlyPaths', 'readonlyPaths')]),
            'RETAINED_KERNEL_PATH_OVERRIDE')
    require(type(host.get('Memory')) is int and 0 < host['Memory'] == host.get('MemorySwap') <= 8589934592
            and type(host.get('PidsLimit')) is int and 1 <= host['PidsLimit'] <= 4096
            and type(host.get('NanoCpus', 0)) is int and 0 <= host.get('NanoCpus', 0) <= 8000000000
            and host.get('NanoCpus', 0) % 10000 == 0, 'FINITE_RETAINED_RESOURCES_REQUIRED')


def compile_peer(raw_baseline, request, context, *, engine_profile):
    require(type(raw_baseline) is bytes and hashlib.sha256(raw_baseline).hexdigest() == BASELINE_SHA,
            'PINNED_INDEPENDENT_ENGINE_BASELINE_REQUIRED')
    baseline = json.loads(raw_baseline)
    require(baseline['engine'] == engine_profile == ENGINE and baseline['role'] == 'southbound'
            and baseline['syntheticFixture'] is True and baseline['targetTemplateApproved'] is False
            and baseline['mountOrdering'] == 'depth-path', 'EXACT_INDEPENDENT_BASELINE_REQUIRED')
    require(context['networkNamespaceName'] is None and context['cgroupDriver'] == 'systemd'
            and context['rootfsPath'] == context['storageParent'] + '/rootfs/overlayfs/' + context['containerId'],
            'EXACT_PRIVATE_OVERLAYFS_CONTEXT_REQUIRED')
    docker_context(context)
    # Existing compiler resolves the baseline's closed Docker path slots. Its
    # synthetic source descriptors are not promoted to target custody claims.
    oci = compile_policy(baseline['template'], baseline['launch'], context)['expectedOci']
    require(type(request) is dict and len(canonical(request)) <= 131072
            and request.get('User') == '10001:10001' and request.get('Entrypoint') == ENTRY
            and request.get('Cmd') == JAVA and request.get('WorkingDir') == '/app'
            and re.fullmatch('sha256:[a-f0-9]{64}', request.get('Image', '')),
            'EXACT_RETAINED_GATE_REQUEST_REQUIRED')
    require(request.get('Tty', False) is False and request.get('Domainname') in (None, '')
            and not request.get('NetworkDisabled') and not request.get('Volumes')
            and 'MacAddress' not in request, 'EXACT_NONTTY_ENDPOINT_MAC_PROFILE_REQUIRED')
    hostname = request.get('Hostname') or context['containerId'][:12]
    require(type(hostname) is str and re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9.-]{0,62}', hostname),
            'EXPLICIT_RETAINED_HOSTNAME_REQUIRED')
    env = environment(request.get('Env'))
    require(env.get('PATH') and 'HOSTNAME' not in env
            and env.get('OUF_SCHEMA_GOV_ENABLED') == env.get('OUF_DISCOVERY_WORKER_ENABLED') == 'false',
            'EXPLICIT_DISABLED_DISCOVERY_AND_IMAGE_ENV_REQUIRED')
    require(not set(env) & {'JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', '_JAVA_OPTIONS'}
            and not any(k.startswith('SPRING_') and k != 'SPRING_CONFIG_IMPORT' for k in env)
            and not any(k.lower().replace('_', '') in {'oufsemanticprovidersschemagovenabled',
                'oufsemanticdiscoveryworkerenabled'} for k in env), 'HIGHER_PRIORITY_FEATURE_OVERRIDE_DENIED')
    host = request['HostConfig']; host_profile(host, oci)
    endpoints = request.get('NetworkingConfig', {}).get('EndpointsConfig', {})
    require(type(endpoints) is dict and len(endpoints) == 1, 'ONE_NAMED_BRIDGE_REQUIRED')
    network, endpoint = next(iter(endpoints.items()))
    require(re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', network)
            and network not in ('host', 'none', 'bridge', 'default') and host['NetworkMode'] == network
            and type(endpoint) is dict and not endpoint.get('Links'), 'EXPLICIT_PRIVATE_NAMED_BRIDGE_REQUIRED')
    binds = readonly_binds(host)
    require(env.get('SPRING_CONFIG_IMPORT', '').startswith('configtree:')
            and env['SPRING_CONFIG_IMPORT'].endswith('/')
            and env['SPRING_CONFIG_IMPORT'][11:-1] in {b['target'] for b in binds},
            'DECLARED_READONLY_CONFIGTREE_REQUIRED')
    oci['hostname'] = hostname
    oci['process'].update(user={'uid': 10001, 'gid': 10001, 'additionalGids': [10001]},
                          args=copy.deepcopy(ENTRY + JAVA), cwd='/app',
                          env=['PATH=' + env['PATH'], 'HOSTNAME=' + hostname] +
                              [v for v in request['Env'] if not v.startswith('PATH=')])
    resources = oci['linux']['resources']
    resources['memory'] = {'limit': host['Memory'], 'swap': host['MemorySwap']}
    resources['pids'] = {'limit': host['PidsLimit']}
    if host.get('NanoCpus', 0):
        resources['cpu'] = {'period': 100000, 'quota': host['NanoCpus'] // 10000}
    targets = {s['target'] for s in baseline['launch']['sources']}
    defaults = [m for m in oci['mounts'] if m['type'] != 'bind']
    engine_mounts = [m for m in oci['mounts'] if m['type'] == 'bind' and m['destination'] not in targets]
    require({m['destination'] for m in engine_mounts} == {'/etc/hosts', '/etc/hostname', '/etc/resolv.conf'},
            'EXACT_BASELINE_ENGINE_MOUNTS_REQUIRED')
    mounted = [{'type': 'bind', 'source': b['source'], 'destination': b['target'],
                'options': ['rbind', 'rro', 'rprivate']} for b in binds]
    oci['mounts'] = defaults + sorted(mounted + engine_mounts,
                                    key=lambda m: (m['destination'].count('/'), m['destination']))
    return {'schema': 'ouf.retained-semantic-peer-recipe.v1', 'expectedOci': oci,
            'applicationHash': digest(oci), 'creationRequestHash': digest(request),
            'engineBaselineSha256': BASELINE_SHA, 'context': copy.deepcopy(context),
            'observedOciUsedAsExpectation': False, 'mountContentsVerified': False,
            'rootfsSealProduced': False, 'inputsAuthenticated': False, 'startAuthorized': False}
