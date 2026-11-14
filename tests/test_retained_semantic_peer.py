import copy
import json
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.semantic_frame_compiler.compile_retained_semantic_peer import (
    BASELINE_SHA, ENGINE, ENTRY, JAVA, compile_peer, digest,
)


def fixture():
    request = {'Image': 'sha256:' + 'a' * 64, 'User': '10001:10001',
               'Hostname': 'retained-before-replacement', 'WorkingDir': '/app',
               'Entrypoint': copy.deepcopy(ENTRY), 'Cmd': list(JAVA),
               'Env': ['OUF_SCHEMA_GOV_ENABLED=false', 'PATH=/usr/local/bin:/usr/bin:/bin',
                       'OUF_DISCOVERY_WORKER_ENABLED=false', 'SPRING_CONFIG_IMPORT=configtree:/run/ouf/database/'],
               'HostConfig': {'Memory': 536870912, 'MemorySwap': 536870912, 'PidsLimit': 128,
                              'NanoCpus': 500000000, 'CapDrop': ['ALL'],
                              'SecurityOpt': ['no-new-privileges:true'],
                              'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0},
                              'NetworkMode': 'reviewed-backend',
                              'Mounts': [{'Type': 'bind', 'Source': '/approved/' + role,
                                          'Target': target, 'ReadOnly': True}
                                         for role, target in [('delegation', '/run/secrets/semantic-read-owner.key'),
                                                              ('proposal', '/run/secrets/proposal.key'),
                                                              ('database', '/run/ouf/database'),
                                                              ('policy', '/run/ouf/policy')]]},
               'NetworkingConfig': {'EndpointsConfig': {'reviewed-backend': {
                   'IPAMConfig': {'IPv4Address': '172.29.0.6'}, 'MacAddress': '02:42:ac:1d:00:06'}}}}
    cid = 'c' * 64
    context = {'schema': 'ouf.semantic-docker-frame-context.v1', 'containerId': cid,
               'bundleParent': '/run/containerd/io.containerd.runtime.v2.task/moby',
               'metadataParent': '/var/lib/docker/containers', 'networkNamespaceParent': '/run/docker/netns',
               'networkNamespaceName': None, 'cgroupDriver': 'systemd', 'storageParent': '/var/lib/docker',
               'rootfsPath': '/var/lib/docker/rootfs/overlayfs/' + cid}
    return request, context


class RetainedPeerTests(unittest.TestCase):
    def setUp(self):
        self.raw = (ROOT / 'tools/semantic_frame_compiler/containerd-overlayfs-southbound.json').read_bytes()
        self.request, self.context = fixture()

    def compile(self):
        return compile_peer(self.raw, self.request, self.context, engine_profile=ENGINE)

    def test_explicit_hostname_gate_and_environment_order(self):
        before = copy.deepcopy(self.request)
        recipe = self.compile(); oci = recipe['expectedOci']
        self.assertEqual(oci['hostname'], 'retained-before-replacement')
        self.assertEqual(oci['process']['args'], ENTRY + JAVA)
        self.assertEqual(oci['process']['env'][:2], [self.request['Env'][1], 'HOSTNAME=retained-before-replacement'])
        self.assertEqual(self.request, before)
        self.assertEqual(recipe['applicationHash'], digest(oci))
        self.assertFalse(recipe['mountContentsVerified']); self.assertFalse(recipe['startAuthorized'])

    def test_implicit_hostname_and_unlimited_cpu_use_separate_qualified_defaults(self):
        self.request['Hostname'] = ''; self.request['HostConfig']['NanoCpus'] = 0
        oci = self.compile()['expectedOci']
        self.assertEqual(oci['hostname'], 'c' * 12)
        self.assertNotIn('cpu', oci['linux']['resources'])

    def test_equivalent_readonly_binds_have_identical_expectation(self):
        before = self.compile()['expectedOci']
        host = self.request['HostConfig']
        host['Binds'] = [m['Source'] + ':' + m['Target'] + ':ro' for m in host.pop('Mounts')]
        self.assertEqual(self.compile()['expectedOci'], before)

    def test_rejects_unknown_host_properties_even_when_empty(self):
        self.request['HostConfig']['FutureKernelOverride'] = None
        with self.assertRaisesRegex(ValueError, 'UNKNOWN_RETAINED_HOST_PROPERTY'): self.compile()

    def test_rejects_baseline_drift(self):
        self.raw += b'\n'
        with self.assertRaisesRegex(ValueError, 'PINNED_INDEPENDENT_ENGINE_BASELINE'): self.compile()

    def test_rejects_overrides_and_discovery_enable(self):
        for key, value in [('Privileged', True), ('MaskedPaths', []), ('ReadonlyPaths', []),
                           ('CpuQuota', 12000), ('ShmSize', 128), ('SecurityOpt', ['seccomp=unconfined'])]:
            with self.subTest(key=key):
                self.request, self.context = fixture(); self.request['HostConfig'][key] = value
                with self.assertRaises(ValueError): self.compile()
        self.request, self.context = fixture(); self.request['Env'][0] = 'OUF_SCHEMA_GOV_ENABLED=true'
        with self.assertRaises(ValueError): self.compile()

    def test_rejects_mount_shadow_or_writable_source(self):
        for target, ro in [('/run/ouf', True), ('/etc/hosts', True), ('/run/secrets/proposal.key', False)]:
            self.request, self.context = fixture()
            self.request['HostConfig']['Mounts'][1].update(Target=target, ReadOnly=ro)
            with self.assertRaises(ValueError): self.compile()

    def test_rejects_legacy_global_mac_shared_namespace_and_java_override(self):
        self.request['MacAddress'] = '02:42:ac:1d:00:06'
        with self.assertRaises(ValueError): self.compile()
        self.request, self.context = fixture(); self.context['networkNamespaceName'] = '1' * 12
        with self.assertRaises(ValueError): self.compile()
        self.request, self.context = fixture(); self.request['Env'].append('JAVA_TOOL_OPTIONS=-Doverride=true')
        with self.assertRaises(ValueError): self.compile()

    def test_no_observed_oci_input_and_no_synthetic_custody_for_target(self):
        recipe = self.compile()
        self.assertNotIn('sources', recipe)
        self.assertNotIn('manifest', recipe)
        self.assertFalse(recipe['observedOciUsedAsExpectation'])
        self.assertFalse(recipe['inputsAuthenticated'])
        self.assertFalse(recipe['rootfsSealProduced'])

    def reader(self):
        spec = importlib.util.spec_from_file_location('peer_reader', ROOT / 'scripts/read-retained-semantic-peer-20261109.py')
        reader = importlib.util.module_from_spec(spec); spec.loader.exec_module(reader)
        return reader

    def test_reader_dependencies_are_pinned_and_import_without_effects(self):
        self.assertEqual(len(self.reader().dependencies()), 5)

    def test_endpoint_declaration_comes_from_precreate_request(self):
        reader = self.reader(); recipe = self.compile()
        kw = {'network_name': 'reviewed-backend', 'network_id': '1' * 64,
              'address': '172.29.0.6', 'mac': '02:42:ac:1d:00:06'}
        peer = reader.declaration(self.request, recipe, 'c' * 64, **kw)
        self.assertEqual(peer['networkBindings'][0]['interface'], 'eth0')
        self.request['NetworkingConfig']['EndpointsConfig']['reviewed-backend']['MacAddress'] = '02:42:ac:1d:00:07'
        with self.assertRaisesRegex(RuntimeError, 'PRECREATE_ENDPOINT_IDENTITY_DRIFT'):
            reader.declaration(self.request, recipe, 'c' * 64, **kw)

    def test_differences_report_paths_without_values(self):
        diff = self.reader().differences({'process': {'env': ['PRIVATE_VALUE']}}, {'process': {'env': ['OTHER_VALUE']}})
        self.assertEqual(diff, ['/process/env/0'])

    def test_runtime_command_allowlist_blocks_effects_before_execution(self):
        reader = self.reader(); io = object.__new__(reader.PeerIO)
        io.cid = 'c' * 64; io.pid = 42; io.calls = []
        io.commands = {k: {'path': '/usr/bin/' + k} for k in ('runc', 'ip', 'nsenter')}
        for binding, args in [('runc', ['delete', io.cid]), ('ip', ['link', 'delete', 'eth0']),
                              ('nsenter', ['--net=/proc/42/ns/net', '/bin/sh'])]:
            with self.assertRaisesRegex(RuntimeError, 'CLOSED_PEER_READ_COMMAND_REQUIRED'):
                io.run(io.commands[binding], args, 16384)


if __name__ == '__main__': unittest.main()
