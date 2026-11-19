"""Exact archived Registry image; disposable gates, no Java/DB/provider calls."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'tests')]
from test_retained_semantic_peer import fixture
from tools.semantic_frame_compiler.compile_retained_semantic_peer import compile_peer, ENGINE, ENTRY, JAVA

spec = importlib.util.spec_from_file_location('reader', ROOT / 'scripts/read-retained-semantic-peer-20261109.py')
reader = importlib.util.module_from_spec(spec); spec.loader.exec_module(reader)
private, native, h, rollout, peers = reader.dependencies()


def command(*args):
    result = subprocess.run(args, capture_output=True, timeout=120)
    if result.returncode: raise AssertionError(result.stderr.decode(errors='replace')[-2000:])
    return result.stdout


class NativePeer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        assert os.geteuid() == 0 and os.environ.get('GITHUB_ACTIONS') == 'true'
        cls.engine = rollout.Engine()
        cls.info = json.loads(command('docker', 'info', '--format', '{{json .}}'))
        assert cls.info['ServerVersion'] == '29.8.1' and cls.info['Driver'] == 'overlayfs'
        assert cls.info['CgroupDriver'] == 'systemd' and cls.info['DockerRootDir'] == '/var/lib/ouf-docker-29'
        archive = ROOT / 'registry-candidate/image.docker.tar'
        assert rollout.file_sha(archive) == rollout.ARCHIVE_SHA
        command('docker', 'load', '-i', str(archive))
        image = json.loads(command('docker', 'image', 'inspect', 'ouf-cohort-semantic:' + rollout.SOURCE))[0]
        assert image['Id'] == rollout.NATIVE_ID
        cls.image = image

    def exercise(self, bind_kind, explicit_hostname, finite_cpu):
        work = Path(tempfile.mkdtemp(prefix='retained-peer-ci-', dir='/var/lib')); work.chmod(0o700)
        name = 'ouf-peer-' + uuid.uuid4().hex[:12]; ids = []
        network_id = command('docker', 'network', 'create', '--subnet', '172.29.0.0/24', name).decode().strip()
        try:
            request, _ = fixture(); request['Image'] = self.image['Id']
            request['Hostname'] = 'retained-hostname' if explicit_hostname else ''
            request['HostConfig']['NanoCpus'] = 500000000 if finite_cpu else 0
            request['HostConfig']['NetworkMode'] = name
            request['NetworkingConfig']['EndpointsConfig'] = {name: {
                'IPAMConfig': {'IPv4Address': '172.29.0.6'}, 'MacAddress': '02:42:ac:1d:00:06',
                'Aliases': ['semantic-ci']}}
            # Use the image's complete environment, as the retained Engine
            # request does. The native OCI remains strictly an observation.
            values = dict(row.split('=', 1) for row in self.image['Config']['Env'])
            values.update(dict(row.split('=', 1) for row in request['Env'] if not row.startswith('PATH=')))
            request['Env'] = [k + '=' + v for k, v in values.items()]
            for i, mount in enumerate(request['HostConfig']['Mounts']):
                p = work / ('source-' + str(i))
                if i < 2: p.write_text('SYNTHETIC_CI_VALUE'); p.chmod(0o400)
                else: p.mkdir(mode=0o500)
                os.chown(p, 10001, 10001); mount['Source'] = str(p)
            if bind_kind == 'Binds':
                request['HostConfig']['Binds'] = [m['Source'] + ':' + m['Target'] + ':ro'
                                                 for m in request['HostConfig'].pop('Mounts')]
            old_cid = self.engine.api('POST', '/containers/create', request)['Id']; ids.append(old_cid)
            self.engine.api('POST', '/containers/' + old_cid + '/start')
            old = self.engine.inspect(old_cid)
            retained = rollout.request(old, self.image['Id'])
            self.engine.api('POST', '/containers/' + old_cid + '/stop?t=1')
            self.engine.api('DELETE', '/containers/' + old_cid)
            ids.remove(old_cid)
            cid = self.engine.api('POST', '/containers/create', retained)['Id']; ids.append(cid)
            self.engine.api('POST', '/containers/' + cid + '/start')
            actual = self.engine.inspect(cid); rollout.verify_replacement(old, retained, actual, True)
            pid = actual['State']['Pid']
            self.assertEqual((Path('/proc') / str(pid) / 'cmdline').read_bytes(),
                             b'\0'.join(v.encode() for v in ENTRY + JAVA) + b'\0')
            matches = [p for p in reader.BUNDLE_PARENTS if (Path(p) / cid / 'config.json').exists()]
            self.assertEqual(len(matches), 1)
            context = reader.context_for(cid, self.info['DockerRootDir'], matches[0])
            baseline = (ROOT / 'tools/semantic_frame_compiler/containerd-overlayfs-southbound.json').read_bytes()
            recipe = compile_peer(baseline, retained, context, engine_profile=ENGINE)
            io = reader.PeerIO(private, native, work, cid, pid, matches[0] + '/' + cid,
                               runc='/usr/sbin/ouf-peer-ci-runc')
            observed = json.loads(io.read_bundle(matches[0] + '/' + cid + '/config.json'))
            bundle_path = Path(matches[0]) / cid / 'config.json'
            mode = bundle_path.stat().st_mode & 0o777
            self.assertIn(mode, (0o600, 0o644))
            try:
                bundle_path.chmod(0o666)
                with self.assertRaisesRegex(RuntimeError, 'ROOT_CONTROLLED_RUNTIME_BUNDLE_REQUIRED'):
                    io.read_bundle(str(bundle_path))
            finally: bundle_path.chmod(mode)
            (work / 'expected-oci.json').write_text(json.dumps(recipe['expectedOci'], indent=2))
            (work / 'observed-oci.json').write_text(json.dumps(observed, indent=2))
            diff = reader.differences(recipe['expectedOci'], observed)
            self.assertEqual(diff, [], 'full independent OCI mismatch; evidence ' + str(work))
            expected = reader.declaration(retained, recipe, cid, network_name=name, network_id=network_id,
                                          address='172.29.0.6', mac='02:42:ac:1d:00:06')
            snapshot = peers.collect(expected, reader.RUNTIME_ROOT, io.commands['runc'], io.commands,
                                     io.run, io.read_bundle, io.generation, reader.Budget())
            self.assertGreater(snapshot['bindings'][0]['hostIfindex'], 1)
            self.assertEqual(snapshot['generation']['pid'], pid)
            self.assertEqual(h.frame(self.engine.inspect(cid)), h.frame(actual))
            changed = copy.deepcopy(expected); changed['applicationHash'] = 'f' * 64
            with self.assertRaisesRegex(ValueError, 'PEER_COMPLETE_OCI_DRIFT'):
                peers.collect(changed, reader.RUNTIME_ROOT, io.commands['runc'], io.commands,
                              io.run, io.read_bundle, io.generation, reader.Budget())
            with self.assertRaisesRegex(RuntimeError, 'CLOSED_PEER_READ_COMMAND_REQUIRED'):
                io.run(io.commands['runc'], ['delete', cid], 16384)
            self.assertEqual((Path('/proc') / str(pid) / 'cmdline').read_bytes(),
                             b'\0'.join(v.encode() for v in ENTRY + JAVA) + b'\0')
            print(json.dumps({'schema': 'ouf.retained-semantic-peer-native-ci.v1',
                              'mountDeclaration': bind_kind, 'initialExplicitHostname': explicit_hostname,
                              'finiteCpu': finite_cpu, 'exactArchivedImage': True,
                              'retainedFullInspectRequest': True, 'fullIndependentOciMatched': True,
                              'reciprocalLinksObserved': True, 'javaStarted': False,
                              'providerRequests': 0, 'targetAcceptance': False}), flush=True)
        finally:
            for cid in ids: command('docker', 'rm', '--force', cid)
            command('docker', 'network', 'rm', name)
            print('CI_EVIDENCE_DIRECTORY=' + str(work), flush=True)

    def test_mounts_explicit_hostname_finite_cpu(self): self.exercise('Mounts', True, True)
    def test_binds_generated_then_retained_hostname_default_cpu(self): self.exercise('Binds', False, False)


if __name__ == '__main__': unittest.main(verbosity=2)
