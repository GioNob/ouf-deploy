"""Real isolated Docker shape compatibility; CI only, never target acceptance.

An owned capture runtime refuses create before invoking runc. The captured OCI
supplies a synthetic CI template to test substitution against Engine output.
This DOES NOT prove independent template approval, context authentication,
pre-create intent issuance, live acceptance or a production start path.
"""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
import sys
import re

sys.path.insert(0, str(Path(__file__).resolve().parent))

from compile_creation_frame_policy import canonical, compile_policy
from build_role_frame_template import build_role_template
from review_semantic_oci_policy import configured_profile, schema_from_source_closure


class NativeCompilerTests(unittest.TestCase):
    def test_real_engine_generated_paths_and_no_runc_or_application_execution(self):
        self.assertEqual(os.geteuid(), 0)
        backend = os.environ.get('OUF_FRAME_COMPILER_BACKEND', 'classic-vfs')
        network_mode = os.environ.get('OUF_FRAME_COMPILER_NETWORK', 'none')
        role = os.environ.get('OUF_FRAME_COMPILER_ROLE', 'adapter')
        self.assertIn(role, ('adapter', 'southbound'))
        role_uid = 10006 if role == 'adapter' else 636
        root_readonly = role == 'adapter'
        readonly_flags = ['--read-only'] if root_readonly else []
        self.assertIn(network_mode, ('none', 'bridge'))
        self.assertIn(backend, ('classic-vfs', 'containerd-overlayfs'))
        root = Path(tempfile.mkdtemp(prefix='ouf-frame-compiler-', dir='/root'))
        root.chmod(0o700); self.addCleanup(shutil.rmtree, root)
        runtime = root / 'capture-runtime'
        runtime.write_text('#!/usr/bin/python3\n' +
            'import json,os,pathlib,subprocess,sys\n' +
            'args=sys.argv[1:]\n' +
            'if "create" in args:\n' +
            '    i=args.index("--bundle") if "--bundle" in args else args.index("-b")\n' +
            '    bundle=pathlib.Path(args[i+1]).resolve()\n' +
            '    context_read={}\n' +
            '    value={"cid":args[-1],"bundle":str(bundle),"contextRead":context_read,"oci":json.loads((bundle/"config.json").read_bytes())}\n' +
            '    fd=os.open(' + repr(str(root / 'capture-')) + '+args[-1]+".json",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)\n' +
            '    with os.fdopen(fd,"wb") as stream:stream.write(json.dumps(value).encode());stream.flush();os.fsync(stream.fileno())\n' +
            '    sys.exit(77)\n' +
            'if "start" in args:sys.exit(78)\n' +
            'sys.exit(subprocess.call([' + repr(shutil.which('runc')) + ']+args))\n')
        runtime.chmod(0o700)
        daemon_cfg = root / 'daemon.json'
        daemon_cfg.write_text(json.dumps({'runtimes': {'ouf-ci-capture': {'path': str(runtime)}},
            'features': {'containerd-snapshotter': backend == 'containerd-overlayfs'}}))
        socket = 'unix://' + str(root / 'docker.sock')
        with (root / 'daemon.log').open('wb') as log:
            daemon = subprocess.Popen([shutil.which('dockerd'), '--config-file', str(daemon_cfg),
                '--data-root', str(root / 'data'), '--exec-root', str(root / 'exec'), '--pidfile', str(root / 'pid'),
                '-H', socket, '--bridge', 'none', '--iptables=false', '--ip6tables=false', '--storage-driver',
                'vfs' if backend == 'classic-vfs' else 'overlayfs'],
                stdout=log, stderr=log)
            def stop():
                if daemon.poll() is None:
                    daemon.terminate()
                    try: daemon.wait(timeout=20)
                    except subprocess.TimeoutExpired: daemon.kill(); daemon.wait(timeout=5)
            self.addCleanup(stop)
            def docker(*args, timeout=30):
                return subprocess.run([shutil.which('docker'), '-H', socket, *map(str, args)],
                                      capture_output=True, timeout=timeout)
            deadline = time.monotonic() + 60
            while docker('info').returncode:
                self.assertIsNone(daemon.poll(), 'owned fixture daemon failed')
                self.assertLess(time.monotonic(), deadline, 'owned daemon readiness timed out')
                time.sleep(.25)
            info = json.loads(docker('info', '--format', '{{json .}}').stdout)
            expected_version = os.environ.get('OUF_FRAME_COMPILER_ENGINE_VERSION')
            if expected_version:
                self.assertEqual(info['ServerVersion'], expected_version, 'CI_ENGINE_VERSION_DRIFT')
            print('CI_ENGINE_VERSION=' + info['ServerVersion'])
            self.assertEqual(docker('pull', 'busybox:1.37.0', timeout=120).returncode, 0)
            candidate_network = 'none'
            if network_mode == 'bridge':
                net = docker('network', 'create', '--subnet', '198.19.250.0/24', 'ouf-ci-frame-bridge')
                self.assertEqual(net.returncode, 0)
                candidate_network = 'ouf-ci-frame-bridge'
            self.assertEqual(docker('run', '-d', '--network', 'none', '--name', 'existing',
                                    'busybox:1.37.0', 'sleep', '600').returncode, 0)
            self.addCleanup(lambda: docker('rm', '-f', 'candidate', 'candidate2', 'existing'))
            source = root / 'source'; source.write_bytes(b'CI_PRIVATE_SOURCE'); source.chmod(0o600); os.chown(source, role_uid, role_uid)
            create = docker('create', '--name', 'candidate', '--runtime', 'ouf-ci-capture', '--network', candidate_network,
                            '--user', str(role_uid) + ':' + str(role_uid), *readonly_flags, '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                            '--memory', '256m', '--memory-swap', '256m', '--pids-limit', '128', '--no-healthcheck',
                            '--mount', 'type=bind,source=' + str(source) + ',target=/approved-source,readonly',
                            'busybox:1.37.0', 'sleep', '600')
            self.assertEqual(create.returncode, 0); cid = create.stdout.decode().strip()
            inspected = json.loads(docker('inspect', '--format', '{{json .}}', cid).stdout)
            if backend == 'classic-vfs':
                storage_data = inspected['GraphDriver']['Data']
                self.assertEqual(inspected['GraphDriver']['Name'], 'vfs')
                self.assertEqual(set(storage_data), {'ID'}, 'owned Engine fixture storage schema drift')
                self.assertTrue(re.fullmatch('[0-9a-f]{64}', storage_data['ID']))
                # API ID is not the writable layer's mount ID. Read the owned
                # daemon's CID-to-mount-ID metadata before task create.
                mount_record = root / 'data' / 'image' / 'vfs' / 'layerdb' / 'mounts' / cid / 'mount-id'
                mount_id = mount_record.read_text().strip()
                self.assertTrue(re.fullmatch('[0-9a-f]{64}', mount_id))
                independent_rootfs = str(root / 'data' / 'vfs' / 'dir' / mount_id)
                self.assertTrue(Path(independent_rootfs).is_dir())
            self.assertNotEqual(docker('start', cid).returncode, 0)
            capture = root / ('capture-' + cid + '.json')
            self.assertTrue(capture.is_file(), 'create did not reach refusing capture runtime')
            captured = json.loads(capture.read_bytes()); self.assertEqual(captured['cid'], cid)
            actual = captured['oci']; bundle = Path(captured['bundle'])
            if backend == 'containerd-overlayfs':
                self.assertEqual(info['Driver'], 'overlayfs')
                independent_rootfs = str(root / 'data' / 'rootfs' / 'overlayfs' / cid)
            rootfs = Path(actual['root']['path'])
            if not rootfs.is_absolute(): rootfs = bundle / rootfs
            actual['root']['path'] = str(rootfs)
            network = next(v for v in actual['linux']['namespaces'] if v['type'] == 'network')
            # Mirror the reviewed runtime's /var/run -> /run normalization.
            if network.get('path'):
                network['path'] = str(Path(network['path']).resolve())
                netpath = Path(network['path'])
                netparent, netname = str(netpath.parent), netpath.name
            else:
                print('CI_ENGINE_NETWORK_SHAPE=' + json.dumps({'hasNamespacePath': bool(network.get('path')),
                      'ciHooks': actual.get('hooks') or {}}))
                netparent, netname = str(root / 'exec' / 'netns'), None
            template_oci = copy.deepcopy(actual)
            template_oci['root']['path'] = '$OUF_ROOTFS'; template_oci['hostname'] = '$OUF_HOSTNAME'
            template_oci['linux']['cgroupsPath'] = '$OUF_CGROUPS'
            next(v for v in template_oci['linux']['namespaces'] if v['type'] == 'network')['path'] = '$OUF_NETWORK_NAMESPACE'
            for target, sentinel in (('/etc/hosts', '$OUF_HOSTS'), ('/etc/hostname', '$OUF_HOSTNAME_FILE'), ('/etc/resolv.conf', '$OUF_RESOLV')):
                next(v for v in template_oci['mounts'] if v['destination'] == target)['source'] = sentinel
            env = template_oci['process']['env']; env[env.index('HOSTNAME=' + cid[:12])] = 'HOSTNAME=$OUF_HOSTNAME'
            import hashlib
            mount = {'source': str(source), 'target': '/approved-source', 'readOnly': True}
            launch = {'schema': 'ouf.semantic-creation-frame-launch.v1',
                'manifest': {'user': str(role_uid) + ':' + str(role_uid), 'readOnlyRoot': root_readonly, 'memoryBytes': 268435456, 'pidsLimit': 128, 'mounts': [mount]},
                'startup': {'uid': role_uid, 'gid': role_uid, 'umask': None, 'cwd': '/', 'args': ['sleep', '600'], 'env': list(env)},
                'sources': [{**mount, 'uid': role_uid, 'gid': role_uid, 'mode': 0o600, 'maxBytes': 131072,
                            'sha256': hashlib.sha256(source.read_bytes()).hexdigest()}]}
            context = {'schema': 'ouf.semantic-docker-frame-context.v1', 'containerId': cid,
                       'bundleParent': str(bundle.parent), 'metadataParent': str(root / 'data' / 'containers'),
                       'networkNamespaceParent': netparent, 'networkNamespaceName': netname,
                       'cgroupDriver': info['CgroupDriver'], 'rootfsPath': independent_rootfs, 'storageParent': str(root / 'data')}
            policy = compile_policy({'schema': 'ouf.semantic-creation-frame-template.v1', 'expectedOci': template_oci,
                                     'approvedHooks': copy.deepcopy(actual.get('hooks') or {})}, launch, context)
            if policy['expectedOci'] != actual:
                expected = policy['expectedOci']
                print('CI_DYNAMIC_SLOT_DIAGNOSIS=' + json.dumps({
                    'rootMatches': expected['root'] == actual['root'],
                    'cgroupMatches': expected['linux']['cgroupsPath'] == actual['linux']['cgroupsPath'],
                    'mountsMatch': expected['mounts'] == actual['mounts'],
                    'networkMatches': expected['linux']['namespaces'] == actual['linux']['namespaces'],
                    'hostnameMatches': expected['hostname'] == actual['hostname'],
                    'environmentMatches': expected['process']['env'] == actual['process']['env'],
                    # Only generated CI paths; no policy/env/source bytes.
                    'ciActualRootPath': actual['root']['path'],
                    'ciExpectedRootPath': expected['root']['path'],
                    'ciActualCgroupPath': actual['linux']['cgroupsPath'],
                    'ciExpectedCgroupPath': expected['linux']['cgroupsPath']}))
            self.assertTrue(policy['expectedOci'] == actual, 'CI_COMPILED_POLICY_DRIFT')
            schema = schema_from_source_closure(Path(__file__).with_name('semantic_oci_shape_schema.json').read_bytes())
            result = configured_profile(actual, policy['expectedOci'], policy['manifest'], policy['startup'], policy['approvedHooks'], schema)
            self.assertTrue(result['configuredPolicyConforms']); self.assertFalse(result['acceptanceGranted'])
            state = json.loads(docker('inspect', '--format', '{{json .State}}', cid).stdout)
            self.assertFalse(state['Running']); self.assertEqual(state['Pid'], 0)
            self.assertTrue(state['StartedAt'].startswith('0001-01-01'))
            # Baseline fixture only: the template from candidate one is now
            # fixed. Compile candidate two before Docker generates its OCI.
            # No field from candidate two's captured OCI may alter that policy.
            self.assertIsNone(context['networkNamespaceName'], 'fixture requires a fresh private namespace')
            source2 = root / 'source2'; source2.write_bytes(b'CI_SECOND_SEALED_SOURCE')
            source2.chmod(0o600); os.chown(source2, role_uid, role_uid)
            create2 = docker('create', '--name', 'candidate2', '--runtime', 'ouf-ci-capture', '--network', candidate_network,
                            '--user', str(role_uid) + ':' + str(role_uid), *readonly_flags,
                            '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                            '--memory', '512m', '--memory-swap', '512m', '--pids-limit', '64', '--no-healthcheck',
                            '--workdir', '/tmp', '--env', 'CI_ROLE=second',
                            '--mount', 'type=bind,source=' + str(source) + ',target=/run/role.json,readonly',
                            '--mount', 'type=bind,source=' + str(source2) + ',target=/run/deep/trust.pem,readonly',
                            'busybox:1.37.0', 'sh', '-c', 'sleep 601')
            self.assertEqual(create2.returncode, 0); cid2 = create2.stdout.decode().strip()
            metadata2 = json.loads(docker('inspect', '--format', '{{json .}}', cid2).stdout)
            if backend == 'classic-vfs':
                self.assertEqual(metadata2['GraphDriver']['Name'], 'vfs')
                self.assertEqual(set(metadata2['GraphDriver']['Data']), {'ID'})
                self.assertTrue(re.fullmatch('[0-9a-f]{64}', metadata2['GraphDriver']['Data']['ID']))
                mount_id2 = (root / 'data' / 'image' / 'vfs' / 'layerdb' / 'mounts' / cid2 / 'mount-id').read_text().strip()
                self.assertTrue(re.fullmatch('[0-9a-f]{64}', mount_id2))
                independent_rootfs2 = str(root / 'data' / 'vfs' / 'dir' / mount_id2)
            else:
                # The owned baseline fixes the task parent. CID2 and this path
                # are known before its task/OCI exists; OCI2 is not consulted.
                independent_rootfs2 = str(root / 'data' / 'rootfs' / 'overlayfs' / cid2)
            context2 = {**context, 'containerId': cid2,
                        'rootfsPath': independent_rootfs2}
            template = {'schema': 'ouf.semantic-creation-frame-template.v1', 'expectedOci': template_oci,
                        'approvedHooks': copy.deepcopy(actual.get('hooks') or {})}
            launch2 = copy.deepcopy(launch)
            launch2['startup'].update(args=['sh', '-c', 'sleep 601'], cwd='/tmp')
            launch2['startup']['env'].append('CI_ROLE=second')
            launch2['manifest'].update(memoryBytes=536870912, pidsLimit=64)
            mount2 = {'source': str(source2), 'target': '/run/deep/trust.pem', 'readOnly': True}
            launch2['manifest']['mounts'] = [{**mount, 'target': '/run/role.json'}, mount2]
            launch2['sources'] = [{**launch['sources'][0], 'target': '/run/role.json'},
                {**launch['sources'][0], **mount2, 'sha256': hashlib.sha256(source2.read_bytes()).hexdigest()}]
            mount_ordering = os.environ.get('OUF_FRAME_COMPILER_MOUNT_ORDER', 'depth-stable-user-first')
            template2 = build_role_template(template, launch, launch2, copy.deepcopy(actual['process']['user']),
                                            mount_ordering=mount_ordering)
            policy_path2 = root / 'precreate-policy.json'
            # Both bridge backends in this fixture use a fresh runc-private
            # namespace (no path), so policy2 does not need the sandbox mapping.
            # Fix the complete policy before Docker generates candidate2 OCI.
            policy2 = compile_policy(template2, launch2, context2)
            sealed2 = canonical(policy2)
            fd = os.open(policy_path2, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(sealed2); stream.flush(); os.fsync(stream.fileno())
            capture2 = root / ('capture-' + cid2 + '.json'); self.assertFalse(capture2.exists())
            self.assertNotEqual(docker('start', cid2).returncode, 0)
            self.assertTrue(capture2.is_file(), 'second create did not reach refusing capture runtime')
            captured2 = json.loads(capture2.read_bytes()); self.assertEqual(captured2['cid'], cid2)
            actual2 = captured2['oci']; rootfs2 = Path(actual2['root']['path'])
            if not rootfs2.is_absolute(): rootfs2 = Path(captured2['bundle']) / rootfs2
            actual2['root']['path'] = str(rootfs2)
            if network_mode == 'bridge':
                namespace2 = next(v for v in actual2['linux']['namespaces'] if v['type'] == 'network')
                if namespace2.get('path'):
                    namespace2['path'] = str(Path(namespace2['path']).resolve())
            self.assertEqual(policy_path2.read_bytes(), sealed2)
            if policy2['expectedOci'] != actual2:
                def differences(left, right, prefix=''):
                    if type(left) is not type(right): return [prefix]
                    if isinstance(left, dict):
                        return [prefix + '/' + k for k in left.keys() ^ right.keys()] + [
                            p for k in left.keys() & right.keys() for p in differences(left[k], right[k], prefix + '/' + k)]
                    if isinstance(left, list):
                        if len(left) != len(right): return [prefix + '/length']
                        return [p for i, (a, b) in enumerate(zip(left, right))
                                for p in differences(a, b, prefix + '/' + str(i))]
                    return [] if left == right else [prefix]
                print('CI_ROLE_TEMPLATE_DRIFT_FIELDS=' + json.dumps(sorted(differences(policy2['expectedOci'], actual2))))
                print('CI_ROLE_MOUNT_ORDER=' + json.dumps({'expected': [m['destination'] for m in policy2['expectedOci']['mounts']],
                    'actual': [m['destination'] for m in actual2['mounts']]}))
            self.assertTrue(policy2['expectedOci'] == actual2, 'SECOND_CANDIDATE_PRECREATE_POLICY_DRIFT')
            self.assertTrue(configured_profile(actual2, policy2['expectedOci'], policy2['manifest'], policy2['startup'],
                                              policy2['approvedHooks'], schema)['configuredPolicyConforms'])
            state2 = json.loads(docker('inspect', '--format', '{{json .State}}', cid2).stdout)
            self.assertFalse(state2['Running']); self.assertEqual(state2['Pid'], 0)
            self.assertTrue(state2['StartedAt'].startswith('0001-01-01'))
            self.assertEqual(docker('inspect', '--format', '{{.State.Running}}', 'existing').stdout.strip(), b'true')
            export_parent = os.environ.get('OUF_FRAME_COMPILER_EXPORT_DIRECTORY')
            if export_parent:
                export = Path(export_parent)
                self.assertTrue(export.is_absolute()); export.mkdir(parents=True, exist_ok=True)
                baseline = {'schema': 'ouf.semantic-ci-engine-frame-baseline.v1',
                            'template': template, 'launch': launch,
                            'approvedUser': copy.deepcopy(actual['process']['user']),
                            'engine': {'serverVersion': info['ServerVersion'], 'storageDriver': info['Driver'],
                                       'cgroupDriver': info['CgroupDriver'], 'backend': backend},
                            'role': role, 'mountOrdering': mount_ordering, 'syntheticFixture': True, 'targetTemplateApproved': False,
                            'acceptanceGranted': False, 'startAuthorized': False}
                raw = canonical(baseline)
                destination = export / (backend + '-' + role + '.json')
                destination.write_bytes(raw); destination.chmod(0o644)
                print('CI_FRAME_BASELINE_EXPORT=' + json.dumps({'file': destination.name,
                      'sha256': hashlib.sha256(raw).hexdigest(), 'targetTemplateApproved': False}))
            print('FRAME_COMPILER_NATIVE=PASS REAL_DOCKER_SHAPE=true RUNC_CREATE_REFUSED=true APPLICATION_NOT_STARTED=true '
                  'SYNTHETIC_TEMPLATE_ONLY=true INDEPENDENT_TEMPLATE_APPROVAL=false CONTEXT_AUTHENTICATED=false '
                  'SECOND_POLICY_SEALED_BEFORE_OCI_GENERATION=true' +
                  ' SECOND_POLICY_SEALED_BEFORE_OCI_READ=true SECOND_EXACT_COMPARISON=true '
                  'PRODUCTION_PRECREATE_BINDING_PROVEN=false TARGET_START_AUTHORIZED=false BACKEND=' + backend +
                  ' NETWORK=' + network_mode + ' ROLE=' + role + ' ROLE_STARTUP_RESOURCES_MULTI_MOUNT=true')


if __name__ == '__main__': unittest.main()
