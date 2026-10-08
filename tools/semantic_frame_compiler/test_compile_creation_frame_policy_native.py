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
from review_semantic_oci_policy import configured_profile, schema_from_source_closure


class NativeCompilerTests(unittest.TestCase):
    def test_real_engine_generated_paths_and_no_runc_or_application_execution(self):
        self.assertEqual(os.geteuid(), 0)
        backend = os.environ.get('OUF_FRAME_COMPILER_BACKEND', 'classic-vfs')
        network_mode = os.environ.get('OUF_FRAME_COMPILER_NETWORK', 'none')
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
            '    if ' + repr(network_mode) + '=="bridge":\n' +
            '        sys.path.insert(0,' + repr(str(Path(__file__).resolve().parent)) + ')\n' +
            '        from read_committed_sandbox_fixture import committed_sandbox\n' +
            '        dbpath=pathlib.Path(' + repr(str(root / 'data' / 'network' / 'files' / 'local-kv.db')) + ')\n' +
            '        checkpoint=dbpath.read_bytes()\n' +
            '        committed=committed_sandbox(checkpoint,args[-1])\n' +
            '        if dbpath.read_bytes()!=checkpoint:sys.exit(82)\n' +
            '        stored_key=' + repr(str(root / 'exec' / 'netns') + '/') + '+committed["namespaceName"]\n' +
            '        context_read={"querySucceeded":True,"sandboxKey":stored_key,"source":"OWNED_COMMITTED_SANDBOX_CHECKPOINT"}\n' +
            '        planfile=pathlib.Path(' + repr(str(root / 'compiler-plan.json')) + ')\n' +
            '        if planfile.exists():\n' +
            '            plan=json.loads(planfile.read_bytes())\n' +
            '            if plan["context"]["containerId"]==args[-1]:\n' +
            '                if not context_read.get("querySucceeded") or not context_read.get("sandboxKey"):sys.exit(79)\n' +
            '                import sys\n' +
            '                sys.path.insert(0,' + repr(str(Path(__file__).resolve().parent)) + ')\n' +
            '                from compile_creation_frame_policy import compile_policy,canonical\n' +
            '                netpath=pathlib.Path(context_read["sandboxKey"]).resolve()\n' +
            '                if str(netpath.parent)!=plan["context"]["networkNamespaceParent"]:\n' +
            '                    pathlib.Path(' + repr(str(root / 'runtime-diagnosis.json')) + ').write_text(json.dumps({"stage":"NAMESPACE_PARENT","ciExpectedParent":plan["context"]["networkNamespaceParent"],"ciDerivedParent":str(netpath.parent)}));sys.exit(80)\n' +
            '                plan["context"]["networkNamespaceName"]=netpath.name\n' +
            '                try:policy=canonical(compile_policy(plan["template"],plan["launch"],plan["context"]))\n' +
            '                except Exception as error:\n' +
            '                    pathlib.Path(' + repr(str(root / 'runtime-diagnosis.json')) + ').write_text(json.dumps({"stage":"COMPILE_POLICY","publicErrorType":type(error).__name__}));sys.exit(83)\n' +
            '                fd=os.open(' + repr(str(root / 'precreate-policy.json')) + ',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)\n' +
            '                with os.fdopen(fd,"wb") as stream:stream.write(policy);stream.flush();os.fsync(stream.fileno())\n' +
            '                context_read["policySealedBeforeOciRead"]=True\n' +
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
            self.assertEqual(docker('pull', 'busybox:1.37.0', timeout=120).returncode, 0)
            candidate_network = 'none'
            if network_mode == 'bridge':
                net = docker('network', 'create', '--subnet', '198.19.250.0/24', 'ouf-ci-frame-bridge')
                self.assertEqual(net.returncode, 0)
                candidate_network = 'ouf-ci-frame-bridge'
            self.assertEqual(docker('run', '-d', '--network', 'none', '--name', 'existing',
                                    'busybox:1.37.0', 'sleep', '600').returncode, 0)
            self.addCleanup(lambda: docker('rm', '-f', 'candidate', 'candidate2', 'existing'))
            source = root / 'source'; source.write_bytes(b'CI_PRIVATE_SOURCE'); source.chmod(0o600); os.chown(source, 10006, 10006)
            create = docker('create', '--name', 'candidate', '--runtime', 'ouf-ci-capture', '--network', candidate_network,
                            '--user', '10006:10006', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
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
                'manifest': {'user': '10006:10006', 'readOnlyRoot': True, 'memoryBytes': 268435456, 'pidsLimit': 128, 'mounts': [mount]},
                'startup': {'uid': 10006, 'gid': 10006, 'umask': None, 'cwd': '/', 'args': ['sleep', '600'], 'env': list(env)},
                'sources': [{**mount, 'uid': 10006, 'gid': 10006, 'mode': 0o600, 'maxBytes': 131072,
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
            if network_mode == 'none':
                self.assertIsNone(context['networkNamespaceName'], 'fixture requires a fresh private namespace')
            else:
                print('CI_BRIDGE_METADATA_QUERY=' + json.dumps({
                    'succeeded': captured['contextRead'].get('querySucceeded', False),
                    'failure': captured['contextRead'].get('failure'),
                    'sandboxKeyPresent': bool(captured['contextRead'].get('sandboxKey')),
                    'storedMetadataIdMatches': captured['contextRead'].get('metadataIdMatches'),
                    'storedMetadataStable': captured['contextRead'].get('metadataStable'),
                    'storedMetadataSandboxKeyPresent': captured['contextRead'].get('metadataSandboxKeyPresent'),
                    'source': captured['contextRead'].get('source')}))
                self.assertTrue(captured['contextRead'].get('querySucceeded'), 'IN_CREATE_DOCKER_CONTEXT_QUERY_FAILED')
            create2 = docker('create', '--name', 'candidate2', '--runtime', 'ouf-ci-capture', '--network', candidate_network,
                            '--user', '10006:10006', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                            '--memory', '256m', '--memory-swap', '256m', '--pids-limit', '128', '--no-healthcheck',
                            '--mount', 'type=bind,source=' + str(source) + ',target=/approved-source,readonly',
                            'busybox:1.37.0', 'sleep', '600')
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
            policy_path2 = root / 'precreate-policy.json'
            if network_mode == 'none':
                policy2 = compile_policy(template, launch, context2)
                sealed2 = canonical(policy2)
                fd = os.open(policy_path2, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(sealed2); stream.flush(); os.fsync(stream.fileno())
            else:
                # Fixed template/launch/CID/storage context before OCI2 exists.
                # The refusing runtime reads the independently owned daemon's
                # sandbox mapping and seals policy before opening config.json.
                (root / 'compiler-plan.json').write_bytes(canonical({'template': template,
                    'launch': launch, 'context': context2}))
                self.assertFalse(policy_path2.exists())
            capture2 = root / ('capture-' + cid2 + '.json'); self.assertFalse(capture2.exists())
            self.assertNotEqual(docker('start', cid2).returncode, 0)
            if not capture2.exists() and (root / 'runtime-diagnosis.json').exists():
                print('CI_BRIDGE_PRECREATE_DIAGNOSIS=' + (root / 'runtime-diagnosis.json').read_text())
            captured2 = json.loads(capture2.read_bytes()); self.assertEqual(captured2['cid'], cid2)
            if network_mode == 'bridge':
                self.assertTrue(captured2['contextRead'].get('policySealedBeforeOciRead'))
                sealed2 = policy_path2.read_bytes(); policy2 = json.loads(sealed2)
            actual2 = captured2['oci']; rootfs2 = Path(actual2['root']['path'])
            if not rootfs2.is_absolute(): rootfs2 = Path(captured2['bundle']) / rootfs2
            actual2['root']['path'] = str(rootfs2)
            if network_mode == 'bridge':
                namespace2 = next(v for v in actual2['linux']['namespaces'] if v['type'] == 'network')
                namespace2['path'] = str(Path(namespace2['path']).resolve())
            self.assertEqual(policy_path2.read_bytes(), sealed2)
            self.assertTrue(policy2['expectedOci'] == actual2, 'SECOND_CANDIDATE_PRECREATE_POLICY_DRIFT')
            self.assertTrue(configured_profile(actual2, policy2['expectedOci'], policy2['manifest'], policy2['startup'],
                                              policy2['approvedHooks'], schema)['configuredPolicyConforms'])
            state2 = json.loads(docker('inspect', '--format', '{{json .State}}', cid2).stdout)
            self.assertFalse(state2['Running']); self.assertEqual(state2['Pid'], 0)
            self.assertTrue(state2['StartedAt'].startswith('0001-01-01'))
            self.assertEqual(docker('inspect', '--format', '{{.State.Running}}', 'existing').stdout.strip(), b'true')
            print('FRAME_COMPILER_NATIVE=PASS REAL_DOCKER_SHAPE=true RUNC_CREATE_REFUSED=true APPLICATION_NOT_STARTED=true '
                  'SYNTHETIC_TEMPLATE_ONLY=true INDEPENDENT_TEMPLATE_APPROVAL=false CONTEXT_AUTHENTICATED=false '
                  'SECOND_POLICY_SEALED_BEFORE_OCI_GENERATION=' + str(network_mode == 'none').lower() +
                  ' SECOND_POLICY_SEALED_BEFORE_OCI_READ=true SECOND_EXACT_COMPARISON=true '
                  'PRODUCTION_PRECREATE_BINDING_PROVEN=false TARGET_START_AUTHORIZED=false BACKEND=' + backend +
                  ' NETWORK=' + network_mode)


if __name__ == '__main__': unittest.main()
