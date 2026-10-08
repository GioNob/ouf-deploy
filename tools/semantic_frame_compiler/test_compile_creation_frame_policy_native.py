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

sys.path.insert(0, str(Path(__file__).resolve().parent))

from compile_creation_frame_policy import compile_policy
from review_semantic_oci_policy import configured_profile, schema_from_source_closure


class NativeCompilerTests(unittest.TestCase):
    def test_real_engine_generated_paths_and_no_runc_or_application_execution(self):
        self.assertEqual(os.geteuid(), 0)
        root = Path(tempfile.mkdtemp(prefix='ouf-frame-compiler-', dir='/root'))
        root.chmod(0o700); self.addCleanup(shutil.rmtree, root)
        capture = root / 'capture.json'; runtime = root / 'capture-runtime'
        runtime.write_text('#!/usr/bin/python3\n' +
            'import json,os,pathlib,subprocess,sys\n' +
            'args=sys.argv[1:]\n' +
            'if "create" in args:\n' +
            '    i=args.index("--bundle") if "--bundle" in args else args.index("-b")\n' +
            '    bundle=pathlib.Path(args[i+1]).resolve()\n' +
            '    value={"cid":args[-1],"bundle":str(bundle),"oci":json.loads((bundle/"config.json").read_bytes())}\n' +
            '    fd=os.open(' + repr(str(capture)) + ',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)\n' +
            '    with os.fdopen(fd,"wb") as stream:stream.write(json.dumps(value).encode());stream.flush();os.fsync(stream.fileno())\n' +
            '    sys.exit(77)\n' +
            'if "start" in args:sys.exit(78)\n' +
            'sys.exit(subprocess.call([' + repr(shutil.which('runc')) + ']+args))\n')
        runtime.chmod(0o700)
        daemon_cfg = root / 'daemon.json'
        daemon_cfg.write_text(json.dumps({'runtimes': {'ouf-ci-capture': {'path': str(runtime)}}}))
        socket = 'unix://' + str(root / 'docker.sock')
        with (root / 'daemon.log').open('wb') as log:
            daemon = subprocess.Popen([shutil.which('dockerd'), '--config-file', str(daemon_cfg),
                '--data-root', str(root / 'data'), '--exec-root', str(root / 'exec'), '--pidfile', str(root / 'pid'),
                '-H', socket, '--bridge', 'none', '--iptables=false', '--ip6tables=false', '--storage-driver', 'vfs'],
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
            self.assertEqual(docker('run', '-d', '--network', 'none', '--name', 'existing',
                                    'busybox:1.37.0', 'sleep', '600').returncode, 0)
            self.addCleanup(lambda: docker('rm', '-f', 'candidate', 'existing'))
            source = root / 'source'; source.write_bytes(b'CI_PRIVATE_SOURCE'); source.chmod(0o600); os.chown(source, 10006, 10006)
            create = docker('create', '--name', 'candidate', '--runtime', 'ouf-ci-capture', '--network', 'none',
                            '--user', '10006:10006', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                            '--memory', '256m', '--memory-swap', '256m', '--pids-limit', '128', '--no-healthcheck',
                            '--mount', 'type=bind,source=' + str(source) + ',target=/approved-source,readonly',
                            'busybox:1.37.0', 'sleep', '600')
            self.assertEqual(create.returncode, 0); cid = create.stdout.decode().strip()
            inspected = json.loads(docker('inspect', '--format', '{{json .}}', cid).stdout)
            storage_data = inspected['GraphDriver']['Data']
            self.assertEqual(len(storage_data), 1, 'owned vfs fixture must expose one independently read storage root')
            independent_rootfs = next(iter(storage_data.values()))
            self.assertNotEqual(docker('start', cid).returncode, 0)
            self.assertTrue(capture.is_file(), 'create did not reach refusing capture runtime')
            captured = json.loads(capture.read_bytes()); self.assertEqual(captured['cid'], cid)
            actual = captured['oci']; bundle = Path(captured['bundle'])
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
            self.assertTrue(policy['expectedOci'] == actual, 'CI_COMPILED_POLICY_DRIFT')
            schema = schema_from_source_closure(Path(__file__).with_name('semantic_oci_shape_schema.json').read_bytes())
            result = configured_profile(actual, policy['expectedOci'], policy['manifest'], policy['startup'], policy['approvedHooks'], schema)
            self.assertTrue(result['configuredPolicyConforms']); self.assertFalse(result['acceptanceGranted'])
            state = json.loads(docker('inspect', '--format', '{{json .State}}', cid).stdout)
            self.assertFalse(state['Running']); self.assertEqual(state['Pid'], 0)
            self.assertTrue(state['StartedAt'].startswith('0001-01-01'))
            self.assertEqual(docker('inspect', '--format', '{{.State.Running}}', 'existing').stdout.strip(), b'true')
            print('FRAME_COMPILER_NATIVE=PASS REAL_DOCKER_SHAPE=true RUNC_CREATE_REFUSED=true APPLICATION_NOT_STARTED=true '
                  'SYNTHETIC_TEMPLATE_ONLY=true INDEPENDENT_TEMPLATE_APPROVAL=false CONTEXT_AUTHENTICATED=false '
                  'PRODUCTION_PRECREATE_BINDING_PROVEN=false TARGET_START_AUTHORIZED=false')


if __name__ == '__main__': unittest.main()
