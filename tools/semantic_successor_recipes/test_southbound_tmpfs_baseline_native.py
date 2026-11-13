"""Docker 29.8.1/containerd-overlayfs synthetic shape proof; CI root only.

OCI1 supplies the template. Launch2, context2 and policy2 are fixed before
OCI2 exists. Neither captured OCI is normalized, including paths and options.
The runtime refuses create (77) and start (78); no candidate executes runc.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'semantic_frame_compiler'))
sys.path.insert(0, str(HERE))

from build_role_frame_template import build_role_template as build_historical
from build_role_frame_template_tmpfs import build_role_template
from compile_creation_frame_policy import canonical, compile_policy

TMPFS_TARGET = '/run/ouf-southbound-runtime'
TMPFS_OPTIONS = 'rw,noexec,nosuid,nodev,uid=636,gid=636,mode=0700,size=1m,noswap'
TMPFS = {TMPFS_TARGET: TMPFS_OPTIONS}
BASELINE_NAME = 'containerd-overlayfs-southbound-tmpfs.json'
IMAGE = 'busybox:1.37.0'
MOUNT_ORDERING = 'depth-path'


class SouthboundTmpfsNativeTests(unittest.TestCase):
    maxDiff = 2000

    def test_second_candidate_exact_oci_with_unchanged_tmpfs(self):
        self.assertEqual(sys.platform, 'linux', 'NATIVE_LINUX_RUNNER_REQUIRED')
        self.assertEqual(os.geteuid(), 0, 'NATIVE_ROOT_REQUIRED')
        for binary in ('docker', 'dockerd', 'runc', 'unshare', 'mount', 'umount'):
            self.assertIsNotNone(shutil.which(binary), 'NATIVE_TOOL_REQUIRED: ' + binary)
        self.assertEqual(os.environ.get('OUF_FRAME_COMPILER_ENGINE_VERSION', '29.8.1'), '29.8.1')
        self.assertEqual(os.environ.get('OUF_FRAME_COMPILER_BACKEND', 'containerd-overlayfs'), 'containerd-overlayfs')
        self.assertEqual(os.environ.get('OUF_FRAME_COMPILER_NETWORK', 'bridge'), 'bridge')
        # Stable owned source paths are part of the exported baseline. Random
        # mkdtemp paths would make byte-for-byte reproduction impossible.
        root = Path('/root/ouf-southbound-tmpfs-native')
        root.mkdir(mode=0o700, exist_ok=False)
        self.addCleanup(shutil.rmtree, root)
        probe = root / 'noswap-probe'
        probe.mkdir(mode=0o700)
        # The refusing runtime never mounts tmpfs. Probe the real kernel in a
        # private mount namespace, otherwise an unsupported noswap could pass.
        support = subprocess.run([
            'unshare', '--mount', '--propagation', 'private', '/bin/sh', '-ec',
            'mount -t tmpfs -o "$1" tmpfs "$2"; '
            'trap \'umount "$2"\' EXIT; '
            'awk -v target="$2" \'$2 == target && $3 == "tmpfs" && '
            '$4 ~ /(^|,)noswap(,|$)/ {found=1} END {exit !found}\' /proc/self/mounts',
            'ouf-noswap-probe', TMPFS_OPTIONS, str(probe)], capture_output=True, timeout=30)
        self.assertEqual(support.returncode, 0,
                         'TMPFS_NOSWAP_KERNEL_REQUIRED: mount/probe failed; noswap must not be removed: '
                         + support.stderr.decode(errors='replace'))

        runtime = root / 'capture-runtime'
        runtime.write_text('#!/usr/bin/python3\n' +
            'import json,os,pathlib,subprocess,sys\n' +
            'args=sys.argv[1:]\n' +
            'if "create" in args:\n' +
            '    i=args.index("--bundle") if "--bundle" in args else args.index("-b")\n' +
            '    bundle=pathlib.Path(args[i+1]).resolve()\n' +
            '    value={"cid":args[-1],"bundle":str(bundle),"refusedExit":77,"oci":json.loads((bundle/"config.json").read_bytes())}\n' +
            '    fd=os.open(' + repr(str(root / 'capture-')) + '+args[-1]+".json",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)\n' +
            '    with os.fdopen(fd,"wb") as stream:stream.write(json.dumps(value).encode());stream.flush();os.fsync(stream.fileno())\n' +
            '    sys.exit(77)\n' +
            'if "start" in args:sys.exit(78)\n' +
            'sys.exit(subprocess.call([' + repr(shutil.which('runc')) + ']+args))\n', encoding='utf-8')
        runtime.chmod(0o700)
        self.assertEqual(subprocess.run([str(runtime), 'start', 'ci-refusal-probe'],
                                       capture_output=True, timeout=10).returncode, 78)
        daemon_cfg = root / 'daemon.json'
        daemon_cfg.write_bytes(canonical({'runtimes': {'ouf-ci-capture': {'path': str(runtime)}},
                                          'features': {'containerd-snapshotter': True}}))
        socket = 'unix://' + str(root / 'docker.sock')
        log = (root / 'daemon.log').open('wb')
        self.addCleanup(log.close)
        daemon = subprocess.Popen([
            shutil.which('dockerd'), '--config-file', str(daemon_cfg),
            '--data-root', str(root / 'data'), '--exec-root', str(root / 'exec'),
            '--pidfile', str(root / 'pid'), '-H', socket, '--bridge', 'none',
            '--iptables=false', '--ip6tables=false', '--storage-driver', 'overlayfs'],
            stdout=log, stderr=log)

        def stop():
            if daemon.poll() is None:
                daemon.terminate()
                try:
                    daemon.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    daemon.kill()
                    daemon.wait(timeout=5)

        self.addCleanup(stop)

        def docker(*args, timeout=30):
            return subprocess.run([shutil.which('docker'), '-H', socket, *map(str, args)],
                                  capture_output=True, timeout=timeout)

        def checked(*args, timeout=30):
            result = docker(*args, timeout=timeout)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
            return result.stdout

        deadline = time.monotonic() + 60
        while docker('info').returncode:
            self.assertIsNone(daemon.poll(), 'OWNED_FIXTURE_DAEMON_FAILED')
            self.assertLess(time.monotonic(), deadline, 'OWNED_DAEMON_READINESS_TIMEOUT')
            time.sleep(.25)
        info = json.loads(checked('info', '--format', '{{json .}}'))
        self.assertEqual(info['ServerVersion'], '29.8.1', 'CI_ENGINE_VERSION_DRIFT')
        self.assertEqual(info['Driver'], 'overlayfs', 'CI_ENGINE_STORAGE_DRIFT')
        print('CI_ENGINE_VERSION=' + info['ServerVersion'], flush=True)
        checked('pull', IMAGE, timeout=120)
        image = json.loads(checked('image', 'inspect', IMAGE))[0]
        image_env = image['Config'].get('Env') or []
        self.assertFalse(any(row.startswith('HOSTNAME=') for row in image_env))
        environment = [*image_env, 'HOSTNAME=$OUF_HOSTNAME']
        checked('network', 'create', '--subnet', '198.19.250.0/24', 'ouf-ci-tmpfs-bridge')
        self.addCleanup(lambda: docker('rm', '-f', 'candidate', 'candidate2'))

        def inputs(number):
            sources = []
            for name, target in (('config', '/usr/local/etc/ouf/config.json'),
                                 ('hmac', '/run/ouf-southbound-hmac.key')):
                source = root / ('source-' + str(number) + '-' + name)
                source.write_bytes(('SYNTHETIC_' + name + '_' + str(number)).encode())
                source.chmod(0o600)
                os.chown(source, 636, 636)
                sources.append({'source': str(source), 'target': target, 'readOnly': True,
                                'uid': 636, 'gid': 636, 'mode': 0o600, 'maxBytes': 1048576,
                                'sha256': hashlib.sha256(source.read_bytes()).hexdigest()})
            script = 'printf synthetic-' + str(number) + '; exit 0'
            return {'schema': 'ouf.semantic-creation-frame-launch.v1',
                    'manifest': {'user': '636:636', 'readOnlyRoot': False,
                                 'memoryBytes': 536870912, 'pidsLimit': 128,
                                 'mounts': [{k: s[k] for k in ('source', 'target', 'readOnly')} for s in sources],
                                 'tmpfs': copy.deepcopy(TMPFS)},
                    'startup': {'uid': 636, 'gid': 636, 'umask': None, 'cwd': '/',
                                'args': ['/bin/sh', '-c', script], 'env': list(environment)},
                    'sources': sources}

        def create(name, launch):
            mounts = [arg for m in launch['manifest']['mounts'] for arg in (
                '--mount', 'type=bind,source=' + m['source'] + ',target=' + m['target'] + ',readonly')]
            cid = checked('create', '--name', name, '--runtime', 'ouf-ci-capture',
                          '--network', 'ouf-ci-tmpfs-bridge', '--user', '636:636',
                          '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                          '--memory', '512m', '--memory-swap', '512m', '--pids-limit', '128',
                          '--no-healthcheck', '--tmpfs', TMPFS_TARGET + ':' + TMPFS_OPTIONS,
                          *mounts, '--entrypoint', '/bin/sh', IMAGE, '-c', launch['startup']['args'][2]).decode().strip()
            self.assertRegex(cid, r'^[0-9a-f]{64}$')
            return cid

        def capture(cid):
            result = docker('start', cid)
            self.assertNotEqual(result.returncode, 0, 'CAPTURE_RUNTIME_MUST_REFUSE_CREATE')
            captured_path = root / ('capture-' + cid + '.json')
            self.assertTrue(captured_path.is_file(),
                            'CAPTURE_NOT_REACHED (including possible tmpfs/noswap rejection): '
                            + result.stderr.decode(errors='replace'))
            captured = json.loads(captured_path.read_bytes())
            self.assertEqual(captured['cid'], cid)
            self.assertEqual(captured['refusedExit'], 77)
            state = json.loads(checked('inspect', '--format', '{{json .State}}', cid))
            self.assertFalse(state['Running'])
            self.assertEqual(state['Pid'], 0)
            self.assertTrue(state['StartedAt'].startswith('0001-01-01'))
            return captured

        launch = inputs(1)
        cid = create('candidate', launch)
        captured = capture(cid)
        actual = captured['oci']  # Never modify or normalize a captured OCI.
        self.assertEqual(actual['root']['path'], str(root / 'data' / 'rootfs' / 'overlayfs' / cid),
                         'UNNORMALIZED_ROOTFS_CONTEXT_DRIFT')
        namespace = next(n for n in actual['linux']['namespaces'] if n['type'] == 'network')
        self.assertNotIn('path', namespace, 'FRESH_PRIVATE_NETWORK_NAMESPACE_REQUIRED')
        tmpfs_mounts = [m for m in actual['mounts'] if m['destination'] == TMPFS_TARGET]
        self.assertEqual(len(tmpfs_mounts), 1)
        self.assertEqual(tmpfs_mounts[0]['type'], 'tmpfs')
        self.assertIn('noswap', tmpfs_mounts[0]['options'], 'OCI_TMPFS_NOSWAP_REQUIRED')
        template_oci = copy.deepcopy(actual)
        template_oci['root']['path'] = '$OUF_ROOTFS'
        template_oci['hostname'] = '$OUF_HOSTNAME'
        template_oci['linux']['cgroupsPath'] = '$OUF_CGROUPS'
        next(n for n in template_oci['linux']['namespaces'] if n['type'] == 'network')['path'] = '$OUF_NETWORK_NAMESPACE'
        for target, sentinel in (('/etc/hosts', '$OUF_HOSTS'), ('/etc/hostname', '$OUF_HOSTNAME_FILE'),
                                 ('/etc/resolv.conf', '$OUF_RESOLV')):
            next(m for m in template_oci['mounts'] if m['destination'] == target)['source'] = sentinel
        env = template_oci['process']['env']
        env[env.index('HOSTNAME=' + cid[:12])] = 'HOSTNAME=$OUF_HOSTNAME'
        template = {'schema': 'ouf.semantic-creation-frame-template.v1', 'expectedOci': template_oci,
                    'approvedHooks': copy.deepcopy(actual.get('hooks') or {})}
        approved_user = copy.deepcopy(actual['process']['user'])
        context = {'schema': 'ouf.semantic-docker-frame-context.v1', 'containerId': cid,
                   'bundleParent': str(Path(captured['bundle']).parent),
                   'metadataParent': str(root / 'data' / 'containers'),
                   'networkNamespaceParent': str(root / 'exec' / 'netns'), 'networkNamespaceName': None,
                   'cgroupDriver': info['CgroupDriver'], 'storageParent': str(root / 'data'),
                   'rootfsPath': str(root / 'data' / 'rootfs' / 'overlayfs' / cid)}
        self.assertEqual(compile_policy(template, launch, context)['expectedOci'], actual,
                         'BASELINE_FIRST_CANDIDATE_DRIFT')
        # Qualify necessity on OCI1, never by adapting to the candidate2 OCI.
        # If either historical order suffices, stop and remove this extension
        # during review rather than carrying an unnecessary alternative builder.
        for ordering in ('depth-path', 'depth-stable-user-first'):
            historical = build_historical(template, launch, launch, approved_user, mount_ordering=ordering)
            self.assertNotEqual(historical, template, 'HISTORICAL_BUILDER_SUFFICES: ' + ordering)
            self.assertEqual(sorted(map(canonical, historical['expectedOci']['mounts'])),
                             sorted(map(canonical, template_oci['mounts'])),
                             'HISTORICAL_MOUNT_DRIFT_NOT_ONLY_ORDER')
            historical_without_mounts = copy.deepcopy(historical)
            historical_without_mounts['expectedOci']['mounts'] = copy.deepcopy(template_oci['mounts'])
            self.assertEqual(historical_without_mounts, template, 'HISTORICAL_DRIFT_NOT_ONLY_MOUNT_ORDER')
        self.assertEqual(build_role_template(template, launch, launch, approved_user,
                                            mount_ordering=MOUNT_ORDERING), template,
                         'TMPFS_BUILDER_BASELINE_ROUNDTRIP_DRIFT')
        print('CI_TMPFS_BUILDER=build_role_frame_template_tmpfs HISTORICAL_ORDERS_INSUFFICIENT=true', flush=True)

        launch2 = inputs(2)  # Image config and owned source files only; no OCI2.
        self.assertNotEqual(launch2['sources'], launch['sources'])
        self.assertNotEqual(launch2['startup']['args'], launch['startup']['args'])
        cid2 = create('candidate2', launch2)
        context2 = {**context, 'containerId': cid2,
                    'rootfsPath': str(root / 'data' / 'rootfs' / 'overlayfs' / cid2)}
        template2 = build_role_template(template, launch, launch2, approved_user, mount_ordering=MOUNT_ORDERING)
        policy2 = compile_policy(template2, launch2, context2)
        sealed2 = canonical(policy2)
        policy_path = root / 'precreate-policy2.json'
        fd = os.open(policy_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(sealed2)
            stream.flush()
            os.fsync(stream.fileno())
        self.assertFalse((root / ('capture-' + cid2 + '.json')).exists())
        actual2 = capture(cid2)['oci']
        self.assertEqual(policy_path.read_bytes(), sealed2, 'SEALED_SECOND_POLICY_CHANGED')
        self.assertEqual(policy2['expectedOci'], actual2, 'SECOND_CANDIDATE_FULL_UNNORMALIZED_OCI_DRIFT')
        self.assertEqual([m for m in actual2['mounts'] if m['destination'] == TMPFS_TARGET], tmpfs_mounts)

        baseline = {'schema': 'ouf.semantic-ci-engine-frame-baseline.v1', 'template': template,
                    'launch': launch, 'approvedUser': approved_user,
                    'engine': {'serverVersion': info['ServerVersion'], 'storageDriver': info['Driver'],
                               'cgroupDriver': info['CgroupDriver'], 'backend': 'containerd-overlayfs'},
                    'role': 'southbound', 'mountOrdering': MOUNT_ORDERING, 'tmpfs': copy.deepcopy(TMPFS),
                    'syntheticFixture': True, 'targetTemplateApproved': False,
                    'acceptanceGranted': False, 'startAuthorized': False}
        raw = canonical(baseline)
        export = Path(os.environ['OUF_FRAME_COMPILER_EXPORT_DIRECTORY'])
        self.assertTrue(export.is_absolute())
        export.mkdir(parents=True, exist_ok=True)
        destination = export / BASELINE_NAME
        destination.write_bytes(raw)
        destination.chmod(0o644)
        print('CI_FRAME_BASELINE_EXPORT=' + json.dumps({'file': destination.name,
              'sha256': hashlib.sha256(raw).hexdigest(), 'targetTemplateApproved': False}), flush=True)
        committed = HERE / BASELINE_NAME
        if committed.exists():
            self.assertEqual(committed.read_bytes(), raw, 'COMMITTED_BASELINE_BYTE_DRIFT')
            print('CI_COMMITTED_BASELINE_BYTE_MATCH=true', flush=True)
        print('SOUTHBOUND_TMPFS_NATIVE=PASS SECOND_EXACT_COMPARISON=true OCI_NORMALIZED=false '
              'SECOND_POLICY_SEALED_BEFORE_OCI_GENERATION=true RUNC_CREATE_REFUSED=true '
              'RUNTIME_START_REFUSED=true APPLICATION_NOT_STARTED=true SYNTHETIC_TEMPLATE_ONLY=true '
              'TARGET_TEMPLATE_APPROVED=false ACCEPTANCE_GRANTED=false START_AUTHORIZED=false', flush=True)


if __name__ == '__main__':
    unittest.main()
