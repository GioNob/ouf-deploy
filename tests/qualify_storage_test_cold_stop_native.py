"""Real Docker signals/journals using disposable PID1 handlers, not OUF services."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


b = load('cold_native', 'scripts/storage-cold-backup.py')
p = load('proposal_native', 'tools/storage_planning/cold_stop_proposal.py')
d = load('stop_native', 'scripts/storage-test-cold-stop.py')
IMAGE = 'postgis/postgis@sha256:894f570c0cf0664ed5576a8fd5d5bfb8fb1b19d592885b686c3a88c8bd90c41f'


def docker(*args):
    return subprocess.check_output(['docker', *args], stderr=subprocess.STDOUT, timeout=300).decode().strip()


def main():
    assert os.geteuid() == 0 and os.environ.get('GITHUB_ACTIONS') == 'true'
    os.umask(0o077)
    root = Path(tempfile.mkdtemp(prefix='ouf-test-stop-native-', dir='/var/lib'))
    source = root / 'shared'
    source.mkdir(mode=0o700)
    (source / 'keep').write_bytes(b'preserve-test-state')
    containers, bindings = [], {}
    try:
        docker('pull', IMAGE)
        for role in sorted(b.ROLES | {'etcd'}):
            cid = docker('run', '-d', '--network=none', '--restart=' + ('no' if role == 'semantic' else 'unless-stopped'),
                '--stop-signal=SIGINT' if role == 'postgres' else '--stop-signal=SIGTERM',
                '--mount', 'type=bind,src=' + str(source) + ',dst=/fixture', '--entrypoint=/bin/sh',
                IMAGE, '-c', "trap 'exit 0' TERM INT; touch /ready; while :; do sleep 1 & wait $!; done")
            containers.append(cid)
            bindings[role] = {'containerId': cid, 'nativeImage': json.loads(docker('inspect', cid))[0]['Image']}
        for _ in range(2):
            containers.append(docker('create', '--network=none', '--restart=unless-stopped',
                '--mount', 'type=bind,src=' + str(source) + ',dst=/fixture', IMAGE))
        # Ensure all PID1 traps are installed before the measured operation.
        for row in bindings.values(): docker('exec', row['containerId'], 'test', '-f', '/ready')
        prepare = root / 'prepare'
        prepare.mkdir(mode=0o700)
        r = b.Runner(prepare, seconds=300)
        host = r.inventory({v['containerId'] for v in bindings.values()})
        plan = b.build_plan(bindings, host, prepare, b.digest((ROOT / 'scripts/storage-cold-backup.py').read_bytes()))
        before = b.digest((source / 'keep').read_bytes())
        stop = root / 'stop'
        stop.mkdir(mode=0o700)
        run = d.bounded_runner(vars(b), stop)
        result = d.stop_once(vars(b), vars(p), plan, host, stop, run, 'synthetic-stop-decision')
        assert result['policyChanges'] == 15 and result['selectedRolesStopped'] == 14
        assert result['mutationCalls'] == 29
        after = run.inventory({v['containerId'] for v in bindings.values()})
        b.offline(plan, after)
        assert all(not x['State']['Running'] for x in after.values())
        assert before == b.digest((source / 'keep').read_bytes())
        before_calls = run.calls
        try:
            d.stop_once(vars(b), vars(p), plan, host, stop, run, 'synthetic-stop-decision')
            raise AssertionError('Replay accepted')
        except FileExistsError: pass
        assert run.calls == before_calls
        report = {'schema': 'ouf.storage-test-cold-stop-native.v1', 'status': 'PASS',
            'fixture': '14 PID1 signal handlers plus2 stopped sharing containers; no OUF application or real PostgreSQL workload',
            'image': IMAGE, 'policyChanges': 15, 'signals': 14, 'sourceBytesPreserved': True,
            'allContainersStopped': True, 'backupV3OfflineGuardPassed': True, 'replayDeniedWithoutProviderCall': True,
            'privateIntentReceipts': len(list(stop.glob('*.intent.private.json'))),
            'applicationDrainProven': False, 'targetOperations': 0, 'acceptanceCreditAdded': 0,
            'sources': {name: b.digest((ROOT / name).read_bytes()) for name in (
                'scripts/storage-test-cold-stop.py', 'tools/storage_planning/cold_stop_proposal.py',
                'scripts/storage-cold-backup.py')}}
        Path('test-stop-native-result.json').write_bytes(b.canonical(report))
        print(json.dumps(report, sort_keys=True))
    finally:
        # Fixture cleanup only; production driver has no remove/start/force path.
        for cid in reversed(containers):
            try: docker('rm', '-f', cid)
            except subprocess.CalledProcessError: pass


if __name__ == '__main__': main()
