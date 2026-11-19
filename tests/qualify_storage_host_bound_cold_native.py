"""Disposable native composition: real systemd readback,14Docker handlers,archive.
Not a repetition of real PostgreSQL/MinIO restore qualification; no target access.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import types
import uuid

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    m = importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    return m


def cmd(*args, timeout=120):
    return subprocess.check_output(list(args), stderr=subprocess.STDOUT, timeout=timeout).decode().strip()


def main():
    assert os.geteuid() == 0 and os.environ.get('GITHUB_ACTIONS') == 'true'
    os.umask(0o077)
    v4 = load('v4', 'scripts/storage-cold-backup-v4.py')
    h = v4.definitions((ROOT / 'scripts/storage-cold-backup.py').read_bytes())
    d = load('stop', 'scripts/storage-test-cold-stop.py')
    p = load('host_reader', 'scripts/prepare-storage-host-containment-20261106.py')
    core = load('host_core', 'scripts/storage-host-containment-20261106.py')
    o = load('linked', 'scripts/storage-host-bound-cold-backup-20261107.py')
    planner = vars(load('planner', 'tools/storage_planning/cold_stop_proposal.py'))
    root = Path(tempfile.mkdtemp(prefix='ouf-host-bound-native-', dir='/var/lib'))
    source = root / 'source';source.mkdir(mode=0o700)
    runtime = []
    for i in range(5):
        path = source / ('runtime-' + str(i));path.mkdir(mode=0o700)
        h['new'](path / 'value', b'before-host-containment');runtime.append(str(path))
    containers, created_units, dropins = [], [], []
    prefix = 'ouf-linked-' + uuid.uuid4().hex[:10]
    p.TIMERS = tuple(prefix + ('-' if i < 3 else '@') + str(i) + '.timer' for i in range(5))
    p.SERVICES = tuple(n[:-6] + '.service' for n in p.TIMERS)
    p.REGISTRY = prefix + '-registry.service'
    p.MASKED = (prefix + '-masked.service', prefix + '-masked.timer')
    p.EXPECTED = set(p.TIMERS + p.SERVICES + (p.REGISTRY,) + p.MASKED)
    d.AREA = root / 'old-stop';d.AREA.mkdir(mode=0o700)
    o.AREA = root / 'linked-operation';o.HOST_AREA = root / 'host-receipt';o.HOST_AREA.mkdir(mode=0o700)
    try:
        for name in sorted(p.EXPECTED):
            path = core.SYSTEMD_ROOT / name
            assert not os.path.lexists(path)
            if name in p.MASKED:
                path.symlink_to('/dev/null')
            elif name in p.TIMERS:
                h['new'](path, ('[Timer]\nOnActiveSec=1h\nUnit=' + name[:-6] + '.service\n[Install]\nWantedBy=timers.target\n').encode())
            else:
                h['new'](path, ('[Service]\nType=' + ('simple' if name == p.REGISTRY else 'oneshot') +
                    '\nExecStart=/usr/bin/true\n[Install]\nWantedBy=multi-user.target\n').encode())
                directory = core.SYSTEMD_ROOT / (name + '.d');directory.mkdir(mode=0o755)
                h['new'](directory / core.OVERRIDE_NAME, core.OVERRIDE);dropins.append(directory)
            created_units.append(path)
        cmd('systemctl', 'daemon-reload')
        guardroot = root / 'host-fixture-read';guardroot.mkdir(mode=0o700)
        probe = core.Runner(h, guardroot)
        rows = core.show(p, probe)
        probe.cgroups = {n: core.slice_cgroup_path(p.one(rows[n], 'Slice')).rstrip('/') + '/' + n
                         for n in tuple(p.SERVICES) + (p.REGISTRY,)}
        prior_rows = copy.deepcopy(list(rows.values()))
        for row in prior_rows:
            if row['Id'][0] in tuple(p.SERVICES) + (p.REGISTRY,):row['DropInPaths'] = ['']
        draft = {'unitProperties': prior_rows,
            'unitConfiguration': {str(path): {'sha256': h['digest'](path.read_bytes()), 'text': path.read_text()} for path in created_units if not path.is_symlink()}}
        draft_raw = h['canonical'](draft)
        h['new'](o.HOST_AREA / 'reviewed-draft.private.json', draft_raw)
        h['new'](o.HOST_AREA / 'preflight.private.json', h['canonical']({'unitCgroups': probe.cgroups}))
        h['new'](o.HOST_AREA / 'final-units.private.json', h['canonical'](rows))
        h['new'](o.HOST_AREA / 'claim.private.json', h['canonical']({'fixture': 'retained host success'}))
        cmd('docker', 'pull', 'busybox:1.36.1', timeout=300)
        image = json.loads(cmd('docker', 'image', 'inspect', 'busybox:1.36.1'))[0]['Id']
        bindings = {}
        for role in sorted(h['ROLES'] | {'etcd'}):
            cid = cmd('docker', 'run', '-d', '--network=none', '--restart=' + ('no' if role == 'semantic' else 'unless-stopped'),
                '--stop-signal=' + ('SIGINT' if role == 'postgres' else 'SIGTERM'), '--mount',
                'type=bind,src=' + str(source) + ',dst=/fixture', '--entrypoint=/bin/sh', image,
                '-c', "trap 'exit 0' TERM INT; touch /ready; while :; do sleep 1 & wait $!; done")
            containers.append(cid);bindings[role] = {'containerId': cid, 'nativeImage': image}
        for _ in range(2):
            containers.append(cmd('docker', 'create', '--network=none', '--restart=unless-stopped', '--mount',
                'type=bind,src=' + str(source) + ',dst=/fixture', image))
        for row in bindings.values():cmd('docker', 'exec', row['containerId'], 'test', '-f', '/ready')
        prepareroot = root / 'prepare';prepareroot.mkdir(mode=0o700)
        retained = h['Runner'](prepareroot, seconds=300).inventory({v['containerId'] for v in bindings.values()})
        old_plan = h['build_plan'](bindings, retained, o.AREA, 'fixture-old-program')
        old_plan['runtimeSources'] = {path: h['runtime_source_identity'](path) for path in runtime}
        for path in runtime:(Path(path) / 'value').write_bytes(b'after-verified-host-containment')
        snapshot = {path: h['runtime_source_identity'](path) for path in runtime}
        snapshot_raw = h['canonical'](snapshot);o.HOST_SNAPSHOT_SHA = h['digest'](snapshot_raw)
        h['new'](o.HOST_AREA / 'runtime-snapshot.private.json', snapshot_raw)
        host_result = {'status': 'HOST_WRITERS_CONTAINED_NEW_STOP_PLAN_REQUIRED', 'overrideFilesWritten': 6,
            'timersDisabledAndStopped': 5, 'registryDisabledAndStopped': True, 'priorAttemptPreserved': True,
            'forcedServiceKills': 0, 'draftSha256': h['digest'](draft_raw), 'legacyValidUntilEpoch': old_plan['validUntilEpoch']}
        raw = h['canonical'](host_result);o.HOST_RESULT_SHA = h['digest'](raw)
        h['new'](o.HOST_AREA / 'continuation-result.json', raw)
        old_run = d.bounded_runner(h, d.AREA)
        try:
            d.stop_once(h, planner, old_plan, retained, d.AREA, old_run, o.OLD_DECISION)
            raise AssertionError('Expected old source-drift hold')
        except Exception as error:
            assert str(error) == 'RUN_SOURCE_CHANGED_SINCE_PLAN'
        assert old_run.calls == 3
        original = {x.name: x.read_bytes() for x in d.AREA.iterdir() if x.is_file()}
        o.OLD_STOP_PINS = {name: h['digest'](original[name]) for name in o.OLD_STOP_PINS}
        o.EXPECTED_HOST = len(retained);o.EXPECTED_POLICY = (13, 2)
        context = o.host_review(h)
        # Only runtime identities/program/provenance may change in the new plan.
        derived = o.bind_plan(h, old_plan, context, 'fixture-new-program')
        assert {k for k in derived if derived.get(k) != old_plan.get(k)} == {'runtimeSources', 'programSha256', 'hostContainmentLink'}
        assert derived['validUntilEpoch'] == old_plan['validUntilEpoch']
        identity = root / 'identity'
        cmd('ssh-keygen', '-t', 'ed25519', '-N', '', '-f', str(identity))
        public = h['recipient']((root / 'identity.pub').read_bytes())
        # Host re-enablement is detected by the real systemd readback before Docker mutation.
        cmd('systemctl', 'enable', p.TIMERS[0])
        try:
            o.host_check(h, core, p, context, probe)
            raise AssertionError('Re-enabled host writer accepted')
        except ValueError as error:
            assert str(error) == 'HOST_WRITER_REENABLED'
        cmd('systemctl', 'disable', p.TIMERS[0])  # Fixture setup only.
        result = o.execute(h, d, planner, core, p, old_plan, retained, context, public, o.DECISION, 'fixture-new-program')
        assert result['status'] == 'ENCRYPTED_OFFLINE_RECOVERY_SET_CAPTURED'
        assert result['selectedRolesStopped'] == 14 and result['policyChanges'] == 15
        assert result['hostReadOnlyChecks'] == 3 and result['priorStopReadCalls'] == 3
        assert {x.name: x.read_bytes() for x in d.AREA.iterdir() if x.is_file()} == original
        decrypted = root / 'decrypted.tar';restored = root / 'restored';restored.mkdir()
        cmd('age', '-d', '-i', str(identity), '-o', str(decrypted), result['archive'])
        cmd('tar', '-xf', str(decrypted), '-C', str(restored))
        archived_plan = h['decode']((restored / 'plan.private.json').read_bytes())
        assert archived_plan['hostContainmentLink']['hostEvidenceSha256'] == context['hashes']
        assert archived_plan['hostContainmentLink']['hostRecoveryEvidence'] == context['evidence']
        data = root / 'restored-data';data.mkdir()
        cmd('tar', '-xf', str(restored / 'source-000.tar'), '-C', str(data))
        assert all((data / 'source' / Path(path).name / 'value').read_bytes() == b'after-verified-host-containment' for path in runtime)
        try:
            o.execute(h, d, planner, core, p, old_plan, retained, context, public, o.DECISION, 'fixture-new-program')
            raise AssertionError('Linked replay accepted')
        except ValueError as error:
            assert str(error) == 'LINKED_OPERATION_ALREADY_CLAIMED'
        print(json.dumps({'schema': 'ouf.storage-host-bound-cold-native.v1', 'status': 'PASS',
            'fixture': '14BusyBoxPID1handlers+2stoppedsharers;real systemd readback and capture,not PostgreSQL/MinIO workload',
            'nativeImage': image, 'oldSourceHoldReproduced': True, 'oldStopJournalBytePreserved': True,
            'hostReenablementDenied': True, 'runtimeOnlyPlanRebind': True, 'originalExpiryPreserved': True,
            'fiveCapturedRuntimeBodiesRestored': True, 'archivedHostEvidenceLinkVerified': True,
            'replayDenied': True, 'result': result, 'targetOperations': 0, 'acceptanceCreditAdded': 0,
            'productionSha256': h['digest']((ROOT / 'scripts/storage-host-bound-cold-backup-20261107.py').read_bytes())}), flush=True)
    finally:
        for cid in reversed(containers):
            subprocess.run(['docker', 'rm', '-f', cid], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for path in dropins:shutil.rmtree(path)
        for path in created_units:path.unlink()
        subprocess.run(['systemctl', 'daemon-reload'], check=False)
        shutil.rmtree(root)


if __name__ == '__main__':main()
