"""Capture-only continuation: actual etcd exec events, retained stop, encrypted archive.
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
    r = load('event_reader', 'scripts/read-storage-cold-event-held-20261107.py')
    c = load('capture_only', 'scripts/capture-storage-after-held-stop-20261107.py')
    planner = vars(load('planner', 'tools/storage_planning/cold_stop_proposal.py'))
    root = Path(tempfile.mkdtemp(prefix='ouf-capture-only-native-', dir='/var/lib'))
    source = root / 'source';source.mkdir(mode=0o700)
    runtime = []
    for i in range(5):
        path = source / ('runtime-' + str(i));path.mkdir(mode=0o700)
        h['new'](path / 'value', b'before-host-containment');runtime.append(str(path))
    containers, created_units, dropins = [], [], []
    prefix = 'ouf-capture-only-' + uuid.uuid4().hex[:10]
    p.TIMERS = tuple(prefix + ('-' if i < 3 else '@') + str(i) + '.timer' for i in range(5))
    p.SERVICES = tuple(n[:-6] + '.service' for n in p.TIMERS)
    p.REGISTRY = prefix + '-registry.service'
    p.MASKED = (prefix + '-masked.service', prefix + '-masked.timer')
    p.EXPECTED = set(p.TIMERS + p.SERVICES + (p.REGISTRY,) + p.MASKED)
    d.AREA = root / 'unused-old-stop'
    o.AREA = root / 'held-operation';r.AREA = o.AREA;c.AREA = root / 'capture-continuation';o.HOST_AREA = root / 'host-receipt';o.HOST_AREA.mkdir(mode=0o700)
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
        for i in range(131):
            mount = ['--mount', 'type=bind,src=' + str(source) + ',dst=/fixture'] if i < 103 else []
            containers.append(cmd('docker', 'create', '--network=none', '--restart=' + ('unless-stopped' if i < 22 else 'no'), *mount, image))
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
        context = o.host_review(h)
        derived = o.bind_plan(h, old_plan, context, r.PROGRAM_SHA)
        r.HOST_RESULT_SHA, r.SNAPSHOT_SHA = o.HOST_RESULT_SHA, o.HOST_SNAPSHOT_SHA
        o.AREA.mkdir(mode=0o700)
        for name in ('host-checks','stop','capture'):(o.AREA / name).mkdir(mode=0o700)
        h['new'](o.AREA / 'plan.private.json', h['canonical'](derived))
        h['new'](o.AREA / 'operation-claim.private.json', h['canonical']({
            'decisionReference': r.DECISION, 'attempts': 1, 'hostReceiptSha256': context['hashes']}))
        old_guard = core.Runner(h, o.AREA / 'host-checks')
        o.host_check(h, core, p, context, old_guard)
        stop_run = d.bounded_runner(h, o.AREA / 'stop');stop_run.calls = 3
        real_docker = stop_run.docker
        injected = [False]
        def with_external_execs(*args, **kw):
            raw = real_docker(*args, **kw)
            if args[0] == 'update' and not injected[0]:
                injected[0] = True
                for _ in range(3):cmd('docker', 'exec', bindings['etcd']['containerId'], '/bin/true')
            return raw
        stop_run.docker = with_external_execs
        try:
            d.stop_once(h, planner, derived, retained, o.AREA / 'stop', stop_run, r.DECISION)
            raise AssertionError('Expected late event HOLD')
        except Exception as error:
            assert str(error) == 'UNEXPECTED_CONTAINER_EVENT', str(error)
        assert injected[0] and not list((o.AREA / 'capture').iterdir())
        report = r.review(h, o)
        assert report['mutationRepliesBound'] == 49 and report['verifiedRestartPolicyReceipts'] == 35
        assert report['retainedRunningContainerCount'] == 0 and report['events']['unexpectedByOriginalFilter'] == 9
        c.REPORT_SHA = h['digest'](h['canonical'](report))
        c.PLAN_SHA, c.JOURNAL_SHA = report['planSha256'], report['retainedJournalDigest']
        original = {str(x.relative_to(o.AREA)): x.read_bytes() for x in o.AREA.rglob('*') if x.is_file()}
        sealed = c.sealed_stop(h, r, o, core, p)
        identity = root / 'identity'
        cmd('ssh-keygen', '-t', 'ed25519', '-N', '', '-f', str(identity))
        public = h['recipient']((root / 'identity.pub').read_bytes())
        # No provider action can be reached if the reviewed journal is altered.
        receipt = o.AREA / 'stop/action-001.intent.private.json'
        before = receipt.read_bytes();receipt.write_bytes(before.replace(b'RESTART_NO', b'RESTART_XX'))
        try:
            c.execute(h, r, o, core, p, context, public, c.DECISION, 'fixture-capture-program')
            raise AssertionError('Altered journal accepted')
        except ValueError as error:
            assert str(error) == 'ACTION_SCOPE_MISMATCH'
        assert not c.AREA.exists();receipt.write_bytes(before)
        result = c.execute(h, r, o, core, p, context, public, c.DECISION, 'fixture-capture-program')
        assert result['status'] == 'ENCRYPTED_OFFLINE_RECOVERY_SET_CAPTURED'
        assert result['stopSignalsSent'] == result['restartPoliciesChanged'] == result['hostMutations'] == 0
        assert result['cumulativeHostReadCalls'] == 3 and result['priorHostReadCallsCharged'] == 1
        assert {str(x.relative_to(o.AREA)): x.read_bytes() for x in o.AREA.rglob('*') if x.is_file()} == original
        decrypted = root / 'decrypted.tar';restored = root / 'restored';restored.mkdir()
        cmd('age', '-d', '-i', str(identity), '-o', str(decrypted), result['archive'])
        cmd('tar', '-xf', str(decrypted), '-C', str(restored))
        archived_plan = h['decode']((restored / 'plan.private.json').read_bytes())
        assert archived_plan['hostContainmentLink']['hostEvidenceSha256'] == context['hashes']
        assert archived_plan['hostContainmentLink']['hostRecoveryEvidence'] == context['evidence']
        archived_context = archived_plan['captureAfterHeldStop']
        assert archived_context['retainedReadback'] == report
        assert archived_context['privateStopEvidence'] == sealed['privateEvidence']
        assert archived_context['journalHashes'] == sealed['journalHashes']
        assert archived_plan['validUntilEpoch'] == old_plan['validUntilEpoch']
        data = root / 'restored-data';data.mkdir()
        cmd('tar', '-xf', str(restored / 'source-000.tar'), '-C', str(data))
        assert all((data / 'source' / Path(path).name / 'value').read_bytes() == b'after-verified-host-containment' for path in runtime)
        try:
            c.execute(h, r, o, core, p, context, public, c.DECISION, 'fixture-capture-program')
            raise AssertionError('Capture continuation replay accepted')
        except ValueError as error:
            assert str(error) == 'CAPTURE_CONTINUATION_ALREADY_CLAIMED'
        print(json.dumps({'schema': 'ouf.storage-capture-after-held-stop-native.v1', 'status': 'PASS',
            'fixture': '14BusyBoxPID1handlers+131stopped;103sharing;real systemd readback and encrypted capture;not target workloads',
            'nativeImage': image, 'lateHoldWithThreeEtcdExecsReproduced': True,
            'retainedJournalFiles': report['filesBound'], 'retainedEvents': report['events']['eventCount'],
            'unexpectedRetainedEvents': 9, 'oldStopJournalBytePreserved': True,
            'alteredIntentDeniedBeforeContinuationClaim': True, 'originalExpiryPreserved': True,
            'fiveCapturedRuntimeBodiesRestored': True, 'archivedFullEventAndActionEvidenceVerified': True,
            'replayDenied': True, 'result': result, 'targetOperations': 0, 'acceptanceCreditAdded': 0,
            'productionSha256': h['digest']((ROOT / 'scripts/capture-storage-after-held-stop-20261107.py').read_bytes())}), flush=True)
    finally:
        for cid in reversed(containers):
            subprocess.run(['docker', 'rm', '-f', cid], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for path in dropins:shutil.rmtree(path)
        for path in created_units:path.unlink()
        subprocess.run(['systemctl', 'daemon-reload'], check=False)
        shutil.rmtree(root)


if __name__ == '__main__':main()
