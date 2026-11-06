"""Disposable runner-only host containment: actual systemd, no Docker or IAM."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]


def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main():
    assert os.environ.get('GITHUB_ACTIONS') == 'true' and os.geteuid() == 0
    b = load('backup_io', 'scripts/storage-cold-backup.py')
    p = load('host_preparation', 'scripts/prepare-storage-host-containment-20261106.py')
    d = load('host_containment', 'scripts/storage-host-containment-20261106.py')
    tag = uuid.uuid4().hex[:10]
    root = Path('/var/lib') / ('ouf-host-stop-native-' + tag)
    root.mkdir(mode=0o700)
    prefix = 'ouf-native-token-' + tag
    p.TIMERS = tuple(prefix + ('-' if i < 3 else '@') + str(i) + '.timer' for i in range(5))
    p.SERVICES = tuple(n[:-6] + '.service' for n in p.TIMERS)
    p.REGISTRY = prefix + '-registry.service'
    p.MASKED = (prefix + '-masked.service', prefix + '-masked.timer')
    p.EXPECTED = set(p.TIMERS + p.SERVICES + (p.REGISTRY,) + p.MASKED)
    p.AREA = root / 'preparation'
    d.AREA = root / 'host-operation'
    d.DRAFT = p.AREA / 'draft.private.json'
    created, enabled = [], []
    runtime = []
    for i in range(6):
        path = root / ('runtime-' + str(i))
        path.mkdir(mode=0o700)
        b.new(path / 'value', b'initial')
        runtime.append(str(path))
    worker = root / 'worker.py'
    b.new(worker, b'''import os,signal,sys,time\nfrom pathlib import Path\np=Path(sys.argv[1]); running=True\ndef stop(*_):\n global running\n running=False\nsignal.signal(signal.SIGTERM,stop)\nif sys.argv[2]=='once':\n time.sleep(8);(p/'value').write_text('naturally completed')\nelse:\n while running:\n  (p/'value').write_text(str(time.monotonic_ns()));time.sleep(.1)\n (p/'term').write_text('graceful')\n''')

    def ctl(*args, check=True):
        return subprocess.run(['/usr/bin/systemctl', '--no-pager', *args], check=check,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, text=True)

    try:
        for name in sorted(p.EXPECTED):
            path = d.SYSTEMD_ROOT / name
            assert not os.path.lexists(path)
            if name in p.MASKED:
                path.symlink_to('/dev/null')
            elif name.endswith('.timer'):
                raw = '[Unit]\nDescription=OUF disposable timer\n[Timer]\nOnActiveSec=1h\nUnit=' + name[:-6] + '.service\n[Install]\nWantedBy=timers.target\n'
                b.new(path, raw.encode())
            else:
                registry = name == p.REGISTRY
                i = 5 if registry else p.SERVICES.index(name)
                raw = ('[Unit]\nDescription=OUF disposable token writer\n[Service]\nType=' + ('simple' if registry else 'oneshot') +
                       '\nExecStart=/usr/bin/python3 ' + str(worker) + ' ' + runtime[i] + (' loop' if registry else ' once') +
                       '\nRestart=' + ('on-failure' if registry else 'no') + '\nRuntimeDirectoryPreserve=no\nSendSIGKILL=yes\nTimeoutStopSec=35s\n[Install]\nWantedBy=multi-user.target\n')
                b.new(path, raw.encode())
            created.append(path)
        ctl('daemon-reload')
        for unit in tuple(p.TIMERS) + (p.REGISTRY,):
            ctl('enable', '--now', unit)
            enabled.append(unit)
        # Only five services are static on the target; remove fixture-only Install
        # stanzas for them before preparing the exact bound configuration.
        for name in p.SERVICES:
            path = d.SYSTEMD_ROOT / name
            path.write_text(path.read_text().split('[Install]')[0])
        ctl('daemon-reload')
        legacy = {'sources': runtime + ['/data/fixture-' + str(i) for i in range(28)],
                  'runtimeSources': {path: {} for path in runtime[:5]},
                  'validUntilEpoch': int(time.time()) + 86400}
        p.PRIOR = {}
        for i in range(4):
            path = root / ('prior-' + str(i) + '.json')
            raw = b.canonical(legacy if i == 0 else {'fixturePrior': i})
            b.new(path, raw);p.PRIOR[str(path)] = b.digest(raw)
        prepared = p.prepare(vars(b))
        print(json.dumps({'phase': 'PREPARED', 'boundFiles': prepared['unitConfigurationFilesBound'], 'findings': prepared['findings']}), flush=True)
        d.DRAFT_SHA = prepared['candidateSha256']
        probe_area = root / 'inactive-cgroup-proof'
        probe_area.mkdir(mode=0o700)
        probe = d.Runner(vars(b), probe_area)
        initial_rows = d.show(p, probe)
        instance_slices = [p.one(initial_rows[n], 'Slice') for n in p.SERVICES if '@' in n]
        assert len(instance_slices) == 2 and all('\\x2d' in n for n in instance_slices)
        d.bind_cgroups(p, probe, initial_rows)
        for unit in p.SERVICES:
            d.no_processes(probe, unit)
        assert not d.cgroup_empty(probe.cgroups[p.REGISTRY])
        # Exercise natural completion after the containment starts.
        ctl('start', '--no-block', *p.SERVICES)
        until = time.monotonic() + 5
        while True:
            active_rows = d.show(p, probe)
            if all(p.one(active_rows[n], 'ControlGroup') for n in p.SERVICES):
                break
            assert time.monotonic() < until
            time.sleep(.1)
        assert all(p.one(active_rows[n], 'ControlGroup') == probe.cgroups[n] for n in p.SERVICES)
        result = d.apply(vars(b), p, 'SYNTHETIC-RUNNER-HOST-CONTAINMENT')
        assert result['status'] == 'HOST_WRITERS_CONTAINED_NEW_STOP_PLAN_REQUIRED'
        assert result['overrideFilesWritten'] == 6 and result['timersDisabledAndStopped'] == 5
        assert result['mutationCommands'] == 13 and result['forcedServiceKills'] == 0
        assert result['typedEmptyStopHooksVerified'] == 12
        assert result['runtimeSourcesStableAtObservation'] == 5
        assert (Path(runtime[5]) / 'term').read_text() == 'graceful'
        assert all((Path(path) / 'value').read_text() == 'naturally completed' for path in runtime[:5])
        try:
            d.apply(vars(b), p, 'SYNTHETIC-RUNNER-HOST-CONTAINMENT')
            raise AssertionError('Host attempt replay accepted')
        except FileExistsError:
            pass
        print(json.dumps({'schema': 'ouf.storage-host-containment-native.v1', 'status': 'PASS',
            'result': result, 'fiveNaturalCompletions': True, 'registryTermHandlerCompleted': True,
            'hostAttemptReplayRejected': True, 'targetOperationProven': False,
            'initiallyInactiveAndActiveCgroupsChecked': True,
            'instantiatedServiceEscapedSlicesChecked': len(instance_slices),
            'productionSha256': b.digest((ROOT / 'scripts/storage-host-containment-20261106.py').read_bytes()),
            'acceptanceCreditAdded': 0}), flush=True)
    except Exception:
        if d.AREA.exists():
            logs = sorted(d.AREA.glob('command-*.private.json'))
            if logs:
                last = json.loads(logs[-1].read_bytes())
                print(json.dumps({'fixtureLastCommand': last['args'], 'returncode': last['returncode'],
                                  'stderr': last['stderr']}), flush=True)
        raise
    finally:
        # Fixture cleanup only: never part of production driver or target instructions.
        ctl('stop', '--no-block', *sorted(p.EXPECTED), check=False)
        for unit in enabled:
            ctl('disable', '--no-reload', unit, check=False)
        for name in tuple(p.SERVICES) + (p.REGISTRY,):
            drop = d.SYSTEMD_ROOT / (name + '.d')
            if drop.exists():
                shutil.rmtree(drop)
        for path in reversed(created):
            path.unlink()
        ctl('daemon-reload')
        ctl('reset-failed', *sorted(p.EXPECTED), check=False)
        # Fixture process timeout is not a target retry/kill permission.
        shutil.rmtree(root)


if __name__ == '__main__':
    main()
