"""Disposable GitHub-runner systemd read integration; never starts a service.

Creates unique synthetic service/timer files, two masks and one linked external
fragment. Exercises the actual bounded preparer and protected filesystem reader.
No VPS, Docker, IAM, token writer, stop/capture or acceptance qualification.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    assert os.environ.get('GITHUB_ACTIONS') == 'true' and os.geteuid() == 0
    assert Path('/run/systemd/system').is_dir()
    p = load('host_preparation_native', 'scripts/prepare-storage-host-containment-20261106.py')
    b = load('protected_io_native', 'scripts/storage-cold-backup.py')
    tag = uuid.uuid4().hex[:12]
    area = Path('/var/lib') / ('ouf-host-preparation-native-' + tag)
    area.mkdir(mode=0o700)
    units_dir = Path('/run/systemd/system')
    prefix = 'ouf-native-token-' + tag
    p.TIMERS = tuple(prefix + '-' + str(i) + '.timer' for i in range(5))
    p.SERVICES = tuple(n[:-6] + '.service' for n in p.TIMERS)
    p.REGISTRY = prefix + '-registry.service'
    p.MASKED = (prefix + '-masked.service', prefix + '-masked.timer')
    p.EXPECTED = set(p.TIMERS + p.SERVICES + (p.REGISTRY,) + p.MASKED)
    p.AREA = area / 'prepared'
    created = []
    secret = 'SYNTHETIC_UNIT_VALUE_' + tag

    def reload_manager():
        subprocess.run(['/usr/bin/systemctl', 'daemon-reload'], check=True, timeout=30,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    try:
        for name in sorted(p.EXPECTED):
            path = units_dir / name
            assert not os.path.lexists(path)
            if name in p.MASKED:
                path.symlink_to('/dev/null')
            elif name == p.REGISTRY:
                fragment = area / 'owner.fragment'
                b.new(fragment, ('[Unit]\nDescription=OUF synthetic metadata fixture\n'
                    '[Service]\nType=oneshot\nExecStart=/usr/bin/true\n'
                    'ExecStop=/usr/bin/true first-fixture-command\n'
                    'ExecStop=/usr/bin/true second-fixture-command\n'
                    'Environment=FIXTURE_SECRET=' + secret + '\n').encode())
                path.symlink_to(fragment)
            elif name.endswith('.timer'):
                b.new(path, ('[Unit]\nDescription=OUF synthetic timer metadata\n'
                    '[Timer]\nOnBootSec=10d\nOnUnitActiveSec=20d\nUnit=' + name[:-6] + '.service\n').encode())
            else:
                b.new(path, b'[Unit]\nDescription=OUF synthetic service metadata\n[Service]\nType=oneshot\nExecStart=/usr/bin/true\n')
            created.append(path)
        reload_manager()
        legacy = {'sources': ['/data/synthetic-' + str(i) for i in range(34)],
                  'runtimeSources': {'/run/synthetic-' + str(i): {} for i in range(5)},
                  'validUntilEpoch': int(time.time()) + 3600}
        p.PRIOR = {}
        for i in range(4):
            path = area / ('prior-' + str(i) + '.json')
            raw = b.canonical(legacy if i == 0 else {'syntheticPrior': i})
            b.new(path, raw)
            p.PRIOR[str(path)] = b.digest(raw)
        # No mutation command exists in the production preparer. This recording
        # wrapper delegates its three reads to the real bounded CLI implementation.
        calls = []

        def actual_read(argv, until):
            assert argv[0] in ('list-unit-files', 'list-units', 'show')
            calls.append(argv)
            return p.command(argv, until)

        result = p.prepare(vars(b), run=actual_read)
        print(json.dumps({'schema': 'ouf.storage-host-preparation-systemd-observation.v1',
                          'redactedPreparation': result}, sort_keys=True), flush=True)
        assert len(calls) == 3 and '--all' in calls[-1]
        assert len(result['units']) == 13 and result['unitConfigurationFilesBound'] == 11
        assert result['serviceMutations'] == result['dockerRequests'] == result['iamRequests'] == 0
        registry = next(r for r in result['units'] if r['Id'] == p.REGISTRY)
        assert registry['externalConfigurationFilesBound'] == 1 and registry['execStopPresent'] is True
        assert all(r['ActiveState'] == 'inactive' for r in result['units'])
        assert secret not in json.dumps(result)
        draft = json.loads(b.protected(p.AREA / 'draft.private.json', private=True))
        commands = next(r['ExecStop'] for r in draft['unitProperties'] if r['Id'] == [p.REGISTRY])
        assert 'first-fixture-command' in '\n'.join(commands)
        assert 'second-fixture-command' in '\n'.join(commands)
        assert all(next(r for r in result['units'] if r['Id'] == name)['execStopPresent'] is False
                   for name in p.SERVICES)
        # Capture actual omission/array behaviour, without attributing the VPS's
        # unspecified PROPERTY_CARDINALITY to a particular field or systemd version.
        default_show = p.command(['show', p.REGISTRY, '--property=ExecStopPost'], time.monotonic() + 10)
        calls.clear()
        try:
            p.prepare(vars(b), run=actual_read)
            raise AssertionError('Existing preparation was overwritten')
        except ValueError as error:
            assert str(error) == 'PREPARATION_ALREADY_EXISTS_NO_OVERWRITE'
        assert not calls
        proof = {'schema': 'ouf.storage-host-preparation-systemd-native.v1', 'status': 'PASS',
            'programSha256': hashlib.sha256((ROOT / 'scripts/prepare-storage-host-containment-20261106.py').read_bytes()).hexdigest(),
            'syntheticUnits': 13, 'protectedConfigurationFiles': 11, 'externalFragmentBound': True,
            'multipleExecStopCommandsPreserved': True, 'emptyExecStopKnownFalse': True,
            'defaultShowIncludesEmptyExecStopPost': 'ExecStopPost=' in default_show,
            'optionalPropertyFindings': result['findings'], 'privateOutputProtected': True,
            'existingPreparationDeniedBeforeCommands': True, 'serviceStartsOrStops': 0,
            'fixtureDaemonReloads': 2, 'dockerRequests': 0, 'iamRequests': 0,
            'targetPreparationOrContainmentProven': False, 'acceptanceCreditAdded': 0}
    finally:
        # Only exact unique fixture paths; all units remained inactive.
        for path in reversed(created):
            path.unlink()
        reload_manager()
        shutil.rmtree(area)
    print(json.dumps(proof, sort_keys=True))


if __name__ == '__main__':
    main()
