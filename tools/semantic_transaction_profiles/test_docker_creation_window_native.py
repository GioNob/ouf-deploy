"""Disposable CI Docker/runc creation window, never a target authority test.

Both Docker start requests reach an actual OCI createRuntime hook before either
application is released. This tests engine concurrency and native transitional
states only; it does not approve an observed OCI document or exercise node v4.
"""
import concurrent.futures
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid


def run(*args, payload=None, check=True, timeout=30):
    result = subprocess.run(args, input=payload, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout)
    if check and result.returncode:
        # This fixture owns every argument and contains no credentials/secrets.
        print(json.dumps({'fixtureCommand': str(args[0]), 'exitCode': result.returncode,
                          'fixtureError': result.stderr.decode(errors='replace')[-2048:]}), flush=True)
        raise RuntimeError('COMMAND_FAILED:' + str(args[0]) + ':' + str(result.returncode))
    return result


def fixture(root, args):
    """CI-only runtime wrapper; never imported by the production intake."""
    root = Path(root)
    settings = json.loads((root / 'settings.json').read_text())
    if args[0] == 'hook':
        cid = args[1]
        (root / (cid + '.entered')).touch()
        deadline = time.monotonic() + 25
        while not (root / 'release').exists():
            if time.monotonic() > deadline:
                return 73
            time.sleep(0.02)
        return 0
    if 'create' in args:
        cid = args[-1]
        if cid not in settings['cids']:
            return 74
        bundle = args[args.index('--bundle') + 1] if '--bundle' in args else args[args.index('-b') + 1]
        path = Path(bundle) / 'config.json'
        spec = json.loads(path.read_text())
        spec.setdefault('hooks', {}).setdefault('createRuntime', []).append({
            'path': settings['python'], 'args': [settings['python'], '-I', '-B',
                settings['script'], '--fixture', str(root), 'hook', cid], 'timeout': 26})
        path.write_text(json.dumps(spec))
        runtime_root = args[args.index('--root') + 1]
        (root / (cid + '.runtime.json')).write_text(json.dumps({
            'runtimeRoot': runtime_root, 'applicationHash': hashlib.sha256(
                json.dumps(spec, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}))
    os.execv(settings['runc'], [settings['runc'], *args])


def exercise():
    if os.geteuid() != 0:
        raise RuntimeError('DISPOSABLE_ROOT_CI_REQUIRED')
    daemon_path = Path('/etc/docker/daemon.json')
    previous = daemon_path.read_bytes() if daemon_path.exists() else None
    modified = False
    cids = []
    image = None
    suffix = uuid.uuid4().hex[:12]
    name = 'ouf-ci-window-' + suffix
    with tempfile.TemporaryDirectory(prefix='ouf-ci-window-', dir='/root') as temporary:
        root = Path(temporary)
        python = str(Path(sys.executable).resolve())
        script = str(Path(__file__).resolve())
        runc = str(Path(shutil.which('runc')).resolve())
        def dock(*args, **kw):
            return run('docker', *args, **kw)
        default = dock('info', '--format', '{{.DefaultRuntime}}').stdout
        try:
            config = json.loads(previous) if previous else {}
            config.setdefault('runtimes', {})[name] = {'path': python,
                'runtimeArgs': ['-I', '-B', script, '--fixture', str(root)]}
            daemon_path.parent.mkdir(exist_ok=True)
            daemon_path.write_text(json.dumps(config))
            modified = True
            run('systemctl', 'reload', 'docker')
            assert dock('info', '--format', '{{.DefaultRuntime}}').stdout == default
            archive = io.BytesIO()
            with tarfile.open(fileobj=archive, mode='w') as tar:
                entry = tarfile.TarInfo('bin'); entry.type = tarfile.DIRTYPE; entry.mode = 0o755
                tar.addfile(entry)
                data = Path(shutil.which('busybox')).read_bytes()
                entry = tarfile.TarInfo('bin/busybox'); entry.mode = 0o755; entry.size = len(data)
                tar.addfile(entry, io.BytesIO(data))
            image = dock('image', 'import', '-', payload=archive.getvalue()).stdout.decode().strip()
            # Docker probes the named runtime before creating daemon metadata.
            (root / 'settings.json').write_text(json.dumps({
                'cids': cids, 'python': python, 'script': script, 'runc': runc}))
            for index in range(2):
                proof = root / ('proof-' + str(index)); proof.mkdir()
                cid = dock('create', '--runtime', name, '--network', 'none', '--cap-drop', 'ALL',
                    '--security-opt', 'no-new-privileges', '--mount',
                    'type=bind,source=' + str(proof) + ',target=/proof', image,
                    '/bin/busybox', 'sh', '-c',
                    'echo APP > /proof/started; exec /bin/busybox sleep 60').stdout.decode().strip()
                cids.append(cid)
            (root / 'settings.json').write_text(json.dumps({
                'cids': cids, 'python': python, 'script': script, 'runc': runc}))
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(dock, 'start', cid, check=False, timeout=40) for cid in cids]
                try:
                    deadline = time.monotonic() + 20
                    while not all((root / (cid + '.entered')).exists() for cid in cids):
                        if any(f.done() for f in futures) or time.monotonic() > deadline:
                            raise RuntimeError('BOTH_REAL_DOCKER_CREATES_NOT_REACHED')
                        time.sleep(0.02)
                    assert not any((root / ('proof-' + str(i)) / 'started').exists() for i in range(2))
                    rows = []
                    for cid in cids:
                        metadata = json.loads((root / (cid + '.runtime.json')).read_text())
                        native = json.loads(run(runc, '--root', metadata['runtimeRoot'], 'list', '--format', 'json').stdout)
                        row = next(value for value in native if value['id'] == cid)
                        rows.append({'id': cid, 'status': row['status'], 'pid': row['pid']})
                        # A hook blocks before create finishes. No live state is accepted here.
                        assert row['status'] in ('stopped', 'creating', 'created')
                    (root / 'release').touch()
                    for cid, future in zip(cids, futures):
                        result = future.result()
                        assert result.returncode == 0 and result.stdout.strip() == cid.encode()
                    deadline = time.monotonic() + 5
                    while not all((root / ('proof-' + str(i)) / 'started').exists() for i in range(2)):
                        if time.monotonic() > deadline:
                            raise RuntimeError('BOTH_APPLICATION_MARKERS_UNPROVEN')
                        time.sleep(0.02)
                    print(json.dumps({'status': 'TWO_REAL_DOCKER_CREATION_WINDOWS_PASS',
                        'dockerVersion': dock('version', '--format', '{{.Server.Version}}').stdout.decode().strip(),
                        'transitionalStates': rows, 'bothApplicationsBlockedBeforeRelease': True,
                        'fullFrameAdmissionProven': False, 'targetAuthority': False,
                        'notReleaseAcceptance': True}, sort_keys=True))
                finally:
                    (root / 'release').touch()
        finally:
            for cid in cids:
                dock('rm', '-f', cid, check=False)
            if image:
                dock('image', 'rm', image, check=False)
            if modified:
                if previous is None:
                    daemon_path.unlink()
                else:
                    daemon_path.write_bytes(previous)
                run('systemctl', 'reload', 'docker')


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--fixture':
        sys.exit(fixture(sys.argv[2], sys.argv[3:]))
    exercise()
