"""Disposable CI only. Real MinIO/PostgreSQL cold capture, encryption and restore.
Never imports target bindings, connects to the VPS, or publishes fixture archives.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

spec = importlib.util.spec_from_file_location('cold', Path(__file__).resolve().parents[1] / 'scripts/storage-cold-backup.py')
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)
PG = 'postgis/postgis@sha256:894f570c0cf0664ed5576a8fd5d5bfb8fb1b19d592885b686c3a88c8bd90c41f'
MINIO = 'ghcr.io/datalens-tech/minio@sha256:a1a8bd4ac40ad7881a245bab97323e18f971e4d4cba2c2007ec1bedd21cbaba2'


def cmd(args, timeout=120):
    return subprocess.check_output(args, stderr=subprocess.STDOUT, timeout=timeout).decode().strip()


def docker(*args, timeout=120):
    return cmd(['docker', *args], timeout)


def main():
    assert os.geteuid() == 0 and os.environ.get('GITHUB_ACTIONS') == 'true'
    os.umask(0o077)
    root = Path(tempfile.mkdtemp(prefix='ouf-cold-native-', dir='/var/lib'))
    containers = []
    network = None
    report = {'schema': 'ouf.storage-cold-backup-native.v1', 'status': 'FAIL', 'targetOperations': 0, 'acceptanceCreditAdded': 0}
    try:
        for image in (PG, MINIO):
            docker('pull', image, timeout=300)
        network = None
        for directory in ('pg', 'minio', 'plan', 'capture'):
            (root / directory).mkdir(mode=0o700)
        pg = docker('run', '-d', '--network', 'none', '--restart=no', '--mount', 'type=bind,src=' + str(root / 'pg') + ',dst=/var/lib/postgresql/data',
                    '-e', 'POSTGRES_PASSWORD=fixture-password', PG)
        containers.append(pg)
        mi = docker('run', '-d', '--user', '0:0', '--entrypoint', '/usr/bin/minio', '--stop-signal', 'SIGTERM', '--network', 'none', '--restart=no',
                    '--mount', 'type=bind,src=' + str(root / 'minio') + ',dst=/data',
                    '-e', 'MINIO_ROOT_USER=fixture-admin', '-e', 'MINIO_ROOT_PASSWORD=fixture-secret-password',
                    MINIO, 'server', '/data')
        containers.append(mi)
        for _ in range(90):
            try:
                docker('exec', pg, 'pg_isready', '-U', 'postgres')
                break
            except subprocess.CalledProcessError:
                time.sleep(1)
        else:
            raise AssertionError('PG_READY_TIMEOUT')
        for db in ('onboarding', 'udp', 'ingestion'):
            docker('exec', pg, 'psql', '-U', 'postgres', '-v', 'ON_ERROR_STOP=1', '-c', 'CREATE DATABASE ' + db)
            docker('exec', pg, 'psql', '-U', 'postgres', '-d', db, '-v', 'ON_ERROR_STOP=1', '-c',
                   "CREATE TABLE recovery_fixture(id int primary key, payload text); INSERT INTO recovery_fixture VALUES (1, 'profile/sample/object/lineage');")
        def s3(cid, path, method, body=None):
            pid = json.loads(docker('inspect', cid))[0]['State']['Pid']
            args = ['nsenter', '--target', str(pid), '--net', 'curl', '--noproxy', '*', '--fail', '--silent', '--show-error', '--max-time', '10', '--aws-sigv4', 'aws:amz:us-east-1:s3',
                    '--user', 'fixture-admin:fixture-secret-password', '-X', method]
            if body:
                args += ['--data-binary', '@' + str(body), '-H', 'x-amz-content-sha256: ' + hashlib.sha256(body.read_bytes()).hexdigest()]
            return subprocess.check_output(args + ['http://127.0.0.1:9000' + path], stderr=subprocess.STDOUT, timeout=15)
        report['phase'] = 'MINIO_SEED'
        last_s3_error = None
        for _ in range(90):
            try:
                s3(mi, '/cold-backup', 'PUT')
                break
            except subprocess.CalledProcessError as error:
                last_s3_error = error.output[-512:].decode(errors='replace')
                time.sleep(1)
        else:
            print('Fixture-only S3 diagnosis:', last_s3_error, flush=True)
            print('Fixture-only MinIO logs:', docker('logs', '--tail', '15', mi)[-1500:], flush=True)
            raise AssertionError('MINIO_READY_TIMEOUT')
        object_file = root / 'object'
        object_file.write_bytes(b'complete-object-with-binary\x00\xff' * 4096)
        s3(mi, '/cold-backup/original', 'PUT', object_file)
        assert s3(mi, '/cold-backup/original', 'GET') == object_file.read_bytes()
        # Include a changed container layer; an image-only backup would miss it.
        docker('exec', mi, 'sh', '-c', 'printf retained-writable-layer > /cold-layer-fixture')
        report['phase'] = 'PLAN'
        print('Native phase: PLAN', flush=True)
        run_plan = b.Runner(root / 'plan', seconds=300)
        host = run_plan.inventory(set(containers))
        bindings = {role: {'containerId': cid, 'nativeImage': host[cid]['Image']} for role, cid in [('postgres', pg), ('minio', mi)]}
        plan = b.build_plan(bindings, host, root / 'capture', b.digest(Path(b.__file__).read_bytes()))
        plan_sha = b.digest(b.canonical(plan))
        pgdata = docker('exec', pg, 'psql', '-U', 'postgres', '-At', '-c', 'SHOW data_directory')
        docker('stop', '--time', '120', mi, timeout=130)
        ctl = subprocess.run(['docker', 'exec', '--user', 'postgres', pg, 'pg_ctl', '-D', pgdata, '-m', 'fast', '-w', '-t', '120', 'stop'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=130)
        # Container shutdown may terminate the auxiliary exec before it returns.
        # Reconcile the original server's exit; never replay pg_ctl on ambiguity.
        server_exit = docker('wait', pg, timeout=15)
        assert server_exit == '0', 'POSTGRES_SERVER_EXIT_NOT_CLEAN'
        report['pgCtlExecExitCode'] = ctl.returncode
        report['postgresServerExitCode'] = int(server_exit)
        control = docker('run', '--rm', '--network', 'none', '--user', 'postgres', '--entrypoint', 'pg_controldata',
                         '--mount', 'type=bind,src=' + str(root / 'pg') + ',dst=/var/lib/postgresql/data,readonly', PG, pgdata)
        assert 'Database cluster state:               shut down' in control, 'POSTGRES_CONTROL_NOT_SHUT_DOWN'
        report['postgresControlShutDown'] = True
        for cid in (mi, pg):
            state = json.loads(docker('inspect', cid))[0]['State']
            print('Fixture stop:', 'minio' if cid == mi else 'postgres', json.dumps({k: state[k] for k in ('ExitCode', 'OOMKilled', 'Running', 'Status')}), flush=True)
        identity = root / 'identity'
        cmd(['ssh-keygen', '-t', 'ed25519', '-N', '', '-f', str(identity)])
        public = b.recipient((root / 'identity.pub').read_bytes())
        run = b.Runner(root / 'capture', seconds=1800)
        report['phase'] = 'CAPTURE'
        print('Native phase: CAPTURE', flush=True)
        result = b.capture(plan, plan_sha, root / 'capture', run, public, 'CI-DISPOSABLE-NOT-TARGET-APPROVAL')
        assert result['providerMutationCommands'] == 0 and not result['applicationConsistencyProven']
        try:
            b.capture(plan, plan_sha, root / 'capture', run, public, 'CI-REPLAY')
            raise AssertionError('REPLAY_ACCEPTED')
        except FileExistsError:
            pass
        report['phase'] = 'DECRYPT_AND_RESTORE'
        print('Native phase: DECRYPT_AND_RESTORE', flush=True)
        decrypted = root / 'restored-bundle.tar'
        cmd(['age', '-d', '-i', str(identity), '-o', str(decrypted), result['archive']], timeout=300)
        assert b.hash_file(decrypted, time.monotonic() + 60) == b.hash_file(root / 'capture/backup.tar.partial', time.monotonic() + 60)
        restored = root / 'restored'
        restored.mkdir()
        cmd(['tar', '-xf', str(decrypted), '-C', str(restored)])
        manifest = json.loads((restored / 'manifest.private.json').read_text())
        for name, meta in manifest['members'].items():
            assert (restored / name).stat().st_size == meta['bytes']
            assert b.hash_file(restored / name, time.monotonic() + 60) == meta['sha256']
        # Original fixture containers stay stopped; restored data uses separate roots.
        data = root / 'restored-data'
        data.mkdir()
        for i, source in enumerate(plan['sources']):
            cmd(['tar', '--extract', '--numeric-owner', '--same-owner', '--acls', '--xattrs', '--xattrs-include=*',
                 '-f', str(restored / ('source-%03d.tar' % i)), '-C', str(data)])
        docker('image', 'load', '-i', str(restored / 'images.tar'), timeout=300)
        pg2 = docker('run', '-d', '--network', 'none', '--restart=no', '--mount',
                     'type=bind,src=' + str(data / 'pg') + ',dst=/var/lib/postgresql/data', bindings['postgres']['nativeImage'])
        containers.append(pg2)
        mi2 = docker('run', '-d', '--user', '0:0', '--entrypoint', '/usr/bin/minio', '--stop-signal', 'SIGTERM', '--network', 'none', '--restart=no', '--mount',
                     'type=bind,src=' + str(data / 'minio') + ',dst=/data', '-e', 'MINIO_ROOT_USER=fixture-admin',
                     '-e', 'MINIO_ROOT_PASSWORD=fixture-secret-password', bindings['minio']['nativeImage'], 'server', '/data')
        containers.append(mi2)
        for _ in range(90):
            try:
                docker('exec', pg2, 'pg_isready', '-U', 'postgres')
                assert s3(mi2, '/cold-backup/original', 'GET') == object_file.read_bytes()
                break
            except (subprocess.CalledProcessError, AssertionError):
                time.sleep(1)
        else:
            raise AssertionError('RESTORED_PROVIDER_READY_TIMEOUT')
        for db in ('onboarding', 'udp', 'ingestion'):
            assert docker('exec', pg2, 'psql', '-U', 'postgres', '-d', db, '-At', '-c', 'SELECT payload FROM recovery_fixture WHERE id=1') == 'profile/sample/object/lineage'
        layer = subprocess.check_output(['tar', '-xOf', str(restored / 'minio.rootfs.tar'), 'cold-layer-fixture'], timeout=30)
        assert layer == b'retained-writable-layer'
        assert all(json.loads(docker('inspect', cid))[0]['State']['Running'] is False for cid in (pg, mi))
        report.update(status='PASS', fixtureDatabasesRestored=3, fixtureObjectsRestored=1,
                      fixtureObjectBytes=object_file.stat().st_size, sshRecipientRoundTrip=True,
                      sourceArchiveBytesVerified=True, independentDataRoots=True, writableContainerLayerRetained=True,
                      replayDenied=True, sourceContainersRemainStopped=True, postgresShutdown='pg_ctl-fast', targetG3Complete=False,
                      fullFourteenRoleTargetQualified=False, archiveBytes=result['archiveBytes'])
    except BaseException as error:
        report['errorClass'] = type(error).__name__
        if isinstance(error, b.Held):
            report['reason'] = str(error)
            if 'run' in locals():
                err = run.area / ('command-%03d.stderr.private' % run.calls)
                if err.exists():
                    print('Synthetic fixture command diagnosis:', err.read_text(errors='replace')[-1500:], flush=True)
        raise
    finally:
        # Disposable CI-only fixture teardown, not part of the target utility.
        for cid in reversed(containers):
            subprocess.run(['docker', 'rm', '-f', cid], stdout=subprocess.DEVNULL, timeout=60)
        if network:
            subprocess.run(['docker', 'network', 'rm', network], stdout=subprocess.DEVNULL, timeout=30)
        out = Path(sys.argv[1])
        out.mkdir(parents=True, exist_ok=True)
        (out / 'native-result.json').write_bytes(b.canonical(report))
        out.chmod(0o755)
        (out / 'native-result.json').chmod(0o644)
        # No fixture data, key, environment, raw command logs or archive uploaded.
        print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
