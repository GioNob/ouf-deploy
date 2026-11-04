#!/usr/bin/env python3
"""Disposable OCI33/PG17 fixture: quiesced common cut, S3 deny, independent restore.

A stopped gateway and read-only replacement fence the fixture's sole S3 identity.
This is not a target-writer fence, live atomic snapshot, PITR or RPO/RTO proof.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
import signal
from pathlib import Path
import subprocess
import sys
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'tests')]
import run_storage_postgres_writer_fence as fence
import run_storage_postgres_logical_restore as postgres


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


labs = load('coordinated33_labs', ROOT / 'scripts/run-seaweedfs-452-generation33-labs.py')
LOCK_SHA = 'c2b30130b078a86ca440351980c3e745d4132e256591ec05fe98a9bdfc9058f8'
COHORT_SHA = '5b28de1dd43fca337064d41439d302d53dc7f470640fe3fc0d8d1292b1ec02dc'
COHORT_ARTIFACT_ID = 13305200887
COHORT_ARCHIVE_SHA = '5a8a59be0d0ee6230322e4828cc1edef5ca1e24689dc2ff7f19ede830203430e'
COHORT_ARCHIVE_BYTES = 127980
BODIES = {'lab-acked': b'acknowledged before common cut\x00\xff',
          'lab-ambiguous': b'effect durable, publication response absent\x00\xff'}
MIME = 'application/octet-stream'
NS = {'s': 'http://s3.amazonaws.com/doc/2006-03-01/'}
LEDGER_SQL = """SELECT json_build_object(
 'control',(SELECT row_to_json(c) FROM ouf_fence_lab.control c),
 'intents',(SELECT json_agg(i ORDER BY operation) FROM ouf_fence_lab.intents i),
 'events',(SELECT json_agg(e ORDER BY sequence) FROM ouf_fence_lab.events e));"""
LIMITS = {name: False for name in (
    'targetWriterFenceQualified', 'liveAtomicSnapshotQualified', 'pitrQualified',
    'rpoMeasured', 'rtoMeasured', 'releaseAdmitted', 'runtimeAuthorityIssued',
    'productionCodeChanged', 'completeProductionBackupClaimed', 'lateralIsolationQualified')}
LIMITS.update(targetOperations=0, gatesClosed=0, acceptanceTestsPassed=0)
require = fence.require


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def binding(receipt):
    return labs.preflight(LOCK_SHA, COHORT_SHA, cohort_path=receipt)


def configuration(cold, writable):
    return {'identities': [{'name': cold.ACCESS,
        'credentials': [{'accessKey': cold.ACCESS, 'secretKey': cold.SECRET}],
        'actions': ['Admin', 'Read', 'Write', 'List'] if writable else ['Read', 'List']}]}


def validate_ledger(ledger):
    require(ledger.get('control') == {'singleton': True, 'epoch': 2, 'version': 2, 'phase': 'FROZEN'},
            'EXACT_FROZEN_CONTROL_REQUIRED')
    expected = [{'operation': op, 'epoch': 1, 'body_hash': sha(body), 'body_bytes': len(body),
                 'state': 'ACKED' if op == 'lab-acked' else 'RECONCILED'}
                for op, body in sorted(BODIES.items())]
    require(ledger.get('intents') == expected, 'EXACT_TERMINAL_INTENTS_REQUIRED')
    events = [('RESERVED', 'lab-acked', 1, 0), ('ACKED', 'lab-acked', 1, 0),
              ('RESERVED', 'lab-ambiguous', 1, 0), ('DRAINING', None, 2, 1),
              ('RECONCILED', 'lab-ambiguous', 2, 1), ('FROZEN', None, 2, 2)]
    require(ledger.get('events') == [dict(sequence=n, kind=k, operation=o, epoch=e, version=v)
            for n, (k, o, e, v) in enumerate(events, 1)], 'EXACT_ACK_AND_FENCE_HISTORY_REQUIRED')
    return expected


def read_objects(request):
    raw, _ = request('GET', '', query={'list-type': '2', 'max-keys': '3'}, timeout=10)
    require(len(raw) <= 16384, 'BOUNDED_LIST_REQUIRED')
    listing = ET.fromstring(raw)
    require(listing.tag == '{' + NS['s'] + '}ListBucketResult'
            and listing.findtext('s:IsTruncated', namespaces=NS) == 'false'
            and listing.find('s:NextContinuationToken', NS) is None,
            'COMPLETE_LIST_REQUIRED')
    keys = [item.text for item in listing.findall('s:Contents/s:Key', NS)]
    require(sorted(keys) == sorted(BODIES), 'EXACT_OBJECT_SET_REQUIRED')
    result = {}
    for op, expected in sorted(BODIES.items()):
        body, headers = request('GET', op, timeout=10)
        _, head = request('HEAD', op, timeout=10)
        require(body == expected, 'EXACT_BODY_REQUIRED')
        for values in (headers, head):
            require(values.get('content-length') == str(len(expected))
                    and values.get('content-type') == MIME
                    and values.get('x-amz-meta-ouf-content-hash') == sha(body)
                    and values.get('x-amz-meta-ouf-recovery-generation') == 'fixture33-epoch1',
                    'GET_HEAD_METADATA_REQUIRED')
        result[op] = {'sha256': sha(body), 'bytes': len(body), 'mime': MIME}
    return result


def denied_mutations(request):
    results = []
    for method, key, body in [('PUT', 'lab-late', b'late'),
                              ('PUT', 'lab-acked', b'overwrite'),
                              ('DELETE', 'lab-acked', b'')]:
        raw, _ = request(method, key, body, expected=(403,), timeout=10)
        require(len(raw) <= 16384 and ET.fromstring(raw).findtext('Code') == 'AccessDenied',
                'EXPLICIT_ACCESS_DENIED_REQUIRED')
        results.append({'method': method, 'key': key, 'status': 403, 'code': 'AccessDenied'})
    return results


def client(action):
    cold = load('coordinated33_client', ROOT / 'scripts/run-seaweedfs-452-cold-recovery.py')
    routes = json.loads(cold.command(['ip', '-j', 'route', 'show', 'table', 'all'], timeout=5))
    require(all(r.get('dev') == 'lo' for r in routes), 'LOOPBACK_NAMESPACE_REQUIRED')
    if action == 'bucket':
        cold.request('PUT', '', timeout=10)
        return {'created': True}
    if action in BODIES:
        body = BODIES[action]
        cold.request('PUT', action, body, timeout=10, extra={
            'content-type': MIME, 'x-amz-meta-ouf-content-hash': sha(body),
            'x-amz-meta-ouf-recovery-generation': 'fixture33-epoch1'})
        return {'operation': action, 'sha256': sha(body), 'bytes': len(body)}
    require(action == 'verify-frozen', 'KNOWN_ACTION_REQUIRED')
    before = read_objects(cold.request)
    denied = denied_mutations(cold.request)
    after = read_objects(cold.request)
    require(before == after, 'DENIED_MUTATIONS_MUST_NOT_CHANGE_OBJECTS')
    return {'objects': after, 'denied': denied, 'mutatingRetries': 0}


def worker_marker():
    body = BODIES['lab-ambiguous']
    return {'operation': 'lab-ambiguous', 'phase': 'AFTER_PUT_200_BEFORE_CATALOG_ACK',
            'sha256': sha(body), 'bytes': len(body), 'putRequests': 1}


def validate_crash(result, marker):
    require(result.returncode == -signal.SIGKILL, 'EXACT_WORKER_SIGKILL_REQUIRED')
    require(result.stdout == result.stderr == b'', 'CRASH_WORKER_OUTPUT_MUST_BE_EMPTY')
    require(not marker.is_symlink() and marker.is_file() and marker.stat().st_size <= 4096,
            'BOUNDED_DURABLE_CRASH_MARKER_REQUIRED')
    require(json.loads(marker.read_bytes()) == worker_marker(), 'EXACT_POST_PUT_CRASH_PHASE_REQUIRED')
    return {'workerReturnCode': result.returncode, 'workerSignal': 'SIGKILL',
            'markerSha256': postgres.native.digest(marker), **worker_marker()}


def crash_client(marker):
    require(not marker.exists() and not marker.is_symlink(), 'FRESH_CRASH_MARKER_REQUIRED')
    # A distinct OS worker performs one PUT and dies before any catalog finish.
    # native.run bounds output/time and kills the process group on timeout;
    # a supervisor timeout is never treated as the expected injected SIGKILL.
    result = postgres.native.run([sys.executable, '-I', '-B', '-S',
        str(Path(__file__).resolve()), 'worker-after-put', str(marker)], timeout=30)
    return validate_crash(result, marker)


def verify_restart_pending(calls, lab, proof):
    before = json.loads(calls.raw(LEDGER_SQL))
    require(before['control'] == {'singleton': True, 'epoch': 1, 'version': 0, 'phase': 'ACTIVE'},
            'PRE_DRAIN_CONTROL_REQUIRED')
    require([(i['operation'], i['state']) for i in before['intents']] ==
            [('lab-acked', 'ACKED'), ('lab-ambiguous', 'PENDING')], 'CRASH_MUST_LEAVE_PENDING_INTENT')
    write(proof / 'crash-ledger-before-restart.json', before)
    result = postgres.native.run([str(lab.binary('pg_ctl')), '-D', str(lab.data),
        '-m', 'immediate', '-l', str(lab.output / 'postgres.log'), '-w', '-t', '20', 'restart'], timeout=25)
    (proof / 'crash-postgres-restart.stdout').write_bytes(result.stdout)
    (proof / 'crash-postgres-restart.stderr').write_bytes(result.stderr)
    require(result.returncode == 0, 'POSTGRES_IMMEDIATE_RESTART_FAILED')
    after = json.loads(calls.raw(LEDGER_SQL))
    write(proof / 'crash-ledger-after-restart.json', after)
    require(after == before, 'RESTART_MUST_PRESERVE_ACK_PENDING_AND_HISTORY')
    body = BODIES['lab-ambiguous']
    decision = calls.call('reserve', 'lab-ambiguous', 1, sha(body), len(body), user=fence.WRITER)
    require(decision == 'EXISTING_PENDING', 'RETRY_MUST_NOT_GRANT_ANOTHER_PUT')
    require(json.loads(calls.raw(LEDGER_SQL)) == before, 'RETRY_MUST_NOT_CHANGE_DURABLE_INTENT')
    return {'postgresImmediateRestart': True, 'ledgerSurvivedRestart': True,
            'retryDecision': decision, 'recoveryPutRequests': 0,
            'ledgerBeforeRestartSha256': postgres.native.digest(proof / 'crash-ledger-before-restart.json'),
            'ledgerAfterRestartSha256': postgres.native.digest(proof / 'crash-ledger-after-restart.json')}


def remote(cold, lab, action, proof, marker=None):
    argv = ['sudo', '-n', 'nsenter', '-t', lab.pid, '-n', sys.executable,
            '-I', '-B', '-S', str(Path(__file__).resolve()), 'client', action]
    if marker is not None:
        argv.extend(['--marker', str(marker)])
    try:
        value = json.loads(cold.command(argv, timeout=90))
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        (proof / (lab.prefix + '-' + action + '-stderr.log')).write_text(
            cold.bounded_diagnostic(error.stderr, 'COORDINATED_CHILD_FAILED'))
        raise
    write(proof / (lab.prefix + '-' + action + '.json'), value)
    return value


def compare_readback(ledger, readback):
    intents = validate_ledger(ledger)
    require(readback['objects'] == {i['operation']: {'sha256': i['body_hash'],
            'bytes': i['body_bytes'], 'mime': MIME} for i in intents}, 'CATALOG_S3_MISMATCH')


def ledger_snapshot(calls, proof, name):
    ledger = json.loads(calls.raw(LEDGER_SQL))
    validate_ledger(ledger)
    write(proof / (name + '-ledger.json'), ledger)
    return ledger


def run(archive, pg_bin, work, receipt, *, crash_after_put=False):
    bound = binding(receipt)
    cold = labs.configured_harness('cold', bound)
    proof = work / 'evidence'
    proof.mkdir(parents=True, mode=0o700)
    image = work / 'image'; image.mkdir()
    source_pg = postgres.native.NativeLab(pg_bin, proof / 'postgres-source')
    dest_pg = postgres.native.NativeLab(pg_bin, proof / 'postgres-restored')
    containers = []
    report = {**LIMITS, 'status': 'SYNTHETIC_COMMON_CUT_BLOCKED'}
    failed = None
    crash_evidence = {}
    try:
        write(proof / 'exact-image.json', cold.prepare_image(archive, image))
        original = work / 'original'
        for role in ('master', 'filer', 'volume', 's3', 'config'):
            (original / role).mkdir(parents=True)
        write(original / 'config/s3.json', configuration(cold, True))
        cold.command(['sudo', '-n', 'chown', '-R', '65532:65532', str(original)])
        prefix = 'ouf-cut33-' + str(os.getpid())
        source = cold.Lab(prefix + '-source', original, proof); containers.append(source)
        source_pg.start(initialize_catalog=False)
        source_pg.sql((ROOT / 'tests/fixtures/storage-recovery/writer-fence.sql').read_text())
        calls = fence.Calls(source_pg)
        source.start()
        remote(cold, source, 'bucket', proof)
        for op, body in BODIES.items():
            require(calls.call('reserve', op, 1, sha(body), len(body), user=fence.WRITER) == 'RESERVED',
                    'DURABLE_INTENT_BEFORE_S3_REQUIRED')
            if crash_after_put and op == 'lab-ambiguous':
                crash_evidence = remote(cold, source, 'crash-put', proof, proof / 'crash-worker-marker.json')
                crash_evidence.update(verify_restart_pending(calls, source_pg, proof))
            else:
                remote(cold, source, op, proof)
            if op == 'lab-acked':
                require(calls.call('finish', op, 1, sha(body), len(body), user=fence.WRITER) == 'ACKED',
                        'ACK_AFTER_S3_REQUIRED')
        require(calls.call('begin_drain', 1, 0) == 'DRAINING', 'DRAIN_REQUIRED')
        ambiguous = BODIES['lab-ambiguous']
        require(calls.call('finish', 'lab-ambiguous', 1, sha(ambiguous), len(ambiguous),
                          user=fence.WRITER) == 'FENCED', 'LATE_PUBLICATION_MUST_BE_FENCED')
        require(calls.call('reserve', 'lab-late', 1, sha(b'late'), 4, user=fence.WRITER) == 'FENCED',
                'LATE_RESERVATION_MUST_BE_FENCED')
        require(calls.call('finish_drain', 1) == 'RECONCILE_REQUIRED', 'AMBIGUITY_MUST_BLOCK_CUT')
        # Stop every old process before replacing the sole S3 identity's permissions.
        # No claim of a zero-downtime or production-wide online fence is made.
        source.stop()
        cold.command(['sudo', '-n', 'chown', '-R', f'{os.getuid()}:{os.getgid()}', str(original)])
        write(original / 'config/s3.json', configuration(cold, False))
        readonly_sha = postgres.native.digest(original / 'config/s3.json')
        cold.command(['sudo', '-n', 'chown', '-R', '65532:65532', str(original)])
        frozen = cold.Lab(prefix + '-fenced', original, proof); containers.append(frozen)
        frozen.start()
        observed = remote(cold, frozen, 'verify-frozen', proof)
        identity = observed['objects']['lab-ambiguous']
        require(calls.call('reconcile', 'lab-ambiguous', 1, identity['sha256'], identity['bytes']) == 'RECONCILED',
                'RECONCILE_REAL_S3_BEFORE_FREEZE_REQUIRED')
        require(calls.call('finish_drain', 1) == 'FROZEN', 'COMMON_FROZEN_CUT_REQUIRED')
        ledger = ledger_snapshot(calls, proof, 'source')
        compare_readback(ledger, observed)
        frozen.stop()
        # The quiesced interval spans both the PostgreSQL dump and the cold S3 copy.
        for tool in ('pg_dump', 'pg_restore'):
            version = postgres.checked_command(proof, tool + '-version', [str(source_pg.binary(tool)), '--version'])
            require(version.decode().strip().endswith(' ' + postgres.native.VERSION), 'EXACT_PG_TOOLS_REQUIRED')
        dump = proof / 'catalog.dump'
        postgres.checked_command(proof, 'pg-dump', [str(source_pg.binary('pg_dump')),
            *postgres.connection(source_pg), '--format=custom', '--no-owner', '--no-acl',
            '--schema=ouf_fence_lab', '--file=' + str(dump)])
        dump_sha = postgres.archive_digest(dump)
        require(json.loads(calls.raw(LEDGER_SQL)) == ledger, 'CATALOG_CHANGED_DURING_CUT')
        source_id = postgres.system_identifier(source_pg)
        source_pg.stop()
        cold.command(['sudo', '-n', 'chown', '-R', f'{os.getuid()}:{os.getgid()}', str(original)])
        inventory = cold.cold_copy(original, work / 'backup')
        require(inventory['config/s3.json']['sha256'] == readonly_sha, 'READ_ONLY_BACKUP_REQUIRED')
        original.rename(work / 'withheld-original')
        restored_root = work / 'restored'
        require(cold.cold_copy(work / 'backup', restored_root) == inventory, 'EXACT_COLD_COPY_REQUIRED')
        write(proof / 'cold-backup-inventory.json', inventory)
        write(proof / 'common-cut.json', {
            'schema': 'ouf.synthetic-quiesced-cut33.v1', 'lockSha256': LOCK_SHA,
            'cohortReceiptSha256': COHORT_SHA, 'epoch': 2, 'version': 2,
            'sourceSystemIdentifier': source_id, 'postgresDumpSha256': dump_sha,
            'ledgerSha256': postgres.native.digest(proof / 'source-ledger.json'),
            'coldIndexSha256': postgres.native.digest(proof / 'cold-backup-inventory.json'),
            'readOnlyConfigSha256': readonly_sha, 'sourcePostgresStopped': True,
            'sourceStorageStoppedAndWithheld': True, 'scope': 'two synthetic fixture intents only'})
        dest_pg.start(initialize_catalog=False)
        dest_id = postgres.system_identifier(dest_pg)
        require(dest_id != source_id and dest_pg.sql("SELECT to_regnamespace('ouf_fence_lab') IS NULL;").stdout.strip() == b't',
                'INDEPENDENT_EMPTY_DESTINATION_REQUIRED')
        postgres.restore_archive(dest_pg, dump, dump_sha, proof)
        restored_calls = fence.Calls(dest_pg)
        restored_ledger = ledger_snapshot(restored_calls, proof, 'restored')
        require(restored_ledger == ledger, 'DUMP_RESTORE_MUST_PRESERVE_ACKS_AND_FENCE')
        # Schema-only fixture dump intentionally has no cluster roles/ACL. Install
        # only the fixture writer grants before proving the restored fence denies it.
        dest_pg.sql("CREATE ROLE ouf_fence_writer LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION; "
            "REVOKE ALL ON DATABASE ouf_recovery_fixture FROM PUBLIC; "
            "GRANT CONNECT ON DATABASE ouf_recovery_fixture TO ouf_fence_writer; "
            "REVOKE ALL ON SCHEMA ouf_fence_lab FROM PUBLIC; "
            "REVOKE ALL ON ALL TABLES IN SCHEMA ouf_fence_lab FROM PUBLIC; "
            "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ouf_fence_lab FROM PUBLIC; "
            "GRANT USAGE ON SCHEMA ouf_fence_lab TO ouf_fence_writer; "
            "GRANT EXECUTE ON FUNCTION ouf_fence_lab.reserve(text,bigint,text,bigint), "
            "ouf_fence_lab.finish(text,bigint,text,bigint) TO ouf_fence_writer;")
        require(restored_calls.call('reserve', 'lab-late', 2, sha(b'late'), 4,
                user=fence.WRITER) == 'FENCED', 'RESTORED_DB_MUST_REMAIN_FROZEN')
        cold.command(['sudo', '-n', 'chown', '-R', '65532:65532', str(restored_root)])
        restored = cold.Lab(prefix + '-restored', restored_root, proof); containers.append(restored)
        restored.start()
        reread = remote(cold, restored, 'verify-frozen', proof)
        compare_readback(restored_ledger, reread)
        require(reread == observed, 'RESTORED_OBJECTS_AND_DENIALS_MUST_MATCH')
        restored.stop()
        dest_pg.stop()
        report = {**LIMITS, 'status': 'SYNTHETIC_QUIESCED_COMMON_CUT33_PASS',
            'schema': 'ouf.storage-coordinated-fixture33.v1', 'lockSha256': LOCK_SHA,
            'cohortReceiptSha256': COHORT_SHA, 'ociManifestDigest': bound['lock']['image']['manifestDigest'],
            'postgresVersion': postgres.native.VERSION, 'postgresDumpSha256': dump_sha,
            'sourceSystemIdentifier': source_id, 'restoredSystemIdentifier': dest_id,
            'fixtureCommonCutQualified': True, 'fixtureS3ReadOnlyFenceQualified': True,
            'pendingIntentBlockedFreeze': True, 'latePublicationRejected': True,
            'allOriginalAcknowledgementsPreserved': True, 'ambiguousEffectReconciledWithoutResend': True,
            'independentColdRoots': True, 's3ObjectsReconciled': len(BODIES),
            's3ObjectBytesReadPerPass': sum(len(b) for b in BODIES.values()),
            's3DeniedMutations': len(observed['denied']) + len(reread['denied']),
            'coldBackupFiles': len(inventory), 'coldBackupBytes': sum(x['bytes'] for x in inventory.values()),
            'commonCutSha256': postgres.native.digest(proof / 'common-cut.json'),
            'cleanContainerStops': 12, 'cleanPostgresStops': 2, 'mutatingRetries': 0,
            'workerCrashInjected': crash_after_put, 'crashEvidence': crash_evidence,
            'scope': 'sole synthetic S3 identity; full stop then Read/List replacement; logical PG dump'}
    except Exception as error:
        failed = error
        report['failure'] = type(error).__name__ + ': ' + str(error)[:512]
    finally:
        cleanup_errors = []
        for lab in reversed(containers):
            if lab.names:
                try:
                    lab.stop()
                except Exception as error:
                    cleanup_errors.append(str(error)[:256])
        for lab in (dest_pg, source_pg):
            try:
                lab.stop()
            except Exception as error:
                cleanup_errors.append(str(error)[:256])
        if cleanup_errors:
            report.update(status='SYNTHETIC_COMMON_CUT_BLOCKED', cleanupFailures=cleanup_errors)
            failed = failed or RuntimeError('CLEANUP_FAILED')
        write(proof / 'receipt.json', report)
    if failed:
        raise failed
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    child = sub.add_parser('client'); child.add_argument('action', choices=['bucket', *BODIES, 'verify-frozen', 'crash-put'])
    child.add_argument('--marker', type=Path)
    worker = sub.add_parser('worker-after-put'); worker.add_argument('marker', type=Path)
    runner = sub.add_parser('run')
    for name in ('image', 'pg-bin', 'work', 'cohort-receipt'):
        runner.add_argument('--' + name, required=True, type=Path)
    runner.add_argument('--crash-after-put', action='store_true')
    args = parser.parse_args()
    if args.command == 'worker-after-put':
        client('lab-ambiguous')
        fence.persist_body(args.marker, json.dumps(worker_marker(), sort_keys=True).encode())
        os.kill(os.getpid(), signal.SIGKILL)
        raise RuntimeError('WORKER_SURVIVED_SIGKILL')
    if args.command == 'client':
        if args.action == 'crash-put':
            require(args.marker is not None, 'CRASH_MARKER_REQUIRED')
            print(json.dumps(crash_client(args.marker)))
        else:
            require(args.marker is None, 'UNEXPECTED_MARKER')
            print(json.dumps(client(args.action)))
        return
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.geteuid() != 0, 'UNPRIVILEGED_ISOLATED_CI_REQUIRED')
    require(not args.work.exists() and not args.work.is_symlink(), 'FRESH_WORK_REQUIRED')
    print(json.dumps(run(args.image.resolve(), args.pg_bin.resolve(), args.work.absolute(), args.cohort_receipt.resolve(),
                         crash_after_put=args.crash_after_put)))


if __name__ == '__main__':
    main()
