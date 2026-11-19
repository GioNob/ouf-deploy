#!/usr/bin/env python3
"""Negative reconciliation on disposable OCI33/PG17: absence/corruption blocks cut.

Constructs unresolved fixture states; does not inject another HTTP response loss.
No restore or common-cut artifact is allowed for a still-PENDING intent.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('unresolved_common', ROOT / 'scripts/run-storage-coordinated33-lab.py')
cut = importlib.util.module_from_spec(spec); spec.loader.exec_module(cut)
require, sha, write = cut.require, cut.sha, cut.write
FAULTS = ('missing', 'corrupt')
BODY = cut.BODIES['lab-ambiguous']
CORRUPT = bytes([BODY[0] ^ 1]) + BODY[1:]


def rejected_readback(request, fault):
    require(fault in FAULTS, 'KNOWN_NEGATIVE_CASE_REQUIRED')
    expected = 'EXACT_OBJECT_SET_REQUIRED' if fault == 'missing' else 'EXACT_BODY_REQUIRED'
    try:
        cut.read_objects(request)
    except RuntimeError as error:
        # Transport, permission, incomplete-list or metadata errors cannot masquerade
        # as the intentionally constructed negative result.
        require(str(error) == expected, 'EXPECTED_RECONCILIATION_REJECTION_REQUIRED')
    else:
        raise RuntimeError('INVALID_OBJECT_MUST_NOT_RECONCILE')
    return expected


def observe(request, fault):
    reason = rejected_readback(request, fault)
    listing, _ = request('GET', '', query={'list-type': '2', 'max-keys': '3'}, timeout=10)
    require(len(listing) <= 16384, 'BOUNDED_LIST_REQUIRED')
    tree = ET.fromstring(listing)
    require(tree.tag == '{' + cut.NS['s'] + '}ListBucketResult'
            and tree.findtext('s:IsTruncated', namespaces=cut.NS) == 'false'
            and tree.find('s:NextContinuationToken', cut.NS) is None, 'COMPLETE_LIST_REQUIRED')
    keys = sorted(node.text for node in tree.findall('s:Contents/s:Key', cut.NS))
    require(keys == (['lab-acked'] if fault == 'missing' else sorted(cut.BODIES)),
            'EXACT_NEGATIVE_OBJECT_SET_REQUIRED')
    ack, headers = request('GET', 'lab-acked', timeout=10)
    _, head = request('HEAD', 'lab-acked', timeout=10)
    require(ack == cut.BODIES['lab-acked'], 'ORIGINAL_ACK_BODY_REQUIRED')
    for values in (headers, head):
        require(values.get('content-length') == str(len(ack))
                and values.get('content-type') == cut.MIME
                and values.get('x-amz-meta-ouf-content-hash') == sha(ack)
                and values.get('x-amz-meta-ouf-recovery-generation') == 'fixture33-epoch1',
                'ORIGINAL_ACK_METADATA_REQUIRED')
    if fault == 'missing':
        raw, _ = request('GET', 'lab-ambiguous', expected=(404,), timeout=10)
        require(len(raw) <= 16384 and ET.fromstring(raw).findtext('Code') == 'NoSuchKey',
                'EXPLICIT_NO_SUCH_KEY_REQUIRED')
        raw_head, _ = request('HEAD', 'lab-ambiguous', expected=(404,), timeout=10)
        require(raw_head == b'', 'EMPTY_HEAD_RESPONSE_REQUIRED')
        invalid = {'getStatus': 404, 'headStatus': 404, 'code': 'NoSuchKey', 'present': False}
    else:
        raw, metadata = request('GET', 'lab-ambiguous', timeout=10)
        _, head = request('HEAD', 'lab-ambiguous', timeout=10)
        require(raw == CORRUPT and len(raw) == len(BODY) and sha(raw) != sha(BODY),
                'EXACT_SAME_LENGTH_CORRUPTION_REQUIRED')
        for values in (metadata, head):
            require(values.get('content-length') == str(len(BODY))
                    and values.get('content-type') == cut.MIME
                    and values.get('x-amz-meta-ouf-content-hash') == sha(BODY)
                    and values.get('x-amz-meta-ouf-recovery-generation') == 'fixture33-epoch1',
                    'MISLEADING_METADATA_FIXTURE_REQUIRED')
        invalid = {'getStatus': 200, 'headStatus': 200, 'present': True,
                   'actualSha256': sha(raw), 'claimedSha256': sha(BODY), 'bytes': len(raw)}
    return {'fault': fault, 'rejection': reason, 'listedKeys': keys, 'invalidObject': invalid,
            'originalAck': {'sha256': sha(ack), 'bytes': len(ack), 'mime': cut.MIME}}


def client(action, fault):
    cold = cut.load('unresolved_client', ROOT / 'scripts/run-seaweedfs-452-cold-recovery.py')
    routes = json.loads(cold.command(['ip', '-j', 'route', 'show', 'table', 'all'], timeout=5))
    require(all(r.get('dev') == 'lo' for r in routes), 'LOOPBACK_NAMESPACE_REQUIRED')
    if action == 'seed-corrupt':
        require(fault == 'corrupt', 'CORRUPT_CASE_REQUIRED')
        cold.request('PUT', 'lab-ambiguous', CORRUPT, timeout=10, extra={
            'content-type': cut.MIME, 'x-amz-meta-ouf-content-hash': sha(BODY),
            'x-amz-meta-ouf-recovery-generation': 'fixture33-epoch1'})
        return {'fixturePutRequests': 1, 'bytes': len(CORRUPT), 'actualSha256': sha(CORRUPT)}
    require(action == 'observe', 'KNOWN_ACTION_REQUIRED')
    before = observe(cold.request, fault)
    denied = cut.denied_mutations(cold.request)
    after = observe(cold.request, fault)
    require(before == after, 'DENIED_MUTATIONS_MUST_PRESERVE_NEGATIVE_STATE')
    return {**after, 'denied': denied, 'recoveryPutRequests': 0}


def remote(cold, lab, action, fault, proof, stage):
    argv = ['sudo', '-n', 'nsenter', '-t', lab.pid, '-n', sys.executable,
            '-I', '-B', '-S', str(Path(__file__).resolve()), 'client', action, '--fault', fault]
    try:
        result = json.loads(cold.command(argv, timeout=90))
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        (proof / (stage + '-stderr.log')).write_text(cold.bounded_diagnostic(error.stderr, 'NEGATIVE_CHILD_FAILED'))
        raise
    write(proof / (stage + '.json'), result)
    return result


def validate_pending(ledger):
    require(ledger['control'] == {'singleton': True, 'epoch': 2, 'version': 1, 'phase': 'DRAINING'},
            'UNRESOLVED_CONTROL_MUST_REMAIN_DRAINING')
    expected = [{'operation': op, 'epoch': 1, 'body_hash': sha(body), 'body_bytes': len(body),
                 'state': 'ACKED' if op == 'lab-acked' else 'PENDING'}
                for op, body in sorted(cut.BODIES.items())]
    require(ledger['intents'] == expected, 'ACK_AND_PENDING_MUST_REMAIN_IDENTICAL')
    events = [('RESERVED', 'lab-acked', 1, 0), ('ACKED', 'lab-acked', 1, 0),
              ('RESERVED', 'lab-ambiguous', 1, 0), ('DRAINING', None, 2, 1)]
    actual = ledger['events']
    require(len(actual) == 4, 'NO_TERMINAL_OR_EXTRA_EVENT_ALLOWED')
    ids = [row['sequence'] for row in actual]
    require(all(type(n) is int and 0 < n < 2**63 for n in ids)
            and all(a < b for a, b in zip(ids, ids[1:])), 'STRICT_EVENT_ORDER_REQUIRED')
    require(actual == [dict(sequence=n, kind=k, operation=o, epoch=e, version=v)
                       for n, (k, o, e, v) in zip(ids, events)], 'EXACT_PENDING_HISTORY_REQUIRED')


def assert_blocked(calls, observation, proof, stage):
    before = json.loads(calls.raw(cut.LEDGER_SQL)); validate_pending(before)
    fault = observation['fault']
    require(fault in FAULTS and observation['rejection'] ==
            ('EXACT_OBJECT_SET_REQUIRED' if fault == 'missing' else 'EXACT_BODY_REQUIRED'),
            'VERIFIED_NEGATIVE_READBACK_REQUIRED')
    if fault == 'corrupt':
        actual = observation['invalidObject']
        require(actual['actualSha256'] == sha(CORRUPT) and actual['bytes'] == len(CORRUPT),
                'ACTUAL_CORRUPT_IDENTITY_REQUIRED')
        require(calls.call('reconcile', 'lab-ambiguous', 1, actual['actualSha256'], actual['bytes']) == 'CONFLICT',
                'CORRUPT_BODY_MUST_NOT_RESOLVE_INTENT')
    # No identity exists for a missing object: never synthesize one from metadata.
    require(calls.call('reserve', 'lab-ambiguous', 1, sha(BODY), len(BODY), user=cut.fence.WRITER)
            == 'EXISTING_PENDING', 'RETRY_MUST_NOT_GRANT_ANOTHER_PUT')
    require(calls.call('finish', 'lab-ambiguous', 1, sha(BODY), len(BODY), user=cut.fence.WRITER)
            == 'FENCED', 'LATE_ACK_MUST_REMAIN_FENCED')
    require(calls.call('finish_drain', 1) == 'RECONCILE_REQUIRED', 'UNRESOLVED_FREEZE_MUST_BE_BLOCKED')
    after = json.loads(calls.raw(cut.LEDGER_SQL)); validate_pending(after)
    require(after == before, 'NEGATIVE_ATTEMPTS_MUST_NOT_CHANGE_LEDGER')
    write(proof / (stage + '-ledger.json'), after)
    return after


def run(archive, pg_bin, work, receipt, fault):
    require(fault in FAULTS, 'KNOWN_NEGATIVE_CASE_REQUIRED')
    bound = cut.binding(receipt); cold = cut.labs.configured_harness('cold', bound)
    proof = work / 'evidence'; proof.mkdir(parents=True, mode=0o700)
    image = work / 'image'; image.mkdir()
    pg = cut.postgres.native.NativeLab(pg_bin, proof / 'postgres')
    containers = []; failure = None
    report = {**cut.LIMITS, 'status': 'SYNTHETIC_UNRESOLVED33_TEST_FAILED', 'fault': fault}
    try:
        write(proof / 'exact-image.json', cold.prepare_image(archive, image))
        original = work / 'original'
        for role in ('master', 'filer', 'volume', 's3', 'config'):
            (original / role).mkdir(parents=True)
        write(original / 'config/s3.json', cut.configuration(cold, True))
        cold.command(['sudo', '-n', 'chown', '-R', '65532:65532', str(original)])
        prefix = 'ouf-unresolved33-' + str(os.getpid())
        source = cold.Lab(prefix + '-source', original, proof); containers.append(source)
        pg.start(initialize_catalog=False)
        pg.sql((ROOT / 'tests/fixtures/storage-recovery/writer-fence.sql').read_text())
        calls = cut.fence.Calls(pg)
        source.start(); cut.remote(cold, source, 'bucket', proof)
        for op, body in cut.BODIES.items():
            require(calls.call('reserve', op, 1, sha(body), len(body), user=cut.fence.WRITER) == 'RESERVED',
                    'DURABLE_INTENT_BEFORE_IO_REQUIRED')
            if op == 'lab-acked':
                cut.remote(cold, source, op, proof)
                require(calls.call('finish', op, 1, sha(body), len(body), user=cut.fence.WRITER) == 'ACKED',
                        'ORIGINAL_ACK_REQUIRED')
            elif fault == 'corrupt':
                remote(cold, source, 'seed-corrupt', fault, proof, 'seed-corrupt')
        write(proof / 'pre-drain-ledger.json', json.loads(calls.raw(cut.LEDGER_SQL)))
        require(calls.call('begin_drain', 1, 0) == 'DRAINING', 'DRAIN_REQUIRED')
        source.stop()
        cold.command(['sudo', '-n', 'chown', '-R', f'{os.getuid()}:{os.getgid()}', str(original)])
        write(original / 'config/s3.json', cut.configuration(cold, False))
        cold.command(['sudo', '-n', 'chown', '-R', '65532:65532', str(original)])
        fenced = cold.Lab(prefix + '-fenced', original, proof); containers.append(fenced); fenced.start()
        observed = remote(cold, fenced, 'observe', fault, proof, 'before-restart-readback')
        before = assert_blocked(calls, observed, proof, 'before-restart')
        cut.validate_preserved_prefix(json.loads((proof / 'pre-drain-ledger.json').read_bytes()), before)
        result = cut.postgres.native.run([str(pg.binary('pg_ctl')), '-D', str(pg.data), '-m', 'immediate',
            '-l', str(pg.output / 'postgres.log'), '-w', '-t', '20', 'restart'], timeout=25)
        (proof / 'immediate-restart.stdout').write_bytes(result.stdout)
        (proof / 'immediate-restart.stderr').write_bytes(result.stderr)
        require(result.returncode == 0, 'POSTGRES_IMMEDIATE_RESTART_FAILED')
        restarted = json.loads(calls.raw(cut.LEDGER_SQL))
        write(proof / 'after-restart-initial-ledger.json', restarted)
        require(restarted == before, 'RESTART_MUST_PRESERVE_UNRESOLVED_STATE')
        reread = remote(cold, fenced, 'observe', fault, proof, 'after-restart-readback')
        require(reread == observed, 'NEGATIVE_S3_STATE_MUST_REMAIN_IDENTICAL')
        after = assert_blocked(calls, reread, proof, 'after-restart')
        require(after == before, 'ALL_NEGATIVE_HISTORY_MUST_REMAIN_IDENTICAL')
        fenced.stop(); pg.stop()
        require(not any((proof / name).exists() for name in ('common-cut.json', 'catalog.dump', 'restored-ledger.json')),
                'UNRESOLVED_STATE_MUST_NOT_CREATE_CUT_OR_RESTORE')
        report = {**cut.LIMITS, 'schema': 'ouf.storage-unresolved-fixture33.v1',
            'status': 'SYNTHETIC_UNRESOLVED33_BLOCKING_PASS', 'fault': fault,
            'lockSha256': cut.LOCK_SHA, 'cohortReceiptSha256': cut.COHORT_SHA,
            'ociManifestDigest': bound['lock']['image']['manifestDigest'], 'postgresVersion': cut.postgres.native.VERSION,
            'freezeBlockedBeforeAndAfterRestart': True, 'pendingIntentPreserved': True, 'originalAckPreserved': True,
            'recoveryPutRequests': 0, 'fixtureAmbiguousPutRequests': 1 if fault == 'corrupt' else 0,
            'commonCutCreated': False, 'restoreAttempted': False, 'postgresImmediateRestart': True,
            's3DeniedMutations': 6, 'cleanContainerStops': 8, 'cleanPostgresStops': 1,
            'beforeLedgerSha256': cut.postgres.native.digest(proof / 'before-restart-ledger.json'),
            'afterLedgerSha256': cut.postgres.native.digest(proof / 'after-restart-ledger.json'),
            'scope': 'constructed unresolved state, sole fixture identity; no network-loss injection or target acceptance'}
    except Exception as error:
        failure = error; report['failure'] = type(error).__name__ + ': ' + str(error)[:512]
    finally:
        errors = []
        for lab in reversed(containers):
            if lab.names:
                try: lab.stop()
                except Exception as error: errors.append(str(error)[:256])
        try: pg.stop()
        except Exception as error: errors.append(str(error)[:256])
        if errors:
            report.update(status='SYNTHETIC_UNRESOLVED33_TEST_FAILED', cleanupFailures=errors)
            failure = failure or RuntimeError('CLEANUP_FAILED')
        write(proof / 'receipt.json', report)
    if failure: raise failure
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    child = sub.add_parser('client'); child.add_argument('action', choices=('seed-corrupt', 'observe'))
    child.add_argument('--fault', required=True, choices=FAULTS)
    runner = sub.add_parser('run'); runner.add_argument('--fault', required=True, choices=FAULTS)
    for name in ('image', 'pg-bin', 'work', 'cohort-receipt'):
        runner.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    if args.command == 'client': print(json.dumps(client(args.action, args.fault))); return
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.geteuid() != 0, 'UNPRIVILEGED_ISOLATED_CI_REQUIRED')
    require(not args.work.exists() and not args.work.is_symlink(), 'FRESH_WORK_REQUIRED')
    print(json.dumps(run(args.image.resolve(), args.pg_bin.resolve(), args.work.absolute(),
                         args.cohort_receipt.resolve(), args.fault)))


if __name__ == '__main__': main()
