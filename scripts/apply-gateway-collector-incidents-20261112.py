#!/usr/bin/env python3
"""A: one-file collector migration, read-only plan and single human-approved apply."""
import argparse
from contextlib import closing
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time

BASE_SOURCE = '1629652163edce7b3bc4c8f80bf29a3ef1b1ab8a'
SOURCE = 'f60391301cd82465107d0884ec1ada67b78429d3'
BASE_SHA = '6afeb598905550acaceab75ef314eaf0f6de9a5f9508eb6ea71e943eb70f51d1'
TARGET_SHA = 'cbc6ee191a85289efe57b8f0cd8c1d57c16bc3d9bd1910b7eeb8717581292854'
COMMON_SHA = '487798d53ae88ed0a0f31f4c62ed608a2403b4427a236efd61330bc2d93909eb'


def common():
    path = Path(__file__).resolve().with_name('apply-ingestion-operational-receipt-20261112.py')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != COMMON_SHA:
        raise RuntimeError('COMMON_HELPER_HASH_CHANGED')
    spec = importlib.util.spec_from_file_location('gateway_collector_common', path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


c = common()
need, digest, sha = c.need, c.digest, c.sha


def command(argv):
    result = subprocess.run(argv, capture_output=True, timeout=90)
    need(result.returncode == 0, 'HOST_COMMAND_FAILED')
    return result.stdout.decode().strip()


def unit(args, name):
    keys = ('Id', 'LoadState', 'ActiveState', 'SubState', 'User', 'Type', 'Restart',
            'WorkingDirectory', 'ExecStart', 'NeedDaemonReload', 'FragmentPath', 'DropInPaths',
            'MainPID', 'InvocationID', 'ExecMainStatus', 'Result')
    raw = command([args.systemctl_bin, 'show', name, '--no-pager'] +
                  ['--property=' + k for k in keys])
    values = dict(line.split('=', 1) for line in raw.splitlines() if '=' in line)
    need(set(keys) <= values.keys(), 'UNIT_FIELDS_MISSING')
    # ExecStart contains volatile execution timestamps/PID. Bind the complete
    # configured command and ignore_errors flag, not those observation counters.
    match = re.fullmatch(r'\{ path=([^;{}]+) ; argv\[\]=([^;{}]+) ; ignore_errors=(yes|no) ; '
                         r'start_time=[^;{}]* ; stop_time=[^;{}]* ; pid=\d+ ; code=[^;{}]* ; status=[^;{}]* \}',
                         values['ExecStart'])
    need(match is not None, 'SINGLE_EXEC_START_SHAPE_REQUIRED')
    values['ExecStart'] = {'path': match[1], 'argv': match[2], 'ignoreErrors': match[3]}
    # Hash files only after the configured root service has been identified.
    need(values['LoadState'] == 'loaded' and values['NeedDaemonReload'] == 'no' and
         values['User'] == 'root', 'LOADED_ROOT_UNIT_REQUIRED')
    paths = shlex.split(values['DropInPaths'])
    need(bool(values['FragmentPath']) and all(Path(p).is_absolute() for p in paths + [values['FragmentPath']]),
         'UNIT_SOURCE_PATHS_REQUIRED')
    values['sourceDigests'] = {p: sha(c.read(Path(p))) for p in [values['FragmentPath']] + paths}
    return values


def stable_unit(value):
    return {k: v for k, v in value.items() if k not in
            ('MainPID', 'InvocationID', 'ExecMainStatus', 'Result', 'ActiveState', 'SubState')}


def check_units(args, collector, probe):
    for observed, name, expected, kind in (
            (collector, args.collector_unit, args.collector_exec_start, 'apisix'),
            (probe, args.probe_unit, args.probe_exec_start, 'etcd')):
        need(observed['Id'] == name and observed['WorkingDirectory'] == str(args.checkout),
             'UNIT_ID_OR_WORKING_DIRECTORY_MISMATCH')
        words = shlex.split(expected)
        need(words and ' '.join(words) == expected and words[1:4] ==
             ['-m', 'tools.gateway_operational_collector', kind], 'EXPECTED_COLLECTOR_COMMAND_REQUIRED')
        need(words.count('--store') == 1 and Path(words[words.index('--store') + 1]) == args.store and
             words.count('--container') == 1, 'EXACT_SHARED_STORE_COMMAND_REQUIRED')
        need(observed['ExecStart'] == {'path': words[0], 'argv': expected, 'ignoreErrors': 'no'},
             'EXEC_START_MISMATCH')
    need(collector['Type'] == 'simple' and collector['Restart'] == 'on-failure' and
         collector['ActiveState'] == 'active' and collector['SubState'] == 'running',
         'COLLECTOR_ACTIVE_SIMPLE_REQUIRED')
    need(probe['Type'] == 'oneshot', 'PROBE_ONESHOT_REQUIRED')


def file_frame(path):
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode), 'REGULAR_TARGET_REQUIRED')
    return {'uid': info.st_uid, 'gid': info.st_gid, 'mode': stat.S_IMODE(info.st_mode),
            'device': info.st_dev, 'inode': info.st_ino, 'mtimeNs': info.st_mtime_ns,
            'ctimeNs': info.st_ctime_ns, 'size': info.st_size}


def collect(args, run=command, observe=unit):
    collector, probe = observe(args, args.collector_unit), observe(args, args.probe_unit)
    check_units(args, collector, probe)
    git = [args.git_bin, '--no-optional-locks', '-c', 'core.fsmonitor=false',
           '-c', 'safe.directory=' + str(args.checkout), '-C', str(args.checkout)]
    need(run(git + ['rev-parse', '--show-toplevel']) == str(args.checkout), 'EXACT_CHECKOUT_ROOT_REQUIRED')
    need(args.expected_commit == BASE_SOURCE and run(git + ['rev-parse', 'HEAD']) == args.expected_commit,
         'CHECKOUT_COMMIT_MISMATCH')
    need(not run(git + ['status', '--porcelain=v1', '--untracked-files=all', '--ignore-submodules=none']),
         'DIRTY_CHECKOUT')
    target = args.checkout / 'tools/operational_incidents.py'
    before = file_frame(target)
    need(sha(c.read(target)) == BASE_SHA, 'CURRENT_FILE_HASH_MISMATCH')
    need(sha(c.read(args.candidate_file)) == TARGET_SHA, 'CANDIDATE_FILE_HASH_MISMATCH')
    need(before == file_frame(target), 'TARGET_CHANGED_DURING_PLAN')
    # No DB data/count is part of the approval: the writers remain live during plan.
    return {'schema': 'ouf.gateway-collector-incidents-plan.v1',
            'sourceCommit': SOURCE, 'baseCommit': BASE_SOURCE,
            'controllerSha256': sha(Path(__file__).read_bytes()), 'commonSha256': COMMON_SHA,
            'currentFileSha256': BASE_SHA, 'candidateFileSha256': TARGET_SHA,
            'fileFrame': before, 'collector': stable_unit(collector), 'probe': stable_unit(probe),
            'collectorInvocation': collector['InvocationID'],
            'parameters': {k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()
                           if k not in ('plan', 'apply', 'plan_sha256')}}


def store_counts(path):
    """One read-only WAL snapshot. Baseline = first transition per current incident.

    Concurrent updates append transitions, so total history rows need not equal
    incident count. Never use immutable=1 (would silently omit live WAL data).
    """
    need(all(p.is_file() for p in (path, Path(str(path) + '-wal'), Path(str(path) + '-shm'))),
         'LIVE_WAL_SIDECARS_REQUIRED')
    with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=8)) as db:
        db.execute('begin')
        need(db.execute('pragma journal_mode').fetchone()[0] == 'wal', 'WAL_STORE_REQUIRED')
        required = {('table', 'gateway_incident_transition'), ('index', 'gateway_incident_current'),
                    ('trigger', 'gateway_incident_capture_insert'), ('trigger', 'gateway_incident_capture_update')}
        found = set(db.execute("select type,name from sqlite_master where name in "
                               "('gateway_incident_transition','gateway_incident_current',"
                               "'gateway_incident_capture_insert','gateway_incident_capture_update')"))
        need(found == required, 'TRANSITION_SCHEMA_MISSING')
        incidents = db.execute('select count(*) from gateway_operational_incident').fetchone()[0]
        baseline = db.execute('select count(*) from gateway_operational_incident i where exists '
                              '(select 1 from gateway_incident_transition t where t.incident_id=i.incident_id)').fetchone()[0]
        need(incidents == baseline, 'BASELINE_COUNT_MISMATCH')
        return {'incidentCount': incidents, 'baselineCount': baseline,
                'transitionCount': db.execute('select count(*) from gateway_incident_transition').fetchone()[0]}


def backup(work, raw):
    fd = os.open(work / 'operational_incidents.py.before', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    c.fsync_dir(work)


def replace_file(target, raw, frame):
    # O_EXCL temporary file in the SAME directory/filesystem, then durable rename.
    fd, temporary = tempfile.mkstemp(prefix='.incidents-', dir=target.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            os.fchown(stream.fileno(), frame['uid'], frame['gid'])
            os.fchmod(stream.fileno(), frame['mode'])
            stream.flush()
            os.fsync(stream.fileno())
        need(file_frame(target) == frame and sha(c.read(target)) == BASE_SHA, 'TARGET_CHANGED_BEFORE_RENAME')
        os.replace(temporary, target)
        c.fsync_dir(target.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def wait_collector(args, old_invocation, observe=unit):
    deadline = time.monotonic() + args.timeout
    while True:
        current = observe(args, args.collector_unit)
        if (current['ActiveState'], current['SubState']) == ('active', 'running') and \
                current['InvocationID'] and current['InvocationID'] != old_invocation:
            return
        need(time.monotonic() < deadline, 'COLLECTOR_RESTART_NOT_ACTIVE')
        time.sleep(0.25)


def apply_plan(plan, approved, args, report, recollect=collect, run=command, observe=unit):
    need(digest(plan) == approved, 'FRESH_PLAN_HASH_MISMATCH')
    work = c.begin_attempt(args.journal_root, approved)
    report['privateEvidenceDirectory'] = str(work)
    c.record(work, 'plan.private.json', plan)
    # One persistent claim per file generation, including different concurrent plans.
    c.record(args.journal_root, 'collector-' + digest([str(args.checkout), BASE_SHA]) + '.claim',
             {'planSha256': approved})
    need(digest(recollect(args)) == approved, 'PLAN_CHANGED_BEFORE_REPLACE')
    target = args.checkout / 'tools/operational_incidents.py'
    raw = c.read(target)
    need(sha(raw) == BASE_SHA, 'CURRENT_FILE_HASH_MISMATCH')
    backup(work, raw)
    candidate = c.read(args.candidate_file)
    need(sha(candidate) == TARGET_SHA, 'CANDIDATE_FILE_HASH_MISMATCH')
    c.record(work, 'replace-intent.private.json', {'targetSha256': TARGET_SHA})
    report['runtimeChanged'] = None
    replace_file(target, candidate, plan['fileFrame'])
    report['runtimeChanged'] = True
    need(sha(c.read(target)) == TARGET_SHA, 'REPLACED_FILE_HASH_MISMATCH')
    after = file_frame(target)
    need(all(after[k] == plan['fileFrame'][k] for k in ('uid', 'gid', 'mode')),
         'REPLACED_FILE_OWNERSHIP_OR_MODE_CHANGED')
    c.record(work, 'restart-collector-intent.private.json', {'unit': args.collector_unit})
    run([args.systemctl_bin, 'restart', args.collector_unit])
    wait_collector(args, plan['collectorInvocation'], observe)
    # restart waits for an existing oneshot to finish, then starts a fresh run.
    # systemctl restart is blocking; Result/status prove completion even if timer fires again.
    c.record(work, 'restart-probe-intent.private.json', {'unit': args.probe_unit})
    run([args.systemctl_bin, 'restart', args.probe_unit])
    probe = observe(args, args.probe_unit)
    need(probe['Result'] == 'success' and probe['ExecMainStatus'] == '0', 'PROBE_RUN_FAILED')
    check_units(args, observe(args, args.collector_unit), probe)
    report.update(store_counts(args.store))
    report.update(status='GATEWAY_COLLECTOR_INCIDENTS_READY', reason='FILE_AND_BASELINE_VERIFIED',
                  collectorActive=True, onlyTargetFileReplaced=True)
    c.record(work, 'complete.private.json', report)


def arguments(argv):
    p = c.Parser(description=__doc__)
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--plan', action='store_true')
    mode.add_argument('--apply', action='store_true')
    p.add_argument('--plan-sha256')
    for key in ('checkout', 'candidate-file', 'store', 'journal-root'):
        p.add_argument('--' + key, type=Path, required=True)
    for key in ('collector-unit', 'probe-unit', 'collector-exec-start', 'probe-exec-start',
                'expected-commit', 'systemctl-bin', 'git-bin'):
        p.add_argument('--' + key, required=True)
    p.add_argument('--timeout', type=int, required=True)
    a = p.parse_args(argv)
    need(bool(a.plan_sha256) == a.apply and (not a.apply or re.fullmatch('[a-f0-9]{64}', a.plan_sha256)),
         'HUMAN_APPROVED_PLAN_HASH_REQUIRED')
    need(all(getattr(a, k).is_absolute() for k in ('checkout', 'candidate_file', 'store', 'journal_root')) and
         all(Path(getattr(a, k)).is_absolute() for k in ('systemctl_bin', 'git_bin')) and
         1 <= a.timeout <= 300 and a.collector_unit != a.probe_unit and
         all(re.fullmatch(r'[A-Za-z0-9_.@-]+\.service', n) for n in (a.collector_unit, a.probe_unit)),
         'BOUNDED_ABSOLUTE_PARAMETERS_REQUIRED')
    return a


def main(argv=None):
    report = {'schema': 'ouf.gateway-collector-incidents-result.v1', 'status': 'HELD',
              'runtimeChanged': False, 'automaticRollback': False, 'automaticReplay': False,
              'credentialReads': 0, 'databaseWrites': 0}
    try:
        args = arguments(argv)
        need(os.geteuid() == 0 and sys.flags.isolated, 'ISOLATED_ROOT_REQUIRED')
        if args.apply:
            need(not (args.journal_root / ('apply-' + args.plan_sha256)).exists(), 'EXISTING_ATTEMPT_DO_NOT_REPLAY')
        plan = collect(args)
        report.update(planSha256=digest(plan), currentFileSha256=BASE_SHA, candidateFileSha256=TARGET_SHA,
                      sourceCommit=SOURCE, beforeFrameSha256=digest(plan['fileFrame']),
                      unitEvidenceSha256=digest([plan['collector'], plan['probe']]))
        if args.apply:
            apply_plan(plan, args.plan_sha256, args, report)
        else:
            report.update(status='GATEWAY_COLLECTOR_INCIDENTS_PLANNED', reason='HUMAN_HASH_APPROVAL_REQUIRED')
    except (Exception, KeyboardInterrupt) as exc:
        reason = str(exc) if isinstance(exc, RuntimeError) and re.fullmatch('[A-Z][A-Z0-9_]{0,100}', str(exc)) else type(exc).__name__
        report.update(status='HELD', reason=reason)
        if report.get('privateEvidenceDirectory'):
            try:
                c.record(Path(report['privateEvidenceDirectory']), 'failed.private.json', report)
            except Exception:
                pass  # Preserve the original failure and durable intents.
    print(json.dumps(report, sort_keys=True))
    return int(report['status'] == 'HELD')


if __name__ == '__main__':
    sys.exit(main())
