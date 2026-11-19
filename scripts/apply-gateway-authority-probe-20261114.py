#!/usr/bin/env python3
"""Task-32: release the gateway authority-mandates probe (task-31, D-030).

Read-only plan; a single apply approved by the plan hash. Replaces only
tools/gateway_operational_collector.py in the live checkout, installs the
probe service and timer, restarts the collector, runs the probe once and
enables the timer. No rollback, no replay, no credential reads, no DB writes.
"""
import argparse
from contextlib import closing
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time

CHECKOUT_COMMIT = '1629652163edce7b3bc4c8f80bf29a3ef1b1ab8a'
SOURCE = '5b93e56748034ec678d732cfd40ca915695fefb5'          # ouf-api-gateway, task-31
BASE_SHA = 'dd0edb44703b200e2bbc40aa1dd81f088c5a8856746294bdb7605f65aed307c8'
TARGET_SHA = 'a0599016495b4794ab60c8b9f9bc488bbe23ea65f39312176353858fb676bcdf'
INCIDENTS_SHA = 'c0a8025cac4745cc41cb55694e8c907c96f554877fce57b28a7d7ae7a981b3e2'
ETCD_UNITS = {'ouf-gateway-etcd-probe.service': '6b73d7093f152b61e652bbd06dc74d0d40c438dbf3e479134c23a60b29f06315',
              'ouf-gateway-etcd-probe.timer': '8698fdd54e0551ab4095535524e4493901ef5bf79d44fa98b4891c9ef2ca83f3'}
COLLECTOR_UNIT = 'ouf-gateway-operational-collector.service'
PROBE_SERVICE = 'ouf-gateway-authority-mandates-probe.service'
PROBE_TIMER = 'ouf-gateway-authority-mandates-probe.timer'
STATUS = '/var/lib/ouf-authority-mandate-renewal/status.json'
PORCELAIN = ' M tools/operational_incidents.py'
LAYOUT = {'checkout': '/opt/ouf/gateway-r3-summary', 'unitDirectory': '/etc/systemd/system',
          'store': '/var/lib/ouf-gateway-operations/gateway-operations.sqlite',
          'systemctl': '/usr/bin/systemctl', 'git': '/usr/bin/git', 'owner': 'oufadmin', 'group': 'oufadmin'}


def need(ok, code):
    if not ok:
        raise RuntimeError(code)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path, maximum=1048576):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_size <= maximum, 'BOUNDED_REGULAR_FILE_REQUIRED')
        raw = os.read(fd, maximum + 1)
        after = os.fstat(fd)
        same = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(len(raw) == before.st_size and same(before) == same(after), 'FILE_CHANGED_DURING_READ')
        return raw
    finally:
        os.close(fd)


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new(path, raw, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode)
        written = 0
        while written < len(raw):
            written += os.write(fd, raw[written:])
        os.fsync(fd)
    finally:
        os.close(fd)
    fsync_dir(Path(path).parent)


def record(work, name, value):
    write_new(work / name, encoded(value), 0o600)


def begin_attempt(root, plan_sha):
    info = root.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
         'ROOT_OWNED_0700_JOURNAL_PARENT_REQUIRED')
    path = root / ('apply-' + plan_sha)
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        need(False, 'EXISTING_ATTEMPT_DO_NOT_REPLAY')
    fsync_dir(root)
    return path


def probe_units(layout):
    checkout = layout['checkout']
    service = (
        '[Unit]\n'
        'Description=OUF Gateway authority mandate renewal probe\n'
        'After=local-fs.target\n\n'
        '[Service]\n'
        'Type=oneshot\n'
        'User=root\n'
        'Group=10001\n'
        'WorkingDirectory=' + checkout + '\n'
        'StateDirectory=ouf-gateway-operations\n'
        'StateDirectoryMode=0750\n'
        'UMask=0027\n'
        'ExecStart=/usr/bin/python3 -m tools.gateway_operational_collector authority-mandates --store '
        + layout['store'] + ' --status ' + STATUS + '\n'
        'NoNewPrivileges=true\n'
        'PrivateTmp=true\n'
        'ProtectHome=true\n'
        'ProtectSystem=strict\n'
        'ReadOnlyPaths=' + checkout + ' -' + str(Path(STATUS).parent) + '\n'
        'ReadWritePaths=' + str(Path(layout['store']).parent) + '\n'
    ).encode()
    timer = (
        '[Unit]\n'
        'Description=Run OUF Gateway authority mandate renewal probe\n\n'
        '[Timer]\n'
        'OnBootSec=2min\n'
        'OnUnitActiveSec=15min\n'
        'AccuracySec=1min\n'
        'Unit=' + PROBE_SERVICE + '\n\n'
        '[Install]\n'
        'WantedBy=timers.target\n'
    ).encode()
    return {PROBE_SERVICE: service, PROBE_TIMER: timer}


class Host:
    """systemctl/git access; replaced by a simulation in tests."""

    def __init__(self, layout):
        self.layout = layout

    def run(self, argv, check=True):
        result = subprocess.run(argv, capture_output=True, timeout=90,
                                env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
        if check:
            need(result.returncode == 0, 'HOST_COMMAND_FAILED')
        return result.returncode, result.stdout.decode().rstrip('\n')

    def git(self, *args):
        checkout = self.layout['checkout']
        return self.run([self.layout['git'], '--no-optional-locks', '-c', 'core.fsmonitor=false',
                         '-c', 'safe.directory=' + checkout, '-C', checkout, *args])[1]

    def show(self, name, keys):
        raw = self.run([self.layout['systemctl'], 'show', name, '--no-pager'] + ['--property=' + k for k in keys])[1]
        values = dict(line.split('=', 1) for line in raw.splitlines() if '=' in line)
        need(set(keys) <= values.keys(), 'UNIT_FIELDS_MISSING')
        return values

    def systemctl(self, *args, check=True):
        return self.run([self.layout['systemctl'], *args], check=check)[0]


def owner_ids(layout):
    try:
        return pwd.getpwnam(layout['owner']).pw_uid, grp.getgrnam(layout['group']).gr_gid
    except KeyError:
        need(False, 'CHECKOUT_OWNER_ACCOUNT_REQUIRED')


def file_frame(path):
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode), 'REGULAR_TARGET_REQUIRED')
    return {'uid': info.st_uid, 'gid': info.st_gid, 'mode': stat.S_IMODE(info.st_mode), 'device': info.st_dev,
            'inode': info.st_ino, 'mtimeNs': info.st_mtime_ns, 'ctimeNs': info.st_ctime_ns, 'size': info.st_size}


def store_snapshot(path):
    need(Path(path).is_file(), 'GATEWAY_STORE_REQUIRED')
    with closing(sqlite3.connect(Path(path).as_uri() + '?mode=ro', uri=True, timeout=8)) as db:
        db.execute('begin')
        index = db.execute("select tbl_name from sqlite_master where type='index' "
                           "and name='gateway_incident_transition_dedup'").fetchone()
        need(index is not None and index[0] == 'gateway_incident_transition', 'EPISODE_DEDUP_INDEX_MISSING')
        need(db.execute('pragma integrity_check').fetchall() == [('ok',)], 'STORE_INTEGRITY_CHECK_FAILED')
        rows = db.execute("select dedup_key,lifecycle_state,error_code from gateway_operational_incident "
                          "where dedup_key like 'authority:mandates:%' order by dedup_key").fetchall()
        return {'integrityCheck': 'ok', 'authorityIncidents': [list(row) for row in rows]}


COLLECTOR_KEYS = ('Id', 'LoadState', 'ActiveState', 'SubState', 'User', 'Type', 'WorkingDirectory',
                  'NeedDaemonReload', 'FragmentPath', 'DropInPaths', 'InvocationID')


def collect(layout, candidate, host):
    checkout = Path(layout['checkout'])
    need(host.git('rev-parse', '--show-toplevel') == str(checkout), 'EXACT_CHECKOUT_ROOT_REQUIRED')
    need(host.git('rev-parse', 'HEAD') == CHECKOUT_COMMIT, 'CHECKOUT_COMMIT_MISMATCH')
    need(host.git('status', '--porcelain=v1', '--untracked-files=all', '--ignore-submodules=none') == PORCELAIN,
         'CHECKOUT_STATUS_MISMATCH')
    target = checkout / 'tools/gateway_operational_collector.py'
    before = file_frame(target)
    need(sha(read(target)) == BASE_SHA, 'CURRENT_FILE_HASH_MISMATCH')
    need(sha(read(checkout / 'tools/operational_incidents.py')) == INCIDENTS_SHA, 'INCIDENT_STORE_FILE_HASH_MISMATCH')
    need(sha(read(Path(candidate))) == TARGET_SHA, 'CANDIDATE_FILE_HASH_MISMATCH')
    uid, gid = owner_ids(layout)
    need((before['uid'], before['gid'], before['mode']) == (uid, gid, 0o664), 'TARGET_OWNERSHIP_OR_MODE_MISMATCH')
    collector = host.show(COLLECTOR_UNIT, COLLECTOR_KEYS)
    need(collector['Id'] == COLLECTOR_UNIT and collector['LoadState'] == 'loaded'
         and (collector['ActiveState'], collector['SubState']) == ('active', 'running')
         and collector['User'] == 'root' and collector['Type'] == 'simple'
         and collector['WorkingDirectory'] == str(checkout) and collector['NeedDaemonReload'] == 'no'
         and collector['InvocationID'], 'COLLECTOR_ACTIVE_UNIT_REQUIRED')
    units = Path(layout['unitDirectory'])
    for name, expected in ETCD_UNITS.items():
        need(sha(read(units / name)) == expected, 'ETCD_PROBE_UNIT_CHANGED')
    for name in (PROBE_SERVICE, PROBE_TIMER):
        need(not os.path.lexists(units / name), 'PROBE_UNIT_ALREADY_PRESENT')
        need(host.show(name, ('LoadState',))['LoadState'] == 'not-found', 'PROBE_UNIT_ALREADY_LOADED')
    store = store_snapshot(layout['store'])
    need(before == file_frame(target), 'TARGET_CHANGED_DURING_PLAN')
    return {'schema': 'ouf.gateway-authority-probe-plan.v1', 'sourceCommit': SOURCE, 'checkoutCommit': CHECKOUT_COMMIT,
            'controllerSha256': sha(read(Path(__file__).resolve())),
            'currentFileSha256': BASE_SHA, 'candidateFileSha256': TARGET_SHA, 'incidentStoreFileSha256': INCIDENTS_SHA,
            'fileFrame': before, 'collectorInvocation': collector['InvocationID'],
            'collectorUnit': {k: collector[k] for k in COLLECTOR_KEYS if k != 'InvocationID'},
            'etcdUnits': ETCD_UNITS, 'probeUnits': {n: sha(raw) for n, raw in probe_units(layout).items()},
            'authorityIncidentsBefore': store['authorityIncidents'],
            'layout': layout}


def replace_file(target, raw, frame):
    fd, temporary = tempfile.mkstemp(prefix='.authority-probe-', dir=target.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            os.fchown(stream.fileno(), frame['uid'], frame['gid'])
            os.fchmod(stream.fileno(), frame['mode'])
            stream.flush()
            os.fsync(stream.fileno())
        need(file_frame(target) == frame and sha(read(target)) == BASE_SHA, 'TARGET_CHANGED_BEFORE_RENAME')
        os.replace(temporary, target)
        fsync_dir(target.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def wait_collector(host, old_invocation, timeout, sleep=time.sleep, monotonic=time.monotonic):
    deadline = monotonic() + timeout
    while True:
        current = host.show(COLLECTOR_UNIT, ('ActiveState', 'SubState', 'InvocationID'))
        if (current['ActiveState'], current['SubState']) == ('active', 'running') and \
                current['InvocationID'] and current['InvocationID'] != old_invocation:
            return
        need(monotonic() < deadline, 'COLLECTOR_RESTART_NOT_ACTIVE')
        sleep(0.25)


def apply_plan(plan, approved, layout, candidate, journal, host, report, timeout=60, sleep=time.sleep):
    need(digest(plan) == approved, 'FRESH_PLAN_HASH_MISMATCH')
    work = begin_attempt(journal, approved)
    report['privateEvidenceDirectory'] = str(work)
    record(work, 'plan.private.json', plan)
    need(digest(collect(layout, candidate, host)) == approved, 'PLAN_CHANGED_BEFORE_REPLACE')
    target = Path(layout['checkout']) / 'tools/gateway_operational_collector.py'
    old = read(target)
    need(sha(old) == BASE_SHA, 'CURRENT_FILE_HASH_MISMATCH')
    write_new(work / 'gateway_operational_collector.py.before', old, 0o600)
    raw = read(Path(candidate))
    need(sha(raw) == TARGET_SHA, 'CANDIDATE_FILE_HASH_MISMATCH')
    record(work, 'replace-intent.private.json', {'targetSha256': TARGET_SHA})
    report['runtimeChanged'] = None
    replace_file(target, raw, plan['fileFrame'])
    report['runtimeChanged'] = True
    after = file_frame(target)
    need(sha(read(target)) == TARGET_SHA and all(after[k] == plan['fileFrame'][k] for k in ('uid', 'gid', 'mode')),
         'REPLACED_FILE_MISMATCH')
    units = Path(layout['unitDirectory'])
    record(work, 'units-intent.private.json', plan['probeUnits'])
    for name, unit_raw in probe_units(layout).items():
        write_new(units / name, unit_raw, 0o644)
        need(sha(read(units / name)) == plan['probeUnits'][name], 'PROBE_UNIT_READBACK_MISMATCH')
    host.systemctl('daemon-reload')
    record(work, 'restart-collector-intent.private.json', {'unit': COLLECTOR_UNIT})
    host.systemctl('restart', COLLECTOR_UNIT)
    wait_collector(host, plan['collectorInvocation'], timeout, sleep)
    record(work, 'probe-run-intent.private.json', {'unit': PROBE_SERVICE})
    host.systemctl('start', PROBE_SERVICE, check=False)
    probe = host.show(PROBE_SERVICE, ('LoadState', 'Result', 'ExecMainStatus', 'NeedDaemonReload'))
    need(probe['LoadState'] == 'loaded' and probe['NeedDaemonReload'] == 'no'
         and (probe['Result'], probe['ExecMainStatus']) in (('success', '0'), ('exit-code', '2')), 'PROBE_RUN_FAILED')
    host.systemctl('enable', '--now', PROBE_TIMER)
    timer = host.show(PROBE_TIMER, ('LoadState', 'ActiveState', 'UnitFileState'))
    need(timer == {'LoadState': 'loaded', 'ActiveState': 'active', 'UnitFileState': 'enabled'}, 'PROBE_TIMER_NOT_ACTIVE')
    for name, expected in ETCD_UNITS.items():
        need(sha(read(units / name)) == expected, 'ETCD_PROBE_UNIT_CHANGED')
    collector = host.show(COLLECTOR_UNIT, COLLECTOR_KEYS)
    need({k: collector[k] for k in COLLECTOR_KEYS if k != 'InvocationID'} == plan['collectorUnit'],
         'COLLECTOR_UNIT_CHANGED_AFTER_RESTART')
    store = store_snapshot(layout['store'])
    report.update(status='GATEWAY_AUTHORITY_PROBE_READY', reason='FILE_UNITS_PROBE_AND_TIMER_VERIFIED',
                  probeResult=probe['Result'], probeExitStatus=probe['ExecMainStatus'],
                  authorityIncidents=store['authorityIncidents'], onlyTargetFileReplaced=True)
    record(work, 'complete.private.json', report)


def arguments(argv):
    p = argparse.ArgumentParser(description=__doc__)
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--plan', action='store_true')
    mode.add_argument('--apply', action='store_true')
    p.add_argument('--plan-sha256')
    p.add_argument('--candidate-file', type=Path, required=True)
    p.add_argument('--journal-root', type=Path, required=True)
    a = p.parse_args(argv)
    need(bool(a.plan_sha256) == a.apply and (not a.apply or re.fullmatch('[a-f0-9]{64}', a.plan_sha256)),
         'HUMAN_APPROVED_PLAN_HASH_REQUIRED')
    need(a.candidate_file.is_absolute() and a.journal_root.is_absolute(), 'ABSOLUTE_PARAMETERS_REQUIRED')
    return a


def main(argv=None, layout=None, host=None):
    report = {'schema': 'ouf.gateway-authority-probe-result.v1', 'status': 'HELD', 'runtimeChanged': False,
              'automaticRollback': False, 'automaticReplay': False, 'credentialReads': 0, 'databaseWrites': 0}
    try:
        args = arguments(argv)
        layout = layout or LAYOUT
        host = host or Host(layout)
        if layout is LAYOUT:
            need(os.geteuid() == 0 and sys.flags.isolated, 'ISOLATED_ROOT_REQUIRED')
        if args.apply:
            need(not (args.journal_root / ('apply-' + args.plan_sha256)).exists(), 'EXISTING_ATTEMPT_DO_NOT_REPLAY')
        plan = collect(layout, args.candidate_file, host)
        report.update(planSha256=digest(plan), sourceCommit=SOURCE, currentFileSha256=BASE_SHA,
                      candidateFileSha256=TARGET_SHA, probeUnits=plan['probeUnits'])
        if args.apply:
            apply_plan(plan, args.plan_sha256, layout, args.candidate_file, args.journal_root, host, report)
        else:
            report.update(status='GATEWAY_AUTHORITY_PROBE_PLANNED', reason='HUMAN_HASH_APPROVAL_REQUIRED')
    except (Exception, KeyboardInterrupt) as exc:
        reason = str(exc) if isinstance(exc, RuntimeError) and re.fullmatch('[A-Z][A-Z0-9_]{0,100}', str(exc)) \
            else type(exc).__name__
        report.update(status='HELD', reason=reason)
        if report.get('privateEvidenceDirectory'):
            try:
                record(Path(report['privateEvidenceDirectory']), 'failed.private.json', report)
            except Exception:
                pass
    print(json.dumps(report, sort_keys=True))
    return int(report['status'] == 'HELD')


if __name__ == '__main__':
    sys.exit(main())
