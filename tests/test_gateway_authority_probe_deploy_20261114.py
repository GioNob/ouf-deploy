"""Task-32 contract: plan/apply of the gateway authority probe release.

systemctl and git are simulated; files, journal and SQLite store are real
temporaries. Runs unprivileged on Linux (ownership checks use the current user).
"""

import contextlib
import grp
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import pwd
import re
import sqlite3
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/apply-gateway-authority-probe-20261114.py'
RUNBOOK = ROOT / 'ops/vps/gateway-authority-probe.sh'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load():
    spec = importlib.util.spec_from_file_location('authority_probe_deploy', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeHost:
    def __init__(self, test):
        self.t = test
        self.calls = []
        self.invocation = 'inv-1'
        self.loaded = set()
        self.probe = ('exit-code', '2')
        self.timer_enabled = False
        self.restart_activates = True

    def git(self, *args):
        if args == ('rev-parse', '--show-toplevel'):
            return self.t.layout['checkout']
        if args == ('rev-parse', 'HEAD'):
            return self.t.commit
        return self.t.porcelain

    def show(self, name, keys):
        if name == self.t.a.COLLECTOR_UNIT:
            values = {'Id': name, 'LoadState': 'loaded', 'ActiveState': 'active', 'SubState': 'running',
                      'User': 'root', 'Type': 'simple', 'WorkingDirectory': self.t.layout['checkout'],
                      'NeedDaemonReload': 'no', 'FragmentPath': '/etc/systemd/system/' + name,
                      'DropInPaths': '/etc/systemd/system/' + name + '.d/restart.conf',
                      'InvocationID': self.invocation}
        elif name == self.t.a.PROBE_SERVICE:
            values = {'LoadState': 'loaded' if name in self.loaded else 'not-found', 'Result': self.probe[0],
                      'ExecMainStatus': self.probe[1], 'NeedDaemonReload': 'no'}
        else:
            values = {'LoadState': 'loaded' if name in self.loaded else 'not-found',
                      'ActiveState': 'active' if self.timer_enabled else 'inactive',
                      'UnitFileState': 'enabled' if self.timer_enabled else 'disabled'}
        return {k: values[k] for k in keys}

    def systemctl(self, *args, check=True):
        self.calls.append(args)
        if args == ('daemon-reload',):
            self.loaded = {n for n in (self.t.a.PROBE_SERVICE, self.t.a.PROBE_TIMER)
                           if (Path(self.t.layout['unitDirectory']) / n).exists()}
        elif args[0] == 'restart' and self.restart_activates:
            self.invocation = 'inv-2'
        elif args[:2] == ('enable', '--now'):
            self.timer_enabled = True
        return 0


class Fixture(unittest.TestCase):
    def setUp(self):
        if sys.platform != 'linux':
            self.skipTest('POSIX semantics')
        self.a = load()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        checkout, units, state = root / 'checkout', root / 'units', root / 'state'
        for path in (checkout / 'tools', units, state):
            path.mkdir(parents=True)
        self.layout = {'checkout': str(checkout), 'unitDirectory': str(units), 'store': str(state / 'store.sqlite'),
                       'systemctl': '/usr/bin/systemctl', 'git': '/usr/bin/git',
                       'owner': pwd.getpwuid(os.getuid()).pw_name, 'group': grp.getgrgid(os.getgid()).gr_name}
        self.old, self.new = b'# collector before task-31\n', b'# collector with authority-mandates\n'
        self.target = checkout / 'tools/gateway_operational_collector.py'
        self.target.write_bytes(self.old)
        self.target.chmod(0o664)
        (checkout / 'tools/operational_incidents.py').write_bytes(b'# store\n')
        self.candidate = root / 'candidate.py'
        self.candidate.write_bytes(self.new)
        etcd = {}
        for name in ('ouf-gateway-etcd-probe.service', 'ouf-gateway-etcd-probe.timer'):
            (units / name).write_bytes(name.encode())
            etcd[name] = sha(name.encode())
        self.a.BASE_SHA, self.a.TARGET_SHA = sha(self.old), sha(self.new)
        self.a.INCIDENTS_SHA, self.a.ETCD_UNITS = sha(b'# store\n'), etcd
        with sqlite3.connect(self.layout['store']) as db:
            db.execute('create table gateway_operational_incident(dedup_key text, lifecycle_state text, error_code text)')
            db.execute('create table gateway_incident_transition(dedup_key text)')
            db.execute('create index gateway_incident_transition_dedup on gateway_incident_transition(dedup_key)')
        self.journal = root / 'journal'
        self.journal.mkdir(mode=0o700)
        self.commit, self.porcelain = self.a.CHECKOUT_COMMIT, self.a.PORCELAIN
        self.host = FakeHost(self)

    def plan(self):
        return self.a.collect(self.layout, self.candidate, self.host)

    def main(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = self.a.main([*argv, '--candidate-file', str(self.candidate), '--journal-root', str(self.journal)],
                               self.layout, self.host)
        return code, json.loads(out.getvalue())

    def held(self, code):
        result, report = self.main('--plan')
        self.assertEqual((result, report['status'], report['reason']), (1, 'HELD', code))


class PlanTests(Fixture):
    def test_plan_is_stable_and_read_only(self):
        before = self.target.read_bytes()
        first, second = self.plan(), self.plan()
        self.assertEqual(self.a.digest(first), self.a.digest(second))
        self.assertEqual(self.host.calls, [])
        self.assertEqual(self.target.read_bytes(), before)
        code, report = self.main('--plan')
        self.assertEqual((code, report['status']), (0, 'GATEWAY_AUTHORITY_PROBE_PLANNED'))
        self.assertEqual(report['planSha256'], self.a.digest(first))

    def test_drift_holds(self):
        cases = [('commit', lambda: setattr(self, 'commit', '0' * 40), 'CHECKOUT_COMMIT_MISMATCH'),
                 ('porcelain', lambda: setattr(self, 'porcelain', ' M tools/x.py'), 'CHECKOUT_STATUS_MISMATCH'),
                 ('current', lambda: self.target.write_bytes(b'other'), 'CURRENT_FILE_HASH_MISMATCH'),
                 ('candidate', lambda: self.candidate.write_bytes(b'other'), 'CANDIDATE_FILE_HASH_MISMATCH'),
                 ('mode', lambda: self.target.chmod(0o644), 'TARGET_OWNERSHIP_OR_MODE_MISMATCH'),
                 ('etcd', lambda: (Path(self.layout['unitDirectory']) / 'ouf-gateway-etcd-probe.timer').write_bytes(b'x'),
                  'ETCD_PROBE_UNIT_CHANGED'),
                 ('present', lambda: (Path(self.layout['unitDirectory']) / self.a.PROBE_TIMER).write_bytes(b'x'),
                  'PROBE_UNIT_ALREADY_PRESENT')]
        for name, change, code in cases:
            self.setUp()
            with self.subTest(name=name):
                change()
                self.held(code)

    def test_store_without_episode_index_holds(self):
        with sqlite3.connect(self.layout['store']) as db:
            db.execute('drop index gateway_incident_transition_dedup')
        self.held('EPISODE_DEDUP_INDEX_MISSING')

    def test_units_follow_the_installed_etcd_model(self):
        units = self.a.probe_units(self.a.LAYOUT)
        service = units[self.a.PROBE_SERVICE].decode()
        for line in ('WorkingDirectory=/opt/ouf/gateway-r3-summary', 'Group=10001', 'Type=oneshot', 'User=root',
                     'ReadOnlyPaths=/opt/ouf/gateway-r3-summary -/var/lib/ouf-authority-mandate-renewal',
                     'ReadWritePaths=/var/lib/ouf-gateway-operations',
                     'ExecStart=/usr/bin/python3 -m tools.gateway_operational_collector authority-mandates --store '
                     '/var/lib/ouf-gateway-operations/gateway-operations.sqlite --status '
                     '/var/lib/ouf-authority-mandate-renewal/status.json'):
            self.assertIn(line + '\n', service)
        self.assertIn('OnUnitActiveSec=15min\n', units[self.a.PROBE_TIMER].decode())


class ApplyTests(Fixture):
    def test_apply_replaces_one_file_installs_units_and_enables_timer(self):
        approved = self.a.digest(self.plan())
        code, report = self.main('--apply', '--plan-sha256', approved)
        self.assertEqual((code, report['status']), (0, 'GATEWAY_AUTHORITY_PROBE_READY'), report)
        self.assertEqual(self.target.read_bytes(), self.new)
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o664)
        units = Path(self.layout['unitDirectory'])
        for name, raw in self.a.probe_units(self.layout).items():
            self.assertEqual((units / name).read_bytes(), raw)
            self.assertEqual((units / name).stat().st_mode & 0o777, 0o644)
        self.assertEqual(self.host.calls, [('daemon-reload',), ('restart', self.a.COLLECTOR_UNIT),
                                           ('start', self.a.PROBE_SERVICE), ('enable', '--now', self.a.PROBE_TIMER)])
        work = self.journal / ('apply-' + approved)
        self.assertEqual((work / 'gateway_operational_collector.py.before').read_bytes(), self.old)
        self.assertTrue((work / 'complete.private.json').exists())
        self.assertEqual((report['probeResult'], report['probeExitStatus']), ('exit-code', '2'))
        code, report = self.main('--apply', '--plan-sha256', approved)
        self.assertEqual((code, report['reason']), (1, 'EXISTING_ATTEMPT_DO_NOT_REPLAY'))

    def test_wrong_hash_changes_nothing(self):
        code, report = self.main('--apply', '--plan-sha256', '0' * 64)
        self.assertEqual((code, report['reason']), (1, 'FRESH_PLAN_HASH_MISMATCH'))
        self.assertEqual(self.target.read_bytes(), self.old)
        self.assertEqual(list(self.journal.iterdir()), [])
        self.assertEqual(self.host.calls, [])

    def test_unexpected_probe_result_holds_after_file_change(self):
        self.host.probe = ('exit-code', '1')
        code, report = self.main('--apply', '--plan-sha256', self.a.digest(self.plan()))
        self.assertEqual((code, report['reason'], report['runtimeChanged']), (1, 'PROBE_RUN_FAILED', True))
        self.assertNotIn(('enable', '--now', self.a.PROBE_TIMER), self.host.calls)
        self.assertTrue(any(p.name == 'failed.private.json' for p in self.journal.rglob('*')))

    def test_successful_probe_is_accepted(self):
        self.host.probe = ('success', '0')
        code, report = self.main('--apply', '--plan-sha256', self.a.digest(self.plan()))
        self.assertEqual(code, 0, report)

    def test_collector_not_restarted_holds(self):
        self.host.restart_activates = False
        approved = self.a.digest(self.plan())
        original = self.a.wait_collector

        def quick(host, old, timeout, sleep=None, monotonic=None):
            return original(host, old, 0, lambda _: None)

        self.a.wait_collector = quick
        try:
            code, report = self.main('--apply', '--plan-sha256', approved)
        finally:
            self.a.wait_collector = original
        self.assertEqual((code, report['reason']), (1, 'COLLECTOR_RESTART_NOT_ACTIVE'))


class RunbookTests(unittest.TestCase):
    def test_pins_and_argument_cleaning(self):
        script = RUNBOOK.read_text()
        pins = dict(line.split('=', 1) for line in script.splitlines() if re.match(r'^(C|L|G|T)=', line))
        a_source = SCRIPT.read_bytes()
        self.assertRegex(pins['C'], r'\A[0-9a-f]{40}\Z')
        self.assertRegex(pins['L'], r'\A[0-9a-f]{64}\Z')
        self.assertEqual(pins['G'], '5b93e56748034ec678d732cfd40ca915695fefb5')
        self.assertEqual(pins['T'], 'a0599016495b4794ab60c8b9f9bc488bbe23ea65f39312176353858fb676bcdf')
        if set(pins['C']) != {'0'}:
            self.assertEqual(pins['L'], sha(a_source))
        result = subprocess.run(['bash', str(RUNBOOK), 'apply', 'x\r'], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b'ricevuti 1 caratteri', result.stderr)


if __name__ == '__main__':
    unittest.main()
