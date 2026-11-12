"""Offline guards and real WAL migration from the two fixed gateway git blobs."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


a = load('collector_episodes', ROOT / 'scripts/apply-gateway-collector-episodes-20261112.py')
b = load('owner_episodes', ROOT / 'scripts/apply-gateway-owner-episodes-20261112.py')
mac = load('gateway_test_mac', ROOT / 'tools/acquisition_read_native/retained_mac.py')
OLD, NEW = 'sha256:' + '1' * 64, 'sha256:' + '2' * 64


def source(commit, file='tools/operational_incidents.py'):
    # Only the explicit CI checkout, never an implicit read of a sibling repo.
    repo = Path(os.environ['OUF_GATEWAY_TEST_SOURCE']).resolve()
    return subprocess.check_output(['git', '-c', 'safe.directory=' + repo.as_posix(), '-C', str(repo),
                                    'show', commit + ':' + file])


def source_module(commit, name):
    raw = source(commit)
    spec = importlib.util.spec_from_loader(name, loader=None)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(raw, name, 'exec'), module.__dict__)
    return module


def owner_fixture():
    args = SimpleNamespace(plan=True, apply=False, plan_sha256=None, container='fixture',
                           expected_current_container='3' * 64, expected_current_image=OLD, candidate_image=NEW, store=Path('/synthetic/db'),
                           store_target='/data/db', bundle_manifest=Path('/bundle/manifest.json'),
                           manifest_sha256='a' * 64, journal_root=Path('/private'),
                           docker_socket='/run/docker.sock', nsenter_bin='/usr/bin/nsenter',
                           summary_path='/summary', incidents_path='/incidents', actuator_path='/actuator/health',
                           readiness_port=8081, readiness_timeout=2, stop_timeout=5)
    old = {'Id': '3' * 64, 'Name': '/fixture', 'Image': OLD, 'Created': 'generation',
           'Config': {'Image': 'old-tag', 'Env': ['PRIVATE_FIXTURE=never-print-me'],
                      'Entrypoint': ['java', '-jar', '/app/owner.jar'], 'Cmd': None,
                      'MacAddress': '02:42:ac:53:01:11', 'User': '10001:10001',
                      'WorkingDir': '/app', 'Labels': None},
           'HostConfig': {'NetworkMode': 'backend', 'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0},
                          'Binds': ['/synthetic:/data:ro'], 'Memory': 536870912, 'OomKillDisable': None},
           'Path': 'java', 'Args': ['-jar', '/app/owner.jar'],
           'Mounts': [{'Type': 'bind', 'Source': '/synthetic', 'Destination': '/data', 'RW': False}],
           'NetworkSettings': {'Networks': {'backend': {'IPAddress': '172.30.0.2', 'MacAddress': '02:42:ac:53:01:11',
                                                        'IPAMConfig': None, 'Aliases': ['fixture', '333333333333']}}},
           'State': {'Running': True, 'Pid': 42, 'StartedAt': 'started', 'Paused': False,
                     'Restarting': False, 'OOMKilled': False}}
    return args, old


def image(i):
    return {'Id': i, 'Architecture': 'amd64', 'Os': 'linux', 'Config': {}}


def owner_plan(args, old, present=True):
    return b.compile_plan(old, image(NEW), image(OLD), args, mac,
                          [old['Path']] + old['Args'], present, args.manifest_sha256)


class OwnerGuards(unittest.TestCase):
    def setUp(self):
        self.args, self.old = owner_fixture()

    def test_wrong_container_and_image_held(self):
        for field, value, reason in [('Id', '5' * 64, 'CURRENT_CONTAINER_MISMATCH'),
                                     ('Image', NEW, 'CURRENT_IMAGE_MISMATCH')]:
            bad = copy.deepcopy(self.old)
            bad[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, reason):
                owner_plan(self.args, bad)

    def test_only_image_delta_and_public_digests(self):
        plan = owner_plan(self.args, self.old)
        expected = copy.deepcopy(self.old['Config'])
        expected['Image'] = NEW
        self.assertEqual({k: v for k, v in plan['request'].items() if k not in ('HostConfig', 'NetworkingConfig')}, expected)
        self.assertEqual(plan['request']['HostConfig'], self.old['HostConfig'])
        self.assertNotIn('never-print-me', json.dumps(b.public_plan(plan)))
        self.assertEqual(b.public_plan(plan)['delta'], ['Image'])
        other = copy.deepcopy(self.old)
        other['State']['Health'] = {'Log': ['volatile']}
        self.assertEqual(b.digest(plan), b.digest(owner_plan(self.args, other)))

    def test_no_episode_index_held_before_docker(self):
        with self.assertRaisesRegex(RuntimeError, 'COLLECTOR_EPISODE_DEDUP_INDEX_REQUIRED'):
            owner_plan(self.args, self.old, False)
        with patch.object(b, 'manifest_guard'), patch.object(b, 'episode_index_present', return_value=False):
            with self.assertRaisesRegex(RuntimeError, 'COLLECTOR_EPISODE_DEDUP_INDEX_REQUIRED'):
                b.collect(None, self.args, mac)

    def test_unexpected_delta_and_defaults_held(self):
        req = b.request(self.old, NEW, mac)
        for field, value in [('Env', []), ('Labels', {}), ('User', 'root'), ('Cmd', []),
                             ('Image', OLD), ('HostConfig', {}), ('MacAddress', None), ('NetworkingConfig', {})]:
            bad = copy.deepcopy(req)
            bad[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, 'UNEXPECTED_CREATE_DELTA'):
                b.delta_guard(self.old, bad, NEW, mac)
        for cfg in ({'Env': ['NEW_KEY=x']}, {'Labels': {b.c.REVISION: b.SOURCE}},
                    {'Volumes': {'/new': {}}}, {'Cmd': ['new-default']}):
            with self.subTest(config=cfg), self.assertRaises(RuntimeError):
                b.c.image_defaults_guard(req, {'Config': cfg})

    def test_wrong_hash_no_attempt(self):
        plan = owner_plan(self.args, self.old)
        with patch.object(b.c, 'begin_attempt') as begin, self.assertRaisesRegex(RuntimeError, 'FRESH_PLAN_HASH_MISMATCH'):
            b.apply_plan(plan, '0' * 64, None, self.args, mac, {})
        begin.assert_not_called()

    def test_manifest_mismatch(self):
        with patch.object(b.c, 'read', return_value=b'{}'), self.assertRaisesRegex(RuntimeError, 'BUNDLE_MANIFEST_HASH_MISMATCH'):
            b.manifest_guard(self.args)

    def test_changed_plan_stops_before_mutation(self):
        plan = owner_plan(self.args, self.old)
        effects = []
        class ReadOnly:
            def api(self, method, path, body=None):
                effects.append(method)
                return [{'Names': ['/fixture']}]
        with patch.object(b.c, 'begin_attempt', return_value=Path('/attempt')), patch.object(b.c, 'record'):
            with self.assertRaisesRegex(RuntimeError, 'PLAN_CHANGED_BEFORE_STOP'):
                b.apply_plan(plan, b.digest(plan), ReadOnly(), self.args, mac, {}, recollect=lambda *x: {})
        self.assertEqual(effects, ['GET'])

    def test_full_lifecycle_without_gate_actuator_is_informational(self):
        plan = owner_plan(self.args, self.old)
        original = self.old
        documents, effects, saved = {original['Id']: copy.deepcopy(original)}, [], {}
        new_id = '4' * 64
        class Synthetic:
            def inspect(self, cid):
                return copy.deepcopy(documents[cid])
            def image(self, i):
                return image(i)
            def api(self, method, path, body=None):
                if method == 'GET':
                    return [{'Names': ['/fixture']}]
                effects.append(path)
                old = documents[original['Id']]
                if '/stop?' in path:
                    old['State'].update(Running=False, Pid=0)
                elif path.endswith('/disconnect'):
                    old['NetworkSettings']['Networks'] = {}
                    del old['Config']['MacAddress']
                elif '/rename?' in path:
                    old['Name'] = '/' + path.split('name=')[1]
                elif path.startswith('/containers/create?'):
                    current = copy.deepcopy(original)
                    current.update(Id=new_id, Image=NEW)
                    current['Config'] = {k: v for k, v in body.items() if k not in ('HostConfig', 'NetworkingConfig')}
                    current['State'].update(Running=False, Pid=0)
                    ep = copy.deepcopy(body['NetworkingConfig']['EndpointsConfig']['backend'])
                    ep['Aliases'].append(new_id[:12])
                    ep['IPAddress'] = ep['IPAMConfig']['IPv4Address']
                    current['NetworkSettings']['Networks']['backend'] = ep
                    documents[new_id] = current
                    return {'Id': new_id}
                elif path.endswith('/start'):
                    documents[new_id]['State'].update(Running=True, Pid=99)
                else:
                    raise AssertionError(path)
        report = {'runtimeChanged': False}
        with patch.object(b.c, 'begin_attempt', return_value=Path('/attempt')), \
                patch.object(b.c, 'record', side_effect=lambda w, n, v: saved.setdefault(n, copy.deepcopy(v))), \
                patch.object(b.c, 'process', return_value=[original['Path']] + original['Args']), \
                patch.object(b, 'episode_index_present', return_value=True), \
                patch.object(b, 'http_observation', return_value={'httpStatus': 503}):
            b.apply_plan(plan, b.digest(plan), Synthetic(), self.args, mac, report,
                         recollect=lambda *x: plan, ready=lambda *x: [403, 403])
        self.assertEqual(report['status'], 'GATEWAY_OWNER_EPISODES_READY')
        self.assertEqual(report['actuatorInformation'], {'httpStatus': 503})
        self.assertTrue(report['runtimeChanged'])
        self.assertEqual(len(effects), 5)
        self.assertIn('/stop?', effects[0])
        self.assertTrue(effects[1].endswith('/disconnect'))
        self.assertIn('/rename?', effects[2])
        self.assertTrue(effects[3].startswith('/containers/create?'))
        self.assertTrue(effects[4].endswith('/start'))
        self.assertIn('complete.private.json', saved)

    def test_readiness_only_posts_both_paths(self):
        with patch.object(b, 'http_observation', side_effect=[{'httpStatus': 403}, {'httpStatus': 404}]) as probe:
            self.assertEqual(b.readiness(self.old, self.args), [403, 404])
        self.assertEqual([call.args[2:] for call in probe.call_args_list],
                         [('POST', self.args.summary_path), ('POST', self.args.incidents_path)])

    def test_mac_negative_origins_and_retained_matrix(self):
        for value in ('ABSENT', None, '', 'bad', '01:00:00:00:00:01', '00:00:00:00:00:00', '02:00:00:00:00:02'):
            bad = copy.deepcopy(self.old)
            if value == 'ABSENT':
                del bad['Config']['MacAddress']
            else:
                bad['Config']['MacAddress'] = value
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                b.request(bad, NEW, mac)
        retained = copy.deepcopy(self.old)
        retained['State'].update(Running=False, Pid=0)
        retained['NetworkSettings']['Networks'] = {}
        del retained['Config']['MacAddress']
        b.c.detached(mac, self.old, retained, self.old['Name'])
        for section, key, value in [('Config', 'MacAddress', None), ('Config', 'MacAddress', ''),
                                    ('Config', 'Hostname', 'new'), ('Config', 'Env', []),
                                    ('HostConfig', 'Memory', 1), ('State', 'Running', True),
                                    ('State', 'StartedAt', 'new')]:
            bad = copy.deepcopy(retained)
            bad[section][key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                b.c.detached(mac, self.old, bad, self.old['Name'])
        for key, value in [('Id', 'new'), ('Image', NEW), ('Mounts', []), ('Args', []),
                           ('NetworkSettings', self.old['NetworkSettings'])]:
            bad = copy.deepcopy(retained)
            bad[key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                b.c.detached(mac, self.old, bad, self.old['Name'])

    def test_unknown_stop_result_no_rollback(self):
        plan = owner_plan(self.args, self.old)
        calls, report = [], {'runtimeChanged': False}
        class Broken:
            def api(self, method, path, body=None):
                calls.append((method, path))
                if method == 'GET':
                    return [{'Names': ['/fixture']}]
                raise OSError('uncertain stop response')
        with patch.object(b.c, 'begin_attempt', return_value=Path('/private/attempt')), patch.object(b.c, 'record'):
            with self.assertRaises(OSError):
                b.apply_plan(plan, b.digest(plan), Broken(), self.args, mac, report, recollect=lambda *x: plan)
        self.assertIsNone(report['runtimeChanged'])
        self.assertTrue(report['oldStopDispatched'])
        self.assertEqual(len(calls), 2)
        self.assertIn('/stop?', calls[-1][1])


class CollectorGuards(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.before, cls.after = source(a.PREDECESSOR_SOURCE), source(a.SOURCE)
        if a.sha(cls.before) != a.BASE_SHA or a.sha(cls.after) != a.TARGET_SHA:
            raise AssertionError('source hashes differ from task')

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name).resolve()
        (root / 'tools').mkdir()
        (root / 'tools/operational_incidents.py').write_bytes(self.before)
        (root / 'tools/operational_incidents.py').chmod(0o664)
        (root / 'tools/gateway_operational_collector.py').write_bytes(
            source(a.SOURCE, 'tools/gateway_operational_collector.py'))
        self.candidate = root / 'candidate.py'
        self.candidate.write_bytes(self.after)
        self.args = SimpleNamespace(plan=True, apply=False, plan_sha256=None, checkout=root, candidate_file=self.candidate,
                                    store=root / 'store.db', journal_root=root / 'journal', expected_commit=a.BASE_SOURCE,
                                    git_bin='/usr/bin/git', systemctl_bin='/usr/bin/systemctl', timeout=2, collector_restart='always',
                                    collector_unit='fixture-collector.service', probe_unit='fixture-probe.service',
                                    collector_exec_start='/usr/bin/python3 -m tools.gateway_operational_collector apisix --store ' + (root / 'store.db').as_posix() + ' --container fixture-api',
                                    probe_exec_start='/usr/bin/python3 -m tools.gateway_operational_collector etcd --store ' + (root / 'store.db').as_posix() + ' --container fixture-etcd')
        self.writer = source_module(a.PREDECESSOR_SOURCE, 'fixture_old_store').SQLiteOperationalIncidentStore(self.args.store)
        self.addCleanup(self.writer.close)
        self.units = {}
        for name, command, kind in ((self.args.collector_unit, self.args.collector_exec_start, 'simple'),
                                    (self.args.probe_unit, self.args.probe_exec_start, 'oneshot')):
            self.units[name] = {'Id': name, 'WorkingDirectory': str(root), 'Type': kind, 'Restart': 'always' if kind == 'simple' else 'no',
                                'ExecStart': {'path': '/usr/bin/python3', 'argv': command, 'ignoreErrors': 'no'},
                                'DropInPaths': '/etc/systemd/system/' + name + '.d/restart.conf' if kind == 'simple' else '',
                                'ActiveState': 'active', 'SubState': 'running', 'InvocationID': 'old-invocation'}

    def read(self, path):
        if str(path) == '/etc/systemd/system/' + self.args.collector_unit + '.d/restart.conf':
            return b'[Service]\nRestart=always\n'
        return path.read_bytes()

    def collect(self, dirty=False, commit=None, status=None):
        def run(argv):
            if '--show-toplevel' in argv:
                return str(self.args.checkout)
            if 'HEAD' in argv:
                return commit or a.BASE_SOURCE
            return status if status is not None else (' M tools/operational_incidents.py\n M dirty' if dirty
                                                     else ' M tools/operational_incidents.py')
        # Host safety flags remain mandatory in production; portable unit reader.
        target = self.args.checkout / 'tools/operational_incidents.py'
        with patch.object(a.c, 'read', side_effect=self.read), \
                patch.object(a.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=target.stat().st_uid)), \
                patch.object(a.grp, 'getgrnam', return_value=SimpleNamespace(gr_gid=target.stat().st_gid)):
            return a.collect(self.args, run=run, observe=lambda args, name: self.units[name])

    def test_clean_exact_plan_and_held_cases(self):
        plan = self.collect()
        self.assertEqual(a.digest(plan), a.digest(self.collect()))
        with self.assertRaisesRegex(RuntimeError, 'CHECKOUT_STATUS_MISMATCH'):
            self.collect(dirty=True)
        for status in ('', 'M  tools/operational_incidents.py', ' M tools/operational_incidents.py\n?? extra'):
            with self.subTest(status=status), self.assertRaisesRegex(RuntimeError, 'CHECKOUT_STATUS_MISMATCH'):
                self.collect(status=status)
        # The installed restart policy is an installation parameter bound to the plan.
        self.args.collector_restart = 'on-failure'
        with self.assertRaisesRegex(RuntimeError, 'COLLECTOR_ACTIVE_SIMPLE_REQUIRED'):
            self.collect()
        self.args.collector_restart = 'always'
        with self.assertRaisesRegex(RuntimeError, 'CHECKOUT_COMMIT_MISMATCH'):
            self.collect(commit='a' * 40)
        self.candidate.write_bytes(b'wrong')
        with self.assertRaisesRegex(RuntimeError, 'CANDIDATE_FILE_HASH_MISMATCH'):
            self.collect()
        self.candidate.write_bytes(self.after)
        (self.args.checkout / 'tools/operational_incidents.py').write_bytes(b'wrong')
        with self.assertRaisesRegex(RuntimeError, 'CURRENT_FILE_HASH_MISMATCH'):
            self.collect()

    def test_old_or_already_updated_current_file_held(self):
        for raw in (source(a.BASE_SOURCE), self.after):
            (self.args.checkout / 'tools/operational_incidents.py').write_bytes(raw)
            with self.assertRaisesRegex(RuntimeError, 'CURRENT_FILE_HASH_MISMATCH'):
                self.collect()

    def test_collector_file_mode_and_dropin_held(self):
        path = self.args.checkout / 'tools/gateway_operational_collector.py'
        original = path.read_bytes()
        path.write_bytes(b'changed')
        with self.assertRaisesRegex(RuntimeError, 'COLLECTOR_FILE_HASH_MISMATCH'):
            self.collect()
        path.write_bytes(original)
        target = self.args.checkout / 'tools/operational_incidents.py'
        target.chmod(0o644)
        with self.assertRaisesRegex(RuntimeError, 'TARGET_OWNERSHIP_OR_MODE_MISMATCH'):
            self.collect()
        target.chmod(0o664)
        self.units[self.args.collector_unit]['DropInPaths'] = ''
        with self.assertRaisesRegex(RuntimeError, 'COLLECTOR_RESTART_DROPIN_REQUIRED'):
            self.collect()
        self.units[self.args.collector_unit]['DropInPaths'] = '/etc/systemd/system/' + self.args.collector_unit + '.d/restart.conf'
        for raw in (b'[Service]\nRestart=no\n', b'[Unit]\nRestart=always\n',
                    b'[Service]\nRestart=always\nRestart=no\n'):
            with patch.object(a.c, 'read', return_value=raw), self.assertRaisesRegex(RuntimeError, 'COLLECTOR_RESTART_DROPIN_MISMATCH'):
                a.check_units(self.args, self.units[self.args.collector_unit], self.units[self.args.probe_unit])

    def test_apply_missing_index_real_sqlite_no_success_or_rollback(self):
        # Restart deliberately fails to migrate the actual old WAL store.
        plan, report, effects = self.collect(), {}, []
        def observe(args, name):
            unit = dict(self.units[name])
            unit.update(InvocationID='new', Result='success', ExecMainStatus='0')
            return unit
        with patch.object(a.c, 'begin_attempt', return_value=Path('/attempt')), \
                patch.object(a.c, 'record') as record, patch.object(a, 'backup'), \
                patch.object(a, 'replace_file') as replace, patch.object(a.c, 'read', side_effect=self.read):
            replace.side_effect = lambda target, raw, frame: target.write_bytes(raw)
            with self.assertRaisesRegex(RuntimeError, 'EPISODE_DEDUP_INDEX_MISSING'):
                a.apply_plan(plan, a.digest(plan), self.args, report, recollect=lambda *x: plan,
                             run=lambda cmd: effects.append(cmd[-1]), observe=observe)
        self.assertTrue(report['runtimeChanged'])
        self.assertNotIn('status', report)
        self.assertNotIn('complete.private.json', [call.args[1] for call in record.call_args_list])
        self.assertEqual(effects, [self.args.collector_unit, self.args.probe_unit])
        self.assertEqual((self.args.checkout / 'tools/operational_incidents.py').read_bytes(), self.after)
        self.assertFalse(b.episode_index_present(self.args.store))

    def test_units_workdir_command_and_inactive_held(self):
        for name, field, value in ((self.args.probe_unit, 'WorkingDirectory', '/different'),
                                    (self.args.collector_unit, 'ExecStart', {}),
                                    (self.args.collector_unit, 'ActiveState', 'inactive')):
            original = self.units[name][field]
            self.units[name][field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                self.collect()
            self.units[name][field] = original

    def test_command_preserves_porcelain_leading_space(self):
        with patch.object(a.subprocess, 'run', return_value=SimpleNamespace(
                returncode=0, stdout=b' M tools/operational_incidents.py\n')):
            self.assertEqual(a.command(['synthetic']), ' M tools/operational_incidents.py')

    def test_wrong_hash_and_existing_journal(self):
        plan = self.collect()
        with patch.object(a.c, 'begin_attempt') as begin, self.assertRaisesRegex(RuntimeError, 'FRESH_PLAN_HASH_MISMATCH'):
            a.apply_plan(plan, '0' * 64, self.args, {})
        begin.assert_not_called()
        for module in (a, b):
            root = self.args.checkout / module.__name__
            root.mkdir()
            (root / ('apply-' + 'a' * 64)).mkdir()
            with patch.object(module.c.Path, 'lstat', return_value=SimpleNamespace(st_mode=0o40700, st_uid=0)):
                with self.assertRaisesRegex(RuntimeError, 'EXISTING_ATTEMPT_DO_NOT_REPLAY'):
                    module.c.begin_attempt(root, 'a' * 64)

    def test_changed_plan_never_replaces_file(self):
        plan = self.collect()
        with patch.object(a.c, 'begin_attempt', return_value=Path('/attempt')), patch.object(a.c, 'record'), \
                patch.object(a, 'replace_file') as replace:
            with self.assertRaisesRegex(RuntimeError, 'PLAN_CHANGED_BEFORE_REPLACE'):
                a.apply_plan(plan, a.digest(plan), self.args, {}, recollect=lambda *x: {})
        replace.assert_not_called()

    def test_unit_show_parsing_excludes_only_execution_fields(self):
        raw = '\n'.join(['Id=fixture.service', 'LoadState=loaded', 'ActiveState=active', 'SubState=running',
                         'User=root', 'Type=simple', 'Restart=on-failure', 'WorkingDirectory=/fixture',
                         'NeedDaemonReload=no', 'FragmentPath=' + (self.args.checkout / 'fixture.service').as_posix(), 'DropInPaths=',
                         'MainPID=42', 'InvocationID=abc', 'ExecMainStatus=0', 'Result=success',
                         'ExecStart={ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -m fixture ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=42 ; code=(null) ; status=0/0 }'])
        with patch.object(a, 'command', return_value=raw), patch.object(a.c, 'read', return_value=b'unit'):
            self.assertEqual(a.unit(self.args, 'fixture.service')['ExecStart']['argv'], '/usr/bin/python3 -m fixture')
        with patch.object(a, 'command', return_value=raw.replace('NeedDaemonReload=no', 'NeedDaemonReload=yes')):
            with self.assertRaisesRegex(RuntimeError, 'LOADED_ROOT_UNIT_REQUIRED'):
                a.unit(self.args, 'fixture.service')


class RealWAL(unittest.TestCase):
    def test_old_store_upgrade_preserves_rows_and_captures_transitions(self):
        old = source_module(a.PREDECESSOR_SOURCE, 'gateway_old_store')
        new = source_module(a.SOURCE, 'gateway_new_store')
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp).resolve() / 'operations.db'
            writer = old.SQLiteOperationalIncidentStore(path)
            try:
                for i in range(3):
                    writer.open_incident(dedup_key=str(i), event_type='fixture', severity='WARNING',
                                         error_code=None, impact_summary='synthetic')
                writer.resolve_incident('1', 'resolved')
                writer.mark_collector_observed('APISIX')
                tables = ('gateway_operational_incident', 'gateway_operational_collector_state',
                          'gateway_incident_transition')
                before = {t: [tuple(r) for r in writer.db.execute('select * from ' + t + ' order by 1')]
                          for t in tables}
                schema = a.store_snapshot(path)['schema']
                self.assertFalse(b.episode_index_present(path))
                args, _ = owner_fixture()
                args.store = path
                with patch.object(b, 'manifest_guard'), self.assertRaisesRegex(
                        RuntimeError, 'COLLECTOR_EPISODE_DEDUP_INDEX_REQUIRED'):
                    b.collect(None, args, mac)
                with self.assertRaisesRegex(RuntimeError, 'EPISODE_DEDUP_INDEX_MISSING'):
                    a.store_counts(path)
                upgraded = new.SQLiteOperationalIncidentStore(path)
                try:
                    self.assertTrue(b.episode_index_present(path))
                    counts = a.store_counts(path, schema)
                    self.assertEqual(counts['incidentCount'], 3)
                    self.assertEqual(counts['baselineCount'], 3)
                    self.assertEqual(counts['transitionCount'], len(before['gateway_incident_transition']))
                    for table, rows in before.items():
                        self.assertEqual([tuple(r) for r in upgraded.db.execute('select * from ' + table + ' order by 1')], rows)
                    again = new.SQLiteOperationalIncidentStore(path)
                    again.close()
                    self.assertEqual(a.store_counts(path, schema), counts)
                    # The episode repair makes closure idempotent and reopening a new ID.
                    upgraded.resolve_incident('1', 'resolved')
                    self.assertEqual(a.store_counts(path)['transitionCount'], counts['transitionCount'])
                    previous_id = upgraded.db.execute(
                        'select incident_id from gateway_operational_incident where dedup_key=?', ('1',)).fetchone()[0]
                    upgraded.open_incident(dedup_key='1', event_type='fixture', severity='WARNING',
                                           error_code=None, impact_summary='synthetic')
                    current_id = upgraded.db.execute(
                        'select incident_id from gateway_operational_incident where dedup_key=?', ('1',)).fetchone()[0]
                    self.assertNotEqual(previous_id, current_id)
                    upgraded.recovering('0', 'recovering')
                    self.assertEqual(a.store_counts(path, schema)['transitionCount'], counts['transitionCount'] + 2)
                    upgraded.db.execute('drop index gateway_incident_transition_dedup')
                    upgraded.db.commit()
                    self.assertFalse(b.episode_index_present(path))
                    with self.assertRaisesRegex(RuntimeError, 'EPISODE_DEDUP_INDEX_MISSING'):
                        a.store_counts(path, schema)
                    upgraded.db.execute('create index gateway_incident_transition_dedup on gateway_incident_transition(dedup_key)')
                    upgraded.db.execute('create trigger fixture_change after insert on gateway_incident_transition begin select 1; end')
                    upgraded.db.commit()
                    with self.assertRaisesRegex(RuntimeError, 'TABLE_OR_TRIGGER_CHANGED'):
                        a.store_counts(path, schema)
                    upgraded.db.execute('drop trigger gateway_incident_capture_update')
                    upgraded.db.commit()
                    with self.assertRaisesRegex(RuntimeError, 'TRANSITION_SCHEMA_MISSING'):
                        a.store_counts(path)
                finally:
                    upgraded.close()
            finally:
                writer.close()

    def test_missing_store_is_not_created(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp).resolve() / 'missing.db'
            with self.assertRaisesRegex(RuntimeError, 'LIVE_WAL_SIDECARS_REQUIRED'):
                b.episode_index_present(path)
            self.assertFalse(path.exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
