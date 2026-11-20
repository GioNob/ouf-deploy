"""Portable, offline R3 reader qualification (no root/runtime required)."""
import ast
from contextlib import ExitStack, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import runpy
import stat
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
READERS = ROOT / 'ops/vps/readers'


def load(name):
    return runpy.run_path(str(READERS / name))


def contexts(ns, **values):
    stack = ExitStack()
    spaces = {id(ns): ns}
    for value in ns.values():
        if callable(value) and hasattr(value, '__globals__') and str(READERS) in value.__code__.co_filename:
            spaces[id(value.__globals__)] = value.__globals__
    for space in spaces.values():
        stack.enter_context(patch.dict(space, values))
    return stack


def tree(root):
    return {str(p.relative_to(root)): (p.stat().st_mode, p.stat().st_mtime_ns,
            hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None)
            for p in root.rglob('*')}


def adapter_journal(cid, version=2, **extra):
    return {'schema': f'ouf.semantic-docker-runtime-journal.v{version}', 'containerId': cid, 'epoch': 1,
            'state': 'FAILED', 'failure': 'SAFE_CODE', 'bootId': '00000000-0000-0000-0000-000000000001',
            'configurationHash': 'c' * 64, 'authorizationSha256': 'd' * 64, 'openedAt': 1,
            'runtimeRoot': '/run/test', 'bundleHash': None, 'driverHash': None, 'generation': None, **extra}


class Readers(unittest.TestCase):
    def test_syntax(self):
        for path in READERS.glob('*.py'):
            compile(path.read_bytes(), str(path), 'exec')

    def test_arguments(self):
        cases = {
            'r3-status.py': [['extra']], 'r3-supervisor-journal.py': [['extra']], 'r3-upper-delta.py': [['extra']],
            'r3-watch.py': [[], ['both'], ['other'], ['adapter', 'extra']],
            'r3-epoch-timeline.py': [[], ['other', '1'], ['adapter', 'x'], ['both', '0'],
                                     ['adapter', '-1'], ['adapter', '1', 'extra'], ['adapter', '1 2']],
            'r3-epoch-diag.py': [['x'], ['0'], ['1', '-1'], ['1', '2', '3']],
            'r3-frame-diag.py': [['x'], ['0'], ['1', 'x'], ['1', '2', '3']],
            'r3-guard-diag.py': [['x'], ['0'], ['1', '2']],
        }
        for name, cases_for_name in cases.items():
            ns = load(name)
            for args in cases_for_name:
                with self.subTest(name=name, args=args), patch.object(sys, 'argv', [name, *args]):
                    with redirect_stdout(io.StringIO()), patch('sys.stderr', io.StringIO()):
                        if name.endswith('-diag.py') or name == 'r3-upper-delta.py':
                            self.assertEqual(ns['main'](), 2)
                        else:
                            self.assertEqual(ns['entry'](ns['main']), 2)
        ns = load('r3-watch.py')
        self.assertEqual(ns['arguments'](['adapter'], ns['ROLES']), 'adapter')
        self.assertEqual(ns['arguments'](['both', '12'], (*ns['ROLES'], 'both'), True), ('both', 12))

    def test_delivery_and_sudoers(self):
        text = (ROOT / 'ops/vps/r3-readers-install.sh').read_text()
        rows = re.findall(r'^fetch (\S+) ([0-9a-f]{64})$', text, re.M)
        self.assertEqual({n for n, _ in rows}, {p.name for p in READERS.iterdir() if p.is_file()})
        for name, expected in rows:
            raw = (READERS / name).read_bytes()
            if os.name == 'nt':
                # A Windows Git checkout may translate the LF delivery blobs.
                raw = raw.replace(b'\r\n', b'\n')
            self.assertNotIn(b'\r', raw)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), expected)
        self.assertRegex(text, r'(?m)^C=[0-9a-f]{40} ')  # zero before review, then the reviewed commit
        sudo = (READERS / '91-ouf-r3-readers').read_text()
        commands = [line for line in sudo.splitlines() if line and not line.startswith('#')]
        self.assertEqual(len(commands), 13)
        for line in commands:
            self.assertTrue(line.startswith('oufadmin ALL=(root) NOPASSWD: /usr/bin/python3.13 -I -B /usr/local/libexec/ouf-readers/r3/'))
            if '*' in line:
                self.assertRegex(line, r'(r3-epoch-timeline\.py (adapter|southbound|both)|r3-epoch-diag\.py|r3-guard-diag\.py) \*$')
                self.assertEqual(line.count('*'), 1)
            self.assertFalse(any(c in line for c in '?[]!'))
        self.assertNotIn('90-ouf-readonly-diagnostics', text)

    def test_copies_only_add_validation(self):
        for name in ('r3-frame-diag.py', 'r3-guard-diag.py'):
            old = ast.parse((ROOT / 'ops/vps' / name).read_text())
            new = ast.parse((READERS / name).read_text())
            main = next(n for n in new.body if isinstance(n, ast.FunctionDef) and n.name == 'main')
            del main.body[0]
            self.assertEqual(ast.dump(old), ast.dump(new))

    def test_fixture_readonly_and_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ids = {'adapter': 'a' * 64, 'southbound': 'b' * 64}
            cfg = {'registryRoot': str(root / 'registry'), 'candidates': {cid: {'role': role} for role, cid in ids.items()},
                   'operation': {'authorizationRoot': str(root / 'authorization')}}
            def put(path, value):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(value))
                return {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
            put(root / 'authorization/1.json', {'decision': 'OPERATE', 'privateKey': 'SECRET_SENTINEL'})
            supervisor = {'statusPath': str(root / 'status.json'), 'coordinator': {'journalPath': str(root / 'lease.json')}}
            cfg['leaseQuiesce'] = {'configuration': put(root / 'supervisor.json', supervisor)}
            put(root / 'status.json', {'state': 'WAITING', 'reason': 'IDLE', 'activationsLastHour': 0,
                                      'epochs': dict.fromkeys(ids, 1), 'token': 'SECRET_SENTINEL', 'updatedAt': 123})
            put(root / 'lease.json', {'state': 'QUIESCED', 'leaseAuthorized': False, 'password': 'SECRET_SENTINEL'})
            for role, cid in ids.items():
                epoch = root / 'registry' / cid / 'epochs/1'
                denial = {'phase': 'start', 'code': 'OPERATION_AUTHORIZATION_DRIFT'}
                journal = adapter_journal(cid) if role == 'adapter' else adapter_journal(cid, 3, driverDenial=denial)
                binding = put(epoch / 'adapter.json', journal)
                put(epoch / 'failure.json', {'failure': {'code': 'ERR', 'reason': 'IDLE', 'secret': 'SECRET_SENTINEL'},
                                           'state': 'password=SECRET_SENTINEL'})
                put(root / 'registry' / cid / 'current', {'epoch': 1, 'journalSha256': binding['sha256']})
                put(epoch / 'broker-denial-start.json', {'reason': 'DENIED', 'token': 'SECRET_SENTINEL'})
            def command(argv, **kwargs):
                if argv[0] == '/usr/bin/docker':
                    self.assertIn(argv[-1], ids.values())
                    return json.dumps([{'State': {'Status': 'exited', 'Pid': 0}, 'HostConfig': {'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0}}, 'Config': {'Env': ['SECRET_SENTINEL']}}])
                self.assertEqual(argv, ['/usr/sbin/nft', '-j', 'list', 'tables'])
                return json.dumps({'nftables': [{'table': {'family': 'inet', 'name': 'ouf_r3_adapter'}}]})
            before = tree(root)
            for name, args in [('r3-status.py', []), ('r3-epoch-timeline.py', ['both', '1'])]:
                ns = load(name)
                output = io.StringIO()
                with contexts(ns, configuration=lambda: cfg, command=command), patch.object(sys, 'argv', [name, *args]), redirect_stdout(output):
                    self.assertEqual(ns['main'](), 0)
                self.assertNotIn('SECRET_SENTINEL', output.getvalue())
                self.assertNotIn('privateKey', output.getvalue())
                rows = [json.loads(line) for line in output.getvalue().splitlines()]
                if name == 'r3-status.py':
                    journals = {row['role']: row['epoch'] for row in rows if row.get('step') == 'role'}
                    status = next(row for row in rows if row.get('step') == 'supervisor')
                    self.assertEqual(status['updatedAt'], 123)
                    self.assertIsNone(status['leaseRecovery'])
                else:
                    journals = {row['role']: row for row in rows if row.get('file') == 'adapter.json'}
                self.assertNotIn('driverDenial', journals['adapter'])
                self.assertEqual(journals['southbound']['driverDenial'], denial)
                self.assertEqual(before, tree(root))

    def test_recovery_projection_selects_scope_and_redacts_checkpoint(self):
        ns = load('r3-status.py')
        root = Path(ns['ROOT'])
        configuration_sha, scope = 'a' * 64, 'd' * 48
        selector = json.dumps({'configuration': configuration_sha, 'invocation': scope},
                              sort_keys=True, separators=(',', ':')).encode()
        scope_ref = hashlib.sha256(selector).hexdigest()
        recovery_root = root / 'supervisor/state/recovery'
        sup = {'recoveryJournalRoot': str(recovery_root), 'statusPath': '/fixture/status.json',
               'coordinator': {'journalPath': '/fixture/lease.json'}}
        status = dict(state='WAITING', reason='DNS_WINDOW_TOO_SHORT', activationsLastHour=2,
                      epochs={'adapter': 1, 'southbound': 2}, updatedAt=123, recoveryScope=scope)
        row = {'schema': 'ouf.bounded-recovery.v1', 'contextRef': scope_ref, 'state': 'RETRY_WAIT',
               'attempts': 1, 'nextWall': 130, 'nativeOutput': 'SECRET_SENTINEL 192.0.2.100'}
        incident = dict(schema='ouf.semantic-lease-recovery-incident.v1', scopeRef=scope_ref,
                        authorizationSequence=7, epochs=status['epochs'], incidentCount=1, failedAt=120,
                        pausedAt=121, resumedAt=None, nextRetryAt=130, phase='LOCK_ACQUIRE',
                        code='COMMON_LOCK_TIMEOUT', revocation='VERIFIED', stateAtFailure='ACTIVE',
                        leaseRemainingMs=4315, lockWaitMs=473, deadlineMonotonic=55)
        read_recovery = Mock(side_effect=lambda _: json.dumps(row).encode())
        cfg = {'operation': {'authorizationRoot': str(root / 'authorization')},
               'leaseQuiesce': {'configuration': {'sha256': configuration_sha}}}
        with contexts(ns, configuration=lambda: cfg, bound=lambda _: sup, document=lambda path: (
                status if path == sup['statusPath'] else {'state': 'QUIESCED', 'leaseAuthorized': False}),
                candidates=lambda _: {}, read_recovery=read_recovery,
                read=lambda _: b'{"decision":"OPERATE"}', command=lambda _: '{"nftables":[]}'), \
                patch('pathlib.Path.glob', return_value=[Path('1.json')]), patch.object(sys, 'argv', ['status']):
            timing = dict(schema='ouf.lease-renewal-timing.v1', branch=[0, 75], previous=None,
                          current=dict(sequence=1, events=[['sampleAfter', 104, 21.75, 125.75]], truncated=False))
            for detail in (None, incident, {**incident, 'timing': timing},
                           {**incident, 'code': 'R3_SEMANTIC_CLOSE_UNVERIFIED'}):
                with self.subTest(incident=detail):
                    if detail is not None:
                        row['lastIncident'] = detail
                    output = io.StringIO()
                    with redirect_stdout(output):
                        self.assertEqual(ns['main'](), 0)
                    public = output.getvalue()
                    self.assertNotIn('SECRET_SENTINEL', public)
                    self.assertNotIn('192.0.2.100', public)
                    self.assertNotIn(scope, public)
                    projected = next(r for r in map(json.loads, public.splitlines()) if r['step'] == 'supervisor')
                    expected = {'timing': None, **detail} if detail is not None else None
                    self.assertEqual(projected['leaseRecovery'], {'scopeRef': scope_ref, 'state': 'RETRY_WAIT',
                        'attempts': 1, 'nextRetryAt': 130, 'lastIncident': expected})
                    read_recovery.assert_called_with(recovery_root / scope)
            row['lastCacheRollover'] = ['cacheRenewed', 118, 116, 117, 117.01]
            self.assertEqual(ns['lease_recovery'](sup, status, configuration_sha)['lastCacheRollover'],
                             row['lastCacheRollover'])
            for invalid in (['ready', 118], ['cacheWait', 100, 116, 'SECRET_SENTINEL', 0]):
                row['lastCacheRollover'] = invalid
                with self.assertRaisesRegex(ValueError, 'RECOVERY_CACHE_ROLLOVER_INVALID'):
                    ns['lease_recovery'](sup, status, configuration_sha)
            del row['lastCacheRollover']
            read_recovery.reset_mock()
            for altered in ({'recoveryScope': '../other'}, {'recoveryScope': 'b' * 64}):
                with self.assertRaises(ValueError):
                    ns['lease_recovery'](sup, status | altered, configuration_sha)
            with self.assertRaises(ValueError):
                ns['lease_recovery'](sup | {'recoveryJournalRoot': '/unbound'}, status, configuration_sha)
            read_recovery.assert_not_called()
            for bad in ({'code': 'SECRET_SENTINEL'}, {'phase': '192.0.2.100'}, {'deadlineMonotonic': float('nan')},
                        {'timing': {**timing, 'branch': ['SECRET_SENTINEL', 1]}},
                        {'pausedAt': None}, {'stderr': 'SECRET_SENTINEL'}, {'scopeRef': 'b' * 64}):
                row['lastIncident'] = incident | bad
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(ns['entry'](ns['main']), 2)
                self.assertNotIn('SECRET_SENTINEL', output.getvalue())
            row['lastIncident'] = incident
            with self.assertRaisesRegex(ValueError, 'RECOVERY_CHECKPOINT_INVALID'):
                ns['lease_recovery'](sup, status, 'b' * 64)

    def test_recovery_read_is_bounded_and_requires_stable_private_file(self):
        ns = load('r3_common.py')
        directory = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0, st_gid=0)
        record = dict(st_dev=1, st_ino=2, st_mode=stat.S_IFREG | 0o600, st_uid=0,
                      st_gid=0, st_nlink=1, st_size=2, st_mtime_ns=3, st_ctime_ns=4)
        fake_os = SimpleNamespace(O_RDONLY=0, O_NOFOLLOW=1, O_CLOEXEC=2, O_NONBLOCK=4, O_DIRECTORY=8,
                                  open=Mock(), close=Mock(), fstat=Mock(), read=Mock(return_value=b'{}'), stat=Mock())
        with contexts(ns, os=fake_os):
            for change in ({}, {'st_size': 65537}, {'st_nlink': 2}, {'st_mode': stat.S_IFLNK | 0o600}):
                with self.subTest(change=change):
                    file = SimpleNamespace(**(record | change))
                    fake_os.open.side_effect = [1, 2, 3]
                    fake_os.fstat.side_effect = [directory, file, file]
                    fake_os.stat.return_value = file
                    fake_os.read.reset_mock()
                    if change:
                        with self.assertRaisesRegex(ValueError, 'RECOVERY_FILE_CUSTODY_INVALID'):
                            ns['read_recovery'](PurePosixPath('/scope'))
                        fake_os.read.assert_not_called()
                    else:
                        self.assertEqual(ns['read_recovery'](PurePosixPath('/scope')), b'{}')
                        fake_os.read.assert_called_once_with(3, 65537)
                        fake_os.open.assert_any_call('scope', 15, dir_fd=1)
                        fake_os.open.assert_called_with('recovery.json', 7, dir_fd=2)
            file = SimpleNamespace(**record)
            fake_os.open.side_effect = [1, 2, 3]
            fake_os.fstat.side_effect = [directory, file, file]
            fake_os.stat.return_value = SimpleNamespace(**(record | {'st_ino': 8}))
            with self.assertRaisesRegex(ValueError, 'RECOVERY_FILE_CHANGED'):
                ns['read_recovery'](PurePosixPath('/scope'))

    def test_driver_denial_projection_validates_exact_shape(self):
        ns = load('r3_common.py')
        cid = 'a' * 64
        valid = adapter_journal(cid, 3, driverDenial=None)
        self.assertEqual(ns['driver_denial_fields'](ns['adapter_journal'](json.dumps(valid).encode(), cid, 1)),
                         {'driverDenial': None})
        for detail in ({'phase': 'prepare', 'code': 'D'}, {'phase': 'hook', 'code': 'lowercase'},
                       {'phase': 'hook', 'code': 'D' * 81}, {'phase': 'hook', 'code': 'D', 'stderr': 'SECRET'}):
            with self.subTest(detail=detail), self.assertRaises(ValueError):
                ns['driver_denial_fields'](valid | {'driverDenial': detail})
        with self.assertRaises(ValueError):
            ns['driver_denial_fields'](valid | {'state': 'DELETING', 'driverDenial': {'phase': 'hook', 'code': 'D'}})
        for journal in (adapter_journal(cid, 2, driverDenial=None), adapter_journal(cid, 3)):
            with self.assertRaises(ValueError):
                ns['adapter_journal'](json.dumps(journal).encode(), cid, 1)
        with self.assertRaises(ValueError):
            ns['adapter_journal'](json.dumps(valid).encode().replace(b'null}', b'null,"driverDenial":null}'), cid, 1)

    def test_journal_filter(self):
        ns = load('r3-supervisor-journal.py')
        def command(argv, **kwargs):
            self.assertEqual(argv, ['/usr/bin/journalctl', '-u', 'ouf-semantic-lease-supervisor-v2', '-q', '--no-pager', '-o', 'short-iso', '-n', '200'])
            return '\n'.join(['safe', 'Token SECRET_SENTINEL', 'SECRET SECRET_SENTINEL', 'password SECRET_SENTINEL',
                              'Authorization SECRET_SENTINEL', 'x' * 500])
        output = io.StringIO()
        with contexts(ns, command=command), patch.object(sys, 'argv', ['journal']), redirect_stdout(output):
            self.assertEqual(ns['main'](), 0)
        self.assertEqual(output.getvalue().splitlines(), ['safe', 'x' * 300])

    def test_proc_membership_and_pid_generation(self):
        ns = load('r3-watch.py')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = root / '12'
            base.mkdir()
            cid = 'a' * 64
            (base / 'cgroup').write_text('0::/system.slice/docker-' + cid + '.scope\n')
            (base / 'comm').write_text('runc:[2:INIT]\n')
            (base / 'cmdline').write_bytes(b'runc\0init\0')
            (base / 'stat').write_text('12 (runc init) ' + ' '.join(['0'] * 19 + ['42']))
            before = tree(root)
            with contexts(ns, PROC=root):
                self.assertTrue(ns['member'](12, cid))
                self.assertFalse(ns['member'](12, 'a' * 63))
                self.assertEqual(ns['processes'](cid), [(12, 42, 'runc-init')])
                self.assertTrue(ns['same'](12, 42, cid))
                self.assertFalse(ns['same'](12, 43, cid))
            self.assertEqual(before, tree(root))

    def test_diag_fixture_readonly(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for role in ('adapter', 'southbound'):
                broker = root / 'versions/7/broker' / (role + '.json')
                broker.parent.mkdir(parents=True, exist_ok=True)
                broker.write_text(json.dumps({'registryRoot': str(root / 'registry'), 'containerId': role}))
                epoch = root / 'registry' / role / 'epochs/1'
                epoch.mkdir(parents=True)
                (epoch / 'epoch.json').write_text(json.dumps({'state': 'FAILED', 'private': 'SECRET_SENTINEL'}))
                denial = {'phase': 'hook', 'code': 'GATE_DENIED'}
                (epoch / 'adapter.json').write_text(json.dumps(adapter_journal(role, 3, driverDenial=denial)))
                docs = root / 'versions/8/documents' / role
                docs.mkdir(parents=True)
                (docs / 'preparer-template.json').write_text(json.dumps({'kernel': {}}))
                (docs / 'transport.json').write_text(json.dumps({'networkBindings': []}))
            before = tree(root)
            for name, location in [('r3-epoch-diag.py', root), ('r3-frame-diag.py', root / 'versions'),
                                   ('r3-guard-diag.py', root / 'versions')]:
                ns = load(name)
                output = io.StringIO()
                with contexts(ns, ROOT=location), patch.object(os, 'geteuid', lambda: 0, create=True), \
                        patch.object(sys, 'argv', [name]), redirect_stdout(output):
                    self.assertEqual(ns['main'](), 0)
                self.assertNotIn('SECRET_SENTINEL', output.getvalue())
                if name == 'r3-epoch-diag.py':
                    rows = [json.loads(line) for line in output.getvalue().splitlines()]
                    self.assertEqual([row['driverDenial'] for row in rows if row.get('file') == 'adapter.json'],
                                     [denial, denial])
                self.assertEqual(before, tree(root))

    def test_watch_snapshot_readonly(self):
        ns = load('r3-watch.py')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = root / '12'
            (base / 'fd').mkdir(parents=True)
            (base / 'net').mkdir()
            (base / 'limits').write_text('Max open files            1024 1024 files\n')
            for name in ('tcp', 'tcp6'):
                (base / 'net' / name).write_text('header\n0: 00000000:24E3 00000000:0000 0A\n')
            calls = []
            def command(argv, **kwargs):
                calls.append(argv)
                return 'eth0 UP 172.18.0.2/16\n'
            before = tree(root)
            with contexts(ns, PROC=root, same=lambda *_: True, command=command):
                row = ns['snapshot'](12, 42, 'a' * 64, 9443)
            self.assertTrue(row['LISTEN'])
            self.assertEqual(calls, [['/usr/bin/nsenter', '--net=/proc/12/ns/net', '/usr/bin/ip', '-br', k] for k in ('link', 'addr')])
            self.assertEqual(before, tree(root))

    def test_port_from_bound_configuration(self):
        ns = load('r3-watch.py')
        cfg = {'candidates': {'a' * 64: {'role': 'adapter'}, 'b' * 64: {'role': 'southbound'}},
               'admissionConfigurations': {'a' * 64: {'transportBinding': 'a'}, 'b' * 64: {'transportBinding': 'b'}}}
        transports = {'a': {'networkBindings': [{'ipv4': '10.0.0.1'}], 'transport': []},
                      'b': {'networkBindings': [{'ipv4': '10.0.0.2'}],
                            'transport': [{'destination': '10.0.0.1', 'protocol': 'tcp', 'port': 9443}]}}
        def bound(value):
            return value if isinstance(value, dict) else transports[value]
        with contexts(ns, bound=bound):
            self.assertEqual(ns['port_for'](cfg, 'adapter'), 9443)
            with self.assertRaises(ValueError):
                ns['port_for'](cfg, 'southbound')
    def test_watch_deadlines(self):
        for outcome in ('GONE', 'STILL_UP_20S', 'TIMEOUT_25M'):
            ns = load('r3-watch.py')
            now = [0]
            def sleep(seconds):
                now[0] += seconds
            def processes(cid):
                if outcome == 'TIMEOUT_25M' or (outcome == 'GONE' and now[0] > 0):
                    return []
                return [(12, 42, 'python')]
            output = io.StringIO()
            with contexts(ns, configuration=lambda: {'candidates': {'a' * 64: {'role': 'adapter'}, 'b' * 64: {'role': 'southbound'}}},
                          port_for=lambda *_: 9443, processes=processes, same=lambda *_: True,
                          snapshot=lambda *_: {'pid': 12}), patch.object(ns['time'], 'monotonic', lambda: now[0]), \
                    patch.object(ns['time'], 'sleep', sleep), patch.object(sys, 'argv', ['watch', 'adapter']), redirect_stdout(output):
                self.assertEqual(ns['main'](), 1 if outcome == 'TIMEOUT_25M' else 0)
            self.assertEqual(json.loads(output.getvalue().splitlines()[-1])['state'], outcome)
            self.assertLessEqual(now[0], 1500)


if __name__ == '__main__':
    unittest.main()
