import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / 'scripts/read-discovery-lifecycle-20261109.py'
spec = importlib.util.spec_from_file_location('lifecycle_reader', PATH)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
A, S = 'a' * 64, 'b' * 64


class NativeParsing(unittest.TestCase):
    def test_runc_null_is_empty_but_malformed_output_is_not(self):
        self.assertEqual({A: {'present': False}}, m.runc_rows(b'null', [A]))
        for raw in (b'', b'{}', b'[null]', b'[{"id":"x","id":"y"}]'):
            with self.subTest(raw=raw), self.assertRaises((RuntimeError, ValueError)):
                m.runc_rows(raw, [A])

    def test_duplicate_native_entries_are_not_absence(self):
        row = {'id': A, 'pid': 25, 'status': 'stopped'}
        with self.assertRaisesRegex(RuntimeError, 'DUPLICATE_RUNC_ID'):
            m.runc_rows(m.encoded([row, row]), [A])

    def test_ctr_requires_header_and_closed_status(self):
        for raw in (b'', b'not a task list\n', b'TASK PID STATUS\n' + A.encode() + b' -1 STOPPED\n',
                    b'TASK PID STATUS\n' + A.encode() + b' 2 UNKNOWN_NEW_STATE\n'):
            with self.subTest(raw=raw), self.assertRaises(RuntimeError):
                m.task_rows(raw, [A])
        self.assertEqual({A: {'present': False}}, m.task_rows(b'TASK PID STATUS\n', [A]))

    def test_ctr_retains_stopped_task_for_reconciliation(self):
        raw = ('TASK PID STATUS\n' + A + ' 99 STOPPED\n').encode()
        self.assertEqual({'present': True, 'pid': 99, 'status': 'STOPPED'}, m.task_rows(raw, [A])[A])

    def test_container_metadata_absence_requires_successful_list(self):
        self.assertEqual({A: False}, m.container_ids(b'', [A]))
        self.assertEqual({A: True}, m.container_ids((A + '\n').encode(), [A]))
        with self.assertRaisesRegex(RuntimeError, 'CTR_CONTAINER_LIST_UNPROVEN'):
            m.container_ids(b'error: connection failed\n', [A])

    def test_missing_lease_table_is_distinct_from_partial_table_pair(self):
        self.assertEqual([], m.nft_families(b'{"nftables":[]}', 'leases'))
        raw = m.encoded({'nftables': [{'table': {'name': 'leases', 'family': 'inet'}}]})
        self.assertEqual(['inet'], m.nft_families(raw, 'leases'))
        with self.assertRaises(RuntimeError):
            m.nft_families(b'{"nftables":[{"table":{}}]}', 'leases')

    def test_runtime_journal_uses_per_candidate_binding(self):
        cfg = {'schema': 'v4', 'candidates': {A: {'intentRef': 'x'}, S: {'intentRef': 'y'}}}
        projection = {'schema': 'v4', 'candidate': {'intentRef': 'x'}}
        expected = m.sha(json.dumps(projection, sort_keys=True, separators=(',', ':')).encode())
        self.assertEqual(expected, m.runtime_binding(cfg, A))
        self.assertNotEqual(m.sha(m.encoded(cfg)), expected)
        cfg['candidates'][S]['intentRef'] = 'changed peer'
        self.assertEqual(expected, m.runtime_binding(cfg, A))

    def test_native_mutations_rejected_before_executable_access(self):
        native = m.Native(None)
        for kind, args in (
            ('runc', ['--root', '/run/runc', 'delete', A]),
            ('ctr', ['--address', '/run/containerd/containerd.sock', '--namespace', 'moby', 'tasks', 'delete', A]),
            ('nft', ['-f', '-']), ('nft', ['-j', '-n', 'delete', 'table', 'inet', 't']),
            ('ctr', ['--address', '/tmp/other.sock', '--namespace', 'moby', 'tasks', 'list'])):
            with self.subTest(args=args), patch.object(native, 'binary') as binary:
                with self.assertRaisesRegex(RuntimeError, 'READ_ONLY_NATIVE_COMMAND_REQUIRED'):
                    native.read(kind, '/usr/bin/tool', args)
                binary.assert_not_called()

    def test_nonzero_native_read_cannot_be_interpreted_as_empty(self):
        with tempfile.TemporaryDirectory() as work:
            native = m.Native(work)
            with patch.object(native, 'binary', return_value='/usr/bin/runc'), patch.object(m.subprocess, 'run', return_value=types.SimpleNamespace(returncode=1)):
                with self.assertRaisesRegex(RuntimeError, 'NATIVE_READ_FAILED'):
                    native.read('runc', '/usr/bin/runc', ['--root', '/run/runc', 'list', '--format', 'json'])

    def test_missing_namespace_on_existing_pid_is_incomplete(self):
        with patch.object(Path, 'read_bytes', side_effect=FileNotFoundError), patch.object(Path, 'exists', return_value=True):
            with self.assertRaisesRegex(RuntimeError, 'PROCESS_GENERATION_READ_INCOMPLETE'):
                m.generation({'pid': 42, 'startTicks': 1, 'namespaceInode': 2})


class Fixture:
    def __init__(self):
        self.files = {}; self.seals = {}; self.read_count = 0
        self.root = Path('/etc/ouf/current/registry')
        cfg = {'schema': 'ouf.semantic-docker-runtime-adapter.v4', 'registryRoot': str(self.root),
               'runtimePath': '/usr/bin/runc', 'runtimeSha256': '1' * 64, 'sourceHash': m.sha(b'reviewed data only'), 'candidates': {}}
        self.docs = {role: {'Id': cid, 'State': {'Running': False, 'Pid': 0}, 'HostConfig': {'Runtime': 'ouf-custom'}} for role, cid in (('adapter', A), ('southbound', S))}
        for role, cid in (('adapter', A), ('southbound', S)):
            root = self.root / cid
            template = {'commands': {'nft': '/usr/sbin/nft'}, 'commandHashes': {'nft': '2' * 64}}
            self.put(root / 'template.json', template)
            broker = {'candidateRoot': str(root), 'preparerTemplate': {'path': str(root / 'template.json'), 'sha256': m.sha(self.files[str(root / 'template.json')])}}
            self.put(root / 'broker.json', broker)
            cfg['candidates'][cid] = {'admissionConfigurationHash': m.sha(self.files[str(root / 'broker.json')])}
            driver = {'profile': {'containerId': cid, 'transactionId': cid, 'policy': {'tableName': 'guard_' + role}},
                      'runtimeBinding': {'path': '/usr/bin/runc', 'sha256': '1' * 64, 'root': '/run/runc/moby'},
                      'commands': {'nft': '/usr/sbin/nft'}, 'coordinationJournal': '/etc/ouf/current/coord.json', 'kernel': {'tableName': 'leases'}}
            self.put(root / 'driver.json', driver)
            for name, schema, state in (
                ('broker-state', 'ouf.semantic-deployment-broker-journal.v1', 'CLEANED' if role == 'adapter' else 'PROTECTED'),
                ('admission', 'ouf.semantic-admission-journal.v1', 'CLEANED' if role == 'adapter' else 'PROTECTED'),
                ('preexec', 'ouf.semantic-preexec-journal.v1', 'ROLLED_BACK' if role == 'adapter' else 'PROTECTED')):
                self.put(root / (name + '.json'), {'schema': schema, 'transactionId': cid, 'state': state, 'containerGeneration': {'pid': 100, 'startTicks': 10, 'namespaceInode': 20}, 'namespaceInode': 20})
        for role, cid in (('adapter', A), ('southbound', S)):
            self.put(self.root / cid / 'adapter.json', {'schema': 'ouf.semantic-docker-runtime-journal.v1', 'containerId': cid,
                'configurationHash': m.runtime_binding(cfg, cid), 'state': 'DELETED' if role == 'adapter' else 'DELETING',
                'runtimeRoot': '/run/runc/moby', 'driverHash': m.sha(self.files[str(self.root / cid / 'driver.json')])})
        self.put('/etc/ouf/current/coord.json', {'schema': 'ouf.semantic-lease-coordination.v1', 'state': 'QUIESCED', 'leaseAuthorized': False})
        self.put('/etc/ouf/current/config.json', cfg)
        self.files['/etc/ouf/current/scripts/semantic_provider_docker_runtime.py'] = b'reviewed data only'
        self.files['/usr/local/sbin/ouf-current'] = b'#!/bin/sh\nexec /usr/bin/python3 -I -B /etc/ouf/current/scripts/semantic_provider_docker_runtime.py --configuration /etc/ouf/current/config.json "$@"\n'
        self.h = types.SimpleNamespace(inspect=lambda cid: copy.deepcopy(next(v for v in self.docs.values() if v['Id'] == cid)), frame=lambda v: v,
                                       digest=lambda v: m.sha(m.encoded(v)))
        self.info = {'Runtimes': {'ouf-custom': {'path': '/usr/local/sbin/ouf-current'}}}
        self.s = types.SimpleNamespace(PINS={r: (d['Id'], self.h.digest(d)) for r, d in self.docs.items()}, engine_info=lambda: copy.deepcopy(self.info), exact_path=Path)
        self.processes = {'dockerEndpoints': ['/run/containerd/containerd.sock'], 'shims': {A: [], S: []}}
        self.native = types.SimpleNamespace(read=self.native_read)
        self.task_calls = 0; self.change_tasks = False; self.task_present = False; self.metadata_present = True
        self.native_reads = []

    def put(self, path, value):
        self.files[str(path)] = m.encoded(value)

    def read(self, path, kind):
        self.read_count += 1
        if self.read_count > 40:
            raise RuntimeError('FILE_COUNT_LIMIT')
        raw = self.files[str(path)]
        digest = m.sha(raw)
        if str(path) in self.seals and self.seals[str(path)] != digest:
            raise RuntimeError('SOURCE_CHANGED_BETWEEN_READS')
        self.seals[str(path)] = digest
        return raw

    def native_read(self, kind, path, args, expected=None):
        self.native_reads.append((kind, args))
        if kind == 'runc':
            return b'null'
        if kind == 'ctr' and args[4:] == ['tasks', 'list']:
            self.task_calls += 1
            extra = (S + ' 111 STOPPED\n') if self.task_present or self.change_tasks and self.task_calls > 1 else ''
            return ('TASK PID STATUS\n' + extra).encode()
        if kind == 'ctr' and args[4:] == ['containers', 'list', '--quiet']:
            return (A + '\n' + S + '\n').encode() if self.metadata_present else b''
        if kind == 'ctr':
            return m.encoded({'ID': args[-1]})
        if args[-1] == 'tables':
            return m.encoded({'nftables': [{'table': {'name': 'leases', 'family': f}} for f in ('inet', 'bridge')]})
        return m.encoded({'nftables': [{'set': {'name': 'flow_0', 'elem': []}}]})

    def run(self, work):
        report = {}
        with patch.object(m, 'WRAPPER_SHA', m.sha(self.files['/usr/local/sbin/ouf-current'])), \
             patch.object(m, 'CONFIG_SHA', m.sha(self.files['/etc/ouf/current/config.json'])), \
             patch.object(m, 'process_bindings', return_value=self.processes), \
             patch.object(m, 'file_presence', return_value={'present': False}), \
             patch.object(m, 'generation', return_value={'recordedPidPresent': False, 'recordedGenerationAlive': False}):
            m.collect(report, self.h, self.s, self, self.native, Path(work))
        return report


class Reconciliation(unittest.TestCase):
    def test_full_snapshot_consumed_journals_preserved_and_not_start_qualification(self):
        fixture = Fixture(); before = copy.deepcopy(fixture.files)
        with tempfile.TemporaryDirectory() as work:
            report = fixture.run(work)
        self.assertEqual('DISCOVERY_LIFECYCLE_READ_COMPLETE', report['status'])
        self.assertEqual('NO_NATIVE_RESIDUE_OBSERVED', report['components']['southbound']['classification'])
        self.assertEqual('DELETING', report['components']['southbound']['journalStates']['adapter'])
        self.assertFalse(report['cleanupQualified']); self.assertFalse(report['startQualified'])
        self.assertEqual(before, fixture.files)
        self.assertLessEqual(fixture.read_count, 40)

    def test_terminal_task_does_not_become_no_residue_or_false_drift(self):
        fixture = Fixture(); fixture.task_present = True
        with tempfile.TemporaryDirectory() as work:
            report = fixture.run(work)
        self.assertEqual('CONTAINERD_TASK_REMAINS', report['components']['southbound']['classification'])

    def test_absent_containerd_metadata_does_not_force_info_failure(self):
        fixture = Fixture(); fixture.metadata_present = False
        with tempfile.TemporaryDirectory() as work:
            report = fixture.run(work)
        self.assertFalse(report['components']['adapter']['containerdMetadataPresent'])
        self.assertFalse(any(kind == 'ctr' and args[4:6] == ['containers', 'info'] for kind, args in fixture.native_reads))

    def test_concurrent_task_change_denies_complete(self):
        fixture = Fixture(); fixture.change_tasks = True
        with tempfile.TemporaryDirectory() as work, self.assertRaisesRegex(RuntimeError, 'CONTAINERD_TASKS_CHANGED'):
            fixture.run(work)

    def test_wrong_journal_binding_stops_before_native_commands(self):
        fixture = Fixture()
        path = fixture.root / A / 'adapter.json'; value = m.parse(fixture.files[str(path)])
        value['configurationHash'] = m.sha(fixture.files['/etc/ouf/current/config.json'])
        fixture.put(path, value)
        with tempfile.TemporaryDirectory() as work, self.assertRaisesRegex(RuntimeError, 'BOUND_RUNTIME_JOURNAL_REQUIRED'):
            fixture.run(work)
        self.assertEqual([], fixture.native_reads)

    def test_process_or_owned_handle_prevents_no_residue(self):
        base = {'runc': {'present': False}, 'generations': {}, 'runcDirectory': {'present': False},
                'containerdTask': {'present': False}, 'shimCount': 0, 'ownedTableFamilies': [], 'namespaceHandle': {'present': False}}
        cases = (({'runc': {'present': True}}, 'NATIVE_RUNTIME_OR_PROCESS_PRESENT'),
                 ({'generations': {'preexec': {'recordedGenerationAlive': True}}}, 'NATIVE_RUNTIME_OR_PROCESS_PRESENT'),
                 ({'ownedTableFamilies': ['inet']}, 'GUARD_OR_NAMESPACE_HANDLE_REMAINS'),
                 ({'namespaceHandle': {'present': True}}, 'GUARD_OR_NAMESPACE_HANDLE_REMAINS'),
                 ({'shimCount': 1}, 'SHIM_REMAINS'))
        for change, expected in cases:
            with self.subTest(change=change):
                self.assertEqual(expected, m.classify(dict(base, **change)))


if __name__ == '__main__':
    unittest.main()
