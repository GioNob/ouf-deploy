"""Offline qualification of the emitted R3 v19 runtime and normal upgrade."""
from contextlib import nullcontext
from copy import deepcopy
import io
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_runtime_v52_epochs as V52
from test_semantic_provider_r3_v18 import C, V12, fixture, upgrade
from tools.semantic_provider_admission_v2 import broker_v2 as B


CID = V52.CID
PREFIX = 'versions/19/'
CONFIG = 'runtime-configuration.json'
SUPERVISOR_CONFIG = 'supervisor/configuration.json'
MISSING = b'container does not exist\n'


def composition_fixture():
    inputs, v17 = fixture()
    old = C.compose(inputs, 18, sequence=18, supersedes=C.sha(v17['authorization']))
    return inputs, old, C.compose(inputs, 19, sequence=19, supersedes=C.sha(old['authorization']))


class CompositionV19(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inputs, cls.old, cls.result = composition_fixture()

    def test_v18_golden(self):
        # Recorded from 6e5ff93b before adding the v19 overlay.
        actual = {key: C.sha(C.canonical(self.old[key])) for key in ('hashes', 'inputHashes', 'audit', 'layout')}
        self.assertEqual(actual | {'authorization': C.sha(self.old['authorization'])}, {
            'hashes': '637ba6f81ebe4406a17f449f9d8cb25d186a6089f923fe4304d6019978c231eb',
            'inputHashes': '9b23c1ffd7c65180b07006c1da38cbea528de8420a3fe0f3cb09f1a3b1bb6a5a',
            'audit': '302d3b526d20af5f200c95a7258d9351254ce50220df3425aa7a3749db8e8aab',
            'layout': 'd77218902b88dd4a6ae8dbf8747b5ecc284b12dc1b13217978c02b3fdaf0785c',
            'authorization': '10bffbf8c2163694c441d6bca073c7ce3520d2abd1e41abdf943ef06e5c228b9',
        })

    def test_operate_and_probe_trust_the_emitted_v19_runtime(self):
        # R-031: operate/probe check the installed runtime against a closed hash set.
        from tools.semantic_provider_r3 import install_common as I
        if b'\r\n' in (I.ROOT / C.RUNTIME).read_bytes():
            self.skipTest('CRLF working tree: delivered bytes are LF (checked on Linux CI)')
        trusted = I.installed_runtime_hashes()
        for result, version in ((self.old, 18), (self.result, 19)):
            raw = result['documents'][f'versions/{version}/source/' + C.RUNTIME]
            self.assertIn(C.sha(raw), trusted, version)
        self.assertEqual(len(trusted), 3)

    def test_v19_golden(self):
        # Captured at 0a5840ca and retained from the task-85 diagnostic.
        result = self.result
        actual = {key: C.sha(C.canonical(result[key])) for key in ('hashes', 'inputHashes', 'audit', 'layout')}
        self.assertEqual(actual | {'authorization': C.sha(result['authorization'])}, {
            'hashes': '3bdd788787532520b2b9463a0e5c045ea4d348766e88a420d38935723c8d82ff',
            'inputHashes': '9b23c1ffd7c65180b07006c1da38cbea528de8420a3fe0f3cb09f1a3b1bb6a5a',
            'audit': '302d3b526d20af5f200c95a7258d9351254ce50220df3425aa7a3749db8e8aab',
            'layout': 'bf51fc33a58f4833a0e826465fc4f64569115afaaf2af75e91b43bda12f6e1e2',
            'authorization': '4196bbc40c677a3960389cdd6eda4fc0d4ca2cb36e9b85a543d634faea8a8945',
        })

    def test_issuance_and_final_source_seal(self):
        inputs, old, new = self.inputs, self.old, self.result
        self.assertEqual(C.SOURCE_MAP_V19, C.SOURCE_MAP_V18)
        self.assertEqual(C.SOURCE_INPUTS_V19, C.SOURCE_INPUTS_V18)
        self.assertEqual(C.DATA_INPUTS_V19, C.DATA_INPUTS_V18)
        self.assertTrue(C.input_set(**inputs))
        self.assertEqual(new['inputHashes'], old['inputHashes'])

        previous, auth = [C.document(result['authorization']) for result in (old, new)]
        head = dict(decision='OPERATE', sequence=18, sha256=C.sha(old['authorization']), authorization=previous)
        issuer = V12.F.load('scripts/issue-semantic-provider-operation-authorization.py', 'v19_issuer')
        self.assertEqual(issuer.compose_next(inputs, head, auth['issuedAt']), new)
        self.assertEqual((auth['sequence'], auth['supersedes']), (19, head['sha256']))
        self.assertEqual(auth['runtimeConfigurationSha256'], new['hashes'][PREFIX + CONFIG])
        self.assertEqual(auth['acceptanceSha256'], previous['acceptanceSha256'])
        self.assertEqual(C.ACCEPT.decode_manifest(inputs['files']['acceptance'])['generation'], 7)
        self.assertEqual(auth['lease'], previous['lease'])
        self.assertEqual(new['audit'], old['audit'])

        docs, old_docs = new['documents'], old['documents']
        for path, raw in docs.items():
            if path.startswith(PREFIX + 'source/'):
                target = path.removeprefix(PREFIX)
                if target != 'source/' + C.RUNTIME:
                    self.assertEqual(raw, old_docs['versions/18/' + target], target)
                self.assertEqual(new['hashes'][path], C.sha(raw))
        cfg, old_cfg = [C.document(d[p + CONFIG]) for d, p in ((docs, PREFIX), (old_docs, 'versions/18/'))]
        self.assertEqual(cfg['candidates'], old_cfg['candidates'])
        self.assertEqual(cfg['sourceHash'], new['hashes'][PREFIX + 'source/' + C.RUNTIME])
        self.assertNotEqual(cfg['sourceHash'], old_cfg['sourceHash'])
        sup, old_sup = [C.document(d[p + SUPERVISOR_CONFIG])
                        for d, p in ((docs, PREFIX), (old_docs, 'versions/18/'))]
        self.assertEqual(sup['sourceHashes'], old_sup['sourceHashes'])
        old_coordinator, coordinator = old_sup['coordinator'], sup['coordinator']
        old_dns, dns = old_coordinator['dnsProfile'], coordinator['dnsProfile']
        self.assertEqual(dns, old_dns | {'path': old_dns['path'].replace('/versions/18/', '/versions/19/')})
        self.assertEqual(coordinator, old_coordinator | {'dnsProfile': dns})
        self.assertEqual(sup['leaseRenewal'], C.document(inputs['files']['leaseRenewal']))
        for role in C.ROLES:
            path = f'documents/{role}/preparer-template.json'
            template = C.document(docs[PREFIX + path])
            self.assertEqual(template, C.document(old_docs['versions/18/' + path]))
            self.assertEqual(template['budgetSeconds'], 12)
            self.assertEqual(template['kernel']['generation'], 2)

    def test_missing_or_duplicate_runtime_anchor_is_denied(self):
        path = C.SOURCE_MAP_V19[C.RUNTIME]
        original = self.inputs['sources'][path]
        anchor = b"        if not failed and operation in ('state', 'delete')"
        for replacement in (anchor.replace(b'not failed', b'(not failed)'), anchor + b'\n' + anchor):
            with self.subTest(replacement=replacement), self.assertRaisesRegex(
                    C.A.OperationDenied, '^R3_V19_SOURCE_CONTRACT_DRIFT$'):
                inputs = self.inputs | {'sources': self.inputs['sources'] | {path: original.replace(anchor, replacement)}}
                C.compose(inputs, 19, sequence=19, supersedes=C.sha(self.old['authorization']))

    def test_normal_upgrade_plan_binds_v19_wrapper_unit_and_documents(self):
        observe = V12.NativeBindingsAndUpgrade().observation_fixture
        with observe((self.inputs, self.old, self.result), version=19) as (args, _, _, _):
            state, composed = upgrade.observe(args)
            self.assertEqual(composed, self.result)
            self.assertEqual((state['versionBefore'], state['versionAfter']), (18, 19))
            self.assertIn(f'/{PREFIX}source/{C.RUNTIME}', state['wrapperProposed']['text'])
            self.assertIn(f'/{PREFIX}{CONFIG}', state['wrapperProposed']['text'])
            self.assertIn(f'/{PREFIX}source/scripts/semantic-provider-lease-supervisor-v2.py', state['unit']['text'])
            self.assertIn(composed['hashes'][PREFIX + SUPERVISOR_CONFIG], state['unit']['text'])
            self.assertEqual(state['unit']['sha256'], C.sha(state['unit']['text'].encode('ascii')))
            self.assertEqual({row['sha256'] for row in state['writes']['files']},
                             {C.sha(raw) for raw in composed['documents'].values()})


class RuntimeV19(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _, _, result = composition_fixture()
        cls.source = result['documents'][PREFIX + 'source/' + C.RUNTIME]

    def setUp(self):
        self.bridge = bridge = V52.PortableFailedCleanup()
        bridge.setUp()
        self.addCleanup(bridge.doCleanups)
        self.r = bridge.r = C.contract_module(self.source, 'v19_runtime')
        self.r.Path = Path
        bridge.prepared()
        self.raw_stderr = MISSING
        self.probe_failure = None
        self.simulate_base = bridge.simulate
        bridge.simulate = self.simulate

    def simulate(self, args, **kw):
        if self.probe_failure is not None and args == self.probe:
            self.bridge.calls.append(args)
            raise self.probe_failure
        if args[0] == '/runc' and ('kill' in args or 'delete' in args) and hasattr(kw['stderr'], 'write'):
            kw['stderr'].write(self.raw_stderr)
            self.assertEqual(kw['timeout'], 10)
            self.assertEqual(kw['env'], self.r.ENV)
        return self.simulate_base(args, **kw)

    @property
    def probe(self):
        return ['/runc', '--root', str(self.bridge.runtime_root), 'state', CID]

    def receipt(self, **change):
        bridge = self.bridge
        bridge.files[str(bridge.folder/'runtime-cleanup.json')] = C.canonical({
            'schema': 'ouf.semantic-docker-runtime-cleanup.v1', 'epoch': bridge.record['epoch'],
            'operation': 'delete', 'at': 100, 'runcStatusBefore': 'absent',
        } | change)

    def forwarded(self, operation, expected=MISSING, code=1):
        bridge = self.bridge
        before, files = deepcopy(bridge.record), bridge.files.copy()
        argv = ['--root', str(bridge.runtime_root), '--log', str(bridge.root/'runc.log'), '--log-format', 'json', operation]
        argv += ['--all', CID, 'SIGKILL'] if operation == 'kill' else ['--force', CID]
        stderr = io.BytesIO()
        bridge.calls.clear()
        with patch.object(self.r.sys, 'stderr', SimpleNamespace(buffer=stderr)):
            self.assertEqual(bridge.run_op(operation, argv=argv), code)
        self.assertEqual(stderr.getvalue(), expected)
        self.assertEqual(bridge.calls, [self.probe, ['/runc', *argv]])
        self.assertEqual(bridge.record, before)
        self.assertEqual(bridge.files, files)
        self.assertFalse(bridge.transitions)
        bridge.quiesce.assert_not_called()

    def test_cleaned_failed_epoch_relays_exact_argv_stderr_and_status(self):
        self.bridge.state = None
        self.bridge.forward_code = 1
        self.receipt()
        self.forwarded('kill')
        self.forwarded('delete')
        # The probe and requested operation need not produce identical diagnostics.
        self.raw_stderr = MISSING + b'x' * 20000
        self.bridge.forward_code = 7
        self.forwarded('kill', self.raw_stderr[:16384], 7)

    def test_pending_cleanup_keeps_the_existing_path(self):
        bridge = self.bridge
        bridge.state = None
        bridge.denied('kill', 'FAILED_PREPARED_EPOCH_REQUIRES_RECOVERY')
        self.assertEqual(bridge.calls, [self.probe])
        self.assertFalse(bridge.transitions)
        self.assertEqual(bridge.run_op('delete'), 0)
        self.assertEqual(bridge.transitions, ['DELETING', 'FAILED'])
        self.assertEqual([args[-1] for args in bridge.calls if args[0] == '/python'], ['rollback', 'cleanup'])
        self.assertEqual(C.document(bridge.files[str(bridge.folder/'runtime-cleanup.json')])['runcStatusBefore'], 'absent')

    def test_present_runc_keeps_kill_and_rejects_reappearance_after_receipt(self):
        bridge = self.bridge
        self.assertEqual(bridge.run_op('kill'), 0)
        self.assertEqual(bridge.calls[-1][-3:], ['kill', CID, 'SIGTERM'])
        self.receipt()
        before = bridge.files.copy()
        for operation in ('kill', 'delete'):
            bridge.calls.clear()
            bridge.denied(operation, 'FAILED_PREPARED_EPOCH_REQUIRES_RECOVERY')
            self.assertEqual(bridge.calls, [self.probe])
        self.assertEqual(bridge.files, before)
        self.assertFalse(bridge.transitions)

    def test_unproven_absence_and_invalid_receipt_do_not_forward(self):
        bridge = self.bridge
        bridge.state = None
        self.receipt()
        for diagnostic, code, error in (
            (MISSING, 1, subprocess.TimeoutExpired(self.probe, 10)),
            (b'permission denied\n', 1, None),
            (b'prefix container does not exist\n', 1, None),
            (MISSING, 2, None),
        ):
            with self.subTest(diagnostic=diagnostic, code=code, error=error):
                bridge.absence, bridge.probe_code, self.probe_failure = diagnostic, code, error
                self.assert_cleanup_denied()
        bridge.absence, bridge.probe_code, self.probe_failure = MISSING, 1, None
        self.receipt(epoch=2)
        self.assert_cleanup_denied()

    def assert_cleanup_denied(self):
        bridge = self.bridge
        files = bridge.files.copy()
        for operation in ('kill', 'delete'):
            bridge.calls.clear()
            bridge.denied(operation, 'FAILED_PREPARED_EPOCH_REQUIRES_RECOVERY')
            self.assertEqual(bridge.calls, [self.probe])
        self.assertEqual(bridge.files, files)
        self.assertFalse(bridge.transitions)
        bridge.quiesce.assert_not_called()

    def test_deleted_epoch_requires_current_boot_bound_root_and_absence(self):
        bridge = self.bridge
        bridge.record.update(state='DELETED', failure=None)
        for operation in ('kill', 'delete'):
            bridge.denied(operation, 'RUNTIME_PHASE_INACTIVE_UNEXPECTED_CONTAINER')
        bridge.state, bridge.forward_code = None, 1
        bridge.absence = b'permission denied'
        for operation in ('kill', 'delete'):
            bridge.denied(operation, 'INACTIVE_RUNTIME_ABSENCE_UNPROVEN')
        bridge.absence = b'time="now" level=error msg="container does not exist"\n'
        self.forwarded('kill')
        self.forwarded('delete')
        bridge.record['runtimeRoot'] = '/foreign'
        for operation in ('kill', 'delete'):
            bridge.denied(operation, 'EPOCH_RUNTIME_ROOT_DRIFT')
        bridge.record.update(runtimeRoot=str(bridge.runtime_root), bootId='old-boot')
        bridge.denied('kill', 'RUNTIME_PHASE_INACTIVE')
        bridge.record.update(state='ABANDONED', bootId='current-boot')
        bridge.denied('kill', 'RUNTIME_PHASE_INACTIVE')

    def test_reconciled_epoch_21_can_create_epoch_22(self):
        bridge = self.bridge
        bridge.folder = bridge.base/'epochs/21'
        bridge.record.update(epoch=21, authorizationSha256='f'*64, configurationHash='0'*64,
                             schema='ouf.semantic-docker-runtime-journal.v3', containerId=CID,
                             openedAt=1, driverDenial=None)
        bridge.files = {path: raw for path, raw in bridge.files.items() if '/epochs/' not in Path(path).as_posix()}
        bridge.files[str(bridge.folder/'driver.json')] = b'sealed driver'
        for journal in ('broker-state.json', 'admission.json'):
            bridge.files[str(bridge.folder/journal)] = C.canonical({'epoch': 21, 'state': 'CLEANED'})
        self.receipt()
        bridge.state, bridge.forward_code = None, 1

        pointer = str(bridge.base/'current')
        for number in range(1, 22):
            folder = bridge.base/'epochs'/str(number)
            folder.mkdir(parents=True)
            bridge.files[str(folder/'adapter.json')] = C.canonical(bridge.record | {'epoch': number})
        bridge.files[pointer] = C.canonical({'epoch': 21, 'journalSha256': C.sha(
            bridge.files[str(bridge.folder/'adapter.json')])})
        historical = {path: raw for path, raw in bridge.files.items() if path != pointer}
        bundle = bridge.root/'oci'/CID
        bridge.cfg['candidates'][CID]['bundleParents'] = [str(bundle.parent)]
        bridge.cfg['limits'] = {'maxEpochsPerHour': 6}
        bridge.files[str(bundle/'config.json')] = C.canonical({
            'root': {'path': str(bridge.root/'rootfs')}, 'linux': {'namespaces': [{'type': 'network'}]},
        })
        bridge.epochs.JOURNAL_SCHEMA = bridge.record['schema']
        bridge.epochs.MAX_EPOCH = 10**9
        bridge.epochs.validate_journal = lambda raw, cid, epoch: C.document(raw)

        def current(*_):
            row = C.document(bridge.files[pointer])
            raw = bridge.files[str(bridge.base/'epochs'/str(row['epoch'])/'adapter.json')]
            self.assertEqual(row['journalSha256'], C.sha(raw))
            return C.document(raw)

        def replace(path, old, raw):
            self.assertEqual(bridge.files.get(str(path)), old)
            bridge.files[str(path)] = raw

        bridge.epochs.current = current
        self.forwarded('kill')
        self.forwarded('delete')
        fresh = bridge.base/'epochs/22'
        broker_modes = []
        runc = bridge.simulate
        scope = bridge.cfg['operation']
        role = {'containerId': CID, 'admissionConfigurationSha256': bridge.cfg['admissionConfigurations'][CID]['sha256']}
        head = {'decision': 'OPERATE', 'sha256': 'a'*64, 'authorization': {**scope, 'roles': {'adapter': role}}}

        def journal(path):
            return SimpleNamespace(read=lambda: C.document(bridge.files[str(path)]),
                                   write=lambda old, new: replace(path, C.canonical(old), C.canonical(new)))

        def write_once(path, row):
            replace(path, None, C.canonical(row))

        broker = B.Broker.__new__(B.Broker)
        broker.root, broker.cid, broker.epochs = fresh, CID, bridge.epochs
        broker.cfg, broker.head, broker.lock = bridge.cfg, lambda: head, nullcontext
        broker.stable = lambda: broker.check_epoch(head)
        broker.binding = {**scope, 'containerId': CID, 'epoch': 22, 'authorizationSha256': head['sha256'],
                          'configurationHash': role['admissionConfigurationSha256']}
        broker.journal = journal(fresh/'broker-state.json')
        broker.gate = B.EpochConsumption(broker.binding, journal(fresh/'deployment.json'), broker.lock)
        broker.runtime = lambda state: (current()['bundleHash'], dict(pid=state['pid'], startTicks=123, namespaceInode=456))

        def simulate_create(args, **kw):
            if args[0] == '/python':
                self.assertEqual(args[args.index('--epoch')+1], '22')
                self.assertEqual(args[args.index('--bundle')+1], str(fresh/'bundle'))
                broker_modes.append(args[-1])
                broker.args = SimpleNamespace(mode=args[-1], epoch=22, runtime_root=str(bridge.runtime_root))
                broker.operate(C.document(kw['input']))
                return subprocess.CompletedProcess(args, 0)
            if 'create' in args:
                self.assertEqual(args[args.index('--bundle')+1], str(fresh/'bundle'))
                bridge.state = dict(id=CID, bundle=str(fresh/'bundle'), status='created', pid=42)
            return runc(args, **kw)

        bridge.simulate = simulate_create
        bridge.forward_code = 0
        with patch.object(self.r, 'replace_cas', side_effect=replace), patch.object(self.r, 'sync_directory'), \
                patch.object(B.evidence_v2, 'write_exclusive', side_effect=write_once):
            self.assertEqual(bridge.run_op('create', publish_epoch=self.r.publish_epoch), 0)
        self.assertEqual(broker_modes, ['authorize-create', 'record-created'])
        self.assertEqual((current()['epoch'], current()['state'], current()['authorizationSha256']),
                         (22, 'CREATED', head['sha256']))
        self.assertEqual(broker.record()['state'], 'CREATED')
        self.assertEqual(broker.gate.record()['state'], 'CREATED')
        self.assertEqual({path: bridge.files[path] for path in historical}, historical)


if __name__ == '__main__':
    unittest.main()
