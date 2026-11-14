"""Governed v1 -> v2 upgrade (task-30b) over a synthetic but real v1 installation.

Real root custody, real Ed25519 signatures (installer and attestor roles),
real v1 and v2 guards, real ledgers and fences. Only systemctl is simulated.
"""
import copy
from dataclasses import asdict
import hashlib
import importlib
import json
import os
from pathlib import Path
import time
import unittest

import test_native_transport as fixture_transport
from tools.semantic_registry_operational_owner_v2 import core, guard, installation, upgrade
from tools.semantic_registry_operational_owner_v2.store import file_identity
from tools.semantic_registry_operational_owner import contract as v1_contract
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator, signing_bytes
from tools.semantic_provider_deployment_signing import ExistingEd25519Signer

LOGICAL = '7' * 64


class FakeManager:
    def __init__(self):
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append(argv[1:])
        out = b'ActiveState=inactive\nUnitFileState=enabled\n' if argv[1] == 'show' else b''
        return type('Result', (), {'returncode': 0, 'stdout': out})()


@unittest.skipUnless(os.environ.get('OUF_NATIVE_OPERATIONAL_OWNER') == '1', 'Explicit disposable native root scope required')
class Upgrade(unittest.TestCase):
    def setUp(self):
        self.f = fixture_transport.NativeOwner(methodName='runTest')
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        f = self.f
        for name in v1_contract.SOURCE_NAMES:
            importlib.import_module(name)
        self.parent = f.root / 'deploy'
        self.parent.mkdir(mode=0o700)
        self.units = f.root / 'units'
        self.units.mkdir(mode=0o755)
        journal = f.root / 'journal'
        journal.mkdir(mode=0o700)
        self.common = f.write(journal / 'invocation.lock', b'')
        self.v1root = self.parent / ('semantic-registry-operational-' + LOGICAL)
        self.v1ledger = self.parent / ('semantic-registry-operational-state-' + LOGICAL)
        for path in (self.v1root, self.v1ledger, self.v1root / 'fence', self.v1root / 'receipt-signatures'):
            path.mkdir(mode=0o700)
        capsule = f.write(self.v1root / 'capsule.py', b'# v1 capsule fixture\n', 0o400)
        manifest = {'schema': 'ouf.registry-operational-owner-sources.v1', 'sourceCommit': 'a' * 40, 'sourceHashes': {},
                    'dependencyClosureHash': 'b' * 64, 'bootstrapHash': 'c' * 64}
        for name in v1_contract.SOURCE_NAMES:
            manifest['sourceHashes'][name] = hashlib.sha256(Path(importlib.import_module(name).__file__).read_bytes()).hexdigest()
        fence_value = {'schema': 'ouf.registry-operational-owner-fence.v1', 'logicalOwnerScopeHash': LOGICAL,
                       'proposalHash': 'd' * 64, 'sourceManifestHash': core.digest(manifest),
                       'journalPath': str(self.v1ledger), 'installationRoot': str(self.v1root),
                       'predecessorWorkerHash': 'e' * 64, 'priorControlledAttempts': 321,
                       'operationalFencePath': str(self.v1root / 'fence/fence.json'), 'active': True}
        verification = {k: v for k, v in f.config['verification'].items() if k != 'mandateLedgerRoot'}
        unit_path = self.units / ('ouf-registry-token-' + LOGICAL[:24] + '.service')
        self.c1 = dict(copy.deepcopy(f.config), sourceManifest=manifest,
                       sources=[{'path': str(capsule), 'sha256': f.binding(capsule)['sha256'], 'maximumBytes': 2097152},
                                f.config['sources'][0]],
                       destinations={'installationRoot': str(self.v1root), 'ledgerRoot': str(self.v1ledger),
                                     'commonInvocationLock': str(self.common)},
                       fenceBinding={'path': str(self.v1root / 'fence/fence.json'), 'value': fence_value},
                       commonLockIdentity=list(file_identity(self.common.stat())), verification=verification,
                       tlsCa={'path': str(self.v1root / 'iam-ca.pem'), 'sha256': f.binding(f.ca)['sha256']},
                       serviceUnitPath=str(unit_path))
        f.write(self.v1root / 'iam-ca.pem', f.ca.read_bytes())
        self.c1_path = f.write(self.v1root / 'configuration.json', core.encoded(self.c1))
        self.c1_sha = hashlib.sha256(self.c1_path.read_bytes()).hexdigest()
        f.write(unit_path, ('ExecStart=:/usr/bin/python3 capsule.py worker --configuration-sha256 ' + self.c1_sha + '\n').encode(), 0o644)
        f.write(self.v1root / 'fence/fence.json', core.encoded(fence_value))
        (f.root / 'global').mkdir(mode=0o700)
        self.global_fence = f.write(f.root / 'global/fence.json', core.encoded(fence_value))
        receipt = {'schema': 'ouf.registry-operational-token-installation-receipt.v1', 'complete': True,
                   'configurationHash': self.c1_sha, 'proposalHash': 'd' * 64, 'sourceManifestHash': core.digest(manifest),
                   'operationalRenewalInstalled': True, 'priorControlledAttempts': 321, 'serviceUnitPath': str(unit_path),
                   'serviceUnitHash': f.binding(unit_path)['sha256']}
        raw = core.encoded(receipt)
        f.write(self.v1root / 'installed.json', raw)
        self.sign(raw, self.v1root / 'receipt-signatures', 'CREATION_ATTESTATION', 'fixture-attestor-key', f.ctx['attestorRef'])
        row = core.initial(self.c1_sha, 'e' * 64, 321, f.policy, 'fixture-boot', (time.time(), time.monotonic()))
        row.update(attempts=9, cumulativeAttempts=330)
        self.write_row(row)
        f.write(self.v1ledger / 'invocation.lock', b'')
        f.write(self.v1ledger / 'cas.lock', b'')
        self.capsule2 = f.write(f.root / 'capsule-v2.py', b'# v2 capsule fixture\n', 0o400)
        self.manager = FakeManager()

    def write_row(self, row):
        path = self.v1ledger / 'state.json'
        if path.exists():
            path.unlink()
        self.f.write(path, core.encoded(row))

    def sign(self, raw, directory, role, key_ref, issuer):
        f = self.f
        header = dict(schema='ouf.semantic-deployment-detached-signature.v1', algorithm='Ed25519', keyRef=key_ref,
                      role=role, issuerRef=issuer, installationRef=f.ctx['installationRef'], entityRef=f.ctx['entityRef'],
                      payloadHash=hashlib.sha256(raw).hexdigest())
        frame = f.write(f.root / 'frame', signing_bytes(raw, header))
        signature = f.native('pkeyutl', '-sign', '-rawin', '-inkey', str(f.signing_key), '-in', str(frame))
        f.write(directory / (header['payloadHash'] + '.' + role + '.json'), core.encoded(dict(header, signature=signature.hex())))

    def review(self, attempt=1):
        f = self.f
        pred = upgrade.predecessor(str(self.c1_path), self.c1_sha, str(self.global_fence))
        public = {'executables': {'python': {k: f.config['sources'][0][k] for k in ('path', 'sha256')},
                                  'openssl': f.config['verification']['openssl'],
                                  'systemctl': {'path': '/usr/bin/systemctl', 'sha256': '0' * 64}},
                  'authorityProfile': {'syntheticFixtureProfile': True}, 'stdlibHash': 'a' * 64, 'stdlibFileCount': 1}
        return upgrade.compose(pred, f.config['sourceManifest'], f.binding(self.capsule2), public, attempt=attempt,
                               unit_parent=str(self.units), mandate_ledger_root=str(f.mandate_root),
                               authority_public={'fixture': True})

    def authority(self, review):
        f = self.f
        directory = f.root / ('authority-' + core.digest(review)[:12])
        directory.mkdir(mode=0o700)
        now = int(time.time())
        raw = core.encoded({'schema': installation.AUTHORITY_SCHEMA, 'scope': installation.review_scope(review),
                            'issuedAt': now, 'expiresAt': now + 900, 'installationRef': f.ctx['installationRef'],
                            'entityRef': f.ctx['entityRef'], 'automaticReplayAllowed': False, 'budgetReset': False,
                            'releaseAcceptance': False})
        human = {'schema': installation.HUMAN_SCHEMA, 'reviewHash': core.digest(review),
                 'authorityHash': hashlib.sha256(raw).hexdigest(), 'decision': installation.DECISION, 'state': 'ACTIVE',
                 'issuedAt': now, 'expiresAt': now + 900}
        human_path = f.write(directory / 'human.json', core.encoded(human))
        verifier = DetachedAuthenticator(f.binding(f.trust), str(directory), f.config['verification']['openssl'])
        for role in ('DEPLOYMENT_INTENT', 'FINAL_DEPLOYMENT_APPROVAL'):
            self.sign(raw, directory, role, 'fixture-installer-key', f.ctx['intentIssuerRef'])
        authority = installation.SignedInstallation(review, raw, f.binding(human_path), core.digest(human), verifier)
        attestor = ExistingEd25519Signer(f.binding(f.signing_key), 'fixture-attestor-key', verifier,
                                         {'role': 'CREATION_ATTESTATION', 'issuerRef': f.ctx['attestorRef'],
                                          'installationRef': f.ctx['installationRef'], 'entityRef': f.ctx['entityRef']})
        return authority, attestor

    def install(self, review=None):
        review = review or self.review()
        authority, attestor = self.authority(review)
        result = upgrade.install(review, authority, attestor, runner=self.manager, sleep=lambda _: None)
        return review, authority, result

    def v1_guard(self):
        from tools.semantic_registry_operational_owner import guard as v1_guard
        return v1_guard.InstalledGuard(self.c1_path, self.c1_sha)

    def test_v1_guard_is_valid_before_the_upgrade(self):
        self.assertIsNotNone(self.v1_guard())

    def test_complete_upgrade_keeps_counter_fences_v1_and_activates_v2(self):
        review, authority, result = self.install()
        self.assertEqual((result['status'], result['retainedCumulativeAttempts']), ('V2_INSTALLED_V1_FENCED_NOT_STARTED', 330))
        c2 = review['configuration']
        owner = guard.InstalledGuard(Path(c2['destinations']['installationRoot']) / 'configuration.json', core.digest(c2))
        self.assertEqual(owner.prior, 330)
        self.assertEqual(installation.read_object(self.global_fence), c2['fenceBinding']['value'])
        self.assertFalse(installation.read_object(self.v1root / 'fence/fence.json')['active'])
        with self.assertRaises(core.Denied) as caught:
            self.v1_guard()
        self.assertEqual(str(caught.exception), 'OPERATIONAL_OWNER_FENCE_CHANGED')
        self.assertIn(['stop', 'ouf-registry-token-' + LOGICAL[:24] + '.service'], self.manager.calls)
        state = installation.read_object(Path(c2['destinations']['ledgerRoot']) / 'state.json')
        self.assertEqual((state['priorControlledAttempts'], state['cumulativeAttempts'], state['attempts']), (330, 330, 0))
        receipt = installation.read_object(Path(c2['destinations']['installationRoot']) / 'installed.json')
        self.assertEqual((receipt['schema'], receipt['priorControlledAttempts']),
                         ('ouf.registry-operational-token-installation-receipt.v2', 330))
        # The v1 ledger is never written by the upgrade.
        self.assertEqual(installation.read_object(self.v1ledger / 'state.json')['cumulativeAttempts'], 330)
        with self.assertRaises((FileExistsError, core.Denied)):
            upgrade.install(review, authority, self.authority(review)[1], runner=self.manager, sleep=lambda _: None)
        observation = upgrade.start(review, authority, runner=self.manager, sleep=lambda _: None,
                                    reader=lambda: dict(state, state='ACTIVE', publications=1))
        self.assertEqual(observation['status'], 'V2_ACTIVE_PUBLISHED')
        self.assertEqual(self.manager.calls[-5:-2], [['disable', '--now', 'ouf-registry-token-' + LOGICAL[:24] + '.service'],
                                                     ['daemon-reload'], ['enable', '--now', Path(c2['serviceUnitPath']).name]])

    def test_predecessor_drift_between_prepare_and_install_has_no_effect(self):
        review = self.review()
        authority, attestor = self.authority(review)
        changed = installation.read_object(self.global_fence)
        changed['proposalHash'] = '0' * 64
        self.global_fence.unlink()
        self.f.write(self.global_fence, core.encoded(changed))
        with self.assertRaises(core.Denied):
            upgrade.install(review, authority, attestor, runner=self.manager, sleep=lambda _: None)
        self.assertFalse(Path(review['configuration']['destinations']['installationRoot']).exists())
        self.assertEqual(self.manager.calls, [])

    def test_in_flight_v1_attempt_stops_and_rollback_restarts_v1(self):
        row = installation.read_object(self.v1ledger / 'state.json')
        row.update(state='RESERVED', attemptId=core.digest({'installationHash': self.c1_sha, 'cumulativeAttempt': 330}))
        self.write_row(row)
        review = self.review()
        authority, attestor = self.authority(review)
        with self.assertRaises(core.Denied) as caught:
            upgrade.install(review, authority, attestor, runner=self.manager, sleep=lambda _: None)
        self.assertEqual(str(caught.exception), 'V1_ATTEMPT_IN_FLIGHT_RECONCILE_FIRST')
        self.assertTrue(installation.read_object(self.v1root / 'fence/fence.json')['active'])
        plan = upgrade.rollback_plan(review)
        self.assertEqual([s['restore'] for s in plan['steps']], [False, False])
        upgrade.rollback_apply(review, core.digest(plan), runner=self.manager)
        self.assertEqual(self.manager.calls[-1], ['enable', '--now', 'ouf-registry-token-' + LOGICAL[:24] + '.service'])

    def test_rollback_after_install_restores_v1_and_refused_after_publication(self):
        review, _, _ = self.install()
        plan = upgrade.rollback_plan(review)
        self.assertEqual([s['restore'] for s in plan['steps']], [True, True])
        with self.assertRaises(core.Denied):
            upgrade.rollback_apply(review, '0' * 64, runner=self.manager)
        upgrade.rollback_apply(review, core.digest(plan), runner=self.manager)
        self.assertEqual(installation.read_object(self.global_fence), self.c1['fenceBinding']['value'])
        self.assertIsNotNone(self.v1_guard())
        state = installation.read_object(Path(review['configuration']['destinations']['ledgerRoot']) / 'state.json')
        with self.assertRaises(core.Denied) as caught:
            upgrade.rollback_plan(review, reader=lambda: dict(state, publications=1))
        self.assertEqual(str(caught.exception), 'V2_ALREADY_PUBLISHED_ROLLBACK_REFUSED')

    def test_second_attempt_after_rollback_uses_new_roots(self):
        first, _, _ = self.install()
        plan = upgrade.rollback_plan(first)
        upgrade.rollback_apply(first, core.digest(plan), runner=self.manager)
        second, _, result = self.install(self.review(attempt=2))
        self.assertNotEqual(first['configuration']['destinations'], second['configuration']['destinations'])
        self.assertEqual(result['retainedCumulativeAttempts'], 330)

    def test_scope_is_bound_to_the_exact_review(self):
        review = self.review()
        scope = installation.review_scope(review)
        self.assertEqual(scope['reviewHash'], core.digest(review))
        tampered = copy.deepcopy(review)
        tampered['configuration']['policy'] = dict(tampered['configuration']['policy'], maximum_attempts_per_hour=999)
        with self.assertRaises(core.Denied):
            installation.review_scope(tampered)


if __name__ == '__main__':
    unittest.main()
