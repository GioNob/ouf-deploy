import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

import activate_resilient_r11 as m


class Tests(unittest.TestCase):
    def scope(self):
        return json.loads((Path(__file__).parent/'target_bindings_r11.json').read_bytes())

    def current(self):
        scope = self.scope()
        return {'ownerConfigurationHash': scope['ownerConfigurationHash'],
            'leaseIngressSeparated': True, 'roles': copy.deepcopy(scope['roles']),
            'currentSemanticPeer': copy.deepcopy(scope['currentSemanticPeer']),
            'lease': {'flowCount': 2, 'flows': [{'leaseSeconds': 30}, {'leaseSeconds': 30}],
                'nativeStructureVerified': True, 'journalAndMembershipConsistent': True,
                'pollSeconds': 15, 'sourceMatchesByRole': {'adapter': [0], 'southbound': [1]},
                'journalState': 'QUIESCED', 'leaseAuthorized': False, 'startAuthorized': False,
                'providerSetsEmpty': True, 'journalFileHash': scope['quiescentJournalHash']}}

    def test_current_operator_scope_is_exact_and_read_only(self):
        value = self.current(); before = copy.deepcopy(value)
        m.validate_current(value, self.scope(), quiescent=True)
        self.assertEqual(value, before)

    def test_peer_driver_oci_ownership_and_scope_drift_denied(self):
        for path in [('currentSemanticPeer', 'generation', 'pid'),
                     ('roles', 'adapter', 'fullOciHash'),
                     ('roles', 'southbound', 'driverBinding', 'sha256'),
                     ('ownerConfigurationHash',)]:
            value = self.current(); row = value
            for name in path[:-1]: row = row[name]
            row[path[-1]] = 'foreign'
            with self.assertRaises(ValueError): m.validate_current(value, self.scope(), quiescent=True)

    def test_nonempty_or_nonquiescent_native_lease_cannot_start(self):
        for key, value in [('leaseAuthorized', True), ('providerSetsEmpty', False),
                           ('startAuthorized', True), ('journalFileHash', 'foreign')]:
            current = self.current(); current['lease'][key] = value
            with self.assertRaises(ValueError): m.validate_current(current, self.scope(), quiescent=True)

    def test_new_request_and_window_never_adopt_old_authority(self):
        m.approval_live(m.APPROVAL_REF, lambda: m.ISSUED_AT)
        for ref, now in [('old-r10', m.ISSUED_AT), (m.APPROVAL_REF, m.EXECUTION_EXPIRES_AT),
                         (m.APPROVAL_REF, m.ISSUED_AT - 1)]:
            with self.assertRaises(ValueError): m.approval_live(ref, lambda: now)
        self.assertNotEqual(m.CLAIM, Path('/etc/ouf/provider-finite-lease-recovery-r10.claim'))
        self.assertNotEqual(m.UNIT, m.PRIOR_UNIT)

    def test_consumed_new_claim_denied_before_reads_or_effects(self):
        with tempfile.TemporaryDirectory() as root:
            claim = Path(root)/'claim'; claim.write_text('consumed')
            with patch.object(m, 'CLAIM', claim), patch.object(m, 'approval_live'), patch.object(m, 'readers') as read:
                with self.assertRaisesRegex(ValueError, 'NEW_RECOVERY_ALREADY_CONSUMED'):
                    m.apply(m.APPROVAL_REF)
                read.assert_not_called()
                self.assertEqual(claim.read_text(), 'consumed')

    def capsule(self):
        scope = self.scope()
        value = {'schema': 'ouf.provider-resilient-r11-authorization.v1',
            'approvalRef': m.APPROVAL_REF, 'serviceUnit': m.UNIT,
            'ownerConfigurationHash': scope['ownerConfigurationHash'],
            'automaticRestart': False, 'enableAtBoot': False, 'containerLifecycleAuthorized': False,
            'issuedAt': m.ISSUED_AT, 'executionExpiresAt': m.EXECUTION_EXPIRES_AT,
            'programHashes': {'activate.py': 'a'*64, **m.MODULE_HASHES},
            'hostBootId': 'fixture-boot', 'roleGenerations': {'adapter': {'pid': 1}},
            'targetScope': scope}
        value['generationRef'] = m.sha(m.encoded({'bootId': value['hostBootId'],
            'roles': value['roleGenerations'], 'peer': scope['currentSemanticPeer']['generation']}))
        value['contextRef'] = m.sha(m.encoded(value))
        return value

    def test_capsule_closure_context_and_generation_are_sealed(self):
        reader = types.SimpleNamespace(OWNER_HASH=self.scope()['ownerConfigurationHash'])
        m.validate_capsule(reader, self.capsule())
        for key, value in [('automaticRestart', True), ('enableAtBoot', True),
                           ('containerLifecycleAuthorized', True), ('contextRef', 'f'*64),
                           ('generationRef', 'f'*64)]:
            capsule = self.capsule(); capsule[key] = value
            with self.assertRaises(ValueError): m.validate_capsule(reader, capsule)
        capsule = self.capsule(); capsule['programHashes']['unreviewed.py'] = 'f'*64
        with self.assertRaises(ValueError): m.validate_capsule(reader, capsule)

    def test_known_component_tamper_never_executes(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)/'component'; path.write_bytes(b'not-reviewed')
            with self.assertRaises(ValueError): m.component(path, 'a'*64)

    def test_metadata_transport_uses_caller_deadline(self):
        spec = importlib.util.spec_from_file_location('r11_reader', Path(__file__).parent/'resilient_reader.py')
        reader = importlib.util.module_from_spec(spec); spec.loader.exec_module(reader)
        with patch.object(reader.time, 'monotonic', return_value=10):
            reader.CALL_DEADLINE = 11
            self.assertEqual(reader.transport_timeout(15), 1)
            reader.CALL_DEADLINE = 10
            with self.assertRaises(reader.ReadDenied): reader.transport_timeout(15)


if __name__ == '__main__': unittest.main()
