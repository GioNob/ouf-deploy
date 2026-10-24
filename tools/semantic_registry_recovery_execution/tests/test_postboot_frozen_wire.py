"""Observed snake-case contract, exact-reference guards and retained reads."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import test_postboot_prepare as fixture
from tools.semantic_registry_recovery_execution import postboot_prepare as p, frozen_response as wire, frozen_wire_reconciliation as r

ROOT = Path(__file__).resolve().parents[3]


class FrozenWire(unittest.TestCase):
    setUp = fixture.Preparation.setUp

    def snake(self):
        value = copy.deepcopy(self.frozen)
        for source, target in wire.IDENTITY.items(): value[source] = value.pop(target)
        return value

    def test_observed_snake_identity_and_checksum_preserved(self):
        value = self.snake(); before = copy.deepcopy(value)
        self.assertEqual(wire.normalize(value), self.frozen)
        self.assertEqual(p.frozen_configuration(value, self.reference), [self.semantic])
        self.assertEqual(value, before); self.assertEqual(wire.schema(value), 'snake_case')

    def test_legacy_camel_case_unchanged(self):
        self.assertEqual(p.frozen_configuration(self.frozen, self.reference), [self.semantic])
        self.assertEqual(wire.normalize(self.frozen), self.frozen); self.assertEqual(wire.schema(self.frozen), 'camelCase')

    def test_mixed_partial_or_conflicting_aliases_are_rejected(self):
        for value in (dict(self.snake(), sourceId=self.reference['sourceId']),
                      dict(self.frozen, source_id=self.reference['sourceId']),
                      dict(self.frozen, source_id='DIFFERENT')):
            with self.subTest(keys=list(value)):
                with self.assertRaisesRegex(Exception, 'AMBIGUOUS_FROZEN_RESPONSE'): p.frozen_configuration(value, self.reference)
        value = self.snake(); del value['configuration_hash']
        with self.assertRaises(Exception): p.frozen_configuration(value, self.reference)

    def test_same_version_state_checksum_and_reference_checks_still_enforced(self):
        for key, value in [('source_id', 'different'), ('onboarding_version_id', 'different'),
                           ('configuration_hash', 'sha256:' + 'b' * 64), ('state', 'ACTIVE')]:
            changed = dict(self.snake(), **{key: value})
            with self.subTest(key=key):
                with self.assertRaises(Exception): p.frozen_configuration(changed, self.reference)
        changed = self.snake(); changed['configuration']['added'] = 'drift'
        with self.assertRaisesRegex(Exception, 'CHECKSUM_CHANGED'): p.frozen_configuration(changed, self.reference)

    def test_wire_case_root_survives_source_or_case_changes_for_same_response(self):
        case = json.loads((ROOT / 'releases/semantic-registry-postboot-wire-case-20261023.json').read_bytes())['preparation']
        boot = '00000000-1111-2222-3333-444444444444'
        p.validate_case(case)
        self.assertEqual(p.prepared_root(case, {'source': 'a'}, boot), p.prepared_root(case, {'source': 'b'}, boot))
        self.assertEqual(p.Files().maximum_reads, 128); self.assertEqual(p.Files(maximum_reads=192).maximum_reads, 192)
        files = p.Files(maximum_reads=256); path = self.root / 'bounded'; path.write_bytes(b'fixture'); path.chmod(0o400)
        for _ in range(256): files.seal(str(path), 64, retain=False)
        with self.assertRaises(Exception): files.seal(str(path), 64, retain=False)

    def test_last_preparation_and_response_probe_reconciled_without_old_file_changes(self):
        case = json.loads((ROOT / 'releases/semantic-registry-postboot-wire-case-20261023.json').read_bytes())['preparation']
        case['privateParent'] = str(self.root); case['frozenReference'] = self.reference
        proof = {'priorAttemptCounts': {'engineGets': 22, 'adminGets': 3, 'frozenConfigurationGets': 0, 'resolverCalls': 3, 'tlsAttemptMarkers': 3}}
        original = {k: v for k, v in case.items() if k != 'frozenWireRecovery'}
        boot = '00000000-1111-2222-3333-444444444444'
        old = self.root / 'consumed'; old.mkdir(mode=0o700)
        expected = {'schema': p.SCHEMA, 'caseHash': p.digest(original), 'sourceClosureHash': case['frozenWireRecovery']['resolverSourceClosureHash'],
            'bootId': boot, 'maximumEngineGets': 12, 'maximumAdminGets': 1, 'maximumFrozenGets': 1,
            'automaticReplayAllowed': False, 'runtimeAuthorityIssued': False, 'maximumTlsHandshakes': 1, 'maximumMetadataReads': 192}
        p.publish(old, 'claim.json', expected)
        for n in range(1, 7): p.publish(old, 'engine-get-' + str(n) + '.json', {'requestPathHash': 'a' * 64, 'attempt': n})
        p.publish(old, 'admin-get.json', {'method': 'GET', 'operation': '/apisix/admin/routes', 'maximumAttempts': 1})
        p.publish(old, 'tls-handshake.json', {'originHash': 'a' * 64, 'caProfileHash': 'b' * 64,
            'maximumAttempts': 1, 'httpRequests': 0, 'bearersSent': 0})
        p.publish(old, 'frozen-get.json', {'method': 'GET', 'path': p.FROZEN_PATH, 'referenceHash': p.digest(self.reference), 'maximumAttempts': 1})
        observer = self.root / 'observer'; observer.mkdir(mode=0o700)
        response = self.snake(); p.publish(observer, 'response.json', response)
        case['frozenWireRecovery']['response'] = {'path': str(observer / 'response.json'), 'sha256': p.digest(response)}
        p.publish(observer, 'claim.json', {'schema': 'ouf.semantic-registry-frozen-response-result.v1', 'bootId': boot,
            'retainedPreparationClaimHash': p.digest(expected), 'scriptSha256': case['frozenWireRecovery']['observerScriptSha256'],
            'maximumEngineGets': 2, 'maximumFrozenGets': 1, 'maximumResolverCalls': 1, 'maximumTlsConnections': 1,
            'priorAttemptCounts': {'engineGets': 28, 'adminGets': 4, 'frozenConfigurationGets': 1, 'resolverCalls': 5, 'tlsIdentityIntentMarkers': 4},
            'cumulativeEngineGetCeiling': 30, 'cumulativeFrozenGetCeiling': 2, 'cumulativeResolverCallCeiling': 6,
            'automaticReplayAllowed': False, 'budgetReset': False})
        for n in (1, 2): p.publish(observer, 'engine-get-' + str(n) + '.json', {'requestPathHash': 'a' * 64, 'attempt': n})
        p.publish(observer, 'frozen-get.json', {'method': 'GET', 'path': p.FROZEN_PATH, 'referenceHash': p.digest(self.reference),
            'maximumAttempts': 1, 'resolverSource': 'SIGNED_CALLER_FILES', 'retainedPeerPinUsed': True})
        p.publish(observer, 'observation.json', {'responseHash': p.digest(response), 'shape': {}, 'referenceHash': p.digest(self.reference)})
        before = {f: (f.read_bytes(), f.stat()) for f in self.root.rglob('*.json')}
        # Only the previously qualified predecessor chain and its root locator
        # are simulated; this layer exercises actual protected files/markers.
        with patch.object(p, 'reconcile_prior_preparation', return_value=proof), patch.object(p, 'prepared_root', return_value=old):
            result = r.reconcile(case, p.Files(maximum_reads=256), boot)
            self.assertEqual(result['priorAttemptCounts']['engineGets'], 30)
            self.assertEqual(result['cumulativeAttemptCeilings']['engineGets'], 42)
            self.assertFalse(result['budgetReset'])
            self.assertEqual(before, {f: (f.read_bytes(), f.stat()) for f in before})
            p.publish(old, 'prepared.json', {'unexpected': True})
            with self.assertRaisesRegex(Exception, 'RESOLVER_PREPARATION_ADVANCED'): r.reconcile(case, p.Files(), boot)


if __name__ == '__main__': unittest.main()
