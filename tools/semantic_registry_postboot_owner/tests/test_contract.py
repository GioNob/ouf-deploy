"""Pure signed-input compilation, deliberately not production admission proof."""
import copy
from pathlib import Path
import tempfile
import unittest

from tools.semantic_registry_postboot_owner import contract as c
from tools.semantic_registry_postboot_owner.tests.fixture import make_context

ROOT = Path(__file__).resolve().parents[3]


class Contract(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=ROOT); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        output = self.root/'output'; output.mkdir(mode=0o750)
        secret = self.root/'client-secret'; secret.write_text('DISPOSABLE'); secret.chmod(0o400)
        binding = {'endpoint': 'https://fixture.invalid/token', 'client_id': 'fixture', 'scope': 'policy:read',
            'output_directory': str(output), 'output_member': 'token.jwt', 'output_gid': 10001,
            'minimum_remaining': 90, 'maximum_token_seconds': 3600}
        recovery = {'planHash': 'a'*64, 'logicalOperationRef': 'b'*64, 'registryId': 'c'*64,
            'bootId': 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'}
        sources = {name: Path(c.__file__) for name in c.SOURCE_FILES}
        self.context = make_context(self.root/'metadata', binding, {}, 'd'*64, secret, recovery,
            'e'*64, source_paths=sources)

    def test_counter_319_becomes_base_not_new_budget_and_old_boot_stays_immutable(self):
        before = copy.deepcopy(self.context)
        scope = c.compile_scope(self.context)
        self.assertEqual(scope['predecessorGrantAttempts'], 319)
        self.assertEqual(scope['maximumCumulativeGrantAttempts'], 320)
        self.assertNotEqual(scope['currentSessionBootId'], scope['retainedFirstGrantBootId'])
        self.assertFalse(scope['budgetReset']); self.assertFalse(scope['firstGrantReplayAllowed'])
        self.assertEqual(self.context, before)

    def test_attempt_budget_must_be_explicit_integer_and_bounded(self):
        for value in (None, True, 0, 129):
            with self.subTest(value=value):
                context = copy.deepcopy(self.context); context['budget']['maximumGrantAttempts'] = value
                with self.assertRaisesRegex(c.Denied, 'EXPLICIT_FINITE_POSTBOOT_BUDGET'):
                    c.compile_scope(context)

    def test_claim_and_parent_bind_exact_old_logical_fence(self):
        scope = c.compile_scope(self.context)
        self.assertEqual(scope['fenceBinding']['path'], scope['predecessorFenceBinding']['path'])
        context = copy.deepcopy(self.context); context['predecessorJournalPath'] = str(self.root/'different-parent/worker')
        with self.assertRaisesRegex(c.Denied, 'EXACT_PREDECESSOR_GLOBAL_FENCE'):
            c.compile_scope(context)

    def test_stale_boot_cannot_be_relabelled_current_in_the_old_receipt(self):
        context = copy.deepcopy(self.context)
        context['recovery']['bootId'] = context['retainedRecords']['owner-first-grant.json']['bootId']
        with self.assertRaisesRegex(c.Denied, 'DISTINCT_CURRENT_BOOT'):
            c.compile_scope(context)

    def test_old_record_hash_and_counter_cannot_be_reset(self):
        context = copy.deepcopy(self.context)
        context['retainedRecords']['recovery.json']['attempts'] = 0
        with self.assertRaisesRegex(c.Denied, 'EXACT_TERMINAL_OWNER_RECORD'):
            c.compile_scope(context)

    def test_disconnected_or_branched_lineage_never_selects_highest(self):
        context = copy.deepcopy(self.context)
        context['lineageReceipt']['metadataLineage'][2]['predecessorCandidateOrdinal'] = 0
        with self.assertRaises(c.Denied):
            c.compile_scope(context)

    def test_source_input_and_credential_output_are_bound(self):
        for field in ('source', 'output'):
            context = copy.deepcopy(self.context)
            if field == 'source':
                context['sourceFiles'].pop(next(iter(c.SOURCE_FILES)))
            else:
                context['ownerInputs']['binding']['output_member'] = 'different.jwt'
            with self.subTest(field=field), self.assertRaises(c.Denied):
                c.compile_scope(context)

    def test_initial_journal_requires_paused_gate_and_carries_no_old_expiry(self):
        proof = {'schema': 'ouf.semantic-registry-postboot-gate-witness.v1', 'checkpoint': 4,
            'paused': True, 'processKind': 'GATE_WAITING', 'recoveryPlanHash': 'a'*64,
            'recoveryLogicalOperationRef': 'b'*64, 'runtimeGeneration': {
                'containerId': 'c'*64, 'bootId': self.context['recovery']['bootId'], 'pid': 123,
                'startTicks': 456, 'namespaceDevice': 1, 'namespaceInode': 2}}
        row = c.initial_record(self.context, proof, 1000, 100)
        self.assertEqual(row['attempts'], 0); self.assertEqual(row['controlledCumulativeGrantAttempts'], 319)
        self.assertIsNone(row['tokenExpiresWall']); self.assertIsNone(row['tokenExpiresMonotonic'])
        proof['processKind'] = 'APPLICATION_RUNNING'
        with self.assertRaisesRegex(c.Denied, 'DURABLE_PAUSED_CURRENT_BOOT_GATE'):
            c.initial_record(self.context, proof, 1000, 100)


if __name__ == '__main__':
    unittest.main()
