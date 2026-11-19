"""Real parent/child signatures/journals; namespace routes/Engine are modeled."""
import copy, sys, unittest
from pathlib import Path
from unittest.mock import Mock
ROOT = Path(__file__).resolve().parents[1]; sys.path[:0] = [str(ROOT), str(ROOT/'tests')]
import test_m2_discovery_publication_owner as fixture
from tools.m2_discovery_installation_profile import current_gateway_routes as m
from tools.m2_discovery_installation_profile import publication_owner as publication


class CurrentRoutes(unittest.TestCase):
    @classmethod
    def setUpClass(cls): fixture.Publication.setUpClass()
    @classmethod
    def tearDownClass(cls): fixture.Publication.tearDownClass()

    def prepared(self):
        case = fixture.Publication(); self.addCleanup(case.doCleanups); f = case.fixture()
        runtime = f.window.selected.gateway; runtime.images = f.window.selected.images; runtime.parent = f.window.parent
        runtime.guard = Mock()
        channel = object.__new__(m.DiscoveryGatewayReadOnlyAdmin); channel.discovery_owner = runtime
        channel.check = Mock(); channel.routes = Mock(side_effect=lambda: copy.deepcopy(f.inventory))
        runtime.transport = Mock(return_value=channel)
        # The real public window guard would call the very checkpoint being
        # assembled. Any accidental recursive use fails immediately here.
        f.checkpoint.reset_mock(); f.checkpoint.side_effect = AssertionError('NO_CHECKPOINT_REENTRY')
        return m.CurrentGatewayRoutes(f.gateway), f, channel

    def pending(self, f, *, dispatched=False, applied=False):
        p = f.gateway; row = p.record(); change = p.plan['changes'][0]
        effect = {'routeId': change['id'], 'intentHash': m.digest(change), 'state': 'APPLIED' if applied else 'CLAIMED'}
        following = copy.deepcopy(row); following.update(nextStep=int(applied), effects=[effect])
        p.save(row, following)
        if dispatched:
            f.crypto.write(p.journal.root/publication.marker(change['id']), publication.encoded(publication.claim(p, change['id'])))
        return change

    def test_baseline_uses_two_readonly_gets_and_no_recursive_checkpoint_or_journal_change(self):
        reader, f, channel = self.prepared(); before = copy.deepcopy(f.gateway.record())
        proof = reader.observe()
        self.assertTrue(proof['currentRoutesMatchReviewedPublicationProgress'])
        self.assertTrue(proof['currentGatewayConfigurationAndAdminExecutableObserved'])
        self.assertEqual(proof['routeGets'], 2); self.assertEqual(proof['routeWrites'], 0)
        self.assertEqual(f.gateway.record(), before); f.checkpoint.assert_not_called(); self.assertFalse(f.writes)
        self.assertEqual(channel.routes.call_count, 2)
        for key in ('publicationCheckpointReentered', 'journalAdvanced', 'allGatewayRuntimeExecutableBytesProven',
            'completePrivateCustodyProven', 'fullCohortProven', 'producerReleaseDispatched',
            'runtimeAuthorityIssued', 'targetApplyAuthorized', 'releaseAcceptance'):
            self.assertIs(proof[key], False)

    def test_empty_journal_baseline_is_observed_without_initializing_it(self):
        reader, f, _ = self.prepared()
        for path in f.gateway.journal.root.iterdir(): path.unlink()
        proof = reader.observe()
        self.assertEqual(list(f.gateway.journal.root.iterdir()), [])
        self.assertFalse(proof['pendingDispatchedOutcomeStillRequiresOwnerReconciliation'])

    def test_partial_initializer_is_not_adopted_or_completed(self):
        reader, f, channel = self.prepared(); (f.gateway.journal.root/'recovery.json').unlink()
        with self.assertRaises((ValueError, OSError)): reader.observe()
        channel.routes.assert_not_called(); self.assertFalse(f.writes)

    def test_unrelated_current_route_changes_are_denied(self):
        reader, f, channel = self.prepared(); f.inventory['foreign'] = {'id':'foreign','uri':'/foreign'}
        with self.assertRaisesRegex(ValueError, 'DIFFER_FROM_EXACT_REVIEWED'): reader.observe()
        channel.routes.assert_called_once(); self.assertFalse(f.writes)

    def test_claim_without_dispatch_admits_only_previous_map(self):
        reader, f, _ = self.prepared(); self.pending(f)
        self.assertFalse(reader.observe()['pendingDispatchedOutcomeStillRequiresOwnerReconciliation'])
        f.inventory.clear(); f.inventory.update(f.gateway.expected(1))
        with self.assertRaisesRegex(ValueError, 'DIFFER_FROM_EXACT_REVIEWED'): reader.observe()

    def test_dispatched_lost_ack_admits_only_exact_before_or_after_without_advancing(self):
        for after in (False, True):
            with self.subTest(after=after):
                reader, f, _ = self.prepared(); self.pending(f, dispatched=True)
                if after: f.inventory.clear(); f.inventory.update(f.gateway.expected(1))
                before = copy.deepcopy(f.gateway.record()); proof = reader.observe()
                self.assertTrue(proof['pendingDispatchedOutcomeStillRequiresOwnerReconciliation'])
                self.assertEqual(f.gateway.record(), before); self.assertFalse(f.writes)
                self.assertEqual(before['nextStep'], 0); self.assertEqual(before['effects'][-1]['state'], 'CLAIMED')

    def test_applied_route_requires_original_dispatch_and_exact_map(self):
        reader, f, _ = self.prepared(); self.pending(f, applied=True)
        f.inventory.clear(); f.inventory.update(f.gateway.expected(1))
        with self.assertRaises((ValueError, OSError)): reader.observe()
        name = f.gateway.plan['changes'][0]['id']
        f.crypto.write(f.gateway.journal.root/publication.marker(name), publication.encoded(publication.claim(f.gateway, name)))
        self.assertTrue(reader.observe()['currentRoutesMatchReviewedPublicationProgress'])

    def test_revocation_foreign_owner_and_generation_drift_stop_without_route_write(self):
        reader, f, channel = self.prepared(); reader.runtime = object()
        with self.assertRaisesRegex(ValueError, 'SAME_EXACT_CURRENT_GATEWAY'): reader.observe()
        channel.routes.assert_not_called()
        reader, f, channel = self.prepared(); f.crypto.write(Path(f.window.parent.binding['path']), b'REVOKED')
        with self.assertRaises(ValueError): reader.observe()
        channel.routes.assert_not_called()
        reader, f, channel = self.prepared()
        reader.runtime.generation.side_effect = [{'fixtureGeneration':1}, {'fixtureGeneration':2}]
        with self.assertRaisesRegex(ValueError, 'GENERATION_OR_PUBLICATION_HISTORY_CHANGED'): reader.observe()
        self.assertFalse(f.writes)

    def test_changes_between_gets_or_history_reads_never_return_combined_success(self):
        reader, f, channel = self.prepared(); channel.routes.side_effect = [copy.deepcopy(f.inventory), {}]
        with self.assertRaisesRegex(ValueError, 'GENERATION_OR_PUBLICATION_HISTORY_CHANGED'): reader.observe()
        reader, f, channel = self.prepared()
        def drift():
            f.row['version'] += 1; return copy.deepcopy(f.inventory)
        channel.routes.side_effect = drift
        with self.assertRaisesRegex(ValueError, 'GENERATION_OR_PUBLICATION_HISTORY_CHANGED'): reader.observe()

    def test_transient_failure_is_propagated_once_without_checkpoint_reentry_or_mutation(self):
        reader, f, channel = self.prepared(); before = copy.deepcopy(f.gateway.record())
        channel.routes.side_effect = TimeoutError('READ_ONLY_GATEWAY_UNAVAILABLE')
        with self.assertRaises(TimeoutError): reader.observe()
        channel.routes.assert_called_once(); f.checkpoint.assert_not_called()
        self.assertEqual(f.gateway.record(), before); self.assertFalse(f.writes)


if __name__ == '__main__': unittest.main()
