"""Actual protected metadata reads; fixtures follow installed/continued owner schemas."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('bound_lineage', ROOT / 'scripts/read-registry-bound-owner-lineage-20261023.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
BOOT = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
OLD = '11111111-2222-3333-4444-555555555555'


class Lineage(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.root.chmod(0o700)
        self.paths, self.values = [], {}
        self.first = {'state': 'TOKEN_PUBLISHED_NOT_RUNTIME_ACCEPTED', 'attemptSlotsConsumed': 1,
            'gapRemainsOpen': True, 'historicalAccountingReconciled': False,
            'legacyHistoricalGrantAttempts': None, 'bootId': OLD, 'operation': 'a'*64, 'scopeHash': 'b'*64}
        self.make_owner('early', 1, 1)
        self.make_owner('anchor', 2, 3, predecessor=0)
        self.make_owner('last', 5, 1, predecessor=1, governed=True)
        self.build_anchor()

    def put(self, path, value):
        path = Path(path)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(m.encoded(value))
        path.chmod(0o600)
        self.values[str(path)] = copy.deepcopy(value)
        return m.digest(value)

    def make_owner(self, name, prior, attempts, predecessor=None, governed=False, logical='c'*64):
        path = str(self.root/name)
        n = len(self.paths) + 1
        context, generation = m.digest({'context': n}), m.digest({'generation': n})
        policy = {'delays': [5,15,60,300,900], 'max_attempts': 60, 'max_elapsed': 3600,
            'attempt_timeout': 30, 'jitter': 0.2}
        session = {'schema': m.GOVERNED if governed else 'ouf.policy-token-new-finite-worker-session.v'+str(prior),
            'logicalOwnerScopeHash': logical, 'predecessorFirstGrantOperation': self.first['operation'],
            'predecessorFirstGrantScopeHash': self.first['scopeHash'], 'contextRef': context,
            'generationRef': generation, 'policy': policy, 'intervalSeconds': 60,
            'legacyHistoryDisposition': 'UNKNOWN_RETAINED_NOT_RECONCILED',
            'predecessorGrantAttempts': prior, 'automaticBudgetRenewalAllowed': False,
            'consumedClaimReplayAllowed': False}
        if predecessor is not None:
            p = self.paths[predecessor]
            refs = {name: m.digest(self.values[p+'/'+name]) for name in ('recovery.json','owner-session.json')}
            if governed:
                session.update(controlledHistoryProfile='ouf.policy-token-governed-worker-continuation.v1',
                    predecessorRecordHashes=refs, firstGrantReceiptHash=m.digest(self.first),
                    maximumCumulativeGrantAttempts=prior+policy['max_attempts'])
            else:
                session.update(controlledHistoryProfile='ouf.policy-token-cancelled-worker-continuation.v1',
                    predecessorCancelledWorkerHash=refs['recovery.json'], predecessorWorkerSessionHash=refs['owner-session.json'])
        row = {'schema': 'ouf.bounded-recovery.v1', 'contextRef': context, 'generationRef': generation,
            'policyHash': m.digest(policy), 'state': 'CANCELLED', 'reason': 'CANCELLED_BY_OWNER',
            'attempts': attempts, 'workerSessionHash': m.digest(session), 'firstGrantReceiptHash': m.digest(self.first),
            'controlledPredecessorGrantAttempts': prior, 'controlledCumulativeGrantAttempts': prior+attempts,
            'bootId': OLD, 'legacyHistory': {'state': 'UNKNOWN', 'cumulativeGrantAttemptCount': None,
                'reconciled': False, 'gapRemainsOpen': True}}
        for key in ('controlledHistoryProfile','predecessorCancelledWorkerHash','predecessorWorkerSessionHash'):
            if key in session:
                row[key] = session[key]
        marker = {'schema': 'ouf.policy-token-owner-admission.v1', 'ownerProfileHash': m.digest({'profile': n}),
            'contextRef': context, 'generationRef': generation, 'version': 2, 'state': 'BLOCKED',
            'tokenHash': None, 'blockedAttempt': None}
        for name, value in [('recovery.json',row), ('owner-session.json',session),
                            ('owner-admission.json',marker), ('owner-first-grant.json',self.first)]:
            self.put(path+'/'+name, value)
        self.paths.append(path)

    def build_anchor(self):
        path = self.paths[1]
        row = self.values[path+'/recovery.json']
        marker = self.values[path+'/owner-admission.json']
        session = self.values[path+'/owner-session.json']
        binding = {'endpoint': 'https://private.example/token', 'client_id': 'fixture-client', 'scope': 'read',
            'output_directory': str(self.root/'never-open-output'), 'output_member': 'token.jwt',
            'output_gid': 10001, 'minimum_remaining': 90, 'maximum_token_seconds': 3600}
        registry = {'nodeRecipe': {'renewableToken': {'source': binding['output_directory'], 'fileName': 'token.jwt',
            'gid': 10001, 'ownerBindingHash': m.digest(binding)}}}
        owner = {'binding': binding, 'contextRef': row['contextRef'], 'generationRef': row['generationRef']}
        prepared = {'registry': registry, 'owner': owner}
        declaration = {'sourceCommit': m.SOURCE}
        bundle = {'prepared': prepared, 'declaration': declaration}
        bundle_path = str(self.root/'bundle/child-bundle.json')
        bundle_hash = self.put(bundle_path, bundle)
        scope = {'schema': 'ouf.policy-token-owner-installation.v1', 'journalPath': path,
            'workerSessionScopeHash': m.digest(session), 'firstGrantReceiptHash': m.digest(self.first),
            'ownerBindingHash': marker['ownerProfileHash'], 'contextRef': row['contextRef'], 'generationRef': row['generationRef']}
        review = {'sourceClosure': {'declaration': declaration}, 'privateInputHashes': {'preparedInputs': m.digest(prepared)},
            'scopes': {'finiteActionProcess': {'bundle': {'path': bundle_path, 'sha256': bundle_hash}},
                'applicationRegistryCutover': {'preparedHash': m.digest(registry)},
                'policyTokenOwnerInstallation': scope, 'policyTokenFiniteWorkerSession': session,
                'tokenOwnerRuntime': {'ownerBindingHash': marker['ownerProfileHash']}}}
        self.context = str(self.root/'context')
        review_hash = self.put(self.context+'/review.json', review)
        inputs = {'schema': 'ouf.semantic-registry-recovery-private-historical-inputs.v1',
            'kind': 'OFFLINE_COMPOSITION_INPUTS_NOT_EXECUTABLE_AUTHORITY', 'registryInputs': registry,
            'historicalBinding': {'reviewHash': review_hash, 'preparedBundleHash': bundle_hash,
                'historicalDeploymentChainBound': True, 'historicalAuthorityReactivated': False}}
        self.inputs = str(self.root/'history/inputs.json')
        inputs_hash = self.put(self.inputs, inputs)
        self.constants = {'INPUTS': self.inputs, 'INPUTS_HASH': inputs_hash, 'CONTEXT': self.context,
            'REVIEW_HASH': review_hash}

    def observe(self):
        with patch.multiple(m, **self.constants):
            reader = m.Reader(str(self.root))
            return m.reconcile(reader, BOOT, tuple(self.paths))

    def assert_stop(self, reason):
        with self.assertRaisesRegex(m.Stop, '^'+reason+'$'):
            self.observe()

    def change(self, index, member, **updates):
        path = self.paths[index]+'/'+member
        value = copy.deepcopy(self.values[path]); value.update(updates)
        self.put(path,value)

    def test_anchor_output_and_hash_links_find_terminal_without_current_authority(self):
        result = self.observe()
        self.assertEqual(result['historicalOwnerAnchorOrdinal'], 1)
        self.assertEqual(result['boundedTerminalRecordOrdinal'], 2)
        self.assertEqual([x['controlledCumulativeGrantAttempts'] for x in result['metadataLineage']], [2,5,6])
        self.assertTrue(all(not x['sameCurrentBoot'] for x in result['metadataLineage']))
        self.assertFalse(result['currentOwnerIdentityEstablished'])
        self.assertFalse(result['boundedTerminalIsCurrentAuthority'])
        self.assertEqual(result['metadataReadOperations'], 30)

    def test_ordinal_order_is_not_temporal_selection(self):
        self.paths = [self.paths[2], self.paths[0], self.paths[1]]
        result = self.observe()
        self.assertEqual(result['boundedTerminalRecordOrdinal'], 0)
        self.assertEqual(result['historicalOwnerAnchorOrdinal'], 2)

    def test_missing_earliest_ancestor_does_not_claim_complete_accounting(self):
        self.paths = self.paths[1:]
        self.assert_stop('FIRST_CONTROLLED_GRANT_ANCESTOR_LINK_REQUIRED')

    def test_same_boot_observation_still_does_not_admit_cancelled_owner(self):
        self.first['bootId'] = BOOT
        self.paths = []
        self.make_owner('early', 1, 1)
        self.make_owner('anchor', 2, 3, predecessor=0)
        self.make_owner('last', 5, 1, predecessor=1, governed=True)
        for path in self.paths:
            row = copy.deepcopy(self.values[path+'/recovery.json'])
            # make_owner uses OLD for row.bootId; first/worker equality is separately enforced.
            row['bootId'] = BOOT
            self.put(path+'/recovery.json', row)
        # Recreate in order with boot-specific rows so predecessor hashes are exact.
        for i in (1,2):
            path = self.paths[i]
            session = copy.deepcopy(self.values[path+'/owner-session.json'])
            previous = self.paths[i-1]
            if i == 1:
                session['predecessorCancelledWorkerHash'] = m.digest(self.values[previous+'/recovery.json'])
            else:
                session['predecessorRecordHashes'] = {name: m.digest(self.values[previous+'/'+name])
                    for name in ('recovery.json','owner-session.json')}
            self.put(path+'/owner-session.json',session)
            row = copy.deepcopy(self.values[path+'/recovery.json'])
            row['workerSessionHash'] = m.digest(session)
            if i == 1:
                row['predecessorCancelledWorkerHash'] = session['predecessorCancelledWorkerHash']
            self.put(path+'/recovery.json',row)
        self.build_anchor()
        result = self.observe()
        self.assertTrue(all(x['sameCurrentBoot'] for x in result['metadataLineage']))
        self.assertFalse(result['currentOwnerAdmissionProven'])
        self.assertFalse(result['currentOwnerSelected'])

    def test_changed_counter_cannot_replace_predecessor_bound_hash(self):
        self.change(0, 'recovery.json', attempts=2, controlledCumulativeGrantAttempts=3)
        self.assert_stop('RETAINED_LINEAGE_LINK_INCOMPLETE')

    def test_counter_inconsistency_stops_not_repaired_or_summed(self):
        self.change(2, 'recovery.json', controlledCumulativeGrantAttempts=999)
        self.assert_stop('EXACT_PER_SESSION_ACCOUNTING_REQUIRED')

    def test_branch_stops_instead_of_choosing_larger_counter(self):
        self.make_owner('competing', 5, 12, predecessor=1, governed=True)
        self.assert_stop('BRANCHED_CREDENTIAL_LINEAGE')

    def test_token_output_mismatch_stops_even_with_self_consistent_new_hashes(self):
        p = self.root/'bundle/child-bundle.json'
        bundle = self.values[str(p)]
        bundle['prepared']['registry']['nodeRecipe']['renewableToken']['fileName'] = 'wrong.jwt'
        # Rebuild both historical pins to exercise semantic binding, not hash rejection.
        bh = self.put(p,bundle)
        review = self.values[self.context+'/review.json']
        review['scopes']['finiteActionProcess']['bundle']['sha256'] = bh
        review['privateInputHashes']['preparedInputs'] = m.digest(bundle['prepared'])
        review['scopes']['applicationRegistryCutover']['preparedHash'] = m.digest(bundle['prepared']['registry'])
        rh = self.put(self.context+'/review.json',review)
        inputs = self.values[self.inputs]
        inputs['registryInputs'] = bundle['prepared']['registry']
        inputs['historicalBinding'].update(reviewHash=rh,preparedBundleHash=bh)
        self.constants.update(REVIEW_HASH=rh,INPUTS_HASH=self.put(self.inputs,inputs))
        self.assert_stop('REGISTRY_OWNER_OUTPUT_BINDING_MISMATCH')

    def test_duplicate_json_and_nonfinite_values_rejected(self):
        with self.assertRaisesRegex(m.Stop,'DUPLICATE_JSON_KEY'):
            m.decode(b'{"x":1,"x":2}')
        with self.assertRaisesRegex(m.Stop,'NONFINITE_JSON_NUMBER'):
            m.decode(b'{"x":NaN}')

    def test_symlink_private_file_and_writable_ancestor_rejected(self):
        p = Path(self.paths[0])/'owner-session.json'
        saved = p.with_name('copy.json'); p.rename(saved); p.symlink_to(saved)
        self.assert_stop('METADATA_UNAVAILABLE_OR_UNSAFE')
        p.unlink(); saved.rename(p)
        Path(self.paths[0]).chmod(0o777)
        self.assert_stop('UNPROTECTED_METADATA_ANCESTOR')

    def test_hardlink_or_group_readable_metadata_rejected(self):
        p = Path(self.paths[0])/'recovery.json'
        os.link(p, p.with_name('extra.json'))
        self.assert_stop('UNPROTECTED_OR_UNBOUNDED_METADATA')
        p.with_name('extra.json').unlink(); p.chmod(0o640)
        self.assert_stop('UNPROTECTED_OR_UNBOUNDED_METADATA')

    def test_file_drift_after_first_read_is_detected(self):
        original = m.Reader.verify
        def changed(reader):
            self.change(2,'recovery.json',extraObservation=True)
            return original(reader)
        with patch.object(m.Reader,'verify',changed):
            self.assert_stop('METADATA_CHANGED_DURING_OBSERVATION')

    def test_no_secret_reads_directory_scans_or_mutating_opens(self):
        original = os.open
        leaves = set()
        def bounded(path, flags, *args, **kwargs):
            self.assertFalse(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC))
            if not flags & os.O_DIRECTORY:
                leaves.add(Path(path).name)
                self.assertIn(Path(path).name, {*m.MEMBERS,'inputs.json','review.json','child-bundle.json'})
            return original(path, flags, *args, **kwargs)
        with patch.object(m.os,'open',side_effect=bounded), patch.object(m.os,'scandir',side_effect=AssertionError):
            result = self.observe()
        text = json.dumps(result)
        for private in ('private.example','token.jwt',str(self.root),'fixture-client'):
            self.assertNotIn(private,text)
        self.assertEqual(result['credentialFilesOpened'],0)

    def test_bounded_reader_rejects_extra_reads_and_oversized_files(self):
        with patch.multiple(m,**self.constants):
            reader = m.Reader(str(self.root))
            with self.assertRaisesRegex(m.Stop,'UNAPPROVED_METADATA_READ'):
                reader.raw(str(self.root/'token.jwt'))
            reader.allowed[self.inputs] = 8
            with self.assertRaisesRegex(m.Stop,'UNPROTECTED_OR_UNBOUNDED_METADATA'):
                reader.read(self.inputs)

    def test_historical_inputs_hash_drift_stops(self):
        self.constants['INPUTS_HASH'] = '0'*64
        self.assert_stop('PINNED_METADATA_HASH_DRIFT')


if __name__ == '__main__':
    unittest.main()
