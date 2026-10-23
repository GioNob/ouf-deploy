"""Private preparation custody and exact frozen-input tests.

These exercise actual local files and timers. They do not attest target Engine,
IAM, Registry, or application readiness; those require native qualification.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import tempfile
import time
import unittest
from unittest.mock import patch

from tools.semantic_registry_recovery_execution import core as c
from tools.semantic_registry_recovery_execution import postboot_prepare as p

ROOT = Path(__file__).resolve().parents[3]


class Preparation(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.geteuid(), 0, 'private preparation qualification requires root')
        temporary = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.reference = {'sourceId': 'fixture-source',
            'onboardingVersionId': '00000000-0000-0000-0000-000000000001',
            'configurationHash': 'sha256:' + 'a' * 64}
        self.semantic = {'semanticId': 'urn:fixture:città', 'semanticVersion': '1.0',
            'revisionId': '00000000-0000-0000-0000-000000000002',
            'publicationSetId': '00000000-0000-0000-0000-000000000003'}
        configuration = {'semanticReferenceBindings': [self.semantic],
            'semanticMapping': {'semanticRefs': ['urn:fixture:città@1.0']}}
        self.reference['configurationHash'] = 'sha256:' + hashlib.sha256(json.dumps(configuration,
            sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
        self.frozen = {**self.reference, 'state': 'APPROVED', 'configuration': configuration}

    def write(self, name, value=b'fixture'):
        target = self.root / name
        target.write_bytes(value)
        target.chmod(0o400)
        return target

    def test_failed_preparation_is_linked_with_attempts_retained_and_never_changed(self):
        case = {'fixture': 'original'}
        boot = '00000000-1111-2222-3333-444444444444'
        prior = {'sourceClosureHash': 'a' * 64, 'caseHash': c.digest(case),
                 'engineAttempts': 6, 'adminAttempts': 1, 'frozenAttempts': 0}
        root = self.root / ('semantic-registry-postboot-inputs-' + c.digest({
            'case': case, 'closure': prior['sourceClosureHash'], 'boot': boot}))
        root.mkdir(mode=0o700)
        claim = {'schema': p.SCHEMA, 'caseHash': prior['caseHash'], 'sourceClosureHash': prior['sourceClosureHash'],
                 'bootId': boot, 'maximumEngineGets': 12, 'maximumAdminGets': 1, 'maximumFrozenGets': 1,
                 'automaticReplayAllowed': False, 'runtimeAuthorityIssued': False}
        p.publish(root, 'claim.json', claim)
        for number in range(1, 7):
            p.publish(root, 'engine-get-' + str(number) + '.json', {'requestPathHash': 'b' * 64, 'attempt': number})
        p.publish(root, 'admin-get.json', {'method': 'GET', 'operation': '/apisix/admin/routes', 'maximumAttempts': 1})
        before = {f.name: (f.read_bytes(), f.stat()) for f in root.iterdir()}
        current = dict(case, priorPreparation=prior)
        with patch.object(p, 'PARENT', str(self.root)):
            proof = p.reconcile_prior_preparation(current, p.Files(), boot)
            self.assertEqual(proof['priorAttemptCounts']['engineGets'], 6)
            self.assertEqual(proof['cumulativeAttemptCeilings']['engineGets'], 18)
            self.assertFalse(proof['oldPreparationReplayed'])
            for f in root.iterdir():
                self.assertEqual((f.read_bytes(), f.stat()), before[f.name])
            p.publish(root, 'frozen-get.json', {'attempt': 1})
            with self.assertRaisesRegex(c.RecoveryDenied, 'ADVANCED_RECONCILE'):
                p.reconcile_prior_preparation(current, p.Files(), boot)
            (root / 'frozen-get.json').unlink()
            claim['bootId'] = '00000000-1111-2222-3333-555555555555'
            (root / 'claim.json').chmod(0o600); (root / 'claim.json').write_bytes(c.encoded(claim))
            with self.assertRaisesRegex(c.RecoveryDenied, 'PRIOR_PREPARATION_CLAIM'):
                p.reconcile_prior_preparation(current, p.Files(), boot)

    def test_private_pin_detects_atomic_replacement_even_with_same_bytes(self):
        target = self.write('input.json', c.encoded({'fixture': True}))
        files = p.Files()
        value, binding = files.json(str(target))
        self.assertEqual(value, {'fixture': True})
        replacement = self.write('replacement.json', target.read_bytes())
        os.replace(replacement, target)
        with self.assertRaisesRegex(c.RecoveryDenied, 'PREPARATION_INPUT_CHANGED'):
            files.verify()
        self.assertNotEqual(binding['metadata'][1], target.stat().st_ino)

    def test_symlink_hardlink_and_writable_parent_are_not_private_pins(self):
        target = self.write('source')
        link = self.root / 'link'; link.symlink_to(target)
        with self.assertRaises((OSError, c.RecoveryDenied)):
            p.Files().seal(str(link), 32)
        hard = self.root / 'hard'; os.link(target, hard)
        with self.assertRaisesRegex(c.RecoveryDenied, 'PROTECTED_PREPARATION_FILE'):
            p.Files().seal(str(target), 32)
        hard.unlink(); self.root.chmod(0o777)
        try:
            with self.assertRaisesRegex(c.RecoveryDenied, 'PROTECTED_PREPARATION_ANCESTRY'):
                p.Files().seal(str(target), 32)
        finally:
            self.root.chmod(0o700)

    def test_credential_custody_never_opens_or_reads_credential_member(self):
        secret = self.write('client-secret', b'PRIVATE_FIXTURE_NEVER_READ')
        with patch.object(p.os, 'open', wraps=os.open) as opened, patch.object(p.os, 'read', side_effect=AssertionError('no bytes')):
            result = p.Files().stat_private(str(secret))
        self.assertEqual(result, p.metadata(secret.stat()))
        self.assertFalse(any(str(call.args[0]).endswith('client-secret') for call in opened.call_args_list))

    def test_duplicate_json_noncanonical_json_and_byte_overrun_are_rejected(self):
        with self.assertRaisesRegex(c.RecoveryDenied, 'DUPLICATE'):
            p.decode(b'{"a":1,"a":2}')
        with self.assertRaisesRegex(c.RecoveryDenied, 'NONFINITE'):
            p.decode(b'{"a":NaN}')
        target = self.write('not-canonical.json', b'{"a": 1}\n')
        with self.assertRaisesRegex(c.RecoveryDenied, 'CANONICAL'):
            p.Files().json(str(target))
        with self.assertRaisesRegex(c.RecoveryDenied, 'BOUNDED_PREPARATION_FILE'):
            p.Files().seal(str(target), 1)

    def test_claim_publication_is_exclusive_and_does_not_overwrite_partial_result(self):
        first = {'attempt': 1, 'automaticReplayAllowed': False}
        p.publish(self.root, 'claim.json', first)
        with self.assertRaises(FileExistsError):
            p.publish(self.root, 'claim.json', {'attempt': 0})
        target = self.root / 'claim.json'
        self.assertEqual(target.read_bytes(), c.encoded(first))
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o400)

    def test_source_profiles_point_to_real_immutable_files_with_exact_bytes(self):
        sources = {name: ('# exact ' + name + '\nVALUE=1\n').encode() for name in p.owner_contract.SOURCE_FILES}
        manifest = {'sourceHashes': {name: hashlib.sha256(raw).hexdigest() for name, raw in sources.items()}}
        files = p.Files(); profiles = p.source_files(self.root, manifest, sources, files)
        self.assertEqual(set(profiles), p.owner_contract.SOURCE_FILES)
        for name, profile in profiles.items():
            target = Path(profile['path'])
            self.assertEqual(target.read_bytes(), sources[name])
            self.assertEqual(profile['metadata'], p.metadata(target.stat()))
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o400)
            self.assertEqual(profile['sha256'], manifest['sourceHashes'][name])
        self.assertEqual(stat.S_IMODE((self.root / 'source').stat().st_mode), 0o500)
        files.verify()

    def test_mount_selection_requires_one_exact_readonly_bind(self):
        actual = {'Mounts': [{'Destination': '/run/service', 'Source': '/private/service', 'Type': 'bind', 'RW': False}]}
        self.assertEqual(p.mounted_source(actual, '/run/service/token.jwt'), '/private/service/token.jwt')
        for mutation in ('write', 'shadow', 'volume'):
            changed = copy.deepcopy(actual)
            if mutation == 'write': changed['Mounts'][0]['RW'] = True
            if mutation == 'shadow': changed['Mounts'].append({**changed['Mounts'][0], 'Destination': '/run'})
            if mutation == 'volume': changed['Mounts'][0]['Type'] = 'volume'
            with self.subTest(mutation=mutation), self.assertRaisesRegex(c.RecoveryDenied, 'ONE_READONLY'):
                p.mounted_source(changed, '/run/service/token.jwt')

    def test_frozen_configuration_preserves_unicode_checksum_and_all_four_reference_fields(self):
        before = copy.deepcopy(self.frozen)
        self.assertEqual(p.frozen_configuration(self.frozen, self.reference), [self.semantic])
        self.assertEqual(self.frozen, before)
        p.frozen_query(self.reference)

    def test_changed_source_version_state_configuration_and_reference_set_are_rejected(self):
        for field in ('sourceId', 'onboardingVersionId', 'state', 'configuration', 'references'):
            value = copy.deepcopy(self.frozen)
            if field in ('sourceId', 'onboardingVersionId'): value[field] = 'different'
            if field == 'state': value[field] = 'DRAFT'
            if field == 'configuration': value[field]['unreviewed'] = True
            if field == 'references': value['configuration']['semanticMapping']['semanticRefs'] = []
            with self.subTest(field=field), self.assertRaises(c.RecoveryDenied):
                p.frozen_configuration(value, self.reference)

    def test_hard_deadline_interrupts_blocked_preparation_and_restores_handler(self):
        original = signal.getsignal(signal.SIGALRM)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        with patch.object(p, 'MAX_SECONDS', 0.02), patch.object(p, '_prepare', side_effect=lambda *args: time.sleep(1)):
            with self.assertRaisesRegex(c.RecoveryDenied, 'PREPARATION_DEADLINE'):
                p.prepare({}, {}, {})
        self.assertEqual(signal.getsignal(signal.SIGALRM), original)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))

    def test_completed_preparation_reopens_only_same_case_boot_and_actual_source_files(self):
        from tools.semantic_registry_postboot_owner.tests.fixture import make_context
        boot = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        output = self.root / 'output'; output.mkdir(mode=0o750)
        secret = self.write('existing-client-secret')
        binding = {'endpoint': 'https://fixture.invalid/token', 'client_id': 'fixture', 'scope': 'policy:read',
            'output_directory': str(output), 'output_member': 'token.jwt', 'output_gid': 10001,
            'minimum_remaining': 90, 'maximum_token_seconds': 3600}
        sources = {name: b'# fixture source\nVALUE=1\n' for name in p.owner_contract.SOURCE_FILES}
        manifest = {'sourceHashes': {name: hashlib.sha256(raw).hexdigest() for name, raw in sources.items()}}
        owner = make_context(self.root / 'metadata', binding, {}, 'c' * 64, secret,
            {'planHash': 'a' * 64, 'logicalOperationRef': 'b' * 64, 'registryId': 'c' * 64, 'bootId': boot},
            c.digest(manifest), source_paths={name: Path(p.owner_contract.__file__) for name in sources})
        owner['lineageReceipt'].update(historicalInputsHash='a' * 64, historicalReviewHash='b' * 64)
        case = {'schema': p.SCHEMA, 'privateParent': str(self.root),
            'retainedInputs': {'path': str(self.root / 'retained/inputs.json'), 'sha256': 'a' * 64},
            'historicalReview': {'path': str(self.root / 'review/review.json'), 'sha256': 'b' * 64},
            'patchContext': str(self.root / 'patch'), 'lineageReceipt': owner['lineageReceipt'],
            'predecessorJournalPath': owner['predecessorJournalPath'], 'frozenReference': self.reference,
            'proposedOwnerBudget': owner['budget'], 'originalRequestTls': None}
        with patch.object(p, 'PARENT', str(self.root)), patch.object(p.Path, 'read_text', return_value=boot):
            root = p.prepared_root(case, manifest); root.mkdir(mode=0o700)
            owner['sourceFiles'] = p.source_files(root, manifest, sources, p.Files())
            private = {'schema': 'ouf.semantic-registry-postboot-prepared-inputs.v1',
                'nativeContext': {'retainedInputs': case['retainedInputs']}, 'ownerContext': owner,
                'registryInputs': {}, 'authorityInputs': {}, 'sourceClosure': manifest,
                'preparationProof': {'caseHash': c.digest(case), 'sourceClosureHash': c.digest(manifest), 'bootId': boot}}
            p.publish(root, 'prepared.json', private)
            result = p.read_prepared(case, manifest)
            self.assertEqual(result['privatePreparationPath'], str(root / 'prepared.json'))
            self.assertEqual(result['privatePreparationHash'], c.digest(private))
            self.assertNotEqual(p.prepared_root(case, manifest, 'ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee'), root)
            changed = next(iter(owner['sourceFiles'].values()))
            Path(changed['path']).chmod(0o600); Path(changed['path']).write_bytes(b'CHANGED')
            with self.assertRaisesRegex(c.RecoveryDenied, 'RETAINED_PREPARATION_HASH_CHANGED'):
                p.read_prepared(case, manifest)


if __name__ == '__main__':
    unittest.main()
