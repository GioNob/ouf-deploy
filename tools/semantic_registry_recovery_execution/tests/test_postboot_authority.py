"""Issuer safety units with explicit collaborator substitutes.

Exercises production function bodies and real private-file publication. These
units do not qualify native crypto, source closure, JVM or target recovery.
"""
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'postboot_authority.py'


def module():
    tree = ast.parse(SOURCE.read_text())
    tree.body = [node for node in tree.body if not (isinstance(node, ast.ImportFrom)
        and (node.level or (node.module or '').startswith(('tools.', 'cutover_authority', 'file_only_profile'))))]
    result = types.ModuleType('postboot_authority_test_subject')
    def require(ok, reason):
        if not ok:
            raise RuntimeError(reason)
    def encoded(value):
        return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    result.__dict__.update(require=require, encoded=encoded,
        digest=lambda value: hashlib.sha256(encoded(value)).hexdigest(),
        hashed=lambda value: type(value) is str and len(value) == 64 and set(value) <= set('abcdef0123456789'),
        PROFILE='ouf.semantic-file-only-native-proposal.v1', PHASES=('OLD_CREATE', 'OLD_START'))
    exec(compile(tree, str(SOURCE), 'exec'), result.__dict__)
    return result


class AuthorityUnits(unittest.TestCase):
    def setUp(self):
        self.m = module()
        self.review = {'schema': self.m.SCHEMA, 'intakeHash': '1'*64, 'sourceClosureHash': '2'*64,
            'creationRequestHash': '3'*64, 'predecessorHistoryHash': '4'*64, 'predecessorIncidentRef': '5'*64,
            'executionProfileHash': '6'*64, 'deploymentProfile': self.m.PROFILE, 'maximumElapsedSeconds': 900,
            'bootId': '00000000-1111-2222-3333-444444444444',
            'currentContext': {'plan': {'logicalOperationRef': '7'*64}},
            'ownerContext': {'lineageReceipt': {'logicalOwnerScopeHash': '8'*64}, 'budget': {'maximumGrantAttempts': 1}},
            'authorityInputs': {'context': {'intentIssuerRef': 'installer', 'approvalIssuerRef': 'installer',
                'installationRef': 'installation', 'entityRef': 'entity'}},
            'scopes': {'semanticRegistryPostbootOwner': {'predecessorGrantAttempts': 319}}}
        self.now = 1000

    def decision(self, review=None):
        review = review or self.review; h = self.m.digest(review)
        return {'schema': 'ouf.semantic-registry-postboot-terminal-decision.v1',
            'approvalRef': 'registry-postboot-' + h[:24] + '-1000', 'approvedReviewHash': h,
            'approvedSourceClosureHash': review['sourceClosureHash'], 'approvedAt': 1000,
            'expiresAt': 1900, 'decision': self.m.DECISION, 'state': 'ACTIVE'}

    def test_envelopes_bind_current_context_owner_and_full_review(self):
        raw, mandate, expected = self.m.envelopes(self.review, self.decision(), self.now)
        authority, human = json.loads(raw), json.loads(mandate)
        self.assertEqual(expected['intakeHash'], self.review['intakeHash'])
        self.assertNotEqual(expected['intakeHash'], self.m.digest(self.review))
        self.assertEqual(authority[self.m.REVIEW_SCOPE]['reviewHash'], self.m.digest(self.review))
        self.assertEqual(authority[self.m.REVIEW_SCOPE]['ownerContextHash'], self.m.digest(self.review['ownerContext']))
        self.assertEqual(human['executionAuthorityHash'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(authority['semanticRegistryPostbootOwner']['predecessorGrantAttempts'], 319)
        self.assertFalse(authority['automaticReplayAllowed'])
        self.assertFalse(authority['budgetReset'])
        self.assertNotIn('applicationRegistryCutover', authority)

    def test_changed_review_old_decision_and_expiry_denied(self):
        decision = self.decision(); review = copy.deepcopy(self.review)
        review['ownerContext']['budget']['maximumGrantAttempts'] = 2
        for candidate, when in ((review, 1000), (self.review, 1900), (self.review, 999)):
            with self.subTest(when=when), self.assertRaisesRegex(RuntimeError, 'EXACT_CURRENT'):
                self.m.envelopes(candidate, decision, when)

    def test_claim_identity_ignores_changed_review_budget_and_source(self):
        before = self.m.claim_name(self.review); altered = copy.deepcopy(self.review)
        altered['ownerContext']['budget']['maximumGrantAttempts'] = 128
        altered['sourceClosureHash'] = '9'*64
        self.assertEqual(before, self.m.claim_name(altered))
        altered['bootId'] = '00000000-1111-2222-3333-555555555555'
        self.assertNotEqual(before, self.m.claim_name(altered))

    def test_duplicate_json_and_noncanonical_json_denied(self):
        for raw in (b'{"a":1,"a":2}', b'{ "a": 1 }', b'{"a":NaN}'):
            with self.subTest(raw=raw), self.assertRaises(RuntimeError):
                self.m.decode(raw)

    def test_review_requires_independent_exact_scope_set(self):
        review = self.review
        context = {'plan': {'stages': [{'intent': {'historicalChainHash': 'a'*64}}],
            'retainedPredecessorIncidentRef': 'b'*64}, 'nodeRecipe': {'sourceClosureHash': 'c'*64}}
        closure = {'schema': 'ouf.semantic-registry-postboot-source-closure.v1',
            'entryModule': 'tools.semantic_registry_recovery_execution.postboot_entry',
            'runtimeAuthorityIssued': False, 'targetInstallationAccepted': False, 'releaseAcceptance': False,
            'sourceHashes': {'module': 'd'*64}}
        context['nodeRecipe']['sourceClosureHash'] = self.m.digest(closure)
        owner = {'recovery': {'bootId': review['bootId']}, 'sourceClosureHash': self.m.digest(closure),
            'sourceFiles': {'module': {'sha256': 'd'*64}}}
        expected = {'scopeA': {'real': 'computed'}, 'scopeB': {'deny': False}}
        self.m.KEYS = frozenset(expected)
        self.m.retained = lambda _: {'creationRequest': {}, 'configtree': {}}
        self.m.FileOnlyProfile = lambda *_: types.SimpleNamespace(sha256='e'*64)
        self.m.compile_scopes = lambda *_: copy.deepcopy(expected)
        self.m.authority_metadata = lambda _: None
        self.m.compile_review(context, owner, {}, closure, expected)
        for bad in ({'scopeA': expected['scopeA']}, {**expected, 'scopeC': {}},
                    {**expected, 'scopeB': {'deny': True}}):
            with self.assertRaisesRegex(RuntimeError, 'INDEPENDENT_COMPLETE'):
                self.m.compile_review(context, owner, {}, closure, bad)

    def test_publish_is_exclusive_and_retains_partial_attempt(self):
        with tempfile.TemporaryDirectory(dir=SOURCE.parents[3]) as d:
            with self.m.protected_directory(Path(d)) as fd:
                self.m.publish(fd, 'claim.json', b'{"state":"CONSUMED"}')
                with self.assertRaises(FileExistsError):
                    self.m.publish(fd, 'claim.json', b'{"state":"REPLACED"}')
            path = Path(d) / 'claim.json'
            self.assertEqual(path.read_bytes(), b'{"state":"CONSUMED"}')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_second_signature_failure_consumes_claim_and_cannot_repeat(self):
        with tempfile.TemporaryDirectory(dir=SOURCE.parents[3]) as d:
            parent = Path(d); root = parent / ('semantic-registry-postboot-inputs-' + 'a'*64)
            root.mkdir(mode=0o700); self.m.PARENT = parent
            self.m.read_review = lambda *_: copy.deepcopy(self.review)
            self.m.execution_custody = lambda *_: None
            self.m.terminal_decision = lambda *_: self.decision()
            self.m.authority_metadata = lambda _: ({'keyBindings': {'installer': {}}, 'keyRefs': {'installer': 'key'}}, {})
            gate = types.SimpleNamespace(mandate=lambda _: None)
            self.m.build_runtime = lambda *_: (gate, b'', object(), object())
            signed = []
            class Signer:
                def __init__(inner, key, ref, verifier, scope): inner.role = scope['role']
                def sign(inner, raw):
                    self.assertTrue((parent / self.m.claim_name(self.review)).exists())
                    signed.append(inner.role)
                    if len(signed) == 2:
                        raise RuntimeError('SIMULATED_SECOND_SIGNATURE_FAILURE')
                    return b'{"fixture":"first-signature"}'
            self.m.ExistingEd25519Signer = Signer
            binding = {'path': str(root / 'review.json'), 'sha256': self.m.digest(self.review)}
            with patch.object(self.m.time, 'time', return_value=1000):
                with self.assertRaisesRegex(RuntimeError, 'SIMULATED_SECOND'):
                    self.m.issue(root, binding, self.m.digest(self.review))
                self.assertFalse((root / 'authority' / 'receipt.json').exists())
                with self.assertRaisesRegex(RuntimeError, 'POSTBOOT_ISSUANCE_ALREADY_CONSUMED'):
                    self.m.issue(root, binding, self.m.digest(self.review))
            self.assertEqual(signed, ['DEPLOYMENT_INTENT', 'FINAL_DEPLOYMENT_APPROVAL'])

    def test_approval_hash_mismatch_before_prompt_or_key(self):
        self.m.read_review = lambda *_: copy.deepcopy(self.review)
        self.m.checked_root = lambda *_: Path('/fixture')
        with patch.object(self.m, 'terminal_decision', side_effect=AssertionError('prompt reached')):
            with self.assertRaisesRegex(RuntimeError, 'EXPLICIT_CURRENT'):
                self.m.issue('/fixture', {}, 'f'*64)


if __name__ == '__main__':
    unittest.main()
