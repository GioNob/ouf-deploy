"""Real existing signed owner, finite journal and pinned Java role constraints.

Transport is an explicit HTTP/IAM fixture; no target login or publication.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT/'tests')]
import test_chatbot_cohort_authorization as existing
import tools.chatbot_file_cohort.authorization as auth


def primitives(test):
    import tempfile,shutil
    owner=Path(os.environ['OUF_REVISION_ONBOARDING_ROOT'])
    temporary=tempfile.TemporaryDirectory();test.addCleanup(temporary.cleanup)
    root=Path(temporary.name)
    names=('scripts/r4a_authorization_lifecycle.py','scripts/r4a_keycloak_client_scope_catalogue.py')
    for name in names:
        target=root/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(owner/name,target)
    catalogue=auth.DISCOVERY_CATALOGUE
    target=root/catalogue;target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(ROOT/catalogue,target)
    bindings={name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in (*names,catalogue)}
    return auth.OwnerPrimitives(root,bindings,profile=auth.DISCOVERY_PROFILE)


class DiscoveryCompiler(unittest.TestCase):
    def setUp(self):
        self.primitives = primitives(self)
        self.selection, self.observed = existing.fixture()

    def compile(self):
        return auth.compile_plan(self.observed, self.primitives, self.selection,
                                 include_ingestion_status=False, now='2026-10-18T06:00:00Z')

    def test_exact_three_discovery_capabilities_and_one_oauth_scope(self):
        plan = self.compile()
        self.assertEqual({r['descriptor']['capabilityId'] for r in self.primitives.descriptors}, set(auth.DISCOVERY))
        self.assertEqual(set(plan['addedDescriptors'][i]['capabilityId'] for i in range(3)), set(auth.DISCOVERY))
        self.assertEqual({r['descriptor']['capabilityId'] for r in plan['registrationAdditions']}, set(auth.DISCOVERY))
        self.assertEqual({p['capabilityId'] for p in plan['addedPermissions']}, set(auth.DISCOVERY))
        self.assertEqual(set(plan['scopeCreations']), {auth.DISCOVERY_SCOPE})
        self.assertEqual({b['purpose'] for b in plan['scopeBindings']}, {'chatgpt'})
        self.assertEqual(plan['requiredScopes'], {'chatgpt':[auth.DISCOVERY_SCOPE],'ths':[]})
        self.assertEqual(plan['candidatePolicy']['grants'], self.observed['active']['policy']['grants'])
        self.assertEqual(plan['targetRoles']['assignments'], self.observed['roles']['assignments'])
        self.assertEqual(existing.owner_constraint_roundtrip(plan['targetRoles']), plan['targetRoles'])
        self.assertEqual(auth.authorization_scope(plan)['profile'], auth.DISCOVERY_PROFILE)
        self.assertFalse(plan['issueTokens']); self.assertFalse(plan['revokeSessions'])

    def test_unrelated_status_extension_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'EXCLUDES_UNRELATED_STATUS'):
            auth.compile_plan(self.observed, self.primitives, self.selection)

    def test_unknown_profile_and_changed_owner_contract_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'EXACT_AUTHORIZATION_PROFILE'):
            auth.profile_definition('caller-defined-profile')
        self.primitives.catalogue[-1]['descriptor']['operation'] = 'COMMAND'
        with self.assertRaisesRegex(ValueError, 'SEMANTICS_CHANGED'):
            self.compile()

    def test_catalogue_must_include_exactly_the_three_discovery_descriptors(self):
        self.primitives.catalogue = self.primitives.catalogue[:-1]
        with self.assertRaisesRegex(ValueError, 'EXACT_PROFILE_CAPABILITY_CATALOGUE'):
            self.compile()

    def test_read_capability_cannot_require_an_invented_separate_oauth_scope(self):
        self.primitives.catalogue[-1]['descriptor']['requiredScope']='ouf.semantic.discovery.candidates'
        with self.assertRaisesRegex(ValueError,'SEMANTICS_CHANGED'):
            self.compile()

    def test_only_discovery_permissions_are_added_and_existing_roles_remain_unchanged(self):
        before=copy.deepcopy(self.observed)
        plan=self.compile()
        self.assertEqual(self.observed,before)
        self.assertEqual(plan['targetRoles']['assignments'],before['roles']['assignments'])
        self.assertEqual(plan['requiredScopes']['ths'],[])
        self.assertEqual(plan['targetRoles']['roles'][0]['permissions'][:-3],before['roles']['roles'][0]['permissions'])
        for permission in plan['addedPermissions']:
            self.assertIn(permission['capabilityId'],auth.DISCOVERY)
            self.assertIsNone(permission['constraints']['resourceType'])
            self.assertEqual(permission['constraints']['allowedDataLabels'],[])
        self.assertTrue(plan['preserveExistingGrants'])
        self.assertTrue(plan['preserveRoleAssignments'])
        self.assertFalse(plan['issueTokens'])
        self.assertFalse(plan['revokeSessions'])

    def test_expired_nominal_assignment_cannot_prepare_discovery_mandate(self):
        self.observed['roles']['assignments'][0]['validUntil']='2026-01-01T00:00:00Z'
        with self.assertRaisesRegex(ValueError,'NOMINAL_ADMIN_ASSIGNMENT'):
            self.compile()

    def test_conflicting_existing_registration_is_not_overwritten(self):
        cap = next(iter(auth.DISCOVERY))
        self.observed['registrations'][cap] = {'ownerRef':'wrong', 'descriptor':{}}
        with self.assertRaisesRegex(ValueError, 'REGISTRATION_CONFLICT'):
            self.compile()


class DiscoverySignedOwner(unittest.TestCase):
    def setUp(self):
        self.crypto = existing.signed.SignedCutover()
        self.crypto.setUp(); self.addCleanup(self.crypto.doCleanups)
        self.primitives = primitives(self)
        self.selection, observed = existing.fixture()
        self.plan = auth.compile_plan(observed, self.primitives, self.selection,
                                      include_ingestion_status=False, now='2026-10-18T06:00:00Z')
        f = self.crypto
        authority = json.loads(f.authority)
        authority['chatbotFileAuthorization'] = auth.authorization_scope(self.plan)
        f.authority = existing.encoded(authority)
        f.approval['executionAuthorityHash'] = existing.signed.sha(f.authority)
        f.write(f.mandate, existing.encoded(f.approval))
        f.approved = existing.signed.sha(f.mandate.read_bytes())
        for role in f.grant['roles']: f.sign(role)
        action = existing.AggregateAction(f.gate(), f.authority, f.expected['sourceClosureHash'])
        directory = f.root/'discovery-authorization'; directory.mkdir(mode=0o700)
        self.journal = existing.Journal(directory)
        self.transport = auth.OwnerTransport(self.selection, f.root/'unused-admin.jwt', f.root/'unused-mcp.jwt')
        self.owner = existing.OwnerFixture(observed, self.plan)
        for method in ('observe','active','roles','registrations','oauth','request','kc','tool'):
            patcher = patch.object(self.transport, method, side_effect=getattr(self.owner,method))
            patcher.start(); self.addCleanup(patcher.stop)
        self.delta = auth.AuthorizationDelta(action, self.plan, self.journal, self.transport, self.primitives)
        self.delta.initialize()

    def prepare(self):
        with self.assertRaisesRegex(auth.AuthorizationPaused, 'HUMAN_OWNER_ROLE_CONFIRMATION_REQUIRED'):
            self.delta.apply()

    def test_native_human_confirmation_and_exact_resume_preserve_old_grants(self):
        self.prepare()
        self.assertEqual(self.owner.roles(), self.plan['baseline']['roles'])
        self.assertEqual(self.owner.active()['policy']['grants'], self.plan['baseline']['active']['policy']['grants'])
        self.prepare()
        self.assertEqual(len(self.owner.drafts), 1); self.assertEqual(len(self.owner.proposals), 1)
        self.owner.human_confirms()
        receipt = self.delta.apply()
        self.assertTrue(receipt['existingGrantsPreserved'])
        self.assertTrue(receipt['existingRoleAssignmentsPreserved'])
        self.assertFalse(receipt['freshClientTokenScopesProven'])
        self.assertEqual(self.owner.calls.count(('POST', auth.ADMIN+'/capabilities')), 3)
        mutations = [c for c in self.owner.calls if c[0] in
                     ('POST','KC:create','KC:update','KC:delete','authorization.permissions.propose')]
        self.delta.apply()
        self.assertEqual(mutations, [c for c in self.owner.calls if c[0] in
                         ('POST','KC:create','KC:update','KC:delete','authorization.permissions.propose')])
        again = auth.compile_plan(self.owner.observe(), self.primitives, self.selection,
                                  include_ingestion_status=False)
        self.assertIsNone(again['roleProposal']); self.assertFalse(again['addedDescriptors'])
        self.assertFalse(again['scopeCreations']); self.assertFalse(again['scopeBindings'])

    def test_signed_installation_adds_only_one_shared_oauth_scope(self):
        self.prepare();self.owner.human_confirms();self.delta.apply()
        self.assertEqual(self.owner.calls.count(('KC:create','client-scopes')),1)
        self.assertEqual(set(self.plan['scopeCreations']),{auth.DISCOVERY_SCOPE})
        self.assertEqual(len(self.plan['scopeBindings']),1)
        self.assertEqual(self.plan['scopeBindings'][0]['scopeName'],auth.DISCOVERY_SCOPE)
        self.assertEqual(self.plan['scopeBindings'][0]['purpose'],'chatgpt')

    def test_lost_registration_reply_reconciles_without_duplicate_dispatch(self):
        self.owner.lost = ('POST', auth.ADMIN+'/capabilities')
        with self.assertRaisesRegex(auth.AuthorizationPaused, 'LOST_RESPONSE'):
            self.delta.apply()
        self.prepare()
        self.assertEqual(self.owner.calls.count(('POST', auth.ADMIN+'/capabilities')), 3)

    def test_ambiguous_policy_creation_never_creates_a_second_draft(self):
        self.owner.lost = ('POST', auth.ADMIN+'/policies')
        with self.assertRaisesRegex(auth.AuthorizationPaused, 'LOST_RESPONSE'):
            self.delta.apply()
        with self.assertRaisesRegex(auth.AuthorizationPaused, 'EFFECT_RECONCILIATION_REQUIRED'):
            self.delta.apply()
        self.assertEqual(len(self.owner.drafts), 1)
        self.delta.reconcile_draft(next(iter(self.owner.drafts))); self.prepare()
        self.assertEqual(len(self.owner.drafts), 1)

    def test_existing_signed_profile_cannot_be_swapped_to_the_new_profile(self):
        changed = copy.deepcopy(self.plan); changed['profile'] = auth.PROFILE
        with self.assertRaisesRegex(ValueError, 'PLAN_SELECTION'):
            auth.AuthorizationDelta(self.delta.action, changed, self.journal, self.transport, self.primitives)
        self.assertFalse(self.owner.calls)

    def test_revocation_stops_before_any_owner_or_iam_request(self):
        f = self.crypto
        f.approval['state'] = 'REVOKED'; f.write(f.mandate, existing.encoded(f.approval))
        with self.assertRaises(Exception): self.delta.apply()
        self.assertFalse(self.owner.calls)


if __name__ == '__main__': unittest.main()
