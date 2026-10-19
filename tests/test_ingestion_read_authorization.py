"""One native read capability only; reuses exact owner helpers and lifecycle."""
import copy,hashlib,json,os,shutil,tempfile,unittest
from pathlib import Path
import sys
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_chatbot_cohort_authorization as existing
import tools.chatbot_file_cohort.authorization as auth

class IngestionOperationalReadPlan(unittest.TestCase):
 def setUp(self):
  self.selection,self.observed=existing.fixture()
  self.observed['registrations'].pop('ingestion.operations.read')
  p=self.observed['active']['policy']
  p['capabilities']=[c for c in p['capabilities'] if c['capabilityId']!='ingestion.operations.read']
  self.observed['active']['contentHash']=auth.digest(p)
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  root=Path(self.tmp.name);owner=Path(os.environ['OUF_REVISION_ONBOARDING_ROOT'])
  names=('scripts/r4a_authorization_lifecycle.py','scripts/r4a_keycloak_client_scope_catalogue.py')
  for n in names:
   dest=root/n;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(owner/n,dest)
  manifest=root/'catalogue/chatbot-source-review-capabilities.json';manifest.parent.mkdir()
  manifest.write_text(json.dumps([{'ownerRef':'ingestion','descriptor':{'capabilityId':'ingestion.operations.read','operation':'READ','requiredScope':'ingestion.operations.read','allowedActors':['HUMAN']}}]))
  paths=(*names,'catalogue/chatbot-source-review-capabilities.json')
  bindings={n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in paths}
  self.primitives=auth.OwnerPrimitives(root,bindings,profile=auth.INGESTION_READ_PROFILE)
 def compile(self,**kw):
  return auth.compile_plan(self.observed,self.primitives,self.selection,include_ingestion_status=False,
      source_id=kw.pop('source_id','fixture-source'),now='2026-10-19T08:00:00Z',**kw)
 def test_one_exact_descriptor_and_source_scoped_read_with_native_constraints(self):
  plan=self.compile()
  self.assertEqual(plan['registrationAdditions'],self.primitives.catalogue)
  self.assertEqual(plan['addedDescriptors'],[self.primitives.catalogue[0]['descriptor']])
  permission=plan['readScope']
  self.assertEqual(permission['capabilityId'],'ingestion.operations.read')
  self.assertEqual(permission['constraints']['resourceType'],'operational')
  self.assertEqual(permission['constraints']['resourceAttributes'],{'module':'INGESTION','sourceRef':'fixture-source'})
  self.assertEqual(permission['constraints']['allowedDetailLevels'],['TENANT_OPERATIONAL'])
  self.assertEqual(plan['addedPermissions'],[]);self.assertIsNone(plan['roleProposal'])
  self.assertEqual(plan['targetRoles'],self.observed['roles'])
  self.assertTrue(plan['readScope']['separateFiniteGrantReviewRequired'])
  self.assertFalse(plan['readScope']['grantPublicationAllowed'])
  self.assertEqual(existing.owner_constraint_roundtrip(plan['targetRoles']),plan['targetRoles'])
 def test_preserves_prior_policy_roles_assignments_and_oauth(self):
  before=copy.deepcopy(self.observed);plan=self.compile()
  self.assertEqual(self.observed,before)
  self.assertEqual(plan['candidatePolicy']['grants'],before['active']['policy']['grants'])
  self.assertEqual(plan['targetRoles']['assignments'],before['roles']['assignments'])
  self.assertEqual(plan['candidatePolicy']['capabilities'][:-1],before['active']['policy']['capabilities'])
  self.assertEqual(plan['requiredScopes'],{'chatgpt':['ingestion.operations.read'],'ths':[]})
  self.assertEqual(set(plan['scopeCreations']),{'ingestion.operations.read'})
  self.assertEqual(len(plan['scopeBindings']),1)
  self.assertFalse(plan['runtimeAuthorityIssued']);self.assertFalse(plan['issueTokens']);self.assertFalse(plan['revokeSessions'])
 def test_no_source_no_wildcard_and_no_legacy_status_expansion(self):
  for source in (None,'','*','source/foreign'):
   with self.assertRaises(Exception):self.compile(source_id=source)
  with self.assertRaises(Exception):
   auth.compile_plan(self.observed,self.primitives,self.selection,source_id='fixture-source')
 def test_conflicting_existing_descriptor_blocks_and_other_role_permissions_remain(self):
  self.observed['registrations']['ingestion.operations.read']={'ownerRef':'wrong','descriptor':self.primitives.catalogue[0]['descriptor']}
  with self.assertRaises(Exception):self.compile()
  self.observed['registrations'].clear()
  self.observed['roles']['roles'][0]['permissions']=[{'capabilityId':'ingestion.operations.read','constraints':auth.owner_permission_constraints('operational',{'module':'INGESTION','sourceRef':'other-source'},['TENANT_OPERATIONAL'])}]
  plan=self.compile()
  self.assertEqual(plan['targetRoles'],self.observed['roles']);self.assertIsNone(plan['roleProposal'])
 def test_exact_existing_registration_is_reused_without_republication(self):
  row=copy.deepcopy(self.primitives.catalogue[0]);self.observed['registrations']['ingestion.operations.read']=row
  self.observed['active']['policy']['capabilities'].append(row['descriptor'])
  plan=self.compile()
  self.assertEqual(plan['registrationAdditions'],[]);self.assertEqual(plan['addedDescriptors'],[])
 def test_profile_never_admits_other_capabilities_or_weakens_legacy_contract(self):
  self.assertEqual(set(auth.profile_definition(auth.INGESTION_READ_PROFILE)['new']),{'ingestion.operations.read'})
  self.assertEqual(set(auth.profile_definition(auth.REVISION_PROFILE)['new']),set(auth.REVISION))
  with self.assertRaises(Exception):auth.profile_definition('caller-selected-profile')

class IngestionReadSignedOwner(unittest.TestCase):
    compile = IngestionOperationalReadPlan.compile
    def setUp(self):
        IngestionOperationalReadPlan.setUp(self)
        self.crypto = existing.signed.SignedCutover()
        self.crypto.setUp(); self.addCleanup(self.crypto.doCleanups)
        observed = self.observed
        self.plan = self.compile()
        f = self.crypto
        authority = json.loads(f.authority)
        authority['chatbotFileAuthorization'] = auth.authorization_scope(self.plan)
        f.authority = existing.encoded(authority)
        f.approval['executionAuthorityHash'] = existing.signed.sha(f.authority)
        f.write(f.mandate, existing.encoded(f.approval))
        f.approved = existing.signed.sha(f.mandate.read_bytes())
        for role in f.grant['roles']: f.sign(role)
        action = existing.AggregateAction(f.gate(), f.authority, f.expected['sourceClosureHash'])
        directory = f.root/'revision-authorization'; directory.mkdir(mode=0o700)
        self.journal = existing.Journal(directory)
        self.transport = auth.OwnerTransport(self.selection, f.root/'unused-admin.jwt', f.root/'unused-mcp.jwt')
        self.owner = existing.OwnerFixture(observed, self.plan)
        for method in ('observe','active','roles','registrations','oauth','request','kc','tool'):
            patcher = patch.object(self.transport, method, side_effect=getattr(self.owner,method))
            patcher.start(); self.addCleanup(patcher.stop)
        self.delta = auth.AuthorizationDelta(action, self.plan, self.journal, self.transport, self.primitives)
        self.delta.initialize()

    def prepare(self):
        return self.delta.apply()

    def test_real_signed_registration_scope_and_resume_never_publish_a_grant(self):
        receipt=self.prepare()
        self.assertTrue(receipt['existingGrantsPreserved'])
        self.assertFalse(receipt['freshClientTokenScopesProven'])
        self.assertEqual(self.owner.roles(),self.plan['baseline']['roles'])
        self.assertEqual(self.owner.active()['policy']['grants'],self.plan['baseline']['active']['policy']['grants'])
        self.assertEqual(len(self.owner.proposals),0)
        self.assertEqual(self.owner.calls.count(('POST',auth.ADMIN+'/capabilities')),1)
        mutations=[c for c in self.owner.calls if c[0] in ('POST','KC:create','KC:update','KC:delete','authorization.permissions.propose')]
        self.delta.apply()
        self.assertEqual(mutations,[c for c in self.owner.calls if c[0] in ('POST','KC:create','KC:update','KC:delete','authorization.permissions.propose')])

    def test_lost_registration_reply_reconciles_without_duplicate_dispatch(self):
        self.owner.lost = ('POST', auth.ADMIN+'/capabilities')
        with self.assertRaisesRegex(auth.AuthorizationPaused, 'LOST_RESPONSE'):
            self.delta.apply()
        self.prepare()
        self.assertEqual(self.owner.calls.count(('POST', auth.ADMIN+'/capabilities')), 1)

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



if __name__=='__main__':unittest.main()
