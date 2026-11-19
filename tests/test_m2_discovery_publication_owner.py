"""Actual parent/child signatures and journals; native/HTTP leaves are fixtures.

This tests governed owner composition and one-use publication, not native full
cohort admission, real THS confirmation, current VPS state or application E2E.
"""
import copy,hashlib,os,sys,unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]+[str(ROOT/'tools'/p) for p in
    ('semantic_application_cutover','semantic_frame_compiler','semantic_policy_token_owner',
     'semantic_lease_recovery','semantic_transaction_profiles','semantic_cohort_admission/cohort-draft')]
import test_m2_discovery_parent_review as review_fixture
import test_chatbot_cohort_authorization as auth_fixture
from tools.m2_discovery_installation_profile import publication_owner as m
from tools.chatbot_file_cohort import authorization as auth
from engine_creation import Engine
from transition_journal import PHASES


class Publication(unittest.TestCase):
    @classmethod
    def setUpClass(cls):review_fixture.ParentReview.setUpClass()
    @classmethod
    def tearDownClass(cls):review_fixture.ParentReview.tearDownClass()

    def fixture(self):
        case=review_fixture.ParentReview();self.addCleanup(case.doCleanups)
        inputs,crypto,calls,child,raw=case.fixture()
        roots={kind:crypto.root/'publication'/kind for kind in ('authorization','gateway')}
        inputs['publicationInputs']['journalDirectories']={k:str(v) for k,v in roots.items()}
        for root in roots.values():root.mkdir(mode=0o700,parents=True)
        assembly=case.compile(inputs);crypto.review=copy.deepcopy(assembly['review']);parent=crypto.fixture(seconds=300)
        cohort=inputs['infrastructureInputs']['cohortInputs']
        row={'state':'READY','nextPhase':PHASES.index(m.PHASE),'version':42,
            'creationRequestHash':m.digest(cohort['registry']['request']),
            'transitionAuthorityEvidenceHash':hashlib.sha256(raw).hexdigest()}
        occupied=[False]
        @contextmanager
        def invocation():
            if occupied[0]:raise BlockingIOError('fixture Registry fence occupied')
            occupied[0]=True
            try:yield
            finally:occupied[0]=False
        gate=SimpleNamespace(parent=parent,child=child,raw=raw,transition=SimpleNamespace(invocation=invocation))
        executor=object.__new__(m.DiscoveryExecutor);executor.discovery_parent=parent
        app=object.__new__(m.DiscoveryApplication);app.executor=executor
        app.request_hash=row['creationRequestHash'];app.intent_hashes={p:'1'*64 for p in PHASES}
        def checkpoint(phase,point,current):
            self.assertEqual((phase,point),(m.PHASE,m.POINT));self.assertEqual(current,row)
            return {'schema':'ouf.semantic-cutover-native-checkpoint.v1','phase':phase,'point':point,
                'journalVersion':row['version'],'intentHash':app.intent_hashes[phase],
                'authorityHash':action.authority_hash,'sourceClosureHash':parent.scope['sourceClosureHash'],
                'nativeEvidenceHash':m.digest({'modeledNativeFullCohort':True,'row':row})}
        executor.checkpoint=Mock(side_effect=checkpoint)
        action=m.AggregateAction(child,raw,parent.scope['sourceClosureHash'])
        selected=object.__new__(m.DiscoverySelectedRuntime)
        selected.images=SimpleNamespace(parent=parent,window=gate)
        selected.installation=SimpleNamespace(application=app);selected.mcp=SimpleNamespace(action=action)
        runtime=object.__new__(m.DiscoveryGatewayRuntime);runtime.plan=copy.deepcopy(cohort['gateway']['plan'])
        runtime.engine=object.__new__(Engine);runtime.generation=Mock(return_value={'fixtureGeneration':1})
        selected.gateway=runtime
        def held(expected=None):
            parent.registry_child(child,raw)
            m.require(row['state']=='READY' and row['nextPhase']==PHASES.index(m.PHASE),'fixture Registry not held')
            m.require(expected is None or expected==row,'fixture Registry history drift')
            return copy.deepcopy(row)
        selected.held=Mock(side_effect=held)
        window=m.DiscoveryPublicationWindow(selected,inputs['publicationInputs'],cohort,case.primitives)
        native=auth_fixture.OwnerFixture(window.assembly['authorizationPlan']['baseline'],window.assembly['authorizationPlan'])
        transport=auth.OwnerTransport(window.assembly['authorizationPlan']['selection'],crypto.root/'unused-admin',crypto.root/'unused-mcp')
        for method in ('observe','active','roles','registrations','oauth','request','kc','tool'):
            p=patch.object(transport,method,side_effect=getattr(native,method));p.start();self.addCleanup(p.stop)
        authorization=m.DiscoveryAuthorization(window,m.Journal(roots['authorization']),transport)
        gateway=m.DiscoveryGatewayPublication(window,m.Journal(roots['gateway']))
        inventory=copy.deepcopy(window.assembly['gatewayPlan']['previousRoutes']);writes=[];lost=[False]
        observed={'runtimeBinding':{'fixtureGeneration':1},'pythonExecutable':runtime.plan['pythonExecutable'],
            'adminKeyBinding':runtime.plan['adminKeyBinding']}
        def request(channel,method,path,body=None):
            channel.check()
            if method=='GET':return 200,{'total':len(inventory),'list':[{'value':v} for v in inventory.values()]}
            self.assertEqual(method,'PUT');writes.append(path);inventory[body['id']]=copy.deepcopy(body)
            if lost[0]:lost[0]=False;raise OSError('fixture lost PUT acknowledgement')
            return 201,{}
        patches=[patch.object(m.NamespaceAdmin,'observe',return_value=observed),
            patch.object(m.NamespaceAdmin,'check',return_value=None),
            patch.object(m.NamespaceAdmin,'request',new=request),
            patch.object(m,'apisix_runtime_binding',side_effect=lambda value,profile:value)]
        for p in patches:p.start();self.addCleanup(p.stop)
        authorization.initialize();gateway.initialize()
        return SimpleNamespace(window=window,auth=authorization,gateway=gateway,native=native,writes=writes,
            inventory=inventory,lost=lost,crypto=crypto,row=row,occupied=occupied,transport=transport,roots=roots,
            coordinator=m.DiscoveryPublication(authorization,gateway),checkpoint=executor.checkpoint)

    def confirm(self,f):
        with self.assertRaisesRegex(auth.AuthorizationPaused,'HUMAN_OWNER_ROLE_CONFIRMATION_REQUIRED'):
            f.coordinator.apply()
        self.assertFalse(f.writes)
        self.assertFalse(f.occupied[0]);self.assertIsNone(f.window.fence)
        # Explicit modeled HUMAN transition; the unchanged Java constraint
        # roundtrip is qualified by the existing discovery authorization suite.
        # Production code has no confirmation adapter or automatic approval.
        native=f.native;native.current['roles']=copy.deepcopy(native.plan['targetRoles'])
        policy=native.current['active']['policy']
        policy['grants']+=list(auth.expected_role_grant_additions(native.plan).values());policy['version']+=1
        native.current['active'].update(policyRef=policy['bundleId']+':'+str(policy['version']),contentHash=m.digest(policy))
        for proposal in native.proposals.values():
            proposal.update(state='PUBLISHED',revision=1,finalPolicyRef=native.current['active']['policyRef'])

    def test_owner_human_confirmation_precedes_three_routes_under_one_fence(self):
        f=self.fixture();self.confirm(f);r=f.coordinator.apply()
        self.assertEqual(len(f.writes),3);self.assertTrue(r['governedDeltaReconciled'])
        self.assertFalse(r['producerReleaseDispatched']);self.assertFalse(r['fullCohortProven'])
        self.assertFalse(r['targetApplyAuthorized']);self.assertFalse(f.occupied[0])
        self.assertGreater(f.checkpoint.call_count,0)
        before=list(f.writes);self.assertEqual(f.coordinator.apply(),r);self.assertEqual(f.writes,before)

    def test_legacy_child_gets_no_projected_or_new_publication_sections(self):
        f=self.fixture();from tools.m2_discovery_installation_profile.custody_capture import decode
        child=decode(f.window.gate.raw)
        self.assertNotIn('chatbotFileAuthorization',child);self.assertNotIn('gatewayRoutePublication',child)
        self.confirm(f);f.coordinator.apply();self.assertEqual(decode(f.window.gate.raw),child)

    def test_lost_gateway_reply_reconciles_without_a_second_put(self):
        f=self.fixture();self.confirm(f);f.lost[0]=True
        with self.assertRaises(OSError):f.coordinator.apply()
        self.assertEqual(len(f.writes),1);f.coordinator.apply();self.assertEqual(len(f.writes),3)

    def test_lost_registration_reply_reconciles_without_duplicate_registration(self):
        f=self.fixture();f.native.lost=('POST',auth.ADMIN+'/capabilities')
        with self.assertRaisesRegex(auth.AuthorizationPaused,'FIXTURE_LOST_RESPONSE'):f.coordinator.apply()
        self.confirm(f);f.coordinator.apply()
        self.assertEqual(f.native.calls.count(('POST',auth.ADMIN+'/capabilities')),3)

    def test_ambiguous_role_proposal_is_never_redispatched_even_when_deduplicated(self):
        f=self.fixture();f.native.proposal_failure='AUTHORIZATION_TRANSPORT_OUTCOME_UNPROVEN'
        with self.assertRaisesRegex(auth.AuthorizationPaused,'TRANSPORT_OUTCOME_UNPROVEN'):f.coordinator.apply()
        with self.assertRaisesRegex(auth.AuthorizationPaused,'EFFECT_RECONCILIATION_REQUIRED'):f.coordinator.apply()
        self.assertEqual(sum(1 for c in f.native.calls if c[0]=='authorization.permissions.propose'),1)
        self.assertFalse(f.writes)

    def test_gateway_journal_regression_cannot_redispatch_a_consumed_route(self):
        f=self.fixture();self.confirm(f);before=f.gateway.record();f.coordinator.apply()
        f.gateway.journal.record.write_bytes(m.encoded(before))
        with self.assertRaisesRegex(ValueError,'HISTORY_REGRESSED'):f.coordinator.apply()
        self.assertEqual(len(f.writes),3)

    def test_authorization_journal_regression_cannot_redispatch_registration(self):
        f=self.fixture();before=f.auth.record();self.confirm(f)
        f.auth.journal.record.write_bytes(m.encoded(before))
        with self.assertRaisesRegex(ValueError,'HISTORY_REGRESSED'):f.coordinator.apply()
        self.assertFalse(f.writes)

    def test_parent_revocation_denies_before_owner_or_gateway_effects(self):
        f=self.fixture();p=Path(f.window.parent.binding['path']);f.crypto.write(p,b'REVOKED')
        with self.assertRaisesRegex(ValueError,'HUMAN_DECISION_CHANGED'):f.coordinator.apply()
        self.assertFalse(f.writes);self.assertFalse(f.native.drafts)

    def test_parent_revocation_after_dispatch_claim_stops_before_remote_mutation(self):
        f=self.fixture();real=m.new_file
        def revoke(fd,name,raw):
            result=real(fd,name,raw)
            if name.startswith('dispatch-'):f.crypto.write(Path(f.window.parent.binding['path']),b'REVOKED')
            return result
        with patch.object(m,'new_file',side_effect=revoke),self.assertRaisesRegex(ValueError,'HUMAN_DECISION_CHANGED'):
            f.coordinator.apply()
        self.assertFalse(f.writes);self.assertFalse(f.native.calls)
        self.assertTrue(any(p.name.startswith('dispatch-') for p in f.roots['authorization'].iterdir()))

    def test_bad_native_checkpoint_or_changed_registry_boundary_denies_before_writes(self):
        for case in ('checkpoint','boundary'):
            f=self.fixture()
            if case=='checkpoint':f.checkpoint.side_effect=None;f.checkpoint.return_value={'nativeAdmission':True}
            else:f.row['nextPhase']-=1
            with self.subTest(case=case),self.assertRaises(ValueError):f.coordinator.apply()
            self.assertFalse(f.writes);self.assertFalse(f.native.drafts)

    def test_occupied_registry_fence_prevents_any_publication(self):
        f=self.fixture();f.occupied[0]=True
        with self.assertRaises(BlockingIOError):f.coordinator.apply()
        self.assertFalse(f.writes);self.assertFalse(f.native.drafts)

    def test_existing_or_partial_owner_binding_never_reinitializes(self):
        f=self.fixture();before={p.name:p.read_bytes() for p in f.roots['authorization'].iterdir()}
        with self.assertRaisesRegex(ValueError,'NO_REPLAY'):f.auth.initialize()
        self.assertEqual(before,{p.name:p.read_bytes() for p in f.roots['authorization'].iterdir()})
        for p in f.roots['authorization'].iterdir():
            if p.name!=m.BINDING:p.unlink()
        with self.assertRaisesRegex(ValueError,'NO_REPLAY'):f.auth.initialize()
        self.assertEqual({p.name for p in f.roots['authorization'].iterdir()},{m.BINDING})

    def test_put_without_a_durable_exact_route_claim_is_denied_before_http(self):
        f=self.fixture()
        with self.assertRaisesRegex(ValueError,'DURABLE_CURRENT_DISCOVERY_ROUTE_CLAIM'):
            f.gateway.transport.request('PUT','/apisix/admin/routes/foreign',{'id':'foreign'})
        self.assertFalse(f.writes)

    def test_changed_gateway_generation_denies_before_route_dispatch(self):
        f=self.fixture();self.confirm(f);f.window.selected.gateway.generation.return_value={'fixtureGeneration':2}
        with self.assertRaisesRegex(ValueError,'GATEWAY_GENERATION'):f.coordinator.apply()
        self.assertFalse(f.writes)

if __name__=='__main__':unittest.main()
