"""Pinned production materializers; review proposals, no target publication."""
import copy,json,os,sys,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]+[str(ROOT/'tools'/p) for p in
    ('semantic_application_cutover','semantic_frame_compiler','semantic_policy_token_owner',
     'semantic_lease_recovery','semantic_transaction_profiles','semantic_cohort_admission/cohort-draft')]
import test_m2_discovery_private_review as cohort_fixture
import test_chatbot_cohort_authorization as auth_fixture
from tools.m2_discovery_installation_profile import publication_review as m
from tools.m2_discovery_installation_profile.publication_primitives import PublicationPrimitives,GATEWAY,ONBOARDING
from tools.chatbot_file_cohort import authorization as auth


class PublicationReview(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cohort_fixture.PrivateReview.setUpClass()
        cls.primitives=PublicationPrimitives.from_directories(os.environ['OUF_PUBLICATION_GATEWAY_ROOT'],
            os.environ['OUF_REVISION_ONBOARDING_ROOT'],ROOT/auth.DISCOVERY_CATALOGUE)
    @classmethod
    def tearDownClass(cls):cohort_fixture.PrivateReview.tearDownClass()
    def fixture(self):
        c=cohort_fixture.PrivateReview().fixture();reg=c['registry'];env=m.environment(reg['request']['Env'])
        next(iter(reg['request']['NetworkingConfig']['EndpointsConfig'].values()))['Aliases']=['fixture-discovery-registry']
        c['images']['registryCreationRequestHash']=m.digest(reg['request'])
        gp=c['gateway']['plan'];gp['creationRequest']['Env'].append('FIXTURE_DELEGATION_KEY='+'c'*64)
        selection,observed=auth_fixture.fixture();selection['issuer']=env['OUF_IAM_ISSUER']
        observed['roles']['issuer']=selection['issuer']
        before={'execute':{'id':'execute','uri':'/internal/capabilities/v1/execute','methods':['POST'],
            'labels':{'ouf-mediation':'retained-fixture'},'plugins':{
                'openid-connect':{'bearer_only':True,'client_id':env['OUF_IAM_AUDIENCE']},
                'limit-count':{'count':10,'time_window':60},'request-validation':{'body_schema':{}},
                'serverless-pre-function':{'phase':'rewrite','functions':['\n'.join('local '+k+' = '+json.dumps(v)
                    for k,v in {'DELEGATION_KEY_ENV':'FIXTURE_DELEGATION_KEY','ISSUER':env['OUF_IAM_ISSUER'],
                        'AUDIENCE':env['OUF_IAM_AUDIENCE'],'MCP_WORKLOAD':reg['selection']['mcp_workload']}.items())]}}},
            'retained':{'id':'retained','uri':'/retained','methods':['GET']}}
        alias=next(iter(reg['request']['NetworkingConfig']['EndpointsConfig'].values()))['Aliases'][0]
        i={'schema':m.SCHEMA,'cohortInputsHash':m.digest(c),'authorization':{'selection':selection,
            'observed':observed,'roleId':'admin','reviewTime':'2026-10-31T06:00:00Z','sessionBinding':None},
            'gateway':{'previousRoutes':before,'installation':{'issuerUrl':env['OUF_IAM_ISSUER'],
                'gatewayAudience':env['OUF_IAM_AUDIENCE'],'mcpServiceIdentity':reg['selection']['mcp_workload']},
                'delegationKeyEnvironment':'FIXTURE_DELEGATION_KEY','discoveryKeyEnvironment':gp['proposalKeyEnvironment'],
                'upstream':{'scheme':'http','nodes':{alias+':8080':1}},
                'routeIds':{n:'fixture-discovery-'+n for n in ('request','status','candidates')}},
            'journalDirectories':{n:c['gateway']['journalDirectory']+'-publication-'+n for n in ('authorization','gateway')}}
        return i,c
    def compile(self,i,c):return m.assemble(i,m.digest(i),c,self.primitives)

    def test_deterministic_exact_three_routes_capabilities_and_one_scope(self):
        i,c=self.fixture();before=copy.deepcopy((i,c));a=self.compile(i,c)
        self.assertEqual(a,self.compile(i,c));self.assertEqual((i,c),before)
        ap,gp=a['authorizationPlan'],a['gatewayPlan']
        self.assertEqual({r['descriptor']['capabilityId'] for r in ap['registrationAdditions']},set(auth.DISCOVERY))
        self.assertEqual(ap['requiredScopes'],{'chatgpt':[auth.DISCOVERY_SCOPE],'ths':[]})
        self.assertEqual(len(gp['changes']),3)
        for n,rid in i['gateway']['routeIds'].items():
            row=gp['proposedRoutes'][rid];self.assertEqual(row['methods'],['POST'])
            self.assertEqual(row['uri'],'/internal/capabilities/v1/execute/semantic/discovery/'+n)
            self.assertEqual(row['plugins']['proxy-rewrite']['uri'],'/api/internal/v1/semantic/discovery/'+n)
            self.assertEqual(row['upstream']['retries'],0)
        for rid,row in i['gateway']['previousRoutes'].items():self.assertEqual(gp['proposedRoutes'][rid],row)
        self.assertEqual(ap['targetRoles']['assignments'],i['authorization']['observed']['roles']['assignments'])
        self.assertEqual(ap['candidatePolicy']['grants'],i['authorization']['observed']['active']['policy']['grants'])
        for flag in ('inputsAuthenticated','currentNativeAdmissionProven','publicationExecutorIntegrated',
            'runtimeAuthorityIssued','targetApplyAuthorized','capabilitiesPublished','applicationE2EProven','releaseAcceptance'):
            self.assertIs(a[flag],False)
        self.assertEqual(a['signaturesIssued'],0)

    def test_each_external_source_is_checked_before_execution(self):
        g={p:(Path(os.environ['OUF_PUBLICATION_GATEWAY_ROOT'])/p).read_bytes() for p in GATEWAY}
        o={p:(ROOT/p if p==auth.DISCOVERY_CATALOGUE else Path(os.environ['OUF_REVISION_ONBOARDING_ROOT'])/p).read_bytes()
            for p in ONBOARDING}
        for rows,name in ((g,n) for n in g):
            changed=dict(rows);changed[name]+=b'\n'
            with self.subTest(name=name),self.assertRaisesRegex(ValueError,'SOURCE_CLOSURE'):
                PublicationPrimitives(changed,o)
        for name in o:
            changed=dict(o);changed[name]+=b'\n'
            with self.subTest(name=name),self.assertRaisesRegex(ValueError,'SOURCE_CLOSURE'):
                PublicationPrimitives(g,changed)

    def test_identity_key_upstream_and_extra_scopes_cannot_drift(self):
        for case in ('issuer','audience','workload','key','same_key','upstream','auth_issuer','extra_scope','time','cohort'):
            i,c=self.fixture();g=i['gateway']
            if case=='issuer':g['installation']['issuerUrl']='https://other.invalid'
            elif case=='audience':g['installation']['gatewayAudience']='other'
            elif case=='workload':g['installation']['mcpServiceIdentity']='other'
            elif case=='key':g['discoveryKeyEnvironment']='OTHER_KEY'
            elif case=='same_key':g['delegationKeyEnvironment']=g['discoveryKeyEnvironment']
            elif case=='upstream':g['upstream']['nodes']={'foreign:8080':1}
            elif case=='auth_issuer':i['authorization']['selection']['issuer']='https://other.invalid'
            elif case=='extra_scope':i['authorization']['include_ingestion_status']=True
            elif case=='time':i['authorization']['reviewTime']=None
            else:c['installationInputsHash']='a'*64
            with self.subTest(case=case),self.assertRaises(ValueError):self.compile(i,c)

    def test_existing_route_ids_or_discovery_selectors_cannot_be_overwritten(self):
        for case in ('id','uri','uris','names','baseline'):
            i,c=self.fixture();g=i['gateway']
            if case=='id':g['routeIds']['request']='retained'
            elif case=='uri':g['previousRoutes']['retained']['uri']='/internal/capabilities/v1/execute/semantic/discovery/status'
            elif case=='uris':g['previousRoutes']['retained'].update(uris=['/internal/capabilities/v1/execute/semantic/discovery/status'],methods=['POST'])
            elif case=='names':g['routeIds']['request']='bad/id'
            else:g['previousRoutes']['other']=g['previousRoutes']['retained']
            with self.subTest(case=case),self.assertRaises(ValueError):self.compile(i,c)

    def test_historical_approval_flags_or_owner_plans_are_not_inputs(self):
        for key in ('retainedRoleObservation','authorizationPlan','targetApplyAuthorized','runtimeAuthorityIssued','completeParentReview'):
            i,c=self.fixture();i[key]=True
            with self.subTest(key=key),self.assertRaises(ValueError):self.compile(i,c)

    def test_journals_are_separate_and_cannot_shadow_current_sources_or_owner_history(self):
        for case in ('same','nested','image','runtime','input'):
            i,c=self.fixture();j=i['journalDirectories']
            j['gateway']={'same':j['authorization'],'nested':j['authorization']+'/nested',
                'image':c['images']['journalDirectories']['semantic'],
                'runtime':c['gateway']['journalDirectory'],'input':c['images']['images'][0]['archivePath']}[case]
            with self.subTest(case=case),self.assertRaisesRegex(ValueError,'JOURNALS'):self.compile(i,c)

    def test_verified_snapshot_never_rereads_mutable_external_source_files(self):
        i,c=self.fixture();expected=self.compile(i,c)
        with patch.object(Path,'read_text',side_effect=AssertionError('late source read')),\
             patch.object(Path,'read_bytes',side_effect=AssertionError('late source read')):
            self.assertEqual(self.compile(i,c),expected)

    def test_review_cannot_issue_signatures_or_use_engine_or_network(self):
        i,c=self.fixture()
        from engine_creation import Engine
        from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
        with patch.object(Engine,'request',side_effect=AssertionError('engine effect')),\
             patch.object(ExistingEd25519Signer,'sign',side_effect=AssertionError('signature effect')),\
             patch.object(auth.OwnerTransport,'request',side_effect=AssertionError('owner effect')),\
             patch.object(auth.OwnerTransport,'kc',side_effect=AssertionError('IAM effect')):
            self.compile(i,c)

if __name__=='__main__':unittest.main()
