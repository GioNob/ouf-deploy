"""Pure cross-profile reconciliation, no target calls or runtime authority."""
import copy
import os
from pathlib import Path
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),
             str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.ingestion_rollout_execution import contract as c,native_review as n
import test_ingestion_rollout_runtime_guard as runtime_fixture
import test_ingestion_rollout_database_read as database_fixture
import test_ingestion_rollout_owner_read as owner_fixture
from test_ingestion_rollout_gateway_transport import binding

class NativeReview(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT)))
        self.addCleanup(self.temp.cleanup);root=Path(self.temp.name);root.chmod(0o700)
        selected={}
        for name in('old','new','archive','projection'):
            p=root/name;p.write_bytes(('isolated '+name+' fixture').encode());p.chmod(0o600);selected[name]=binding(p)
        old=runtime_fixture.OldGeneration();old.setUp()
        self.packet=copy.deepcopy(old.packet);self.human=old.review['humanBinding']
        self.human['retryProfile']={'maximumAttempts':288}
        self.packet['candidate']['sourceCommit']='1'*40
        self.packet['candidate']['imageConfig'].setdefault('Labels',{})['org.opencontainers.image.revision']='1'*40
        self.packet['frames']['ingestion']['requestTemplate'].setdefault('Labels',{})['org.opencontainers.image.revision']='1'*40
        for key,name in(('gatewayConfigBefore','old'),('retainedGatewayConfig','new')):
            self.packet[key]={k:selected[name][k]for k in('path','sha256','metadata')}
        self.packet['candidate']['nativeArchiveBinding']={k:selected['archive'][k]for k in('path','sha256','metadata')}
        config=root/'empty-config';config.mkdir(mode=0o700)
        db,_=database_fixture.fixture_profile(config)
        db['postgresRuntimeBinding']['containerId']='f'*64
        owner=owner_fixture.profile(root/'projection')
        pin=old.profile['unchangedApplications']['onboarding']
        owner.update(runtimeBinding=copy.deepcopy(pin['binding']),restartCount=pin['restartCount'],runtimeBindingProfile=pin['bindingProfile'])
        owner['expectedPayload']={'installationId':owner['installationId'],
            'secrets':{'references':{'ingestionReadOwnerKey':self.packet['dedicatedOwnerKey']['path']}}}
        self.owner_plan={'bindingPlan':{'candidatePayload':copy.deepcopy(owner['expectedPayload'])}}
        self.packet['ownerPlanSha256']=c.digest(self.owner_plan)
        self.completed={'complete':True,'planHash':self.packet['ownerPlanSha256']}
        self.profiles={'schema':n.PROFILE,'engineBinding':copy.deepcopy(db['engineBinding']),
            'runtimeGuardProfile':copy.deepcopy(old.profile),'ownerControlProfile':owner,'databaseControlProfile':db,
            'imageImportProfile':{'schema':'ouf.ingestion-rollout-native-image-load.v1',
                **{k:copy.deepcopy(db[k])for k in('engineBinding','dockerExecutable','dockerConfigDirectory','dockerConfigIdentity')},
                'archive':selected['archive']},'retainedGatewayNamespace':{'device':1,'inode':2},
            'ingestionReadinessProfile':{'schema':'ouf.ingestion-rollout-ingestion-readiness-local-ns.v1',
                'endpoint':{'host':'127.0.0.2','port':18080},'pythonExecutable':owner['pythonExecutable']}}
        for field,name in(('retainedGatewayTransportProfile','old'),('gatewayTransportProfile','new')):
            self.profiles[field]={'schema':'ouf.ingestion-rollout-gateway-transport.v1',
                'endpoint':{'host':'127.0.0.2','port':19280},'pythonExecutable':owner['pythonExecutable'],
                'config':selected[name],'adminKey':None}
        self.owner_plan.update(engine=copy.deepcopy(self.profiles['engineBinding']),
            currentApplications={**copy.deepcopy(self.packet['expectedRuntimeBindings']),
                **{name:copy.deepcopy(pin['binding'])for name,pin in self.profiles['runtimeGuardProfile']['unchangedApplications'].items()}})
        self.owner_plan['bindingPlan']['candidatePayloadChecksum']=owner['expectedActive']['checksum']
        self.packet['ownerPlanSha256']=c.digest(self.owner_plan);self.completed['planHash']=self.packet['ownerPlanSha256']
        self.completed.update(active=copy.deepcopy(owner['expectedActive']),ownerPayloadReadbackProven=True,
            projectionBinding={k:owner['projection'][k]for k in('path','sha256')},
            oauthAttemptsAfter=278,maximumCumulativeOAuthAttempts=288)
        self.inputs={k:copy.deepcopy(self.packet[k])for k in('candidate','expectedRuntimeBindings',
            'gatewayConfigBefore','retainedGatewayConfig','dedicatedOwnerKey','retainedClaims')}
        self.packet['verifiedInputsHash']=c.digest(self.inputs)

    def compile(self):
        return n.compile_native_review(self.packet,{'path':'/fixture/packet','sha256':c.digest(self.packet)},
            self.inputs,self.human,'/fixture/execution',self.profiles,self.owner_plan,self.completed)

    def test_complete_cross_bound_review_is_private_preparation_only(self):
        original=copy.deepcopy((self.packet,self.profiles,self.owner_plan,self.completed))
        review=self.compile();n.validate_review(review,self.packet)
        self.assertFalse(review['runtimeAuthorityIssued']);self.assertFalse(review['nativeExecutorQualified'])
        self.assertFalse(review['nativeProfilePublished']);self.assertEqual(review['functionalMilestonesProven'],4)
        self.assertEqual((self.packet,self.profiles,self.owner_plan,self.completed),original)

    def test_distinct_engine_or_credential_config_channel_blocks(self):
        for field,key,value in(('engineBinding','socketPath','/other/engine.sock'),
            ('imageImportProfile','dockerConfigDirectory','/other/config')):
            original=copy.deepcopy(self.profiles)
            self.profiles[field][key]=value
            with self.assertRaises(c.Denied):self.compile()
            self.profiles=original

    def test_owner_profile_cannot_select_another_runtime_or_binding_encoding(self):
        for key,value in(('runtimeBindingProfile','ouf.runtime-binding.native-mount-order.v1'),('restartCount',17)):
            original=copy.deepcopy(self.profiles)
            self.profiles['ownerControlProfile'][key]=value
            with self.assertRaises(c.Denied):self.compile()
            self.profiles=original

    def test_completed_owner_plan_and_result_cannot_be_substituted(self):
        original=copy.deepcopy(self.completed)
        for value in({'complete':False,'planHash':self.packet['ownerPlanSha256']},
                      {'complete':True,'planHash':'f'*64}):
            self.completed=value
            with self.assertRaises(c.Denied):self.compile()
        self.completed=original;self.owner_plan['extra']='different plan'
        with self.assertRaises(c.Denied):self.compile()

    def test_owner_payload_and_published_secret_reference_remain_exact(self):
        self.profiles['ownerControlProfile']['expectedPayload']['secrets']['references']['ingestionReadOwnerKey']='/foreign/key'
        with self.assertRaises(c.Denied):self.compile()
        self.owner_plan['bindingPlan']['candidatePayload']=copy.deepcopy(self.profiles['ownerControlProfile']['expectedPayload'])
        self.packet['ownerPlanSha256']=c.digest(self.owner_plan);self.completed['planHash']=self.packet['ownerPlanSha256']
        with self.assertRaises(c.Denied):self.compile()

    def test_gateway_endpoint_or_staged_config_substitution_blocks(self):
        original=copy.deepcopy(self.profiles)
        self.profiles['gatewayTransportProfile']['endpoint']['port']=29280
        with self.assertRaises(c.Denied):self.compile()
        self.profiles=original
        self.profiles['gatewayTransportProfile']['config']=self.profiles['retainedGatewayTransportProfile']['config']
        with self.assertRaises(c.Denied):self.compile()

    def test_native_budgets_cannot_be_extended_or_bool_aliased(self):
        review=self.compile()
        for key in n.BUDGETS:
            for value in(True,n.BUDGETS[key]+1):
                changed=copy.deepcopy(review);changed[key]=value
                with self.assertRaises(c.Denied):n.validate_review(changed,self.packet)
    def test_rehashed_foreign_owner_engine_or_missing_application_cannot_reconcile(self):
        for mutation in('engine','application'):
            original=copy.deepcopy(self.owner_plan)
            if mutation=='engine':self.owner_plan['engine']['socketPath']='/foreign/engine.sock'
            else:self.owner_plan['currentApplications'].pop('udp')
            self.packet['ownerPlanSha256']=c.digest(self.owner_plan);self.completed['planHash']=self.packet['ownerPlanSha256']
            with self.assertRaises(c.Denied):self.compile()
            self.owner_plan=original
    def test_another_active_revision_with_same_payload_or_export_substitution_blocks(self):
        original=copy.deepcopy(self.completed)
        self.completed['active']['generation']+=1
        with self.assertRaises(c.Denied):self.compile()
        self.completed=original;self.completed['projectionBinding']['sha256']='f'*64
        with self.assertRaises(c.Denied):self.compile()

if __name__=='__main__':unittest.main()
