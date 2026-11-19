"""Independent synthetic proposals; no file install, signature or admission."""
import copy,dataclasses,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_lease_recovery'),
    str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_m2_discovery_lease_unit as units
from tools.m2_discovery_installation_profile import lease_installation_template as m


class Template(unittest.TestCase):
    def fixture(self):
        c,r,s,p,o=units.Unit().fixture();install=o['installation_root']
        hashes={name:pin['sha256'] for name,pin in m.PINS.items()}
        c['sourceManifest']={'schema':'ouf.discovery-operational-lease-sources.v1',
            'sourceHashes':hashes,'dependencyClosureHash':m.digest(hashes)}
        c['verification']['context']={'installationRef':'synthetic-ci','entityRef':'synthetic-ci',
            'attestorRef':'synthetic-ci-attestor'}
        c['commonLockIdentity']=None
        next(v for v in c['sources'] if v['path']==install+'/capsule.py').update(
            sha256=m.CAPSULE_SHA,maximumBytes=m.CAPSULE_BYTES)
        next(v for v in c['sources'] if v['path']==install+'/worker-recipe.json').update(sha256=m.ZERO)
        r['kernel']={'tableName':'ouf_template_ci','guardedInterfaces':['synthetic0'],'existingInterfaces':[],
            'staticFlows':[],'providerFlows':[{'endpointRef':'synthetic-provider',
                'endpoint':'https://provider.invalid/approved','source':'10.99.0.2','addresses':[],
                'leaseSeconds':30,'resolutionEvidenceRef':'synthetic-ci','allowedPrivateAddresses':[]}]}
        r['dns']={'resolvers':['1.1.1.1'],'resolverPort':53,'timeoutSeconds':2,'maxLeaseSeconds':30,'applyBudgetSeconds':1}
        r['policy']=dataclasses.asdict(m.Policy(delays=(1,2),max_attempts=8,max_elapsed=600,attempt_timeout=30,jitter=0))
        r['policy']['delays']=list(r['policy']['delays']);c['scopePolicyHash']=m.fingerprint(r['policy'])
        structure='8'*64;r['binding']={'transactionId':'9'*64,
            'configurationHash':m.fingerprint(r['kernel']),'leaseStructureHash':structure}
        r['scope']={'sourceClosureHash':m.digest(hashes),'installationInputsHash':c['installationInputsHash'],
            'contextRef':'1'*64,'generationRef':None,'policyHash':c['scopePolicyHash'],
            'coordinatorBindingHash':m.fingerprint(r['binding']),'configurationHash':m.fingerprint(r['kernel']),
            'dnsProfileHash':m.fingerprint(r['dns']),'leaseStructureHash':structure,'pollSeconds':1,'heartbeatSeconds':1}
        options={**o,'source_closure_hash':'f'*64,'expected_images':{role:v['imageId'] for role,v in s['peers'].items()},
            'expected_node_profiles':{role:{k:v[k] for k in m.INDEPENDENT_FIELDS} for role,v in s['profiles'].items()}}
        return c,r,s,p,options

    def prepared(self):
        c,r,s,p,o=self.fixture();return m.template(c,r,p,**o),s

    def test_parent_review_precedes_actual_generation_without_inventing_acceptance(self):
        value,snapshot=self.prepared();before=copy.deepcopy(value)
        scope=m.parent_scope(value);result=m.materialize(value,snapshot,[1,4,0,0,0o100600,1])
        self.assertEqual(value,before);self.assertEqual(result['templateHash'],scope['templateHash'])
        self.assertEqual(result['recipe']['scope']['generationRef'],snapshot['generationRef'])
        self.assertEqual(result['configuration']['serviceUnitHash'],result['serviceUnit']['unitSha256'])
        self.assertTrue(result['currentNativeAdmissionStillRequired'])
        for key in ('runtimeAuthorityIssued','targetApplyAuthorized','releaseAcceptance'):self.assertFalse(result[key])
        self.assertFalse(scope['containerLifecycleOperationsAllowed']);self.assertFalse(scope['automaticBudgetResetAllowed'])

    def test_new_generation_may_change_only_dynamic_references_and_not_expected_node_recipe(self):
        value,snapshot=self.prepared();snapshot['peers']['registry']['pid']+=1000
        snapshot['peers']['registry']['startTicks']+=1;snapshot['generationRef']=m.generation_reference(snapshot)
        result=m.materialize(value,snapshot,[1,4,0,0,0o100600,1])
        self.assertIn('/proc/1101/stat',result['serviceUnit']['processStatPaths'])
        for role in ('registry','provider'):
            wrong=copy.deepcopy(snapshot);wrong['profiles'][role]['nodeRecipeHash']='f'*64
            wrong['nativeProfileHash']=m.digest(wrong['profiles']);wrong['generationRef']=m.generation_reference(wrong)
            with self.assertRaisesRegex(ValueError,'INDEPENDENT_APPROVED_NODE_RECIPES'):
                m.materialize(value,wrong,[1,4,0,0,0o100600,1])

    def test_observed_image_or_rootfs_cannot_replace_independent_review(self):
        for role in ('registry','provider'):
            for field in ('image','rootfs'):
                value,snapshot=self.prepared()
                if field=='image':snapshot['peers'][role]['imageId']='sha256:'+'e'*64
                else:snapshot['profiles'][role]['rootfsSealHash']='e'*64
                snapshot['nativeProfileHash']=m.digest(snapshot['profiles']);snapshot['generationRef']=m.generation_reference(snapshot)
                with self.assertRaisesRegex(ValueError,'INDEPENDENT_APPROVED_NODE_RECIPES'):
                    m.materialize(value,snapshot,[1,4,0,0,0o100600,1])

    def test_exact_runtime_capsule_and_full_source_closure_are_required(self):
        for change in ('capsule','closure','extra'):
            c,r,s,p,o=self.fixture()
            if change=='capsule':c['sources'][-2]['sha256']='e'*64
            elif change=='closure':c['sourceManifest']['sourceHashes'].pop(next(iter(m.PINS)))
            else:c['sourceManifest']['sourceHashes']['unreviewed']='e'*64
            with self.assertRaises(ValueError):m.template(c,r,p,**o)

    def test_only_explicit_holes_are_permitted_and_materialization_does_not_change_budgets(self):
        for change in ('lock','unit','recipe','generation'):
            c,r,s,p,o=self.fixture()
            if change=='lock':c['commonLockIdentity']=[1,4,0,0,0o100600,1]
            elif change=='unit':c['serviceUnitHash']='f'*64
            elif change=='recipe':c['sources'][-1]['sha256']='f'*64
            else:r['scope']['generationRef']=s['generationRef']
            with self.assertRaises(ValueError):m.template(c,r,p,**o)
        value,snapshot=self.prepared();result=m.materialize(value,snapshot,[1,4,0,0,0o100600,1])
        self.assertEqual(result['recipe']['policy'],value['recipeTemplate']['policy'])
        self.assertEqual(result['recipe']['scope']['contextRef'],value['recipeTemplate']['scope']['contextRef'])

    def test_changed_template_private_key_visibility_or_unowned_lock_is_denied(self):
        value,snapshot=self.prepared();value['targetApplyAuthorized']=True
        with self.assertRaisesRegex(ValueError,'TEMPLATE_CHANGED'):m.parent_scope(value)
        c,r,s,p,o=self.fixture();o['signing_key_paths']=[o['installation_root']+'/private.key']
        with self.assertRaisesRegex(ValueError,'SIGNING_KEY_WOULD_BE_EXPOSED'):m.template(c,r,p,**o)
        value,snapshot=self.prepared()
        for lock in ([1,4,10001,0,0o100600,1],[1,4,0,0,0o100644,1],[1,4,0,0,0o100600,2]):
            with self.assertRaisesRegex(ValueError,'PRIVATE_LOGICAL_LOCK'):m.materialize(value,snapshot,lock)

    def test_policy_or_coordinator_reference_cannot_silently_change(self):
        for change in ('policy','binding','dns'):
            c,r,s,p,o=self.fixture()
            if change=='policy':r['policy']['max_attempts']+=1
            elif change=='binding':r['binding']['configurationHash']='f'*64
            else:r['dns']['resolvers']=['9.9.9.9']
            with self.assertRaisesRegex(ValueError,'STATIC_DISCOVERY_SCOPE'):m.template(c,r,p,**o)

if __name__=='__main__':unittest.main()
