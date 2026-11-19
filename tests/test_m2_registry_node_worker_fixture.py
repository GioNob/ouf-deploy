"""CI-only preparation and prefix custody; not native admission or target proof."""
import copy,json,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_m2_provider_profiles as profiles
from fixtures import m2_registry_node_worker_native as m


class RegistryWorkerPreparation(unittest.TestCase):
    def test_independent_recipe_and_transport_share_static_inputs_before_any_node_claim(self):
        case=profiles.Profiles();self.addCleanup(case.doCleanups)
        issuer,window,auth,_,_,options,_=case.fixture()
        root=auth.root/'joint-registry-preparation';root.mkdir(mode=0o700)
        commands={k:'/usr/bin/true' for k in ('runc','ip','nsenter','nft')}
        seal=copy.deepcopy(options['registry_recipe']['expectedRootfsSeal'])
        result=m.configure_recipe(auth,root,options,commands,seal)
        recipe=options['registry_recipe'];transport=result['transportRecipe']
        self.assertEqual(recipe['expectedRootfsSeal'],seal)
        self.assertEqual(transport['nodeRecipeHash'],m.digest(recipe))
        self.assertEqual(transport['leaseConfigurationHash'],m.digest(options['preparer_template']['kernel']))
        self.assertEqual(transport['coordinatorBindingHash'],m.digest(options['preparer_template']['coordinationBinding']))
        self.assertEqual(result['transportIntent']['transportRecipeHash'],m.digest(transport))
        self.assertEqual(recipe['observationConfiguration']['candidate']['networkBindings'][0]['leaseGuard'],{
            'configurationHash':transport['leaseConfigurationHash'],
            'tableName':options['preparer_template']['kernel']['tableName']})
        self.assertEqual(list(result['nodeRoot'].iterdir()),[])
        self.assertEqual(list(result['transportRoot'].iterdir()),[])
        self.assertNotIn('observedOci',json.dumps(result['transportRecipe']))

    def test_native_prefix_is_preserved_and_incomplete_prefix_cannot_be_rewritten(self):
        phases=m.nodes.DISCOVERY_PHASES;index=phases.index('START_DISTINCT_LEASE_WORKER')
        raw=json.dumps({'phaseIntentHashes':{p:str(i%10)*64 for i,p in enumerate(phases)}}).encode()
        prefix=[{'phase':p,'state':'APPLIED','nativeEvidenceHash':str(i%10)*64} for i,p in enumerate(phases[:index])]
        row={'state':'READY','nextPhase':index,'effects':copy.deepcopy(prefix)}
        m.enter(row,'START_DISTINCT_LEASE_WORKER',raw)
        self.assertEqual(row['effects'][:index],prefix)
        before=copy.deepcopy(row)
        with self.assertRaises(AssertionError):m.enter(row,'START_DISTINCT_LEASE_WORKER',raw)
        self.assertEqual(row,before)
        pending={'state':'READY','nextPhase':index,'effects':copy.deepcopy(prefix)}
        pending['effects'][6]['state']='IN_FLIGHT';before=copy.deepcopy(pending)
        with self.assertRaises(AssertionError):m.enter(pending,'START_DISTINCT_LEASE_WORKER',raw)
        self.assertEqual(pending,before)


if __name__=='__main__':unittest.main()
