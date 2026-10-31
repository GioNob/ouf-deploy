"""Early composition contract; no Engine, namespace, kernel or manager effects."""
import copy,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_m2_provider_profiles as providers
from fixtures.m2_admitted_provider_sealed_worker_native import review,bind_review
from tools.m2_discovery_installation_profile import lease_materialization as materialization
from tools.m2_discovery_installation_profile.provider_materialized_admission import admission_scope

class EarlyReview(unittest.TestCase):
    def test_same_provider_and_registry_inputs_are_bound_before_cids_or_worker_ledger_exist(self):
        fixture=providers.Profiles();self.addCleanup(fixture.doCleanups)
        issuer,window,auth,_,_,options,_=fixture.fixture()
        root=auth.root/'joint-worker-case';root.mkdir(mode=0o700)
        profile=copy.deepcopy(issuer.scope);prep=profile['preparerTemplate']
        kernel=root/'provider-kernel';kernel.mkdir(mode=0o700)
        prep['lockFile']=str(kernel/'kernel.lock')
        auth.write(Path(prep['lockFile']),b'')
        prep['coordinationBinding']['configurationHash']=materialization.digest(prep['kernel'])
        template,setup=review(auth,root,issuer.template,profile,window.request)
        provider=admission_scope(template,issuer.template,issuer.creation.scope,profile)
        scope_hash=bind_review(auth,setup,provider)
        materialization.paired_native_inputs(template,profile,window.request,
            [*materialization.inode(prep['lockFile']),0,1,1])
        self.assertEqual(scope_hash,materialization.digest(setup['start']))
        self.assertFalse(Path(template['configurationTemplate']['commonInvocationLock']).exists())
        self.assertFalse(Path(template['configurationTemplate']['ledgerRoot']).exists())
        self.assertFalse(Path(template['installationRoot']).exists())
        self.assertEqual(template['recipeTemplate']['kernel'],prep['kernel'])
        self.assertEqual(template['recipeTemplate']['dns'],prep['dns'])
        self.assertEqual(template['expectedImages']['registry'],window.request['Image'])
        self.assertEqual(template['expectedImages']['provider'],issuer.template['expectedImageId'])
        self.assertIn(str(auth.key),template['signingKeyPaths'])

if __name__=='__main__':unittest.main()
