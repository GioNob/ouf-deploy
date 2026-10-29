import importlib.util
from pathlib import Path
import sys
import unittest

spec=importlib.util.spec_from_file_location('new_r10_core',Path(__file__).with_name('activation_core.py'))
core=importlib.util.module_from_spec(spec);spec.loader.exec_module(core)


class Tests(unittest.TestCase):
    def setUp(self):
        self.saved_modules={k:v for k,v in sys.modules.items() if k=='tools' or k.startswith('tools.')}
        names=('materialize_southbound_kernel','semantic_provider_dns','materialize_southbound_lease_refresh',
               'semantic_provider_lease_nft','semantic_provider_lease_owner','semantic_provider_lease_coordination',
               'semantic_provider_coordinated_supervisor')
        self.sources={'tools/'+n+'.py':b'ORIGINAL=True\n' for n in names}
        self.sources['scripts/run_semantic_coordinated_lease_owner.py']=b'# sealed old launcher\n'
        self.owner={'sourceHashes':{n:core.digest(b) for n,b in self.sources.items()}}
        self.new=b'NEW_REVIEWED_CANDIDATE=True\n'
        self.delta={'path':'/fixture/new.py','sha256':core.digest(self.new),'originalSha256':core.digest(b'ORIGINAL=True\n')}
    def tearDown(self):
        for k in list(sys.modules):
            if k=='tools' or k.startswith('tools.'):del sys.modules[k]
        sys.modules.update(self.saved_modules)
    def read(self,path,expected):
        raw=self.new if str(path)=='/fixture/new.py' else self.sources[str(path.relative_to('/fixture/source'))]
        self.assertEqual(core.digest(raw),expected);return raw
    def test_new_nft_and_supervisor_execute_only_reviewed_bytes_old_closure_retained(self):
        modules,saved=core.load_installed(self.owner,Path('/fixture/source'),self.read,
                  nft_override=self.delta,supervisor_override=self.delta)
        self.assertEqual(saved,self.sources)
        self.assertTrue(modules['semantic_provider_lease_nft'].NEW_REVIEWED_CANDIDATE)
        self.assertTrue(modules['semantic_provider_coordinated_supervisor'].NEW_REVIEWED_CANDIDATE)
    def test_wrong_old_hash_or_unreviewed_fields_refused(self):
        for delta in ({**self.delta,'originalSha256':'0'*64},{**self.delta,'allowRestart':True}):
            for kind in ('nft_override','supervisor_override'):
                with self.assertRaisesRegex(ValueError,'EXPLICIT_REVIEWED_FINITE_LEASE_DELTA_REQUIRED'):
                    core.load_installed(self.owner,Path('/fixture/source'),self.read,**{kind:delta})
    def test_missing_old_program_is_not_discovered_or_adopted(self):
        self.owner['sourceHashes'].pop('tools/semantic_provider_lease_nft.py')
        with self.assertRaisesRegex(ValueError,'EXACT_INSTALLED_OWNER_CLOSURE_REQUIRED'):
            core.load_installed(self.owner,Path('/fixture/source'),self.read,nft_override=self.delta)
    def test_future_rejected_ttl_value_is_retained_without_address_or_secrets(self):
        error=RuntimeError('NFT_SET_TTL_UNPROVEN')
        error.nft_readback={'family':'inet','flowIndex':0,'expiresType':'int','expiresValue':0,
                           'duplicateAddress':False,'configuredLeaseSeconds':30}
        self.assertEqual(core.diagnosis(error)['exceptionChain'][0]['nftReadback']['expiresValue'],0)
        error.nft_readback['address']='private-secret-value'
        result=core.diagnosis(error)
        self.assertNotIn('nftReadback',result['exceptionChain'][0])
        self.assertNotIn('private-secret-value',str(result))


if __name__=='__main__':unittest.main()
