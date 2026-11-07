"""Pure private projection plans; no credentials or target IO."""
import copy,stat,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from tools.m2_discovery_installation_profile.projections import compile_projections
from tools.m2_discovery_installation_profile.audit import digest

class Projections(unittest.TestCase):
    def fixture(self):
        roles={'providerCredential':(10001,10001,0o400,'1'), 'registryDiscoveryKey':(10001,10001,0o400,'2'),
            'gatewayDiscoveryKey':(636,636,0o400,'2'),'publicProviderCa':(0,0,0o600,'3')}
        rows={k:{'path':'/fixture/historical/'+k,'sha256':h*64,'uid':u,'gid':g,'mode':mode,
            'metadata':[1,i+1,stat.S_IFREG|mode,u,g,1,64,10,11], 'historicalAuthorityReused':False,'runtimeAdmissionProven':False}
            for i,(k,(u,g,mode,h)) in enumerate(roles.items())}
        value={'schema':'ouf.m2-discovery-current-material-candidates.v1','installationInputsHash':'4'*64,
            'materialManifestHash':'5'*64,'processPins':{},'candidates':rows,'runtimeAuthorityIssued':False,
            'targetApplyAuthorized':False,'historicalAuthorityReused':False}
        return value,{'path':'/fixture/capture/material-candidates.private.json','sha256':digest(value)}
    def compile(self,v,b):return compile_projections(v,b,'/fixture/new-preparation','OUF_SEMANTIC_DISCOVERY_OWNER_KEY')
    def test_proposes_copies_preserving_source_owners_without_authority(self):
        v,b=self.fixture();before=copy.deepcopy(v);p=self.compile(v,b)
        self.assertEqual(v,before);self.assertEqual(len(p['projections']),2)
        for row in p['projections']:
            self.assertEqual((row['uid'],row['gid'],row['mode']),(0,10001,0o440))
            self.assertEqual((row['source']['uid'],row['source']['mode']),(10001,0o400))
        self.assertFalse(p['executionAllowed']);self.assertFalse(p['targetApplyAuthorized']);self.assertEqual(p['newKeysGenerated'],0)
    def test_public_receipt_or_changed_binding_is_not_private_input(self):
        v,b=self.fixture();b['sha256']='f'*64
        with self.assertRaises(ValueError):self.compile(v,b)
        public={'schema':'ouf.m2-discovery-custody-capture-result.v1','candidateBindingHash':'e'*64}
        with self.assertRaises(ValueError):self.compile(public,{'path':b['path'],'sha256':digest(public)})
    def test_same_source_directory_or_shadowing_output_is_denied(self):
        v,b=self.fixture()
        for path in ('/fixture/historical','/fixture/historical/new','/fixture'):
            with self.subTest(path=path),self.assertRaises(ValueError):compile_projections(v,b,path,'OUF_SEMANTIC_DISCOVERY_OWNER_KEY')
    def test_owner_metadata_or_key_pair_drift_is_denied_even_if_rehashed(self):
        for case in ('owner','mode','link','pair','credential','admission'):
            v,b=self.fixture();r=v['candidates']['gatewayDiscoveryKey']
            if case=='owner':r['metadata'][3]=0
            if case=='mode':r['metadata'][2]=stat.S_IFREG|0o444
            if case=='link':r['metadata'][2]=stat.S_IFLNK|0o400
            if case=='pair':r['sha256']='7'*64
            if case=='credential':v['candidates']['providerCredential']['sha256']='2'*64
            if case=='admission':v['targetApplyAuthorized']=True
            b['sha256']=digest(v)
            with self.subTest(case=case),self.assertRaises(ValueError):self.compile(v,b)
    def test_other_existing_receipt_key_slot_is_not_reused(self):
        v,b=self.fixture()
        with self.assertRaises(ValueError):compile_projections(v,b,'/fixture/new-preparation','OUF_SEMANTIC_READ_OWNER_KEY')

if __name__=='__main__':unittest.main()
