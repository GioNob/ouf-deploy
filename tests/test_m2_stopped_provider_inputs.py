"""Stopped dependency inputs are provenance, never a reused live admission."""
import copy,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from tools.m2_discovery_installation_profile import stopped_provider_preparation as m


def history():
    cid='a'*64;image='sha256:'+'b'*64
    oci={'ociVersion':'1.0.2','process':{'user':{'uid':636,'gid':636},'args':['reviewed-gateway']}}
    profile={'containerId':cid,'bundleHash':m.digest(oci),'applicationStartAuthorized':True}
    values={'driver':{'schema':'ouf.semantic-preexec-driver.v6','profile':profile,
        'authorityBinding':{'path':'/historical/expired-approval.json','sha256':'f'*64}},
        'framePolicy':{'schema':'ouf.semantic-configured-creation-frame-policy.v1','expectedOci':oci},
        'launch':{'schema':'ouf.semantic-creation-frame-launch.v1'},
        'template':{'schema':'ouf.semantic-creation-frame-template.v1'},
        'preparerTemplate':{'schema':'ouf.semantic-admission-preparer-template.v1'}}
    return values,dict(provider_id=cid,provider_image=image,profile_hash=m.digest(profile))


class StoppedProviderContract(unittest.TestCase):
    def test_exact_historical_contract_has_no_current_admission_or_replacement_policy(self):
        values,args=history();before=copy.deepcopy(values);out=m.retained_contract(values,**args)
        self.assertEqual(values,before);self.assertEqual(out['providerId'],args['provider_id'])
        self.assertFalse(out['authorityReused']);self.assertFalse(out['currentNativeAdmissionProven'])
        self.assertFalse(out['replacementExpectedPolicyCompiled'])
        self.assertNotIn('applicationStartAuthorized',out)

    def test_different_provider_or_profile_hash_is_refused(self):
        for name in ('provider','hash'):
            values,args=history()
            if name=='provider':args['provider_id']='c'*64
            else:args['profile_hash']='e'*64
            with self.subTest(name=name),self.assertRaises(ValueError):m.retained_contract(values,**args)

    def test_full_historical_oci_hash_must_match_driver(self):
        values,args=history();values['framePolicy']['expectedOci']['process']['args']=['changed']
        with self.assertRaises(ValueError):m.retained_contract(values,**args)

    def test_unrecognized_record_domain_or_wrong_frame_schema_is_refused(self):
        for name in ('extra','missing','frame'):
            values,args=history()
            if name=='extra':values['unreviewed']={}
            if name=='missing':del values['launch']
            if name=='frame':values['framePolicy']['schema']='ouf.fake.policy'
            with self.subTest(name=name),self.assertRaises(ValueError):m.retained_contract(values,**args)

if __name__=='__main__':unittest.main()
