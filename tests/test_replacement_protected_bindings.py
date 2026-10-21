import copy,importlib.util,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('intake',Path(__file__).parent.parent/'scripts/read-replacement-protected-bindings.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Intake(unittest.TestCase):
    def setUp(self):
        self.args=[{'schema':'ouf.discovery.private-runtime-input-manifest.v1','mountsInstalled':False,'applicationCutoverAuthorized':False,'existingWorkloadCredentialHash':'a'*64,'discoveryMacKeyHash':'b'*64,'publicCaHash':'c'*64},{'routes':{'fixture':'retained privately'}},{'status':'CANDIDATE_PUBLIC_JAVA_TRUST_PREPARED_NOT_MOUNTED','runtimeInputManifestHash':m.MANIFEST_HASH,'truststoreHash':'dcfb221cf3382ab02b752bce3274f64a63c0d822227a5359d1329dee38008079','containsPrivateKeys':False,'toolContainerCleanupProven':True},{'runtimeInputManifestHash':m.MANIFEST_HASH,'applyAuthorized':False,'completeReplacementOciProven':False}]
    def test_preserves_binding_privately_without_promoting_apply(self):
        p=m.validate(*self.args);self.assertEqual(p['originalProviderBinding'],self.args[1]);self.assertFalse(p['productionApplyReady'])
    def test_mounted_or_authorized_inputs_denied(self):
        for k in ('mountsInstalled','applicationCutoverAuthorized'):
            args=copy.deepcopy(self.args);args[0][k]=True
            with self.assertRaises(ValueError):m.validate(*args)
    def test_unbound_trust_or_missing_cleanup_denied(self):
        for k,value in [('runtimeInputManifestHash','0'*64),('toolContainerCleanupProven',False),('containsPrivateKeys',True)]:
            args=copy.deepcopy(self.args);args[2][k]=value
            with self.assertRaises(ValueError):m.validate(*args)
    def test_unreviewed_draft_and_missing_route_bindings_denied(self):
        for index,k,v in [(3,'applyAuthorized',True),(1,'routes',None),(0,'discoveryMacKeyHash','raw-private-value')]:
            args=copy.deepcopy(self.args);args[index][k]=v
            with self.assertRaises(ValueError):m.validate(*args)
if __name__=='__main__':unittest.main()
