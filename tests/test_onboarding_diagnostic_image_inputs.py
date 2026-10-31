import copy,importlib.util,json,pathlib,tempfile,unittest
from unittest.mock import patch
ROOT=pathlib.Path(__file__).parents[1]
SPEC=importlib.util.spec_from_file_location('owner_prep',ROOT/'scripts/prepare-onboarding-diagnostic-image-inputs-20261026.py')
m=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(m)

def fixtures():
    inputs={'schema':'ouf.onboarding-diagnostic-current-inputs.v1','counts':{'bytes':127338,'engineGets':3,'privateMetadataReads':3},'retainedInstalledSource':'194b586508c6661b40a74d9c7f99ed3b876f5fbc','bootId':'ci-only','engineBinding':{},'engineInfo':{'ServerVersion':'29.8.1','DriverStatus':[['driver-type','io.containerd.snapshotter.v1']]},'onboardingProcessPin':{'pid':44},'onboardingObservation':{'Id':'a'*64,'Image':'sha256:'+'b'*64,'Name':'/ci-only-owner','State':{'Running':True,'Pid':44},'Config':{'User':'10003:10003','MacAddress':'02:42:ac:11:00:09','Env':['PRIVATE_CANARY=value']},'HostConfig':{'Memory':0,'OomKillDisable':None}}}
    receipt={'schema':'ouf.onboarding-diagnostic-current-input-capture-result.v1','status':'ONBOARDING_DIAGNOSTIC_CURRENT_INPUTS_CAPTURED_NOT_AUTHORIZED','complete':True,'inputsHash':m.INPUT_HASH,'counts':copy.deepcopy(inputs['counts']),'containerWrites':0,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False}
    return inputs,receipt

class Tests(unittest.TestCase):
    def setUp(self):self.inputs,self.receipt=fixtures()
    def test_exact_capture_is_input_not_authority(self):
        actual=m.validate_capture(self.inputs,self.receipt)
        self.assertEqual(actual,self.inputs['onboardingObservation'])
        self.assertEqual(actual['HostConfig']['Memory'],0)
        self.assertIsNone(actual['HostConfig']['OomKillDisable'])
        self.assertEqual(actual['Config']['MacAddress'],'02:42:ac:11:00:09')
    def test_changed_hash(self):
        self.receipt['inputsHash']='wrong'
        with self.assertRaises(m.Stop):m.validate_capture(self.inputs,self.receipt)
    def test_incomplete_capture(self):
        self.receipt['complete']=False
        with self.assertRaises(m.Stop):m.validate_capture(self.inputs,self.receipt)
    def test_authority_or_replay_never_inferred(self):
        for field in ['runtimeAuthorityIssued','automaticReplayAllowed','budgetReset']:
            with self.subTest(field=field):
                receipt=copy.deepcopy(self.receipt);receipt[field]=True
                with self.assertRaises(m.Stop):m.validate_capture(self.inputs,receipt)
    def test_counts_preserved(self):
        self.receipt['counts']['engineGets']=0
        with self.assertRaises(m.Stop):m.validate_capture(self.inputs,self.receipt)
    def test_unknown_engine_profile(self):
        self.inputs['engineInfo']['DriverStatus']=[]
        with self.assertRaises(m.Stop):m.validate_capture(self.inputs,self.receipt)
    def test_stopped_owner(self):
        self.inputs['onboardingObservation']['State']['Running']=False
        with self.assertRaises(m.Stop):m.validate_capture(self.inputs,self.receipt)
    def test_pid_drift(self):
        self.inputs['onboardingProcessPin']['pid']=45
        with self.assertRaises(m.Stop):m.validate_capture(self.inputs,self.receipt)
    def test_other_uid(self):
        self.inputs['onboardingObservation']['Config']['User']='0'
        with self.assertRaises(m.Stop):m.validate_capture(self.inputs,self.receipt)
    def test_duplicate_and_nonfinite_json(self):
        for raw in [b'{"a":1,"a":2}',b'{"a":NaN}']:
            with self.assertRaises(m.Stop):m.decode(raw)

if __name__=='__main__':unittest.main()
