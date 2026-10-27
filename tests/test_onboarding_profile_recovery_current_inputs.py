import copy
import importlib.util
import pathlib
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('capture', pathlib.Path(__file__).parents[1]/'scripts/capture-onboarding-profile-recovery-inputs-20261027.py')
m = importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(m)


def fixture(observation=None,generation=None,binding=None,boot='boot',installed=pathlib.Path('/private/installed')):
    observation=copy.deepcopy(observation or {'Id':'a'*64,'Image':m.INSTALLED_NATIVE_IMAGE,'Name':'/private-owner','State':{'Running':True,'Paused':False,'Restarting':False,'Pid':44,'StartedAt':'now'},'Config':{'Env':['PRIVATE_CANARY']},'HostConfig':{'Memory':0},'Mounts':[],'NetworkSettings':{}})
    generation=copy.deepcopy(generation or {'pid':44,'startTicks':1,'namespaces':{'net':[1,2],'mnt':[1,3]}})
    review={'schema':'ouf.onboarding-diagnostic-update-review.v1','executionRoot':str(installed),'nativePlan':{'proposal':{'engineBinding':binding or {}}},'bootId':boot,'stages':['VERIFY_CURRENT_ADMISSION','VERIFY_FINAL','VERIFY_FINAL_STATE']}
    reviewed=m.digest(review);native=m.digest(m.stable_binding(observation))
    result={'schema':'ouf.onboarding-diagnostic-update-result.v1','status':'ONBOARDING_DIAGNOSTIC_UPDATE_INSTALLED_E2E_NOT_ACCEPTED','contextPath':str(installed),'complete':True,
        'reviewHash':reviewed,'authorityHash':m.AUTHORITY_HASH,'nativeImageId':observation['Image'],'nativeBindingHash':native,
        'candidateSourceCommit':'a5ed8b05c264a8221783a6e323ba00117aed891d','registryWorkerTouched':False,'componentReadinessProven':True,
        'databaseMigrationsByRepair':0,'newGrantsGranted':0,'sourceActivations':0,'acquisitionsExecuted':0,'budgetReset':False,'automaticReplayAllowed':False,
        'counts':{'engineGets':261,'engineWrites':8,'sqlSessions':4},'operationalStateProof':{'retainedFailedJobUnchanged':True}}
    effects=[{'stage':stage,'state':'APPLIED','intentHash':m.digest({'reviewHash':reviewed,'stage':stage}),'proof':{'nativeBindingHash':native,'generation':copy.deepcopy(generation)} if stage=='VERIFY_FINAL' else {}} for stage in review['stages']]
    journal={'schema':'ouf.onboarding-diagnostic-update-journal.v1','state':'COMPLETE','reviewHash':reviewed,'authorityHash':m.AUTHORITY_HASH,'quarantine':None,
        'automaticReplayAllowed':False,'budgetReset':False,'nextStage':len(effects),'effects':effects,'candidates':{'onboarding':{'id':observation['Id'],'configurationVerified':True,'readinessProven':True,'generation':copy.deepcopy(generation)}}}
    inputs={'schema':'ouf.onboarding-diagnostic-current-inputs.v1','bootId':boot,'engineBinding':binding or {},'automaticReplayAllowed':False,'budgetReset':False}
    return {'inputs.json':inputs,'review.json':review,'result.json':result,'recovery.json':journal},observation,generation,reviewed,native


class Capture:
    root=pathlib.Path('/private/new-scope')
    seals={}
    def __init__(self,values):self.values=values;self.counts={'engineGets':0,'privateMetadataReads':0,'bytes':0};self.saved={}
    def private(self,path,expected=None):self.counts['privateMetadataReads']+=1;return copy.deepcopy(self.values[path.name])
    def put(self,name,value):
        if name in self.saved:raise AssertionError('overwrite')
        self.saved[name]=copy.deepcopy(value)


class Boot:
    def read_text(self):return 'boot\n'


class Tests(unittest.TestCase):
    def setUp(self):
        values,self.observation,self.pin,reviewed,native=fixture();self.c=Capture(values);self.paths=[]
        for name,value in [('REVIEW_HASH',reviewed),('INSTALLED_NATIVE_BINDING_HASH',native)]:
            patcher=patch.object(m,name,value);patcher.start();self.addCleanup(patcher.stop)
    def engine(self,c,binding,ids):
        self.assertEqual(ids,[self.observation['Id']]);outer=self
        class Engine:
            def get(self,path):
                outer.paths.append(path);c.counts['engineGets']+=1
                value={'ID':'private-engine'} if path=='/v1.44/info' else copy.deepcopy(outer.observation)
                if len(outer.paths)==3 and getattr(outer,'drift',False):value['Config']['MacAddress']='changed'
                return value
        return Engine()
    def prepare(self):return m.prepare(self.c,inputs_path=pathlib.Path('/private/capture/inputs.json'),installed=pathlib.Path('/private/installed'),engine_factory=self.engine,pin=lambda pid:copy.deepcopy(self.pin),boot_path=Boot())
    def test_positive_four_metadata_three_gets_no_runtime_or_private_print(self):
        result=self.prepare();self.assertTrue(result['complete']);self.assertEqual(self.c.counts['privateMetadataReads'],4);self.assertEqual(len(self.paths),3)
        self.assertNotIn('PRIVATE_CANARY',str(result));self.assertFalse(result['runtimeAuthorityIssued']);self.assertFalse(result['currentJobOrBudgetStateObserved']);self.assertEqual(result['containerWrites'],0)
        self.assertEqual(self.c.saved['inputs.json']['retainedDiagnosticApplyCounts']['engineGets'],261)
    def test_review_drift_stops_before_engine(self):
        self.c.values['review.json']['executionRoot']='/different'
        with self.assertRaises(m.Stop):self.prepare()
        self.assertEqual(self.paths,[])
    def test_unfinished_or_claimed_effect_stops_before_engine(self):
        self.c.values['recovery.json']['effects'][0]['state']='CLAIMED'
        with self.assertRaises(m.Stop):self.prepare()
        self.assertEqual(self.paths,[])
    def test_incomplete_or_quarantined_journal_stops_before_engine(self):
        for field,value in [('state','OPEN'),('quarantine',{'state':'CLAIMED'})]:
            original=copy.deepcopy(self.c.values['recovery.json']);self.c.values['recovery.json'][field]=value
            with self.assertRaises(m.Stop):self.prepare()
            self.c.values['recovery.json']=original
        self.assertEqual(self.paths,[])
    def test_wrong_receipt_authority_stops_before_engine(self):
        self.c.values['result.json']['authorityHash']='different'
        with self.assertRaises(m.Stop):self.prepare()
        self.assertEqual(self.paths,[])
    def test_wrong_retained_generation_stops_before_engine(self):
        self.c.values['recovery.json']['candidates']['onboarding']['generation']['startTicks']=2
        with self.assertRaises(m.Stop):self.prepare()
        self.assertEqual(self.paths,[])
    def test_current_image_change_stops_with_private_engine_evidence_retained(self):
        self.observation['Image']='sha256:'+'b'*64
        with self.assertRaises(m.Stop):self.prepare()
        self.assertEqual(len(self.paths),2);self.assertNotIn('inputs.json',self.c.saved)
    def test_running_generation_drift_is_not_normalized(self):
        self.drift=True
        with self.assertRaises(m.Stop):self.prepare()
        self.assertNotIn('inputs.json',self.c.saved)
    def test_current_process_pin_drift_stops_without_dispatching_runtime_effects(self):
        self.pin['startTicks']=99
        with self.assertRaises(m.Stop):self.prepare()
        self.assertEqual(len(self.paths),2)
    def test_scope_is_consumed_even_after_stop(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(m,'ancestry'):
            root=pathlib.Path(folder)/'scope';m.Capture(root)
            with self.assertRaises(m.Stop):m.Capture(root)
    def test_duplicate_and_nonfinite_private_json_rejected(self):
        for raw in [b'{"x":1,"x":2}',b'{"x":NaN}']:
            with self.assertRaises(m.Stop):m.decode(raw)
    def test_transport_only_exact_selected_id_and_three_gets(self):
        e=m.Engine(self.c,{},[self.observation['Id']])
        for path in ['/v1.44/containers/json','/v1.44/containers/'+'b'*64+'/json','/v1.44/containers/'+self.observation['Id']+'/stop']:
            with self.assertRaises(m.Stop):e.get(path)
        self.assertEqual(self.c.counts['engineGets'],0);self.c.counts['engineGets']=3
        with self.assertRaises(m.Stop):e.get('/v1.44/info')


if __name__=='__main__':unittest.main()
