import copy
import importlib.util
import pathlib
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('capture', pathlib.Path(__file__).parents[1]/'scripts/capture-onboarding-diagnostic-inputs-20261026.py')
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


class Capture:
    root = pathlib.Path('/private/new-scope')
    seals = {}
    def __init__(self):
        self.counts = {'engineGets': 0, 'privateMetadataReads': 0, 'bytes': 0}
        self.saved = {}
        self.cid = 'a'*64
        self.inputs = {'schema':'ouf.acquisition-redaction-update-inputs.v1','bootId':'boot','engineBinding':{},'automaticReplayAllowed':False,'budgetReset':False}
        self.review = {'bootId':'boot','recovery':{'currentCandidate':{'containerId':self.cid}}}
        self.result = {'schema':'ouf.onboarding-v35-native-update-result.v1','status':'ONBOARDING_V35_EXISTING_CANDIDATE_RECOVERED_SOURCE_PRESERVED','complete':True,'reviewHash':m.REVIEW_HASH,'authorityHash':m.AUTHORITY_HASH,'existingCandidateAdopted':True,'creationReplayed':False,'registryWorkerTouched':False,'applicationReadinessProven':True}
    def private(self, path, expected=None):
        self.counts['privateMetadataReads'] += 1
        return copy.deepcopy(self.review if path.name == 'review.json' else self.result if path.name == 'result.json' else self.inputs)
    def put(self, name, value):
        if name in self.saved: raise AssertionError('overwrite')
        self.saved[name] = value


class Boot:
    def read_text(self): return 'boot\n'


class Tests(unittest.TestCase):
    def setUp(self):
        self.c = Capture()
        self.observation = {'Id':self.c.cid,'Image':'sha256:'+'b'*64,'Name':'/private-owner','State':{'Running':True,'Paused':False,'Restarting':False,'Pid':44,'StartedAt':'now'},'Config':{'Env':['PRIVATE_VALUE']},'HostConfig':{'Memory':0},'Mounts':[],'NetworkSettings':{}}
        self.paths = []
    def engine(self, c, binding, ids):
        self.assertEqual(ids, [self.c.cid])
        outer = self
        class Engine:
            def get(self, path):
                outer.paths.append(path)
                c.counts['engineGets'] += 1
                value = {'ID':'private-engine'} if path == '/v1.44/info' else copy.deepcopy(outer.observation)
                if len(outer.paths) == 3 and getattr(outer, 'drift', False): value['Config']['MacAddress'] = 'changed'
                return value
        return Engine()
    def prepare(self):
        return m.prepare(self.c, inputs_path=pathlib.Path('/p/inputs.json'), installed=pathlib.Path('/p'), engine_factory=self.engine, pin=lambda pid:{'pid':pid,'startTicks':1}, boot_path=Boot())
    def test_positive_only_three_gets_and_no_configuration_printed(self):
        result = self.prepare()
        self.assertEqual(len(self.paths), 3)
        self.assertTrue(result['complete'])
        self.assertNotIn('PRIVATE_VALUE', str(result))
        self.assertEqual(self.c.saved['inputs.json']['onboardingObservation'], self.observation)
        self.assertFalse(result['runtimeAuthorityIssued'])
        self.assertEqual(result['containerWrites'], 0)
    def test_wrong_history_stops_before_engine(self):
        self.c.result['reviewHash'] = 'wrong'
        with self.assertRaises(m.Stop): self.prepare()
        self.assertEqual(self.paths, [])
    def test_consumed_create_cannot_be_replayed(self):
        self.c.result['creationReplayed'] = True
        with self.assertRaises(m.Stop): self.prepare()
        self.assertEqual(self.paths, [])
    def test_boot_drift_stops_before_engine(self):
        self.c.review['bootId'] = 'other'
        with self.assertRaises(m.Stop): self.prepare()
        self.assertEqual(self.paths, [])
    def test_stopped_candidate_rejected(self):
        self.observation['State']['Running'] = False
        with self.assertRaises(m.Stop): self.prepare()
        self.assertEqual(len(self.paths), 2)
    def test_config_mac_or_other_drift_not_ignored(self):
        self.drift = True
        with self.assertRaises(m.Stop): self.prepare()
        self.assertNotIn('inputs.json', self.c.saved)
    def test_decode_duplicate_and_nonfinite_rejected(self):
        for raw in [b'{"x":1,"x":2}', b'{"x":NaN}']:
            with self.assertRaises(m.Stop): m.decode(raw)
    def test_scope_is_one_shot_even_after_stop(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(m,'ancestry'):
            root = pathlib.Path(folder)/'scope'
            m.Capture(root)
            with self.assertRaises(m.Stop): m.Capture(root)
    def test_transport_rejects_unselected_id_and_post_paths(self):
        engine = m.Engine(self.c, {}, [self.c.cid])
        for path in ['/v1.44/containers/json','/v1.44/containers/'+self.c.cid+'/stop','/v1.44/containers/'+'b'*64+'/json']:
            with self.assertRaises(m.Stop): engine.get(path)
        self.assertEqual(self.c.counts['engineGets'], 0)


if __name__ == '__main__': unittest.main()
