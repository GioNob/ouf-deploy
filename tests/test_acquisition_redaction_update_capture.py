"""Synthetic completed installation; actual protected files. No production access."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
f=load('old_capture_fixture',ROOT/'tests/test_mcp_denial_update_capture.py')
m=load('redaction_capture',ROOT/'scripts/prepare-acquisition-redaction-update-inputs-20261026.py')

class RedactionCaptureTests(unittest.TestCase):
    # Reuse only setup/teardown from earlier synthetic seven-component fixture.
    def setUp(self):
        f.CaptureTests.setUp(self)
        self.inputs={'schema':'ouf.mcp-denial-update-inputs.v1','bootId':'ci-boot','engineBinding':{},
                     'currentObservations':{r:copy.deepcopy(self.observations[cid]) for r,cid in self.ids.items()},
                     'currentProcessPins':{r:copy.deepcopy(self.pins[self.observations[cid]['State']['Pid']]) for r,cid in self.ids.items()}}
        old=self.ids['mcp'];new=format(8,'064x');self.ids['mcp']=new
        current=copy.deepcopy(self.observations[old]);current['Id']=new;current['State']['Pid']=108
        current['Image']=m.MCP_IMAGE;self.observations[new]=current;self.pins[108]=dict(copy.deepcopy(self.pin),pid=108)
        self.review={'schema':'ouf.mcp-diagnostic-update-review.v1','bootId':'ci-boot','stages':m.STAGES,
                     'nativePlan':{'proposal':{'capturedInputsHash':m.digest(self.inputs)}}}
        self.review['nativePlanHash']=m.digest(self.review['nativePlan'])
        self.result={'schema':'ouf.mcp-diagnostic-update-result.v1','status':'MCP_DIAGNOSTIC_UPDATE_INSTALLED_E2E_NOT_ACCEPTED',
                     'complete':True,'reviewHash':m.digest(self.review),'authorityHash':m.AUTHORITY_HASH,'nativeImageId':m.MCP_IMAGE,
                     'nativeBindingHash':m.digest(m.stable_binding(current)),'counts':m.COUNTS,
                     'originalsAndReadReplicasUnchanged':6,'registryWorkerTouched':False,'componentReadinessProven':True}
        self.journal={'schema':'ouf.mcp-diagnostic-update-journal.v1','state':'COMPLETE','quarantine':None,
                      'reviewHash':m.digest(self.review),'authorityHash':m.AUTHORITY_HASH,'counts':m.COUNTS,
                      'nextStage':len(m.STAGES),'effects':[{'stage':s,'state':'APPLIED'} for s in m.STAGES],
                      'candidates':{'mcp':{'id':new,'generation':self.pins[108],'configurationVerified':True,'readinessProven':True}}}
        self.input_path=self.source/'redaction-inputs.json'
        self.rewrite_history()
        self.diag_patch=patch.multiple(m,INPUTS_HASH=m.digest(self.inputs),REVIEW_HASH=m.digest(self.review),MCP_BINDING_HASH=self.result['nativeBindingHash'])
        self.diag_patch.start()
    def tearDown(self):self.diag_patch.stop();f.CaptureTests.tearDown(self)
    def rewrite_history(self):
        for path,value in [(self.input_path,self.inputs),(self.installed/'review.json',self.review),(self.installed/'result.json',self.result),(self.installed/'recovery.json',self.journal)]:
            path.write_bytes(m.encoded(value));path.chmod(0o600)
    def prepare(self):
        self.capture=m.Capture(self.base/'redaction-capture')
        return m.prepare(self.capture,inputs_path=self.input_path,installed=self.installed,engine_factory=self.engine,
                         pin=lambda pid:copy.deepcopy(self.pins[pid]),boot_path=self.boot)
    def test_completed_current_mcp_and_six_unchanged_components_no_old_history_writes(self):
        files=list(self.source.rglob('*.json'));before={str(p):(p.read_bytes(),m.frame(p.stat())) for p in files}
        result=self.prepare();self.assertTrue(result['complete'])
        self.assertEqual(result['counts']['privateMetadataReads'],4);self.assertEqual(result['counts']['engineGets'],10)
        self.assertEqual(len(self.calls),10);self.assertFalse(result['runtimeAuthorityIssued'])
        self.assertFalse(result['currentApplicationPolicyOrLabelsObserved'])
        self.assertNotIn('PRIVATE_CANARY',json.dumps(result));self.assertNotIn('do-not-print',json.dumps(result))
        self.assertEqual(before,{str(p):(p.read_bytes(),m.frame(p.stat())) for p in files})
        self.assertEqual(result['inputsHash'],m.digest(json.loads((self.capture.root/'inputs.json').read_text())))
        with self.assertRaises(m.Stop):m.Capture(self.capture.root)
    def test_incomplete_or_claimed_prefix_stops_before_engine(self):
        self.journal['effects'][0]['state']='CLAIMED';self.rewrite_history()
        with self.assertRaises(m.Stop):self.prepare()
        self.assertEqual(self.calls,[])
    def test_wrong_original_input_hash_stops_before_engine(self):
        self.input_path.write_text(json.dumps(self.inputs,indent=2))
        with self.assertRaises(m.Stop):self.prepare()
        self.assertEqual(self.calls,[])
    def test_changed_mcp_generation_cannot_be_adopted(self):
        self.pins[108]['startTicks']+=1
        with self.assertRaises(m.Stop):self.prepare()
    def test_changed_read_replica_is_not_ignored(self):
        self.observations[self.ids['udp-read']]['Config']['Hostname']='drift'
        with self.assertRaises(m.Stop):self.prepare()
    def test_changed_original_stops_without_writes(self):
        self.observations[self.ids['gateway']]['HostConfig']['RestartPolicy']['Name']='always'
        with self.assertRaises(m.Stop):self.prepare()
    def test_reboot_requires_reconciliation_before_engine(self):
        self.boot.write_text('different-boot')
        with self.assertRaises(m.Stop):self.prepare()
        self.assertEqual(self.calls,[])
    def test_engine_remains_closed_read_only(self):
        c=m.Capture(self.base/'engine-only');e=m.Engine(c,{},list(self.ids.values()))
        for path in ('/v1.44/containers/json','/v1.44/containers/'+self.ids['mcp']+'/logs','/v1.44/containers/'+format(99,'064x')+'/json'):
            with self.assertRaises(m.Stop):e.get(path)
        self.assertEqual(c.counts['engineGets'],0);self.assertFalse(hasattr(e,'request'))


if __name__=='__main__':
    # Do not run inherited tests for the earlier, different operation.
    names=[name for name in RedactionCaptureTests.__dict__ if name.startswith('test_')]
    suite=unittest.TestSuite(RedactionCaptureTests(name) for name in names)
    outcome=unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if outcome.wasSuccessful() else 1)
