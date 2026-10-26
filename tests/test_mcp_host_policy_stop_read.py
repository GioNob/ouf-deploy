"""Root filesystem tests, synthetic retained records only; no runtime services."""
import copy,hashlib,importlib.util,json,os,tempfile,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('host_read',Path(__file__).resolve().parents[1]/'scripts/read-mcp-host-policy-stop-20261026.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class RetainedRead(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.geteuid(),0,'ROOT_TEST_REQUIRED_NO_SKIP');self.tmp=tempfile.TemporaryDirectory(dir=Path.cwd());self.base=Path(self.tmp.name);self.base.chmod(0o700)
        for n in('stopped','code','native','inputs'):(self.base/n).mkdir(mode=0o700)
        self.host={'AutoRemove':False,'Memory':0,'MemorySwap':0,'OomKillDisable':None,'RestartPolicy':{'Name':'unless-stopped','MaximumRetryCount':0},'Binds':['/synthetic/private:/config:ro']}
        self.source={}
        for n in('entry.py','context.py','sources.json'):
            raw=('SYNTHETIC_'+n).encode();self.write(self.base/'code'/n,raw);self.source[n]=m.sha(raw)
        self.write(self.base/'code/operator.log',{'schema':'ouf.mcp-diagnostic-update-result.v1','status':'STOP_RECONCILE','reasonCode':'FINITE_RETAINED_MCP_HOST_POLICY_REQUIRED','contextPath':None,'complete':False},mode=0o600)
        self.write(self.base/'stopped/preflight-attempt-1234-00001.json',{'kind':'ownerConfigurationReads','attempt':1,'attemptNotCompletion':True})
        self.write(self.base/'stopped/preflight-attempt-1234-00002.json',{'kind':'ownerConfigurationReads','attempt':2,'attemptNotCompletion':True})
        self.prepare()
    def tearDown(self):self.tmp.cleanup()
    def write(self,p,v,mode=0o400):
        raw=v if isinstance(v,bytes)else m.encoded(v)
        if p.exists():p.chmod(0o600)
        p.write_bytes(raw);p.chmod(mode);return m.sha(raw)
    def prepare(self):
        self.ih=self.write(self.base/'inputs/inputs.json',{'schema':'ouf.mcp-denial-update-inputs.v1','currentObservations':{'mcp':{'HostConfig':self.host}}})
        replacement=copy.deepcopy(self.host);replacement['RestartPolicy']={'Name':'no','MaximumRetryCount':0}
        self.nh=self.write(self.base/'native/native-plan.json',{'schema':'ouf.mcp-denial-native-image-plan.v1','proposal':{'capturedInputsHash':self.ih,'mcpReplacement':{'request':{'HostConfig':replacement},'oldNativeHostConfig':self.host}}})
        self.write(self.base/'stopped/preparation-claim.json',{'schema':'ouf.mcp-diagnostic-update-preflight-claim.v1','nativePlanHash':self.nh,'maximums':m.LIMITS,'runtimeEffectsDispatched':0,'automaticReplayAllowed':False,'budgetReset':False})
    def call(self):return m.observe(self.base/'read',self.base/'stopped',self.base/'native/native-plan.json',self.base/'inputs/inputs.json',self.base/'code',self.ih,self.nh,self.source)
    def test_zero_memory_retained_no_authority_and_no_writes_to_originals(self):
        before={p:(p.read_bytes(),m.frame(p.stat()))for d in('stopped','code','native','inputs')for p in(self.base/d).iterdir()}
        v=self.call();self.assertTrue(v['complete']);self.assertEqual(v['failedGuardChecks'],['memoryStrictlyPositive']);self.assertEqual(v['hostPolicy']['Memory'],{'present':True,'type':'int','value':0});self.assertEqual(v['counts']['fileReads'],9)
        self.assertFalse(v['runtimeAuthorityIssued']);self.assertFalse(v['currentRuntimeStateObserved']);self.assertEqual(v['newEngineRequests'],0)
        for p,(raw,metadata)in before.items():self.assertEqual(p.read_bytes(),raw);self.assertEqual(m.frame(p.stat()),metadata)
        self.assertNotIn('synthetic/private',json.dumps(v));self.assertNotIn('Binds',json.dumps(v))
    def test_retained_scope_is_not_replayed(self):
        self.call()
        with self.assertRaisesRegex(m.Stop,'CONSUMED_NO_REPLAY'):self.call()
    def test_exact_guard_can_be_autoremove(self):
        self.host.update(AutoRemove=True,Memory=134217728);self.prepare();self.assertEqual(self.call()['failedGuardChecks'],['autoRemoveExactlyFalse'])
    def test_memory_bool_not_int(self):
        self.host['Memory']=True;self.prepare();v=self.call();self.assertEqual(v['failedGuardChecks'],['memoryExactlyInt','memoryStrictlyPositive'])
    def test_memory_missing_differentiated(self):
        del self.host['Memory'];self.prepare();self.assertFalse(self.call()['hostPolicy']['Memory']['present'])
    def test_positive_policy_does_not_explain_stop(self):
        self.host['Memory']=134217728;self.prepare()
        with self.assertRaisesRegex(m.Stop,'STOP_NOT_REPRODUCED'):self.call()
    def test_any_journal_marker_rejected_before_native_reads(self):
        self.write(self.base/'stopped/journal.json',{})
        with self.assertRaisesRegex(m.Stop,'ONLY_PREFLIGHT_FILES'):self.call()
    def test_wrong_native_bytes_rejected(self):
        self.write(self.base/'native/native-plan.json',{})
        with self.assertRaisesRegex(m.Stop,'EXACT_RETAINED_BYTES'):self.call()
    def test_nonroot_writable_or_unprotected_old_file_rejected(self):
        (self.base/'inputs/inputs.json').chmod(0o644)
        with self.assertRaisesRegex(m.Stop,'PROTECTED_BOUNDED'):self.call()
    def test_symlink_rejected(self):
        p=self.base/'inputs/inputs.json';p.rename(p.with_suffix('.saved'));p.symlink_to(p.with_suffix('.saved'))
        with self.assertRaises(OSError):self.call()
    def test_duplicate_keys_rejected(self):
        with self.assertRaisesRegex(m.Stop,'DUPLICATE_RETAINED_KEY'):m.decode(b'{"x":1,"x":2}')
    def test_wrong_code_bytes_rejected(self):
        self.write(self.base/'code/context.py',b'WRONG')
        with self.assertRaisesRegex(m.Stop,'EXACT_RETAINED_BYTES'):self.call()
if __name__=='__main__':unittest.main(verbosity=2)
