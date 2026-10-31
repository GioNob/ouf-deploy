import hashlib,importlib.util,json,os,subprocess,tempfile,unittest
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('offline',BASE/'scripts/read-acquisition-unapproved-review-20261025.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)

class Contract(unittest.TestCase):
    def test_parser_rejects_duplicate_and_nonfinite_json(self):
        for raw in(b'{"a":1,"a":2}',b'{"a":NaN}'):
            with self.assertRaises(r.Stop):r.decode(raw)
    def test_main_requires_isolated_root_no_alternate_arguments(self):
        p=subprocess.run([os.sys.executable,str(BASE/'scripts/read-acquisition-unapproved-review-20261025.py')],capture_output=True,text=True)
        self.assertEqual(p.returncode,2);self.assertEqual(json.loads(p.stdout)['reasonCode'],'ONE_ISOLATED_ROOT_OFFLINE_READER_REQUIRED')
    def test_source_has_no_runtime_transport_or_old_entry_execution(self):
        import ast
        tree=ast.parse((BASE/'scripts/read-acquisition-unapproved-review-20261025.py').read_text())
        imports={a.name.split('.')[0]for node in ast.walk(tree)if isinstance(node,(ast.Import,ast.ImportFrom))for a in node.names}
        self.assertFalse(imports&{'socket','subprocess','ctypes','importlib','urllib','http','tools'})
        calls={node.func.id for node in ast.walk(tree)if isinstance(node,ast.Call)and isinstance(node.func,ast.Name)}
        self.assertFalse(calls&{'exec','eval','compile','__import__'})

@unittest.skipUnless(os.environ.get('OUF_UNAPPROVED_ROOT_FIXTURE')=='1','requires dedicated root filesystem CI fixture')
class RetainedFilesystem(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir='/var/lib');self.base=Path(self.tmp.name);self.root=self.base/'execution';self.code=self.base/'code'
        self.root.mkdir(mode=0o700);self.code.mkdir(mode=0o700);self.native=self.base/'native.json'
        self.old=r.INPUT_HASH
        native={'schema':'ouf.acquisition-native-execution-inputs.v1','frozenPlanHash':'a'*64}
        self.write(self.native,native);r.INPUT_HASH=r.sha(self.native.read_bytes())
        manifest={}
        for n in r.SOURCE_NAMES:
            self.write(self.code/n,{'fixtureSource':n});manifest[n]=r.sha((self.code/n).read_bytes())
        self.write(self.code/'sources.json',manifest);self.mh=r.sha((self.code/'sources.json').read_bytes())
        self.closure={str(self.code/'sources.json'):self.mh,**{str(self.code/n):h for n,h in manifest.items()}}
        self.counts={k:0 for k in r.LIMITS};serial=0
        for kind in ['ownerConfigurationReads']*2+['ownerConfigurationReads','serviceCredentialFileReads']+['engineGets']*9+['ownerConfigurationReads']*2+['adminGets']:
            self.counts[kind]+=1;serial+=1;self.write(self.root/f'preflight-claim-{serial:04d}.json',{'kind':kind,'attempt':self.counts[kind],'attemptNotCompletion':True})
            if kind in('engineGets','adminGets'):
                serial+=1;prefix='engine-response'if kind=='engineGets'else'admin';self.write(self.root/f'preflight-{prefix}-{serial:04d}.json',{'privateValue':'MUST_NEVER_PRINT','status':200})
        self.write(self.root/'preparation-claim.json',{'schema':'ouf.acquisition-signed-execution-preparation-claim.v1','nativeInputsHash':r.INPUT_HASH,'maximums':r.LIMITS,'runtimeEffectsDispatched':0,'automaticReplayAllowed':False,'budgetReset':False})
        plan={'frozenPlanHash':'a'*64,'nativeInputsHash':r.INPUT_HASH,'privateValue':'MUST_NEVER_PRINT'}
        self.review={'schema':'ouf.acquisition-read-native-review.v1','executionRoot':str(self.root),'logicalOperationRef':r.INPUT_HASH,'maximums':r.LIMITS,'nativePlan':plan,'nativePlanHash':r.sha(r.encoded(plan)),'sourceClosure':self.closure,'sourceClosureHash':r.sha(r.encoded(self.closure)),'maximumSeconds':900,'negativeCleanup':{'maximumAdditionalSeconds':30,'startupSeconds':180,'candidateStopOnly':True,'maximumStops':3,'disableCandidateRestartFirst':True},'frozenPlanHash':'a'*64,'preflightCounts':self.counts,**{k:False for k in('databaseRestoreAuthorized','humanBudgetOrSourceActivationAuthorized','automaticReplayAllowed','budgetReset','releaseAcceptance')}}
        self.save_review()
    def tearDown(self):r.INPUT_HASH=self.old;self.tmp.cleanup()
    def write(self,path,v):
        if path.exists():path.chmod(0o600)
        path.write_bytes(r.encoded(v));path.chmod(0o400)
    def save_review(self):self.write(self.root/'review.json',self.review);self.rh=r.sha((self.root/'review.json').read_bytes())
    def run_reader(self):return r.reconcile(r.Reader(),self.root,self.code,self.native,self.rh,self.mh)
    def snapshot(self):return{str(p):p.read_bytes()for p in self.base.rglob('*')if p.is_file()and r.CHILD not in p.parts}
    def test_actual_filesystem_success_parent_unchanged_counters_and_redaction(self):
        before=self.snapshot();result=self.run_reader();self.assertEqual(before,self.snapshot());self.assertTrue(result['complete']);self.assertEqual(result['retainedPreflightCounts'],self.counts);self.assertLessEqual(result['privateMetadataReads'],96);self.assertNotIn('MUST_NEVER_PRINT',r.encoded(result).decode());self.assertFalse(result['currentRuntimeStateObserved']);self.assertFalse(result['continuationAuthorized'])
        self.assertTrue((self.root/r.CHILD/'complete.json').exists())
        with self.assertRaisesRegex(r.Stop,'SCOPE_CONSUMED'):self.run_reader()
    def test_authority_directory_blocks_without_modifying_it(self):
        (self.root/'authority').mkdir(mode=0o700)
        with self.assertRaisesRegex(r.Stop,'POST_REVIEW'):self.run_reader()
        self.assertEqual(list((self.root/'authority').iterdir()),[])
    def test_journal_or_unexpected_entry_blocks(self):
        for name in('journal.json','result.json','quarantine-unproven.json'):
            with self.subTest(name=name):
                self.write(self.root/name,{'private':'MUST_NEVER_PRINT'})
                with self.assertRaisesRegex(r.Stop,'POST_REVIEW'):self.run_reader()
                (self.root/name).unlink();self.remove_child()
    def remove_child(self):
        import shutil
        shutil.rmtree(self.root/r.CHILD)
    def test_review_or_source_drift_blocks(self):
        for path in(self.root/'review.json',self.code/'apply.py'):
            with self.subTest(path=path):
                old=path.read_bytes();self.write(path,{'changed':True})
                with self.assertRaisesRegex(r.Stop,'EXACT_RETAINED_HASH'):self.run_reader()
                path.chmod(0o600);path.write_bytes(old);path.chmod(0o400);self.remove_child()
    def test_symlink_and_hardlink_are_rejected(self):
        p=self.root/'preparation-claim.json';backup=self.base/'other';p.rename(backup);p.symlink_to(backup)
        with self.assertRaisesRegex(r.Stop,'ONLY_REGULAR'):self.run_reader()
        p.unlink();os.link(backup,p);self.remove_child()
        with self.assertRaisesRegex(r.Stop,'ONLY_REGULAR'):self.run_reader()
    def test_counter_change_is_not_reset(self):
        self.review['preflightCounts']={**self.counts,'engineGets':0};self.save_review()
        with self.assertRaisesRegex(r.Stop,'EXACT_RETAINED_PREFLIGHT_COUNTS'):self.run_reader()
    def test_missing_response_and_serial_gap_rejected(self):
        p=next(self.root.glob('preflight-engine-response-*'));p.unlink()
        with self.assertRaisesRegex(r.Stop,'COMPLETE_RETAINED_PREFLIGHT_SEQUENCE'):self.run_reader()
    def test_post_read_drift_detected(self):
        reader=r.Reader();reader.read(self.native);self.write(self.native,{'changed':True})
        with self.assertRaisesRegex(r.Stop,'RETAINED_METADATA_CHANGED'):reader.stable()
    def test_writable_or_nonroot_custody_rejected(self):
        (self.root/'review.json').chmod(0o600)
        with self.assertRaisesRegex(r.Stop,'IMMUTABLE_ROOT'):self.run_reader()
    def test_no_hidden_approval_signature_or_current_process_probe(self):
        result=self.run_reader();self.assertTrue(result['originalAuthorityAndJournalAbsent']);self.assertFalse((self.root/'authority').exists());self.assertFalse((self.root/'journal.json').exists());self.assertEqual(result['newCredentialReads'],0)
if __name__=='__main__':unittest.main()
