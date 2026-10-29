import copy,importlib.util,json,os,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
BASE=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('guard_reader',BASE/'scripts/read-acquisition-old-mcp-guard-20261025.py');r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
class Classification(unittest.TestCase):
    def capture(self):return {'Id':'a'*64,'Image':'sha256:'+'b'*64,'Name':'/fixture-mcp','Config':{'MacAddress':'02:00:00:00:00:01','Env':['SECRET=MUST_NEVER_PRINT'],'Hostname':'fixture','Cmd':['server']},'Mounts':[],'State':{'StartedAt':'fixture-start','Running':True,'Pid':123},'NetworkSettings':{'Networks':{'fixture':{'MacAddress':'02:00:00:00:00:01'}}}}
    def binding(self,v):return {'containerId':v['Id'],'imageId':v['Image'],'configHash':r.digest(v['Config']),'mountsHash':r.digest(v['Mounts']),'startedAt':v['State']['StartedAt']}
    def test_four_guard_components_are_distinct_and_values_redacted(self):
        before=self.capture();after=copy.deepcopy(before);after['Image']='changed';after['Config']['Env']=['SECRET=DIFFERENT_PRIVATE'];after['Mounts']=[{'Destination':'/private','Source':'MUST_NEVER_PRINT'}];after['State']['StartedAt']='changed'
        result=r.compare(before,after,self.binding(before));self.assertEqual(result['failedGuardComponents'],['image','config','mounts','startedAt']);self.assertEqual(result['configDifferences'][0]['field'],'Env');self.assertNotIn('PRIVATE',r.encoded(result).decode());self.assertNotIn('MUST_NEVER_PRINT',r.encoded(result).decode())
    def test_legacy_mac_field_classified_without_claiming_target_cause(self):
        before=self.capture();after=copy.deepcopy(before);after['Config']['MacAddress']='';after['NetworkSettings']['Networks']={};after['State'].update(Running=False,Pid=0)
        result=r.compare(before,after,self.binding(before));self.assertEqual(result['failedGuardComponents'],['config']);field=result['configDifferences'][0];self.assertEqual(field['field'],'MacAddress');self.assertTrue(field['afterDefaultLike']);self.assertTrue(field['beforeMatchesOriginalSingleEndpointMac']);self.assertNotIn('02:00',r.encoded(result).decode())
    def test_boolean_and_integer_are_not_equal_typed_config(self):
        before=self.capture();before['Config']['AttachStdin']=False;after=copy.deepcopy(before);after['Config']['AttachStdin']=0
        result=r.compare(before,after,self.binding(before));self.assertEqual(result['configDifferences'][0]['field'],'AttachStdin');self.assertEqual(result['configDifferences'][0]['beforeType'],'bool');self.assertEqual(result['configDifferences'][0]['afterType'],'int')
    def test_unknown_field_names_hashed_and_duplicate_json_denied(self):
        before=self.capture();after=copy.deepcopy(before);after['Config']['PRIVATE_FIELD_NAME']='PRIVATE_VALUE';result=r.compare(before,after,self.binding(before));self.assertTrue(result['configDifferences'][0]['field'].startswith('UNKNOWN_SHA256_'));self.assertNotIn('PRIVATE_',r.encoded(result).decode())
        with self.assertRaises(r.Stop):r.decode(b'{"a":1,"a":2}')
    def test_no_runtime_ports_imports_and_main_has_no_override_arguments(self):
        import ast
        tree=ast.parse((BASE/'scripts/read-acquisition-old-mcp-guard-20261025.py').read_text());imports={a.name.split('.')[0]for n in ast.walk(tree)if isinstance(n,(ast.Import,ast.ImportFrom))for a in n.names};self.assertFalse(imports&{'socket','http','urllib','subprocess','ctypes','importlib','tools'})
        calls={n.func.id for n in ast.walk(tree)if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)};self.assertFalse(calls&{'exec','eval','compile','__import__'})
        p=subprocess.run([os.sys.executable,str(BASE/'scripts/read-acquisition-old-mcp-guard-20261025.py')],capture_output=True,text=True);self.assertEqual(p.returncode,2);self.assertEqual(json.loads(p.stdout)['reasonCode'],'ONE_ISOLATED_ROOT_RETAINED_GUARD_READER_REQUIRED')
@unittest.skipUnless(os.environ.get('OUF_OLD_MCP_GUARD_ROOT_FIXTURE')=='1','requires dedicated root filesystem CI fixture')
class RetainedFilesystem(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir='/var/lib');self.base=Path(self.tmp.name);self.root=self.base/'execution';self.code=self.base/'code';self.root.mkdir(mode=0o700);self.code.mkdir(mode=0o700);(self.root/'authority').mkdir(mode=0o700)
        self.before=Classification().capture();self.binding=Classification().binding(self.before);self.after=copy.deepcopy(self.before);self.after['Config']['MacAddress']='';self.after['State'].update(Running=False,Pid=0);self.after['NetworkSettings']['Networks']={}
        manifest={}
        for name in r.SOURCE_NAMES:self.write(self.code/name,{'fixtureSource':name});manifest[name]=r.sha((self.code/name).read_bytes())
        self.write(self.code/'sources.json',manifest);self.mh=r.sha((self.code/'sources.json').read_bytes())
        old=self.base/'old-mcp.json';self.write(old,self.before);self.inputs=self.base/'inputs.json';self.write(self.inputs,{'currentObservations':{'mcp':{'path':str(old),'sha256':r.digest(self.before)}}});self.ih=r.sha(self.inputs.read_bytes())
        proposal={'capturedInputsHash':self.ih,'mcpReplacement':{'oldBinding':self.binding,'name':'fixture-mcp','network':{'name':'fixture'}}};plan={'proposal':proposal}
        self.review={'schema':'ouf.acquisition-read-continuation-review.v1','executionRoot':str(self.root),'stages':list(r.STAGES),'maximums':r.LIMITS,'nativePlan':plan,'nativePlanHash':r.digest(plan)};self.write(self.root/'review.json',self.review);self.rh=r.digest(self.review)
        self.authority={'schema':'ouf.acquisition-read-native-authority.v1','scope':{'reviewHash':self.rh,'nativePlanHash':self.review['nativePlanHash'],'stages':list(r.STAGES),'maximums':r.LIMITS}};self.write(self.root/'authority/authority.json',self.authority);self.ah=r.digest(self.authority)
        effects=[{'stage':s,'state':'APPLIED','intentHash':r.digest({'reviewHash':self.rh,'stage':s}),'proof':{'fixture':True}}for s in r.STAGES[:13]];effects[-1]['proof']={'oldDetached':True};effects[-2]['proof']={'oldStopped':True}
        candidates={role:{'id':str(i)*64,'configurationVerified':True,'readinessProven':True}for i,role in enumerate(('ingestion','udp'),1)}
        self.journal={'schema':'ouf.acquisition-read-native-journal.v1','reviewHash':self.rh,'authorityHash':self.ah,'nextStage':13,'state':'STOP_RECONCILE','automaticReplayAllowed':False,'budgetReset':False,'effects':effects,'counts':{**r.LAST_PROGRESS,'engineGets':130,'engineWrites':14,'ownerConfigurationReads':42,'quarantineStops':2},'candidates':candidates,'quarantine':{'state':'APPLIED','candidates':{role:{'id':v['id'],'stopped':True,'restartDisabled':True}for role,v in candidates.items()}}};self.write(self.root/'recovery.json',self.journal,0o600)
        self.write(self.root/'engine-response-0001.json',{'status':200,'body':self.before});self.write(self.root/'engine-response-0002.json',{'status':200,'body':self.after});self.write(self.root/'engine-response-0003.json',{'status':200,'body':{'Id':'c'*64,'private':'MUST_NEVER_PRINT'}});self.write(self.root/'quarantine-result.json',{'status':'OWNED_CANDIDATES_QUARANTINED'})
    def tearDown(self):self.tmp.cleanup()
    def write(self,path,value,mode=0o400):
        if path.exists():path.chmod(0o600)
        path.write_bytes(r.encoded(value));path.chmod(mode)
    def read(self,reader=None):return r.inspect(reader or r.Reader(),self.root,self.code,self.inputs,self.rh,self.ah,self.mh,self.ih)
    def snapshot(self):return {str(p):p.read_bytes()for p in self.base.rglob('*')if p.is_file()and r.CHILD not in p.parts}
    def remove_child(self):
        import shutil
        shutil.rmtree(self.root/r.CHILD)
    def test_actual_filesystem_latest_response_counts_quarantine_parent_unchanged(self):
        before=self.snapshot();result=self.read();self.assertEqual(before,self.snapshot());self.assertEqual(result['failedGuardComponents'],['config']);self.assertEqual(result['configDifferences'][0]['field'],'MacAddress');self.assertEqual(result['negativeCandidateStopsProvenInRetainedJournal'],['ingestion','udp']);self.assertEqual(result['recordedCounts'],self.journal['counts']);self.assertFalse(result['currentRuntimeStateObserved']);self.assertFalse(result['continuationAuthorized']);self.assertNotIn('MUST_NEVER_PRINT',r.encoded(result).decode());self.assertTrue((self.root/r.CHILD/'private-evidence.json').exists())
        with self.assertRaisesRegex(r.Stop,'SCOPE_CONSUMED'):self.read()
    def test_partial_or_absent_quarantine_is_reported_without_inventing_cleanup(self):
        for q in(None,{'state':'CLAIMED','candidates':{}}):
            with self.subTest(q=q):
                self.journal['quarantine']=q;self.write(self.root/'recovery.json',self.journal,0o600);result=self.read();self.assertEqual(result['negativeCandidateStopsProvenInRetainedJournal'],[]);self.assertEqual(result['negativeJournalState'],None if q is None else'CLAIMED');self.remove_child()
    def test_extra_claim_or_new_mcp_blocks_wrong_checkpoint(self):
        self.journal['effects'].append({'stage':'RENAME_OLD_MCP','state':'CLAIMED'});self.write(self.root/'recovery.json',self.journal,0o600)
        with self.assertRaisesRegex(r.Stop,'NO_RENAME'):self.read()
    def test_counter_reset_is_rejected(self):
        self.journal['counts']['serviceCredentialFileReads']=0;self.write(self.root/'recovery.json',self.journal,0o600)
        with self.assertRaisesRegex(r.Stop,'CUMULATIVE_COUNTERS'):self.read()
    def test_review_authority_or_source_hash_drift_rejected(self):
        for p in(self.root/'review.json',self.root/'authority/authority.json',self.code/'ports.py'):
            with self.subTest(path=p):
                old=p.read_bytes();self.write(p,{'changed':True})
                with self.assertRaisesRegex(r.Stop,'EXACT_RETAINED_HASH'):self.read()
                p.chmod(0o600);p.write_bytes(old);p.chmod(0o400);self.remove_child()
    def test_symlink_hardlink_and_writable_custody_rejected(self):
        p=self.root/'engine-response-0002.json';other=self.base/'moved';p.rename(other);p.symlink_to(other)
        with self.assertRaises(OSError):self.read()
        p.unlink();os.link(other,p);self.remove_child()
        with self.assertRaisesRegex(r.Stop,'PRIVATE_RETAINED_FILE'):self.read()
        p.unlink();other.rename(p);p.chmod(0o644);self.remove_child()
        with self.assertRaisesRegex(r.Stop,'PRIVATE_RETAINED_FILE'):self.read()
    def test_unknown_quarantine_status_does_not_disclose_private_values(self):
        self.write(self.root/'quarantine-result.json',{'status':'PRIVATE_VALUE'});result=self.read();self.assertEqual(result['negativeMarkers']['quarantine-result.json']['status'],'UNKNOWN_RETAINED_STATUS');self.assertNotIn('PRIVATE_VALUE',r.encoded(result).decode())
    def test_journal_mutation_between_reads_blocks_snapshot(self):
        outer=self
        class Racing(r.Reader):
            def read(self,path,expected=None):
                if path==outer.root/'recovery.json'and expected is not None:
                    outer.journal['counts']['engineGets']+=1;outer.write(path,outer.journal,0o600)
                return super().read(path,expected)
        with self.assertRaisesRegex(r.Stop,'EXACT_RETAINED_HASH'):self.read(Racing())
    def test_historical_original_binding_drift_not_normalized(self):
        bad=copy.deepcopy(self.before);bad['Config']['Hostname']='changed'
        with self.assertRaisesRegex(r.Stop,'ORIGINAL_MCP_CAPTURE_BINDING'):r.compare(bad,self.after,self.binding)
if __name__=='__main__':unittest.main()
