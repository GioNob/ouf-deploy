"""CI-only real Ed25519/fencing tests; never a production HUMAN authority."""
import copy,hashlib,importlib.util,json,os,re,subprocess,sys,tempfile,time,unittest
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
def module(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
bundle=module('mcp_bundle',BASE/'tools/mcp_diagnostic_update/bundle.py')
@unittest.skipUnless(os.geteuid()==0 and os.environ.get('OUF_MCP_UPDATE_TEST_ROOT'),'explicit root CI fixture required')
class Protocol(unittest.TestCase):
    def setUp(self):
        for name in list(sys.modules):
            if name=='tools'or name.startswith('tools.')or name.startswith('sealed_mcp_update_'):del sys.modules[name]
        self.tmp=tempfile.TemporaryDirectory(dir=os.environ['OUF_MCP_UPDATE_TEST_ROOT']);self.root=Path(self.tmp.name);self.code=self.root/'code';bundle.stage(BASE,self.code)
        self.entry=module('mcp_entry_'+str(time.time_ns()),self.code/'entry.py');self.parts,self.auth,self.sign,self.journal,self.closure,self.runtime=self.entry.components()
        self.core=self.parts['authority'];self.p=self.parts['plan_helper'];self.execution_root=self.root/'execution';self.execution_root.mkdir(mode=0o700)
        self.context={'installationRef':'ci-only-mcp-installation','entityRef':'ci-only-entity','intentIssuerRef':'ci-only-installer','approvalIssuerRef':'ci-only-installer','attestorRef':'ci-only-attestor'}
        self.profile={'keyRefs':{},'keyBindings':{}};keys=[];now=int(time.time())
        for role,issuer,roles in(('installer','ci-only-installer',['DEPLOYMENT_INTENT','FINAL_DEPLOYMENT_APPROVAL']),('attestor','ci-only-attestor',['CREATION_ATTESTATION'])):
            key=self.root/(role+'.key');subprocess.run(['/usr/bin/openssl','genpkey','-algorithm','ED25519','-out',str(key)],check=True,capture_output=True);key.chmod(0o600)
            public=subprocess.check_output(['/usr/bin/openssl','pkey','-in',str(key),'-pubout','-outform','DER'])[-32:]
            self.profile['keyRefs'][role]='ci-only-'+role;self.profile['keyBindings'][role]={'path':str(key),'sha256':hashlib.sha256(key.read_bytes()).hexdigest()}
            keys.append({'keyRef':'ci-only-'+role,'issuerRef':issuer,'roles':roles,'publicKey':public.hex(),'notBefore':now-5,'expiresAt':now+3600,'state':'ACTIVE'})
        self.policy_path=self.root/'policy.json';policy={'schema':'ouf.semantic-deployment-trust-policy.v1','installationRef':self.context['installationRef'],'entityRef':self.context['entityRef'],'keys':keys};self.policy_path.write_bytes(self.core.encoded(policy));self.policy_path.chmod(0o600)
        openssl=Path('/usr/bin/openssl').resolve();version=re.match(rb'OpenSSL ([0-9]+\.[0-9]+\.[0-9]+[a-z]?)\b',subprocess.check_output([str(openssl),'version']))[1].decode()
        self.verification={'trustPolicy':{'path':str(self.policy_path),'sha256':hashlib.sha256(self.policy_path.read_bytes()).hexdigest()},'openssl':{'path':str(openssl),'sha256':hashlib.sha256(openssl.read_bytes()).hexdigest(),'version':version},'context':self.context}
        frozen={'schema':'ouf.synthetic-ci-mcp-plan.v1','effect':'NO_PRODUCTION_RUNTIME_ACCESS'};self.frozen_hash=self.core.digest(frozen);plan={'frozenPlanHash':self.frozen_hash,'proposal':frozen}
        self.review={'schema':'ouf.mcp-diagnostic-update-review.v1','executionRoot':str(self.execution_root),'frozenPlanHash':self.frozen_hash,'nativePlan':plan,'nativePlanHash':self.core.digest(plan),'sourceClosure':self.closure,'sourceClosureHash':self.core.digest(self.closure),'logicalOperationRef':self.core.digest({'ci-only':True}),'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'maximumSeconds':900,'maximums':copy.deepcopy(self.core.LIMITS),'stages':list(self.core.STAGES),'negativeCleanup':{'maximumAdditionalSeconds':30,'startupSeconds':180,'candidateStopOnly':True,'maximumStops':1,'disableCandidateRestartFirst':True},'preflightCounts':{k:0 for k in self.core.LIMITS},'verification':self.verification,'databaseRestoreAuthorized':False,'humanBudgetOrSourceActivationAuthorized':False,'acquisitionCallsAuthorized':False,'gatewayMutationAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}
    def tearDown(self):self.tmp.cleanup()
    def write(self,root,name,value):
        raw=value if isinstance(value,bytes)else self.core.encoded(value);path=Path(root)/name;fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o400)
        with os.fdopen(fd,'wb')as stream:os.fchmod(stream.fileno(),0o400);stream.write(raw);stream.flush();os.fsync(stream.fileno())
    def read(self,path,expected):return self.p.decode(self.p.protected(Path(path),expected))
    def issue(self):return self.core.issue(self.review,self.execution_root,self.profile,{'reviewHash':self.core.digest(self.review),'decision':self.core.DECISION,'approvedAt':int(time.time())},self.write,self.read)
    def ports(self,fail=False):
        outer=self
        class Ports:
            root=outer.execution_root
            ctx=type('C',(),{'counts':{k:0 for k in outer.core.LIMITS}})()
            def guard(self,stage):pass
            def execute(self,stage):
                self.execution.reserve('engineGets')
                if fail:raise outer.core.Stop('AMBIGUOUS_CI_ONLY_EFFECT')
                return {'syntheticClosedEffect':True}
            def final_result(self):return {'complete':True,'syntheticOnly':True}
        return Ports()
    def test_real_dual_signatures_and_no_commit_before_native_attestation(self):
        gate=self.issue();execution=self.core.Execution(gate,self.journal.Journal(self.execution_root),self.ports());execution.initialize();result=execution.run()
        self.assertTrue(result['syntheticOnly']);row=execution.journal.read();self.assertEqual(row['state'],'OPEN');self.assertEqual(len(row['effects']),11);self.assertEqual(row['counts']['engineGets'],11)
        self.assertEqual({k:row['counts'][k]for k in('adminGets','adminPuts','serviceCredentialFileReads')},{'adminGets':0,'adminPuts':0,'serviceCredentialFileReads':0})
    def test_ambiguous_claim_cannot_replay(self):
        gate=self.issue();execution=self.core.Execution(gate,self.journal.Journal(self.execution_root),self.ports(True));execution.initialize()
        with self.assertRaisesRegex(self.core.Stop,'AMBIGUOUS_CI_ONLY_EFFECT'):execution.run()
        before=execution.journal.read()
        with self.assertRaisesRegex(self.core.Stop,'NO_REPLAY'):execution.run()
        self.assertEqual(before,execution.journal.read());self.assertEqual(before['effects'][0]['state'],'CLAIMED')
    def test_live_policy_revocation_blocks_positive_gate(self):
        gate=self.issue();self.policy_path.write_bytes(b'{}')
        with self.assertRaises(Exception):gate.check()
    def test_wrong_or_stale_decision_does_not_read_signing_keys(self):
        for decision in({'reviewHash':'0'*64,'decision':self.core.DECISION,'approvedAt':int(time.time())},{'reviewHash':self.core.digest(self.review),'decision':self.core.DECISION,'approvedAt':int(time.time())-121}):
            with self.assertRaises(self.core.Stop):self.core.issue(self.review,self.execution_root,self.profile,decision,self.write,self.read)
        self.assertFalse((self.execution_root/'authority').exists())
    def test_new_scope_cannot_adopt_old_authority_or_recovery_profile(self):
        for key,value in(('schema','ouf.acquisition-read-native-review.v1'),('recovery',{'adoptedIds':{}}),('continuation',{})):
            review=copy.deepcopy(self.review);review[key]=value
            with self.assertRaises(self.core.Stop):self.core.validate_review(review)
    def test_no_gateway_or_acquisition_budget_widening(self):
        for key in('adminPuts','serviceCredentialFileReads'):
            review=copy.deepcopy(self.review);review['maximums'][key]=1
            with self.assertRaises(self.core.Stop):self.core.validate_review(review)
        review=copy.deepcopy(self.review);review['acquisitionCallsAuthorized']=True
        with self.assertRaises(self.core.Stop):self.core.validate_review(review)
    def test_closed_source_loader_rejects_source_tamper(self):
        path=self.code/'ports.py';path.chmod(0o600);path.write_bytes(path.read_bytes()+b'\n# synthetic tamper\n');path.chmod(0o400)
        with self.assertRaisesRegex(RuntimeError,'SOURCE_DIGEST'):self.entry.components()
    def test_raw_receipt_is_kept_before_invalid_engine_json_guard(self):
        transport=self.parts['transport'];events=[];engine=transport.Engine(self.p,{})
        engine.before=lambda *args:events.append('CLAIM');engine.raw=lambda *args,**kwargs:(201,b'not-json-ambiguous')
        engine.retained=lambda method,path,status,raw:events.append(('RAW_RECEIPT',status,raw))
        with self.assertRaises(ValueError):engine.request('POST','/v1.44/containers/create',{})
        self.assertEqual(events,['CLAIM',('RAW_RECEIPT',201,b'not-json-ambiguous')])
if __name__=='__main__':unittest.main()
