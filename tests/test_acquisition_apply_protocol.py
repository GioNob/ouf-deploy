import hashlib,importlib.util,json,os,re,shutil,subprocess,tempfile,time,unittest
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
def module(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
bundle=module('bundle',BASE/'tools/acquisition_read_native/bundle.py')
@unittest.skipUnless(os.environ.get('OUF_APPLY_ROOT_FIXTURE')=='1','root crypto fixture requires dedicated CI')
class Protocol(unittest.TestCase):
    def setUp(self):
        import sys
        for name in list(sys.modules):
            if name=='tools'or name.startswith('tools.')or name.startswith('sealed_acquisition_'):del sys.modules[name]
        self.tmp=tempfile.TemporaryDirectory(dir='/var/lib');self.root=Path(self.tmp.name);self.code=self.root/'code';bundle.stage(BASE,self.code);self.entry=module('entry_'+str(time.time_ns()),self.code/'apply.py');saved=self.entry.Context;self.entry.Context=lambda parts,auth,sign,journal,closure:(parts,auth,sign,journal,closure)
        try:self.parts,self.auth,self.sign,self.journal,self.closure=self.entry.bootstrap()
        finally:self.entry.Context=saved
        self.core=self.parts['protocol'];self.p=self.parts['plan_helper'];self.execution_root=self.root/'execution';self.execution_root.mkdir(mode=0o700);self.policy_path=self.root/'policy';self.context={'installationRef':'ci-installation','entityRef':'ci-entity','intentIssuerRef':'ci-installer','approvalIssuerRef':'ci-installer','attestorRef':'ci-attestor'};self.profile={'keyBindings':{},'keyRefs':{}}
        keys=[];now=int(time.time())
        for role,issuer,roles in(('installer','ci-installer',['DEPLOYMENT_INTENT','FINAL_DEPLOYMENT_APPROVAL']),('attestor','ci-attestor',['CREATION_ATTESTATION'])):
            key=self.root/(role+'.key');subprocess.run(['/usr/bin/openssl','genpkey','-algorithm','ED25519','-out',str(key)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);key.chmod(0o600);der=subprocess.check_output(['/usr/bin/openssl','pkey','-in',str(key),'-pubout','-outform','DER']);self.profile['keyBindings'][role]={'path':str(key),'sha256':hashlib.sha256(key.read_bytes()).hexdigest()};self.profile['keyRefs'][role]='ci-key-'+role;keys.append({'keyRef':'ci-key-'+role,'issuerRef':issuer,'roles':roles,'publicKey':der[-32:].hex(),'notBefore':now-5,'expiresAt':now+3600,'state':'ACTIVE'})
        policy={'schema':'ouf.semantic-deployment-trust-policy.v1','installationRef':'ci-installation','entityRef':'ci-entity','keys':keys};self.policy_path.write_bytes(self.core.encoded(policy));self.policy_path.chmod(0o600);openssl=Path('/usr/bin/openssl').resolve();version=re.match(rb'OpenSSL ([0-9]+\.[0-9]+\.[0-9]+[a-z]?)\b',subprocess.check_output([str(openssl),'version']))[1].decode();self.verification={'trustPolicy':{'path':str(self.policy_path),'sha256':hashlib.sha256(self.policy_path.read_bytes()).hexdigest()},'openssl':{'path':str(openssl),'sha256':hashlib.sha256(openssl.read_bytes()).hexdigest(),'version':version},'context':self.context}
        plan={'frozenPlanHash':'a'*64};self.review={'schema':'ouf.acquisition-read-native-review.v1','executionRoot':str(self.execution_root),'frozenPlanHash':'a'*64,'nativePlan':plan,'nativePlanHash':self.core.digest(plan),'sourceClosure':self.closure,'sourceClosureHash':self.core.digest(self.closure),'logicalOperationRef':'b'*64,'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'maximumSeconds':900,'maximums':self.core.LIMITS,'stages':list(self.core.STAGES),'negativeCleanup':{'maximumAdditionalSeconds':30,'startupSeconds':180,'candidateStopOnly':True,'maximumStops':3,'disableCandidateRestartFirst':True},'preflightCounts':{k:0 for k in self.core.LIMITS},'verification':self.verification,'databaseRestoreAuthorized':False,'humanBudgetOrSourceActivationAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}
    def tearDown(self):self.tmp.cleanup()
    def write(self,root,name,value):self.p.put(Path(root)/name,value)
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
                if fail:raise outer.core.Stop('AMBIGUOUS_CI_EFFECT')
                return {'closedFixtureEffect':True}
            def final_result(self):return {'complete':True}
        return Ports()
    def test_real_dual_signatures_and_ordered_protocol(self):
        gate=self.issue();ports=self.ports();execution=self.core.Execution(gate,self.journal.Journal(self.execution_root),ports);execution.initialize();self.assertTrue(execution.run()['complete']);row=execution.journal.read();self.assertEqual(row['state'],'COMPLETE');self.assertEqual(len(row['effects']),23);self.assertEqual(row['counts']['engineGets'],23)
    def test_ambiguous_effect_is_durably_claimed_and_never_replayed(self):
        gate=self.issue();ports=self.ports(True);e=self.core.Execution(gate,self.journal.Journal(self.execution_root),ports);e.initialize()
        with self.assertRaisesRegex(self.core.Stop,'AMBIGUOUS_CI_EFFECT'):e.run()
        before=e.journal.read()
        with self.assertRaisesRegex(self.core.Stop,'NO_REPLAY'):e.run()
        self.assertEqual(before,e.journal.read());self.assertEqual(before['effects'][0]['state'],'CLAIMED')
    def test_live_policy_revocation_blocks_positive_execution(self):
        gate=self.issue();self.policy_path.chmod(0o600);self.policy_path.write_bytes(b'{}')
        with self.assertRaises(Exception):gate.check()
    def test_forged_or_stale_terminal_decision_does_not_sign(self):
        for decision in({'reviewHash':'0'*64,'decision':self.core.DECISION,'approvedAt':int(time.time())},{'reviewHash':self.core.digest(self.review),'decision':self.core.DECISION,'approvedAt':int(time.time())-121}):
            with self.assertRaises(self.core.Stop):self.core.issue(self.review,self.execution_root,self.profile,decision,self.write,self.read)
        self.assertFalse((self.execution_root/'authority').exists())
    def test_negative_scope_signature_survives_live_policy_removal(self):
        gate=self.issue();snapshot=self.execution_root/'authority/issued-trust-policy.json';v=self.auth.DetachedAuthenticator({'path':str(snapshot),'sha256':self.verification['trustPolicy']['sha256']},str(snapshot.parent),self.verification['openssl']);self.policy_path.unlink();c=self.context
        for role,key in(('DEPLOYMENT_INTENT','intentIssuerRef'),('FINAL_DEPLOYMENT_APPROVAL','approvalIssuerRef')):self.assertTrue(v(gate.raw,role,c[key],c['installationRef'],c['entityRef']))
    def test_entrypoint_and_namespace_child_fail_closed(self):
        result=subprocess.run([os.sys.executable,str(self.code/'apply.py')],capture_output=True,text=True);self.assertEqual(result.returncode,2);self.assertEqual(json.loads(result.stdout)['reasonCode'],'ONE_ISOLATED_ROOT_ACQUISITION_APPLY_REQUIRED');compile(self.parts['transport'].CHILD,'namespace-child','exec')
if __name__=='__main__':unittest.main()
