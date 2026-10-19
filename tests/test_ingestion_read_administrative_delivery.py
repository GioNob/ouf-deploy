"""Private delivery integrity and explicit governed-session scope boundaries."""
import copy,hashlib,importlib.util,json,os,sys,tempfile,unittest,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.ingestion_read_authorization import authorization as a

def script(name):
    spec=importlib.util.spec_from_file_location('qualified_'+name.replace('-','_'),ROOT/'scripts'/name)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

class PrivateDelivery(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT)));self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.root.chmod(0o700)
        self.boot=script('execute-ingestion-read-authorization.py')
    def test_raw_code_is_read_as_bytes_and_json_helper_preserves_private_input_contract(self):
        p=self.root/'executor.py';p.write_bytes(b'raise AssertionError("must never execute on read")\n');p.chmod(0o600)
        self.assertEqual(self.boot.raw_read(p,expected=hashlib.sha256(p.read_bytes()).hexdigest()),p.read_bytes())
        j=self.root/'row.json';j.write_text('{"attempts":207,"budgetReset":false}');j.chmod(0o600)
        self.assertEqual(self.boot.read(j,65536),{'attempts':207,'budgetReset':False})
    def test_changed_hash_group_readability_hardlink_and_symlink_block_before_decode(self):
        p=self.root/'code';p.write_text('original');p.chmod(0o600);h=hashlib.sha256(p.read_bytes()).hexdigest()
        p.write_text('changed')
        with self.assertRaises(Exception):self.boot.raw_read(p,expected=h)
        p.chmod(0o640)
        with self.assertRaises(Exception):self.boot.raw_read(p)
        p.chmod(0o600);other=self.root/'other';os.link(p,other)
        with self.assertRaises(Exception):self.boot.raw_read(p)
        other.unlink();other.symlink_to(p)
        with self.assertRaises(Exception):self.boot.raw_read(other)
    def test_durable_one_use_claim_cannot_be_overwritten(self):
        prep=script('prepare-ingestion-read-authorization.py')
        prep.write_new(self.root,'claim.json',b'first')
        with self.assertRaises(FileExistsError):prep.write_new(self.root,'claim.json',b'second')
        self.assertEqual((self.root/'claim.json').read_bytes(),b'first')
        with self.assertRaises(Exception):prep.write_new(self.root,'../outside',b'bad')
    def test_tampered_unprivileged_stage_is_rejected(self):
        prep=script('prepare-ingestion-read-authorization.py')
        path=self.root/'stage';path.write_bytes(b'qualified')
        h=hashlib.sha256(path.read_bytes()).hexdigest()
        self.assertEqual(prep.stage_read(path,h),b'qualified')
        path.write_bytes(b'changed')
        with self.assertRaises(Exception):prep.stage_read(path,h)
    def test_bootstrap_diagnostic_never_exposes_uppercase_exception_text(self):
        import subprocess
        path=ROOT/'scripts/execute-ingestion-read-authorization.py'
        harness='import runpy,sys;sys.argv=[sys.argv[1],"PRIVATE_CANARY","bad"];runpy.run_path(sys.argv[1],run_name="__main__")'
        result=subprocess.run([sys.executable,'-I','-B','-S','-c',harness,str(path)],capture_output=True,timeout=15)
        self.assertEqual(result.returncode,2)
        self.assertNotIn(b'PRIVATE_CANARY',result.stdout+result.stderr)
        self.assertEqual(json.loads(result.stdout)['reason'],'PRIVATE_DETAILS_REDACTED')

class GovernedSession(unittest.TestCase):
    def setUp(self):
        self.selection={'issuer':'https://issuer.fixture.invalid','tenant':'fixture','subject':'human-fixture'}
        self.retry={'id':'ouf.chatbot-human-session.finite-test.v2','maximumAttempts':256,
            'maximumElapsedSeconds':7200,'backoffSeconds':[5,15,60,300,900],
            'maximumJitterPercent':20,'automaticBudgetRenewalAllowed':False}
        self.binding={'sessionId':str(uuid.uuid4()),'selectionHash':a.digest(self.selection),**self.selection,
            'clientId':'ouf-human-admin','scopes':['openid','authorization.policy.admin','mcp.connect',
                'authorization.permissions.read','authorization.permissions.propose','authorization.proposal.read','udp.materialization.retry'],
            'tokenPath':'/fixture/human/human-access.jwt','sessionDirectory':'/fixture/human','createdAt':100,'expiresAt':7300,'retryProfile':self.retry}
    def test_existing_test_profile_allowed_only_with_explicit_ingestion_read_profile(self):
        a.validate_session_binding(self.binding,self.selection,profile=a.INGESTION_READ_PROFILE)
        for profile in (None,a.PROFILE,a.REVISION_PROFILE):
            with self.assertRaises(Exception):a.validate_session_binding(self.binding,self.selection,profile=profile)
    def test_wider_budget_scope_identity_or_window_is_rejected(self):
        for change in ({'retryProfile':{**self.retry,'maximumAttempts':257}}, {'scopes':self.binding['scopes']+['other.write']},
                {'subject':'other'},{'expiresAt':7301}):
            with self.subTest(change=change),self.assertRaises(Exception):
                a.validate_session_binding({**self.binding,**change},self.selection,profile=a.INGESTION_READ_PROFILE)
if __name__=='__main__':unittest.main()
