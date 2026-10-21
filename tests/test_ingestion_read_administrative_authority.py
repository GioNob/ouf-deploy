"""Real existing-key Ed25519 issuance; synthetic authenticated HUMAN boundary."""
import copy,json,os,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_cutover_authority_native as crypto
from tools.ingestion_read_authorization import authority as m
from tools.source_revision_update.owner import scope
from tools.chatbot_file_cohort.human_session import HumanSession
from tools.source_revision_update.owner import STAGES,PROFILE,MIGRATION

class Issuance(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.library=m.stdlib_binding()if os.environ.get('OUF_NATIVE_UIDS')=='1'else{'fileHashes':{}}
 def setUp(self):
  if os.environ.get('OUF_NATIVE_UIDS')!='1':
   p=patch.object(m,'stdlib_binding',return_value=self.library);p.start();self.addCleanup(p.stop)
  self.temp=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT)));self.addCleanup(self.temp.cleanup)
  self.root=Path(self.temp.name);self.root.chmod(0o700);self.c=crypto.SignedCutover()
  with patch.object(crypto,'ROOT',self.root):self.c.setUp()
  self.addCleanup(self.c.doCleanups);c=self.c
  self.context=c.root/'ingestion-read-authorization-execution-abcdefgh';self.context.mkdir(mode=0o700)
  policy=json.loads(c.policy.read_bytes())
  for key in policy['keys']:key['expiresAt']=int(time.time())+7200
  c.write(c.policy,m.encoded(policy));policy_binding=c.binding(c.policy)
  profile={'schema':'ouf.semantic-existing-installation-authority-bindings.v1','authorities':c.context,'policyBinding':policy_binding,
   'keyRefs':{'installer':policy['keys'][0]['keyRef'],'attestor':policy['keys'][1]['keyRef']},
   'keyBindings':{'installer':c.binding(c.key),'attestor':{'path':str(c.root/'UNREAD-ATTESTOR.pem'),'sha256':'f'*64}}}
  path=c.root/'existing-profile.json';c.write(path,m.encoded(profile))
  for target,name,value in((m.evidence,'PARENT',c.root),(m.governance,'PROFILE',c.binding(path)),
   (m.governance,'POLICY',policy_binding),(m.governance,'CONTEXT',c.context)):
   p=patch.object(target,name,value);p.start();self.addCleanup(p.stop)
  self.human_dir=c.root/'human';self.human_dir.mkdir(mode=0o700)
  self.human=HumanSession({'issuer':'https://issuer.fixture.invalid','subject':'fixture-human','tenant':'fixture'},
   self.human_dir,self.human_dir/'human-access.jwt',int(time.time())+7200)
  self.hb={**self.human.selection,'sessionId':'fixture-human-session','expiresAt':self.human.expires_at}
  p=patch.object(self.human,'current',return_value=self.hb);p.start();self.addCleanup(p.stop)
  self.closure={'declaration':{'entryModule':'tools.ingestion_read_authorization.entry','requiredPythonFlags':['-I','-B','-S']},
   'executables':{'openssl':c.verifier.openssl_binding},'stdlibHash':m.digest(self.library),'stdlibFileCount':len(self.library['fileHashes'])}
  self.scopes={'chatbotFileAuthorization':{'profile':m.INGESTION_READ_PROFILE,'planHash':'d'*64,
   'basePolicyRef':'fixture:45','basePolicyHash':'e'*64,'descriptorDeltaHash':'f'*64,'roleDeltaHash':m.digest(None),
   'oauthDeltaHash':'b'*64,'preserveExistingGrants':True,'preserveRoleAssignments':True,
   'sessionRevocationAuthorized':False,'tokenIssuanceAuthorized':False,
   'roleConfirmationRequiresOwnerHumanSession':True,'retryPolicy':m.RETRY,'sessionBinding':self.hb},
   'ingestionReadAdministration':m.administrative_scope('d'*64,'fixture-source')}
  self.review=m.compile_action_review('INGESTION_READ_AUTHORIZATION',self.closure,self.scopes,self.hb,self.context,
   {'predecessorHistoryHash':'b'*64,'predecessorIncidentRef':'c'*64},480)
  c.write(self.context/'review.json',m.encoded(self.review))
 def decision(self):
  now=int(time.time());return {'schema':'ouf.semantic-scoped-terminal-decision.v1','reviewHash':m.digest(self.review),
   'approvalRef':'mcp-scoped-'+m.digest(self.review)[:24]+'-'+str(now),'sourceClosureHash':self.review['sourceClosureHash'],
   'humanSessionHash':m.digest(self.hb),'approvedAt':now,'expiresAt':min(now+self.review['maximumElapsedSeconds'],self.review.get('absoluteExpiresAt',now+self.review['maximumElapsedSeconds'])),'decision':'APPROVE_EXACT_FINITE_SCOPED_ACTION','state':'ACTIVE'}
 def test_real_two_installer_role_signatures_and_no_attestor_read(self):
  action=m.issue_action(self.review,self.decision(),self.human)
  self.assertTrue(action.guard('ingestionReadAdministration',self.scopes['ingestionReadAdministration']))
  files=list(self.context.glob('*.json'));self.assertEqual(len(list(self.context.glob('*.DEPLOYMENT_INTENT.json'))),1)
  self.assertEqual(len(list(self.context.glob('*.FINAL_DEPLOYMENT_APPROVAL.json'))),1)
  self.assertFalse((self.c.root/'UNREAD-ATTESTOR.pem').exists())
  with self.assertRaises(Exception):m.issue_action(self.review,self.decision(),self.human)
 def test_wrong_human_changed_review_and_expired_decision_fail_before_key_use(self):
  bad=self.decision();bad['reviewHash']='0'*64
  with patch.object(m.ExistingEd25519Signer,'sign')as signing:
   with self.assertRaises(Exception):m.issue_action(self.review,bad,self.human)
   with patch.object(self.human,'current',return_value={**self.hb,'subject':'other'}):
    with self.assertRaises(Exception):m.issue_action(self.review,self.decision(),self.human)
  signing.assert_not_called()
  self.assertFalse((self.context/'issuance.claim.json').exists())
 def test_scope_widening_unsigned_callbacks_and_human_window_extension_are_denied(self):
  scopes=copy.deepcopy(self.scopes);scopes['databaseRestore']={'allowed':True}
  with self.assertRaises(Exception):m.compile_action_review('INGESTION_READ_AUTHORIZATION',self.closure,scopes,self.hb,self.context,
   {'predecessorHistoryHash':'b'*64,'predecessorIncidentRef':'c'*64},480)
  with self.assertRaises(Exception):m.issue_action(self.review,self.decision(),lambda:self.hb)
  self.human.expires_at=int(time.time())+100
  with self.assertRaises(Exception):m.issue_action(self.review,self.decision(),self.human)
 def test_role_policy_drift_or_changed_review_file_blocks_issue(self):
  old=self.c.policy.read_bytes();self.c.policy.write_bytes(old+b'\n')
  with self.assertRaises(Exception):m.issue_action(self.review,self.decision(),self.human)
  self.c.policy.write_bytes(old)
  self.c.write(self.context/'review.json',m.encoded({**self.review,'unapproved':'change'}))
  with self.assertRaises(Exception):m.issue_action(self.review,self.decision(),self.human)
 def test_legacy_or_widened_authorization_profile_and_distinct_human_are_denied(self):
  for key,value in [('profile','ouf.chatbot-file-authorization.v1'),('tokenIssuanceAuthorized',True),
                    ('preserveExistingGrants',False),('sessionBinding',{**self.hb,'subject':'other'})]:
   changed=copy.deepcopy(self.scopes);changed['chatbotFileAuthorization'][key]=value
   with self.subTest(key=key),self.assertRaises(Exception):
    m.compile_action_review('INGESTION_READ_AUTHORIZATION',self.closure,changed,self.hb,self.context,
     {'predecessorHistoryHash':'b'*64,'predecessorIncidentRef':'c'*64},480)
if __name__=='__main__':unittest.main()

