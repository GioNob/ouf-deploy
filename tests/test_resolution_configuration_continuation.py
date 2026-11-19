"""Rebind exact pre-authority input; preserve failed refresh and cumulative OAuth."""
import copy,json,os,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_mcp_update_successor_session as fixtures
from tools.semantic_mcp_update import session
from tools.resolution_ths_configuration.entry import retained_preparation,blocked_login_review
from tools.resolution_ths_configuration.owner import digest,encoded
class Continuation(fixtures.Successor):
 def setUp(self):
  super().setUp();self.retained=self.root/'prepared';self.retained.mkdir(mode=0o700);self.next=self.root/'new';self.next.mkdir(mode=0o700)
  self.case={'retainedConfigurationPreparation':{'contextPath':str(self.retained)}}
  self.private={'schema':'fixture-private-review','noCredentials':True}
  self.binding={'path':str(self.retained/'candidate-review.json'),'sha256':digest(self.private)}
  self.plan={'schema':'ouf.resolution-ths-configuration-plan.v1','authorityDirectory':str(self.retained),'beforeRoutes':{'existing':{'id':'existing'}},'routes':{k:{'id':k}for k in('ths-resolution-package-read','ths-resolution-package-confirm','trusted-human-resolution-review')},'replacements':{'onboarding':{'request':{'Image':'sha256:fixture','Env':['unchanged-input']}}},'privateReviewBinding':self.binding,'maximumExecutionSeconds':900,'maximumEffectAttemptsPerStage':1,'maximumGatewayWrites':3,'sameImageOnly':True,'containerLifecycleAllowed':True,**{k:False for k in('automaticReplayAllowed','databaseMigrationsAllowed','grantChangesAllowed','semanticDispatchAllowed','automaticRollbackAllowed','identityDecisionsAllowed')}}
  self.plan['logicalUpdateRef']=digest({'beforeRoutes':digest(self.plan['beforeRoutes']),'routes':self.plan['routes'],'replacement':self.plan['replacements']['onboarding']})
  (self.retained/'prepared-plan.json').write_bytes(encoded(self.plan));(self.retained/'candidate-review.json').write_bytes(encoded(self.private))
 def read(self,path,limit,sha=None):
  raw=Path(path).read_bytes();self.assertLessEqual(len(raw),limit)
  if sha is not None:self.assertEqual(digest(json.loads(raw)),sha)
  return json.loads(raw)
 def current_plan(self):
  plan=copy.deepcopy(self.plan);plan['authorityDirectory']=str(self.next);plan['privateReviewBinding']={'path':str(self.next/'candidate-review.json'),'sha256':digest(self.private)};return plan
 def blocked(self,attempts=94):
  row=self.human._read();row.update(state='BLOCKED',operation='REFRESH',attempts=attempts,reason='HUMAN_OAUTH_REVOKED_OR_PERMANENT_OR_UNKNOWN');self.human.journal.record.write_bytes(session.encoded(row));return row
 def test_reuse_preserves_old_files_and_exact_intent_with_new_authority_directory_only(self):
  before={p.name:p.read_bytes()for p in self.retained.iterdir()};plan,prior_hash=retained_preparation(self.case,self.next,self.read,self.current_plan(),self.private)
  self.assertEqual(plan['logicalUpdateRef'],self.plan['logicalUpdateRef']);self.assertEqual(plan['privateReviewBinding'],self.binding);self.assertEqual(prior_hash,digest(self.plan));self.assertEqual(before,{p.name:p.read_bytes()for p in self.retained.iterdir()})
 def test_changed_input_and_any_authority_or_effect_claim_block_continuation(self):
  changed=self.current_plan();changed['replacements']['onboarding']['request']['Env']=['changed']
  with self.assertRaises(Exception):retained_preparation(self.case,self.next,self.read,changed,self.private)
  for name in('authority.json','review.json','decision.json','issuance.claim.json','recovery.json'):
   path=self.retained/name;path.write_text('{}')
   with self.assertRaises(Exception):retained_preparation(self.case,self.next,self.read,self.current_plan(),self.private)
   path.unlink()
  claim=self.root/('resolution-config-update-'+self.plan['logicalUpdateRef']+'.claim.json');claim.write_text('{}')
  with self.assertRaises(Exception):retained_preparation(self.case,self.next,self.read,self.current_plan(),self.private)
 def test_received_refresh_failure_opens_only_fresh_device_window_after_explicit_consent(self):
  self.blocked();before=self.human.journal.record.read_bytes()
  with patch.object(self.human,'_http',side_effect=AssertionError('NO_OLD_REFRESH_REPLAY')):
   review=blocked_login_review(self.human,self.case,self.next,self.read,'a'*64,'b'*64)
   self.assertEqual(review['priorOAuthAttempts'],94);self.assertEqual(review['maximumRemainingOAuthAttempts'],34)
   following=session.open_approved_login(self.human,review,self.decision(review))
  self.assertEqual(following._read()['attempts'],94);self.assertEqual(following._read()['state'],'NEW');self.assertFalse(following.token_path.exists());self.assertEqual(before,self.human.journal.record.read_bytes())
  with self.assertRaises(Exception):session.open_approved_login(self.human,review,self.decision(review))
 def test_unknown_interrupted_exhausted_refresh_never_opens_successor(self):
  initial=self.blocked()
  for change in({'reason':'HUMAN_OAUTH_OUTCOME_UNPROVEN'},{'state':'REQUESTING'},{'operation':'USERINFO'},{'attempts':128}):
   self.human.journal.record.write_bytes(session.encoded({**initial,**change}))
   with self.assertRaises(Exception):blocked_login_review(self.human,self.case,self.next,self.read,'a'*64,'b'*64)
if __name__=='__main__':unittest.main()
