import copy,importlib.util,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('history',ROOT/'scripts/read-source-revision-human-history-20261019.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
CONSTANTS=m.profile_constants((ROOT/'tools/csv_materialization_recovery/human_session.py').read_bytes())
def fixture(directory):
 selection={'issuer':'https://fixture.invalid/realms/test','subject':'PRIVATE_SUBJECT','tenant':'PRIVATE_TENANT','other':'retained'}
 review={'schema':'ouf.human-explicit-test-continuation-review.v3','predecessorMaximumCumulativeOAuthAttempts':256,'priorOAuthAttempts':150,'freshIssuerAuthenticationRequired':True,'failedRefreshReplayAllowed':False,'budgetReset':False,'purpose':'CONFIGURATION_AND_VALIDATION','maximumCumulativeOAuthAttempts':256}
 decision={'reviewHash':m.digest(review),'approvedAt':1000,'expiresAt':8200}
 hb={'selectionHash':m.digest(selection),'issuer':selection['issuer'],'subject':selection['subject'],'tenant':selection['tenant'],'clientId':CONSTANTS['CLIENT'],'scopes':CONSTANTS['SCOPES'],'tokenPath':str(directory/'human-access.jwt'),'sessionDirectory':str(directory),'expiresAt':8200,'createdAt':1000,'retryProfile':CONSTANTS['PROFILE']}
 row={'schema':'ouf.chatbot-human-session.private.v1','binding':hb,'budgetReset':False,'bootId':'old-boot','governedWindowRenewal':{'review':review,'decision':decision},'attempts':151,'state':'READY','lastObservedAt':8000,'monotonicDeadline':9999999,'accessToken':'PRIVATE_TOKEN_CANARY','refreshToken':'PRIVATE_REFRESH_CANARY'}
 return selection,hb,row
class Predicates(unittest.TestCase):
 def test_boot_drift_is_isolated_without_rebasing_or_exposing_identity(self):
  selection,hb,row=fixture(Path('/fixture/session'));before=copy.deepcopy(row);result=m.predicates(row,hb,selection,CONSTANTS,'new-boot',9000)
  self.assertEqual(result['failedChecks'],['currentBootMatches']);self.assertTrue(result['expiredByWallClock']);self.assertFalse(result['monotonicComparisonMeaningful']);self.assertFalse(result['runtimeHistoryAccepted']);self.assertEqual(row,before)
  text=json.dumps(result);self.assertNotIn('PRIVATE_',text);self.assertNotIn('old-boot',text)
 def test_report_matches_native_binding_budget_guard_for_individual_drift(self):
  import test_source_revision_update_configuration
  from tools.csv_materialization_recovery.human_session import HumanSession
  fields=['selectionHash','issuer','subject','tenant','clientId','scopes','tokenPath','sessionDirectory','expiresAt','retryProfile']
  for field in (None,*fields,'bootId','budgetReset'):
   selection,hb,row=fixture(Path('/fixture/session'));hb=copy.deepcopy(hb)
   if field in fields:row['binding'][field]='wrong'
   elif field=='bootId':row[field]='other'
   elif field=='budgetReset':row[field]=True
   human=HumanSession.__new__(HumanSession);human.selection=selection;human.directory=Path(hb['sessionDirectory']);human.token_path=Path(hb['tokenPath']);human.expires_at=hb['expiresAt'];human._boot=lambda:'old-boot'
   report=m.predicates(row,hb,selection,CONSTANTS,'old-boot',9000)
   try:human._check_identity_and_budget(row);accepted=True
   except Exception:accepted=False
   with self.subTest(field=field):self.assertEqual(accepted,field is None);self.assertEqual(bool(report['failedChecks']),field is not None)
 def test_renewal_history_and_remaining_budget_are_not_forged(self):
  selection,hb,row=fixture(Path('/fixture/session'));row['attempts']=257;row['governedWindowRenewal']['decision']['reviewHash']='bad'
  result=m.predicates(row,hb,selection,CONSTANTS,'old-boot',9000)
  self.assertFalse(result['checks']['attemptsWithinMaximum']);self.assertFalse(result['renewalChecks']['decisionHashMatchesReview']);self.assertEqual(row['attempts'],257)
 def test_literal_profile_parser_does_not_execute_source(self):
  raw=(ROOT/'tools/csv_materialization_recovery/human_session.py').read_bytes()+b'\nraise RuntimeError("PRIVATE_CANARY")\n'
  self.assertEqual(m.profile_constants(raw),CONSTANTS)
  with self.assertRaises((ValueError,TypeError)):m.profile_constants(b'CLIENT=__import__("os").system("false")')
 def test_duplicate_journal_keys_are_rejected(self):
  with self.assertRaises(ValueError):m.parse(b'{"binding":{},"binding":{}}')
class Files(unittest.TestCase):
 def temporary(self):return tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT.parent)))
 def put(self,path,value):
  path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);path.write_bytes(value if type(value)is bytes else m.encoded(value));path.chmod(0o600)
 def test_successor_chain_reads_nested_historical_sessions_and_preserves_tokens(self):
  with self.temporary()as temp:
   root=Path(temp);directory=root/'incident'/'human';selection,hb,row=fixture(directory);self.put(directory/'recovery.json',row)
   nextdir=directory.parent/'successor';_,next_hb,nextrow=fixture(nextdir);nextrow['attempts']=152;renewal=nextrow['governedWindowRenewal']
   claim={'destination':str(nextdir),'budgetReset':False,'reviewHash':m.digest(renewal['review']),'decisionHash':m.digest(renewal['decision'])};self.put(directory/'successor-window.claim.json',claim);self.put(nextdir/'recovery.json',nextrow)
   before={str(p):p.read_bytes()for p in root.rglob('*')if p.is_file()}
   with patch.object(m,'PREPARED',root/'prepared'):rows,snapshots=m.chain(hb,selection,CONSTANTS,'new-boot',9000,m.read)
   self.assertEqual(len(rows),2);self.assertTrue(rows[0]['successorReceiptLinksMatch']);self.assertFalse(rows[-1]['successorClaimPresent']);self.assertTrue(all(r['journalStableDuringRead']for r in rows));self.assertNotIn('PRIVATE_',json.dumps(rows));self.assertNotIn('journalSha256',json.dumps(rows))
   self.assertEqual(before,{str(p):p.read_bytes()for p in root.rglob('*')if p.is_file()})
 def test_changed_journal_during_final_read_and_broken_successor_fail(self):
  with self.temporary()as temp:
   root=Path(temp);directory=root/'human';selection,hb,row=fixture(directory);self.put(directory/'recovery.json',row)
   def unstable(path,expected=None,maximum=65536):
    if expected:raise ValueError('CHANGED')
    return m.read(path,None,maximum)
   with patch.object(m,'PREPARED',root/'prepared'),self.assertRaises(ValueError):m.chain(hb,selection,CONSTANTS,'new',9000,unstable)
   self.put(directory/'successor-window.claim.json',{'destination':str(directory),'budgetReset':False})
   with patch.object(m,'PREPARED',root/'prepared'),self.assertRaises(ValueError):m.chain(hb,selection,CONSTANTS,'new',9000,m.read)
 def execution(self,root):
  prepared=root/'prepared';stopped=root/'stopped';case={'preparedPlanBinding':{'path':'/fixed/private','sha256':'a'*64}}
  for base in (prepared,stopped):
   base.mkdir(mode=0o700)
   for i in range(7):self.put(base/'gateway-compiler'/('file'+str(i)+'.py'),b'pass\n')
  review={'schema':'ouf.source-revision-candidate-review.v1','preparedPlanBinding':case['preparedPlanBinding'],'runtimeAuthorityIssued':False,'readyForExecution':False};self.put(stopped/'candidate-review.json',review)
  plan={'schema':'ouf.source-revision-native-update-plan.v1','authorityDirectory':str(stopped),'privateReviewBinding':{'path':str(stopped/'candidate-review.json'),'sha256':m.digest(review)},**{k:False for k in('automaticReplayAllowed','manualSqlMigrationAllowed','grantChangesAllowed','semanticDispatchAllowed','automaticRollbackAllowed','identityDecisionsAllowed','profilePublicationAllowed','jobRetriesAllowed')}};self.put(stopped/'prepared-plan.json',plan)
  return prepared,stopped,case
 def test_exact_nine_execution_files_and_refusal_of_unknown_authority_or_sources(self):
  for change in (None,'authority','compiler','emptydir','link'):
   with self.subTest(change=change),self.temporary()as temp:
    prepared,stopped,case=self.execution(Path(temp))
    if change=='authority':self.put(stopped/'authority.json',{})
    if change=='compiler':self.put(stopped/'gateway-compiler/file0.py',b'changed')
    if change=='emptydir':(stopped/'gateway-compiler/unknown').mkdir(mode=0o700)
    if change=='link':(stopped/'gateway-compiler/file0.py').unlink();(stopped/'gateway-compiler/file0.py').symlink_to(stopped/'gateway-compiler/file1.py')
    if change:
     with self.assertRaises(ValueError):m.reconcile_execution(stopped,prepared,{},case)
    else:self.assertEqual(m.reconcile_execution(stopped,prepared,{},case)['contextFiles'],9)
if __name__=='__main__':unittest.main()
