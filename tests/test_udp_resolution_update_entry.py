import copy,sys,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.udp_resolution_update import entry
from tools.resolution_ths_configuration.owner import STAGES
from tools.chatbot_file_cohort.human_session import HumanSessionPaused

class Preparation(unittest.TestCase):
 def fixture(self):
  context=Path('/fixture/completed');case={'rolloutContext':str(context),'rolloutSourceCommit':'a'*40};plan={'retained':'fixture'}
  selected={'planHash':entry.digest(plan),'stages':list(STAGES)}
  closure={'declaration':{'sourceCommit':'a'*40}}
  review={'kind':'RESOLUTION_THS_CONFIGURATION','authorityDirectory':str(context),'sourceClosure':closure,'sourceClosureHash':entry.digest(closure),'scopes':{'resolutionConfigurationUpdate':selected}}
  issued={'sourceClosureHash':entry.digest(closure),'resolutionConfigurationUpdate':selected}
  record={'version':37,'incidentState':'RECOVERED','scopeHash':entry.digest(selected),'authorityHash':entry.digest(issued),'nextStage':13,'effects':[{'stage':s,'state':'APPLIED','intentHash':entry.digest({'planHash':selected['planHash'],'stage':s})}for s in STAGES]}
  records={'review.json':review,'execution-plan.json':plan,'recovery.json':record,'authority.json':issued}
  return case,records,lambda path,maximum:copy.deepcopy(records[Path(path).name])
 def test_completed_predecessor_is_bound_to_plan_scope_authority_and_order(self):
  case,records,read=self.fixture();self.assertEqual(entry.predecessor(case,read)[0],records['review.json'])
  for what in('scope','authority','order','intent','source'):
   case,records,read=self.fixture()
   if what=='scope':records['execution-plan.json']['changed']=True
   if what=='authority':records['authority.json']['changed']=True
   if what=='order':records['recovery.json']['effects'][1]['stage']='FOREIGN'
   if what=='intent':records['recovery.json']['effects'][1]['intentHash']='f'*64
   if what=='source':case['rolloutSourceCommit']='b'*40
   with self.assertRaises(Exception):entry.predecessor(case,read)
 def test_received_permanent_refresh_failure_requires_separate_login_consent(self):
  human=SimpleNamespace(expires_at=10**12);row={'state':'READY'};human._read=lambda:row
  def refresh():row['state']='BLOCKED';raise HumanSessionPaused('HUMAN_OAUTH_REVOKED_OR_PERMANENT_OR_UNKNOWN')
  human.refresh_if_due=refresh;successor=SimpleNamespace(login=lambda emit:None)
  login={'priorOAuthAttempts':81,'maximumRemainingOAuthAttempts':47}
  with patch.object(entry.session,'blocked_refresh_login_review',return_value=login)as review,patch.object(entry.authority,'terminal_consent',return_value={'explicit':'decision'})as consent,patch.object(entry.session,'open_approved_login',return_value=successor)as opened,patch.object(entry,'publish_json'):
   self.assertIs(entry.authenticate(human,{}, {},{},Path('/fixture'),lambda x:None),successor)
   review.assert_called_once();consent.assert_called_once();opened.assert_called_once_with(human,login,{'explicit':'decision'})
 def test_ambiguous_or_transient_refresh_never_opens_a_successor_login(self):
  for reason in('HUMAN_OAUTH_TRANSPORT_OUTCOME_UNPROVEN','HUMAN_OAUTH_TEMPORARILY_UNAVAILABLE'):
   human=SimpleNamespace(expires_at=10**12,_read=lambda:{'state':'READY'},refresh_if_due=lambda:(_ for _ in()).throw(HumanSessionPaused(reason)))
   with patch.object(entry.session,'open_approved_login')as opened:
    with self.assertRaises(HumanSessionPaused):entry.authenticate(human,{}, {},{},Path('/fixture'),lambda x:None)
    opened.assert_not_called()
if __name__=='__main__':unittest.main()
