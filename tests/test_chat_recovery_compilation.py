"""Preparation contract across retained state and exact replacement compilers."""
import copy,sys,tempfile,unittest
from pathlib import Path
from contextlib import ExitStack
from unittest.mock import patch,Mock
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_chat_recovery_plan as fixtures
from tools.chat_recovery_update import preparation as p
from tools.chat_recovery_update.owner import MIGRATION,UpdateDenied
class Compilation(unittest.TestCase):
 def exercise(self,drift=False,database_error=False):
  actual={};saved={};candidates={};case={'candidateSourceCommits':{},'deployedSourceCommits':{}}
  for i,module in enumerate(('udp','mcp','onboarding','postgres')):
   s,a,image,c=fixtures.Replacement().fixture('udp' if module in ('onboarding','postgres') else module)
   a['Id']=str(i+1)*64;a['State'].update(Paused=False,Restarting=False)
   actual[module]=a
   if module in ('udp','mcp'):
    saved[module]={'name':s['name'],'request':s['creationRequest'],'readiness':c['readiness'][module]}
    candidates[module]=image
    case['candidateSourceCommits'][module]='c'*40;case['deployedSourceCommits'][module]='a'*40
  engine={'socketPath':'/fixture/socket','socketBinding':[1,2,3]}
  before={'udp':{'database':'ouf_udp','migrations':[]},'mcp':{'migrations':[]}}
  retained={'schema':'ouf.chat-recovery-private-inputs.v1','readyForExecution':False,
   'runtimeAuthorityIssued':False,'engine':engine,'beforeApplications':{m:p.raw_runtime(actual[m]) for m in ('udp','mcp','onboarding')},
   'databasePlan':{'postgresRuntimeBinding':p.raw_runtime(actual['postgres'])},'databaseFacts':before}
  case.update(preparedPlanBinding={'path':'/fixture/prepared','sha256':'a'*64},
   runnerImageReview={'path':'/fixture/images','sha256':'e'*64},
   completedLinkedUpdate={'path':'/fixture/linked','sha256':'b'*64},
   udpMigrations=[{**MIGRATION,'version':'36'}],mcpMigrations=[],udpApplicationConfigurationSha256='f'*64)
  previous={'gateway':{'beforeRoutes':{},'afterRoutes':{},'transport':{}},'replacements':saved,'unchangedApplications':{}}
  record={'effects':[{'evidence':{'applications':{m:{'runtimeBinding':p.runtime(actual[m])} for m in ('udp','onboarding')}}}]}
  mcp={'replacement':saved['mcp'],'readiness':{'port':8080,'path':'/health/ready'}}
  db=Mock()
  if database_error:db.verify_before.side_effect=ValueError('READBACK_CHANGED')
  if drift:actual['mcp']['State']['Pid']+=1
  ns={'engine_get':lambda engine,kind,id:next(a for a in actual.values() if a['Id']==id)}
  with tempfile.TemporaryDirectory(dir='/root') as temp,ExitStack() as stack:
   context=Path(temp);context.chmod(0o700)
   for name,value in [('protected_review',retained),('completed_plan',({},previous,record)),
      ('completed_mcp',(mcp,{'path':'/fixture/mcp','sha256':'d'*64})),('stage_candidates',candidates),
      ('Engine',Mock()),('Database',db),('verify_history',None)]:
    stack.enter_context(patch.object(p,name,return_value=value))
   admin=stack.enter_context(patch.object(p,'NamespaceAdmin'));admin.return_value.routes.return_value={}
   stack.enter_context(patch.object(p.configuration,'verify',return_value={'verified':True}))
   stack.enter_context(patch.object(p.compiler,'runtime_image_id',return_value='sha256:'+'d'*64))
   stack.enter_context(patch.object(p.compiler,'requested_host_config_matches',return_value=True))
   if drift or database_error:
    with self.assertRaises((UpdateDenied,ValueError)):p.compile_private({'engine':engine},{'executables':{'docker':{}}},case,context,lambda *a:None,ns)
    self.assertFalse((context/'prepared-plan.json').exists())
    if drift:db.verify_before.assert_not_called()
   else:
    result,_,_=p.compile_private({'engine':engine},{'executables':{'docker':{}}},case,context,lambda *a:None,ns)
    db.verify_before.assert_called_once_with()
    self.assertEqual(result['replacements']['mcp']['request']['Env'],actual['mcp']['Config']['Env'])
    self.assertEqual(result['unchangedApplications']['onboarding'],p.runtime(actual['onboarding']))
    self.assertTrue((context/'prepared-plan.json').exists())
    self.assertFalse(result['profilePublicationAllowed'])
 def test_complete_preparation_preserves_configuration(self):self.exercise()
 def test_generation_change_prevents_preparation(self):self.exercise(drift=True)
 def test_fresh_database_readback_failure_never_publishes_plan(self):self.exercise(database_error=True)
if __name__=='__main__':unittest.main()
