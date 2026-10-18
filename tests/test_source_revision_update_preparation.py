"""Full preparation wiring with real retained replacement compilation.

External Engine, root files and SQL are explicit fixture boundaries. No authority,
login, backup, image import or Gateway mutation is available in this harness.
"""
import copy,sys,tempfile,unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_source_revision_update_plan as fixtures
import test_source_revision_update_owner as owner_fixtures
from tools.source_revision_update import preparation as p
from tools.source_revision_update.owner import MIGRATION,UpdateDenied

class Preparation(unittest.TestCase):
 def exercise(self,failure=None):
  actual={};saved={};candidates={};selected={'currentApplications':{},'candidateSourceCommits':{},'completedUpdate':{}}
  for i,module in enumerate(('onboarding','mcp','udp','ingestion','postgres')):
   s,a,image,c=fixtures.Replacement().fixture('mcp' if module=='mcp' else 'onboarding')
   a['Id']=str(i+1)*64;a['State'].update(Paused=False,Restarting=False)
   actual[module]=a
   if module in ('onboarding','mcp'):
    saved[module]={'name':s['name'],'request':s['creationRequest'],'restoreRestartPolicy':s['restoreRestartPolicy'],'readiness':c['readiness'][module]}
    candidates[module]=image
    selected['currentApplications'][module]={'sourceCommit':'a'*40};selected['candidateSourceCommits'][module]='c'*40
  candidates['onboarding']['migrations']=[{**MIGRATION,'version':'34'}]
  engine={'socketPath':'/fixture/socket','socketBinding':[1,2,3]};gateway=owner_fixtures.gateway_fixture()
  projection={'installation':'fixture'};projection_raw=p.shared.encoded(projection)
  private={'schema':'ouf.source-revision-private-inputs.v1','readyForExecution':False,'runtimeAuthorityIssued':False,
   'packageRootCustodyProven':True,'selection':selected,'engine':engine,
   'beforeApplications':copy.deepcopy({m:actual[m]for m in ('onboarding','mcp','udp')}),
   'databasePlan':{'postgresRuntimeBinding':p.raw_runtime(actual['postgres']),
                   'modules':[{'module':'onboarding','database':'ouf_onboarding'}]},
   'databaseFacts':{'onboarding':{},'mcp':{},'udp':{}},'retainedReplacements':saved,'candidates':candidates,
   'unchangedApplications':{m:p.runtime(actual[m])for m in ('onboarding','ingestion')},
   'gateway':{'transport':{},'beforeRoutes':{},'projectionRaw':projection_raw.decode(),'projectionBinding':{'path':'/fixture/projection'}}}
  case={'preparedPlanBinding':{'path':'/fixture/prepared','sha256':'a'*64},'postgresNativePort':5432,
        'onboardingApplicationConfigurationSha256':'b'*64}
  db=Mock();admin=Mock();admin.routes.return_value={}
  if failure=='generation':actual['mcp']['State']['Pid']+=1
  if failure=='gateway':admin.routes.return_value={'foreign':{}}
  if failure=='sql':db.verify_before.side_effect=ValueError('DATABASE_CHANGED')
  if failure=='migration':candidates['onboarding']['migrations'][-1]['checksum']+=1
  if failure=='flyway':flyway_error=UpdateDenied('NATIVE_FLYWAY_CONFIGURATION_UNPROVEN')
  else:flyway_error=None
  with tempfile.TemporaryDirectory(dir='/root')as temp,ExitStack()as stack:
   context=Path(temp);context.chmod(0o700)
   for target,name,value in [(p,'Engine',Mock()),(p,'NamespaceAdmin',admin),(p,'Database',db),
      (p,'compiler_inputs',(context,{}, {},object(),{})),(p,'retained_metadata',[{'path':'/fixture/policy','sha256':'c'*64}]),
      (p,'completed_plan',({}, {}, {})),(p,'private_config',(projection_raw,{'path':'/fixture/projection'})),
      (p,'private_file',{}),(p.compiler,'runtime_image_id','sha256:'+'d'*64),
      (p.gateway,'compile_routes',gateway)]:
    stack.enter_context(patch.object(target,name,return_value=value))
   verifier=stack.enter_context(patch.object(p.configuration,'verify',return_value={'verified':True},side_effect=flyway_error))
   ns={'engine_get':lambda engine,kind,id:next(a for a in actual.values()if a['Id']==id)}
   if failure:
    with self.assertRaises((ValueError,UpdateDenied)):
     p.compile_private({'engine':engine},{'executables':{'docker':{}}},case,context,lambda *a:private,ns)
    self.assertFalse((context/'prepared-plan.json').exists())
    if failure in ('generation','gateway'):verifier.assert_not_called();db.verify_before.assert_not_called()
   else:
    plan,_,_=p.compile_private({'engine':engine},{'executables':{'docker':{}}},case,context,lambda *a:private,ns)
    db.verify_before.assert_called_once_with()
    self.assertEqual(plan['unchangedApplications'],{m:p.runtime(actual[m])for m in ('udp','ingestion')})
    self.assertEqual(plan['replacements']['onboarding']['request']['Env'],actual['onboarding']['Config']['Env'])
    self.assertEqual(plan['retainedMcpMetadata'],[{'path':'/fixture/policy','sha256':'c'*64}])
    self.assertFalse(plan['profilePublicationAllowed']);self.assertFalse(plan['jobRetriesAllowed'])
    self.assertTrue((context/'prepared-plan.json').exists())
 def test_exact_completed_preparation_is_consumed_without_new_authority(self):self.exercise()
 def test_changed_generation_blocks_before_flyway_and_sql(self):self.exercise('generation')
 def test_changed_routes_block_before_flyway_and_sql(self):self.exercise('gateway')
 def test_wrong_pending_migration_never_publishes_plan(self):self.exercise('migration')
 def test_unknown_flyway_override_never_publishes_plan(self):self.exercise('flyway')
 def test_fresh_database_failure_never_publishes_plan(self):self.exercise('sql')

if __name__=='__main__':unittest.main()
