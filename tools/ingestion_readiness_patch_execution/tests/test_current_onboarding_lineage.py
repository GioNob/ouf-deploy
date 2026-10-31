"""Later deployment metadata; all owner/runtime histories are fixtures.

Root files, Unix socket metadata and proc identities are real. No API/SQL or
target deployment qualification is claimed. Previous sealed sources unchanged.
"""
import copy,hashlib,importlib.util,json,os,socket,stat,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[3]if Path(__file__).parent.name=='tests'else Path(__file__).parent
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
oldpath=ROOT/'tools/ingestion_readiness_patch_execution/tests/test_onboarding_engine_metadata.py'
if not oldpath.exists():oldpath=ROOT/'test_onboarding_engine_metadata.py'
old=module('earlier_lineage_fixture_support',oldpath)
c,d,m,r=old.c,old.d,old.m,old.r
script=ROOT/'scripts/read-current-onboarding-source-revision-lineage-20261024.py'
if not script.exists():script=ROOT/'read-current-onboarding-source-revision-lineage-20261024.py'
q=module('current_source_revision_lineage',script)
from tools.ingestion_readiness_patch_execution import runtime_bindings,database_read

def private(path,value):
    raw=m.encoded(value);path.write_bytes(raw);path.chmod(0o400);return m.sha(raw)

def history(owner,engines=None,onb=None,pg=None):
    plan={'schema':'ouf.source-revision-native-update-plan.v1','authorityDirectory':owner,
        'databaseMigration':copy.deepcopy(q.MIGRATION),'replacements':{'onboarding':{'request':{'Labels':{'org.opencontainers.image.revision':q.DEPLOYED_SOURCE}}},'mcp':{}},
        'gateway':{'afterRoutes':{}},'database':{'postgresRuntimeBinding':pg,'before':{'onboarding':{'database':'onboarding_fixture','databaseOid':100,'role':'pgadmin'}}},'engine':engines}
    scope={'planHash':q.digest(plan),'stages':list(q.STAGES),'databaseMigration':copy.deepcopy(q.MIGRATION)}
    preparation={'schema':'ouf.source-revision-postboot-preparation-result.v1','runtimeAuthorityIssued':False,'sourceClosureSha256':'f'*64}
    review={'authorityDirectory':owner,'sourceClosureHash':'f'*64,'scopes':{'sourceRevisionUpdate':scope}}
    authority={'sourceClosureHash':'f'*64,'scopedExecution':{'reviewHash':q.digest(review)}}
    effects=[{'stage':name,'state':'APPLIED','intentHash':q.digest({'planHash':q.digest(plan),'stage':name})}for name in q.STAGES]
    effects[-1]['evidence']={'applications':{'onboarding':{'runtimeBinding':onb},'mcp':{}},'routeMapHash':q.digest({})}
    journal={'schema':'ouf.source-revision-update-journal.v1','budgetReset':False,'scopeHash':q.digest(scope),
        'authorityHash':q.digest(authority),'incidentState':'RECOVERED','version':57,'nextStage':len(effects),'effects':effects,
        'bootId':'fixture'}
    return preparation,plan,review,authority,journal

class Guards(unittest.TestCase):
    def test_exact_deployed_v34_contract_and_complete_owner_history(self):
        self.assertEqual(q.MIGRATION['script'],'V34__source_property_revision.sql')
        self.assertEqual(q.MIGRATION['checksum'],-1996496299);self.assertEqual(len(q.MIGRATION['sha256']),64)
        row=history(q.OWNER);final=q.verify_history(*row,q.digest(row[3]));self.assertIn('onboarding',final['applications'])

    def test_new_budget_v34_or_changed_historical_plan_cannot_replace_deployed_v34(self):
        row=list(history(q.OWNER));row[1]['databaseMigration']['script']='V34__managed_readiness_budget_sessions.sql'
        with self.assertRaises(q.Stop):q.verify_history(*row,q.digest(row[3]))
        row=list(history(q.OWNER));row[1]['databaseMigration']['to']=35
        with self.assertRaises(q.Stop):q.verify_history(*row,q.digest(row[3]))

    def test_partial_recovery_wrong_authority_and_changed_intent_refused(self):
        for change in('partial','authority','intent','stage'):
            row=list(history(q.OWNER));journal=row[-1]
            if change=='partial':journal['effects'][-1]['state']='CLAIMED'
            elif change=='authority':journal['authorityHash']='0'*64
            elif change=='intent':journal['effects'][4]['intentHash']='0'*64
            else:journal['effects'][4]['stage']='WRONG'
            with self.assertRaises(q.Stop):q.verify_history(*row,q.digest(row[3]))

    def test_old_context_or_review_hash_does_not_become_current_authority(self):
        row=list(history('/different/old-owner'))
        with self.assertRaises(q.Stop):q.verify_history(*row,q.digest(row[3]))
        row=list(history(q.OWNER));row[3]['scopedExecution']['reviewHash']='0'*64
        with self.assertRaises(q.Stop):q.verify_history(*row,q.digest(row[3]))

@unittest.skipUnless(os.environ.get('OUF_NATIVE_CURRENT_LINEAGE')=='1','root proc/socket filesystem runner required')
class Native(unittest.TestCase):
    def setUp(self):old.Native.setUp(self)
    def test_full_later_lineage_reads_private_files_and_proc_without_any_old_entry_sql_or_engine(self):
        root=self.root;package=root/'package';package.mkdir(mode=0o700)
        capture=package/'input-preparation-v1';capture.mkdir(mode=0o700)
        owner=root/'later-owner';owner.mkdir(mode=0o700)
        actual={'Image':'sha256:'+'b'*64,'State':{'Pid':os.getpid(),'StartedAt':'fixture','Running':True,'Paused':False,
            'Restarting':False,'Dead':False,'OOMKilled':False,'Error':''},'HostConfig':{},'NetworkSettings':{},'Mounts':[],'RestartCount':0}
        onb={**actual,'Id':'a'*64,'Config':{'Labels':{'org.opencontainers.image.revision':q.DEPLOYED_SOURCE},
            'Env':['OUF_ONB_DB_URL=jdbc:postgresql://private-fixture:5432/onboarding_fixture','OUF_ONB_DB_USER=app_role','PASSWORD=never-print']}}
        pg={**actual,'Id':'b'*64,'Config':{'Env':['POSTGRES_USER=pgadmin']}}
        observations={'onboarding':onb,'postgres':pg};refs={};bindings={};processes={}
        for name,row in observations.items():
            p=capture/(name+'.json');refs[name]={'path':str(p),'sha256':private(p,row)}
            bindings[name]=runtime_bindings.observed(row,runtime_bindings.NATIVE);processes[name]=m.process(row)
        inputs={'schema':'ouf.onboarding-finite-session-private-inputs.v1','kind':'INPUTS_NOT_EXECUTABLE_AUTHORITY',
            'targetApplyAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False,
            'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'runtimeObservations':refs,
            'currentBindings':bindings,'currentProcessIdentities':processes,'engineBinding':self.current,
            'legacyIngestionDatabaseControlProfile':{'identity':{'postgresPort':5432,'database':'wrong_ingestion_fixture'}}}
        ip=capture/'inputs.json';ih=private(ip,inputs)
        private(capture/'complete.json',{'complete':True,'privateInputsHash':ih,'engineGetAttempts':14,'currentCohortStable':True})
        rp=root/'reconciliation.json';rh=private(rp,{'schema':'ouf.onboarding-engine-metadata-private-reconciliation.v1','inputHash':ih,'newSqlAttemptAuthorized':False})
        original=root/'original.json';oh=private(original,{'databasePlan':{'modules':[{'module':'onboarding','schema':'ouf_onboarding',
            'database':'onboarding_fixture','databaseOid':100,'user':'app_role'}],'mcpAuditRoleAdministration':{'admin':'pgadmin'}}})
        prep,plan,review,authority,journal=history(str(owner),self.historical,
            runtime_bindings.observed(onb,runtime_bindings.SORTED),runtime_bindings.observed(pg,runtime_bindings.NATIVE))
        journal['bootId']=inputs['bootId'];prep['currentOriginalPreparationBinding']={'path':str(original),'sha256':oh}
        preparation=root/'preparation.json';ph=private(preparation,prep)
        for name,row in [('execution-plan.json',plan),('review.json',review),('authority.json',authority),('recovery.json',journal)]:private(owner/name,row)
        oldbytes={p:p.read_bytes()for p in root.rglob('*.json')}
        pins={'OWNER':str(owner),'PREPARATION':str(preparation),'PREPARATION_HASH':ph,'ORIGINAL':str(original),'ORIGINAL_HASH':oh,
            'RECON':str(rp),'RECON_HASH':rh}
        with patch.multiple(q,**pins),patch.object(d,'INPUT',str(ip)),patch.object(d,'INPUT_HASH',ih),patch.object(m,'PACKAGE',str(package)),\
             patch.object(m.Engine,'get',side_effect=AssertionError('NO_ENGINE')),\
             patch.object(d,'prepare',side_effect=AssertionError('NO_OLD_ENTRY')),\
             patch.object(c,'prepare',side_effect=AssertionError('NO_OLD_RECONCILIATION')),\
             patch.object(d,'query',side_effect=AssertionError('NO_SQL')),\
             patch.object(database_read,'bounded_read',side_effect=AssertionError('NO_SQL_DISPATCH')),\
             patch.object(subprocess,'Popen',side_effect=AssertionError('NO_SUBPROCESS')),\
             patch.object(socket,'socket',side_effect=AssertionError('NO_CONNECTION')):
            result=q.prepare(c,d,m,r)
            self.assertTrue(result['historicalOnboardingRuntimeMatchesCaptured']);self.assertTrue(result['historicalPostgresRuntimeMatchesCaptured'])
            self.assertTrue(result['capturedOnboardingSourceLabelMatchesDocumentedDeployment'])
            self.assertTrue(result['currentDatabaseEnvMatchesSourceRevisionBinding']);self.assertTrue(result['currentPostgresAdminDeclarationMatchesSourceRevision'])
            self.assertEqual(result['engineConnections'],0);self.assertEqual(result['sqlSessionAttempts'],0)
            self.assertFalse(result['newSqlAttemptAuthorized']);self.assertFalse(result['targetApplyAuthorized']);self.assertTrue(result['oldBudgetImageBlocked'])
            self.assertNotIn('never-print',json.dumps(result));self.assertNotIn('private-fixture',json.dumps(result))
            self.assertFalse(result['priorScopeState']['sqlAttemptMarkerPresent'])
            stored=json.loads((package/q.SCOPE/'lineage.json').read_bytes())
            self.assertEqual(result['privateLineageHash'],q.digest(stored))
            self.assertEqual(stored['proposedOnboardingIdentity']['binding']['database'],'onboarding_fixture')
            self.assertTrue(all(stat.S_IMODE(p.stat().st_mode)==0o400 for p in(package/q.SCOPE).iterdir()))
            with self.assertRaisesRegex(q.Stop,'ALREADY_CLAIMED'):q.prepare(c,d,m,r)
        self.assertEqual(oldbytes,{p:p.read_bytes()for p in oldbytes})
        with self.assertRaises(BlockingIOError):self.server.accept()

if __name__=='__main__':unittest.main()
