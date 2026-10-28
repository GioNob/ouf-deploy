import copy,importlib.util,json,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
def module(name,path):
    s=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
m=module('owner_inputs','scripts/capture-managed-file-owner-inputs-20261028.py')
b=module('owner_inputs_builder','tools/build_managed_file_owner_inputs.py')
old=module('old_input_fixture','tests/test_managed_profile_ths_scopes.py')

def fixture():
    _,_,_,_,cohort,observations,generations=old.fixture();case=copy.deepcopy(m.CASE)
    case.update(nativeBindingHash=m.digest(m.stable_binding(observations[cohort['onboarding']['containerId']])),nativeImageId=observations[cohort['onboarding']['containerId']]['Image'])
    proposal={'existingApplications':copy.deepcopy(cohort),'boundDatabaseProfile':{'postgresRuntimeBinding':{'containerId':cohort['peer-0']['containerId']}},'engineBinding':{'peerCredentials':[77,0,0]}}
    proposal['existingApplications']['onboarding']['containerId']='%064x'%90
    stages=['fixture-stage-'+str(i)for i in range(15)]
    review={'schema':'ouf.ths-owner-request-update-review.v1','executionRoot':case['installedRoot'],'bootId':'fixture-boot','stages':stages,'nativePlan':{'proposal':proposal}}
    case['frozenPlanHash']=m.digest(proposal);review['frozenPlanHash']=case['frozenPlanHash'];case['reviewHash']=m.digest(review)
    result={'schema':'ouf.ths-owner-request-update-result.v1','status':'THS_OWNER_REQUEST_UPDATE_INSTALLED_E2E_NOT_ACCEPTED','complete':True,'scopePatchApplied':True,'componentReadinessProven':True,
        'reviewHash':case['reviewHash'],'authorityHash':case['authorityHash'],'executionInputsHash':case['executionInputsHash'],'nativeBindingHash':case['nativeBindingHash'],'nativeImageId':case['nativeImageId'],
        'generation':generations['onboarding'],'humanBudgetsGranted':0,'resumes':0}
    case['resultHash']=m.digest(result)
    journal={'schema':'ouf.managed-csv-control-update-journal.v1','state':'COMPLETE','reviewHash':case['reviewHash'],'authorityHash':case['authorityHash'],'quarantine':None,
        'automaticReplayAllowed':False,'budgetReset':False,'nextStage':15,'candidates':{'onboarding':{'id':cohort['onboarding']['containerId'],'configurationVerified':True,'readinessProven':True,'generation':generations['onboarding']}},
        'effects':[{'stage':s,'state':'APPLIED','intentHash':m.digest({'reviewHash':case['reviewHash'],'stage':s})}for s in stages]}
    retained=json.loads((ROOT/'evidence/managed-file-ownership-read-target-20261028.json').read_bytes())['result'];case['ownerReadHash']=m.digest(retained)
    return case,review,result,journal,retained,cohort,observations,generations

class CaptureTests(unittest.TestCase):
    def run_capture(self,change=None):
        case,review,result,journal,retained,cohort,observed,generations=fixture()
        if change:change(case,review,result,journal,retained,observed)
        class Cap:
            root=Path('/synthetic-new-scope');seals={};maximums={'engineGets':27,'privateMetadataReads':4}
            def __init__(s):s.counts={'privateMetadataReads':0,'engineGets':0,'bytes':0};s.output={}
            def private(s,path,expected=None):
                s.counts['privateMetadataReads']+=1
                return retained if str(path.parent)==case['ownerReadRoot']else {'review.json':review,'result.json':result,'recovery.json':journal}[path.name]
            def put(s,name,v):s.output[name]=v
        class Engine:
            def __init__(s,c,b,ids):s.c=c
            def get(s,path):
                s.c.counts['engineGets']+=1
                return {'ServerVersion':'29.8.1'}if path=='/v1.44/info'else copy.deepcopy(observed[path.split('/')[-2]])
        class Boot:
            def read_text(s):return 'fixture-boot'
        cap=Cap();pins={v['pid']:v for v in generations.values()};pins.update({1:{'pid':1},77:{'pid':77}})
        out=m.capture_inputs(cap,case,engine_factory=Engine,pin=lambda pid:pins[pid],boot_path=Boot());return out,cap
    def test_reproducible_sealed_source_has_no_sql_execution_or_auth_port(self):
        raw=(ROOT/'scripts/capture-managed-file-owner-inputs-20261028.py').read_text();self.assertEqual(raw,b.build())
        self.assertNotIn('import subprocess',raw);self.assertNotIn('def query(',raw);self.assertNotIn('Popen',raw);self.assertNotIn('urlopen',raw)
    def test_four_metadata_and_27_gets_preserve_retained_read_accounting_without_fresh_job_claim(self):
        out,c=self.run_capture();self.assertEqual(c.counts['privateMetadataReads'],4);self.assertEqual(c.counts['engineGets'],27)
        self.assertEqual(out['captureAccounting']['cumulativeCounts'],{'bytes':573839,'privateMetadataReads':7,'engineGets':32,'sqlSessions':1})
        self.assertFalse(out['currentJobOrBudgetStateObserved']);self.assertEqual(out['retainedJobObservation']['cumulativeAttempts'],5)
        self.assertFalse(out['runtimeAuthorityIssued']);self.assertEqual(len(c.output['inputs.json']['currentObservations']),13)
    def test_consumed_ownership_read_must_be_exact_success_and_zero_effects(self):
        for key,value in [('complete',False),('humanBudgetsGranted',1),('browserIdentityVerified',True),('counts',{})]:
            def mutate(case,review,result,journal,retained,observed):retained[key]=value
            with self.subTest(key=key),self.assertRaises(m.Stop):self.run_capture(mutate)
    def test_ambiguous_successor_cannot_adopt_predecessor_authority(self):
        def mutate(case,review,result,journal,retained,observed):journal['effects'][0]['state']='CLAIMED'
        with self.assertRaises(m.Stop):self.run_capture(mutate)
    def test_changed_peer_or_onboarding_configuration_is_denied(self):
        for role in ('onboarding','peer-0'):
            def mutate(case,review,result,journal,retained,observed):
                v=next(v for v in observed.values()if v['Name']=='/'+role);v['Config']['Env'].append('DRIFT=1')
            with self.subTest(role=role),self.assertRaises(m.Stop):self.run_capture(mutate)
    def test_private_environment_stays_out_of_public_result(self):
        def mutate(case,review,result,journal,retained,observed):
            v=next(v for v in observed.values()if v['Name']=='/peer-0');v['Config']['Env'].append('PRIVATE_CREDENTIAL=fixture-value')
            review['nativePlan']['proposal']['existingApplications']['peer-0']=m.stable_binding(v)
            case['frozenPlanHash']=m.digest(review['nativePlan']['proposal']);review['frozenPlanHash']=case['frozenPlanHash'];case['reviewHash']=m.digest(review)
            result['reviewHash']=case['reviewHash'];case['resultHash']=m.digest(result);journal['reviewHash']=case['reviewHash']
            for e in journal['effects']:e['intentHash']=m.digest({'reviewHash':case['reviewHash'],'stage':e['stage']})
        out,c=self.run_capture(mutate);self.assertNotIn('fixture-value',json.dumps(out));self.assertIn('fixture-value',json.dumps(c.output['inputs.json']))
    def test_no_tty_stops_before_any_scope_or_engine(self):
        flags=type('Flags',(),{'isolated':1,'no_site':1})();account=type('User',(),{'pw_uid':1001})()
        with patch.object(m.sys,'argv',['capture']),patch.object(m.sys,'flags',flags),patch.object(m.sys,'dont_write_bytecode',True),patch.object(m.os,'geteuid',return_value=0),patch.object(m.os,'getegid',return_value=0),patch.object(m.pwd,'getpwnam',return_value=account),patch.dict(m.os.environ,{'SUDO_UID':'1001'}),patch.object(m.sys.stdin,'isatty',return_value=False),patch.object(m,'Capture')as c,patch('builtins.print'):
            self.assertEqual(m.main(),2)
        c.assert_not_called()

if __name__=='__main__':unittest.main()
