import copy, importlib.util, json, unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]


def module(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    loaded=importlib.util.module_from_spec(spec);spec.loader.exec_module(loaded)
    return loaded


m=module('m2_bindings','scripts/read-m2-discovery-bindings-20261029.py')
builder=module('m2_bindings_builder','tools/build_m2_discovery_bindings.py')


def fixture():
    case=copy.deepcopy(m.CASE)
    case.update(installedRoot='/synthetic/consumed-v38',outputRoot='/synthetic/new-binding-scope')
    observations={};generations={};cohort={}
    for i in range(13):
        role='onboarding' if i==0 else 'peer-'+str(i)
        cid=('%064x'%(1000 if i==0 else i+1))
        value={'Id':cid,'Image':'sha256:'+('%064x'%(i+20)),'Name':'/'+role,
            'Config':{'Env':['OUF_SCHEMA_GOV_ENABLED=false','OUF_DISCOVERY_WORKER_ENABLED=false',
                'RETAINED_SECRET=fixture-private-credential'],'Labels':{}},
            'HostConfig':{'RestartPolicy':{'Name':'no','MaximumRetryCount':0}},
            'Mounts':[{'Destination':'/private-fixture','RW':False}],
            'NetworkSettings':{'Networks':{'fixture':{}}},
            'State':{'Pid':100+i,'Running':True,'Paused':False,'Restarting':False,
                'StartedAt':'2026-10-28T00:00:00Z'},'RestartCount':0}
        observations[cid]=value;cohort[role]=m.stable_binding(value)
        generations[role]={'pid':100+i,'startTicks':i+900,'namespaces':{'mnt':[4,i+100],'net':[4,i+200]}}
    candidate_id=cohort['onboarding']['containerId']
    case['nativeImageId']=observations[candidate_id]['Image']
    case['nativeBindingHash']=m.digest(cohort['onboarding'])
    cohort['onboarding']['containerId']='%064x'%1
    proposal={'existingApplications':copy.deepcopy(cohort),'engineBinding':{'peerCredentials':[77,0,0]}}
    case['frozenPlanHash']=m.digest(proposal)
    review={'schema':'ouf.managed-file-owner-v38-update-review.v1','executionRoot':case['installedRoot'],
        'frozenPlanHash':case['frozenPlanHash'],'nativePlan':{'proposal':proposal,'frozenPlanHash':case['frozenPlanHash']},
        'bootId':'fixture-boot','stages':list(m.STAGES),'targetRoles':['onboarding'],
        'automaticReplayAllowed':False,'budgetReset':False}
    case['reviewHash']=m.digest(review)
    result={'schema':'ouf.managed-file-owner-v38-update-result.v1',
        'status':'MANAGED_FILE_OWNER_V38_INSTALLED_E2E_NOT_ACCEPTED','complete':True,
        'componentReadinessProven':True,'contextPath':case['installedRoot'],
        'reviewHash':case['reviewHash'],'authorityHash':case['authorityHash'],
        'executionInputsHash':case['executionInputsHash'],'frozenPlanHash':case['frozenPlanHash'],
        'nativeBindingHash':case['nativeBindingHash'],'nativeImageId':case['nativeImageId'],
        'sourceCommit':case['sourceCommit'],'installedSchemaVersion':38,'unchangedPeers':12,
        'mcpUnchanged':True,'registryWorkerTouched':False,'automaticReplayAllowed':False,
        'budgetReset':False,'generation':generations['onboarding']}
    case['resultHash']=m.digest(result)
    journal={'schema':'ouf.managed-csv-control-update-journal.v1','state':'COMPLETE',
        'reviewHash':case['reviewHash'],'authorityHash':case['authorityHash'],'quarantine':None,
        'nextStage':len(m.STAGES),'automaticReplayAllowed':False,'budgetReset':False,
        'candidates':{'onboarding':{'id':candidate_id,'configurationVerified':True,
            'readinessProven':True,'generation':generations['onboarding']}},
        'effects':[{'stage':stage,'state':'APPLIED','intentHash':m.digest({'reviewHash':case['reviewHash'],'stage':stage})}
            for stage in m.STAGES]}
    return case,review,result,journal,observations,generations


class BindingsTests(unittest.TestCase):
    def run_capture(self,mutate=None,second_read_drift=False):
        case,review,result,journal,observations,generations=fixture()
        if mutate:mutate(case,review,result,journal,observations,generations)
        class Capture:
            def __init__(self):
                self.root=Path(case['outputRoot']);self.seals={}
                self.counts={'privateMetadataReads':0,'engineGets':0,'bytes':0};self.output={}
            def private(self,path,expected=None):
                self.counts['privateMetadataReads']+=1
                return {'review.json':review,'result.json':result,'recovery.json':journal}[path.name]
            def put(self,name,value):self.output[name]=value
        class Engine:
            def __init__(self,c,binding,ids):self.c=c;self.reads={}
            def get(self,path):
                self.c.counts['engineGets']+=1
                if path=='/v1.44/info':return {'ServerVersion':'29.8.1'}
                cid=path.split('/')[-2];self.reads[cid]=self.reads.get(cid,0)+1
                value=copy.deepcopy(observations[cid])
                if second_read_drift and self.reads[cid]==2:value['Config']['Env'].append('DRIFT=1')
                return value
        class Boot:
            def read_text(self):return 'fixture-boot'
        pins={v['pid']:v for v in generations.values()}
        pins.update({1:{'pid':1},77:{'pid':77}})
        cap=Capture()
        self.last_capture=cap
        out=m.capture_bindings(cap,case,engine_factory=Engine,pin=lambda pid:pins[pid],boot_path=Boot())
        return out,cap

    def test_reader_is_reproducible_and_has_only_unix_engine_port(self):
        source=(ROOT/'scripts/read-m2-discovery-bindings-20261029.py').read_text()
        self.assertEqual(source,builder.build())
        for forbidden in ('import subprocess','Popen','urlopen','import urllib','def query('):
            self.assertNotIn(forbidden,source)

    def test_current_cohort_is_read_twice_without_replaying_consumed_authority(self):
        out,c=self.run_capture()
        self.assertEqual(c.counts,{'privateMetadataReads':3,'engineGets':27,'bytes':0})
        self.assertEqual(len(out['bindings']),13)
        for key in ('runtimeAuthorityIssued','targetApplyAuthorized','historicalAuthorityReused',
                    'effectiveProviderConfigurationProven','applicationE2EProven',
                    'currentJobOrBudgetStateRead','databaseAdmissionProven'):
            self.assertFalse(out[key],key)
        self.assertEqual(out['sqlSessions'],0)

    def test_ambiguous_prior_effect_stops_before_engine(self):
        def mutate(case,review,result,journal,obs,pins):journal['effects'][0]['state']='CLAIMED'
        with self.assertRaises(m.Stop):self.run_capture(mutate)
        self.assertEqual(self.last_capture.counts['engineGets'],0)
        self.assertNotIn('inputs.json',self.last_capture.output)

    def test_review_or_result_drift_stops_before_engine(self):
        for selected in ('review','result'):
            def mutate(case,review,result,journal,obs,pins):
                (review if selected=='review' else result)['unexpected']='private'
            with self.subTest(selected=selected),self.assertRaises(m.Stop):self.run_capture(mutate)
            self.assertEqual(self.last_capture.counts['engineGets'],0)

    def test_changed_peer_or_owner_cannot_be_adopted(self):
        for role in ('/onboarding','/peer-1'):
            def mutate(case,review,result,journal,obs,pins):
                next(v for v in obs.values() if v['Name']==role)['Config']['Env'].append('DRIFT=1')
            with self.subTest(role=role),self.assertRaises(m.Stop):self.run_capture(mutate)

    def test_second_read_configuration_drift_never_publishes_inputs(self):
        with self.assertRaises(m.Stop):self.run_capture(second_read_drift=True)
        self.assertNotIn('inputs.json',self.last_capture.output)

    def test_private_metadata_is_not_published_or_reinterpreted_as_effective_flags(self):
        out,c=self.run_capture()
        self.assertNotIn('fixture-private-credential',json.dumps(out))
        self.assertIn('fixture-private-credential',json.dumps(c.output['inputs.json']))
        self.assertTrue(all(row['declaredDiscoveryFlags']['OUF_SCHEMA_GOV_ENABLED']=='FALSE'
            and row['effectiveDiscoveryConfigurationProven'] is False for row in out['bindings']))

    def test_unknown_flag_value_is_redacted_and_spring_overrides_are_not_guessed(self):
        value=next(iter(fixture()[4].values()))
        value['Config']['Env']=['OUF_SCHEMA_GOV_ENABLED=never-print-this',
            'SPRING_APPLICATION_JSON={"secret":"never-print-this","feature":true}']
        summary=m.public_binding(value,{'pid':100})
        self.assertEqual(summary['declaredDiscoveryFlags']['OUF_SCHEMA_GOV_ENABLED'],'UNRECOGNIZED')
        self.assertTrue(summary['springJsonPresent'])
        self.assertFalse(summary['effectiveDiscoveryConfigurationProven'])
        self.assertNotIn('never-print-this',json.dumps(summary))

    def test_duplicate_environment_is_not_silently_resolved(self):
        def mutate(case,review,result,journal,obs,pins):
            next(iter(obs.values()))['Config']['Env'].append('OUF_SCHEMA_GOV_ENABLED=true')
            case['nativeBindingHash']=m.digest(m.stable_binding(next(iter(obs.values()))))
            result['nativeBindingHash']=case['nativeBindingHash'];case['resultHash']=m.digest(result)
        with self.assertRaises(m.Stop):self.run_capture(mutate)

    def test_unknown_repository_label_is_not_published(self):
        value=next(iter(fixture()[4].values()))
        value['Config']['Labels']={'org.opencontainers.image.source':'https://private.invalid/secret'}
        summary=m.public_binding(value,{'pid':100})
        self.assertIsNone(summary['sourceRepositoryDeclaredByContainerLabel'])
        self.assertTrue(summary['sourceRepositoryLabelPresent'])
        self.assertNotIn('private.invalid',json.dumps(summary))

    def test_absent_environment_is_metadata_not_an_effective_configuration_claim(self):
        value=next(iter(fixture()[4].values()))
        value['Config']['Env']=None
        summary=m.public_binding(value,{'pid':100})
        self.assertTrue(all(flag=='ABSENT' for flag in summary['declaredDiscoveryFlags'].values()))
        self.assertFalse(summary['springJsonPresent'])
        self.assertFalse(summary['effectiveDiscoveryConfigurationProven'])

    def test_engine_has_no_listing_or_arbitrary_endpoint(self):
        cap=type('Cap',(),{'counts':{'engineGets':0},'maximums':{'engineGets':27}})()
        engine=m.Engine(cap,{},['a'*64])
        for path in ('/v1.44/containers/json','https://example.invalid/','/v1.44/images/json'):
            with self.subTest(path=path),self.assertRaises(m.Stop):engine.get(path)
        self.assertEqual(cap.counts['engineGets'],0)

    def test_no_tty_stops_before_scope_or_engine(self):
        flags=type('Flags',(),{'isolated':1,'no_site':1})();account=type('Account',(),{'pw_uid':1001})()
        with patch.object(m.sys,'argv',['capture']),patch.object(m.sys,'flags',flags),patch.object(m.sys,'dont_write_bytecode',True),patch.object(m.os,'geteuid',return_value=0),patch.object(m.os,'getegid',return_value=0),patch.object(m.pwd,'getpwnam',return_value=account),patch.dict(m.os.environ,{'SUDO_UID':'1001'}),patch.object(m.sys.stdin,'isatty',return_value=False),patch.object(m,'Capture') as capture,patch('builtins.print'):
            self.assertEqual(m.main(),2)
        capture.assert_not_called()


if __name__=='__main__':unittest.main()

