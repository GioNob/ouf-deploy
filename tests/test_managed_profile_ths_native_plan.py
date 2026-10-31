"""Real retained compiler functions; fixture history is not target evidence."""
import ast,copy,importlib.util,json,sys,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
m=load('sealed_ths_native_plan',ROOT/'scripts/prepare-managed-profile-ths-native-plan-20261028.py')
old=load('old_ths_plan_fixture',ROOT/'tests/test_managed_profile_ths_scopes.py')

def fixture():
    case,review,result,journal,cohort,observations,generations=old.fixture()
    case.update(iamRoot='/fixture/iam-correction',clientId='ouf-authorization-ths',outputRoot='/fixture/new-native-plan')
    actual=observations[cohort['onboarding']['containerId']]
    actual['Config'].update(User='10003:10003',WorkingDir='/app',Image=actual['Image'],Labels={'retained':'yes'},MacAddress='02:42:ac:12:00:02')
    obj=json.loads(actual['Config']['Env'][1].split('=',1)[1]);obj[m.CLIENT_PROPERTY]=case['clientId']
    obj[m.SCOPE_PROPERTY]=['openid','authorization.policy.admin','ouf.managed-source.file.upload','resolution.issue.read','resolution.match.approve']
    actual['Config']['Env'][1]='SPRING_APPLICATION_JSON='+json.dumps(obj)
    actual['HostConfig']={'NetworkMode':'ouf-local','AutoRemove':False,'Memory':0,'OomKillDisable':None,
        'RestartPolicy':{'Name':'unless-stopped','MaximumRetryCount':0},'PortBindings':{'8080/tcp':[{'HostIp':'127.0.0.1','HostPort':'0'}]}}
    actual['Mounts']=[{'Destination':'/run/secrets/onboarding-ths.yaml','Source':'/fixture/not-read.yaml','RW':False,'Type':'bind'}]
    actual['NetworkSettings']={'Ports':{'8080/tcp':[{'HostIp':'127.0.0.1','HostPort':'18080'}]},
        'Networks':{'ouf-local':{'NetworkID':'a'*64,'IPAddress':'172.18.0.2','GlobalIPv6Address':'',
            'IPAMConfig':{},'MacAddress':'02:42:ac:12:00:02','Aliases':['onboarding','retained-alias']}}}
    case['nativeBindingHashes']['onboarding']=m.digest(m.stable_binding(actual))
    for r in cohort:
        cohort[r]=m.stable_binding(observations[cohort[r]['containerId']])
        review['nativePlan']['proposal']['existingApplications'][r]=copy.deepcopy(cohort[r])
    for n,r in enumerate(('onboarding','mcp'),90):review['nativePlan']['proposal']['existingApplications'][r]['containerId']='%064x'%n
    retained=review['nativePlan']['proposal']
    retained.update(candidateApplicationFacts={'migrations':[{'version':n}for n in range(1,37)],'applicationYamlSha256':'b'*64},
        databaseMigration={'from':36,'to':36,'newMigrations':0},boundDatabaseProfile={'retained':'database'},
        nativeFlywayConfiguration={'retained':'overlay'},readReplacements={'onboarding':{
            'imageAudit':{'nativeIdentity':{'nativeImageId':actual['Image']},'imageConfig':{'Labels':{'org.opencontainers.image.source':'retained'}}},
            'readiness':{'readinessPort':8080,'readinessPath':'/actuator/health/readiness','expectedStatus':200}}})
    case['frozenPlanHash']=m.digest(retained);review['frozenPlanHash']=case['frozenPlanHash'];case['reviewHash']=m.digest(review)
    result.update(reviewHash=case['reviewHash'],frozenPlanHash=case['frozenPlanHash'])
    journal['reviewHash']=case['reviewHash']
    result['ownerProofs']['onboarding']['nativeBindingHash']=case['nativeBindingHashes']['onboarding']
    for effect in journal['effects']:
        effect['intentHash']=m.digest({'reviewHash':case['reviewHash'],'stage':effect['stage']})
        if effect['stage']=='VERIFY_FINAL':effect['proof']['ownerProofs']=copy.deepcopy(result['ownerProofs'])
    receipt=json.loads((ROOT/'evidence/managed-profile-ths-iam-binding-correction-target-20261028.json').read_text())['result']
    receipt['contextPath']=case['iamRoot'];observation=receipt['bindingObservation']
    sys.path.insert(0,str(ROOT))
    try:
        from tools.managed_profile_ths_scopes.bindings import configuration_profile
        profile=configuration_profile(actual,observation,{'registrationId':'ouf-ths','clientId':case['clientId'],
            'issuer':'https://fixture.invalid/realms/ouf','fileSelectionAndPrecedenceVerified':True},installation_ref='fixture-installation')
    finally:sys.path.pop(0)
    case['configurationProfileHash']=m.digest(profile);receipt['configurationProfileHash']=case['configurationProfileHash'];case['iamResultHash']=m.digest(receipt)
    capture={'currentObservations':{r:observations[v['containerId']]for r,v in cohort.items()},'currentProcessPins':generations,
        'currentRootProcessPins':{'pid1':{'pid':1},'engine':{'pid':77}},'bootId':'fixture-boot',
        'engineBinding':retained['engineBinding'],'engineInfo':{'ServerVersion':'29.8.1','DriverStatus':[['driver-type','io.containerd.snapshotter.v1']]}}
    return case,review,result,journal,cohort,observations,generations,receipt,profile,capture

class NativePlanTests(unittest.TestCase):
    def setUp(self):
        self.case,self.review,self.result,self.journal,self.cohort,self.observations,self.generations,self.iam,self.profile,self.capture=fixture()
    def compile(self):return m.compile_native_plan(self.capture,self.review,self.iam,self.profile,self.case)
    def test_same_image_only_exact_scopes_and_twelve_unchanged_peers(self):
        before=copy.deepcopy((self.capture,self.profile,self.review));p=self.compile()
        self.assertEqual(list(p['replacements']),['onboarding']);self.assertEqual(len(p['unchangedApplications']),12)
        self.assertIn('mcp',p['unchangedApplications']);self.assertEqual((self.capture,self.profile,self.review),before)
        request=p['replacements']['onboarding']['request'];actual=self.capture['currentObservations']['onboarding']
        self.assertEqual(request['Image'],actual['Image']);self.assertEqual(request['Env'],self.profile['replacementEnvironment'])
        self.assertEqual(p['scopeRequestDelta']['missingRequestScopes'],list(m.REQUIRED))
        self.assertFalse(p['runtimeAuthorityIssued']);self.assertFalse(p['targetApplyAuthorized']);self.assertFalse(p['databaseAdmissionProven'])
    def test_retained_mac_ip_alias_ports_mounts_resources_and_restart_policy(self):
        p=self.compile();r=p['replacements']['onboarding'];request=r['request'];network=request['NetworkingConfig']['EndpointsConfig']['ouf-local']
        self.assertEqual(network['MacAddress'],'02:42:ac:12:00:02');self.assertEqual(network['IPAMConfig']['IPv4Address'],'172.18.0.2')
        self.assertIn('retained-alias',network['Aliases']);self.assertEqual(request['HostConfig']['PortBindings']['8080/tcp'][0]['HostPort'],'18080')
        self.assertEqual(request['HostConfig']['Memory'],0);self.assertIsNone(request['HostConfig']['OomKillDisable'])
        self.assertEqual(request['HostConfig']['RestartPolicy']['Name'],'no');self.assertEqual(r['restoreRestartPolicy']['Name'],'unless-stopped')
        self.assertEqual(r['oldBinding']['mountsHash'],m.stable_binding(self.capture['currentObservations']['onboarding'])['mountsHash'])
        self.assertNotIn('MacAddress',request);self.assertEqual(r['legacyConfigMacDetachPolicy']['profile'],'LEGACY_CONFIG_MAC_ABSENT_ONLY_AFTER_PROVEN_STOP_AND_DETACH_V1')
    def test_wrong_result_hash_blocks_without_any_iam_or_execution_port(self):
        self.iam['iamMutations']=3
        with self.assertRaisesRegex(m.Stop,'EXACT_SUCCESSFUL_CONSUMED_IAM_CORRECTION_REQUIRED'):self.compile()
    def test_cross_owner_or_changed_current_configuration_blocks_profile(self):
        for field,value in [('ownerContainerId','f'*64),('ownerImageId','sha256:'+'f'*64),('currentConfigurationHash','f'*64)]:
            with self.subTest(field=field):
                profile=copy.deepcopy(self.profile);profile[field]=value;self.case['configurationProfileHash']=m.digest(profile)
                iam=copy.deepcopy(self.iam);iam['configurationProfileHash']=self.case['configurationProfileHash'];self.case['iamResultHash']=m.digest(iam)
                with self.assertRaisesRegex(m.Stop,'EXACT_PRIVATE_CONDITIONAL_SAME_OWNER_PROFILE_REQUIRED'):m.compile_native_plan(self.capture,self.review,iam,profile,self.case)
    def test_tampered_environment_cannot_preserve_unrelated_property_claim(self):
        self.profile['replacementEnvironment'].append('UNREVIEWED=1');self.case['configurationProfileHash']=m.digest(self.profile)
        self.iam['configurationProfileHash']=self.case['configurationProfileHash'];self.case['iamResultHash']=m.digest(self.iam)
        with self.assertRaisesRegex(m.Stop,'EXACT_ADDITIVE_REQUEST_PROFILE_REQUIRED'):self.compile()
    def test_incomplete_iam_eligibility_or_wrong_optional_count_denied(self):
        for key,value in [('bindingAndUnrestrictedEligibilityProven',False),('optionalScopeCount',8)]:
            with self.subTest(key=key):
                iam=copy.deepcopy(self.iam);iam['bindingObservation'][key]=value;case=copy.deepcopy(self.case);case['iamResultHash']=m.digest(iam)
                with self.assertRaisesRegex(m.Stop,'PROVED_RETAINED_IAM_OPTIONAL_BINDINGS_REQUIRED'):m.compile_native_plan(self.capture,self.review,iam,self.profile,case)
    def test_non_native_engine_and_migration_drift_denied(self):
        self.capture['engineInfo']['DriverStatus']=[]
        with self.assertRaisesRegex(m.Stop,'QUALIFIED_NATIVE_ENGINE_PROFILE_REQUIRED'):self.compile()
        self.capture['engineInfo']['DriverStatus']=[['driver-type','io.containerd.snapshotter.v1']]
        self.review['nativePlan']['proposal']['candidateApplicationFacts']['migrations'].pop()
        with self.assertRaisesRegex(m.Stop,'RETAINED_SCHEMA36_FACTS_REQUIRED'):self.compile()
    def test_full_history_still_uses_completed_two_owner_ids_not_old_ones(self):
        cohort=m.completed_history(self.review,self.result,self.journal,self.case)
        self.assertEqual(cohort['onboarding']['containerId'],self.cohort['onboarding']['containerId']);self.assertEqual(len(cohort),13)
    def test_no_tty_stops_before_scope_or_metadata(self):
        flags=type('Flags',(),{'isolated':1,'no_site':1})()
        with patch.object(m.sys,'argv',['plan']),patch.object(m.sys,'flags',flags),patch.object(m.sys,'dont_write_bytecode',True),patch.object(m.os,'geteuid',return_value=0),patch.object(m.os,'getegid',return_value=0),patch.object(m.pwd,'getpwnam',return_value=type('User',(),{'pw_uid':1001})()),patch.dict(m.os.environ,{'SUDO_UID':'1001'}),patch.object(m.sys.stdin,'isatty',return_value=False),patch.object(m,'PlanCapture')as capture,patch('builtins.print')as output:
            self.assertEqual(m.main(),2)
        capture.assert_not_called();self.assertIn('INTERACTIVE_OPERATOR_TERMINAL_REQUIRED',str(output.call_args))
    def test_tracked_planner_and_sealed_definitions_are_equal(self):
        tracked=ast.parse((ROOT/'tools/managed_profile_ths_scopes/native_plan.py').read_text());sealed=ast.parse((ROOT/'scripts/prepare-managed-profile-ths-native-plan-20261028.py').read_text())
        definitions={n.name:ast.dump(n,include_attributes=False)for n in sealed.body if isinstance(n,ast.FunctionDef)}
        for n in tracked.body:
            if isinstance(n,ast.FunctionDef):self.assertEqual(ast.dump(n,include_attributes=False),definitions[n.name])
if __name__=='__main__':unittest.main()
