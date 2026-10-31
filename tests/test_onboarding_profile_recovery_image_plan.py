import copy,importlib.util,json,pathlib,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
m=load('profile_prepare',ROOT/'scripts/prepare-onboarding-profile-recovery-image-plan-20261027.py')
p=load('pure_plan',ROOT/'tools/acquisition_read_native/plan_helper.py')
mac=load('pure_mac',ROOT/'tools/acquisition_read_native/retained_mac.py')
CASE=json.loads((ROOT/'releases/onboarding-profile-recovery-image-custody-20261027.json').read_text())
def fixtures():
    actual={'Id':'a'*64,'Image':m.INSTALLED_IMAGE,'Name':'/ci-only-onboarding','State':{'Running':True,'Pid':44,'StartedAt':'ci-generation'},
        'Config':{'User':'10003:10003','Env':['PRIVATE_CANARY=value'],'Entrypoint':['java','-jar','/app/application.jar'],'Cmd':None,
            'WorkingDir':'/app','Healthcheck':None,'Labels':{'ouf.owner':'retained'},'Image':m.INSTALLED_IMAGE},
        'HostConfig':{'AutoRemove':False,'Memory':0,'OomKillDisable':None,'NetworkMode':'ci-owner-network','RestartPolicy':{'Name':'unless-stopped','MaximumRetryCount':0},
            'PortBindings':{'8080/tcp':[{'HostIp':'127.0.0.1','HostPort':'0'}]},'Binds':['/ci/private:/opt/ouf/secrets/onboarding-ths.yaml:ro']},
        'Mounts':[{'Type':'bind','Source':'/ci/private','Destination':'/opt/ouf/secrets/onboarding-ths.yaml','RW':False}],
        'NetworkSettings':{'Networks':{'ci-owner-network':{'NetworkID':'b'*64,'Aliases':['ci-owner-alias'],'MacAddress':'02:42:ac:11:00:09','IPAddress':'172.17.0.9','IPAMConfig':None}},
            'Ports':{'8080/tcp':[{'HostIp':'127.0.0.1','HostPort':'18080'}]}}}
    counts={'bytes':526335,'engineGets':3,'privateMetadataReads':4}
    inputs={'schema':'ouf.onboarding-profile-recovery-current-inputs.v1','counts':counts,'retainedInstalledSource':m.INSTALLED_SOURCE,
        'retainedReviewHash':'d77154b3e734c0b249f315fe10961d99baa380d4625d920b917cbe7c270b134b',
        'retainedAuthorityHash':'fa906ab28f8268e7b62a8df59c9825b8c2524bf28da44821801db7b916c1f4ce',
        'retainedNativeBindingHash':'1bda483e8138353f4ada203a6b19fa532344393b5e0f995c963d01c90584eb78',
        'bootId':'ci-only','engineBinding':{'socketPath':'/ci/no-socket','socketBinding':[1,2,0,0,432],'peerCredentials':[1,0,0]},
        'engineInfo':{'ServerVersion':'29.8.1','DriverStatus':[['driver-type','io.containerd.snapshotter.v1']]},
        'onboardingProcessPin':{'pid':44,'startTicks':1},'onboardingObservation':actual,
        'retainedDiagnosticApplyCounts':{'engineGets':261,'engineWrites':8,'sqlSessions':4},'retainedDiagnosticOperationalStateProof':{'retainedFailedJobUnchanged':True},
        'historySeals':[{'path':'/ci/retained','sha256':'c'*64}]}
    receipt={'schema':'ouf.onboarding-profile-recovery-current-input-capture-result.v1','status':'ONBOARDING_PROFILE_RECOVERY_CURRENT_INPUTS_CAPTURED_NOT_AUTHORIZED',
        'complete':True,'inputsHash':m.INPUT_HASH,'counts':copy.deepcopy(counts),'retainedCandidateIdentityObserved':True,'retainedProcessGenerationMatched':True}
    receipt.update({k:False for k in('runtimeAuthorityIssued','automaticReplayAllowed','budgetReset','currentApplicationPolicyOrLabelsObserved','currentJobOrBudgetStateObserved','currentReadinessObserved','continuationAuthorized','historicalAuthorityReused')})
    receipt.update({k:0 for k in('containerWrites','imageImports','sourceActivations','acquisitionsExecuted','sqlSessions','oauthRequests','credentialFileReads')})
    frozen={'schema':'ouf.onboarding-v35-frozen-native-plan.v1','runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
        'replacements':{'onboarding':{'request':copy.deepcopy(actual['Config']),'readiness':{'readinessPort':8080,'readinessPath':'/actuator/health/readiness'}}},
        'nativeFlywayConfiguration':{'ownerOverlays':[{'binding':{'path':'/opt/ouf/secrets/onboarding-ths.yaml','sha256':'d'*64}}]},
        'boundDatabaseProfile':{'schema':'ouf.current-onboarding-database-snapshot-profile.v1','runtimeBindingProfile':'ouf.runtime-binding.native-mount-order.v1','engineBinding':{'socketPath':'/ci/no-socket'}}}
    audit={'nativeIdentity':{'nativeImageId':CASE['nativeImageId']},'imageConfig':{'User':'10003:10003','Entrypoint':['java','-jar','/app/application.jar'],'Cmd':None,'Labels':{'org.opencontainers.image.revision':m.TESTED}}}
    return inputs,receipt,frozen,audit

class Tests(unittest.TestCase):
    def setUp(self):self.inputs,self.receipt,self.frozen,self.audit=fixtures()
    def plan(self):return m.conditional_plan(self.inputs,self.frozen,self.audit,p,mac,CASE)
    def test_capture_and_pid1_are_preserved_without_live_observation(self):
        self.assertEqual(m.validate_capture(self.inputs,self.receipt),self.inputs['onboardingObservation']);self.assertEqual(self.plan()['engineBinding']['peerCredentials'],[1,0,0])
    def test_no_authority_or_current_application_proof_inferred(self):
        plan=self.plan()
        for field in('runtimeAuthorityIssued','targetApplyAuthorized','databaseAdmissionProven','currentRuntimeRevalidated','newJobOrHumanBudgetAuthorized','budgetReset','releaseAcceptance'):
            self.assertIs(plan[field],False)
        self.assertTrue(plan['freshDatabaseAdmissionRequiredAtApply']);self.assertTrue(plan['freshOwnerConfigurationContentRequiredAtApply'])
        self.assertEqual(plan['boundDatabaseProfile'],self.frozen['boundDatabaseProfile']);self.assertNotIn('peerCredentials',plan['boundDatabaseProfile']['engineBinding'])
    def test_environment_mounts_existing_labels_resources_and_counters_preserved(self):
        before=copy.deepcopy(self.inputs);plan=self.plan();request=plan['onboardingReplacement']['request']
        self.assertEqual(request['Env'],before['onboardingObservation']['Config']['Env']);self.assertEqual(request['HostConfig']['Binds'],before['onboardingObservation']['HostConfig']['Binds'])
        self.assertEqual(request['HostConfig']['Memory'],0);self.assertIsNone(request['HostConfig']['OomKillDisable']);self.assertEqual(request['Labels'],before['onboardingObservation']['Config']['Labels'])
        self.assertEqual(plan['retainedDiagnosticApplyCounts'],before['retainedDiagnosticApplyCounts']);self.assertEqual(self.inputs,before)
    def test_existing_ip_mac_and_dynamic_port_are_pinned(self):
        request=self.plan()['onboardingReplacement']['request'];endpoint=request['NetworkingConfig']['EndpointsConfig']['ci-owner-network']
        self.assertEqual(endpoint['IPAMConfig']['IPv4Address'],'172.17.0.9');self.assertEqual(endpoint['MacAddress'],'02:42:ac:11:00:09')
        self.assertEqual(request['HostConfig']['PortBindings']['8080/tcp'][0]['HostPort'],'18080')
    def test_absent_legacy_mac_uses_exact_unchanged_config_policy(self):self.assertEqual(self.plan()['legacyConfigMacDetachPolicy']['profile'],'NO_LEGACY_CONFIG_MAC_CHANGE_RETAIN_EXACT_V1')
    def test_legacy_mac_uses_already_qualified_narrow_transition(self):
        self.inputs['onboardingObservation']['Config']['MacAddress']='02:42:ac:11:00:09'
        self.assertEqual(self.plan()['legacyConfigMacDetachPolicy']['profile'],'LEGACY_CONFIG_MAC_ABSENT_ONLY_AFTER_PROVEN_STOP_AND_DETACH_V1')
    def test_mismatching_legacy_mac_is_not_ignored(self):
        self.inputs['onboardingObservation']['Config']['MacAddress']='02:42:ac:11:00:08'
        with self.assertRaises(p.Stop):self.plan()
    def test_static_ip_drift_is_not_normalized(self):
        self.inputs['onboardingObservation']['NetworkSettings']['Networks']['ci-owner-network']['IPAMConfig']={'IPv4Address':'172.17.0.8'}
        with self.assertRaises(m.Stop):self.plan()
    def test_config_drift_stops(self):
        self.frozen['replacements']['onboarding']['request']['Env']=[]
        with self.assertRaises(m.Stop):self.plan()
    def test_unknown_database_profile_or_overlay_stops(self):
        self.frozen['boundDatabaseProfile']['schema']='unknown'
        with self.assertRaises(m.Stop):self.plan()
        self.frozen=fixtures()[2];self.frozen['nativeFlywayConfiguration']['ownerOverlays'][0]['binding']['path']='/other'
        with self.assertRaises(m.Stop):self.plan()
    def test_negative_or_bool_memory_is_rejected(self):
        for value in(-1,True):
            self.inputs['onboardingObservation']['HostConfig']['Memory']=value
            with self.assertRaises(m.Stop):self.plan()
    def test_invalid_peer_capture_generation_and_authority_stop(self):
        for field in('inputsHash','complete','runtimeAuthorityIssued','retainedProcessGenerationMatched','budgetReset'):
            receipt=copy.deepcopy(self.receipt);receipt[field]=False if receipt[field]is True else True
            with self.assertRaises(m.Stop):m.validate_capture(self.inputs,receipt)
        for peer in([0,0,0],[1,1000,0],[True,0,0]):
            self.inputs['engineBinding']['peerCredentials']=peer
            with self.assertRaises(m.Stop):m.validate_capture(self.inputs,self.receipt)
    def test_only_new_v36_and_exact_prior35_are_in_the_proposal(self):
        plan=self.plan();self.assertEqual(plan['databaseMigration']['from'],35);self.assertEqual(plan['databaseMigration']['to'],36)
        self.assertEqual(len(plan['candidateApplicationFacts']['migrations']),36);self.assertEqual(plan['databaseMigration']['flywayChecksum'],-317278534)
    def test_duplicate_nonfinite_json_rejected(self):
        for raw in(b'{"a":1,"a":2}',b'{"a":NaN}'):
            with self.assertRaises(m.Stop):m.decode(raw)

if __name__=='__main__':unittest.main()
