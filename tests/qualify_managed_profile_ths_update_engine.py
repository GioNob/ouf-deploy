"""Real Docker29.8.1/PG17 single-owner controller; synthetic CI workload/identity.

No production image is started and all decisions/keys are fixture-only. Exact
production JAR/configuration is qualified in a separate non-runtime job.
"""
import ast,copy,hashlib,importlib.util,json,os,select,subprocess,time,unittest
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
fixture=load('ths_native_protocol_fixture',BASE/'tests/test_managed_profile_ths_update_protocol.py')
old=load('retained_two_owner_native_fixture',BASE/'tests/qualify_managed_csv_control_update_engine.py')
plan=load('sealed_ths_plan_fixture',BASE/'scripts/prepare-managed-profile-ths-native-plan-20261028.py')
node=next(n for n in ast.parse((BASE/'tools/managed_profile_ths_scopes/bindings.py').read_text()).body if isinstance(n,ast.FunctionDef)and n.name=='configuration_profile')
exec(compile(ast.Module(body=[node],type_ignores=[]),'<fixture-persistent-profile-compiler>','exec'),plan.__dict__)

class Native(fixture.Protocol):
    cli=old.Native.cli;api=old.Native.api;psql=old.Native.psql
    apply_fixture_migration=old.Native.apply_fixture_migration
    cleanup_native=old.Native.cleanup_native
    context_instance=old.Native.context_instance
    decision=old.Native.decision

    def setup_native(self):
        # Retained synthetic native-image custody and PG fixture initialization;
        # its two-owner controller is NEVER executed.
        old.Native.setup_native(self)
        oldcase=copy.deepcopy(self.case);folder=Path(oldcase['preparedRoot'])
        prior=json.loads((folder/'execution-inputs.json').read_bytes())
        retained_plan=json.loads((folder/'execution-plan.json').read_bytes())
        archive=prior['nativeArchives']['onboarding'];audit=prior['imageAudits']['onboarding']
        self.cli('load','--input',archive['path']) # fixture install BEFORE controller
        actual=self.original['onboarding'];name=actual['Name'].lstrip('/')
        request=self.p.config_copy(actual);request['Image']=oldcase['nativeImageIds']['onboarding']
        request['HostConfig']=copy.deepcopy(actual['HostConfig'])
        request['NetworkingConfig']=copy.deepcopy(retained_plan['replacements']['onboarding']['request']['NetworkingConfig'])
        body={'spring.security.oauth2.client.registration.ouf-ths.scope':['openid','authorization.policy.admin',
            'ouf.managed-source.file.upload','resolution.issue.read','resolution.match.approve'],
            'ouf.authorization.ths.enabled':True}
        request['Env']=[*request['Env'],'SPRING_APPLICATION_JSON='+json.dumps(body)]
        self.api('POST','/containers/'+actual['Id']+'/stop?t=2')
        self.cli('rm',actual['Id']) # disposable fixture only, never controller
        cid=self.api('POST','/containers/create?name='+name,request)['Id'];self.ids.append(cid)
        self.api('POST','/containers/'+cid+'/start');self.original['onboarding']=self.api('GET','/containers/'+cid+'/json')
        actual=self.original['onboarding'];capture=copy.deepcopy(prior['currentCapture'])
        capture['currentObservations']['onboarding']=actual
        capture['currentProcessPins']['onboarding']=self.p.process_pin(actual['State']['Pid'])
        retained_plan['readReplacements']=retained_plan['replacements']
        iam=json.loads((BASE/'evidence/managed-profile-ths-iam-binding-correction-target-20261028.json').read_bytes())['result']
        iam['contextPath']=str(self.root/'synthetic-consumed-iam')
        identity={'registrationId':'ouf-ths','clientId':iam['bindingObservation']['clientId'],
            'issuer':'https://ci.invalid/realms/ouf','fileSelectionAndPrecedenceVerified':True}
        profile=plan.configuration_profile(actual,iam['bindingObservation'],identity,installation_ref='ci-only-onboarding-installation')
        iam['configurationProfileHash']=self.core.digest(profile)
        planner_case={'iamResultHash':self.core.digest(iam),'iamRoot':iam['contextPath'],
            'configurationProfileHash':self.core.digest(profile),'nativeImageIds':{'onboarding':actual['Image']},
            'clientId':identity['clientId']}
        review={'nativePlan':{'proposal':retained_plan}}
        compiled=plan.compile_native_plan(capture,review,iam,profile,planner_case)
        prepared=self.root/'single-owner-native-plan';prepared.mkdir(mode=0o700)
        private={'schema':'ouf.ths-owner-request-private-native-inputs.v1','currentCapture':capture,
            'conditionalNativePlanHash':self.core.digest(compiled),'configurationProfileHash':self.core.digest(profile),
            'retainedSuccessfulControlReview':review,'retainedIamResult':iam,'historySeals':{},
            **{k:False for k in('executionEntryQualified','runtimeAuthorityIssued','targetApplyAuthorized','automaticReplayAllowed','budgetReset')}}
        counts={'bytes':12345,'engineGets':27,'privateMetadataReads':5}
        result={'schema':'ouf.ths-owner-request-native-plan-result.v1',
            'status':'THS_OWNER_REQUEST_CONDITIONAL_NATIVE_PLAN_PREPARED_NOT_AUTHORIZED','complete':True,
            'executionInputsHash':self.core.digest(private),'conditionalNativePlanHash':self.core.digest(compiled),
            'configurationProfileHash':self.core.digest(profile),'counts':counts,'targetRoles':['onboarding'],
            'cohortSize':13,'unchangedPeers':12,'scopePatchApplied':False,'runtimeAuthorityIssued':False}
        for name,value in [('execution-inputs.json',private),('execution-plan.json',compiled),('result.json',result)]:self.write(prepared,name,value)
        self.case={'executionInputsHash':self.core.digest(private),'conditionalPlanHash':self.core.digest(compiled),
            'configurationProfileHash':self.core.digest(profile),'iamResultHash':self.core.digest(iam),
            'preparedRoot':str(prepared),'executionRoot':str(self.root/'single-owner-execution'),
            'ownerOverlayPath':oldcase['ownerOverlayPath'],'preparationCounts':counts,
            'sources':{'onboarding':self.source},'testedSources':{'onboarding':self.source},
            'nativeImageIds':{'onboarding':actual['Image']},'archives':{'onboarding':archive['sha256']},
            'retainedImageInputsPath':str(folder/'execution-inputs.json'),'retainedImageInputsHash':self.core.digest(prior),
            'transportHashes':oldcase['transportHashes']}
        self.expected_environment=profile['replacementEnvironment']

    def test_full_same_image_single_owner_update_preserves_failed5_and_twelve_peers(self):
        try:
            self.setup_native();ctx=self.context_instance();review=self.entry.review(ctx)
            result=self.entry.execute_approved(ctx,review,self.decision(review));row=ctx.execution.journal.read()
            self.assertTrue(result['complete']);self.assertTrue(result['scopePatchApplied']);self.assertEqual(row['state'],'COMPLETE')
            self.assertEqual(row['counts']['sqlSessions'],7);self.assertEqual(row['counts']['imageLoadAttempts'],0)
            self.assertEqual(row['counts']['engineWrites'],7);self.assertEqual(len(row['effects']),15)
            self.assertEqual(list(row['candidates']),['onboarding']);self.assertTrue(result['backup']['payloadParsed'])
            candidate=self.api('GET','/containers/'+row['candidates']['onboarding']['id']+'/json')
            self.assertEqual(candidate['Image'],self.original['onboarding']['Image'])
            self.assertEqual(self.p.env(candidate['Config']),self.p.env({'Env':self.expected_environment}))
            for role,before in self.original.items():
                after=self.api('GET','/containers/'+before['Id']+'/json')
                if role=='onboarding':
                    self.assertFalse(after['State']['Running']);self.assertEqual(after['NetworkSettings']['Networks'],{})
                    for key in ('MacAddress','IPAddress'):
                        self.assertEqual(candidate['NetworkSettings']['Networks'][self.net][key],before['NetworkSettings']['Networks'][self.net][key])
                    self.assertEqual(candidate['HostConfig']['Memory'],before['HostConfig']['Memory'])
                else:self.assertEqual(self.p.stable_binding(before),self.p.stable_binding(after))
            self.assertEqual(self.psql('SELECT attempts FROM ouf_onboarding.file_profile_job'),'5')
            self.assertEqual(self.psql('SELECT state FROM ouf_onboarding.file_profile_job'),'FAILED')
            print('THS_SINGLE_OWNER_SAME_IMAGE_V36_FAILED5_TWELVE_PEERS_PASS',flush=True)
        finally:self.cleanup_native()

    def test_pending_profile_stops_before_runtime_writes(self):
        try:
            self.setup_native();self.psql("UPDATE ouf_onboarding.file_profile_job SET state='READY'")
            ctx=self.context_instance();review=self.entry.review(ctx)
            with self.assertRaisesRegex(RuntimeError,'QUIESCENT'):self.entry.execute_approved(ctx,review,self.decision(review))
            row=ctx.execution.journal.read();self.assertEqual(row['counts']['engineWrites'],0);self.assertEqual(row['counts']['sqlSessions'],1)
            self.assertTrue(self.api('GET','/containers/'+self.original['onboarding']['Id']+'/json')['State']['Running'])
        finally:self.cleanup_native()

    def test_external_change_before_start_is_retained_and_not_reset(self):
        try:
            self.setup_native();ctx=self.context_instance();review=self.entry.review(ctx);cls=self.parts['ports'].NativePorts;original=cls.execute
            def drift(ports,stage):
                if stage=='VERIFY_PRESTART_STATE':self.psql("UPDATE ouf_onboarding.source SET payload='EXTERNAL_CHANGE_RETAINED'")
                return original(ports,stage)
            cls.execute=drift
            with self.assertRaisesRegex(RuntimeError,'STATE_HISTORY_COUNTERS'):self.entry.execute_approved(ctx,review,self.decision(review))
            row=ctx.execution.journal.read();self.assertEqual(row['counts']['sqlSessions'],5)
            self.assertNotIn('START_ONBOARDING_OWNER',[e['stage']for e in row['effects']])
            self.assertEqual(self.psql('SELECT payload FROM ouf_onboarding.source'),'EXTERNAL_CHANGE_RETAINED')
            self.assertEqual(self.psql('SELECT attempts FROM ouf_onboarding.file_profile_job'),'5')
            self.assertTrue(self.api('GET','/containers/'+self.original['mcp']['Id']+'/json')['State']['Running'])
        finally:self.cleanup_native()

    def test_actual_lost_controller_quarantines_only_its_single_candidate(self):
        try:
            self.setup_native();r,w=os.pipe();child=os.fork()
            if child==0:
                try:
                    os.close(r);ctx=self.context_instance();review=self.entry.review(ctx);cls=self.parts['ports'].NativePorts;original=cls.execute
                    def lost(ports,stage):
                        proof=original(ports,stage)
                        if stage=='START_ONBOARDING_OWNER':os.write(w,b'SINGLE_STARTED');os._exit(73)
                        return proof
                    cls.execute=lost;self.entry.execute_approved(ctx,review,self.decision(review));os._exit(74)
                except BaseException:
                    __import__('traceback').print_exc();os._exit(75)
            os.close(w);self.assertTrue(select.select([r],[],[],240)[0]);self.assertEqual(os.read(r,32),b'SINGLE_STARTED')
            os.close(r);_,status=os.waitpid(child,0);self.assertEqual(os.waitstatus_to_exitcode(status),73)
            journal=self.journal.Journal(Path(self.case['executionRoot']));deadline=time.monotonic()+30
            while True:
                row=self.parts['quarantine'].snapshot(journal)
                if(row.get('quarantine')or{}).get('state')=='APPLIED':break
                self.assertLess(time.monotonic(),deadline);time.sleep(.2)
            self.assertEqual(row['counts']['quarantineStops'],1);self.assertEqual(row['state'],'STOP_RECONCILE')
            self.assertEqual(row['effects'][-1]['state'],'CLAIMED');self.assertEqual(list(row['candidates']),['onboarding'])
            candidate=self.api('GET','/containers/'+row['candidates']['onboarding']['id']+'/json')
            self.assertFalse(candidate['State']['Running']);self.assertEqual(candidate['HostConfig']['RestartPolicy']['Name'],'no')
            for role,before in self.original.items():
                if role!='onboarding':self.assertEqual(self.p.stable_binding(before),self.p.stable_binding(self.api('GET','/containers/'+before['Id']+'/json')))
            print('THS_LOST_CONTROLLER_SINGLE_CANDIDATE_ONLY_PASS',flush=True)
        finally:self.cleanup_native()

    def test_zero_memory_retained(self):
        self.memory_bytes=0
        return self.test_full_same_image_single_owner_update_preserves_failed5_and_twelve_peers()

if __name__=='__main__':
    names=__import__('sys').argv[1:]or[n for n in sorted(Native.__dict__)if n.startswith('test_')]
    assert names and all(n in Native.__dict__and n.startswith('test_')for n in names)
    result=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(Native(n)for n in names))
    raise SystemExit(0 if result.wasSuccessful()else 1)
