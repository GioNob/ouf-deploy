"""Real Docker29/PG17,new signed controller,actual37/38 SQL. Workload/keys are CI-only.

The harness emulates owner startup migration;it never starts the production image.
Production JAR and configuration are independently qualified in another job.
"""
import copy,hashlib,importlib.util,json,os,select,time,unittest
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
def load(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
fixture=load('owner_v38_protocol_fixture',BASE/'tests/test_managed_file_owner_update_protocol.py')
old=load('owner_v38_retained_native',BASE/'tests/qualify_managed_csv_control_update_engine.py')

class Native(fixture.Protocol):
    cli=old.Native.cli;api=old.Native.api;psql=old.Native.psql;cleanup_native=old.Native.cleanup_native
    apply_fixture_migration=old.Native.apply_fixture_migration;context_instance=old.Native.context_instance;decision=old.Native.decision
    def setup_native(self):
        fence=self.parts['state_fence'];fence.TABLES=tuple(self.parts['base_state_fence'].TABLES)
        old.Native.setup_native(self)
        fence.TABLES=(*self.parts['base_state_fence'].TABLES,'managed_file_upload_attempt','managed_profile_budget_session','managed_profile_event')
        self.psql("ALTER TABLE ouf_onboarding.managed_file_asset ADD COLUMN uploaded_by text,ADD COLUMN content_hash text,ADD COLUMN size_bytes bigint;CREATE TABLE ouf_onboarding.managed_file_upload_attempt(asset_id uuid,tenant_id text,subject_id text);")
        self.psql("INSERT INTO ouf_onboarding.managed_file_asset VALUES('%s','b93d8cf6-cd14-4ee6-91d7-84cd76c4f500','sha256:f670059bb524832aa9cd78fbe5e907be053244248ff1ef4d7962b14fcd72c311',13903)"%fence.ASSET)
        previous=copy.deepcopy(self.case);folder=Path(previous['preparedRoot']);prior=json.loads((folder/'execution-inputs.json').read_bytes());plan=json.loads((folder/'execution-plan.json').read_bytes())
        capture=prior['currentCapture'];capture['schema']='ouf.managed-file-owner-recovery-current-inputs.v1'
        capture['targetRoles']=['onboarding'];capture.pop('targets',None);capture.pop('resolvedTargetRoles',None)
        newroot=self.root/'single-owner-v38-prepared';newroot.mkdir(mode=0o700)
        archive=copy.deepcopy(prior['nativeArchives']['onboarding']);path=newroot/'onboarding-native.tar'
        import shutil
        shutil.copyfile(archive['path'],path);path.chmod(0o400);archive.update(path=str(path),metadata=list(self.p.frame(path.lstat())))
        audit=prior['imageAudits']['onboarding'];row=plan['replacements']['onboarding'];row['nativeArchive']=archive
        plan['replacements']={'onboarding':row};plan['targetRoles']=['onboarding'];plan.pop('targetRoleKeys',None)
        plan['existingApplications']={r:self.p.stable_binding(v)for r,v in capture['currentObservations'].items()};plan['unchangedApplications']={r:v for r,v in plan['existingApplications'].items()if r!='onboarding'}
        application=plan['candidateApplicationFacts'];add=json.loads((BASE/'releases/managed-file-owner-v38-image-custody-20261028.json').read_text())['additionalMigrations'];application['migrations']+=add;application['databaseMigrationRequired']=True
        plan.update(schema='ouf.managed-file-owner-recovery-conditional-native-plan.v1',capturedInputsHash=self.core.digest(capture),databaseMigration={'from':36,'to':38,'newMigrations':2,'newMigrationFacts':add},currentJobOrBudgetStateObserved=False,imageImportAuthorized=False,humanOwnershipOrBudgetOrResumeAuthorized=False,sourceActivationAuthorized=False)
        native={'schema':'ouf.managed-file-owner-recovery-private-execution-inputs.v1','capturedInputsHash':self.core.digest(capture),'currentCapture':capture,'conditionalNativePlanHash':self.core.digest(plan),'nativeArchives':{'onboarding':archive},'imageAudits':{'onboarding':audit},**{k:False for k in('executionEntryQualified','runtimeAuthorityIssued','targetUpdateAuthorized','currentRuntimeRevalidated','automaticReplayAllowed','budgetReset')}}
        counts={'privateMetadataReads':3,'privateMetadataBytes':1,'ciZipReads':1,'nativeArchivesPrepared':1,'engineGets':0,'containerWrites':0,'imageImports':0}
        result={'schema':'ouf.managed-file-owner-recovery-image-plan-result.v1','status':'MANAGED_FILE_OWNER_RECOVERY_IMAGE_AND_CONDITIONAL_PLAN_PREPARED_NOT_AUTHORIZED','complete':True,'executionInputsHash':self.core.digest(native),'conditionalNativePlanHash':self.core.digest(plan),'capturedInputsHash':self.core.digest(capture),'counts':counts,'targetRoles':['onboarding'],'cohortSize':13,'unchangedPeers':12,'databaseMigration':{'from':36,'to':38,'newMigrations':2},'humanOwnershipReceiptsCreated':0,'humanBudgetsGranted':0,'resumes':0,**{k:False for k in('runtimeAuthorityIssued','targetUpdateAuthorized','currentRuntimeRevalidated','databaseAdmissionProven','currentJobOrBudgetStateObserved')}}
        for name,value in [('execution-inputs.json',native),('execution-plan.json',plan),('result.json',result)]:self.write(newroot,name,value)
        self.case={**previous,'preparedRoot':str(newroot),'executionRoot':str(self.root/'single-owner-v38-execution'),'executionInputsHash':self.core.digest(native),'conditionalPlanHash':self.core.digest(plan),'preparedResultHash':self.core.digest(result),'inputsHash':self.core.digest(capture),'preparationCounts':counts,'sources':{'onboarding':self.source},'testedSources':{'onboarding':self.source},'nativeImageIds':{'onboarding':previous['nativeImageIds']['onboarding']},'archives':{'onboarding':archive['sha256']}}
        self.additions=add
    def owner_migrations(self,limit=2):
        for row in self.additions[:limit]:
            raw=(BASE/'tests/fixtures/owner-v38'/row['script']).read_bytes();self.assertEqual(hashlib.sha256(raw).hexdigest(),row['sha256']);self.psql(raw.decode())
            self.psql("INSERT INTO ouf_onboarding.flyway_schema_history VALUES(%s,'%s','%s',%d,true,'SQL')"%(row['version'],row['version'],row['script'],row['flywayChecksum']))
    def install_startup_fixture(self,partial=False,lost_fd=None):
        cls=self.parts['ports'].NativePorts;original=cls.execute
        def execute(ports,stage):
            proof=original(ports,stage)
            if stage=='START_ONBOARDING_OWNER':
                self.owner_migrations(limit=1 if partial else 2)
                if partial:raise RuntimeError('CI_ONLY_OWNER_FAILED_AFTER_V37')
                if lost_fd is not None:os.write(lost_fd,b'V38_STARTED');os._exit(73)
            return proof
        cls.execute=execute
    def test_full36_to38_preserves_failed5_and_twelve_peers(self):
        try:
            self.setup_native();self.install_startup_fixture();ctx=self.context_instance();review=self.entry.review(ctx);result=self.entry.execute_approved(ctx,review,self.decision(review));row=ctx.execution.journal.read()
            self.assertTrue(result['complete']);self.assertEqual(row['state'],'COMPLETE');self.assertEqual(len(row['effects']),16);self.assertEqual(row['counts']['sqlSessions'],7);self.assertEqual(row['counts']['imageLoadAttempts'],1);self.assertEqual(row['counts']['engineWrites'],8)
            self.assertTrue(result['backup']['payloadParsed']);self.assertEqual(result['installedSchemaVersion'],38);self.assertEqual(result['humanOwnershipReceiptsCreated'],0)
            self.assertEqual(self.psql('SELECT count(*) FROM ouf_onboarding.managed_file_owner_reconciliation'),'0');self.assertEqual(self.psql('SELECT count(*) FROM ouf_onboarding.managed_file_asset WHERE tenant_id IS NOT NULL'),'0')
            self.assertEqual(self.psql('SELECT attempts FROM ouf_onboarding.file_profile_job'),'5');self.assertEqual(self.psql('SELECT state FROM ouf_onboarding.file_profile_job'),'FAILED')
            candidate=self.api('GET','/containers/'+row['candidates']['onboarding']['id']+'/json')
            for role,before in self.original.items():
                after=self.api('GET','/containers/'+before['Id']+'/json')
                if role=='onboarding':
                    self.assertFalse(after['State']['Running']);self.assertEqual(after['NetworkSettings']['Networks'],{})
                    for k in('MacAddress','IPAddress'):self.assertEqual(candidate['NetworkSettings']['Networks'][self.net][k],before['NetworkSettings']['Networks'][self.net][k])
                    self.assertEqual(candidate['HostConfig']['Memory'],before['HostConfig']['Memory'])
                else:self.assertEqual(self.p.stable_binding(before),self.p.stable_binding(after))
            with self.assertRaisesRegex(RuntimeError,'CONSUMED_NO_REPLAY'):self.context_instance()
            print('OWNER_V38_REAL_DOCKER_PG17_BACKUP_12PEERS_FAILED5_EMPTY_OWNER_RECEIPT_PASS',flush=True)
        finally:self.cleanup_native()
    def test_zero_memory_retained(self):self.memory_bytes=0;return self.test_full36_to38_preserves_failed5_and_twelve_peers()
    def test_pending_profile_stops_before_any_write(self):
        try:
            self.setup_native();self.psql("UPDATE ouf_onboarding.file_profile_job SET state='READY'");ctx=self.context_instance();r=self.entry.review(ctx)
            with self.assertRaisesRegex(RuntimeError,'QUIESCENT'):self.entry.execute_approved(ctx,r,self.decision(r))
            row=ctx.execution.journal.read();self.assertEqual(row['counts']['engineWrites'],0);self.assertEqual(row['counts']['sqlSessions'],1)
        finally:self.cleanup_native()
    def test_external_change_before_start_is_retained(self):
        try:
            self.setup_native();ctx=self.context_instance();r=self.entry.review(ctx);cls=self.parts['ports'].NativePorts;original=cls.execute
            def drift(ports,stage):
                if stage=='VERIFY_PRESTART_STATE':self.psql("UPDATE ouf_onboarding.source SET payload='EXTERNAL_RETAINED'")
                return original(ports,stage)
            cls.execute=drift
            with self.assertRaisesRegex(RuntimeError,'OPERATIONAL_ROWS'):self.entry.execute_approved(ctx,r,self.decision(r))
            row=ctx.execution.journal.read();self.assertEqual(row['counts']['sqlSessions'],5);self.assertNotIn('START_ONBOARDING_OWNER',[e['stage']for e in row['effects']]);self.assertEqual(self.psql('SELECT payload FROM ouf_onboarding.source'),'EXTERNAL_RETAINED')
        finally:self.cleanup_native()
    def test_partial_v37_is_preserved_without_rollback_or_replay(self):
        try:
            self.setup_native();self.install_startup_fixture(partial=True);ctx=self.context_instance();r=self.entry.review(ctx)
            with self.assertRaisesRegex(RuntimeError,'CI_ONLY_OWNER_FAILED_AFTER_V37'):self.entry.execute_approved(ctx,r,self.decision(r))
            row=ctx.execution.journal.read();self.assertEqual(row['effects'][-1]['state'],'CLAIMED');self.assertEqual(self.psql("SELECT max(version::int) FROM ouf_onboarding.flyway_schema_history"),'37');self.assertEqual(self.psql('SELECT attempts FROM ouf_onboarding.file_profile_job'),'5')
            with self.assertRaisesRegex(RuntimeError,'CONSUMED_NO_REPLAY'):self.context_instance()
        finally:self.cleanup_native()
    def test_actual_lost_controller_stops_only_own_candidate(self):
        try:
            self.setup_native();r,w=os.pipe();child=os.fork()
            if child==0:
                try:
                    os.close(r);self.install_startup_fixture(lost_fd=w);ctx=self.context_instance();review=self.entry.review(ctx);self.entry.execute_approved(ctx,review,self.decision(review));os._exit(74)
                except BaseException:__import__('traceback').print_exc();os._exit(75)
            os.close(w);self.assertTrue(select.select([r],[],[],240)[0]);self.assertEqual(os.read(r,32),b'V38_STARTED');os.close(r);_,status=os.waitpid(child,0);self.assertEqual(os.waitstatus_to_exitcode(status),73)
            journal=self.journal.Journal(Path(self.case['executionRoot']));deadline=time.monotonic()+30
            while True:
                row=self.parts['quarantine'].snapshot(journal)
                if(row.get('quarantine')or{}).get('state')=='APPLIED':break
                self.assertLess(time.monotonic(),deadline);time.sleep(.2)
            self.assertEqual(row['counts']['quarantineStops'],1);self.assertEqual(row['effects'][-1]['state'],'CLAIMED');self.assertEqual(row['state'],'STOP_RECONCILE')
            value=self.api('GET','/containers/'+row['candidates']['onboarding']['id']+'/json');self.assertFalse(value['State']['Running']);self.assertEqual(value['HostConfig']['RestartPolicy']['Name'],'no')
            for role,before in self.original.items():
                if role!='onboarding':self.assertEqual(self.p.stable_binding(before),self.p.stable_binding(self.api('GET','/containers/'+before['Id']+'/json')))
            self.assertEqual(self.psql('SELECT count(*) FROM ouf_onboarding.managed_file_owner_reconciliation'),'0');print('OWNER_V38_ACTUAL_LOST_CONTROLLER_SINGLE_CANDIDATE_ONLY_PASS',flush=True)
        finally:self.cleanup_native()
if __name__=='__main__':
    names=__import__('sys').argv[1:]or[n for n in sorted(Native.__dict__)if n.startswith('test_')];assert names and all(n in Native.__dict__ and n.startswith('test_')for n in names)
    r=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(Native(n)for n in names));raise SystemExit(0 if r.wasSuccessful()else 1)
