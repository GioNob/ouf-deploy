"""Real V34 -> failed Hostname create -> signed same-claim V35 recovery.

Private historical bindings and expiry are fixtures. Real Docker/PG17, original
CI image, old seven effects, new Context, Ed25519/TTY, one backend/two closed
transactions, CAS counters and parent-loss cleanup run without executor mocks.
"""
import copy,importlib.util,json,os,signal,sys,time,types,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[3]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);sys.modules[name]=value;spec.loader.exec_module(value);return value
old=module('existing_create_native_fixture',Path(__file__).with_name('test_onboarding_v35_native_apply.py'))
for name,value in (('base',old.entry),('protocol',old.core),('ports',old.ports),('quarantine',old.quarantine)):sys.modules['verified_v35_recovery_'+name]=value
session=module('verified_v35_recovery_sql',ROOT/'tools/onboarding_v35_native/recovery_sql.py')
recovery=module('verified_v35_recovery_impl',ROOT/'tools/onboarding_v35_native/recovery.py')

@unittest.skipUnless(os.environ.get('OUF_NATIVE_V35_APPLY')=='1','actual Docker PG17 exact image required')
class NativeRecovery(unittest.TestCase):
    explicit_empty_hostname=True
    # Reuse setup helpers without inheriting the unrelated successful-rollout tests.
    for _name,_value in old.Native.__dict__.items():
        if callable(_value)and not _name.startswith(('test_','__')):locals()[_name]=_value
    def setUp(self):
        # Each disposable fixture has its own metadata-only compiler namespace.
        # No target/execution journal or cumulative attempt counter is reset.
        compiler=old.module('independent_recovery_fixture_plan_'+str(time.monotonic_ns()),Path(old.n.__file__))
        selected=patch.object(old,'n',compiler);selected.start();self.addCleanup(selected.stop)
        old.Native.setUp(self)
    def cleanup(self):
        # Remove ONLY the exact untagged CI candidate image after its disposable
        # containers, so each independent fixture exercises the original import.
        image=None
        if hasattr(self,'ctx')and (self.ctx.root/'review.json').exists():image=json.loads((self.ctx.root/'review.json').read_bytes())['nativePlan']['candidate']['nativeImageId']
        old.Native.cleanup(self)
        if image:
            try:self.docker('image','rm',image)
            except Exception:pass
    def initial_stop(self):
        code,output,_=self.perform();self.assertEqual(code,2,output.decode(errors='replace'))
        self.parent_ctx=self.ctx;self.parent_row=json.loads((self.ctx.root/'recovery.json').read_bytes())
        self.assertEqual(self.parent_row['nextStage'],7);self.assertEqual(self.parent_row['counts'],recovery.BASE_COUNTS)
        self.assertEqual([e['state']for e in self.parent_row['effects']],['APPLIED']*7+['CLAIMED'])
        self.created=self.parent_row['createdId'];actual=self.inspect(self.created)
        self.assertEqual(actual['Config']['Hostname'],self.created[:12]);self.assertFalse(actual['State']['Running'])
        retained_review=json.loads((self.ctx.root/'review.json').read_bytes())
        self.assertEqual(retained_review['nativePlan']['replacement']['request']['Hostname'],'')
        # The old ephemeral watchdog observes its ended parent and exits; no stop
        # is authorized because createdConfigurationVerified stayed false.
        time.sleep(1.1)
    def recovered_context(self):
        parent=self.parent_ctx;root=parent.root
        old_review=json.loads((root/'review.json').read_bytes());old_auth=json.loads((root/'authority/authority.json').read_bytes())
        reader=self.root/'retained-reader';reader.mkdir(mode=0o700)
        raw=(ROOT/'scripts/read-onboarding-v35-created-config-20261024.py').read_bytes();old.private(reader/'read.py',raw)
        old.private(reader/'reader-result.json',{'status':'RETAINED_CREATED_CONFIG_DIFFERENCE_OBSERVED','complete':True,
            'reviewHash':old.core.digest(old_review),'authorityHash':old.core.digest(old_auth),'retainedJournalHash':old.core.digest(self.parent_row),
            'retainedCumulativeCounts':self.parent_row['counts'],'retainedCandidateConfigDifferences':[{'field':'Hostname','expectedEmpty':True,'observedEmpty':False}]})
        code=self.root/'recovery-code';code.mkdir(mode=0o700)
        for path,name in ((ROOT/'tools/onboarding_v35_native/recovery.py','recovery.py'),(ROOT/'tools/onboarding_v35_native/recovery_sql.py','recovery_sql.py'),(ROOT/'scripts/recover-onboarding-v35-existing-create-20261024.py','recover.py')):old.private(code/name,path.read_bytes())
        source_dir=Path(next(p for p in parent.source_bindings if p.endswith('/apply.py'))).parent
        self.scope_patches=[patch.multiple(recovery,PARENT_REVIEW=old.core.digest(old_review),PARENT_AUTHORITY=old.core.digest(old_auth),PARENT_JOURNAL=old.core.digest(self.parent_row),READER=str(reader)),
            patch.multiple(old.entry,FROZEN=str(self.root/'frozen-proposal/execution-plan.json'),FROZEN_HASH=parent.fixture_frozen_hash,PARENT=str(root.parent),__file__=str(source_dir/'apply.py')),
            patch.multiple(old.d,INPUT=str(self.root/'inputs.json'),INPUT_HASH=parent.frozen['inputHash']),patch.object(old.p,'PACKAGE',os.environ['OUF_V35_TEST_PACKAGE']),
            patch.object(old.postboot_authority,'authority_metadata',return_value=(self.signing_profile,self.public_policy))]
        for p in self.scope_patches:p.start();self.addCleanup(p.stop)
        # Only the historical-expiry observation is a fixture. Restore the real
        # clock BEFORE any new review, signer, authority, watchdog or SQL work.
        real_time=time.time
        with patch.object(time,'time',side_effect=lambda:real_time()+1000):
            return recovery.Context(parent.n,old.p,old.q,None,None,old.d,old.m,parent.r,old.CONFIG,old.REPLACEMENT,code,code/'recover.py')
    def invoke(self,ctx,wrong=False,kill=False):
        def run():
            try:return recovery.operator(ctx)
            except BaseException:
                row=json.loads((ctx.parent/'recovery.json').read_bytes());print('FIXTURE_RECOVERY_STAGE '+str(row['nextStage'])+' '+str(row['counts']),flush=True)
                raise
        return old.tty_call(run,wrong=wrong,kill_after_start_root=str(ctx.parent)if kill else None)
    def test_same_candidate_exact_hostname_one_backend_and_preserved_history(self):
        self.initial_stop();ctx=self.recovered_context();observations=[];original=session.ReadOnlySession.query
        def observed_sql(instance,after=False):
            facts=original(instance,after=after)
            raw=self.sql("SELECT coalesce(jsonb_agg(jsonb_build_object('pid',pid,'state',state,'noTransaction',xact_start IS NULL)),'[]'::jsonb) FROM pg_stat_activity WHERE application_name='ouf-v35-reconciliation'")
            rows=json.loads(raw);self.assertEqual(len(rows),1);self.assertEqual(rows[0]['state'],'idle');self.assertTrue(rows[0]['noTransaction'])
            observations.append(rows[0]);return facts
        # Observations are in the child process; persist only fixture backend ids
        # privately so the parent can independently check one connection/idle tx.
        def record_sql(instance,after=False):
            result=observed_sql(instance,after=after);old.private(ctx.root/('fixture-backend-after.json'if after else'fixture-backend-before.json'),observations[-1]);return result
        with patch.object(session.ReadOnlySession,'query',record_sql):code,output,approved,_=self.invoke(ctx)
        self.assertTrue(approved,output.decode(errors='replace'));self.assertEqual(code,0,output.decode(errors='replace'))
        row=json.loads((ctx.parent/'recovery.json').read_bytes());self.assertEqual(row['nextStage'],13);self.assertEqual(row['state'],'COMPLETE')
        self.assertEqual(row['createdId'],self.created);self.assertEqual(row['effects'][:7],self.parent_row['effects'][:7]);self.assertEqual(row['effects'][7]['intentHash'],self.parent_row['effects'][7]['intentHash'])
        self.assertTrue(row['effects'][7]['proof']['creationReconciledWithoutReplay']);self.assertEqual(row['backup'],self.parent_row['backup'])
        self.assertEqual(row['counts']['sqlSessions'],6);self.assertEqual(row['counts']['imageLoadAttempts'],1);self.assertEqual(row['counts']['backupProcesses'],2);self.assertEqual(row['counts']['engineWrites'],6)
        self.assertEqual(row['recoverySql']['state'],'APPLIED');self.assertEqual([t['state']for t in row['recoverySql']['transactions']],['APPLIED','APPLIED'])
        first=json.loads((ctx.root/'fixture-backend-before.json').read_bytes());last=json.loads((ctx.root/'fixture-backend-after.json').read_bytes());self.assertEqual(first['pid'],last['pid'])
        self.assertEqual(self.sql("SELECT count(*) FROM pg_stat_activity WHERE application_name='ouf-v35-reconciliation'"),'0')
        self.assertEqual(self.sql("SELECT count(*) FROM ouf_onboarding.flyway_schema_history WHERE version='35' AND checksum=1095739786 AND success"),'1')
        self.assertEqual(self.sql('SELECT count(*) FROM ouf_onboarding.managed_readiness_budget_session'),'0')
        self.assertEqual(json.loads(self.sql("SELECT jsonb_build_object('review',to_jsonb(m)-'readiness_session_id','revision',to_jsonb(r)) FROM ouf_onboarding.managed_onboarding_review m CROSS JOIN ouf_onboarding.source_property_revision r")),json.loads(self.retained))
        self.assertFalse(self.inspect(self.app)['State']['Running']);self.assertTrue(self.inspect(self.created)['State']['Running'])
        self.assertEqual(self.inspect(self.created)['Config']['Hostname'],self.created[:12])
        for name,original_row in self.rows.items():
            if name!='onboarding':self.assertEqual(old.runtime_bindings.observed(self.inspect(original_row['Id']),old.runtime_bindings.NATIVE),old.runtime_bindings.observed(original_row,old.runtime_bindings.NATIVE))
        receipt=json.loads((ctx.root/'result.json').read_bytes());review=json.loads((ctx.root/'review.json').read_bytes());v=review['verification'];verify=old.DetachedAuthenticator(v['trustPolicy'],str(ctx.root/'authority'),v['openssl'])
        self.assertTrue(verify(old.core.encoded(receipt),'CREATION_ATTESTATION','fixture-attestor','fixture-installation','fixture-entity'))
        with self.assertRaises(Exception):recovery.operator(ctx)
    def test_wrong_terminal_keeps_original_claim_and_never_starts(self):
        self.initial_stop();ctx=self.recovered_context();code,output,approved,_=self.invoke(ctx,wrong=True)
        self.assertTrue(approved);self.assertEqual(code,2,output.decode(errors='replace'));self.assertEqual(json.loads((ctx.parent/'recovery.json').read_bytes()),self.parent_row)
        self.assertFalse(self.inspect(self.created)['State']['Running']);self.assertFalse((ctx.root/'authority').exists())
    def test_parent_loss_closes_sql_and_stops_only_existing_candidate_once(self):
        self.initial_stop();ctx=self.recovered_context();code,output,approved,killed=self.invoke(ctx,kill=True)
        self.assertTrue(approved);self.assertTrue(killed,output.decode(errors='replace'));self.assertEqual(code,-signal.SIGKILL)
        until=time.monotonic()+35
        while True:
            row=json.loads((ctx.parent/'recovery.json').read_bytes())
            if row.get('quarantine')and row['quarantine']['state']=='APPLIED':break
            if (ctx.root/'watchdog-stop.json').exists():self.fail((ctx.root/'watchdog-stop.json').read_text())
            self.assertLess(time.monotonic(),until);time.sleep(.2)
        self.assertEqual(row['counts']['quarantineStops'],1);self.assertEqual(row['counts']['sqlSessions'],6)
        self.assertFalse(self.inspect(self.created)['State']['Running']);self.assertFalse(self.inspect(self.app)['State']['Running'])
        while self.sql("SELECT count(*) FROM pg_stat_activity WHERE application_name='ouf-v35-reconciliation'")!='0':self.assertLess(time.monotonic(),until);time.sleep(.2)
        for name,original_row in self.rows.items():
            if name!='onboarding':self.assertEqual(old.runtime_bindings.observed(self.inspect(original_row['Id']),old.runtime_bindings.NATIVE),old.runtime_bindings.observed(original_row,old.runtime_bindings.NATIVE))

if __name__=='__main__':unittest.main()
