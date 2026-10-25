"""Actual Engine29.8.1/APISIX residual recovery; synthetic owners/keys/TTY decision."""
import copy,json,os,select,signal,time,unittest
from pathlib import Path
from unittest.mock import patch
import importlib.util
BASE=Path(__file__).resolve().parents[1]
def module(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
continuation=module('detached_continuation_fixture',BASE/'tests/qualify_acquisition_continuation_engine.py')
Continuation,cont=continuation.Continuation,continuation.cont
recovery=module('detached_recovery',BASE/'scripts/recover-acquisition-detached-mcp-20261025.py')
reader=module('detached_receipt',BASE/'scripts/read-acquisition-old-mcp-guard-20261025.py')
class DetachedRecovery(Continuation):
    def terminal(self,review,path):
        # CI-only synthetic decision. Production parser is never replaced.
        self.assertIsNone(self.ctx.key);self.assertTrue(path.exists());self.assertFalse((self.ctx.root/'authority').exists())
        return {'schema':'ouf.acquisition-read-native-terminal-decision.v1','reviewHash':self.core.digest(review),'decision':self.core.DECISION,'approvedAt':int(time.time())}
    def setup_residual(self,prepare=False):
        super().setup_runtime(whole_operator=True)
        original_ports=self.ctx.ports_module.NativePorts
        class HistoricalGuard(original_ports):
            def old_guard(ports,stage):
                if stage=='RENAME_OLD_MCP':
                    # Reproduce the historical exact-Config guard on REAL post-detach bytes.
                    v=ports.container(ports.plan['mcpReplacement']['oldBinding']['containerId'])
                    ports.require(ports.core.digest(v['Config'])==ports.plan['mcpReplacement']['oldBinding']['configHash'],'OLD_MCP_CONFIG_GENERATION_REQUIRED')
                return super().old_guard(stage)
        with patch.object(self.ctx.ports_module,'NativePorts',HistoricalGuard),patch.object(self.core,'terminal_decision',self.terminal):
            with self.assertRaisesRegex(self.core.Stop,'OLD_MCP_CONFIG_GENERATION_REQUIRED'):cont.operator(self.entry,self.ctx)
        prior=self.ctx;h=prior.execution.read_journal();self.assertEqual(h['nextStage'],13);self.assertEqual(len(h['effects']),13);self.assertEqual(h['quarantine']['state'],'APPLIED');self.assertEqual(h['counts'],recovery.COUNTS)
        self.assertFalse(json.loads(self.cli('inspect',self.old['mcp']['Id']))[0]['Config'].get('MacAddress'));self.assertNotIn('MacAddress',json.loads(self.cli('inspect',self.old['mcp']['Id']))[0]['Config'])
        manifest=json.loads((self.code/'sources.json').read_bytes())
        with patch.object(reader,'SOURCE_NAMES',set(manifest)):
            receipt=reader.inspect(reader.Reader(),root=prior.root,code=self.code,inputs_path=self.p.INPUTS,review_hash=self.p.digest(prior.execution.review),authority_hash=self.p.sha(prior.execution.gate.raw),manifest_hash=self.p.sha((self.code/'sources.json').read_bytes()),inputs_hash=prior.proposal['capturedInputsHash'])
        self.prior=prior;self.prior_history=copy.deepcopy(h);self.prior_read_ids={r:v['id']for r,v in h['candidates'].items()};self.prior_generations={r:v['generation']for r,v in h['candidates'].items()}
        self.prior_files={str(p):p.read_bytes()for p in prior.root.rglob('*')if p.is_file()and p.name!='watchdog.log'}
        Parent=recovery.context_class(self.entry)
        class FixtureRecovery(Parent):refresh_authority=type(prior).refresh_authority
        self.recovery_factory=lambda:FixtureRecovery(self.parts,self.auth,self.sign,self.journal,self.closure,original=prior.root,review_hash=self.p.digest(prior.execution.review),journal_hash=self.p.digest(h),receipt_hash=self.p.digest(receipt),evidence_hash=receipt['privateEvidenceHash'],native_path=prior.native_path,native_hash=prior.NATIVE_HASH)
        key_path=prior.proposal['gateway']['transportBinding']['adminKeyBinding']['path'];actual=self.p.private_config
        def forbid_key(path,*args,**kwargs):
            self.assertNotEqual(str(path),key_path,'No credential before exact signed mandate');return actual(path,*args,**kwargs)
        with patch.object(self.p,'private_config',forbid_key):
            ctx=self.recovery_factory();self.ctx=ctx
            if prepare:self.review=recovery.prepare_review(ctx)
        self.execution_root=ctx.root;self.assertIsNone(ctx.key);self.assertEqual(ctx.counts['serviceCredentialFileReads'],2)
        return ctx
    def assert_history_unchanged(self):
        for p,raw in self.prior_files.items():self.assertEqual(Path(p).read_bytes(),raw,p)
        self.assertEqual(self.prior.execution.read_journal(),self.prior_history)
    def test_whole_residual_operator_and_no_replay(self):
        try:
            ctx=self.setup_residual()
            with patch.object(self.core,'terminal_decision',self.terminal):result=recovery.operator(self.entry,ctx)
            h=ctx.execution.read_journal();self.assertTrue(result['complete']);self.assertEqual(h['state'],'COMPLETE');self.assertEqual(len(h['effects']),16)
            self.assertEqual(h['counts']['imageLoadAttempts'],3);self.assertEqual(h['counts']['engineWrites'],22);self.assertEqual(h['counts']['serviceCredentialFileReads'],3);self.assertEqual(h['counts']['adminPuts'],2)
            self.assertEqual({r:h['candidates'][r]['id']for r in('ingestion','udp')},self.prior_read_ids)
            for r in('ingestion','udp'):self.assertNotEqual(h['candidates'][r]['generation'],self.prior_generations[r]);self.assertTrue(h['candidates'][r]['readinessProven'])
            self.assertEqual(len(self.api('GET','/apisix/admin/routes')[1]['list']),84);self.assert_history_unchanged()
            for r in('ingestion','udp','postgres','gateway'):self.assertEqual(self.p.stable_binding(json.loads(self.cli('inspect',self.old[r]['Id']))[0]),ctx.proposal['existingApplications'][r])
            old=json.loads(self.cli('inspect',self.old['mcp']['Id']))[0];ctx.mac.verify_detached(ctx.original_mcp,old,expected_name='/'+ctx.proposal['mcpReplacement']['retiredName'])
            with self.assertRaisesRegex(recovery.Stop,'SCOPE_CONSUMED'):self.recovery_factory()
            self.assertEqual(h,ctx.execution.read_journal());self.assertTrue(list((ctx.root/'authority').glob('*.CREATION_ATTESTATION.json')))
            print(json.dumps({'schema':'ouf.synthetic-detached-residual-ci.v1','complete':True,'retainedAppliedStages':13,'residualAppliedStages':16,'sameOwnedReadIds':True,'freshReadGenerationsAndReadiness':True,'noReplayNoReimportNoReadCreate':True,'cumulativeWrites':22,'cumulativeCredentialReads':3,'oldHistoryUnchanged':True,'legacyConfigMacActuallyAbsent':True,'productionRuntimeAccess':False}),flush=True)
        finally:self.teardown_runtime()
    def test_rejected_review_has_no_new_credential_or_effect(self):
        try:
            ctx=self.setup_residual();before={r:json.loads(self.cli('inspect',cid))[0]['State']for r,cid in self.prior_read_ids.items()}
            def rejected(*_):raise self.core.Stop('EXACT_ACQUISITION_REVIEW_NOT_APPROVED')
            with patch.object(self.core,'terminal_decision',rejected):
                with self.assertRaisesRegex(self.core.Stop,'NOT_APPROVED'):recovery.operator(self.entry,ctx)
            self.assertIsNone(ctx.key);self.assertEqual(ctx.counts['serviceCredentialFileReads'],2);self.assertEqual(ctx.counts['engineWrites'],14);self.assertFalse((ctx.root/'authority').exists());self.assertFalse((ctx.root/'recovery.json').exists());self.assert_history_unchanged()
            for r,cid in self.prior_read_ids.items():self.assertEqual(json.loads(self.cli('inspect',cid))[0]['State'],before[r])
            with self.assertRaisesRegex(recovery.Stop,'SCOPE_CONSUMED'):self.recovery_factory()
        finally:self.teardown_runtime()
    def test_lost_controller_quarantines_adopted_reads_and_new_mcp(self):
        child=None
        try:
            ctx=self.setup_residual(prepare=True);gate=self.issue();ports=recovery.ports_class(ctx.ports_module)(ctx,self.review,gate);e=self.core.Execution(gate,self.journal.Journal(ctx.root),ports);e.initialize();ctx.execution=e
            r,w=os.pipe();child=os.fork()
            if child==0:
                try:
                    os.close(r);ctx.watch.launch(ctx,self.review,gate,e.journal);execute=ports.execute
                    def paused(stage):
                        if stage=='ADD_INGESTION_ROUTE':os.write(w,b'READY');signal.pause();raise AssertionError('Lost controller resumed')
                        return execute(stage)
                    ports.execute=paused;e.run();os._exit(3)
                except BaseException:os._exit(4)
            os.close(w)
            try:
                ready,_,_=select.select([r],[],[],180);self.assertTrue(ready,'Residual controller did not reach MCP readiness');self.assertEqual(os.read(r,16),b'READY');os.kill(child,signal.SIGKILL);os.waitpid(child,0);child=None
                for _ in range(160):
                    h=e.read_journal()
                    if h['quarantine']and h['quarantine']['state']=='APPLIED':break
                    time.sleep(.25)
                else:raise AssertionError('Residual negative watchdog failed')
                self.assertEqual(h['state'],'STOP_RECONCILE');self.assertEqual(h['counts']['quarantineStops'],5);self.assertLessEqual(h['counts']['engineWrites'],28);self.assertEqual(set(h['quarantine']['candidates']),{'ingestion','udp','mcp'})
                for c in h['candidates'].values():
                    v=json.loads(self.cli('inspect',c['id']))[0];self.assertFalse(v['State']['Running']);self.assertEqual(v['HostConfig']['RestartPolicy'],{'Name':'no','MaximumRetryCount':0})
                self.assertEqual(len(self.api('GET','/apisix/admin/routes')[1]['list']),82);self.assert_history_unchanged()
                for role in('ingestion','udp','postgres','gateway'):self.assertEqual(self.p.stable_binding(json.loads(self.cli('inspect',self.old[role]['Id']))[0]),ctx.proposal['existingApplications'][role])
                self.assertFalse(json.loads(self.cli('inspect',self.old['mcp']['Id']))[0]['State']['Running']);snapshot=copy.deepcopy(h)
                with self.assertRaises(self.core.Stop):e.run()
                self.assertEqual(snapshot,e.read_journal())
                print(json.dumps({'schema':'ouf.synthetic-detached-residual-negative-ci.v1','complete':True,'ownedCandidatesQuarantined':3,'cumulativeQuarantineStops':5,'oldMcpRemainsStopped':True,'otherOriginalOwnersUnchanged':True,'retainedHistoryUnchanged':True,'automaticReplayAllowed':False,'productionRuntimeAccess':False}),flush=True)
            finally:os.close(r)
        finally:
            if child:
                try:os.kill(child,signal.SIGKILL);os.waitpid(child,0)
                except ProcessLookupError:pass
            self.teardown_runtime()
if __name__=='__main__':
    suite=unittest.TestSuite(DetachedRecovery(n)for n in('test_whole_residual_operator_and_no_replay','test_rejected_review_has_no_new_credential_or_effect','test_lost_controller_quarantines_adopted_reads_and_new_mcp'));r=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(0 if r.wasSuccessful()else 1)
