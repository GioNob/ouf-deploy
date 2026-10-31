"""Actual continuation Context+operator ports on synthetic owners and CI-only keys."""
import copy,importlib.util,json,os,subprocess,unittest
from pathlib import Path
from unittest.mock import patch
BASE=Path(__file__).resolve().parents[1]
def module(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
native=module('native_fixture',BASE/'tests/qualify_acquisition_apply_engine.py')
cont=module('continuation_fixture',BASE/'scripts/continue-acquisition-unapproved-review-20261025.py')
class Continuation(native.EngineLifecycle):
    def setup_runtime(self,launch_watchdog=True,whole_operator=False):
        super().setup_runtime(launch_watchdog=False,prepare_only=True)
        old=self.ctx;self.original_root=old.root
        self.assertEqual(old.counts,self.core.RETAINED_COUNTS);self.assertFalse((old.root/'authority').exists());self.assertFalse((old.root/'recovery.json').exists())
        original_files={str(p):p.read_bytes()for p in old.root.iterdir()if p.is_file()};self.original_files=original_files
        receipt={'schema':'ouf.acquisition-unapproved-review-reconciliation.v1','status':'UNAPPROVED_ACQUISITION_REVIEW_RECONCILED_NO_AUTHORITY','complete':True,'reviewHash':self.p.digest(self.review),'nativeInputsHash':old.NATIVE_HASH,'originalAuthorityAndJournalAbsent':True,'retainedClaimsProveNoRuntimeEffectsDispatched':True,'originalScopeConsumed':True,'continuationAuthorized':False,'retainedPreflightCounts':self.core.RETAINED_COUNTS,'retainedMaximums':self.core.LIMITS}
        child=old.root/'unapproved-review-reconciliation-v1';child.mkdir(mode=0o700);self.p.put(child/'complete.json',receipt)
        Parent=cont.context_class(self.entry)
        class FixtureContinuation(Parent):refresh_authority=type(old).refresh_authority
        actual_private_config=self.p.private_config;blocked=[]
        key_path=old.proposal['gateway']['transportBinding']['adminKeyBinding']['path']
        def no_key_before_approval(path,*args,**kwargs):
            if str(path)==key_path:blocked.append(True);raise AssertionError('Credential read before terminal mandate')
            return actual_private_config(path,*args,**kwargs)
        with patch.object(self.p,'private_config',no_key_before_approval):
            ctx=FixtureContinuation(self.parts,self.auth,self.sign,self.journal,self.closure,original=old.root,review_hash=self.p.digest(self.review),receipt_hash=self.p.digest(receipt),native_path=old.native_path,native_hash=old.NATIVE_HASH)
            review=None if whole_operator else cont.prepare_review(ctx)
        self.assertEqual(blocked,[]);self.assertIsNone(ctx.key);self.assertEqual(ctx.counts['serviceCredentialFileReads'],1);self.assertFalse((ctx.root/'authority').exists())
        self.assertEqual(self.original_files,{str(p):p.read_bytes()for p in old.root.iterdir()if p.is_file()})
        self.ctx=ctx;self.execution_root=ctx.root
        if whole_operator:return
        self.review=review;gate=self.issue();ports=ctx.ports_module.NativePorts(ctx,review,gate);execution=self.core.Execution(gate,self.journal.Journal(ctx.root),ports);execution.initialize();ctx.execution=execution
        self.gate,self.native_ports,self.execution=gate,ports,execution
        if launch_watchdog:ctx.watch.launch(ctx,review,gate,execution.journal)
    def test_real_native_lifecycle_and_additive_routes(self):
        try:
            self.setup_runtime(whole_operator=True)
            def fixture_terminal_decision(review,path):
                # CI-only synthetic HUMAN decision; real PTY parser tested separately.
                self.assertIsNone(self.ctx.key);self.assertEqual(self.ctx.counts['serviceCredentialFileReads'],1);self.assertFalse((self.ctx.root/'authority').exists());self.assertTrue(path.exists())
                import time
                return {'schema':'ouf.acquisition-read-native-terminal-decision.v1','reviewHash':self.core.digest(review),'decision':self.core.DECISION,'approvedAt':int(time.time())}
            with patch.object(self.core,'terminal_decision',fixture_terminal_decision):result=cont.operator(self.entry,self.ctx)
            self.execution=self.ctx.execution;self.review=self.execution.review;row=self.execution.read_journal()
            self.assertTrue(result['complete']);self.assertEqual(row['state'],'COMPLETE');self.assertEqual(len(row['effects']),24);self.assertEqual(row['effects'][0]['stage'],'LOAD_EXISTING_ADMIN_KEY');self.assertEqual(row['counts']['serviceCredentialFileReads'],2)
            self.assertEqual(len(self.api('GET','/apisix/admin/routes')[1]['list']),84)
            for role in('ingestion','udp','postgres','gateway'):self.assertEqual(self.p.stable_binding(json.loads(self.cli('inspect',self.old[role]['Id']))[0]),self.ctx.proposal['existingApplications'][role])
            self.assertFalse(json.loads(self.cli('inspect',self.old['mcp']['Id']))[0]['State']['Running']);self.assertTrue((self.ctx.root/'result.json').exists());self.assertTrue(list((self.ctx.root/'authority').glob('*.CREATION_ATTESTATION.json')))
            self.assertEqual(self.original_files,{str(p):p.read_bytes()for p in self.original_root.iterdir()if p.is_file()});self.assertFalse((self.original_root/'authority').exists());self.assertFalse((self.original_root/'recovery.json').exists())
            print(json.dumps({'schema':'ouf.synthetic-reconciled-acquisition-continuation-ci.v1','complete':True,'realContinuationContextAndWholeOperator':True,'syntheticTerminalDecisionPtyQualifiedSeparately':True,'initialCountsRetained':True,'additionalCredentialReadAfterSignedClaimOnly':True,'cumulativeCredentialReads':2,'oldUnapprovedScopeUnchanged':True,'stagesApplied':24,'productionRuntimeAccess':False}),flush=True)
        finally:self.teardown_runtime()
if __name__=='__main__':
    suite=unittest.TestSuite([Continuation('test_real_native_lifecycle_and_additive_routes'),Continuation('test_killed_controller_quarantines_only_uncommitted_candidates')]);result=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(0 if result.wasSuccessful()else 1)
