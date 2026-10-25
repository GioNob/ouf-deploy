import copy,importlib.util,os,time,unittest
from pathlib import Path
from unittest.mock import patch
BASE=Path(__file__).resolve().parents[1]
def module(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
fixture=module('residual_protocol_fixture',BASE/'tests/test_acquisition_apply_protocol.py')
recovery=module('residual_entry_fixture',BASE/'scripts/recover-acquisition-detached-mcp-20261025.py')
@unittest.skipUnless(os.environ.get('OUF_APPLY_ROOT_FIXTURE')=='1','dedicated root fixture required')
class ResidualProtocol(unittest.TestCase):
    setUp=fixture.Protocol.setUp
    tearDown=fixture.Protocol.tearDown
    write=fixture.Protocol.write
    read=fixture.Protocol.read
    issue=fixture.Protocol.issue
    def review_residual(self):
        c=self.core;oldroot=self.root/'old';oldroot.mkdir(mode=0o700);new=oldroot/recovery.CHILD;new.mkdir(mode=0o700);self.execution_root=new
        p={'profile':'LEGACY_CONFIG_MAC_ABSENT_ONLY_AFTER_PROVEN_STOP_AND_DETACH_V1'}
        r={'originalExecutionRoot':str(oldroot),'originalReviewHash':'1'*64,'journalHash':'2'*64,'diagnosticReceiptHash':'3'*64,'privateEvidenceHash':'4'*64,'retainedCounts':copy.deepcopy(recovery.COUNTS),'retainedMaximums':copy.deepcopy(c.CONTINUATION_LIMITS),'retainedAppliedStages':13,'retainedQuarantineApplied':True,'adoptedIds':{'ingestion':'a'*64,'udp':'b'*64},'legacyMacPolicy':p,'newPositiveWritesMaximum':8,'newNegativeWritesMaximum':6,'additionalCredentialFileReadsMaximum':1,'noOriginalStageReplay':True}
        self.review.update(schema='ouf.acquisition-detached-mcp-recovery-review.v1',executionRoot=str(new),recovery=r,maximums=copy.deepcopy(c.RECOVERY_LIMITS),stages=list(c.RECOVERY_STAGES),preflightCounts=copy.deepcopy(recovery.COUNTS));self.review['nativePlan'].update(recovery=r,legacyConfigMacDetachPolicy=p);self.review['nativePlanHash']=c.digest(self.review['nativePlan']);return self.review
    def test_exact_profile_preserves_cumulative_counts_and_forbids_old_stages(self):
        r=self.review_residual();self.core.validate_review(r)
        for stage in r['stages']:self.assertFalse(stage.startswith('IMPORT_')or stage.startswith('CREATE_')and stage!='CREATE_MCP'or stage in('STOP_OLD_MCP','DETACH_OLD_MCP'))
        self.assertEqual(r['maximums']['imageLoadAttempts'],3);self.assertEqual(r['recovery']['retainedCounts']['engineWrites'],14)
    def test_residual_real_tty_discloses_cumulative_mandate_and_exact_command(self):
        self.review_residual();fixture.Protocol.test_tty_requires_the_exact_current_review_hash(self)
    def test_wrong_adoption_or_budget_or_reset_denied(self):
        good=copy.deepcopy(self.review_residual())
        for key,value in(('noOriginalStageReplay',False),('adoptedIds',{'ingestion':'a'*64,'udp':'a'*64}),('retainedAppliedStages',12),('retainedQuarantineApplied',False),('newNegativeWritesMaximum',0),('retainedCounts',{**recovery.COUNTS,'imageLoadAttempts':0})):
            r=copy.deepcopy(good);r['recovery'][key]=value;r['nativePlan']['recovery']=r['recovery'];r['nativePlanHash']=self.core.digest(r['nativePlan'])
            with self.assertRaises(self.core.Stop):self.core.validate_review(r)
        r=copy.deepcopy(good);r['preflightCounts']['engineWrites']=0
        with self.assertRaises(self.core.Stop):self.core.validate_review(r)
        r=copy.deepcopy(good);r['maximums']['engineWrites']=500
        with self.assertRaises(self.core.Stop):self.core.validate_review(r)
    def test_real_signatures_seed_only_signed_owned_candidates_no_counter_reset(self):
        self.review_residual();outer=self
        class Ports:
            root=outer.execution_root
            ctx=type('C',(),{'counts':copy.deepcopy(recovery.COUNTS)})()
            def initial_candidates(self):return{r:{'id':cid,'configurationVerified':True,'generation':None,'readinessProven':False}for r,cid in outer.review['recovery']['adoptedIds'].items()}
        gate=self.issue();e=self.core.Execution(gate,self.journal.Journal(self.execution_root),Ports());e.initialize();h=e.record();self.assertEqual(h['counts'],recovery.COUNTS);self.assertEqual(set(h['candidates']),{'ingestion','udp'});self.assertEqual(h['nextStage'],0)
        with self.assertRaises(Exception):e.initialize()
        self.assertEqual(h,e.record())
    def test_only_exact_claimed_adopted_start_allowed(self):
        self.review_residual();outer=self
        class Base:
            def assert_write(self,*_):raise outer.core.Stop('NOT_A_RESIDUAL_RESTART')
        from types import SimpleNamespace
        p=recovery.ports_class(SimpleNamespace(NativePorts=Base))();p.review=self.review;p.stages=self.core.RECOVERY_STAGES;p.require=self.core.require
        row={'nextStage':2,'effects':[{'state':'APPLIED'},{'state':'APPLIED'},{'state':'CLAIMED'}]};p.execution=type('E',(),{'record':lambda _:row})()
        exact='/v1.44/containers/'+self.review['recovery']['adoptedIds']['ingestion']+'/start';p.assert_write(exact,None)
        for path in('/v1.44/containers/'+('f'*64)+'/start',exact.replace('/start','/stop?t=2')):
            with self.assertRaises(self.core.Stop):p.assert_write(path,None)
        row['effects'][-1]['state']='APPLIED'
        with self.assertRaises(self.core.Stop):p.assert_write(exact,None)
    def test_unverified_bootstrap_never_executes_base(self):
        path=self.code/'apply.py';original=path.read_bytes();path.chmod(0o600);path.write_bytes(b"raise AssertionError('unverified source executed')\n");path.chmod(0o400)
        # recovery.__file__ must be the staged exact entry so the manifest check is real.
        with patch.object(recovery,'__file__',str(self.code/'recovery.py')):
            with self.assertRaisesRegex(recovery.Stop,'EXACT_RECOVERY_BASE_SOURCE_REQUIRED'):recovery.base_module(self.code)
        path.chmod(0o600);path.write_bytes(original);path.chmod(0o400)
    def test_preapproval_reserves_no_credential_or_mutation_budget(self):
        Parent=recovery.context_class(self.entry);ctx=object.__new__(Parent);ctx.execution=None;ctx.core=self.core;ctx.counts=copy.deepcopy(recovery.COUNTS);ctx.evidence=lambda *_:None
        for kind in('serviceCredentialFileReads','engineWrites','adminGets','imageLoadAttempts','quarantineStops'):
            before=copy.deepcopy(ctx.counts)
            with self.assertRaises(recovery.Stop):ctx.reserve(kind)
            self.assertEqual(ctx.counts,before)
        ctx.reserve('engineGets');self.assertEqual(ctx.counts['engineGets'],129)
if __name__=='__main__':unittest.main()
