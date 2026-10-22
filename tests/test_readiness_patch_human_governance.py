"""Real root-private claims and immutable old292 session; synthetic provider.

Runtime preflight and terminal answers are explicit unit fakes. Actual sealed
delivery/TTY and platform generations remain separate integration boundaries.
"""
import copy
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_readiness_patch_operator_control as runtime_fixture
import test_stage18_successor as old_fixture
from tools.ingestion_readiness_patch_execution import human_governance as g,operator_control as runtime,entry as e
from tools.governed_human_successor import operator,window
from tools.governed_human_successor.session import ExplicitFreshSession
from tools.chatbot_file_cohort.human_session import HumanSession
from test_ingestion_rollout_gateway_transport import binding as seal
REAL_PREFLIGHT=g.live_preflight


def expired_previous(self):
    self.old=old_fixture.Fixture();self.old.setUp();self.addCleanup(self.old.doCleanups)
    boot=patch.object(HumanSession,'_boot',return_value=self.old.boot);boot.start();self.addCleanup(boot.stop)
    self.old.open();self.oldcontrol=Path(self.old.control)
    config=json.loads((self.oldcontrol/'control.json').read_bytes())
    b=json.loads((self.oldcontrol/'binding.json').read_bytes());now=int(time.time())
    b.update(createdAt=now-14400,expiresAt=now-7200)
    decision=config['decision'];decision.update(approvedAt=b['createdAt'],expiresAt=b['expiresAt'])
    oldrow=e.Journal(b['sessionDirectory']).read()
    oldrow.update(binding=b,state='READY',attempts=292,monotonicDeadline=time.monotonic()-60,
        lastObservedAt=now-7200,accessExpiresAt=now-7300,
        governedWindowRenewal={'review':config['review'],'decision':decision},
        accessToken='PRIVATE_OLD_TOKEN_NEVER_REUSE',refreshToken='PRIVATE_OLD_REFRESH_NEVER_REUSE')
    self.old.write(Path(b['sessionDirectory'])/'recovery.json',oldrow)
    self.old.write(self.oldcontrol/'control.json',config);self.old.write(self.oldcontrol/'binding.json',b)
    claim=Path(config['review']['predecessorDirectory'])/'successor-window.claim.json'
    fence=json.loads(claim.read_bytes());fence.update(decisionHash=e.c.digest(decision),expiresAt=b['expiresAt'])
    self.old.write(claim,fence)
    self.old_profile={'schema':e.human_reader.SCHEMA,'selection':config['selection'],'expectedBinding':b,
        'journal':seal(Path(b['sessionDirectory'])/'recovery.json'),'minimumCumulativeAttempts':292,
        'maximumCumulativeAttempts':292,'expectedBootId':oldrow['bootId'],
        'expectedMonotonicDeadline':oldrow['monotonicDeadline'],
        'governedWindowReceiptHash':e.c.digest(oldrow['governedWindowRenewal']),
        'readOnly':True,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False}
    self.old.write(self.oldcontrol/'human-read-profile.json',self.old_profile)
    self.oldbytes=(Path(b['sessionDirectory'])/'recovery.json').read_bytes()
    return config

@unittest.skipUnless(os.environ.get('OUF_NATIVE_UIDS')=='1','real root journal custody required')
class Governance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):runtime_fixture.OperatorControl.setUpClass()
    def setUp(self):
        self.r=runtime_fixture.OperatorControl();self.r.setUp();self.addCleanup(self.r.doCleanups)
        config=expired_previous(self)
        self.case={'schema':g.SCHEMA,'purpose':'EXACT_RETAINED_INSTALLATION_NOT_PORTABLE_DEFAULT',
            'runtimeCase':copy.deepcopy(self.r.case),'nativeDeclaration':copy.deepcopy(self.r.manifest),
            'predecessorControlPath':str(self.oldcontrol),'predecessorReviewHash':e.c.digest(config['review']),
            'humanOperatorTransportProfile':dict(operator.TRANSPORT),
            'governanceSourceHash':hashlib.sha256((ROOT/'tools/ingestion_readiness_patch_execution/human_governance.py').read_bytes()).hexdigest()}
        self.closure='b'*64;self.patches=[]
        for obj,name,value in ((g,'__qualified_source_sha256__',self.case['governanceSourceHash']),
                              (runtime,'__qualified_source_sha256__',self.r.control_hash)):
            p=patch.object(obj,name,value,create=True);p.start();self.addCleanup(p.stop)
        probe=patch.object(g,'live_preflight',return_value={'complete':True,'engineRequests':12,
            'maximumEngineRequests':12,'humanCredentialJournalsRead':0,'status':'PATCH_HUMAN_RUNTIME_PREFLIGHT_NO_WINDOW_OR_BUDGET'})
        self.probe=probe.start();self.addCleanup(probe.stop)
    def call(self,mode,selected=None):return g.execute(mode,selected,self.case,{},self.closure)
    def grant(self):
        with patch.object(operator,'terminal_confirm',return_value=True):return self.call('grant-budget')
    def open(self):
        self.grant()
        with patch.object(operator,'terminal_confirm',return_value=True):result=self.call('open-window')
        self.control=result['controlPath'];return result
    def session(self):
        self.open();confirmed,cfg,b=g.load(self.control,self.case,self.closure)
        return ExplicitFreshSession(cfg['selection'],b,cfg['review'],cfg['decision'])
    def test_prepare_and_budget_never_open_old_credential_or_issue_runtime(self):
        before=set(self.r.root.rglob('*'))
        with (patch.object(e.authority.private_file,'read',side_effect=AssertionError('credential read forbidden')),
             patch.object(e.authority,'issue_action')as issue,patch.object(ExplicitFreshSession,'_http')as http):
            result=self.call('prepare');self.assertFalse(result['newBudgetGranted'])
            self.assertEqual(before,set(self.r.root.rglob('*')))
            result=self.grant();self.assertEqual(result['maximumCumulativeOAuthAttempts'],296)
            self.assertFalse(result['newHumanWindowOpened']);self.assertFalse(result['runtimeAuthorityIssued'])
            issue.assert_not_called();http.assert_not_called()
        self.assertEqual(self.oldbytes,Path(self.old_profile['journal']['path']).read_bytes())
    def test_grant_is_one_use_and_partial_claim_never_reopens(self):
        original=g.publish
        def fail(folder,name,value):
            original(folder,name,value)
            if name=='patch-oauth-budget-292.claim.json':raise OSError('synthetic after fence')
        with patch.object(g,'publish',side_effect=fail),self.assertRaises(OSError):self.grant()
        with patch.object(operator,'terminal_confirm')as tty,self.assertRaises(Exception):self.call('grant-budget')
        tty.assert_not_called()
        with self.assertRaises(Exception):self.call('budget-status')
    def test_window_preserves_old292_and_never_copies_credentials_or_opens_twice(self):
        opened=self.open();self.assertEqual(opened['attempts'],292)
        _,cfg,b=g.load(self.control,self.case,self.closure);row=e.Journal(b['sessionDirectory']).read()
        self.assertEqual(row['attempts'],292);self.assertEqual(b['retryProfile']['maximumAttempts'],296)
        self.assertNotIn('accessToken',row);self.assertNotIn('refreshToken',row)
        self.assertEqual(cfg['review']['operationBinding'],g.operation(self.case))
        self.assertEqual(self.oldbytes,Path(self.old_profile['journal']['path']).read_bytes())
        with patch.object(operator,'terminal_confirm')as tty,self.assertRaises(Exception):self.call('open-window')
        tty.assert_not_called()
        self.assertEqual(self.call('status',self.control)['attempts'],292)
    def test_partial_window_and_concurrent_grants_keep_global_predecessor_fences(self):
        self.grant()
        with patch.object(operator,'terminal_confirm',return_value=True),patch.object(operator,'write_new',side_effect=OSError('synthetic')):
            with self.assertRaises(OSError):self.call('open-window')
        with patch.object(operator,'terminal_confirm')as tty,self.assertRaises(Exception):self.call('open-window')
        tty.assert_not_called()
    def test_two_processes_cannot_grant_a_parallel_budget(self):
        ctx=multiprocessing.get_context('fork');barrier=ctx.Barrier(2);q=ctx.Queue()
        def worker():
            def confirm(*_):barrier.wait(timeout=5);return True
            try:
                with patch.object(operator,'terminal_confirm',side_effect=confirm):self.call('grant-budget')
                q.put('granted')
            except Exception:q.put('blocked')
        children=[ctx.Process(target=worker)for _ in range(2)]
        for child in children:child.start()
        for child in children:child.join(10);self.assertFalse(child.is_alive())
        self.assertEqual(sorted(q.get(timeout=2)for _ in children),['blocked','granted'])
    def test_exact_four_manual_requests_reach296_and_publish_bound_patch_reader(self):
        session=self.session();issuer=self.old.selection['issuer']
        responses=[(200,{'issuer':issuer,**{k:issuer+'/protocol/openid-connect/'+k for k in
            ('device_authorization_endpoint','token_endpoint','userinfo_endpoint')}},0),
            (200,{'verification_uri':issuer+'/device','user_code':'FIXTURE','device_code':'PRIVATE','expires_in':600,'interval':5},0),
            (200,{'access_token':self.old.token(),'refresh_token':'PRIVATE_NEW_REFRESH','token_type':'Bearer'},0),
            (200,{'sub':self.old.selection['subject']},0)]
        with patch.object(operator,'terminal_confirm',return_value=True),patch.object(ExplicitFreshSession,'_http',side_effect=responses)as http:
            self.assertEqual(self.call('step',self.control)['attempts'],293)
            self.assertEqual(self.call('step',self.control)['attempts'],294)
            row=session.journal.read();session.journal.compare_and_save(row,{**row,'nextPollAt':time.time()-1})
            self.assertEqual(self.call('step',self.control)['attempts'],295)
            ready=self.call('step',self.control);self.assertEqual(ready['attempts'],296)
            self.assertTrue(ready['productionTokenMarginCovered']);self.assertEqual(http.call_count,4)
        profile=g.custody.read(ready['privateHumanReadProfilePath'])
        h=runtime.human(e,self.r.case,profile);self.assertEqual(h.current(),session.expected_binding)
        self.assertEqual(self.oldbytes,Path(self.old_profile['journal']['path']).read_bytes())
    def test_pending_poll_preserves_userinfo_reserve_and_lost_start_cannot_replay(self):
        session=self.session();issuer=self.old.selection['issuer'];session._http=Mock(return_value=(200,
            {'issuer':issuer,**{k:issuer+'/protocol/openid-connect/'+k for k in
            ('device_authorization_endpoint','token_endpoint','userinfo_endpoint')}},0))
        session.step();session._http.side_effect=OSError('synthetic lost start')
        with self.assertRaises(Exception):session.step()
        self.assertEqual(session.journal.read()['attempts'],294);calls=session._http.call_count
        with self.assertRaises(Exception):session.step()
        self.assertEqual(session._http.call_count,calls)
    def test_changed_source_old_count_or_case_blocks_before_consent(self):
        for key,value in [('predecessorReviewHash','f'*64),('governanceSourceHash','f'*64)]:
            original=self.case[key];self.case[key]=value
            with patch.object(operator,'terminal_confirm')as tty,self.assertRaises(Exception):self.call('grant-budget')
            tty.assert_not_called();self.case[key]=original
        self.old_profile['minimumCumulativeAttempts']=288
        self.old.write(self.oldcontrol/'human-read-profile.json',self.old_profile)
        with self.assertRaises(Exception):self.call('prepare')
    def test_real_preflight_predicates_bound_twelve_gets_and_detect_generation_drift(self):
        import test_ingestion_rollout_database_read as db_fixture
        b=copy.deepcopy(self.r.bundle);before=b['beforeIngestion'];rows={before['Id']:before}
        for name,pin in b['unchangedApplications'].items():
            actual=copy.deepcopy(before);actual.update(Id=pin['binding']['containerId'],Name='/'+name);rows[actual['Id']]=actual
        empty=self.r.root/'preflight-empty';empty.mkdir(mode=0o700)
        _,pg=db_fixture.fixture_profile(empty);pg.update(Id='f'*64,Name='/postgres');rows[pg['Id']]=pg
        gets=[]
        def container(cid):gets.append(cid);return copy.deepcopy(rows[cid])
        with patch.object(g,'Engine'),patch.object(g,'EngineReader')as reader:
            reader.return_value.container.side_effect=container
            result=REAL_PREFLIGHT(self.case);self.assertEqual(result['engineRequests'],12)
            self.assertEqual(len(gets),12);self.assertFalse(result['databaseAdmissionProven'])
            rows[before['Id']]['State']['Pid']+=1
            with self.assertRaisesRegex(Exception,'GENERATION_CHANGED'):REAL_PREFLIGHT(self.case)
    def test_new_human_capsule_is_deterministic_and_uses_exact_frozen_core(self):
        from tools.ingestion_readiness_patch_execution import human_delivery as d,operator_delivery as rd
        _,manifest=rd.core(ROOT);case=copy.deepcopy(self.case);case['nativeDeclaration']=manifest
        case['runtimeCase']['nativeDeclarationHash']=e.c.digest(manifest)
        raw,declaration=d.generate(ROOT,case)
        self.assertEqual(raw,d.generate(ROOT,case)[0]);self.assertLess(len(raw),1048576)
        self.assertEqual(declaration['entryModule'],g.__name__)
        self.assertIn('FINITE_PATCH_HUMAN_INVOCATION_DEADLINE',d.BOOTSTRAP)
        case['governanceSourceHash']='f'*64
        with self.assertRaisesRegex(ValueError,'GOVERNANCE_SOURCE'):d.generate(ROOT,case)

if __name__=='__main__':unittest.main()
