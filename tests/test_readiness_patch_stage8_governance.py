"""Real root-private claims and immutable old300 session; synthetic provider.

Runtime preflight and terminal answers are explicit unit fakes. Actual sealed
delivery/TTY and platform generations remain separate integration boundaries.
"""
import base64
import copy
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import sys
import time
import types
import unittest
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_readiness_patch_stage8_continuation as runtime_fixture
from tools.ingestion_readiness_patch_execution import stage8_human as g,stage8_continuation as runtime,entry_v2 as e
from tools.governed_human_successor import operator,window
from tools.governed_human_successor.session import ExplicitFreshSession
from tools.chatbot_file_cohort.human_session import HumanSession
from test_ingestion_rollout_gateway_transport import binding as seal
REAL_PREFLIGHT=g.live_preflight


def expired_previous(self):
    # Entire predecessor is an explicit synthetic fixture, constructed without
    # importing any old stage18 runtime, grant or completed rollout operation.
    clean={k:v for k,v in os.environ.items()if k.lower()not in
        ('ssl_cert_file','ssl_cert_dir','https_proxy','http_proxy','all_proxy')}
    env=patch.dict(os.environ,clean,clear=True);env.start();self.addCleanup(env.stop)
    root=self.r.root if hasattr(self,'r')else self.root
    parent=root/'old-human-lineage';parent.mkdir(mode=0o700)
    previous=parent/'expired-296';previous.mkdir(mode=0o700)
    now=int(time.time())
    try:boot=window.boot_id()
    except FileNotFoundError:
        boot='synthetic-local-boot'
        pin=patch.object(window,'boot_id',return_value=boot);pin.start();self.addCleanup(pin.stop)
    pin=patch.object(HumanSession,'_boot',return_value=boot);pin.start();self.addCleanup(pin.stop)
    selection={'issuer':'https://fixture.invalid/realm','subject':'fixture-human','tenant':'fixture-tenant'}
    history={'minimumRetainedOAuthAttempts':296,'maximumCumulativeOAuthAttempts':300,
        'ownerPlanHash':'1'*64,'completedResultHash':'2'*64}
    review={'schema':g.contract.SCHEMA,'predecessorDirectory':str(previous),
        'predecessorPublicHistoryHash':'a'*64,'predecessorBindingHash':'b'*64,
        'selectionHash':e.c.digest(selection),'bootId':boot,'priorOAuthAttempts':296,
        'maximumCumulativeOAuthAttempts':300,'maximumRemainingOAuthAttempts':4,
        'requestedScopes':list(g.contract.SCOPES),'newWindowSeconds':7200,'retainedOwnerHistory':history,
        'operationBinding':{'stage18CaseHash':'c'*64},'sourceClosureHash':'d'*64,
        'predecessorWindowExpiresAt':now-18000,'freshIssuerAuthenticationRequired':True,
        'oldCredentialsReusable':False,'oldRefreshReplayAllowed':False,'browserConfirmationPerPollRequired':True,
        'automaticRenewalAllowed':False,'automaticReplayAllowed':False,'budgetReset':False,'runtimeAuthorityIssued':False}
    g.contract.validate_review(review)
    self.oldcontrol=operator.control_path(review);self.oldcontrol.mkdir(mode=0o700)
    session=operator.successor_path(review);session.mkdir(mode=0o700)
    from tools.chatbot_file_cohort.human_session import PROFILE,CLIENT
    b={'sessionId':'synthetic-exhausted300',**selection,'selectionHash':e.c.digest(selection),
        'clientId':CLIENT,'scopes':list(g.contract.SCOPES),'sessionDirectory':str(session),
        'tokenPath':str(session/'human-access.jwt'),'createdAt':now-14400,'expiresAt':now-7200,
        'retryProfile':{**copy.deepcopy(PROFILE),'id':'fixture300','maximumAttempts':300}}
    decision={'schema':'ouf.human-login-window-terminal-consent.v1','reviewHash':e.c.digest(review),
        'decision':'OPEN_ONE_LOGIN_WINDOW_NO_RUNTIME_AUTHORITY','approvedAt':b['createdAt'],'expiresAt':b['expiresAt']}
    oldrow={'schema':'ouf.chatbot-human-session.private.v1','binding':b,'state':'READY','attempts':300,
        'monotonicDeadline':time.monotonic()-60,'lastObservedAt':now-7200,'accessExpiresAt':now-7304,
        'governedWindowRenewal':{'review':review,'decision':decision},'bootId':boot,'budgetReset':False,
        'accessToken':'PRIVATE_OLD_TOKEN_NEVER_REUSE','refreshToken':'PRIVATE_OLD_REFRESH_NEVER_REUSE'}
    e.Journal(session).initialize(oldrow)
    def write(path,value):path.write_bytes(e.c.encoded(value));path.chmod(0o600)
    config={'schema':operator.CONFIG_SCHEMA,'review':review,'decision':decision,'selection':selection,'history':history,
        'predecessorJournal':seal(session/'recovery.json'),'sourceClosureHash':'d'*64,
        'controlDirectory':str(self.oldcontrol),'case':{'humanOperatorTransportProfile':dict(operator.TRANSPORT)},'confirmedRead':{}}
    write(self.oldcontrol/'control.json',config);write(self.oldcontrol/'binding.json',b)
    write(previous/'successor-window.claim.json',{'schema':'ouf.human-explicit-successor-claim.v1',
        'reviewHash':e.c.digest(review),'decisionHash':e.c.digest(decision),'destination':str(session),
        'priorOAuthAttempts':296,'maximumCumulativeOAuthAttempts':300,'expiresAt':b['expiresAt'],
        'automaticReplayAllowed':False,'budgetReset':False,'runtimeAuthorityIssued':False})
    self.old_profile={'schema':e.human_reader.SCHEMA,'selection':selection,'expectedBinding':b,
        'journal':seal(session/'recovery.json'),'minimumCumulativeAttempts':300,'maximumCumulativeAttempts':300,
        'expectedBootId':boot,'expectedMonotonicDeadline':oldrow['monotonicDeadline'],
        'governedWindowReceiptHash':e.c.digest(oldrow['governedWindowRenewal']),
        'readOnly':True,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False}
    write(self.oldcontrol/'human-read-profile.json',self.old_profile)
    self.oldbytes=(session/'recovery.json').read_bytes()
    def token(**changes):
        claims={'iss':selection['issuer'],'sub':selection['subject'],'tenant_id':selection['tenant'],
            'ouf_actor_type':'HUMAN','azp':CLIENT,'aud':'ouf-api-gateway','scope':' '.join(g.contract.SCOPES),
            'iat':int(time.time()),'exp':int(time.time())+1200,'acr':'fixture-only',**changes}
        return 'fixture.'+base64.urlsafe_b64encode(e.c.encoded(claims)).decode().rstrip('=')+'.fixture'
    self.old=types.SimpleNamespace(selection=selection,boot=boot,write=write,token=token)
    return config

@unittest.skipUnless(os.environ.get('OUF_NATIVE_UIDS')=='1','real root journal custody required')
class Stage8Governance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):runtime_fixture.Continuation.setUpClass()
    def setUp(self):
        self.r=runtime_fixture.Continuation();self.addCleanup(self.r.doCleanups);self.r.setUp()
        config=expired_previous(self)
        notice=patch.object(operator,'terminal_notice');notice.start();self.addCleanup(notice.stop)
        self.case={'schema':g.SCHEMA,'purpose':'EXACT_RETAINED_INSTALLATION_NOT_PORTABLE_DEFAULT',
            'runtimeCase':copy.deepcopy(self.r.case),'nativeDeclaration':copy.deepcopy(self.r.manifest),
            'predecessorControlPath':str(self.oldcontrol),'predecessorReviewHash':e.c.digest(config['review']),
            'humanOperatorTransportProfile':dict(operator.TRANSPORT),
            'governanceSourceHash':hashlib.sha256((ROOT/'tools/ingestion_readiness_patch_execution/stage8_human.py').read_bytes()).hexdigest()}
        self.closure='b'*64;self.patches=[]
        for obj,name,value in ((g,'__qualified_source_sha256__',self.case['governanceSourceHash']),
                              (runtime,'__qualified_source_sha256__',self.r.case['controlSourceHash'])):
            p=patch.object(obj,name,value,create=True);p.start();self.addCleanup(p.stop)
        probe=patch.object(g,'live_preflight',return_value={'complete':True,'engineRequests':14,
            'maximumEngineRequests':14,'humanCredentialJournalsRead':0,'status':'PATCH_HUMAN_RUNTIME_PREFLIGHT_NO_WINDOW_OR_BUDGET'})
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
            result=self.grant();self.assertEqual(result['maximumCumulativeOAuthAttempts'],304)
            self.assertFalse(result['newHumanWindowOpened']);self.assertFalse(result['runtimeAuthorityIssued'])
            issue.assert_not_called();http.assert_not_called()
        self.assertEqual(self.oldbytes,Path(self.old_profile['journal']['path']).read_bytes())
    def test_grant_is_one_use_and_partial_claim_never_reopens(self):
        original=g.publish
        def fail(folder,name,value):
            original(folder,name,value)
            if name=='patch-oauth-budget-300.claim.json':raise OSError('synthetic after fence')
        with patch.object(g,'publish',side_effect=fail),self.assertRaises(OSError):self.grant()
        with patch.object(operator,'terminal_confirm')as tty,self.assertRaises(Exception):self.call('grant-budget')
        tty.assert_not_called()
        with self.assertRaises(Exception):self.call('budget-status')
    def test_window_preserves_old300_and_never_copies_credentials_or_opens_twice(self):
        opened=self.open();self.assertEqual(opened['attempts'],300)
        _,cfg,b=g.load(self.control,self.case,self.closure);row=e.Journal(b['sessionDirectory']).read()
        self.assertEqual(row['attempts'],300);self.assertEqual(b['retryProfile']['maximumAttempts'],304)
        self.assertNotIn('accessToken',row);self.assertNotIn('refreshToken',row)
        self.assertEqual(cfg['review']['operationBinding'],g.operation(self.case))
        self.assertEqual(self.oldbytes,Path(self.old_profile['journal']['path']).read_bytes())
        with patch.object(operator,'terminal_confirm')as tty,self.assertRaises(Exception):self.call('open-window')
        tty.assert_not_called()
        self.assertEqual(self.call('status',self.control)['attempts'],300)
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
    def test_exact_four_manual_requests_reach304_and_publish_bound_patch_reader(self):
        session=self.session();issuer=self.old.selection['issuer']
        responses=[(200,{'issuer':issuer,**{k:issuer+'/protocol/openid-connect/'+k for k in
            ('device_authorization_endpoint','token_endpoint','userinfo_endpoint')}},0),
            (200,{'verification_uri':issuer+'/device','user_code':'FIXTURE','device_code':'PRIVATE','expires_in':600,'interval':5},0),
            (200,{'access_token':self.old.token(),'refresh_token':'PRIVATE_NEW_REFRESH','token_type':'Bearer'},0),
            (200,{'sub':self.old.selection['subject']},0)]
        with patch.object(operator,'terminal_confirm',return_value=True),patch.object(ExplicitFreshSession,'_http',side_effect=responses)as http:
            self.assertEqual(self.call('step',self.control)['attempts'],301)
            self.assertEqual(self.call('step',self.control)['attempts'],302)
            row=session.journal.read();session.journal.compare_and_save(row,{**row,'nextPollAt':time.time()-1})
            self.assertEqual(self.call('step',self.control)['attempts'],303)
            ready=self.call('step',self.control);self.assertEqual(ready['attempts'],304)
            self.assertTrue(ready['productionTokenMarginCovered']);self.assertEqual(http.call_count,4)
        profile=g.custody.read(ready['privateHumanReadProfilePath'])
        h=runtime.human(self.r.case,profile);self.assertEqual(h.current(),session.expected_binding)
        self.assertEqual(self.oldbytes,Path(self.old_profile['journal']['path']).read_bytes())
    def test_pending_poll_preserves_userinfo_reserve_and_lost_start_cannot_replay(self):
        session=self.session();issuer=self.old.selection['issuer'];session._http=Mock(return_value=(200,
            {'issuer':issuer,**{k:issuer+'/protocol/openid-connect/'+k for k in
            ('device_authorization_endpoint','token_endpoint','userinfo_endpoint')}},0))
        session.step();session._http.side_effect=OSError('synthetic lost start')
        with self.assertRaises(Exception):session.step()
        self.assertEqual(session.journal.read()['attempts'],302);calls=session._http.call_count
        with self.assertRaises(Exception):session.step()
        self.assertEqual(session._http.call_count,calls)
    def test_changed_source_old_count_or_case_blocks_before_consent(self):
        for key,value in [('predecessorReviewHash','f'*64),('governanceSourceHash','f'*64)]:
            original=self.case[key];self.case[key]=value
            with patch.object(operator,'terminal_confirm')as tty,self.assertRaises(Exception):self.call('grant-budget')
            tty.assert_not_called();self.case[key]=original
        self.old_profile['minimumCumulativeAttempts']=296
        self.old.write(self.oldcontrol/'human-read-profile.json',self.old_profile)
        with self.assertRaises(Exception):self.call('prepare')
    def test_new_human_and_runtime_capsules_are_closed_and_deterministic(self):
        from tools.ingestion_readiness_patch_execution import stage8_delivery as d
        import subprocess
        raw,declaration=d.human_generate(ROOT,self.case)
        self.assertEqual(raw,d.human_generate(ROOT,self.case)[0]);self.assertLess(len(raw),1048576)
        self.assertEqual(declaration['entryModule'],g.__name__)
        runtime,manifest=d.core(ROOT,self.r.manifest['sourceCommit'],self.r.manifest['sourcePins'])
        self.assertEqual(manifest,self.r.manifest)
        runtime_raw,_=d.generate(ROOT,self.r.case,manifest)
        self.assertEqual(runtime_raw,d.generate(ROOT,self.r.case,manifest)[0])
        sh=d.launcher(runtime_raw)
        self.assertNotIn(b'initialize|',sh);self.assertIn(b'import-prefix',sh)
        self.assertEqual(subprocess.run(['bash','-n'],input=sh,capture_output=True).returncode,0)
        path=self.r.root/'invalid-mode.py';path.write_bytes(runtime_raw)
        result=subprocess.run([sys.executable,'-I','-B','-S',str(path),'initialize'],capture_output=True,text=True)
        self.assertEqual(result.returncode,2);self.assertIn('STOP_RECONCILE',result.stdout)
        case=copy.deepcopy(self.case);case['governanceSourceHash']='f'*64
        with self.assertRaisesRegex(ValueError,'GOVERNANCE_SOURCE'):d.human_generate(ROOT,case)

class ProductionDelivery(unittest.TestCase):
    def test_every_exact_production_cache_and_case_reproduces(self):
        from tools.ingestion_readiness_patch_execution import stage8_production as build
        pins=json.loads((ROOT/'evidence/ingestion-readiness-stage8-production-pins-20261022.json').read_bytes())
        files,expected=build.build(ROOT,pins['qualification']);self.assertEqual(pins,expected)
        for path,raw in files.items():self.assertEqual(raw,(ROOT/path).read_bytes(),path)
        self.assertEqual(pins['nativeSourceModules'],148)
        self.assertFalse(pins['newBudgetGranted']);self.assertFalse(pins['targetCommandExecuted'])
        self.assertEqual(pins['currentCumulativeOAuthAttempts'],300)
        self.assertEqual(pins['maximumCumulativeOAuthAttempts'],300)


if __name__=='__main__':unittest.main()
