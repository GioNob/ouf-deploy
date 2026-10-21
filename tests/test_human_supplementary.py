"""Full retained admin chain, four explicit requests, sealed root delivery."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),
    str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_iam_lifetime_policy as lifetime_fixture
import test_iam_policy_read as original_fixture
import test_iam_explicit_api as admin_fixture
from tools.governed_human_successor import supplementary as s,supplementary_delivery as delivery
from tools.governed_human_successor import operator,window
from tools.governed_human_successor.session import ExplicitFreshSession
from tools.chatbot_file_cohort import human_session as h
from tools.ingestion_rollout_preparation import iam_policy_read as api,human_timing as files
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.ingestion_rollout_execution.contract import digest,encoded

original_setup=original_fixture.ApiRead.setUp

def full_setup(f):
    original_setup(f)
    now=int(time.time())
    f.client['clientId']=h.CLIENT;f.case['humanClientId']=h.CLIENT
    review={'priorOAuthAttempts':278,'maximumCumulativeOAuthAttempts':288,'requestedScopes':h.SCOPES,
        'budgetReset':False,'automaticRenewalAllowed':False,'oldCredentialsReusable':False,
        'freshIssuerAuthenticationRequired':True,'sourceClosureHash':'a'*64,
        'operationBinding':{'packetHash':'c'*64}}
    f.control=f.root/('human-successor-control-'+digest(review));f.control.mkdir(mode=0o700)
    session=f.root/('human-successor-'+digest(review));session.mkdir(mode=0o700)
    retry={**copy.deepcopy(h.PROFILE),'id':'fixture-retained','maximumAttempts':288}
    binding={'sessionId':'fixture-expired',**{k:f.selection[k]for k in ('issuer','subject','tenant')},
        'selectionHash':digest(f.selection),'clientId':h.CLIENT,'scopes':h.SCOPES,
        'sessionDirectory':str(session),'tokenPath':str(session/'human-access.jwt'),
        'createdAt':now-14401,'expiresAt':now-7201,'retryProfile':retry}
    decision={'schema':'ouf.human-login-window-terminal-consent.v1','reviewHash':digest(review),
        'decision':'OPEN_ONE_LOGIN_WINDOW_NO_RUNTIME_AUTHORITY','approvedAt':binding['createdAt'],
        'expiresAt':binding['expiresAt']}
    history={'minimumRetainedOAuthAttempts':278,'maximumCumulativeOAuthAttempts':288,
        'ownerPlanHash':digest(f.plan),'completedResultHash':'b'*64}
    config={'schema':'ouf.human-explicit-successor-control.v1','controlDirectory':str(f.control),
        'sourceClosureHash':'a'*64,'selection':f.selection,'review':review,'decision':decision,'history':history}
    f.write(f.control/'control.json',config);f.write(f.control/'binding.json',binding)
    row={'schema':'ouf.chatbot-human-session.private.v1','state':'READY','binding':binding,'attempts':282,
        'bootId':window.boot_id(),'monotonicDeadline':time.monotonic()-1,'lastObservedAt':now-7202,
        'accessExpiresAt':now-7300,'budgetReset':False,'accessToken':'PRIVATE-OLD-HUMAN',
        'governedWindowRenewal':{'review':review,'decision':decision}}
    Journal(session).initialize(row);_,seal=files.selected(str(session/'recovery.json'))
    f.write(f.control/'human-read-profile.json',{'expectedBinding':binding,'selection':f.selection,
        'minimumCumulativeAttempts':282,'maximumCumulativeAttempts':288,'journal':seal})
    f.case['humanControlPath']=str(f.control)
    prepared=json.loads((f.production/'preparation.json').read_text())
    control=f.production/'operator-control';control.mkdir(mode=0o700)
    Journal(control).initialize({'schema':'ouf.ingestion-rollout-explicit-production-control.v1',
        'state':'PRIVATE_READY','complete':False,'caseHash':f.case['productionCaseHash'],
        'controlSourceHash':f.case['productionControlSourceHash'],'preparationHash':digest(prepared),
        'runtimeAuthorityIssued':False,'budgetReset':False})

def keep_full_human(a):
    cfg=json.loads((a.f.control/'control.json').read_text())
    a.session=a.f.root/('human-successor-'+digest(cfg['review']))
    a.human=Journal(a.session).read()

class Supplementary(unittest.TestCase):
    def setUp(self):
        if not Path('/proc/sys/kernel/random/boot_id').exists():
            for obj,name in ((window,'boot_id'),(h.HumanSession,'_boot')):
                boot=patch.object(obj,name,return_value='synthetic-boot');boot.start();self.addCleanup(boot.stop)
        self.now=int(time.time());clock=patch('time.time',side_effect=lambda:self.now)
        clock.start();self.addCleanup(clock.stop)
        setup=patch.object(original_fixture.ApiRead,'setUp',full_setup);setup.start();self.addCleanup(setup.stop)
        install=patch.object(admin_fixture.ExplicitApi,'install_human_history',keep_full_human)
        install.start();self.addCleanup(install.stop)
        self.a=lifetime_fixture.LifetimePolicy();self.a.setUp();self.addCleanup(self.a.doCleanups)
        self.result=self.a.invoke();self.f=self.a.f
        self.case={'schema':'ouf.human-supplementary-ledger-case.v1',
            'purpose':'EXACT_RETAINED_INSTALLATION_NOT_PORTABLE_DEFAULT','lifetimeCase':self.a.case,
            'lifetimeResultHash':digest(self.result),'expectedAttempts':284,'maximumCumulativeOAuthAttempts':288,
            'requiredTokenMarginSeconds':930,'humanOperatorTransportProfile':dict(operator.TRANSPORT)}
        self.closure='8'*64
        self.ledger=self.a.destination
        self.previous=self.a.a.session
        self.old={p:p.read_bytes()for p in (self.previous/'recovery.json',
            self.previous/'successor-window.claim.json',self.ledger.parent/'recovery.json',
            self.ledger.parent/'provider-budget-successor.claim.json',self.ledger/'recovery.json')}
        clean=os.environ.copy()
        for k in ('SSL_CERT_FILE','SSL_CERT_DIR','HTTPS_PROXY','HTTP_PROXY','ALL_PROXY','https_proxy','http_proxy','all_proxy'):
            clean.pop(k,None)
        env=patch.dict(os.environ,clean,clear=True);env.start();self.addCleanup(env.stop)
        notice=patch.object(operator,'terminal_notice');notice.start();self.addCleanup(notice.stop)

    def open(self):
        with patch.object(operator,'terminal_confirm',return_value=True):
            value=s.execute('open-window',None,self.case,{},self.closure)
        self.control=value['controlPath'];return value

    def check_old(self):
        for p,raw in self.old.items():self.assertEqual(p.read_bytes(),raw)

    def test_prepare_validates_real_retained_chain_without_effects(self):
        before={p:p.read_bytes()for p in self.f.root.rglob('*')if p.is_file()}
        with patch.object(ExplicitFreshSession,'_http')as http,patch.object(operator,'terminal_confirm')as tty:
            result=s.execute('prepare',None,self.case,{},self.closure)
        self.assertEqual(result['attempts'],284);self.assertEqual(result['remainingAttempts'],4)
        self.assertTrue(result['readOnly']);self.assertFalse(result['newHumanWindowOpened'])
        self.assertEqual(result['administrativeLedgerAttempts'],[283,284])
        http.assert_not_called();tty.assert_not_called()
        self.assertEqual({p:p.read_bytes()for p in self.f.root.rglob('*')if p.is_file()},before)

    def test_tampered_284_ledger_or_claim_blocks_before_consent(self):
        for field,value in [('attempts',283),('state','STOP_RECONCILE'),('clientPutsReserved',0)]:
            p=self.ledger/'recovery.json';raw=p.read_bytes();row=json.loads(raw);row[field]=value
            self.f.write(p,row)
            with patch.object(operator,'terminal_confirm')as tty,self.assertRaisesRegex(Exception,'EXACT_COMPLETED_LIFETIME'):
                s.execute('open-window',None,self.case,{},self.closure)
            tty.assert_not_called();p.write_bytes(raw)
        self.assertFalse((self.ledger/'provider-budget-successor.claim.json').exists())

    def test_missing_supplementary_283_history_never_falls_back_to282(self):
        self.case['lifetimeCase']['retainedApiResultHash']='0'*64
        with self.assertRaisesRegex(ValueError,'EXACT_COMPLETED_ADMIN_LEDGER'):
            s.execute('prepare',None,self.case,{},self.closure)

    def test_consumed_production_preparation_blocks_new_window(self):
        self.f.write(self.f.production/'recovery.json',{'state':'STARTED'})
        with patch.object(operator,'terminal_confirm')as tty,self.assertRaisesRegex(Exception,'UNCONSUMED_RETAINED_PRODUCTION'):
            s.execute('open-window',None,self.case,{},self.closure)
        tty.assert_not_called()

    def test_denied_window_has_no_writes(self):
        before={p:p.read_bytes()for p in self.f.root.rglob('*')if p.is_file()}
        with patch.object(operator,'terminal_confirm',return_value=False),self.assertRaises(Exception):self.open_denied()
        self.assertEqual({p:p.read_bytes()for p in self.f.root.rglob('*')if p.is_file()},before)

    def open_denied(self):return s.execute('open-window',None,self.case,{},self.closure)

    def test_window_once_claim_survives_crash_and_old_journals_unchanged(self):
        with patch.object(operator,'terminal_confirm',return_value=True),patch.object(s.os,'mkdir',side_effect=OSError('fixture-crash')):
            with self.assertRaises(OSError):s.execute('open-window',None,self.case,{},self.closure)
        self.assertTrue((self.ledger/'provider-budget-successor.claim.json').exists())
        with self.assertRaisesRegex(Exception,'ALREADY_CONSUMED'):self.open()
        self.check_old()

    def test_four_explicit_requests_end_at288_ready_readable_without_refresh(self):
        self.open()
        issuer=self.f.selection['issuer']
        claims={'iss':issuer,'sub':self.f.selection['subject'],'tenant_id':self.f.selection['tenant'],
            'ouf_actor_type':'HUMAN','azp':h.CLIENT,'aud':'ouf-api-gateway','scope':' '.join(h.SCOPES),
            'acr':'fixture','exp':self.now+1200}
        token='fixture.'+base64.urlsafe_b64encode(encoded(claims)).decode().rstrip('=')+'.fixture'
        replies=[(200,{'issuer':issuer,**{k:issuer+'/protocol/openid-connect/'+v for k,v in
            [('device_authorization_endpoint','device-start'),('token_endpoint','token'),('userinfo_endpoint','userinfo')]}},0),
            (200,{'verification_uri':issuer+'/device','user_code':'FIXTURE-CODE','device_code':'PRIVATE-DEVICE',
                'expires_in':600,'interval':5},0),
            (200,{'access_token':token,'refresh_token':'PRIVATE-FRESH-REFRESH','token_type':'Bearer'},0),
            (200,{'sub':self.f.selection['subject']},0)]
        with patch.object(operator,'terminal_confirm',return_value=True),patch.object(ExplicitFreshSession,'_http',side_effect=replies)as http:
            one=s.execute('step',self.control,self.case,{},self.closure)
            two=s.execute('step',self.control,self.case,{},self.closure)
            self.assertEqual((one['attempts'],two['attempts']),(285,286))
            early=s.execute('step',self.control,self.case,{},self.closure)
            self.assertEqual(early['status'],'WAIT_EXPLICIT_STEP');self.assertEqual(http.call_count,2)
            self.now+=6
            self.assertEqual(s.execute('step',self.control,self.case,{},self.closure)['attempts'],287)
            final=s.execute('step',self.control,self.case,{},self.closure)
            self.assertEqual((final['state'],final['attempts'],final['remainingAttempts']),('READY',288,0))
            self.assertTrue(final['productionTokenMarginCovered']);self.assertTrue(final['complete'])
            self.assertTrue(Path(final['privateHumanReadProfilePath']).exists())
            again=s.execute('step',self.control,self.case,{},self.closure)
            self.assertEqual(again['attempts'],288);self.assertEqual(http.call_count,4)
        self.assertNotIn('PRIVATE-',json.dumps(final));self.check_old()

    def test_denied_step_does_not_reserve_and_no_automatic_retry(self):
        self.open()
        with patch.object(operator,'terminal_confirm',return_value=False),patch.object(ExplicitFreshSession,'_http')as http:
            with self.assertRaises(Exception):s.execute('step',self.control,self.case,{},self.closure)
        http.assert_not_called()
        self.assertEqual(s.execute('status',self.control,self.case,{},self.closure)['attempts'],284)

    def test_concurrent_window_is_fenced_by_completed_ledger_lock(self):
        with Journal(self.ledger).invocation():
            with self.assertRaises(BlockingIOError):self.open()
        self.assertFalse((self.ledger/'provider-budget-successor.claim.json').exists())

    def test_ambiguous_discovery_consumes_one_and_never_automatically_replays(self):
        self.open()
        with patch.object(operator,'terminal_confirm',return_value=True),patch.object(ExplicitFreshSession,'_http',side_effect=OSError('fixture-lost-response'))as http:
            with self.assertRaises(Exception):s.execute('step',self.control,self.case,{},self.closure)
            self.assertEqual(http.call_count,1)
            with self.assertRaises(Exception):s.execute('step',self.control,self.case,{},self.closure)
            self.assertEqual(http.call_count,1)
        result=s.execute('status',self.control,self.case,{},self.closure)
        self.assertEqual((result['state'],result['attempts']),('BLOCKED',285))
        self.check_old()

    def test_existing_window_cannot_reopen_and_changed_source_cannot_step(self):
        self.open()
        with patch.object(operator,'terminal_confirm')as tty,patch.object(ExplicitFreshSession,'_http')as http:
            with self.assertRaisesRegex(Exception,'ALREADY_CONSUMED'):s.execute('open-window',None,self.case,{},self.closure)
            with self.assertRaisesRegex(Exception,'EXACT_SUPPLEMENTARY_CONTROL_PATH'):s.execute('step',self.control,self.case,{},'9'*64)
        tty.assert_not_called();http.assert_not_called();self.check_old()

    def test_expired_new_window_status_is_readable_but_authentication_stops(self):
        self.open();self.now+=7201
        value=s.execute('status',self.control,self.case,{},self.closure)
        self.assertFalse(value['windowOpen']);self.assertEqual(value['attempts'],284)
        with patch.object(ExplicitFreshSession,'_http')as http,self.assertRaises(Exception):
            s.execute('step',self.control,self.case,{},self.closure)
        http.assert_not_called();self.check_old()

    def test_sealed_delivery_reproduces_and_offline_prepare_works_in_isolated_root(self):
        if not Path('/proc/sys/kernel/random/boot_id').exists():
            if os.environ.get('GITHUB_ACTIONS')=='true':self.fail('CI requires actual boot evidence')
            self.skipTest('Local sandbox has no proc boot identity; physical loader mandatory in CI')
        raw,dec=delivery.generate(ROOT,self.case)
        self.assertEqual(raw,delivery.generate(ROOT,self.case)[0]);self.assertEqual(dec['moduleCount'],55)
        p=self.f.root/'sealed.py';p.write_bytes(raw)
        result=subprocess.run([sys.executable,'-I','-B','-S',str(p),'prepare'],capture_output=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stdout.decode()+result.stderr.decode())
        value=json.loads(result.stdout);self.assertEqual(value['attempts'],284);self.assertTrue(value['readOnly'])
        self.check_old()

if __name__=='__main__':unittest.main()
