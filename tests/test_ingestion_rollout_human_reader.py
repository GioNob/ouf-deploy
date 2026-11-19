"""Read-only cumulative HUMAN compatibility; synthetic bearer, no provider I/O."""
import base64
import copy
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),
             str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.ingestion_rollout_execution import human_reader as r,contract as c
from tools.chatbot_file_cohort import human_session as h
from test_ingestion_rollout_gateway_transport import binding

class RetainedHumanRead(unittest.TestCase):
    def setUp(self):
        boot=patch.object(h.HumanSession,'_boot',return_value='synthetic-fixture-boot')
        boot.start();self.addCleanup(boot.stop)
        self.temp=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT)))
        self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);self.root.chmod(0o700)
        now=int(time.time());self.selection={'issuer':'https://fixture.invalid','tenant':'fixture','subject':'fixture-human'}
        retry={**h.PROFILE,'id':'ouf.human.ingestion-owner-recovery288.v7','maximumAttempts':288}
        b={'sessionId':'retained-fixture','selectionHash':c.digest(self.selection),**self.selection,
            'clientId':h.CLIENT,'scopes':h.SCOPES,'tokenPath':str(self.root/'human-access.jwt'),
            'sessionDirectory':str(self.root),'createdAt':now,'expiresAt':now+7200,'retryProfile':retry}
        review={'maximumCumulativeOAuthAttempts':288,'priorOAuthAttempts':272,'requestedScopes':h.SCOPES,
            'budgetReset':False,'automaticRenewalAllowed':False,'oldCredentialsReusable':False,'freshIssuerAuthenticationRequired':True}
        receipt={'review':review,'decision':{'reviewHash':c.digest(review),'approvedAt':now,'expiresAt':now+7200}}
        claims={'iss':self.selection['issuer'],'sub':self.selection['subject'],'tenant_id':self.selection['tenant'],
            'ouf_actor_type':'HUMAN','azp':h.CLIENT,'acr':'fixture-only','aud':'ouf-api-gateway',
            'scope':' '.join(h.SCOPES),'exp':now+1800}
        token='fixture.'+base64.urlsafe_b64encode(c.encoded(claims)).decode().rstrip('=')+'.fixture'
        bootstrap=h.HumanSession(self.selection,self.root,self.root/'human-access.jwt',b['expiresAt'])
        deadline=time.monotonic()+7200
        row={'schema':'ouf.chatbot-human-session.private.v1','binding':b,'bootId':bootstrap._boot(),
            'monotonicDeadline':deadline,'lastObservedAt':time.time(),'attempts':278,'state':'READY','budgetReset':False,
            'accessExpiresAt':now+1800,'publishedAccessToken':token,'governedWindowRenewal':receipt,'version':0}
        bootstrap.journal.initialize(row);self.journal=bootstrap.journal
        self.profile={'schema':r.SCHEMA,'selection':self.selection,'expectedBinding':b,'journal':binding(bootstrap.journal.record),
            'minimumCumulativeAttempts':278,'maximumCumulativeAttempts':288,'expectedBootId':row['bootId'],
            'expectedMonotonicDeadline':deadline,'governedWindowReceiptHash':c.digest(receipt),'readOnly':True,
            'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False}
    def test_exact_278_of_288_binding_is_current_without_replaying_extension_or_writing(self):
        before=self.journal.record.read_bytes();human=r.open_existing(self.profile)
        self.assertIs(type(human),h.HumanSession);self.assertEqual(human.current(),self.profile['expectedBinding'])
        self.assertEqual(human._read()['attempts'],278);self.assertTrue(before==self.journal.record.read_bytes())
        r.require_profile(human,{'humanBinding':self.profile['expectedBinding'],'humanReadProfile':self.profile,
            'retainedOwnerHistory':{'minimumRetainedOAuthAttempts':278,'maximumCumulativeOAuthAttempts':288}})
    def test_expired_recorded_window_fails_before_credential_bytes_open(self):
        p=copy.deepcopy(self.profile);p['expectedBinding']['createdAt']-=7201;p['expectedBinding']['expiresAt']-=7201
        with patch.object(r.private_file,'read')as read:
            with self.assertRaisesRegex(c.Denied,'WINDOW_EXPIRED'):r.open_existing(p)
            read.assert_not_called()
    def test_login_refresh_network_and_all_journal_writes_are_disabled(self):
        human=r.open_existing(self.profile);before=self.journal.record.read_bytes()
        for name in('authenticate','start_refresh','refresh_if_due','_save','_publish','_request'):
            with self.subTest(name=name),self.assertRaises((c.Denied,AttributeError)):getattr(human,name)()
        self.assertTrue(before==self.journal.record.read_bytes())
    def test_rebound_journal_cannot_hide_counter_reset_or_missing_consent(self):
        row=self.journal.read();self.journal.compare_and_save(row,{**row,'attempts':1,'version':row['version']+1})
        p=copy.deepcopy(self.profile);p['journal']=binding(self.journal.record)
        with self.assertRaises(c.Denied):r.open_existing(p)
        p['minimumCumulativeAttempts']=0;p['governedWindowReceiptHash']=None
        with self.assertRaises(c.Denied):r.open_existing(p)
    def test_profile_drift_or_unreviewed_adapter_is_rejected(self):
        human=r.open_existing(self.profile)
        with self.assertRaises(c.Denied):r.require_profile(human,{'humanBinding':self.profile['expectedBinding']})
        changed=copy.deepcopy(self.profile);changed['minimumCumulativeAttempts']=277
        with self.assertRaises(c.Denied):r.require_profile(human,{'humanBinding':changed['expectedBinding'],'humanReadProfile':changed})
        human._ingestion_read_profile['maximumCumulativeAttempts']=289
        with self.assertRaises(c.Denied):human.current()

if __name__=='__main__':unittest.main()
