"""Synthetic provider only; durable finite successor, zero target operations."""
import base64
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from urllib.parse import parse_qs
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),
    str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.governed_human_successor import contract as c,window
from tools.governed_human_successor import inspection
from tools.governed_human_successor import reader_delivery
from tools.governed_human_successor.session import ExplicitFreshSession
from tools.chatbot_file_cohort import human_session as h
from tools.chatbot_file_cohort.plan import PlanDenied
from tools.ingestion_rollout_execution.contract import Denied,digest,encoded
from tools.ingestion_rollout_execution import human_reader
from tools.semantic_lease_recovery.recovery_journal import Journal
from test_ingestion_rollout_gateway_transport import binding as file_binding

class GovernedSuccessor(unittest.TestCase):
    def setUp(self):
        self.real_now=int(time.time());self.now=self.real_now
        clock=patch('time.time',side_effect=lambda:self.now);clock.start();self.addCleanup(clock.stop)
        boot=patch.object(h.HumanSession,'_boot',return_value='synthetic-boot');boot.start();self.addCleanup(boot.stop)
        boot2=patch.object(window,'boot_id',return_value='synthetic-boot');boot2.start();self.addCleanup(boot2.stop)
        self.temp=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT)));self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.previous=self.root/'previous';self.previous.mkdir(mode=0o700)
        self.selection={'issuer':'https://fixture.invalid','tenant':'tenant-fixture','subject':'human-fixture'}
        self.scopes=h.SCOPES+['fixture.scope.'+str(i)for i in range(5)]
        retry={**copy.deepcopy(h.PROFILE),'id':'ouf.human.ingestion-owner-recovery288.v7','maximumAttempts':288}
        b={'sessionId':'expired-fixture','selectionHash':digest(self.selection),**self.selection,'clientId':h.CLIENT,
            'scopes':self.scopes,'sessionDirectory':str(self.previous),'tokenPath':str(self.previous/'human-access.jwt'),
            'createdAt':self.now-14401,'expiresAt':self.now-7201,'retryProfile':retry}
        review={'priorOAuthAttempts':272,'maximumCumulativeOAuthAttempts':288,'requestedScopes':self.scopes,
            'budgetReset':False,'automaticRenewalAllowed':False,'oldCredentialsReusable':False,'freshIssuerAuthenticationRequired':True}
        receipt={'review':review,'decision':{'reviewHash':digest(review),'approvedAt':b['createdAt'],'expiresAt':b['expiresAt']}}
        self.row={'schema':'ouf.chatbot-human-session.private.v1','binding':b,'bootId':'synthetic-boot',
            'monotonicDeadline':time.monotonic()-10,'lastObservedAt':self.now-7202,'attempts':278,
            'state':'READY','budgetReset':False,'accessExpiresAt':self.now-7300,
            'accessToken':'old-access-must-not-be-reused','refreshToken':'old-refresh-must-not-be-reused',
            'publishedAccessToken':'old-published-must-not-be-reused','governedWindowRenewal':receipt,'version':0}
        self.old=Journal(self.previous);self.old.initialize(self.row)
        self.old_bytes=self.old.record.read_bytes();self.selected=file_binding(self.old.record)
        self.history={'minimumRetainedOAuthAttempts':278,'maximumCumulativeOAuthAttempts':288,
            'ownerPlanHash':'a'*64,'completedResultHash':'b'*64}
        self.review=self.compile(self.row)
        self.decision={'schema':'ouf.human-login-window-terminal-consent.v1','reviewHash':digest(self.review),
            'decision':'OPEN_ONE_LOGIN_WINDOW_NO_RUNTIME_AUTHORITY','approvedAt':self.now,'expiresAt':self.now+7200}

    def compile(self,row,selection=None):
        return c.compile_review(selection or self.selection,row,self.history,{'packetHash':'c'*64},'d'*64,
            now=self.now,monotonic=time.monotonic(),boot_id='synthetic-boot')

    def session(self):
        b=window.initialize(self.review,self.decision,self.selected,self.selection,self.history)
        self.fresh=ExplicitFreshSession(self.selection,b,self.review,self.decision)
        return self.fresh

    def discovery(self):
        issuer=self.selection['issuer']
        return 200,{'issuer':issuer,**{k:issuer+'/protocol/openid-connect/'+v for k,v in
            [('device_authorization_endpoint','auth/device'),('token_endpoint','token'),('userinfo_endpoint','userinfo')]}},0

    def device(self):
        return 200,{'verification_uri':self.selection['issuer']+'/device','user_code':'FIXTURE-CODE',
            'device_code':'private-device-code','expires_in':600,'interval':5},0

    def token(self,scopes=None):
        claims={'iss':self.selection['issuer'],'sub':self.selection['subject'],'tenant_id':self.selection['tenant'],
            'ouf_actor_type':'HUMAN','azp':h.CLIENT,'acr':'fixture','aud':'ouf-api-gateway',
            'scope':' '.join(scopes or self.scopes),'exp':self.now+1800}
        return 'fixture.'+base64.urlsafe_b64encode(encoded(claims)).decode().rstrip('=')+'.fixture'

    def to_poll(self,session,http):
        http.side_effect=[self.discovery(),self.device()]
        self.assertEqual(session.step()['state'],'DEVICE_START')
        self.assertEqual(session.step()['state'],'DEVICE_POLL')
        self.assertEqual(http.call_count,2);self.now+=6
        result=session.step();self.assertTrue(result['browserConfirmationRequired']);self.assertEqual(http.call_count,2)
        return {'challengeHash':digest(result['challenge']),'confirmedAt':self.now}

    def test_review_contains_public_history_only_and_keeps_278_288(self):
        raw=json.dumps(self.review)
        self.assertNotIn('old-access',raw);self.assertNotIn('old-refresh',raw);self.assertNotIn('old-published',raw)
        self.assertEqual(self.review['priorOAuthAttempts'],278);self.assertEqual(self.review['maximumRemainingOAuthAttempts'],10)
        self.assertFalse(self.review['runtimeAuthorityIssued']);self.assertFalse(self.review['budgetReset'])

    def test_live_ambiguous_reset_budget_and_clock_predecessors_rejected(self):
        for changes in [{'state':'REQUESTING'},{'state':'VERIFYING'},{'attempts':0},{'attempts':289},
                        {'budgetReset':True},{'accessExpiresAt':self.now+20},{'bootId':'different-boot'},
                        {'monotonicDeadline':time.monotonic()+100},{'lastObservedAt':self.now+10}]:
            with self.subTest(changes=changes),self.assertRaises((Denied,ValueError)):
                self.compile({**copy.deepcopy(self.row),**changes})
        bad=copy.deepcopy(self.row);bad['binding']['retryProfile']['maximumAttempts']=289
        with self.assertRaises(Denied):self.compile(bad)

    def test_invalid_consent_leaves_predecessor_and_claim_absent(self):
        bad={**self.decision,'reviewHash':'e'*64}
        with self.assertRaises(Denied):window.initialize(self.review,bad,self.selected,self.selection,self.history)
        self.assertFalse((self.previous/'successor-window.claim.json').exists())
        self.assertEqual(self.old.record.read_bytes(),self.old_bytes)

    def test_successor_claim_is_once_only_and_never_copies_old_credentials(self):
        session=self.session();row=session.journal.read()
        self.assertEqual(row['attempts'],278);self.assertEqual(row['state'],'NEW')
        self.assertFalse(any(k in row for k in('accessToken','refreshToken','publishedAccessToken','deviceCode')))
        self.assertEqual(self.old.record.read_bytes(),self.old_bytes)
        with self.assertRaisesRegex(Denied,'CLAIM_ALREADY_CONSUMED'):
            window.initialize(self.review,self.decision,self.selected,self.selection,self.history)
        self.assertEqual(session.journal.read(),row)

    def test_claim_remains_consumed_after_failure_before_successor_directory(self):
        with patch.object(window.os,'mkdir',side_effect=OSError('synthetic failure after claim')):
            with self.assertRaises(OSError):window.initialize(self.review,self.decision,self.selected,self.selection,self.history)
        self.assertTrue((self.previous/'successor-window.claim.json').exists())
        with self.assertRaisesRegex(Denied,'CLAIM_ALREADY_CONSUMED'):
            window.initialize(self.review,self.decision,self.selected,self.selection,self.history)
        self.assertEqual(self.old.record.read_bytes(),self.old_bytes)

    def test_fresh_provider_path_is_four_requests_in_four_explicit_steps(self):
        session=self.session()
        with patch.object(session,'_http')as http:
            confirmation=self.to_poll(session,http);token=self.token()
            http.side_effect=[(200,{'access_token':token,'refresh_token':'fresh-private-refresh','token_type':'Bearer'},0),
                              (200,{'sub':self.selection['subject']},0)]
            result=session.step(confirmation);self.assertEqual(result['state'],'VERIFYING');self.assertEqual(http.call_count,3)
            result=session.step();self.assertEqual(result['state'],'READY');self.assertEqual(http.call_count,4)
            self.assertEqual(result['attempts'],282);self.assertEqual(result['remainingAttempts'],6)
            self.assertNotIn(token,json.dumps(result));self.assertNotIn('fresh-private-refresh',json.dumps(result))
            self.assertEqual(session.step()['state'],'READY');self.assertEqual(http.call_count,4)
        self.assertEqual(self.old.record.read_bytes(),self.old_bytes)
        self.assertEqual(session.token_path.read_text(),token)
        row=session.journal.read();profile={'schema':human_reader.SCHEMA,'selection':self.selection,
            'expectedBinding':row['binding'],'journal':file_binding(session.journal.record),
            'minimumCumulativeAttempts':282,'maximumCumulativeAttempts':288,'expectedBootId':'synthetic-boot',
            'expectedMonotonicDeadline':row['monotonicDeadline'],'governedWindowReceiptHash':digest(row['governedWindowRenewal']),
            'readOnly':True,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False}
        read=human_reader.open_existing(profile);self.assertIs(type(read),h.HumanSession)
        self.assertEqual(read.current(),row['binding'])

    def test_pending_poll_requires_a_new_exact_confirmation_and_no_automatic_poll(self):
        session=self.session()
        with patch.object(session,'_http')as http:
            confirmation=self.to_poll(session,http);http.side_effect=[(400,{'error':'authorization_pending'},0)]
            result=session.step(confirmation);self.assertEqual(result['attempts'],281);self.assertEqual(http.call_count,3)
            self.now+=6;self.assertTrue(session.step()['browserConfirmationRequired']);self.assertEqual(http.call_count,3)
            with self.assertRaises(Denied):session.step(confirmation)
            self.assertEqual(http.call_count,3);self.assertEqual(session.journal.read()['attempts'],281)

    def test_userinfo_reserve_blocks_poll_before_dispatch_at_287(self):
        session=self.session()
        with patch.object(session,'_http')as http:
            self.to_poll(session,http);row=session.journal.read()
            session.journal.compare_and_save(row,{**row,'attempts':287})
            challenge=session.step()['challenge'];confirmation={'challengeHash':digest(challenge),'confirmedAt':self.now}
            with self.assertRaisesRegex(Denied,'VERIFICATION_BUDGET_RESERVED'):session.step(confirmation)
            self.assertEqual(http.call_count,2);self.assertEqual(session.journal.read()['attempts'],287)

    def test_lost_device_reply_retains_blocked_state_without_replay(self):
        session=self.session()
        with patch.object(session,'_http')as http:
            http.return_value=self.discovery();session.step()
            http.side_effect=h.HumanSessionPaused('HUMAN_OAUTH_TRANSPORT_OUTCOME_UNPROVEN')
            with self.assertRaises(h.HumanSessionPaused):session.step()
            self.assertEqual(session.journal.read()['state'],'BLOCKED');self.assertEqual(session.journal.read()['attempts'],280)
            with self.assertRaises(Denied):session.step()
            with self.assertRaises(Denied):session.reconcile_read()
            self.assertEqual(http.call_count,2)

    def test_transient_read_is_durably_paused_without_sleep_or_automatic_retry(self):
        session=self.session()
        with patch.object(session,'_http')as http:
            http.return_value=(503,{'error':'temporarily_unavailable'},30)
            with self.assertRaises(h.HumanSessionPaused):session.step()
            row=session.journal.read();self.assertEqual(row['state'],'RETRY_WAIT');self.assertEqual(row['attempts'],279)
            with self.assertRaises(Denied):session.step()
            self.assertEqual(http.call_count,1)
            self.now=int(row['nextAttemptAt'])+1;http.return_value=self.discovery()
            self.assertEqual(session.step()['attempts'],280);self.assertEqual(http.call_count,2)

    def test_received_issuer_identity_drift_is_blocked_and_cannot_be_reconciled_as_lost_read(self):
        session=self.session()
        with patch.object(session,'_http',return_value=(200,{'issuer':'https://different.invalid'},0))as http:
            with self.assertRaises(Denied):session.step()
            self.assertEqual(session.journal.read()['state'],'BLOCKED')
            with self.assertRaises(Denied):session.reconcile_read()
            self.assertEqual(http.call_count,1)

    def test_inherited_login_refresh_renewal_and_background_entrypoints_are_disabled(self):
        session=self.session()
        with patch.object(session,'_http')as http:
            for name in('login','_login_locked','_renew','_refresh_ready','refresh_if_due','start_refresh',
                         'expired_window_review','start_approved_window','prepare_interrupted_login'):
                with self.subTest(name=name),self.assertRaises(h.HumanSessionPaused):getattr(session,name)()
            http.assert_not_called()
        self.assertEqual(session.journal.read()['attempts'],278)

    def test_new_request_cannot_reset_counter_change_window_or_binding(self):
        session=self.session();row=session.journal.read()
        for changes in [{'attempts':0},{'attempts':280},{'monotonicDeadline':row['monotonicDeadline']+1},
                        {'budgetReset':True},{'binding':{**row['binding'],'tenant':'different'}}]:
            with self.subTest(changes=changes),self.assertRaises(Denied):session._save(row,**changes)
        self.assertEqual(session.journal.read(),row)

    def test_missing_successor_journal_never_initializes_a_zero_counter(self):
        session=self.session();session.journal.record.unlink()
        with self.assertRaisesRegex(Denied,'NO_ZERO_INITIALIZATION'):
            ExplicitFreshSession(self.selection,session.expected_binding,self.review,self.decision)
        self.assertFalse(session.journal.record.exists())

    def test_missing_retained_scope_blocks_before_userinfo_or_publication(self):
        session=self.session()
        with patch.object(session,'_http')as http:
            confirmation=self.to_poll(session,http)
            http.side_effect=[(200,{'access_token':self.token(self.scopes[:-1]),
                'refresh_token':'fresh-private-refresh','token_type':'Bearer'},0)]
            with self.assertRaises(Denied):session.step(confirmation)
            self.assertEqual(http.call_count,3)
            self.assertEqual(session.journal.read()['state'],'BLOCKED')
            self.assertFalse(session.token_path.exists())

    def test_wrong_provider_subject_never_publishes_and_cannot_reconcile_as_lost_read(self):
        session=self.session()
        with patch.object(session,'_http')as http:
            confirmation=self.to_poll(session,http)
            http.side_effect=[(200,{'access_token':self.token(),
                'refresh_token':'fresh-private-refresh','token_type':'Bearer'},0),
                (200,{'sub':'foreign-human'},0)]
            self.assertEqual(session.step(confirmation)['state'],'VERIFYING')
            with self.assertRaises(PlanDenied):session.step()
            self.assertEqual(session.journal.read()['attempts'],282)
            self.assertEqual(session.journal.read()['state'],'BLOCKED')
            self.assertFalse(session.token_path.exists())
            with self.assertRaises(Denied):session.reconcile_read()
            self.assertEqual(http.call_count,4)

    def test_provider_revocation_is_permanent_without_retry_or_budget_reset(self):
        session=self.session()
        with patch.object(session,'_http',return_value=(401,{'error':'invalid_token'},0))as http:
            with self.assertRaises(h.HumanSessionPaused):session.step()
            row=session.journal.read()
            self.assertEqual((row['state'],row['attempts']),('BLOCKED',279))
            with self.assertRaises(Denied):session.step()
            with self.assertRaises(Denied):session.reconcile_read()
            self.assertEqual(http.call_count,1)
            self.assertEqual(session.journal.read(),row)

    def test_stale_consent_never_consumes_claim_or_creates_successor(self):
        self.now+=61
        with self.assertRaises(Denied):
            window.initialize(self.review,self.decision,self.selected,self.selection,self.history)
        self.assertFalse((self.previous/'successor-window.claim.json').exists())
        self.assertEqual(self.old.record.read_bytes(),self.old_bytes)

    def test_real_verified_tls_provider_completes_only_four_explicit_requests(self):
        cert,key=self.root/'fixture.crt',self.root/'fixture.key'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
            '-keyout',str(key),'-out',str(cert),'-subj','/CN=127.0.0.1',
            '-addext','subjectAltName=IP:127.0.0.1','-addext','basicConstraints=critical,CA:TRUE'],
            check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
        seen=[];fixture=self
        class Provider(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):self.dispatch()
            def do_POST(self):self.dispatch()
            def dispatch(self):
                size=int(self.headers.get('Content-Length','0'))
                if size>65536:self.send_error(413);return
                form=parse_qs(self.rfile.read(size).decode())if size else {}
                seen.append((self.command,self.path))
                if self.path=='/.well-known/openid-configuration':status,value,_=fixture.discovery()
                elif self.path.endswith('/auth/device'):
                    fixture.assertEqual(form,{'client_id':[h.CLIENT],'scope':[' '.join(fixture.scopes)]})
                    status,value,_=fixture.device()
                elif self.path.endswith('/token'):
                    fixture.assertEqual(form['grant_type'],['urn:ietf:params:oauth:grant-type:device_code'])
                    value={'access_token':fixture.token(),'refresh_token':'fixture-private-refresh','token_type':'Bearer'};status=200
                elif self.path.endswith('/userinfo'):
                    fixture.assertEqual(self.headers.get('Authorization'),'Bearer '+fixture.token())
                    status,value=200,{'sub':fixture.selection['subject']}
                else:status,value=404,{'error':'unknown_fixture_path'}
                raw=encoded(value);self.send_response(status);self.send_header('Content-Type','application/json')
                self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
        server=ThreadingHTTPServer(('127.0.0.1',0),Provider)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(str(cert),str(key))
        server.socket=context.wrap_socket(server.socket,server_side=True)
        worker=threading.Thread(target=lambda:server.serve_forever(poll_interval=0.05),daemon=True);worker.start()
        def stop():server.shutdown();server.server_close();worker.join(timeout=2)
        self.addCleanup(stop)
        # Loopback and ephemeral port belong exclusively to this synthetic provider.
        self.selection['issuer']='https://127.0.0.1:'+str(server.server_address[1])
        row=copy.deepcopy(self.row);row['binding'].update(issuer=self.selection['issuer'],selectionHash=digest(self.selection))
        self.old.compare_and_save(self.row,row);self.row=row;self.old_bytes=self.old.record.read_bytes()
        self.selected=file_binding(self.old.record);self.review=self.compile(row)
        self.decision['reviewHash']=digest(self.review)
        trusted=ssl.create_default_context(cafile=str(cert))
        self.assertTrue(trusted.check_hostname);self.assertEqual(trusted.verify_mode,ssl.CERT_REQUIRED)
        with patch.object(h.ssl,'create_default_context',return_value=trusted):session=self.session()
        self.assertEqual(session.step()['state'],'DEVICE_START');self.assertEqual(len(seen),1)
        self.assertEqual(session.step()['state'],'DEVICE_POLL');self.assertEqual(len(seen),2)
        self.now+=6;challenge=session.step()['challenge'];self.assertEqual(len(seen),2)
        confirmation={'challengeHash':digest(challenge),'confirmedAt':self.now}
        self.assertEqual(session.step(confirmation)['state'],'VERIFYING');self.assertEqual(len(seen),3)
        result=session.step();self.assertEqual(result['state'],'READY');self.assertEqual(len(seen),4)
        self.assertEqual(result['attempts'],282);self.assertEqual(result['remainingAttempts'],6)
        self.assertEqual([verb for verb,_ in seen],['GET','POST','POST','GET'])
        self.assertEqual(self.old.record.read_bytes(),self.old_bytes)

    def retained_case(self):
        plan={'humanBinding':self.row['binding']}
        result={'complete':True,'planHash':digest(plan),'oauthAttemptsAfter':278,
            'maximumCumulativeOAuthAttempts':288}
        inputs={'synthetic':'retained-inputs'}
        packet={'schema':'ouf.ingestion-rollout-private-packet.v3',
            'kind':'PRIVATE_TEMPLATES_NOT_EXECUTABLE_AUTHORITY','verifiedInputsHash':digest(inputs),
            'ownerPlanSha256':digest(plan),**{k:False for k in('runtimeAuthorityIssued',
                'targetApplyAuthorized','automaticReplayAllowed','budgetReset','newLoginAllowed')}}
        case={'schema':'ouf.ingestion-rollout-retained-case.v1',
            'purpose':'EXACT_RETAINED_INSTALLATION_CASE_NOT_PORTABLE_DEFAULT',
            'runtimeAuthorityIssued':False,'budgetReset':False}
        for name,value in zip(('packetBinding','verifiedInputsBinding','ownerPlanBinding','ownerResultBinding'),
                              (packet,inputs,plan,result)):
            p=self.root/(name+'.json');p.write_bytes(encoded(value));p.chmod(0o600)
            case[name]={'path':str(p),'sha256':digest(value)}
        return case

    def test_retained_inspection_joins_actual_files_without_writes_or_bearer_reads(self):
        case=self.retained_case();before={p:p.read_bytes()for p in self.root.rglob('*')if p.is_file()}
        with patch.object(h.HumanSession,'_http')as http:
            review,private=inspection.inspect_retained(case,'d'*64);http.assert_not_called()
        self.assertEqual(review['priorOAuthAttempts'],278)
        self.assertEqual(review['maximumRemainingOAuthAttempts'],10)
        self.assertEqual(private['predecessorJournal']['path'],str(self.old.record))
        self.assertFalse(any(v in json.dumps(review)for v in('old-access','old-refresh','old-published')))
        self.assertEqual({p:p.read_bytes()for p in self.root.rglob('*')if p.is_file()},before)

    def test_changed_retained_artifact_is_not_adopted(self):
        case=self.retained_case();p=Path(case['ownerResultBinding']['path'])
        changed=json.loads(p.read_text());changed['maximumCumulativeOAuthAttempts']=999;p.write_bytes(encoded(changed))
        with self.assertRaisesRegex(Denied,'RETAINED_CANONICAL_ARTIFACT_CHANGED'):
            inspection.inspect_retained(case,'d'*64)
        self.assertFalse((self.previous/'successor-window.claim.json').exists())

    def test_retained_symlink_and_duplicate_json_are_rejected(self):
        case=self.retained_case();p=Path(case['packetBinding']['path']);renamed=p.with_suffix('.retained')
        p.rename(renamed);p.symlink_to(renamed)
        with self.assertRaises(OSError):inspection.inspect_retained(case,'d'*64)
        p.unlink();p.write_bytes(b'{"schema":"one","schema":"two"}');p.chmod(0o600)
        with self.assertRaisesRegex(Denied,'DUPLICATE_RETAINED_JSON_FIELD'):
            inspection.inspect_retained(case,'d'*64)

    def test_read_only_delivery_contains_no_authentication_or_journal_writer(self):
        raw,declaration=reader_delivery.generate(ROOT,self.retained_case())
        self.assertEqual(len(declaration['sourceHashes']),6)
        namespace={'__name__':'fixture_reader_not_main'};exec(compile(raw,'<fixture-reader>','exec'),namespace)
        policy=namespace['SOURCES']['tools.chatbot_file_cohort.human_session']
        self.assertNotIn('def ',policy)
        for source in namespace['SOURCES'].values():
            self.assertNotIn('def authenticate(',source)
            self.assertNotIn('def _request(',source)
            self.assertNotIn('def initialize(',source)
            self.assertNotIn('compare_and_save(',source)

    def test_isolated_read_only_delivery_joins_retained_case_and_rejects_tamper(self):
        kernel_boot=Path('/proc/sys/kernel/random/boot_id')
        if not kernel_boot.is_file():self.skipTest('Real Linux boot identifier required; qualified in root CI')
        case=self.retained_case();row=copy.deepcopy(self.row);row['bootId']=kernel_boot.read_text().strip()
        self.old.compare_and_save(self.row,row)
        before={p:p.read_bytes()for p in self.root.rglob('*')if p.is_file()}
        raw,declaration=reader_delivery.generate(ROOT,case)
        script=self.root/'reader.py';script.write_bytes(raw);script.chmod(0o600)
        result=subprocess.run([sys.executable,'-I','-B','-S',str(script)],text=True,
            capture_output=True,timeout=50)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        value=json.loads(result.stdout)
        self.assertEqual(value['status'],'REVIEW_COMPILED_NO_AUTHORITY')
        self.assertEqual((value['priorOAuthAttempts'],value['remainingAttempts']),(278,10))
        self.assertEqual(value['credentialJournalsOpened'],1)
        self.assertEqual(value['journalWrites'],0);self.assertEqual(value['oauthRequests'],0)
        self.assertFalse(any(s in result.stdout for s in('old-access','old-refresh','old-published')))
        for p,content in before.items():self.assertEqual(p.read_bytes(),content)
        # Corrupt the embedded declaration while retaining its expected digest.
        tampered=raw.replace(b"'readOnly': True",b"'readOnly': False",1)
        self.assertNotEqual(tampered,raw);script.write_bytes(tampered)
        result=subprocess.run([sys.executable,'-I','-B','-S',str(script)],text=True,
            capture_output=True,timeout=50)
        self.assertEqual(result.returncode,2);self.assertEqual(json.loads(result.stdout)['status'],'STOP_RECONCILE')
        for p,content in before.items():self.assertEqual(p.read_bytes(),content)

if __name__=='__main__':unittest.main()
