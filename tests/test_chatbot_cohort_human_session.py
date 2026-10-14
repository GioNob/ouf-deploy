"""Disposable loopback OAuth fixture; never represents a target HUMAN approval.

HTTP really crosses a local socket. Only the test opener maps the pinned HTTPS
issuer to this fixture. AggregateAction tests use real Ed25519 signatures and the
existing explicitly synthetic HUMAN mandate fixture.
"""
import base64
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import stat
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),
               str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.chatbot_file_cohort import human_session as module
from tools.chatbot_file_cohort.authorization import OwnerTransport
from tools.chatbot_file_cohort.plan import encoded
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
import test_cutover_authority_native as signed

ISSUER = 'https://issuer.fixture.invalid/realms/fixture'


class Clock:
    def __init__(self): self.now = int(time.time()); self.mono = time.monotonic()
    def time(self): return self.now
    def monotonic(self): return self.mono
    def advance(self, value): self.now += value; self.mono += value


class ImmediateFixtureWait:
    def __init__(self, clock): self.clock = clock
    def is_set(self): return False
    def wait(self, delay): self.clock.advance(delay)


class FixtureOpener:
    def __init__(self, port): self.base = 'http://127.0.0.1:'+str(port)
    def open(self, request, timeout):
        parsed = urllib.parse.urlsplit(request.full_url)
        assert parsed.hostname == 'issuer.fixture.invalid'
        # This test-only mapping is never available in production construction.
        routed = urllib.request.Request(self.base+parsed.path, data=request.data,
                                         headers=dict(request.header_items()), method=request.get_method())
        return urllib.request.urlopen(routed,timeout=timeout)


class OAuthFixture:
    def __init__(self, clock):
        self.clock, self.calls = clock, []
        self.refreshes, self.generation, self.polls, self.approve_after = 0, 0, 0, 1
        self.refresh_error = None
        self.drop_refresh = False
        self.userinfo_fail_once = False
        self.changed_subject = False
        self.fixed_access_expiry = None

    def token(self):
        self.generation += 1
        claims = {'iss':ISSUER,'sub':'changed-fixture' if self.changed_subject else 'human-fixture',
            'tenant_id':'tenant-fixture','ouf_actor_type':'HUMAN','azp':module.CLIENT,'acr':'1',
            'aud':['ouf-api-gateway'],'scope':' '.join(module.SCOPES),
            'exp':self.fixed_access_expiry or self.clock.time()+300,'jti':'fixture-'+str(self.generation)}
        b64 = lambda value:base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b'=').decode()
        # No synthetic signature is asserted as cryptographic token proof. The
        # loopback server models issuer userinfo authentication explicitly.
        return {'access_token':b64({'alg':'RS256'})+'.'+b64(claims)+'.fixture',
                'refresh_token':'private-fixture-refresh-'+str(self.generation),'token_type':'Bearer'}

    def handler(self):
        fixture = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_GET(self): self.handle_call()
            def do_POST(self): self.handle_call()
            def handle_call(self):
                raw = self.rfile.read(int(self.headers.get('Content-Length','0')))
                form = urllib.parse.parse_qs(raw.decode())
                fixture.calls.append((self.command,self.path,form))
                status, value = 200, {}
                prefix = '/realms/fixture/protocol/openid-connect/'
                if self.path.endswith('/.well-known/openid-configuration'):
                    value = {'issuer':ISSUER,'device_authorization_endpoint':ISSUER+'/protocol/openid-connect/auth/device',
                        'token_endpoint':ISSUER+'/protocol/openid-connect/token',
                        'userinfo_endpoint':ISSUER+'/protocol/openid-connect/userinfo'}
                elif self.path == prefix+'auth/device':
                    value = {'device_code':'private-device-fixture','user_code':'USER-1234',
                        'verification_uri':ISSUER+'/device','expires_in':600,'interval':5}
                elif self.path == prefix+'token':
                    if form.get('grant_type') == ['refresh_token']:
                        fixture.refreshes += 1
                        if fixture.refresh_error:
                            status, value = fixture.refresh_error
                        else:
                            value = fixture.token()
                            if fixture.drop_refresh:
                                self.connection.shutdown(socket.SHUT_RDWR); self.connection.close(); return
                    else:
                        fixture.polls += 1
                        if fixture.polls < fixture.approve_after:
                            status, value = 400, {'error':'authorization_pending'}
                        else: value = fixture.token()
                elif self.path == prefix+'userinfo':
                    if fixture.userinfo_fail_once:
                        fixture.userinfo_fail_once = False
                        status, value = 503, {'error':'temporarily_unavailable'}
                    else:
                        value = {'sub':'human-fixture'}
                else:
                    status, value = 404, {'error':'invalid_request'}
                data = json.dumps(value).encode()
                self.send_response(status); self.send_header('Content-Type','application/json')
                self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)
        return Handler


class HumanSessionTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT,prefix='human-session-fixture-')
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name); self.directory.chmod(0o700)
        self.clock = Clock()
        p = patch.object(module,'time',self.clock); p.start(); self.addCleanup(p.stop)
        # The local tool sandbox omits /proc; production still requires the real
        # kernel boot identity, with no fallback or configurable bypass.
        p = patch.object(module.HumanSession,'_boot',return_value='explicit-disposable-kernel-fixture')
        p.start(); self.addCleanup(p.stop)
        self.fixture = OAuthFixture(self.clock)
        self.server = ThreadingHTTPServer(('127.0.0.1',0),self.fixture.handler())
        self.worker = threading.Thread(target=self.server.serve_forever,daemon=True); self.worker.start()
        self.addCleanup(self.server.server_close); self.addCleanup(self.server.shutdown)
        self.selection = {'origin':'https://gateway.fixture.invalid','issuer':ISSUER,'tenant':'tenant-fixture',
            'subject':'human-fixture','docker':{'path':'/usr/bin/docker','sha256':'a'*64},
            'keycloakContainer':'b'*64,'realm':'fixture',
            'clients':{p:{'clientId':'fixture-'+p,'requestedScopes':[]} for p in ('chatgpt','ths')}}
        self.expires = int(self.clock.time()+3600)
        self.output = []
        self.session = self.new_session()

    def new_session(self, action=None):
        session = module.HumanSession(self.selection,self.directory,self.directory/'human-access.jwt',self.expires,action)
        session.opener = FixtureOpener(self.server.server_port)
        return session

    def login(self):
        return self.session.login(self.output.append,ImmediateFixtureWait(self.clock))

    def due(self): self.clock.advance(250)

    def test_real_loopback_login_refresh_atomic_bearer_and_current_owner_transport(self):
        self.fixture.approve_after = 3
        binding = self.login(); old = self.session.token_path.read_text()
        inode = self.session.token_path.stat().st_ino
        self.assertEqual(binding['clientId'],'ouf-human-admin')
        self.assertEqual(self.fixture.polls,3)
        self.assertNotIn('private-device-fixture',' '.join(self.output))
        self.assertNotIn('private-fixture-refresh',' '.join(self.output))
        self.assertNotIn('access_token',json.dumps(binding))
        transport = OwnerTransport(self.selection,self.session.token_path,self.session.token_path)
        self.assertEqual(transport.token('admin'),old)
        self.assertEqual(transport.token('mcp'),old)
        attempts = self.session.journal.read()['attempts']; self.due()
        self.assertEqual(self.session.refresh_if_due(),binding)
        self.assertEqual(self.fixture.refreshes,1)
        self.assertNotEqual(transport.token('admin'),old)
        self.assertNotEqual(self.session.token_path.stat().st_ino,inode)
        self.assertEqual(stat.S_IMODE(self.session.token_path.stat().st_mode),0o600)
        self.assertEqual(self.session.journal.read()['attempts'],attempts+2)
        self.assertEqual(self.session.current(),binding)

    def test_rotation_reply_loss_blocks_restart_without_replay_or_budget_reset(self):
        self.login(); self.due(); self.fixture.drop_refresh = True
        with self.assertRaisesRegex(module.HumanSessionPaused,'OUTCOME_UNPROVEN'): self.session.refresh_if_due()
        before = self.session.journal.read(); resumed = self.new_session()
        with self.assertRaisesRegex(module.HumanSessionPaused,'OUTCOME_UNPROVEN'): resumed.refresh_if_due()
        self.assertEqual(self.fixture.refreshes,1)
        self.assertEqual(resumed.journal.read(),before)

    def test_received_rotation_reconciles_userinfo_after_transient_failure_without_refresh_replay(self):
        self.login(); old = self.session.token_path.read_text(); self.due()
        self.fixture.userinfo_fail_once = True
        with self.assertRaises(module.HumanSessionPaused) as error: self.session.refresh_if_due()
        self.assertIsNotNone(error.exception.retry_at)
        self.assertEqual(self.session.token_path.read_text(),old)
        # The prior bearer remains usable while a new rotation is checked.
        self.assertEqual(self.session.current()['subject'],'human-fixture')
        before = self.session.journal.read(); self.clock.advance(20)
        resumed = self.new_session(); resumed.refresh_if_due()
        self.assertEqual(self.fixture.refreshes,1)
        self.assertEqual(resumed.journal.read()['attempts'],before['attempts']+1)
        self.assertNotEqual(resumed.token_path.read_text(),old)

    def test_permanent_revocation_and_changed_identity_do_not_publish_or_repeat(self):
        self.login(); old = self.session.token_path.read_text(); self.due()
        self.fixture.refresh_error = (400,{'error':'invalid_grant','error_description':'private-never-print'})
        with self.assertRaisesRegex(module.HumanSessionPaused,'REVOKED_OR_PERMANENT'): self.session.refresh_if_due()
        with self.assertRaises(module.HumanSessionPaused): self.new_session().refresh_if_due()
        self.assertEqual(self.fixture.refreshes,1); self.assertEqual(self.session.token_path.read_text(),old)
        self.assertNotIn('private-never-print',self.session.journal.record.read_text())

    def test_wrong_subject_in_new_token_never_replaces_valid_bearer(self):
        self.login(); old = self.session.token_path.read_text(); self.due(); self.fixture.changed_subject = True
        with self.assertRaisesRegex(ValueError,'EXACT_CURRENT_HUMAN_CONTEXT'): self.session.refresh_if_due()
        self.assertEqual(self.session.token_path.read_text(),old)
        with self.assertRaisesRegex(module.HumanSessionPaused,'INTERRUPTED_OUTCOME_UNPROVEN'): self.new_session().refresh_if_due()
        self.assertEqual(self.fixture.refreshes,1)

    def test_persisted_temporary_budget_and_deadline_cannot_reset_on_restart(self):
        self.login(); self.due(); self.fixture.refresh_error = (503,{'error':'temporarily_unavailable'})
        with self.assertRaises(module.HumanSessionPaused): self.session.refresh_if_due()
        before = self.session.journal.read(); resumed = self.new_session()
        with self.assertRaises(module.HumanSessionPaused): resumed.refresh_if_due()
        self.assertEqual(resumed.journal.read(),before); self.assertEqual(self.fixture.refreshes,1)
        self.clock.advance(3700)
        with self.assertRaisesRegex(ValueError,'WINDOW_EXPIRED'): resumed.refresh_if_due()
        self.assertEqual(self.fixture.refreshes,1)

    def test_hour_read_outage_uses_received_new_rotation_and_preserves_cumulative_budget(self):
        self.expires = int(self.clock.time()+7200); self.session = self.new_session()
        self.login(); self.due(); self.fixture.userinfo_fail_once = True
        with self.assertRaises(module.HumanSessionPaused): self.session.refresh_if_due()
        before = self.session.journal.read()
        self.clock.advance(3600)
        resumed = self.new_session()
        with self.assertRaisesRegex(module.HumanSessionPaused,'REFRESH_PENDING'): resumed.current()
        resumed.refresh_if_due()
        refresh_forms = [form for _,_,form in self.fixture.calls if form.get('grant_type') == ['refresh_token']]
        self.assertEqual(len(refresh_forms),2)
        self.assertEqual(refresh_forms[0]['refresh_token'],['private-fixture-refresh-1'])
        self.assertEqual(refresh_forms[1]['refresh_token'],['private-fixture-refresh-2'])
        self.assertEqual(resumed.journal.read()['attempts'],before['attempts']+2)
        self.assertFalse(resumed.journal.read()['budgetReset'])
        self.assertEqual(resumed.current()['subject'],'human-fixture')

    def test_exhaustion_is_durable_and_restart_cannot_extend_window(self):
        self.login(); self.due(); row = self.session.journal.read()
        self.session._save(row,attempts=128)
        for session in (self.session,self.new_session()):
            with self.assertRaisesRegex(ValueError,'BUDGET_EXHAUSTED'): session.refresh_if_due()
        self.assertEqual(self.fixture.refreshes,0)
        with self.assertRaisesRegex(ValueError,'BINDING_OR_HISTORY_DRIFT'):
            module.HumanSession(self.selection,self.directory,self.session.token_path,self.expires+1).current()

    def test_preparation_login_resume_refreshes_expired_bearer_without_new_device_approval(self):
        binding = self.login(); attempts = self.session.journal.read()['attempts']
        self.clock.advance(400)
        self.session = self.new_session()
        self.assertEqual(self.login(),binding)
        self.assertEqual(self.fixture.polls,1); self.assertEqual(self.fixture.refreshes,1)
        self.assertEqual(self.session.journal.read()['attempts'],attempts+2)

    def test_ready_is_not_advertised_before_the_actual_bearer_file_is_published(self):
        self.login(); old = self.session.token_path.read_text(); self.clock.advance(400)
        original = self.session._publish; observed = []
        def publication(row):
            observed.append(row['state'])
            self.assertEqual(self.session.token_path.read_text(),old)
            with self.assertRaisesRegex(module.HumanSessionPaused,'REFRESH_PENDING'): self.session.current()
            original(row)
        with patch.object(self.session,'_publish',side_effect=publication):
            self.session.refresh_if_due()
        self.assertEqual(observed,['REQUESTING'])
        self.assertNotEqual(self.session.token_path.read_text(),old)
        self.assertEqual(self.session.current()['subject'],'human-fixture')

    def test_owner_token_waits_before_dispatch_and_reads_the_refreshed_file(self):
        self.login(); old = self.session.token_path.read_text(); self.clock.advance(400)
        waits = []
        def wait(seconds):
            waits.append(seconds); self.clock.advance(seconds)
            self.session.refresh_if_due()
        transport = OwnerTransport(self.selection,self.session.token_path,self.session.token_path,
                                   wait=wait,human_session=self.session)
        token = transport.token('admin')
        self.assertEqual(len(waits),1); self.assertTrue(1 <= waits[0] <= 5)
        self.assertNotEqual(token,old)
        self.assertEqual(token,self.session.token_path.read_text())
        self.assertEqual(self.fixture.refreshes,1)
        self.assertTrue(all(path.startswith('/realms/fixture/') for _,path,_ in self.fixture.calls))

    def test_current_bearer_survives_concurrent_refresh_request_and_worker_cancellation(self):
        self.login(); row = self.session.journal.read()
        self.session._save(row,state='REQUESTING',operation='REFRESH',resumeState='READY')
        self.assertEqual(self.session.current()['subject'],'human-fixture')
        stopped = threading.Event(); stopped.set(); calls = len(self.fixture.calls)
        worker = self.session.start_refresh(stopped,self.output.append); worker.join(2)
        self.assertFalse(worker.is_alive()); self.assertEqual(len(self.fixture.calls),calls)

    def test_http_issuer_and_unsafe_token_path_are_rejected_before_network(self):
        with self.assertRaisesRegex(ValueError,'PINNED_HTTPS'):
            module.HumanSession(dict(self.selection,issuer='http://127.0.0.1/realm'),self.directory,
                                self.directory/'human-access.jwt',self.expires)
        self.login(); self.session.token_path.unlink(); self.session.token_path.symlink_to(self.session.journal.record)
        with self.assertRaisesRegex(ValueError,'FILE_CUSTODY'): self.session.refresh_if_due()
        self.assertEqual(self.fixture.refreshes,0)

    def test_interrupted_read_reconciles_but_interrupted_refresh_is_not_replayed(self):
        self.login(); row = self.session.journal.read()
        self.session._save(row,state='REQUESTING',operation='REFRESH',resumeState='READY')
        with self.assertRaisesRegex(module.HumanSessionPaused,'INTERRUPTED'): self.new_session().refresh_if_due()
        self.assertEqual(self.fixture.refreshes,0)

    def test_exact_real_signed_binding_and_revocation_checked_before_network(self):
        binding = self.login()
        crypto = signed.SignedCutover(); crypto.setUp(); self.addCleanup(crypto.doCleanups)
        authority = json.loads(crypto.authority)
        authority['chatbotFileAuthorization'] = {'sessionBinding':binding,'fixtureScopeOnly':True}
        crypto.authority = encoded(authority); crypto.approval['executionAuthorityHash'] = signed.sha(crypto.authority)
        crypto.write(crypto.mandate,encoded(crypto.approval)); crypto.approved = signed.sha(crypto.mandate.read_bytes())
        for role in crypto.grant['roles']: crypto.sign(role)
        action = AggregateAction(crypto.gate(),crypto.authority,crypto.expected['sourceClosureHash'])
        child = self.new_session(action); self.assertEqual(child.current(),binding)
        before = len(self.fixture.calls)
        crypto.approval['state'] = 'REVOKED'; crypto.write(crypto.mandate,encoded(crypto.approval))
        with self.assertRaisesRegex(Exception,'MANDATE_CHANGED'): child.refresh_if_due()
        self.assertEqual(len(self.fixture.calls),before)
        self.assertEqual(self.fixture.refreshes,0)


if __name__ == '__main__': unittest.main()
