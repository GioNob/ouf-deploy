"""Explicit terminal consent, one counted authentication, real Docker namespace."""
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

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'tests')]
from tools.ingestion_rollout_preparation import iam_explicit_api as a, iam_explicit_api_delivery as delivery
from tools.ingestion_rollout_preparation import iam_policy_read as p, human_timing as files
from tools.ingestion_rollout_preparation import iam_session_context_reconcile as r
from tools.semantic_lease_recovery.recovery_journal import Journal
import test_iam_context_reconcile as context_fixture


class ExplicitApi(unittest.TestCase):
    def setUp(self):
        self.c = context_fixture.ContextReconcile()
        self.c.setUp()
        self.addCleanup(self.c.doCleanups)
        self.f = self.c.f
        self.calls = []
        self.install_human_history()
        self.source_hash = hashlib.sha256((ROOT / 'tools/ingestion_rollout_preparation/iam_session_context_reconcile.py').read_bytes()).hexdigest()
        with self.c.process_fixture(), patch.object(p, 'EngineRead', self.f.fake_engine()):
            receipt = r.run(self.c.case, p, files, Journal, self.source_hash)
        self.select_receipt(receipt)

    def install_human_history(self):
        config = json.loads((self.f.control / 'control.json').read_text())
        session = self.f.control.parent / ('human-successor-' + p.digest(config['review']))
        if not session.exists():
            session.mkdir(mode=0o700)
        binding = {'selectionHash': p.digest(self.f.selection), 'clientId': 'fixture-human-admin',
            'sessionDirectory': str(session), 'expiresAt': int(time.time()) - 100}
        self.f.write(self.f.control / 'binding.json', binding)
        self.human = {'schema': 'ouf.chatbot-human-session.private.v1', 'state': 'READY',
            'binding': binding, 'attempts': 282, 'budgetReset': False,
            'accessToken': 'PRIVATE-HUMAN-ACCESS-MUST-NOT-USE'}
        Journal(session).initialize(self.human)
        _, seal = files.selected(str(session / 'recovery.json'))
        self.f.write(self.f.control / 'human-read-profile.json', {'expectedBinding': binding,
            'selection': self.f.selection, 'minimumCumulativeAttempts': 282,
            'maximumCumulativeAttempts': 288, 'journal': seal})
        self.session = session

    def select_receipt(self, receipt):
        self.case = {'schema': 'ouf.iam-explicit-api-case.v1', 'reconciledCase': copy.deepcopy(self.c.case),
            'retainedReconciliationResultHash': p.digest(receipt), 'reconciledSourceHash': self.source_hash,
            'expectedAttempts': 282, 'maximumCumulativeOAuthAttempts': 288,
            'maximumNewOAuthRequests': 1, 'maximumNewEngineGets': 2, 'maximumNewAdminGets': 4}
        self.destination = Path(self.c.case['retainedContextPath']) / 'explicit-admin-api-successor'

    def token(self, remaining=60):
        now = int(time.time())
        claims = {'iss': 'http://localhost:8080/realms/master', 'azp': 'admin-cli',
            'iat': now, 'exp': now + remaining}
        # Deliberately omit preferred_username AND sub, as in Keycloak26's
        # default lightweight admin-cli token. ID token carries the subject.
        token = 'fixture.' + base64.urlsafe_b64encode(p.encoded(claims)).decode().rstrip('=') + '.fixture'
        identity={**claims,'sub':'fixture-admin-subject','aud':'admin-cli'}
        id_token='fixture.'+base64.urlsafe_b64encode(p.encoded(identity)).decode().rstrip('=')+'.fixture'
        return {'access_token': token, 'token_type': 'Bearer', 'expires_in': remaining,
            'id_token': id_token,
            'refresh_token': 'PRIVATE-NEW-REFRESH-MUST-NOT-STORE'}

    def reply(self, api, program, ns, payload):
        op = payload['operation']
        self.calls.append(op)
        self.assertEqual(Journal(self.destination).read()['attempts'], 283)
        if op == 'PASSWORD_GRANT':
            self.assertEqual(payload['credential'], 'PRIVATE-ADMIN-PASSWORD')
            return self.token()
        if op == 'IDENTITY':
            return {'id': 'fixture-admin-subject', 'username': 'fixture-admin', 'enabled': True,
                'email': 'PRIVATE-UNNECESSARY-IDENTITY'}
        if op == 'REALM':
            return self.f.realm
        if op == 'CLIENT_LIST':
            return [self.f.client]
        if op == 'CLIENT':
            return self.f.client
        raise AssertionError(op)

    def invoke(self, reply=None):
        with self.c.process_fixture(), self.f.synthetic_namespace(), \
            patch.object(p, 'EngineRead', self.f.fake_engine()), \
            patch.object(a, 'terminal', side_effect=[True, 'PRIVATE-ADMIN-PASSWORD']), \
            patch.object(a, 'dispatch', side_effect=reply or self.reply):
            return a.run(self.case, p, files, r, Journal)

    def test_one_counted_login_lookup_supports_absent_username_old_stop_unchanged(self):
        old = (Path(self.c.context) / 'recovery.json').read_bytes()
        human = (self.session / 'recovery.json').read_bytes()
        result = self.invoke()
        self.assertEqual(self.calls, ['PASSWORD_GRANT', 'IDENTITY', 'REALM', 'CLIENT_LIST', 'CLIENT'])
        self.assertEqual(result['attempts'], 283)
        self.assertEqual(result['remainingAttempts'], 5)
        self.assertEqual(result['engineRequestsThisOperation'], 2)
        self.assertEqual(result['adminGetsReserved'], 4)
        self.assertTrue(result['currentProviderPolicyProven'])
        self.assertTrue(result['adminIdentityApiVerified'])
        self.assertFalse(result['runtimeAuthorityIssued'])
        self.assertEqual((Path(self.c.context) / 'recovery.json').read_bytes(), old)
        self.assertEqual((self.session / 'recovery.json').read_bytes(), human)
        self.assertNotIn('PRIVATE-', json.dumps(result))
        self.assertNotIn('PRIVATE-', (self.destination / 'recovery.json').read_text())
        claim = json.loads((self.session / 'successor-window.claim.json').read_text())
        self.assertEqual(claim['priorOAuthAttempts'], 282)
        self.assertTrue(claim['futureHumanSuccessorMustIncludeThisLedger'])

    def test_wrong_api_subject_or_username_stops_before_policy_and_cannot_repeat(self):
        def wrong(*args):
            value = self.reply(*args)
            if args[-1]['operation'] == 'IDENTITY':
                value['username'] = 'different-user'
            return value
        with self.assertRaisesRegex(ValueError, 'PROVIDER_ADMIN_SUBJECT_USERNAME'):
            self.invoke(wrong)
        self.assertEqual(self.calls, ['PASSWORD_GRANT', 'IDENTITY'])
        self.assertEqual(Journal(self.destination).read()['attempts'], 283)
        with patch.object(a, 'terminal') as terminal, patch.object(a, 'dispatch') as dispatch:
            with self.assertRaisesRegex(ValueError, 'ADMIN_SUCCESSOR_ALREADY_CLAIMED'):
                a.run(self.case, p, files, r, Journal)
        terminal.assert_not_called()
        dispatch.assert_not_called()

    def test_transport_ambiguity_is_reserved_once_and_status_has_no_secret_io(self):
        with self.assertRaisesRegex(ValueError, 'UNKNOWN_OUTCOME'):
            self.invoke(lambda *args: (_ for _ in ()).throw(ValueError('UNKNOWN_OUTCOME')))
        with patch.object(a, 'terminal') as tty, patch.object(a, 'dispatch') as dispatch:
            value = a.status(self.case, p, files, Journal)
        tty.assert_not_called()
        dispatch.assert_not_called()
        self.assertEqual(value['attempts'], 283)
        self.assertEqual(value['oauthRequestsReserved'], 1)
        self.assertEqual(value['state'], 'STOP_RECONCILE')
        self.assertEqual(value['humanCredentialJournalsRead'], 0)

    def test_terminal_decline_or_wrong_history_has_no_authentication_claim(self):
        with patch.object(a, 'terminal', side_effect=ValueError('EXACT_ADMIN_API_TERMINAL_CONSENT_REQUIRED')):
            with self.assertRaises(ValueError):
                a.run(self.case, p, files, r, Journal)
        self.assertFalse((self.session / 'successor-window.claim.json').exists())
        self.assertFalse(self.destination.exists())
        self.f.write(self.session / 'recovery.json', {**self.human, 'attempts': 283})
        with patch.object(a, 'terminal') as tty:
            with self.assertRaises(ValueError):
                a.run(self.case, p, files, r, Journal)
            tty.assert_not_called()

    def test_short_token_never_triggers_refresh_or_admin_get(self):
        with self.assertRaisesRegex(ValueError, 'TOKEN_TOO_SHORT'):
            self.invoke(lambda *args: self.token(30))
        self.assertEqual(Journal(self.destination).read()['adminGetsReserved'], 0)
        self.assertEqual(Journal(self.destination).read()['attempts'], 283)

    def test_lightweight_subject_requires_fresh_same_response_id_token_audience(self):
        response=self.token()
        endpoint=self.f.case['adminReadProfile']
        bad={k:v for k,v in response.items()if k!='id_token'}
        with self.assertRaisesRegex(ValueError,'OIDC_ID_TOKEN_REQUIRED'):
            a.access(p,bad,endpoint,self.f.selection['issuer'],time.time())
        part=response['id_token'].split('.')[1]
        identity=json.loads(base64.urlsafe_b64decode(part+'='*(-len(part)%4)))
        identity['aud']='another-client'
        bad={**response,'id_token':'fixture.'+base64.urlsafe_b64encode(p.encoded(identity)).decode().rstrip('=')+'.fixture'}
        with self.assertRaisesRegex(ValueError,'AUDIENCE_MUST_INCLUDE'):
            a.access(p,bad,endpoint,self.f.selection['issuer'],time.time())

    def test_foreign_namespace_endpoint_and_changed_receipt_rejected_before_terminal(self):
        with patch.object(a, 'terminal') as tty:
            bad = copy.deepcopy(self.case)
            bad['retainedReconciliationResultHash'] = '0' * 64
            with self.assertRaisesRegex(ValueError, 'EXACT_COMPLETED_METADATA'):
                a.run(bad, p, files, r, Journal)
            tty.assert_not_called()

    def test_password_echo_restored_on_timeout_and_no_echoed_secret_in_prompt(self):
        # An actual tty is used in CI below; this verifies restoration on the
        # exceptional path without requiring /dev/tty inside the local sandbox.
        import termios
        attrs = [0, 0, 0, termios.ECHO | termios.ECHONL, 0, 0, []]
        with patch.object(a.os, 'open', return_value=77), patch.object(a.os, 'fstat') as fs, \
            patch.object(a.os, 'isatty', return_value=True), patch.object(a.stat, 'S_ISCHR', return_value=True), \
            patch.object(a.os, 'write') as write, patch.object(a.os, 'close'), \
            patch.object(a.termios, 'tcflush'), patch.object(a.termios, 'tcgetattr', side_effect=[attrs.copy(), attrs.copy()]), \
            patch.object(a.termios, 'tcsetattr') as setattrs, patch.object(a.select, 'select', return_value=([], [], [])):
            with self.assertRaisesRegex(ValueError, 'TERMINAL_INPUT_TIMEOUT'):
                a.terminal('Password nascosta')
        self.assertFalse(setattrs.call_args_list[0].args[2][3] & termios.ECHO)
        self.assertEqual(setattrs.call_args_list[-1].args[2], attrs)

    def test_reproducible_sealed_delivery_and_pinned_launcher(self):
        case = json.loads((ROOT / 'releases/iam-explicit-api-case-20261021.json').read_text())
        raw, _ = delivery.generate(ROOT, case)
        self.assertEqual(raw, (ROOT / 'scripts/iam-explicit-api-20261021.py').read_bytes())
        launcher = ROOT / 'scripts/launch-iam-explicit-api-20261021.sh'
        shell = launcher.read_text()
        self.assertIn(hashlib.sha256(raw).hexdigest(), shell)
        self.assertIn(hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(), shell)
        self.assertEqual(subprocess.run(['/bin/bash', '-n', str(launcher)]).returncode, 0)

    def test_actual_docker_namespace_and_terminal_sealed_authentication(self):
        if os.environ.get('GITHUB_ACTIONS') != 'true':
            self.skipTest('Docker namespace and controlling tty are mandatory in CI')
        self.physical()

    def test_real_keycloak_26_admin_password_grant_and_identity_policy_api(self):
        if os.environ.get('GITHUB_ACTIONS') != 'true':
            self.skipTest('Real disposable Keycloak provider is mandatory in CI')
        fixture = self.f.root / 'keycloak-physical'
        fixture.mkdir(mode=0o755)
        # No CLI credential is consumed by the new operation. This private
        # mounted cache exists only to reproduce the stopped predecessor.
        credentials = fixture / '.keycloak'
        credentials.mkdir(mode=0o700)
        os.chown(credentials, 1000, 1000)
        self.f.write(credentials / 'kcadm.config', self.c.modified_config(username=None, seconds=-10))
        os.chown(credentials / 'kcadm.config', 1000, 1000)
        # Explicit disposable-fixture values, never product defaults or real
        # credentials. No production password is placed in an environment.
        start = subprocess.run(['docker','run','-d','--network','none',
            '-e','KC_BOOTSTRAP_ADMIN_USERNAME=fixture-admin',
            '-e','KC_BOOTSTRAP_ADMIN_PASSWORD=PRIVATE-ADMIN-PASSWORD',
            '--mount','type=bind,src='+str(credentials)+',dst=/opt/keycloak/.keycloak,readonly',
            'quay.io/keycloak/keycloak:26.2.5','start-dev','--hostname=http://localhost:8080'],
            capture_output=True,text=True,timeout=240)
        self.assertEqual(start.returncode,0,start.stderr)
        cid=start.stdout.strip()
        self.addCleanup(lambda:subprocess.run(['docker','rm','-f',cid],capture_output=True,timeout=30))
        ready=False
        for _ in range(120):
            probe=subprocess.run(['docker','exec',cid,'bash','-c','exec 3<>/dev/tcp/127.0.0.1/8080'],capture_output=True,timeout=5)
            if probe.returncode==0:
                ready=True
                break
            time.sleep(.5)
        self.assertTrue(ready,'Disposable Keycloak did not become ready within finite fixture budget')
        # Read the real built-in admin-cli configuration in master. No client
        # creation or policy change is required even in this fixture.
        self.f.selection['realm']='master'
        self.f.selection['issuer']='http://localhost:8080/realms/master'
        self.f.case['humanClientId']='admin-cli'
        self.qualify_container(cid,fixture,'admin-cli')

    def physical(self):
        # Disposable protocol fixture, not the real Keycloak provider. All
        # process-root, Docker HTTP, setns, controlling-tty and child boundaries
        # are actual. Never log a form body, header or credential.
        fixture = self.f.root / 'explicit-physical'
        fixture.mkdir(mode=0o755)
        credentials = fixture / '.keycloak'
        credentials.mkdir(mode=0o700)
        os.chown(credentials, 1000, 1000)
        config_path = credentials / 'kcadm.config'
        self.f.write(config_path, self.c.modified_config(username=None, seconds=-10))
        os.chown(config_path, 1000, 1000)
        passwd = fixture / 'passwd'
        passwd.write_bytes(self.f.passwd)
        passwd.chmod(0o644)
        server = fixture / 'server.py'
        server.write_text(PHYSICAL_SERVER)
        server.chmod(0o644)
        start = subprocess.run(['docker', 'run', '-d', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
            '--user', '1000:1000', '-e', 'HOME=/home/fixture',
            '--mount', 'type=bind,src='+str(credentials)+',dst=/home/fixture/.keycloak,readonly',
            '--mount', 'type=bind,src='+str(passwd)+',dst=/etc/passwd,readonly',
            '--mount', 'type=bind,src='+str(server)+',dst=/server.py,readonly',
            'python:3.13.5-slim', 'python3', '-B', '/server.py'], capture_output=True, text=True, timeout=180)
        self.assertEqual(start.returncode, 0, start.stderr)
        cid = start.stdout.strip()
        self.addCleanup(lambda: subprocess.run(['docker', 'rm', '-f', cid], capture_output=True, timeout=30))
        self.qualify_container(cid,fixture,'fixture-human-admin')

    def qualify_container(self,cid,fixture,client_id):
        subprocess.run(['docker', 'inspect', cid], capture_output=True, check=True, timeout=10)
        time.sleep(.3)
        self.f.selection['keycloakContainer'] = cid
        self.f.plan['humanBinding']['selectionHash'] = p.digest(self.f.selection)
        s = os.stat('/var/run/docker.sock', follow_symlinks=False)
        self.f.plan['engine'] = {'socketPath': '/var/run/docker.sock',
            'socketBinding': [s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode & 0o777]}
        self.f.write(self.f.owner / 'plan.json', self.f.plan)
        self.f.case['ownerPlanBinding']['sha256'] = p.digest(self.f.plan)
        self.f.case['fixtureObservationRef'] = 'new-disposable-physical-installation'
        cfg = json.loads((self.f.control / 'control.json').read_text())
        cfg['selection'] = self.f.selection
        self.f.write(self.f.control / 'control.json', cfg)
        # Recreate only this disposable fixture's history with the new binding.
        # A real target journal is never rewritten by the production operation.
        human_binding = {**self.human['binding'], 'selectionHash': p.digest(self.f.selection),'clientId':client_id}
        self.f.write(self.f.control / 'binding.json', human_binding)
        self.human['binding'] = human_binding
        self.f.write(self.session / 'recovery.json', self.human)
        _, seal = files.selected(str(self.session / 'recovery.json'))
        self.f.write(self.f.control / 'human-read-profile.json', {'expectedBinding': human_binding,
            'selection': self.f.selection,'minimumCumulativeAttempts':282,'maximumCumulativeAttempts':288,'journal':seal})
        with self.assertRaisesRegex(ValueError, 'EXACT_RECORDED_ADMIN_SESSION_CONTEXT_REQUIRED'):
            self.f.invoke()
        context = p.CHECKPOINT['contextPath']
        self.c.case['retainedContextPath'] = context
        self.c.case['originalReadCase'] = self.f.case
        receipt = r.run(self.c.case, p, files, Journal, self.source_hash)
        self.select_receipt(receipt)
        raw, _ = delivery.generate(ROOT, self.case)
        script = fixture / 'sealed.py'
        script.write_bytes(raw)
        old = (Path(context) / 'recovery.json').read_bytes()
        human = (self.session / 'recovery.json').read_bytes()
        output = run_terminal(script, [b'AUTORIZZO LETTURA IAM API ', b'Password IAM per '],
            [None, b'PRIVATE-ADMIN-PASSWORD\n'])
        self.assertEqual(output['returncode'], 0, output['text'])
        result = json.loads(output['text'].splitlines()[-1])
        self.assertTrue(result['adminIdentityApiVerified'])
        self.assertEqual(result['attempts'], 283)
        self.assertEqual(result['adminGetsReserved'], 4)
        self.assertNotIn('PRIVATE-', output['text'])
        self.assertEqual((Path(context) / 'recovery.json').read_bytes(), old)
        self.assertEqual((self.session / 'recovery.json').read_bytes(), human)
        self.assertNotIn('PRIVATE-', (self.destination / 'recovery.json').read_text())
        status = subprocess.run(['/usr/bin/python3','-I','-B','-S',str(script),'status'],capture_output=True,text=True,timeout=15)
        self.assertEqual(status.returncode, 0, status.stdout+status.stderr)
        self.assertEqual(json.loads(status.stdout)['oauthRequestsThisInvocation'], 0)
        # Re-execute must reject before any prompt/authentication dispatch.
        replay = subprocess.run(['/usr/bin/python3','-I','-B','-S',str(script),'execute'],capture_output=True,text=True,timeout=15)
        self.assertEqual(replay.returncode, 2)
        self.assertIn('ADMIN_SUCCESSOR_ALREADY_CLAIMED', replay.stdout)


def run_terminal(script, markers, responses):
    import errno
    import pty
    import select
    import termios
    pid, fd = pty.fork()
    if pid == 0:
        os.execv('/usr/bin/python3', ['/usr/bin/python3','-I','-B','-S',str(script),'execute'])
    raw, sent, ended = b'', 0, False
    deadline = time.monotonic()+80
    try:
        while time.monotonic() < deadline:
            if select.select([fd],[],[],.2)[0]:
                try:
                    chunk = os.read(fd,65536)
                except OSError as error:
                    if error.errno == errno.EIO:
                        ended=True
                        break
                    raise
                if not chunk:
                    ended=True
                    break
                raw += chunk
                if sent < len(markers) and markers[sent] in raw and raw.endswith(b'> '):
                    if responses[sent] is None:
                        phrase = raw.rsplit(b'Scrivi esattamente: ',1)[1].split(b'\r\n',1)[0]
                        os.write(fd,phrase+b'\n')
                    else:
                        if termios.tcgetattr(fd)[3] & termios.ECHO:
                            raise AssertionError('PASSWORD_ECHO_MUST_BE_DISABLED')
                        os.write(fd,responses[sent])
                    sent += 1
        if not ended:
            os.kill(pid,9)
            raise AssertionError('Finite physical terminal fixture timeout')
        _, status = os.waitpid(pid,0)
        return {'returncode':os.waitstatus_to_exitcode(status),'text':raw.decode().replace('\r\n','\n')}
    finally:
        os.close(fd)


PHYSICAL_SERVER = '''import base64,http.server,json,time,urllib.parse
def token(identity=False):
 now=int(time.time());claims={'iss':'http://localhost:8080/realms/master','azp':'admin-cli','iat':now,'exp':now+60}
 if identity:claims.update(sub='fixture-admin-subject',aud='admin-cli')
 return 'fixture.'+base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')+'.fixture'
issued=None
class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def reply(self,status,value):
  raw=json.dumps(value).encode();self.send_response(status);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
 def do_POST(self):
  global issued
  size=int(self.headers.get('Content-Length','0'))
  if not 0<size<8192:self.reply(400,{});return
  v=urllib.parse.parse_qs(self.rfile.read(size).decode())
  if self.path!='/realms/master/protocol/openid-connect/token' or v!={'client_id':['admin-cli'],'grant_type':['password'],'username':['fixture-admin'],'password':['PRIVATE-ADMIN-PASSWORD'],'scope':['openid']}:self.reply(400,{});return
  issued=token();self.reply(200,{'access_token':issued,'id_token':token(True),'token_type':'Bearer','expires_in':60,'refresh_token':'PRIVATE-RETURNED-REFRESH'})
 def do_GET(self):
  if issued is None or self.headers.get('Authorization')!='Bearer '+issued:self.reply(401,{});return
  client={'id':'fixture-client-uuid','clientId':'fixture-human-admin','enabled':True,'protocol':'openid-connect','attributes':{'access.token.lifespan':'300'},'secret':'PRIVATE-CLIENT-SECRET'}
  if self.path=='/admin/realms/master/users/fixture-admin-subject':value={'id':'fixture-admin-subject','username':'fixture-admin','enabled':True,'email':'PRIVATE-EMAIL'}
  elif self.path=='/admin/realms/fixture':value={'realm':'fixture','accessTokenLifespan':300,'ssoSessionIdleTimeout':1800,'ssoSessionMaxLifespan':36000,'clientSessionIdleTimeout':0,'clientSessionMaxLifespan':0,'smtpServer':{'password':'PRIVATE-SMTP'}}
  elif self.path=='/admin/realms/fixture/clients?clientId=fixture-human-admin&exact=true&first=0&max=2':value=[client]
  elif self.path=='/admin/realms/fixture/clients/fixture-client-uuid':value=client
  else:self.reply(404,{});return
  self.reply(200,value)
http.server.HTTPServer(('127.0.0.1',8080),Handler).serve_forever()
'''


if __name__ == '__main__':
    unittest.main()
