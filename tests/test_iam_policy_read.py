"""Existing credentials only; actual custody/claims and Docker namespace in CI."""
import base64
import copy
from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.ingestion_rollout_preparation import iam_policy_read as p, iam_policy_delivery as delivery
from tools.ingestion_rollout_preparation import human_timing as files
from tools.semantic_lease_recovery.recovery_journal import Journal


def binding(path):
    path = Path(path).resolve()
    return {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


class ApiRead(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT', str(ROOT)))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.owner = self.root / 'owner'
        self.owner.mkdir(mode=0o700)
        self.selection = {'issuer': 'https://fixture-issuer.invalid/realms/fixture', 'subject': 'fixture-human',
            'tenant': 'fixture-tenant', 'origin': 'https://fixture-gateway.invalid',
            'docker': binding('/usr/bin/true'), 'keycloakContainer': '1' * 64,
            'realm': 'fixture', 'clients': {'chatgpt': {}, 'ths': {}}}
        self.plan = {'authorityDirectory': str(self.owner),
            'humanBinding': {'selectionHash': p.digest(self.selection)},
            'engine': {'socketPath': '/fixture/docker.sock', 'socketBinding': [1, 2, 0, 0, 384]}}
        self.write(self.owner / 'plan.json', self.plan)
        review = {'sourceClosureHash': 'a' * 64, 'selectionHash': p.digest(self.selection)}
        self.control = self.root / ('human-successor-control-' + p.digest(review))
        self.control.mkdir(mode=0o700)
        self.write(self.control / 'control.json', {'schema': 'ouf.human-explicit-successor-control.v1',
            'controlDirectory': str(self.control), 'sourceClosureHash': 'a' * 64,
            'selection': self.selection, 'review': review})
        self.write(self.control / 'binding.json', {'selectionHash': p.digest(self.selection), 'clientId': 'fixture-human-admin'})
        self.production = self.root / 'production'
        self.production.mkdir(mode=0o700)
        self.write(self.production / 'preparation.json', {'controlSourceHash': 'b' * 64, 'caseHash': 'c' * 64,
            'sourceClosure': {'executables': {'python': binding('/usr/bin/python3')}}})
        self.case = {'schema': 'ouf.iam-current-policy-read-case.v1',
            'purpose': 'EXACT_RETAINED_INSTALLATION_DIAGNOSTIC_NOT_PORTABLE_DEFAULT',
            'ownerPlanBinding': {'path': str(self.owner / 'plan.json'), 'sha256': p.digest(self.plan)},
            'humanControlPath': str(self.control), 'humanSourceClosureHash': 'a' * 64,
            'humanClientId': 'fixture-human-admin', 'productionContextPath': str(self.production),
            'productionControlSourceHash': 'b' * 64, 'productionCaseHash': 'c' * 64,
            'retainedHumanAttempts': 282, 'maximumCumulativeOAuthAttempts': 288,
            'adminReadProfile': {'schema': 'ouf.iam-existing-cli-loopback-read-profile.v1',
                'locationRule': 'CONTAINER_DEFAULT_USER_PASSWD_HOME', 'relativeConfigPath': '.keycloak/kcadm.config',
                'storedServerUrl': 'http://localhost:8080', 'storedHost': 'localhost',
                'connectHost': '127.0.0.1', 'connectPort': 8080, 'adminRealm': 'master',
                'adminClientId': 'admin-cli', 'expectedAdminUser': 'fixture-admin', 'minimumRemainingSeconds': 90}}
        self.container = {'Id': '1' * 64, 'State': {'Running': True, 'Pid': os.getpid(), 'StartedAt': 'fixture-start'},
            'Image': 'sha256:' + '2' * 64, 'Config': {'User': '1000', 'Env': ['HOME=/home/fixture']}}
        self.passwd = b'root:x:0:0:root:/root:/bin/sh\nfixture:x:1000:1000:Fixture:/home/fixture:/bin/sh\n'
        self.directory = {'name': '.keycloak', 'mode': (1 << 31) | 0o700, 'size': 4096, 'mtime': 'fixture', 'linkTarget': ''}
        self.realm = {'realm': 'fixture', 'accessTokenLifespan': 300, 'ssoSessionIdleTimeout': 1800,
            'ssoSessionMaxLifespan': 36000, 'clientSessionIdleTimeout': 0, 'clientSessionMaxLifespan': 0,
            'smtpServer': {'password': 'PRIVATE-REALM-SECRET-MUST-NOT-ESCAPE'}}
        self.client = {'id': 'fixture-client-uuid', 'clientId': 'fixture-human-admin', 'enabled': True,
            'protocol': 'openid-connect', 'attributes': {'access.token.lifespan': '300'},
            'secret': 'PRIVATE-CLIENT-SECRET-MUST-NOT-ESCAPE'}
        self.config = self.config_token(-10)
        self.fake_calls = []

    def write(self, path, value):
        path.write_bytes(p.encoded(value))
        path.chmod(0o600)

    def config_token(self, seconds):
        exp = int(time.time()) + seconds
        claims = {'iss': self.selection['issuer'].rsplit('/realms/', 1)[0] + '/realms/master',
            'azp': 'admin-cli', 'preferred_username': 'fixture-admin', 'exp': exp}
        token = 'fixture.' + base64.urlsafe_b64encode(p.encoded(claims)).decode().rstrip('=') + '.fixture'
        return {'serverUrl': 'http://localhost:8080', 'realm': 'master', 'endpoints': {
            'http://localhost:8080': {'master': {'clientId': 'admin-cli', 'token': token,
                'refreshToken': 'PRIVATE-REFRESH-MUST-NOT-USE', 'secret': 'PRIVATE-CLI-SECRET', 'expiresAt': exp * 1000}}}}

    def archive(self, name, raw, uid, mode):
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode='w') as archive:
            item = tarfile.TarInfo(name)
            item.size, item.uid, item.mode = len(raw), uid, mode
            archive.addfile(item, io.BytesIO(raw))
        return out.getvalue(), {'name': name, 'mode': mode, 'size': len(raw), 'mtime': 'fixture', 'linkTarget': ''}

    def fake_engine(self):
        fixture = self
        class Engine:
            def __init__(self, binding, journal, cid):
                self.journal = journal
            def request(self, method, archive=None):
                fixture.fake_calls.append((method, archive))
                row = self.journal.read()
                p.save(self.journal, engineRequestsReserved=row['engineRequestsReserved'] + 1)
                if archive is None:
                    return copy.deepcopy(fixture.container)
                if archive == '/etc/passwd':
                    return fixture.archive('passwd', fixture.passwd, 0, 0o644)
                if archive == '/home/fixture/.keycloak':
                    return b'', fixture.directory
                if archive == '/home/fixture/.keycloak/kcadm.config':
                    return fixture.archive('kcadm.config', p.encoded(fixture.config), 1000, 0o600)
                raise AssertionError('Unselected archive path')
        return Engine

    def invoke(self):
        return p.run(self.case, files.selected, files.recheck, Journal)

    @contextmanager
    def synthetic_namespace(self):
        # Only for unit protocol fixtures; physical setns is mandatory below.
        selected = '/proc/' + str(self.container['State']['Pid']) + '/ns/net'
        fake = self.root / 'synthetic-netns'
        fake.write_bytes(b'fixture namespace identity')
        real_open, real_stat = os.open, os.stat
        def opened(path, *args, **kwargs):
            return real_open(fake if str(path) == selected else path, *args, **kwargs)
        def stated(path, *args, **kwargs):
            return real_stat(fake if str(path) == selected else path, *args, **kwargs)
        with patch.object(os, 'open', side_effect=opened), patch.object(os, 'stat', side_effect=stated):
            yield

    def test_expired_cached_session_zero_admin_requests_and_no_login(self):
        original = {str(x): x.read_bytes() for x in self.root.rglob('*.json')}
        with patch.object(p, 'EngineRead', self.fake_engine()), patch.object(p, 'admin_get') as get:
            result = self.invoke()
        get.assert_not_called()
        self.assertEqual(result['status'], 'EXISTING_ADMIN_TOKEN_NOT_CURRENT_NO_LOGIN_OR_REFRESH')
        self.assertEqual(result['engineRequestsReserved'], 6)
        self.assertEqual(result['adminGetsReserved'], 0)
        self.assertFalse(result['currentProviderPolicyProven'])
        for name, raw in original.items():
            self.assertEqual(Path(name).read_bytes(), raw)
        with self.assertRaisesRegex(ValueError, 'EXISTING_IAM_READ_CLAIM'):
            self.invoke()
        self.assertNotIn('PRIVATE-', json.dumps(result))

    def test_current_session_three_gets_only_whitelisted_metadata(self):
        self.config = self.config_token(3600)
        replies = [self.realm, [self.client], self.client]
        def get(journal, *args):
            row = journal.read()
            p.save(journal, adminGetsReserved=row['adminGetsReserved'] + 1)
            return replies.pop(0)
        with self.synthetic_namespace(), patch.object(p, 'EngineRead', self.fake_engine()), patch.object(p, 'admin_get', side_effect=get):
            result = self.invoke()
        self.assertTrue(result['currentProviderPolicyProven'])
        self.assertEqual(result['adminGetsReserved'], 3)
        self.assertEqual(result['engineRequestsReserved'], 7)
        self.assertEqual(result['clientTimeoutAttributes']['access.token.lifespan'], '300')
        self.assertNotIn('PRIVATE-', json.dumps(result))
        self.assertFalse(result['effectiveFutureIssuedLifetimeProven'])

    def test_failed_api_keeps_context_claim_and_metadata_status_never_replays(self):
        self.config = self.config_token(3600)
        with self.synthetic_namespace(), patch.object(p, 'EngineRead', self.fake_engine()), patch.object(p, 'admin_get', side_effect=ValueError('CURRENT_ADMIN_API_PERMISSION_OR_RESPONSE_UNPROVEN_NO_REFRESH')):
            with self.assertRaises(ValueError):
                self.invoke()
        context = p.CHECKPOINT['contextPath']
        with patch.object(p, 'EngineRead') as engine:
            result = p.status(self.case, context, files.selected)
        engine.assert_not_called()
        self.assertEqual(result['state'], 'STOP_RECONCILE')
        self.assertEqual(result['credentialFilesRead'], 0)
        with self.assertRaisesRegex(ValueError, 'EXISTING_IAM_READ_CLAIM'):
            self.invoke()

    def test_wrong_full_selection_or_unapproved_remote_endpoint_has_no_claim(self):
        self.case['adminReadProfile']['connectHost'] = '192.0.2.10'
        with self.assertRaisesRegex(ValueError, 'EXPLICIT_SELECTED_CLI_LOOPBACK'):
            self.invoke()
        self.assertFalse(list(self.root.glob('iam-policy-read-*.claim.json')))
        self.case['adminReadProfile']['connectHost'] = '127.0.0.1'
        self.case['humanClientId'] = 'other-client'
        with self.assertRaisesRegex(ValueError, 'SAME_FULL_OWNER_BOUND'):
            self.invoke()

    def test_cli_config_identity_and_expiry_buffer_never_select_refresh(self):
        endpoint = self.case['adminReadProfile']
        cfg = self.config_token(45)
        token, expiry, current = p.token_from_config(cfg, endpoint, self.selection['issuer'], time.time())
        self.assertFalse(current)
        self.assertIn('PRIVATE-REFRESH', json.dumps(cfg))
        cfg['serverUrl'] = 'http://unreviewed.invalid:8080'
        with self.assertRaisesRegex(ValueError, 'EXACT_EXISTING_IAM_CLI_SERVER'):
            p.token_from_config(cfg, endpoint, self.selection['issuer'], time.time())

    def test_home_is_derived_from_selected_user_not_fixed_to_one_ente(self):
        profile = self.case['adminReadProfile']
        self.assertEqual(p.credential_path(self.container, self.passwd, profile),
            ('/home/fixture/.keycloak/kcadm.config', 1000))
        other = {'Config': {'User': 'operator', 'Env': []}}
        self.assertEqual(p.credential_path(other, b'operator:x:2020:2020:Operator:/srv/ente-b:/bin/sh\n', profile),
            ('/srv/ente-b/.keycloak/kcadm.config', 2020))
        other['Config']['Env'] = ['JAVA_OPTS=-Duser.home=/unreviewed']
        with self.assertRaisesRegex(ValueError, 'UNREVIEWED_CLI_CONFIG_OVERRIDE'):
            p.credential_path(other, b'operator:x:2020:2020:Operator:/srv/ente-b:/bin/sh\n', profile)

    def test_archive_symlink_wrong_owner_mode_and_multiple_members_rejected(self):
        raw, meta = self.archive('kcadm.config', b'{}', 1000, 0o600)
        for change in [{'name': '../kcadm.config'}, {'mode': 0o644}, {'linkTarget': '/another/file'}]:
            modified = {**meta, **change}
            with self.subTest(change=change), self.assertRaises(ValueError):
                p.member(raw, modified, 'kcadm.config', 262144, 1000, 0o600)
        with self.assertRaises(ValueError):
            p.member(raw, meta, 'kcadm.config', 262144, 0, 0o600)
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode='w') as archive:
            for name in ['kcadm.config', 'other-secret']:
                item = tarfile.TarInfo(name)
                item.size, item.uid, item.mode = 2, 1000, 0o600
                archive.addfile(item, io.BytesIO(b'{}'))
        with self.assertRaisesRegex(ValueError, 'ONE_SELECTED_IAM_ARCHIVE_MEMBER'):
            p.member(out.getvalue(), meta, 'kcadm.config', 262144, 1000, 0o600)

    def test_engine_cannot_post_and_exhausted_budget_never_opens_socket(self):
        selected = self.case['ownerPlanBinding']
        journal = SimpleNamespace(read=lambda: {'engineRequestsReserved': 0})
        engine = p.EngineRead(self.plan['engine'], journal, self.selection['keycloakContainer'])
        with patch.object(p.socket, 'socket') as connection:
            with self.assertRaisesRegex(ValueError, 'READ_ONLY_IAM_ENGINE_METHOD'):
                engine.request('POST')
            connection.assert_not_called()
        journal.read = lambda: {'engineRequestsReserved': 7}
        with self.assertRaisesRegex(ValueError, 'READ_BUDGET_EXHAUSTED'):
            engine.request('GET')

    def test_unsafe_credential_parent_stops_before_opening_config(self):
        self.directory['mode'] = (1 << 31) | 0o755
        with patch.object(p, 'EngineRead', self.fake_engine()):
            with self.assertRaisesRegex(ValueError, 'PRIVATE_EXISTING_ADMIN_CONFIG_DIRECTORY'):
                self.invoke()
        self.assertFalse(any(path and path.endswith('kcadm.config') for method, path in self.fake_calls))

    def test_policy_rejects_ambiguous_client_and_never_returns_other_fields(self):
        with self.assertRaisesRegex(ValueError, 'EXACT_UNIQUE_CURRENT_HUMAN_CLIENT'):
            p.policy(self.realm, [self.client, self.client], self.client, 'fixture', 'fixture-human-admin')
        result = p.policy(self.realm, [self.client], self.client, 'fixture', 'fixture-human-admin')
        self.assertNotIn('secret', json.dumps(result))
        self.assertEqual(result['realmTimeouts']['accessTokenLifespan'], 300)

    def test_delivery_reproducibility_and_closed_child_has_no_mutating_method(self):
        raw, declaration = delivery.generate(ROOT, self.case)
        self.assertEqual(raw, delivery.generate(ROOT, self.case)[0])
        self.assertIn("c.request('GET'", p.CHILD)
        self.assertNotIn('refresh_token', p.CHILD)
        self.assertNotIn('config credentials', p.CHILD)
        self.assertEqual(declaration['maximumAdminGets'], 3)

    def test_published_artifact_and_launcher_match_profile_and_source(self):
        case = json.loads((ROOT / 'releases/iam-current-policy-read-case-20261020.json').read_text())
        raw, _ = delivery.generate(ROOT, case)
        self.assertEqual((ROOT / 'scripts/iam-current-policy-read-20261020.py').read_bytes(), raw)
        launcher = ROOT / 'scripts/launch-iam-current-policy-read-20261020.sh'
        shell = launcher.read_text()
        self.assertIn(hashlib.sha256(raw).hexdigest(), shell)
        self.assertIn(hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(), shell)
        check = subprocess.run(['/bin/bash', '-n', str(launcher)], capture_output=True, text=True)
        self.assertEqual(check.returncode, 0, check.stderr)

    def test_actual_docker_archive_and_three_namespace_gets_then_expired_sealed_read(self):
        if os.environ.get('GITHUB_ACTIONS') != 'true':
            self.skipTest('Physical Docker and namespace capability are mandatory in target CI')
        fixture = self.root / 'container-fixture'
        fixture.mkdir(mode=0o755)
        credentials = fixture / '.keycloak'
        credentials.mkdir(mode=0o700)
        os.chown(credentials, 1000, 1000)
        config = credentials / 'kcadm.config'
        self.config = self.config_token(3600)
        self.write(config, self.config)
        os.chown(config, 1000, 1000)
        passwd = fixture / 'passwd'
        passwd.write_bytes(self.passwd)
        passwd.chmod(0o644)
        server = fixture / 'server.py'
        server.write_text('''import http.server,json
config=json.load(open('/home/fixture/.keycloak/kcadm.config'))
token=config['endpoints']['http://localhost:8080']['master']['token']
class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):
  print('GET '+self.path,flush=True)
  if self.headers.get('Authorization')!='Bearer '+token:self.send_response(401);self.end_headers();return
  client={'id':'fixture-client-uuid','clientId':'fixture-human-admin','enabled':True,'protocol':'openid-connect','attributes':{'access.token.lifespan':'300'},'secret':'PRIVATE-MUST-NOT-ESCAPE'}
  if self.path=='/admin/realms/fixture':body={'realm':'fixture','accessTokenLifespan':300,'ssoSessionIdleTimeout':1800,'ssoSessionMaxLifespan':36000,'clientSessionIdleTimeout':0,'clientSessionMaxLifespan':0,'smtpServer':{'password':'PRIVATE-MUST-NOT-ESCAPE'}}
  elif self.path.startswith('/admin/realms/fixture/clients?'):body=[client]
  elif self.path=='/admin/realms/fixture/clients/fixture-client-uuid':body=client
  else:self.send_response(404);self.end_headers();return
  raw=json.dumps(body).encode();self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
http.server.HTTPServer(('127.0.0.1',8080),Handler).serve_forever()
''')
        server.chmod(0o644)
        start = subprocess.run(['docker', 'run', '-d', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
            '--user', '1000:1000', '-e', 'HOME=/home/fixture',
            '--mount', 'type=bind,src=' + str(credentials) + ',dst=/home/fixture/.keycloak,readonly',
            '--mount', 'type=bind,src=' + str(passwd) + ',dst=/etc/passwd,readonly',
            '--mount', 'type=bind,src=' + str(server) + ',dst=/fixture-server.py,readonly',
            'python:3.13.5-slim', 'python3', '-B', '/fixture-server.py'], capture_output=True, text=True, timeout=180)
        self.assertEqual(start.returncode, 0, start.stderr)
        cid = start.stdout.strip()
        self.addCleanup(lambda: subprocess.run(['docker', 'rm', '-f', cid], capture_output=True, timeout=30))
        for _ in range(30):
            inspected = subprocess.run(['docker', 'inspect', cid], capture_output=True, text=True, timeout=10)
            row = json.loads(inspected.stdout)[0]
            if row['State']['Running']:
                time.sleep(.2)
                break
            time.sleep(.1)
        self.selection['keycloakContainer'] = cid
        self.plan['humanBinding']['selectionHash'] = p.digest(self.selection)
        s = os.stat('/var/run/docker.sock', follow_symlinks=False)
        self.plan['engine'] = {'socketPath': '/var/run/docker.sock',
            'socketBinding': [s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode & 0o777]}
        self.write(self.owner / 'plan.json', self.plan)
        self.case['ownerPlanBinding']['sha256'] = p.digest(self.plan)
        cfg = json.loads((self.control / 'control.json').read_text())
        cfg['selection'] = self.selection
        self.write(self.control / 'control.json', cfg)
        self.write(self.control / 'binding.json', {'selectionHash': p.digest(self.selection), 'clientId': 'fixture-human-admin'})
        before = config.read_bytes()
        result = self.invoke()
        self.assertTrue(result['currentProviderPolicyProven'])
        self.assertEqual(result['engineRequestsReserved'], 7)
        self.assertEqual(result['adminGetsReserved'], 3)
        self.assertNotIn('PRIVATE-', json.dumps(result))
        self.assertEqual(config.read_bytes(), before)
        # A second explicit fixture case checks the sealed entry with expired
        # credentials. No authentication or Admin GET is available in this run.
        self.case['fixtureObservationRef'] = 'second-disposable-expired-read'
        self.write(config, self.config_token(-10))
        raw, _ = delivery.generate(ROOT, self.case)
        script = self.root / 'sealed-api-read.py'
        script.write_bytes(raw)
        run = subprocess.run(['/usr/bin/python3', '-I', '-B', '-S', str(script), 'read'],
            capture_output=True, text=True, timeout=90)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        value = json.loads(run.stdout)
        self.assertEqual(value['status'], 'EXISTING_ADMIN_TOKEN_NOT_CURRENT_NO_LOGIN_OR_REFRESH')
        self.assertEqual(value['adminGetsReserved'], 0)
        self.assertNotIn('PRIVATE-', run.stdout + run.stderr)


if __name__ == '__main__':
    unittest.main()
