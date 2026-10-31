"""Real loopback TLS/HTTP and issuer-response contract; no production credentials."""
import copy
import datetime
import json
import os
from pathlib import Path
import socket
import ssl
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer,BaseHTTPRequestHandler
from unittest.mock import patch
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from tools.semantic_policy_token_owner.iam_admission import IamProfile,PinnedIamOpener,OnlineIamAdmission
from tools.semantic_policy_token_owner.producer import CredentialFile,Binding,HttpsGrant
from tools.semantic_lease_recovery.bounded_recovery import Permanent,Temporary

def certificate(root):
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'iam.fixture.test')])
    now=datetime.datetime.now(datetime.timezone.utc)
    cert=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(days=1)).add_extension(x509.SubjectAlternativeName([x509.DNSName('iam.fixture.test')]),False).add_extension(x509.BasicConstraints(ca=True,path_length=None),True).sign(key,hashes.SHA256())
    ca=root/'ca.pem';pem=root/'key.pem';ca.write_bytes(cert.public_bytes(serialization.Encoding.PEM));pem.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));pem.chmod(0o600)
    return ca,pem

class Fixture:
    def __init__(self,root,*,lifetime=300):
        assert type(lifetime) is int and 90<=lifetime<=3600
        self.lifetime=lifetime
        self.ca,self.key=certificate(root);self.calls=[];self.body_mode=None;self.code=200;self.after=None
        self.token_issued_at=int(time.time());self.connection_close=False;self.body_piece_bytes=None;self.body_delay=0
        fixture=self
        class Handler(BaseHTTPRequestHandler):
            protocol_version='HTTP/1.1'
            def log_message(self,*_):pass
            def do_GET(self):self.respond(None)
            def do_POST(self):self.respond(urllib.parse.parse_qs(self.rfile.read(int(self.headers['Content-Length'])).decode()))
            def respond(self,fields):
                fixture.calls.append((self.path,fields))
                if self.path.endswith('/.well-known/openid-configuration'):
                    value={'issuer':fixture.profile.issuer,'token_endpoint':fixture.profile.token_endpoint,'introspection_endpoint':fixture.profile.introspection_endpoint}
                elif self.path.endswith('/introspect'):value=copy.deepcopy(fixture.active())
                else:value={'access_token':'FIXTURE_TOKEN','token_type':'Bearer','expires_in':fixture.lifetime}
                if fixture.body_mode=='changed':value['issuer']='https://other.invalid/realms/fixture'
                if fixture.body_mode=='inactive':value={'active':False}
                if type(fixture.body_mode) is tuple:value[fixture.body_mode[0]]=fixture.body_mode[1]
                raw=json.dumps(value).encode()
                if fixture.body_mode=='duplicate':raw=b'{"active":true,"active":false}'
                if fixture.body_mode=='oversize':raw=b'x'*65537
                if fixture.after:fixture.after()
                self.send_response(fixture.code);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)))
                if fixture.code==429:self.send_header('Retry-After','900')
                if fixture.code==302:self.send_header('Location','https://unapproved.invalid/token')
                if fixture.connection_close:
                    self.send_header('Connection','close');self.close_connection=True
                self.end_headers()
                try:
                    if fixture.body_piece_bytes is None:self.wfile.write(raw)
                    else:
                        for index in range(0,len(raw),fixture.body_piece_bytes):
                            time.sleep(fixture.body_delay)
                            self.wfile.write(raw[index:index+fixture.body_piece_bytes]);self.wfile.flush()
                except (BrokenPipeError,ConnectionResetError):pass
        self.server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(self.ca,self.key)
        self.server.socket=context.wrap_socket(self.server.socket,server_side=True)
        issuer='https://iam.fixture.test:'+str(self.server.server_port)+'/realms/fixture'
        self.profile=IamProfile(issuer,issuer+'/protocol/openid-connect/token',issuer+'/protocol/openid-connect/token/introspect','fixture-client','fixture-service-subject','fixture-tenant','fixture-audience',('authorization.bundle.read',),('authorization.bundle.read',),('127.0.0.1',),90,3600)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
    def active(self):
        now=self.token_issued_at
        return {'active':True,'iss':self.profile.issuer,'client_id':self.profile.client_id,'sub':self.profile.subject_id,'tenant_id':self.profile.tenant_id,'ouf_actor_type':'SERVICE','aud':self.profile.audience,'scope':'authorization.bundle.read','iat':now,'exp':now+self.lifetime}
    def close(self):self.server.shutdown();self.thread.join(2);self.server.server_close()
    def context(self):return ssl.create_default_context(cafile=str(self.ca))

class IamAdmissionTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=ROOT);self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.fixture=Fixture(self.root);self.addCleanup(self.fixture.close)
        self.secret=self.root/'credential';self.secret.write_text('DISPOSABLE_FIXTURE_SECRET');self.secret.chmod(0o400)
        self.clock=lambda:(time.time(),time.monotonic())
        self.transport=PinnedIamOpener(self.fixture.profile,self.clock,self.fixture.context())
        self.admission=OnlineIamAdmission(self.fixture.profile,CredentialFile(self.secret),self.transport,self.clock)
    def test_real_tls_discovery_introspection_and_grant_use_exact_peer_and_confidential_client(self):
        self.assertTrue(self.admission.prepare(time.monotonic()+10))
        self.assertTrue(self.admission.admit('FIXTURE_TOKEN',time.monotonic()+300,time.monotonic()+10))
        binding=Binding(self.fixture.profile.token_endpoint,'fixture-client','authorization.bundle.read',str(self.root),'token.jwt',10001)
        result=HttpsGrant(self.clock,opener=self.transport).request(binding,'DISPOSABLE_FIXTURE_SECRET',time.monotonic()+10)
        self.assertEqual(result['access_token'],'FIXTURE_TOKEN')
        self.assertEqual([x[0].rsplit('/',1)[-1] for x in self.fixture.calls],['openid-configuration','introspect','token'])
        self.assertEqual(self.fixture.calls[1][1]['client_id'],['fixture-client'])
    def test_http10_and_explicit_connection_close_keep_body_alive_and_release_socket(self):
        import tools.semantic_policy_token_owner.iam_admission as implementation
        original=implementation._Connection.connect;sockets=[]
        def connected(connection):
            original(connection);sockets.append(connection.sock.sock)
        with patch.object(implementation._Connection,'connect',connected):
            for protocol,close in (('HTTP/1.0',False),('HTTP/1.1',True)):
                with self.subTest(protocol=protocol,connectionClose=close):
                    self.fixture.server.RequestHandlerClass.protocol_version=protocol
                    self.fixture.connection_close=close
                    self.fixture.body_piece_bytes=17;self.fixture.body_delay=0.001
                    self.assertTrue(self.admission.prepare(time.monotonic()+10))
                    self.assertTrue(self.admission.admit('FIXTURE_TOKEN',time.monotonic()+300,time.monotonic()+10))
                    b=Binding(self.fixture.profile.token_endpoint,'fixture-client','authorization.bundle.read',str(self.root),'token.jwt',10001)
                    result=HttpsGrant(self.clock,opener=self.transport).request(b,'DISPOSABLE_FIXTURE_SECRET',time.monotonic()+10)
                    self.assertEqual(result['access_token'],'FIXTURE_TOKEN')
                    self.assertTrue(all(sock.fileno()==-1 for sock in sockets))
        self.assertEqual(len(self.fixture.calls),6)
        self.assertEqual(sum(path.endswith('/token') for path,_ in self.fixture.calls),2)
    def test_closing_response_body_trickle_respects_whole_deadline_and_post_is_not_no_effect(self):
        self.fixture.connection_close=True;self.fixture.body_piece_bytes=1;self.fixture.body_delay=0.03
        for mutating in (False,True):
            with self.subTest(mutating=mutating):
                p=self.fixture.profile
                request=urllib.request.Request(p.token_endpoint,data=b'fixture') if mutating else urllib.request.Request(p.issuer+'/.well-known/openid-configuration')
                start=time.monotonic()
                with self.assertRaises(Temporary) as raised:
                    with self.transport.open(request,0.15) as response:response.read(65537)
                self.assertEqual(raised.exception.no_effect,not mutating)
                self.assertLess(time.monotonic()-start,1)
    def test_rejected_closing_response_releases_socket_even_while_exception_is_retained(self):
        import tools.semantic_policy_token_owner.iam_admission as implementation
        original=implementation._Connection.connect;sockets=[]
        def connected(connection):
            original(connection);sockets.append(connection.sock.sock)
        self.fixture.connection_close=True
        with patch.object(implementation._Connection,'connect',connected):
            for status,expected in ((429,Temporary),(302,Permanent)):
                self.fixture.code=status
                with self.subTest(status=status),self.assertRaises(expected) as raised:
                    self.admission.prepare(time.monotonic()+10)
                self.assertIsNotNone(raised.exception)
                self.assertTrue(all(sock.fileno()==-1 for sock in sockets))
    def test_issuer_revocation_expiry_identity_scope_and_audience_are_denied(self):
        bad=[('client_id','other'),('sub','other'),('tenant_id','other'),('ouf_actor_type','HUMAN'),('iss','https://other.invalid'),('aud',['other']),('scope','authorization.bundle.read privileged.write'),('exp',int(time.time())+1),('exp',True),('iat',int(time.time())+30),'inactive']
        for mode in bad:
            with self.subTest(field=mode):
                self.fixture.body_mode=mode
                with self.assertRaises(Permanent):self.admission.admit('FIXTURE_TOKEN',time.monotonic()+300,time.monotonic()+10)
    def test_metadata_drift_duplicate_and_unbounded_responses_are_denied(self):
        self.fixture.body_mode='changed'
        with self.assertRaises(Permanent):self.admission.prepare(time.monotonic()+10)
        for mode in ('duplicate','oversize'):
            self.fixture.body_mode=mode
            with self.assertRaises(Permanent):self.admission.admit('FIXTURE_TOKEN',time.monotonic()+300,time.monotonic()+10)
    def test_redirect_and_untrusted_certificate_never_send_to_another_endpoint(self):
        self.fixture.code=302
        with self.assertRaises(Permanent):self.admission.prepare(time.monotonic()+10)
        self.assertEqual(len(self.fixture.calls),1)
        bad=PinnedIamOpener(self.fixture.profile,self.clock)
        with self.assertRaises(Permanent):bad.open(urllib.request.Request(self.fixture.profile.token_endpoint,data=b'fixture'),2)
        self.assertEqual(len(self.fixture.calls),1)
    def test_unapproved_peer_is_not_used_even_if_hostname_resolves_elsewhere(self):
        p=self.fixture.profile
        wrong=IamProfile(p.issuer,p.token_endpoint,p.introspection_endpoint,p.client_id,p.subject_id,p.tenant_id,p.audience,p.required_scopes,p.allowed_scopes,('127.0.0.2','127.0.0.1'))
        opener=PinnedIamOpener(wrong,self.clock,self.fixture.context())
        with self.assertRaises(Temporary) as e:opener.open(urllib.request.Request(p.token_endpoint,data=b'fixture'),1)
        self.assertTrue(e.exception.no_effect);self.assertEqual(self.fixture.calls,[])
    def test_rate_limit_read_probe_preserves_retry_after_and_never_grants(self):
        self.fixture.code=429
        with self.assertRaises(Temporary) as e:self.admission.prepare(time.monotonic()+10)
        self.assertEqual(e.exception.retry_after,900);self.assertTrue(e.exception.no_effect)
        self.assertTrue(all(not x[0].endswith('/token') for x in self.fixture.calls))
    def test_expired_deadline_sends_nothing_and_credential_path_custody_is_not_repaired(self):
        with self.assertRaises(Temporary):self.admission.prepare(time.monotonic()-1)
        self.assertEqual(self.fixture.calls,[])
        self.secret.chmod(0o644)
        with self.assertRaises(Permanent):self.admission.admit('FIXTURE_TOKEN',time.monotonic()+300,time.monotonic()+10)
        self.assertEqual(self.fixture.calls,[]);self.assertEqual(self.secret.stat().st_mode&0o777,0o644)
    def test_malformed_endpoint_scope_or_insecure_tls_profile_is_rejected_before_io(self):
        p=self.fixture.profile
        values=dict(p.__dict__);values['introspection_endpoint']='https://other.invalid/token'
        with self.assertRaises(Permanent):IamProfile(**values)
        context=ssl._create_unverified_context()
        with self.assertRaises(Permanent):PinnedIamOpener(p,self.clock,context)
        self.assertEqual(self.fixture.calls,[])

if __name__=='__main__':unittest.main()

