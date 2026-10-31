"""Public discovery only: real TLS, exact route and redacted HTTP outcomes."""
import hashlib
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import importlib.util
import json
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import unittest

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('worker_network_probe',ROOT/'scripts/probe-registry-operational-network-20261024.py')
probe=importlib.util.module_from_spec(spec);spec.loader.exec_module(probe)


class Discovery(unittest.TestCase):
    def serve(self,status=200,drift=False):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root=Path(directory);ca=root/'ca.pem';key=root/'key.pem'
            subprocess.run(['/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                '-subj','/CN=iam.fixture.test','-addext','subjectAltName=DNS:iam.fixture.test',
                '-keyout',str(key),'-out',str(ca)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
            calls=[];profile={}
            class Handler(BaseHTTPRequestHandler):
                def log_message(self,*_):pass
                def do_GET(self):
                    calls.append((self.path,dict(self.headers)))
                    value={'issuer':profile['issuer'] if not drift else 'untrusted-secret-address',
                        'token_endpoint':profile['token_endpoint'],'introspection_endpoint':profile['introspection_endpoint']}
                    if status!=200:value={'untrusted':'NEVER_PRINT_SECRET_BODY'}
                    raw=json.dumps(value).encode();self.send_response(status);self.send_header('Content-Type','application/json')
                    self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
            server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(ca,key)
            server.socket=context.wrap_socket(server.socket,server_side=True)
            issuer='https://iam.fixture.test:'+str(server.server_port)+'/realms/fixture'
            profile.update(issuer=issuer,token_endpoint=issuer+'/protocol/openid-connect/token',
                introspection_endpoint=issuer+'/protocol/openid-connect/token/introspect',peer_addresses=['127.0.0.1'])
            thread=threading.Thread(target=server.serve_forever);thread.start()
            try:result=probe.discovery_tls(profile,ca.read_bytes())
            finally:server.shutdown();server.server_close();thread.join(5)
            self.assertEqual(len(calls),1);self.assertEqual(calls[0][0],'/realms/fixture/.well-known/openid-configuration')
            self.assertFalse(any(k.lower() in('authorization','cookie') for k in calls[0][1]))
            self.assertNotIn('fixture.test',str(result));self.assertNotIn('127.0.0.1',str(result))
            self.assertNotIn('NEVER_PRINT',str(result));return result

    def test_actual_public_discovery_tls_and_exact_configuration_match(self):
        result=self.serve();self.assertEqual(result['httpStatus'],200)
        self.assertTrue(result['certificateChainAndHostnameVerified'] and result['discoveryMatchesConfiguredEndpoints'])

    def test_actual_service_unavailable_is_numeric_and_no_body_leaks(self):
        result=self.serve(503);self.assertEqual(result['httpStatus'],503)
        self.assertFalse(result['discoveryMatchesConfiguredEndpoints'])

    def test_discovery_drift_is_not_accepted(self):
        self.assertFalse(self.serve(drift=True)['discoveryMatchesConfiguredEndpoints'])

    def test_claim_namespace_and_cgroup_path_reject_broad_or_traversal(self):
        for value in('/','/system.slice/../service','relative','/system.slice//service'):
            with self.assertRaises((ValueError,OSError)):probe.cgroup_directory(value)


if __name__=='__main__':unittest.main()
