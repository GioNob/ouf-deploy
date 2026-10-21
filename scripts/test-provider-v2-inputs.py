"""Real sealed-compiler and root-private publication fixtures; no target operations."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import ssl
import sys
import tempfile
import unittest
from unittest.mock import patch

BASE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('startup_inputs',BASE/'prepare-provider-v2-inputs.py')
inputs = importlib.util.module_from_spec(spec); spec.loader.exec_module(inputs)
ns = {'__name__':'fixture_private_helpers','__file__':str(BASE/'prepare-provider-v2-trust.py')}
exec(compile((BASE/'prepare-provider-v2-trust.py').read_bytes(),ns['__file__'],'exec'),ns)

def binding():
    admission={'installation':'install-test','issuer':'https://auth.example/realms/test','audience':'gateway-test','workload':'semantic-test','scope':'gateway.southbound.invoke','tenants':['tenant-test']}
    routes={**admission,'searchPath':'/provider/search','fetchPath':'/provider/fetch','searchRouteId':'provider-search','fetchRouteId':'provider-fetch',
        'receiptKeyEnvironment':'OUF_SEMANTIC_PROVIDER_OWNER_KEY','oidcSecretRef':'$ENV://OIDC_SECRET',
        'upstream':{'type':'roundrobin','scheme':'https','nodes':{'adapter.example:9443':1},'pass_host':'rewrite','upstream_host':'adapter.example','timeout':{'connect':3,'send':3,'read':25}},
        'tlsProfile':{'role':'DEDICATED_SOUTHBOUND','mode':'NGINX_PROXY_SSL_VERIFY','trustedCertificateFile':'/runtime/trust.pem','verifyDepth':3},
        'rateLimit':{'count':30,'time_window':60,'key_type':'var','key':'remote_addr','policy':'local','rejected_code':429},'maxRequestBytes':65536}
    provider={'endpoint':'https://provider.example/sparql','namespace_prefixes':['https://vocab.example/class/'],'allowed_cidrs':[],
        'max_request_bytes':65536,'max_response_bytes':1048576,'max_intent_chars':2000,'timeout_seconds':10,'ca_file':'/runtime/trust.pem'}
    adapter={'listenAddress':'0.0.0.0','listenPort':9443,'maxWorkers':4,'requestTimeoutSeconds':20,'searchPath':'/provider/search','fetchPath':'/provider/fetch',
        'provider':provider,'admission':admission,'receiptKeyFile':'/runtime/receipt.key','tlsCertificateFile':'/runtime/server.crt','tlsPrivateKeyFile':'/runtime/server.key'}
    return {'routes':routes,'adapter':adapter,'tlsIdentities':{'adapterHostname':'adapter.example','southboundHostname':'southbound.example'},
        'dns':{'resolvers':['192.0.2.53','2001:db8::53'],'networkIPVersion':4,'resolverPort':53}}

class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        assert os.geteuid()==0
        cls.package,cls.sources=inputs.load_compilers(BASE/'source',ns['read'])
        cls.compile=staticmethod(cls.package.materialize_semantic_provider_runtime.compile_plan)
        cls.hosts={'adapterHostname':'ouf-semantic-provider-v2','southboundHostname':'ouf-semantic-southbound-v2'}
    def test_rebind_only_two_tls_identity_and_upstream_fields(self):
        original=binding();before=copy.deepcopy(original)
        changed=inputs.rebind(original,self.hosts)
        self.assertEqual(original,before)
        self.assertEqual(changed['adapter'],original['adapter'])
        self.assertEqual(changed['dns'],original['dns'])
        original_routes=copy.deepcopy(original['routes']);changed_routes=copy.deepcopy(changed['routes'])
        original_routes.pop('upstream');changed_routes.pop('upstream')
        self.assertEqual(changed_routes,original_routes)
        self.assertEqual(changed['routes']['upstream']['nodes'],{'ouf-semantic-provider-v2:9443':1})
        self.assertEqual(changed['routes']['upstream']['timeout'],original['routes']['upstream']['timeout'])
        self.compile(changed)
    def test_no_dns_or_socket_during_native_rebind_compilation(self):
        with patch('socket.getaddrinfo',side_effect=AssertionError('DNS called')),patch('socket.socket',side_effect=AssertionError('socket opened')):
            plan=self.compile(inputs.rebind(binding(),self.hosts))
        self.assertEqual(plan['providerCalls'],0);self.assertFalse(plan['installed'])
    def test_mismatched_adapter_admission_refused(self):
        cfg=inputs.rebind(binding(),self.hosts);cfg['adapter']['admission']=copy.deepcopy(cfg['adapter']['admission']);cfg['adapter']['admission']['workload']='different'
        with self.assertRaises(ValueError):self.compile(cfg)
    def test_unrelated_environment_values_never_copied(self):
        value=inputs.selected_environment(['PATH=/fixture','OIDC_SECRET=fixture-credential-123456','OUF_GATEWAY_DELEGATION_KEY=do-not-copy'],binding(),b'ab'*32)
        self.assertEqual(value,b'OIDC_SECRET=fixture-credential-123456\nOUF_SEMANTIC_PROVIDER_OWNER_KEY='+b'ab'*32+b'\n')
    def test_newlines_in_existing_credential_refused(self):
        with self.assertRaises(ValueError):inputs.selected_environment(['OIDC_SECRET=fixture-credential-123456\nINJECTED=value'],binding(),b'ab'*32)
    def test_duplicate_existing_credential_names_refused(self):
        with self.assertRaises(ValueError):inputs.selected_environment(['OIDC_SECRET=fixture-credential-123456','OIDC_SECRET=fixture-credential-654321'],binding(),b'ab'*32)
    def test_unsafe_receipt_environment_refused(self):
        cfg=binding();cfg['routes']['receiptKeyEnvironment']='PATH'
        with self.assertRaises(ValueError):inputs.selected_environment(['OIDC_SECRET=fixture-credential-123456'],cfg,b'ab'*32)
    def test_real_tls_materialized_for_new_name_and_no_http_admin(self):
        with tempfile.TemporaryDirectory(dir=BASE) as folder:
            root=Path(folder);public=Path('/etc/ssl/certs/ca-certificates.crt').read_bytes()
            roles=[{'role':role,'uid':ids[0],'gid':ids[1],'layerBytesVerified':True} for role,ids in ns['IDS'].items()]
            ns['make_trust'](root,roles,public,Path('/usr/bin/openssl'))
            cfg=inputs.rebind(binding(),self.hosts)
            result=self.package.materialize_semantic_provider_tls.materialize_tls(cfg['routes'],{'listenAddress':'0.0.0.0','listenPort':10443,'serverHostname':self.hosts['southboundHostname'],'sslResourceId':'provider-fixture'},
                certificate_pem=(root/'southbound/server.crt').read_text(),private_key_pem=(root/'southbound/server.key').read_text())
            self.assertEqual(result['runtimeConfiguration']['apisix']['node_listen'],[])
            self.assertFalse(result['runtimeConfiguration']['apisix']['enable_admin'])
            self.assertFalse(result['runtimeConfiguration']['apisix']['enable_control'])
            self.assertEqual(result['resources']['ssls'][0]['snis'],['ouf-semantic-southbound-v2'])
            self.assertEqual(result['resources']['routes'][0]['upstream']['upstream_host'],'ouf-semantic-provider-v2')
            self.assertFalse(result['installed']);self.assertEqual(result['providerCalls'],0)
            raw=inputs.encoded(result['resources'])+b'#END\n'
            ns['write'](root/'apisix.yaml',raw,636,636)
            self.assertEqual(ns['read'](root/'apisix.yaml',636,636),raw)
            self.assertEqual((root/'apisix.yaml').stat().st_uid,636)
            with self.assertRaises(FileExistsError):ns['write'](root/'apisix.yaml',b'replacement',636,636)
    def test_foreign_compiler_module_cannot_be_adopted(self):
        with self.assertRaises(ValueError):inputs.load_compilers(BASE/'source',ns['read'])

if __name__=='__main__':
    unittest.main()
