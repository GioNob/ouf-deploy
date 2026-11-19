import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch, Mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('r', ROOT / 'scripts/read-discovery-startup-20261109.py')
r = importlib.util.module_from_spec(spec); spec.loader.exec_module(r)


class FakeReader:
    def __init__(self, files):
        self.files = files; self.seals = {}; self.counts = {}; self.bytes = 0

    def read(self, path, kind, maximum=1048576):
        raw = self.files[str(path)]
        if isinstance(raw, dict): raw = r.encoded(raw)
        if len(raw) > maximum: raise RuntimeError('BOUNDED_REGULAR_SOURCE_REQUIRED')
        self.counts[kind] = self.counts.get(kind, 0) + 1; self.bytes += len(raw)
        self.seals[str(path)] = {'sha256': r.sha(raw), 'metadata': {'uid': 0, 'gid': 10001, 'modeOctal': '0440', 'links': 1, 'bytes': len(raw)}}
        return raw

    def value(self, path, kind='runtimeMetadata', maximum=1048576):
        return json.loads(self.read(path, kind, maximum))


class ReadStartupTest(unittest.TestCase):
    def test_bound_mount_requires_read_only_and_rejects_traversal(self):
        doc = {'Mounts': [{'Type':'bind', 'RW':False, 'Destination':'/run/provider', 'Source':'/etc/ouf/fixture'}]}
        self.assertEqual(r.host_source(doc, '/run/provider/adapter.json'), Path('/etc/ouf/fixture/adapter.json'))
        doc['Mounts'][0]['RW'] = True
        with self.assertRaisesRegex(RuntimeError, 'READ_ONLY_BIND_REQUIRED'): r.host_source(doc, '/run/provider/key')
        with self.assertRaisesRegex(RuntimeError, 'EXACT_ABSOLUTE_PATH_REQUIRED'): r.host_source(doc, '/run/provider/../secret')

    def test_narrow_source_roots_and_no_symlink_follow(self):
        reader = r.Reader()
        with self.assertRaisesRegex(RuntimeError, 'BOUND_SOURCE_ROOT_REQUIRED'): reader.read('/etc/shadow', 'config')
        with patch.object(r.os, 'open', side_effect=OSError('symlink denied')) as opened:
            with self.assertRaises(OSError): reader.read('/etc/ouf/fixture', 'config')
        opened.assert_called_once_with('/', r.os.O_RDONLY | r.os.O_DIRECTORY)

    def test_standard_runtime_is_not_start_permission(self):
        self.assertEqual(r.runtime({'HostConfig': {'Runtime': 'runc'}}, {}, FakeReader({})), {'classification':'STANDARD_RUNTIME', 'startAdmitted':False})

    def custom_fixture(self):
        cid = 'a' * 64
        doc = {'Id':cid, 'HostConfig':{'Runtime':'ouf-provider'}}
        source = '/etc/ouf/source/scripts/semantic_provider_docker_runtime.py'
        cfg_path = '/etc/ouf/runtime/config.json'
        wrapper = '/usr/local/sbin/ouf-provider'
        cfg = {'schema':'ouf.semantic-docker-runtime-adapter.v4', 'sourceHash':r.sha(b'NO_TARGET_CODE_EXECUTED'),
               'registryRoot':'/etc/ouf/registry', 'candidates':{cid:{'admissionConfiguration':'/etc/ouf/registry/'+cid+'/broker.json', 'admissionConfigurationHash':r.sha(r.encoded({'schema':'ouf.semantic-deployment-broker.v1', 'private':'SECRET_MARKER'}))}}}
        files = {source:b'NO_TARGET_CODE_EXECUTED', cfg_path:cfg,
                 wrapper:('#!/bin/sh\nexec /usr/bin/python3 -I -B '+source+' --configuration '+cfg_path+' "$@"\n').encode(),
                 '/etc/ouf/registry/'+cid+'/broker.json':{'schema':'ouf.semantic-deployment-broker.v1', 'private':'SECRET_MARKER'},
                 '/etc/ouf/registry/'+cid+'/adapter.json':{'schema':'ouf.semantic-docker-runtime-journal.v1', 'containerId':cid, 'state':'DELETED'}}
        return doc, {'Runtimes':{'ouf-provider':{'path':wrapper}}}, FakeReader(files), cfg

    def test_deleted_runtime_journal_read_without_executing_target_code(self):
        doc, info, reader, _ = self.custom_fixture()
        with patch.object(r.subprocess, 'run', side_effect=AssertionError('unexpected execution')):
            result = r.runtime(doc, info, reader)
        self.assertEqual(result['journalState'], 'DELETED')
        self.assertTrue(result['sourceMatchesConfiguration'])
        self.assertTrue(result['brokerHashMatchesConfiguration'])
        self.assertNotIn('SECRET_MARKER', json.dumps(result))
        self.assertFalse(result['startAdmitted'])

    def test_unregistered_candidate_does_not_follow_old_journals(self):
        doc, info, reader, cfg = self.custom_fixture(); cfg['candidates'] = {}
        result = r.runtime(doc, info, reader)
        self.assertFalse(result['candidatePresent'])
        self.assertEqual(sum(reader.counts.values()), 3)

    def test_embedded_key_and_oidc_values_not_in_config_summary(self):
        def mount(source, dest): return {'Type':'bind', 'RW':False, 'Source':source, 'Destination':dest}
        adapter = {'Config':{'Entrypoint':['python3','-B','-m','tools.semantic_provider_adapter'], 'Cmd':['--configuration','/run/ouf-semantic-provider/adapter.json']},
            'Mounts':[mount('/etc/ouf/adapter.json','/run/ouf-semantic-provider/adapter.json'), mount('/etc/ouf/cert','/run/cert'), mount('/etc/ouf/key','/run/key'), mount('/etc/ouf/receipt','/run/receipt')]}
        south = {'Config':{'Entrypoint':['/docker-entrypoint.sh'],'Cmd':['docker-start']}, 'Mounts':[mount('/etc/ouf/config.yaml','/usr/local/apisix/conf/config.yaml'),mount('/etc/ouf/apisix.yaml','/usr/local/apisix/conf/apisix.yaml')]}
        semantic = {}; env = {'OUF_SCHEMA_GOV_CLIENT_ID':'workload','OUF_SCHEMA_GOV_WORKLOAD_SCOPE':'scope','OUF_SCHEMA_GOV_SEARCH_PATH':'/search','OUF_SCHEMA_GOV_FETCH_PATH':'/fetch','OIDC_SECRET':'SECRET_MARKER'}
        cfg = {'listenPort':9443,'searchPath':'/search','fetchPath':'/fetch','admission':{'workload':'workload','scope':'scope','audience':'aud'},'tlsCertificateFile':'/run/cert','tlsPrivateKeyFile':'/run/key','receiptKeyFile':'/run/receipt'}
        route = {'uri':'/search','methods':['POST'],'upstream':{'scheme':'https','upstream_host':'ouf-semantic-provider-v2'},'plugins':{'openid-connect':{'client_id':'aud','client_secret':'$ENV://OIDC_SECRET','required_scopes':['scope'],'ssl_verify':True,'bearer_only':True}}}
        files = {'/etc/ouf/adapter.json':cfg,'/etc/ouf/config.yaml':{'apisix':{'enable_admin':False,'ssl':{'enable':True}},'nginx_config':{'http_configuration_snippet':'proxy_ssl_verify on;'}},'/etc/ouf/apisix.yaml':{'routes':[route], 'ssls':[{'snis':['ouf-semantic-southbound-v2'],'cert':'PUBLIC_CERT','key':'PRIVATE_KEY_MARKER'}]},'/etc/ouf/cert':b'PUBLIC_CERT'}
        with patch.object(r, 'certificate', return_value={'validAtRead': True}):
            result = r.config_summary(adapter, south, semantic, FakeReader(files), Mock(environment=lambda d: env))
        self.assertEqual(result['routes'][0]['matchingRoutes'], 1)
        self.assertTrue(result['routes'][0]['secretEnvironmentReferencePresent'])
        for marker in ('PRIVATE_KEY_MARKER','SECRET_MARKER','$ENV://OIDC_SECRET'):
            self.assertNotIn(marker, json.dumps(result))

    def test_prepared_credential_equality_keeps_value_and_hash_private(self):
        raw = b'PRIVATE_CREDENTIAL_MARKER'
        env = {'OUF_SCHEMA_GOV_CLIENT_ID':'c','OUF_SCHEMA_GOV_WORKLOAD_SCOPE':'s','OUF_SCHEMA_GOV_TOKEN_ENDPOINT':'https://issuer/token'}
        value = {'schema':'ouf.m2-discovery-private-material-role-preparation.v1', 'preparedCopies':{'providerCredential':{'path':str(r.MATERIAL_ROOT/'schema-gov-client-secret'),'sha256':r.sha(raw)}}, 'selectedInstallationObservations':{'semantic':{}}}
        files = {str(r.MATERIAL_ROOT/'prepared-inputs.private.json'):value,str(r.MATERIAL_ROOT/'schema-gov-client-secret'):raw,str(r.TRUST_PATH):b'public trust fixture'}
        with patch.object(r,'MATERIAL_HASH',r.sha(r.encoded(value))), patch.object(r,'TRUST_SHA',r.sha(b'public trust fixture')):
            result = r.prepared_material({}, FakeReader(files), Mock(environment=lambda d: env))
        self.assertTrue(result['credentialBytesMatchRetained'])
        self.assertTrue(result['preparedPublicTruststoreMatchesRetained'])
        self.assertNotIn(raw.decode(), json.dumps(result)); self.assertNotIn(r.sha(raw), json.dumps(result))
        self.assertFalse(result['credentialValidityAtIssuerTested'])

    def test_changed_preparation_metadata_does_not_read_credential(self):
        reader = FakeReader({str(r.MATERIAL_ROOT/'prepared-inputs.private.json'):{'changed':True}})
        with self.assertRaisesRegex(RuntimeError,'PREPARED_MATERIAL_METADATA_CHANGED'):
            r.prepared_material({},reader,Mock())
        self.assertNotIn('preparedCredential', reader.counts)

    def test_native_openssl_validity_and_host_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            key, crt = Path(tmp)/'key.pem', Path(tmp)/'cert.pem'
            proc = subprocess.run(['/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(crt),'-days','1','-subj','/CN=ouf-semantic-provider-v2','-addext','subjectAltName=DNS:ouf-semantic-provider-v2'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            self.assertEqual(proc.returncode,0)
            pem = crt.read_text()
            result = r.certificate(pem, 'ouf-semantic-provider-v2')
            self.assertTrue(result['validAtRead']); self.assertTrue(result['hostnameMatches'])
            mismatch = r.certificate(pem, 'ouf-semantic-southbound-v2')
            self.assertFalse(mismatch['hostnameMatches'])
            self.assertFalse(result['chainVerified'])
            with self.assertRaisesRegex(RuntimeError,'PUBLIC_CERTIFICATE_ONLY'): r.certificate(key.read_text(), 'ouf-semantic-provider-v2')

    def test_frame_mismatch_precedes_configuration_reads(self):
        reader = FakeReader({}); helper = Mock(); helper.inspect.return_value = {}; helper.digest.return_value = 'changed'
        with self.assertRaisesRegex(RuntimeError,'CURRENT_RECEIPT_FRAME_CHANGED'):
            r.collect({},helper,reader,get_info=lambda: self.fail('Engine info should not be called'))
        self.assertEqual(reader.counts,{})


if __name__ == '__main__': unittest.main()
