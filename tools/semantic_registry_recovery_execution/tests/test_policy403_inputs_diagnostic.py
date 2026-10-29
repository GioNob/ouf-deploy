import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('policy403_diag',ROOT/'scripts/inspect-registry-policy403-inputs-20261023.py')
d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)

class PolicyInputs(unittest.TestCase):
    def actual(self):return {'Config':{'Env':['OUF_IAM_ENABLED=true','OUF_IAM_ISSUER=https://issuer.fixture','OUF_IAM_AUDIENCE=fixture',
        'OUF_AUTHORIZATION_REGISTRY_URL=https://policy.fixture/active','OUF_AUTHORIZATION_REGISTRY_TOKEN_FILE=/run/auth/token',
        'SPRING_CONFIG_IMPORT=configtree:/run/db/']},'Mounts':[{'Destination':'/run/auth','Source':'/protected/auth','RW':False}]}
    def test_policy_config_is_classified_without_values_or_addresses(self):
        r,m=d.policy_configuration(self.actual());self.assertTrue(r['activePolicyUrlConfigured']);self.assertTrue(r['iamEnabled'])
        self.assertEqual(r['maxStalenessSeconds'],300);self.assertTrue(r['externalConfigurationIsOnlyDbConfigtree'])
        self.assertNotIn('policy.fixture',str(r));self.assertTrue(m['directoryMount'])
    def test_missing_refresh_configuration_cannot_look_configured(self):
        r,m=d.policy_configuration({'Config':{'Env':[]},'Mounts':[]})
        self.assertFalse(r['activePolicyUrlConfigured']);self.assertFalse(r['staticPolicyBundleConfigured']);self.assertIsNone(m)
    def test_ambiguous_relaxed_property_names_rejected(self):
        v=self.actual();v['Config']['Env'].append('ouf.iam.enabled=false')
        with self.assertRaisesRegex(ValueError,'UNAMBIGUOUS'):d.policy_configuration(v)
    def test_retained_expiry_not_called_current_token_proof(self):
        r=d.retained_owner_window({'tokenExpiresWall':100,'tokenExpiresMonotonic':50},101,51)
        self.assertTrue(r['tokenExpiresWallExpired']);self.assertTrue(r['tokenExpiresMonotonicExpired'])
        self.assertTrue(r['lastPublishedWindowIsNotCurrentCredentialValidityProof'])
    def test_absent_expiry_not_invented(self):
        r=d.retained_owner_window({},101,51);self.assertFalse(r['tokenExpiresWallRecorded']);self.assertIsNone(r['tokenExpiresWallExpired'])
    def logs(self,raw,tty=False):
        owner=self
        class Stub:
            def __init__(self,*a,**kw):pass
            def request(self,method,path,headers):owner.request=(method,path)
            def getresponse(self):return self
            status=200
            def read(self,count):return raw[:count]
            def close(self):pass
        class Engine:
            path='fixture-socket'
            def check_socket(self):pass
        with patch.object(d.http.client,'HTTPConnection',Stub):return d.registry_log_classifications(Engine(),'a'*64,123,tty)
    def test_mux_logs_classify_only_matching_registry_path_and_status(self):
        message=b'event="SEMANTIC_HTTP_REQUEST" method="GET" path="/api/semantic/v1/references:resolve" status="403" private=NEVER_PRINT\n'
        mux=b'\x01\0\0\0'+len(message).to_bytes(4,'big')+message;r=self.logs(mux)
        self.assertEqual(r['registrySemanticReference403LogMatches'],1);self.assertNotIn('NEVER_PRINT',str(r));self.assertEqual(self.request[0],'GET')
        self.assertIn('follow=false',self.request[1])
    def test_json_tty_logs_supported_without_printing_lines(self):
        r=self.logs(b'{"event":"SEMANTIC_HTTP_REQUEST","method":"GET","path":"/api/semantic/v1/references:resolve","status":403}\n',True)
        self.assertEqual(r['registrySemanticReference403LogMatches'],1)
    def test_truncated_frame_refused(self):
        with self.assertRaisesRegex(ValueError,'EXACT_DOCKER_LOG_FRAMING_REQUIRED'):self.logs(b'\x01\0')
    def test_oversized_log_response_not_accepted(self):
        with self.assertRaisesRegex(ValueError,'BOUNDED_REGISTRY_LOG_OBSERVATION_REQUIRED'):self.logs(b'x'*262145,True)

if __name__=='__main__':unittest.main()
