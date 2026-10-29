import importlib.util,json,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('read',Path('scripts/read-semantic-workload-client.py'))
read=importlib.util.module_from_spec(spec);spec.loader.exec_module(read)
class Workload(unittest.TestCase):
    def test_client_profile_is_not_credential_or_token_admission(self):
        row={'id':'1234-abcd','clientId':'ouf-semantic','enabled':True,'publicClient':False,'serviceAccountsEnabled':True,'clientAuthenticatorType':'client-secret','secret':'DO_NOT_EXPORT'}
        result=read.project([row]);self.assertTrue(result['profileSupportsConfidentialServiceAccount'])
        self.assertFalse(result['credentialCustodyProven']);self.assertFalse(result['actualTokenAdmissionProven']);self.assertNotIn('DO_NOT_EXPORT',json.dumps(result))
    def test_absent_or_ambiguous_profile_does_not_imply_registration(self):
        self.assertEqual(read.project([])['status'],'SELECTED_WORKLOAD_CLIENT_ABSENT')
        with self.assertRaises(ValueError):read.project([{},{}])
        with self.assertRaises(ValueError):read.project([{'id':'abcd','clientId':'other-workload'}])
    def test_memory_login_keeps_password_out_of_command_and_creates_no_config(self):
        args,stdin=read.memory_only_query('a'*64,['KC_BOOTSTRAP_ADMIN_USERNAME=admin','KC_BOOTSTRAP_ADMIN_PASSWORD=DO_NOT_EXPORT'])
        self.assertNotIn('DO_NOT_EXPORT',json.dumps(args));self.assertEqual(stdin,b'DO_NOT_EXPORT\n')
        self.assertIn('--no-config',args);self.assertIn('http://127.0.0.1:8080',args);self.assertNotIn('--password',args)
        self.assertEqual(args[args.index('get')+1],'clients')
    def test_ambiguous_or_multiline_existing_password_denied(self):
        for env in ([],['KEYCLOAK_ADMIN=admin','KEYCLOAK_ADMIN_PASSWORD=bad\nline'],['KEYCLOAK_ADMIN=a','KEYCLOAK_ADMIN_PASSWORD=a','KC_BOOTSTRAP_ADMIN_USERNAME=b','KC_BOOTSTRAP_ADMIN_PASSWORD=b']):
            with self.assertRaises(ValueError):read.memory_only_query('a'*64,env)
if __name__=='__main__':unittest.main()
