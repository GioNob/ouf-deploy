import copy,unittest
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools.m2_discovery_installation_profile import audit as m


def fixture():
    semantic=['OUF_SCHEMA_GOV_CLIENT_SECRET_FILE=/run/secrets/provider-secret',
        'OUF_SEMANTIC_DISCOVERY_DELEGATION_KEY_FILE=/run/secrets/discovery-key',
        'OUF_IAM_ISSUER=https://issuer.fixture/realms/test','OUF_IAM_AUDIENCE=fixture-gateway',
        'OUF_SCHEMA_GOV_GATEWAY_BASE_URL=https://southbound.fixture:10443',
        'OUF_SCHEMA_GOV_TOKEN_ENDPOINT=https://issuer.fixture/realms/test/token',
        'OUF_SCHEMA_GOV_CLIENT_ID=fixture-semantic','OUF_SCHEMA_GOV_WORKLOAD_SCOPE=gateway.southbound.invoke',
        'OUF_SEMANTIC_DISCOVERY_DELEGATION_WORKLOAD=fixture-mcp','OUF_SCHEMA_GOV_SEARCH_PATH=/providers/search',
        'OUF_SCHEMA_GOV_FETCH_PATH=/providers/fetch','OUF_SCHEMA_GOV_ENABLED=false',
        'OUF_DISCOVERY_WORKER_ENABLED=false','OUF_IAM_ENABLED=true','OUF_SCHEMA_GOV_GATEWAY_AUTH_ENABLED=true']
    mcp=['MCP_OIDC_CLIENT_ID=fixture-mcp','MCP_OIDC_CLIENT_SECRET_FILE=/run/secrets/mcp-secret',
         'MCP_GATEWAY_ENDPOINT=https://gateway.fixture/execute','MCP_GATEWAY_RECOVERY_ENDPOINT=https://gateway.fixture/recovery',
         'MCP_AUTHORIZATION_BUNDLE_ENDPOINT=https://gateway.fixture/policy',
         'MCP_OIDC_TOKEN_ENDPOINT=https://issuer.fixture/realms/test/token','MCP_WORKLOAD_TOKEN=never-disclose-me']
    observations={};pins={}
    for i,role in enumerate(sorted(m.ROLES),1):
        observations[role]={'Id':str(i)*64,'Image':'sha256:'+str(i)*64,'State':{'Running':True,'Paused':False,'Pid':i+100},
            'Config':{'Env':semantic if role=='semantic' else mcp if role=='mcp' else ['SECRET=never-disclose-me']},
            'Mounts':[{'Destination':'/run/secrets/mcp-secret' if role=='mcp' else '/run/auth',
                       'Source':'/private/never-disclose-me','Type':'bind','RW':False}]}
        pins[role]={'pid':i+100,'startTicks':900+i}
    inputs={'schema':m.SCHEMA,'observations':observations,'processPins':pins,
        'historicalAuthorityReused':False,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False}
    return inputs,{'path':'/synthetic/qualified/inputs.json','sha256':m.digest(inputs)}, {'discoveryOwnerKeyEnvironmentName':'FIXTURE_DISCOVERY_OWNER_KEY'}


class InstallationAudit(unittest.TestCase):
    def test_missing_secret_mounts_block_and_mcp_existing_binding_is_retained(self):
        inputs,binding,selection=fixture();before=copy.deepcopy(inputs)
        result=m.compile_audit(inputs,binding,selection)
        self.assertEqual(result['providerCredential']['state'],'NO_COVERING_MOUNT_DECLARED')
        self.assertEqual(result['registryReceiptKey']['state'],'NO_COVERING_MOUNT_DECLARED')
        self.assertEqual(result['mcpCredential']['state'],'EXACT_READONLY_TARGET_DECLARED')
        self.assertEqual(inputs,before)
        self.assertIn('PROVIDER_CLIENT_SECRET_MOUNT_BINDING_REQUIRED',result['blockingRequirements'])
        self.assertFalse(result['nativeExecutionAllowed'])

    def test_parent_mount_is_not_promoted_to_existing_directory_or_credential(self):
        mounts=[{'Destination':'/run/secrets','Type':'bind','RW':False}]
        result=m.coverage('/run/secrets/credential',mounts)
        self.assertEqual(result['state'],'ANCESTOR_TARGET_DECLARED_DIRECTORY_TYPE_AND_FILE_CUSTODY_UNPROVEN')
        self.assertFalse(result['fileExistenceProven'])

    def test_similar_prefix_is_not_a_covering_mount(self):
        mounts=[{'Destination':'/run/secrets/provider-secret-other','Type':'bind','RW':False}]
        self.assertEqual(m.coverage('/run/secrets/provider-secret',mounts)['state'],'NO_COVERING_MOUNT_DECLARED')

    def test_readwrite_exact_mount_does_not_pass_readonly_requirement(self):
        self.assertEqual(m.coverage('/run/key',[{'Destination':'/run/key','Type':'bind','RW':True}])['state'],'READWRITE_TARGET_DECLARED')

    def test_changed_capture_hash_and_public_transcription_are_rejected(self):
        inputs,binding,selection=fixture();inputs['unreviewed']=True
        with self.assertRaisesRegex(ValueError,'HASH_BOUND'):m.compile_audit(inputs,binding,selection)
        inputs,binding,selection=fixture();inputs['schema']='ouf.m2-discovery-installation-inputs-target-observation.v1'
        binding['sha256']=m.digest(inputs)
        with self.assertRaisesRegex(ValueError,'HASH_BOUND'):m.compile_audit(inputs,binding,selection)

    def test_changed_workload_or_reused_key_reference_is_denied(self):
        inputs,binding,selection=fixture()
        for key in m.KEY_REFERENCE_NAMES:
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'DISTINCT_DISCOVERY'):
                m.compile_audit(inputs,binding,{'discoveryOwnerKeyEnvironmentName':key})
        for key in ('PATH','OUF_GATEWAY_OIDC_CLIENT_SECRET'):
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'DISTINCT_DISCOVERY'):
                m.compile_audit(inputs,binding,{'discoveryOwnerKeyEnvironmentName':key})
        inputs['observations']['mcp']['Config']['Env'][0]='MCP_OIDC_CLIENT_ID=wrong-workload'
        binding['sha256']=m.digest(inputs)
        with self.assertRaisesRegex(ValueError,'WORKLOAD_MUST_AGREE'):m.compile_audit(inputs,binding,selection)

    def test_captured_authority_and_ambiguous_roles_cannot_be_promoted(self):
        for key in ('historicalAuthorityReused','runtimeAuthorityIssued','automaticReplayAllowed','budgetReset'):
            inputs,binding,selection=fixture();inputs[key]=True;binding['sha256']=m.digest(inputs)
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'PROVENANCE_NOT_AUTHORITY'):
                m.compile_audit(inputs,binding,selection)
        inputs,binding,selection=fixture();inputs['observations']['mcp']['Id']=inputs['observations']['semantic']['Id'];binding['sha256']=m.digest(inputs)
        with self.assertRaisesRegex(ValueError,'FOUR_INSTALLATION'):m.compile_audit(inputs,binding,selection)

    def test_output_omits_other_credentials_and_raw_mount_sources(self):
        import json
        result=m.compile_audit(*fixture())
        self.assertNotIn('never-disclose-me',json.dumps(result))
        self.assertNotIn('SECRET',json.dumps(result['providerDeclaredReferences']))

    def test_no_declared_mount_combination_grants_native_execution(self):
        inputs,binding,selection=fixture()
        inputs['observations']['semantic']['Mounts']=[{'Destination':p,'Type':'bind','RW':False} for p in ('/run/secrets/provider-secret','/run/secrets/discovery-key')]
        binding['sha256']=m.digest(inputs);result=m.compile_audit(inputs,binding,selection)
        self.assertFalse(result['nativeExecutionAllowed']);self.assertFalse(result['credentialCustodyProven'])
        self.assertFalse(result['providerReadinessProven']);self.assertFalse(result['otherNinePeersProvenCurrent'])
        self.assertFalse(result['fileOnlyProfileCanAuthorizeDiscovery'])


if __name__=='__main__':unittest.main()
