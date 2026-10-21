import copy,importlib.util,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('compose',(Path(__file__).parent if (Path(__file__).parent/'scripts').exists() else Path(__file__).parent.parent)/'scripts/compose-semantic-replacement-draft.py');c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
class Draft(unittest.TestCase):
    def setUp(self):
        self.semantic={'Id':c.SEM,'Image':'old','Name':'/ouf-semantic','Config':{'Env':['OUF_IAM_ISSUER=https://auth.example.test/realms/ouf','OUF_IAM_AUDIENCE=ouf-api-gateway','OUF_SEMANTIC_DELEGATION_WORKLOAD=observed-caller']},'HostConfig':{},'Mounts':[],'NetworkSettings':{'Networks':{'observed-network':{}}},'State':{'Running':True,'Pid':3789123,'StartedAt':'fixture'}}
        self.mcp=copy.deepcopy(self.semantic);self.mcp['Id']='fixture-mcp';self.mcp['Name']='/ouf-mcp';self.mcp['Config']['Env']=['MCP_OIDC_CLIENT_ID=observed-caller','MCP_OIDC_TOKEN_ENDPOINT=https://auth.example.test/realms/ouf/protocol/openid-connect/token','MCP_OIDC_CLIENT_SECRET_FILE=/run/secrets/mcp']
        self.south=copy.deepcopy(self.semantic);self.south['Id']=c.SOUTH;self.south['NetworkSettings']['Networks']['observed-network']['Aliases']=['ouf-semantic-southbound-v2']
        cfg={'Env':['JAVA_HOME=/candidate/java','OUF_SEM_DB_PASSWORD=fixture-retained-secret'],'User':'10001:10001','Entrypoint':['java','-jar','/app/application.jar']}
        self.delta={'candidateConfig':cfg,'retainedContainer':self.semantic,'public':{'unreviewedEnvironmentOverrideNames':[],'explicitCommandOrUserOverrideNames':[],'retainedAuthMounts':[{'destination':'/run/ouf-semantic-auth','readOnly':True},{'destination':'/run/secrets/semantic-read-owner.key','readOnly':True}]}}
        self.old=c.CONFIG_HASH;c.CONFIG_HASH=c.sha(cfg)
    def tearDown(self):c.CONFIG_HASH=self.old
    def test_observed_identity_candidate_defaults_and_private_values_preserved(self):
        plan,public=c.compose(self.delta,self.semantic,self.mcp,self.south);settings=c.env({'Config':plan['candidateConfig']})
        self.assertEqual(settings['JAVA_HOME'],'/candidate/java');self.assertEqual(settings['OUF_SEM_DB_PASSWORD'],'fixture-retained-secret');self.assertEqual(settings['OUF_SEMANTIC_DISCOVERY_DELEGATION_WORKLOAD'],'observed-caller')
        self.assertNotIn('fixture-retained-secret',str(public));self.assertFalse(plan['applyAuthorized']);self.assertTrue(plan['providerPathsRequireFrozenBindingRead']);self.assertTrue(all(v['readOnly'] for v in plan['newReadOnlyMounts']))
    def test_missing_shared_tls_alias_or_primary_drift_blocks(self):
        for field in ('alias','primary'):
            sem=copy.deepcopy(self.semantic);south=copy.deepcopy(self.south)
            if field=='alias':south['NetworkSettings']['Networks']['observed-network']['Aliases']=[]
            else:sem['State']['Pid']=5
            with self.assertRaises(ValueError):c.compose(self.delta,sem,self.mcp,south)
    def test_existing_java_options_are_not_overwritten(self):
        self.delta['candidateConfig']['Env'].append('JAVA_TOOL_OPTIONS=-Xmx1g');c.CONFIG_HASH=c.sha(self.delta['candidateConfig'])
        with self.assertRaisesRegex(ValueError,'JVM_OPTIONS'):c.compose(self.delta,self.semantic,self.mcp,self.south)
    def test_changed_candidate_configuration_is_not_promoted(self):
        self.delta['candidateConfig']['Env'].append('JAVA_VERSION=legacy')
        with self.assertRaisesRegex(ValueError,'REVIEWED_CONFIGURATION'):c.compose(self.delta,self.semantic,self.mcp,self.south)
if __name__=='__main__':unittest.main()
