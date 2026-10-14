"""Current selection reads use the existing THS parser and explicit current binds."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import types
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_chatbot_cohort_gateway import crypto,Engine,ROOT
from tools.chatbot_file_cohort import target_selection as s

SOURCE=ROOT.parent/'onboarding-review-work/scripts/r4a_picker_onboarding_rollout.py'
if not SOURCE.is_file():SOURCE=ROOT/'.pairwise/onboarding/scripts/r4a_picker_onboarding_rollout.py'
CONFIG=b'''spring:
  security:
    oauth2:
      client:
        registration:
          ouf-ths:
            client-id: actual-human-browser-client
            client-secret: SYNTHETIC_NOT_USED
            scope: openid, ouf.semantic.review
        provider:
          ouf:
            issuer-uri: https://auth.example.invalid/realms/ouf
ouf:
  authorization:
    ths:
      public-origin: https://api.example.invalid
'''

class TargetSelection(unittest.TestCase):
    def fixture(self):
        f=crypto.SignedCutover();f.setUp();self.addCleanup(f.doCleanups)
        raw=SOURCE.read_bytes();h=hashlib.sha256(raw).hexdigest()
        picker=types.ModuleType('qualified_onboarding_picker');exec(compile(raw,str(SOURCE),'exec'),picker.__dict__)
        picker.__qualified_source_sha256__=h
        projection=f.root/'active-projection.json'
        projection.write_text(json.dumps({'gateway':{'issuerUrl':'https://auth.example.invalid/realms/ouf','publicApiBaseUrl':'https://api.example.invalid'},
            'iam':{'workloadClients':{'mcpServer':'current-mcp'}},'mcp':{'environment':{'MCP_OIDC_CLIENT_ID':'current-mcp'}}}))
        projection.chmod(0o600)
        ths=f.root/'ths.yaml';ths.write_bytes(CONFIG);ths.chmod(0o600)
        binary=f.root/'docker';binary.write_bytes(b'explicit fixture executable; never executed');binary.chmod(0o700)
        docker={'path':str(binary),'sha256':hashlib.sha256(binary.read_bytes()).hexdigest()}
        overlay={'spring':{'security':{'oauth2':{'client':{'registration':{'ouf-ths':{
            'scope':['openid','ouf.semantic.review','ouf.managed-source.file.upload']}}}}}}}
        onb={'Id':'1'*64,'Name':'/ouf-onboarding','Image':'sha256:'+'a'*64,
            'State':{'Running':True,'Paused':False,'Status':'running','Pid':77,'StartedAt':'2026-10-14T01:00:00Z'},
            'Config':{'Env':['SPRING_APPLICATION_JSON='+json.dumps(overlay),'OUF_RUNTIME_PUBLICATIONS_TENANT_ID=ouf-lab']},
            'HostConfig':{},'NetworkSettings':{},
            'Mounts':[{'Type':'bind','Destination':s.THS_MOUNT,'Source':str(ths),'RW':False}]}
        kc=copy.deepcopy(onb);kc.update(Id='2'*64,Name='/ouf-keycloak')
        observed={'ouf-onboarding':onb,'ouf-keycloak':kc};calls=[]
        engine=Engine.__new__(Engine)
        def request(method,path,body=None):
            self.assertEqual(method,'GET');calls.append(path);return 200,copy.deepcopy(observed[path.split('/')[3]])
        engine.request=request
        return f,picker,h,projection,docker,engine,observed,calls

    def test_effective_browser_client_and_scope_overlay_not_registration_alias(self):
        f,picker,h,projection,docker,engine,observed,calls=self.fixture()
        out=s.select_target(engine,docker,picker,h,projection_path=projection)
        selected=out['selection']
        self.assertEqual(selected['clients']['ths']['clientId'],'actual-human-browser-client')
        self.assertIn('ouf.managed-source.file.upload',selected['clients']['ths']['requestedScopes'])
        self.assertEqual(selected['clients']['chatgpt'],{'clientId':'ouf-chatgpt','requestedScopes':[]})
        self.assertEqual(selected['keycloakContainer'],'2'*64)
        self.assertFalse(out['humanSessionVerified']);self.assertEqual(out['credentialFilesRead'],1)
        self.assertEqual(len(calls),4)

    def test_mounted_issuer_conflict_cannot_be_adopted_from_projection(self):
        f,picker,h,projection,docker,engine,observed,calls=self.fixture()
        config=Path(observed['ouf-onboarding']['Mounts'][0]['Source'])
        config.write_bytes(CONFIG.replace(b'auth.example.invalid',b'wrong.example.invalid'))
        with self.assertRaisesRegex(ValueError,'DISAGREES_WITH_PROJECTION'):
            s.select_target(engine,docker,picker,h,projection_path=projection)

    def test_conflicting_runtime_tenant_or_direct_oauth_env_is_denied(self):
        for env,reason in [('OUF_RUNTIME_PUBLICATIONS_TENANT_ID=another','TENANT_CONTEXT_DRIFT'),
                           ('SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_OUF_THS_CLIENT_ID=other','DIRECT_OAUTH_ENV')]:
            with self.subTest(env=env):
                f,picker,h,projection,docker,engine,observed,calls=self.fixture()
                observed['ouf-onboarding']['Config']['Env']=[env]
                with self.assertRaisesRegex(ValueError,reason):
                    s.select_target(engine,docker,picker,h,projection_path=projection)

    def test_unqualified_parser_is_denied_before_any_reads(self):
        f,picker,h,projection,docker,engine,observed,calls=self.fixture()
        with self.assertRaisesRegex(ValueError,'QUALIFIED_EXISTING_THS_PARSER'):
            s.select_target(engine,docker,picker,'f'*64,projection_path=projection)
        self.assertEqual(calls,[])

if __name__=='__main__':unittest.main()
