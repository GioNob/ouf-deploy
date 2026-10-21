"""Preserve every existing Spring property/environment except two reviewed keys."""
import copy,json,sys,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.resolution_ths_configuration.plan import patch_environment,selected,NORMAL,SCOPES,ENABLED,GATEWAY,THS_CONFIG
class Plan(unittest.TestCase):
 def config(self,nested=False):
  if nested:return {'spring':{'security':{'oauth2':{'client':{'registration':{'ouf-ths':{'scope':['openid','profile','email'],'client-secret':'SYNTHETIC_ONLY'}}}}}},GATEWAY:'https://fixture.invalid','unrelated':[1,2]}
  return {SCOPES:['openid','profile','email'],GATEWAY:'https://fixture.invalid','unrelated':{'password':'SYNTHETIC_ONLY'}}
 def actual(self,obj):return {'Config':{'Env':['KEEP_THIS=original','SPRING_CONFIG_IMPORT=optional:file:/run/ths.yaml','SPRING_APPLICATION_JSON='+json.dumps(obj)],'Cmd':['java','app.jar']},'Mounts':[{'Source':THS_CONFIG,'Destination':'/run/ths.yaml','Type':'bind','RW':False}]}
 def test_additive_scopes_and_explicit_json_enable_preserve_all_other_values_and_input(self):
  for nested in(False,True):
   config=self.config(nested);actual=self.actual(config);before=copy.deepcopy(actual)
   with patch('tools.resolution_ths_configuration.plan.private_config',return_value=(b'ouf: {authorization: {ths: {enabled: true}}}',{'path':THS_CONFIG,'sha256':'a'*64})):
    env,meta=patch_environment(actual,'https://fixture.invalid','a'*64)
   self.assertEqual(actual,before);result=json.loads(next(v.split('=',1)[1]for v in env if v.startswith('SPRING_APPLICATION_JSON=')))
   props=selected(result);self.assertEqual(props[NORMAL(SCOPES)][1],['openid','profile','email','resolution.issue.read','resolution.match.approve']);self.assertTrue(props[NORMAL(ENABLED)][1])
   self.assertEqual(result['unrelated'],config['unrelated']);self.assertNotIn('SYNTHETIC_ONLY',json.dumps(meta));self.assertEqual(meta['preservedScopeCount'],3)
 def test_duplicate_aliases_bad_scope_and_wrong_gateway_are_rejected(self):
  cases=[]
  a=self.config();a['SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_OUF_THS_SCOPE']=['openid'];cases.append(self.actual(a))
  a=self.config();a[SCOPES]='openid profile';cases.append(self.actual(a))
  a=self.config();a[GATEWAY]='https://other.invalid';cases.append(self.actual(a))
  a=self.actual(self.config());a['Config']['Env'].append('JAVA_TOOL_OPTIONS=-Dunsafe=true');cases.append(a)
  for actual in cases:
   with patch('tools.resolution_ths_configuration.plan.private_config',return_value=(b'',{'path':THS_CONFIG,'sha256':'a'*64})):
    with self.assertRaises(Exception):patch_environment(actual,'https://fixture.invalid','a'*64)
 def test_already_requested_scopes_stop_for_reconciliation(self):
  config=self.config();config[SCOPES]+= ['resolution.issue.read','resolution.match.approve']
  with patch('tools.resolution_ths_configuration.plan.private_config',return_value=(b'',{'sha256':'a'*64})):
   with self.assertRaisesRegex(Exception,'ALREADY_REQUESTED'):patch_environment(self.actual(config),'https://fixture.invalid','a'*64)
if __name__=='__main__':unittest.main()
