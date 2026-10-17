"""Retained templates and literal Spring JSON, with no credential disclosure."""
import copy,json,sys,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.resolution_ths_update.plan import compile_routes,configuration,ROUTES,PACKAGE,THS_CONFIG
from tools.resolution_ths_update.native import NativePorts,ReadTransient

def templates():
 pre={'phase':'rewrite','functions':['return function(conf,ctx) -- retained HUMAN boundary\nend']}
 post={'phase':'header_filter','functions':['return function(conf,ctx) end']}
 result={'trusted-human-onboarding-review':{'id':'trusted-human-onboarding-review','uri':'/trusted-human/onboarding/*','methods':['GET','POST'],'plugins':{'serverless-pre-function':pre},'upstream':{'nodes':{'onboarding:8080':1},'retries':0}}}
 for rid,method in(('ths-identity-preflight-read','GET'),('ths-identity-preflight-create','POST')):
  result[rid]={'id':rid,'uri':'/api/udp/v1/governance/identity/preflight','methods':[method],'plugins':{'serverless-pre-function':copy.deepcopy(pre),'serverless-post-function':copy.deepcopy(post),'openid-connect':{'bearer_only':True,'ssl_verify':True,'required_scopes':['urban.identity.preflight'],'client_secret':'SYNTHETIC_ONLY'}},'upstream':{'nodes':{'udp:8080':1},'retries':0}}
 return result
class Plan(unittest.TestCase):
 def test_three_exact_routes_preserve_backends_authentication_and_original_map(self):
  before=templates();retained=copy.deepcopy(before);routes=compile_routes(before)
  self.assertEqual(before,retained);self.assertEqual(tuple(routes),ROUTES)
  self.assertEqual([r['uri']for r in routes.values()],[PACKAGE,PACKAGE+'/confirm','/trusted-human/resolution/*'])
  for rid,template,cap in zip(ROUTES[:2],('ths-identity-preflight-read','ths-identity-preflight-create'),('resolution.issue.read','resolution.match.approve')):
   self.assertEqual(routes[rid]['upstream']['nodes'],before[template]['upstream']['nodes'])
   expected=copy.deepcopy(before[template]['plugins']['openid-connect']);expected['required_scopes']=[cap]
   self.assertEqual(routes[rid]['plugins']['openid-connect'],expected)
  self.assertEqual(routes[ROUTES[2]]['plugins']['serverless-pre-function'],before['trusted-human-onboarding-review']['plugins']['serverless-pre-function'])
 def test_drift_existing_path_and_broadened_template_are_rejected(self):
  for mutate in(lambda b:b.update({ROUTES[0]:{}}),lambda b:b['ths-identity-preflight-read']['plugins']['openid-connect'].update(bearer_only=False),lambda b:b['ths-identity-preflight-read'].update(vars=[['uri','~~','.*']]),lambda b:b.update(foreign={'uri':PACKAGE})):
   before=templates();mutate(before)
   with self.assertRaises(Exception):compile_routes(before)
 def actual(self,values):
  return {'Config':{'Env':['SPRING_CONFIG_IMPORT=optional:file:/run/ths.yaml','SPRING_APPLICATION_JSON='+json.dumps(values)],'Cmd':['java','app.jar']},'Mounts':[{'Source':THS_CONFIG,'Destination':'/run/ths.yaml','Type':'bind','RW':False}]}
 def values(self):return {'ouf.authorization.ths.enabled':True,'ouf.resolution.ths.gateway-base-url':'https://fixture.invalid','spring.security.oauth2.client.registration.ouf-ths.scope':['openid','resolution.issue.read','resolution.match.approve']}
 def test_ths_and_scopes_in_spring_application_json_are_checked_without_printing_values(self):
  with patch('tools.resolution_ths_update.plan.private_config',return_value=(b'# selected private config\n',{'path':THS_CONFIG,'sha256':'a'*64})):
   result=configuration(self.actual(self.values()),'https://fixture.invalid','a'*64)
  self.assertTrue(result['thsAuthenticationEnabled']);self.assertTrue(result['requiredScopesDeclared']);self.assertNotIn('fixture.invalid',json.dumps(result))
 def test_missing_scope_wrong_origin_and_override_fail_before_route_mutation(self):
  for key,value in [('ouf.authorization.ths.enabled',False),('ouf.resolution.ths.gateway-base-url','https://wrong.invalid'),('spring.security.oauth2.client.registration.ouf-ths.scope',['openid'])]:
   values=self.values();values[key]=value
   with patch('tools.resolution_ths_update.plan.private_config',return_value=(b'# literal\n',{'sha256':'a'*64})):
    with self.assertRaises(Exception):configuration(self.actual(values),'https://fixture.invalid','a'*64)
 def test_whole_inventory_prefix_and_retry_after_are_preserved(self):
  ports=NativePorts.__new__(NativePorts);before=templates();ports.plan={'beforeRoutes':before,'routes':compile_routes(before)}
  ports.gateway=type('Admin',(),{'retry_after':'37','request':lambda *args:(503,{})})()
  state,proof=ports.observe('VERIFY_INPUTS');self.assertEqual(state,'TRANSIENT');self.assertEqual(proof['retryAfterSeconds'],37)
  ports.inventory=lambda:{**before,'foreign':{'id':'foreign'}}
  with self.assertRaises(Exception):ports.apply('PUBLISH_READ')
if __name__=='__main__':unittest.main()
