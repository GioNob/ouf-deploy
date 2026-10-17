"""Actual Draft4 validation reproduces the inherited preflight rejection."""
import copy,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.resolution_comparison_update.plan import confirmation_route,CONFIRM_SCHEMA
from tools.resolution_ths_update.plan import compile_routes
from jsonschema import Draft4Validator
class Schema(unittest.TestCase):
 def route(self):
  return {'id':'ths-resolution-package-confirm','uri':'/api/udp/v1/governance/resolution/issues/package/confirm','methods':['POST'],
   'upstream':{'nodes':{'fixture:8080':1},'retries':0},'plugins':{
    'openid-connect':{'bearer_only':True,'ssl_verify':True,'required_scopes':['resolution.match.approve']},
    'serverless-pre-function':{'functions':['retained authentication boundary']},
    'request-validation':{'body_schema':{'type':'object','required':['configuration'],'properties':{'configuration':{'type':'object'}}}}}}
 def payload(self):
  return {'snapshotHash':'sha256:'+'a'*64,'choices':[{'issueId':'00000000-0000-4000-8000-000000000001','expectedVersion':0,'action':'CREATE_NEW','reason':'','targetUrbanObjectId':None,'expectedReviewHash':'sha256:'+'b'*64}]}
 def test_reproduces_configuration_error_then_accepts_actual_browser_payload_and_empty_probe(self):
  old=self.route();payload=self.payload()
  errors=list(Draft4Validator(old['plugins']['request-validation']['body_schema']).iter_errors(payload))
  self.assertTrue(any(e.validator=='required'and'configuration'in e.message for e in errors))
  updated=confirmation_route(old);validator=Draft4Validator(updated['plugins']['request-validation']['body_schema'])
  validator.validate(payload);validator.validate({**payload,'choices':[]})
  del payload['choices'][0]['reason'];validator.validate(payload)
  del payload['choices'][0]['expectedReviewHash'];validator.validate(payload)
  self.assertEqual(confirmation_route(old),updated)
 def test_only_body_schema_changes_and_malformed_requests_are_still_rejected(self):
  old=self.route();before=copy.deepcopy(old);updated=confirmation_route(old)
  self.assertEqual(old,before)
  restored=copy.deepcopy(updated);restored['plugins']['request-validation']['body_schema']=old['plugins']['request-validation']['body_schema']
  self.assertEqual(restored,old)
  validator=Draft4Validator(CONFIRM_SCHEMA)
  for changed in ({'configuration':{}},{**self.payload(),'unexpected':True},{**self.payload(),'snapshotHash':'wrong'},{**self.payload(),'choices':[{'issueId':'wrong','expectedVersion':0,'action':'CREATE_NEW'}]}):
   self.assertFalse(validator.is_valid(changed))
  with self.assertRaises(Exception):confirmation_route(updated)
if __name__=='__main__':unittest.main()
