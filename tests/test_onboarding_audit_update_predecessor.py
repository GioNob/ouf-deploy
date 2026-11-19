"""A new single-app correction binds to the completed predecessor generations."""
import ast,copy,unittest
from pathlib import Path
class Denied(RuntimeError):pass
def require(ok,reason):
 if not ok:raise Denied(reason)
class Predecessor(unittest.TestCase):
 def setUp(self):
  path=Path(__file__).resolve().parents[1]/'tools/onboarding_audit_update/entry.py';tree=ast.parse(path.read_text());fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='predecessor_application_pins');ns={'require':require};exec(compile(ast.Module(body=[fn],type_ignores=[]),str(path),'exec'),ns);self.pins=ns[fn.name]
  self.onb={'containerId':'new-onboarding','configHash':'onb'};self.ing={'containerId':'retained-ingestion','configHash':'ing'}
 def test_completed_single_app_retains_exact_ingestion_binding(self):
  plan={'replacements':{'onboarding':{}},'maximumGatewayWrites':0,'unchangedIngestionRuntimeBinding':self.ing};final={'applications':{'onboarding':{'runtimeBinding':self.onb}}}
  before=copy.deepcopy((plan,final));self.assertEqual(self.pins(plan,final),{'onboarding':self.onb,'ingestion':self.ing});self.assertEqual((plan,final),before)
 def test_original_two_app_predecessor_uses_both_final_generations(self):
  self.assertEqual(self.pins({'replacements':{'onboarding':{},'ingestion':{}}},{'applications':{'onboarding':{'runtimeBinding':self.onb},'ingestion':{'runtimeBinding':self.ing}}}),{'onboarding':self.onb,'ingestion':self.ing})
 def test_missing_retained_pin_and_widened_scope_fail(self):
  final={'applications':{'onboarding':{'runtimeBinding':self.onb}}}
  for plan in ({'replacements':{'onboarding':{}},'maximumGatewayWrites':0},{'replacements':{'onboarding':{},'gateway':{}}},{'replacements':{'onboarding':{}},'maximumGatewayWrites':1,'unchangedIngestionRuntimeBinding':self.ing}):
   with self.assertRaises(Denied):self.pins(plan,final)
 def test_unexpected_predecessor_evidence_fails(self):
  with self.assertRaisesRegex(Denied,'PREDECESSOR_FINAL_APPLICATIONS_MISMATCH'):self.pins({'replacements':{'onboarding':{}}},{'applications':{'onboarding':{'runtimeBinding':self.onb},'ingestion':{'runtimeBinding':self.ing}}})
if __name__=='__main__':unittest.main()
