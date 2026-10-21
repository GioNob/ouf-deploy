import ast,importlib.util,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];SCRIPT=ROOT/'scripts/read-human-renewal-guard-source.py'
if not SCRIPT.exists():SCRIPT=Path(__file__).with_name(SCRIPT.name)
spec=importlib.util.spec_from_file_location('qualified_guard_source_read',SCRIPT);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class GuardSource(unittest.TestCase):
 def fixture(self):return b'class HumanSession:\n def _check_identity_and_budget(self,row):\n  require(row["good"],"RENEWED_HUMAN_WINDOW_CUMULATIVE_HISTORY_REQUIRED")\n'
 def test_extracts_authenticated_method_and_expression_without_execution(self):
  raw=b'raise RuntimeError("MUST_NOT_EXECUTE")\n'+self.fixture()
  result=m.selected_guard(raw);self.assertEqual(result['renewalGuardExpression'],"row['good']")
  self.assertNotIn('MUST_NOT_EXECUTE',result['methodSource'])
 def test_missing_duplicate_or_oversized_method_fails_closed(self):
  for raw in(b'pass\n',self.fixture()+self.fixture(),b'x'*262145):
   with self.assertRaises(Exception):m.selected_guard(raw)
 def test_unrelated_methods_and_module_constants_are_not_exported(self):
  raw=self.fixture()+b' def private(self):\n  return "PRIVATE_UNUSED"\nSECRET="PRIVATE_CONSTANT"\n'
  result=m.selected_guard(raw);self.assertNotIn('PRIVATE',str(result))
 def test_reader_has_no_live_execution_or_oauth_owner_dispatch(self):
  calls=[ast.unparse(n.func)for n in ast.walk(ast.parse(SCRIPT.read_bytes()))if isinstance(n,ast.Call)]
  self.assertFalse(any(v in('exec','eval')or v.endswith(('.login','.refresh_if_due','.request','.main','.write','.execv'))for v in calls))
if __name__=='__main__':unittest.main()
