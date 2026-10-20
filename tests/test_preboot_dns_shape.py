import importlib.util,json,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];spec=importlib.util.spec_from_file_location('dns_shape',ROOT/'scripts/read-preboot-dns-shape.py');r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
class Shape(unittest.TestCase):
 def test_empty_null_and_nonempty_redaction(self):
  self.assertEqual(r.shape([])['count'],0);self.assertIsNone(r.shape(None)['count']);out=r.shape(['PRIVATE_DNS_CANARY']);self.assertTrue(out['explicitOverridePresent']);self.assertNotIn('PRIVATE_DNS_CANARY',json.dumps(out))
 def test_wrong_type_rejected(self):
  for value in ('PRIVATE_CANARY',False,{},[1],['x']*65):
   with self.assertRaises(ValueError):r.shape(value)
 def test_exact_three_role_inspect_only(self):
  selection={'schema':'ouf.preboot-dns-shape-selection.v1','applications':{'mcp':'a'*64,'udp':'b'*64,'onboarding':'c'*64}};rows=[{'id':cid,'running':role!='udp','dns':[]}for role,cid in selection['applications'].items()]
  with patch.object(r.m,'invoke',return_value='\n'.join(json.dumps(row)for row in rows).encode())as invoke:out=r.collect(selection)
  self.assertTrue(out['complete']);self.assertEqual(out['engineWrites'],0);self.assertEqual(invoke.call_args.args[0][0],'inspect');self.assertEqual(len(out['applications']),3)
if __name__=='__main__':unittest.main()
