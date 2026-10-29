import importlib.util,json,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('dependencies',Path(__file__).resolve().parents[1]/'scripts/read-retained-network-dependencies.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Read(unittest.TestCase):
 def test_userinfo_paths_queries_and_other_values_suppressed(self):
  result=m.dependencies(['LAKE=http://user:SECRET_CANARY@ouf-minio:9000/SECRET_CANARY?token=SECRET_CANARY','TOKEN=SECRET_CANARY','OTHER=https://other.invalid/SECRET_CANARY'])
  self.assertNotIn('SECRET_CANARY',json.dumps(result));self.assertEqual(result['references'][0]['host'],'ouf-minio');self.assertEqual(result['references'][0]['port'],9000)
 def test_literal_dependencies_even_outside_urls(self):
  result=m.dependencies(['JSON={"upstream":"172.18.0.6:9000"}','URL=http://172.18.0.5:9080'])
  self.assertEqual(result['literalAddressCounts'],{'172.18.0.5':1,'172.18.0.6':1})
 def test_no_literal_substring_confusion(self):
  result=m.dependencies(['HOST=172.18.0.50 172.18.0.60']);self.assertEqual(sum(result['literalAddressCounts'].values()),0)
if __name__=='__main__':unittest.main()
