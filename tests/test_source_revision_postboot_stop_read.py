import importlib.util,json,os,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def module(name,path):
 spec=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
m=module('stop_read','scripts/read-source-revision-postboot-stop.py')
r=module('reader','scripts/prepare-source-revision-inputs.py')
class Classification(unittest.TestCase):
 def test_json_quoted_keys_classified_without_disclosing_names_or_values(self):
  raw=b'{\n "PRIVATE_KEY_CANARY":{"binding":"PRIVATE_VALUE_CANARY"}\n}'
  result=m.classify(raw);self.assertTrue(result['strictJsonObject']);self.assertEqual(result['syntaxCounts']['flowObject'],1);self.assertEqual(result['syntaxCounts']['quotedLine'],1)
  self.assertEqual(result['reservedSpringOrLoaderKeyCount'],0);self.assertNotIn('CANARY',json.dumps(result))
 def test_duplicate_reserved_and_nested_list_properties(self):
  self.assertTrue(m.classify(b'{"a":1,"a":2}')['duplicateJsonKeys'])
  result=m.classify(b'{"spring.flyway.enabled":false,"a":[{"LOADER_PATH":"secret"}]}');self.assertEqual(result['reservedSpringOrLoaderKeyCount'],2)
 def test_yaml_format_is_not_accepted_as_json(self):
  for raw in (b'"owner": secret\n',b'owner: &alias secret\n',b'<<: *alias\n',b'---\nowner: value\n',b'{"a":NaN}'):
   with self.subTest(raw=raw):self.assertFalse(m.classify(raw)['strictJsonObject']);self.assertTrue(m.classify(raw)['jsonParseFailed'])
 def test_bounds_and_deep_json(self):
  for raw in (b'',b'x'*1048577):
   with self.assertRaises(ValueError):m.classify(raw)
  value='"secret"'
  for _ in range(35):value='{"owner":'+value+'}'
  self.assertTrue(m.classify(value.encode())['depthBoundExceeded'])
class Custody(unittest.TestCase):
 def fixture(self,root):
  expected={**{'executor-code/f'+str(i):b'private code' for i in range(81)},**{'gateway-compiler/f'+str(i):b'compiler' for i in range(7)},'current-original-preparation.json':b'{}','postboot-private-inputs.json':b'{}'}
  for name,raw in expected.items():
   p=root/name;p.parent.mkdir(mode=0o700,parents=True,exist_ok=True);p.write_bytes(raw);p.chmod(0o600)
  return expected
 def test_exact_ninety_files_and_no_authority(self):
  with tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT.parent))) as temp:
   root=Path(temp);expected=self.fixture(root);result=m.exact_tree(root,expected,r);self.assertEqual(len(result),90)
   self.assertNotIn('private code',json.dumps(result))
 def test_unknown_completion_authority_link_mode_and_bytes_fail(self):
  for change in ('receipt','authority','directory','link','mode','bytes'):
   with self.subTest(change=change),tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT.parent))) as temp:
    root=Path(temp);expected=self.fixture(root);p=root/'executor-code/f0'
    if change=='receipt':(root/'postboot-preparation-result.json').write_text('{}')
    if change=='authority':(root/'authority.json').write_text('{}')
    if change=='directory':(root/'unknown').mkdir(mode=0o700)
    if change=='link':p.unlink();p.symlink_to(root/'executor-code/f1')
    if change=='mode':p.chmod(0o644)
    if change=='bytes':p.write_bytes(b'changed')
    with self.assertRaises(ValueError):m.exact_tree(root,expected,r)
 def test_digest_bound_reader_rejects_tamper(self):
  with tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT.parent))) as temp:
   p=Path(temp)/'code';p.write_bytes(b'code');sha=m.digest(b'code');self.assertEqual(m.read(p,sha),b'code');p.write_bytes(b'evil')
   with self.assertRaises(ValueError):m.read(p,sha)
if __name__=='__main__':unittest.main()
