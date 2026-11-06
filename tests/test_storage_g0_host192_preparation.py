import copy,importlib.util,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import test_storage_g0_host_profile as fixture
from tools.storage_planning import g0_package as p
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('host192prep',ROOT/'scripts/prepare-storage-g0-host192-20261106.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class Host192PreparationTests(unittest.TestCase):
 def setUp(self):
  self.mask=os.umask(0o077);original=tempfile.TemporaryDirectory
  anchor='/var/lib' if os.environ.get('GITHUB_ACTIONS')=='true' else str(Path.cwd())
  self.f=fixture.ReconciledProfileTests()
  with patch.object(tempfile,'TemporaryDirectory',lambda:original(dir=anchor)):self.f.setUp()
  self.bundle=self.f.f.bundle;self.destination=self.f.f.root/'new-stage'
  manifest=json.loads((self.bundle/'package-manifest.json').read_bytes())
  manifest['reconciledHostProfileLimits']=p.RECONCILED_LIMITS
  self.manifest=m.encode(manifest);self.prior=copy.deepcopy(self.f.c['priorAttemptFiles'])
 def tearDown(self):self.f.doCleanups();os.umask(self.mask)
 def prepare(self,**kwargs):
  return m.prepare(self.bundle,self.destination,self.f.f.digest,self.manifest,{},self.prior,
                   'fixture-next',preflight=kwargs.get('preflight',p.preflight))
 def test_stage_check_preserves_old_bytes_and_never_creates_collection_scope(self):
  before={str(x):m.sha(x.read_bytes()) for x in self.f.f.root.rglob('*') if x.is_file()}
  r=self.prepare();self.assertEqual(r['limits']['priorEngineGets'],53);self.assertEqual(r['limits']['engineGets'],386)
  self.assertFalse(r['collectionScopeCreated']);self.assertFalse((self.f.f.output/'fixture-next').exists())
  for path,digest in before.items():self.assertEqual(m.sha(Path(path).read_bytes()),digest)
  self.assertIsNone(json.loads((self.destination/'inputs/package-input.review.json').read_bytes())['collectionDecisionRef'])
 def test_embedded_public_payload_matches_qualified_manifest_and_sources(self):
  import base64,zlib,hashlib
  payload=json.loads(zlib.decompress(base64.b64decode(m.PAYLOAD)))
  raw=base64.b64decode(payload['manifest']);self.assertEqual(hashlib.sha256(raw).hexdigest(),m.NEW_MANIFEST)
  manifest=json.loads(raw);self.assertEqual(manifest['deployCommit'],'cfa806d57012f07ead428208b4b8ce9d13b7e1ed')
  self.assertEqual(manifest['files']['bin/inventory'],'12ce46352d731d03861cf1196701869e61e27ecd29ce7d6011b2a13c4422f716')
  self.assertEqual(set(payload['overrides']),{'tools/storage_planning/g0_host.py','tools/storage_planning/g0_package.py','README.md'})
  for name,value in payload['overrides'].items():
   raw=base64.b64decode(value);self.assertEqual(hashlib.sha256(raw).hexdigest(),manifest['files'][name])
   source='docs/OUF_STORAGE_G0_NETWORK_20261106.md' if name=='README.md' else name
   self.assertEqual(raw,(ROOT/source).read_bytes())
 def test_reentry_only_reads_completed_preparation(self):
  self.prepare()
  def deny(*a):raise AssertionError('preflight repeated')
  self.assertTrue(self.prepare(preflight=deny)['existingPreparationReadOnly'])
 def test_partial_destination_is_not_adopted_or_reset(self):
  self.destination.mkdir();self.assertRaises(FileNotFoundError,self.prepare)
  self.assertEqual(list(self.destination.iterdir()),[])
 def test_receipt_drift_denied_before_destination(self):
  path=Path(self.prior['result']['path']);path.write_bytes(path.read_bytes()+b' ')
  self.assertRaises(m.Held,self.prepare);self.assertFalse(self.destination.exists())
 def test_wrong_new_member_digest_denied_before_destination(self):
  manifest=json.loads(self.manifest);manifest['files']['member']='0'*64;self.manifest=m.encode(manifest)
  self.assertRaises(m.Held,self.prepare);self.assertFalse(self.destination.exists())
 def test_failed_preflight_preserves_partial_and_denies_reentry(self):
  def fail(*a):raise ValueError('fixture failure')
  self.assertRaises(ValueError,self.prepare,preflight=fail)
  self.assertTrue((self.destination/'claim.json').exists())
  self.assertRaises(FileNotFoundError,self.prepare)

if __name__=='__main__':unittest.main()
