import importlib.util,io,json,tempfile,unittest,zipfile,hashlib,os,stat
from unittest.mock import patch
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('readiness_preparation',ROOT/'scripts/prepare-ingestion-readiness-update-review-20261017.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class PrivatePreparation(unittest.TestCase):
 def test_projection_reader_pins_source_and_selected_path(self):
  raw=(ROOT/'tools/chatbot_file_cohort/gateway.py').read_bytes()
  read=m.projection_reader(raw)
  with self.assertRaisesRegex(ValueError,'EXACT_SELECTED_PROJECTION_REQUIRED'):read({'path':'/tmp/arbitrary'})
  with self.assertRaisesRegex(ValueError,'GATEWAY_CUSTODY_SOURCE_DRIFT'):m.projection_reader(raw+b'\n')
 @unittest.skipUnless(os.geteuid()==0,'native ownership fixture requires root')
 def test_existing_nonroot_parent_and_exact_binding_without_ownership_changes(self):
  raw=(ROOT/'tools/chatbot_file_cohort/gateway.py').read_bytes();read=m.projection_reader(raw)
  with tempfile.TemporaryDirectory(dir=ROOT)as d:
   root=Path(d);parent=root/'opt/ouf/installation';parent.mkdir(parents=True)
   for p in(root/'opt',root/'opt/ouf',parent):p.chmod(0o700)
   try:os.chown(root/'opt/ouf',1000,1000)
   except OSError as error:
    if error.errno==22:self.skipTest('host user namespace does not map uid 1000')
    raise
   (root/'opt/ouf').chmod(0o750)
   target=parent/'active-projection.json';target.write_bytes(b'{"fixture":true}');target.chmod(0o600)
   s=target.stat();metadata=[s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
   binding={'path':'/opt/ouf/installation/active-projection.json','sha256':hashlib.sha256(target.read_bytes()).hexdigest(),'metadata':metadata}
   original_open=os.open
   def mapped_open(path,*args,**kwargs):return original_open(str(root)if path=='/'else path,*args,**kwargs)
   with patch.object(m.os,'open',side_effect=mapped_open):
    self.assertEqual(read(binding),{'fixture':True})
    for changed in(dict(binding,sha256='0'*64),dict(binding,metadata=[0]*9)):
     with self.assertRaisesRegex(ValueError,'APISIX_SELECTED_CONFIG_CHANGED'):read(changed)
    (root/'opt/ouf').chmod(0o770)
    with self.assertRaisesRegex(ValueError,'APISIX_CONFIG_ANCESTRY_NOT_CUSTODIED'):read(binding)
    (root/'opt/ouf').chmod(0o750)
    target.rename(parent/'real');target.symlink_to('real')
    with self.assertRaises(OSError):read(binding)
   self.assertEqual((root/'opt/ouf').stat().st_uid,1000)
 def test_selection_bytes_and_test_profile(self):
  raw=(ROOT/'releases/ingestion-readiness-private-selection-20261017.json').read_bytes()
  self.assertEqual(hashlib.sha256(raw).hexdigest(),m.CASE_SHA)
  case=json.loads(raw);self.assertEqual(case['worker']['controlledAttempts'],188)
  self.assertEqual(case['finiteTestProfile']['maximumNewTokenGrantAttempts'],128)
  self.assertEqual(set(case['expectedRuntimeBindings']),{'ouf-onboarding','ouf-ingestion','ouf-apisix'})
 def test_stream_copy_is_exact_and_private(self):
  with tempfile.TemporaryDirectory(dir=ROOT)as d:
   source=Path(d)/'source';target=Path(d)/'target';raw=b'fixture'*(400000)
   source.write_bytes(raw);m.copy_artifact(source,target,hashlib.sha256(raw).hexdigest())
   self.assertEqual(target.read_bytes(),raw);self.assertEqual(target.stat().st_mode&0o777,0o600)
   with self.assertRaises(FileExistsError):m.copy_artifact(source,target,hashlib.sha256(raw).hexdigest())
 def test_unsafe_duplicate_and_missing_aggregate_members_are_rejected(self):
  for names in [('../escape',),('/absolute',),('same','same')]:
   stream=io.BytesIO()
   with zipfile.ZipFile(stream,'w')as z:
    for name in names:z.writestr(name,b'fixture')
   stream.seek(0)
   with zipfile.ZipFile(stream)as z:
    with self.assertRaises(ValueError):m.zip_index(z)
  stream=io.BytesIO()
  with zipfile.ZipFile(stream,'w')as z:z.writestr('SHA256SUMS','0'*64+'  absent\n');z.writestr('SHA256SUMS.sigstore.json','{}')
  stream.seek(0)
  with zipfile.ZipFile(stream)as z:
   with self.assertRaises(ValueError):m.verified_zip(z,m.zip_index(z))
 def test_safe_failure_reports_codes_without_raw_messages_or_secondary_failure(self):
  ReadDenied=type('ReadDenied',(Exception,),{})
  self.assertEqual(m.safe_reason(ReadDenied('ROOT_INPUT_CUSTODY_REQUIRED')),'ROOT_INPUT_CUSTODY_REQUIRED')
  self.assertEqual(m.safe_reason(ValueError('password=private')),'ValueError')
  self.assertEqual(m.safe_reason(RuntimeError('PRIVATE_DATA')),'RuntimeError')
if __name__=='__main__':unittest.main()

