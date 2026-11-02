import hashlib,importlib.util,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).parents[1]
spec=importlib.util.spec_from_file_location('bootstrap',ROOT/'tools/storage_migration/inventory_reconciliation_bootstrap.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class DeliveryTests(unittest.TestCase):
 def test_redirects_are_denied(self):
  with self.assertRaises(ValueError):m.NoRedirect().redirect_request(None,None,None,None,None,None)
 def test_capsule_tampering_is_denied_before_install(self):
  with patch.object(m,'DELIVERY',{'capsuleBytes':2,'capsuleSha256':hashlib.sha256(b'ok').hexdigest()}):
   with self.assertRaises(ValueError):m.install(b'no')
 @unittest.skipUnless(os.geteuid()==0,'root installation fixture')
 def test_capsule_only_install_and_existing_files_preserved(self):
  parent='/root' if os.environ.get('GITHUB_ACTIONS')=='true' else ROOT
  with tempfile.TemporaryDirectory(dir=parent) as tmp:
   p=Path(tmp);p.chmod(0o700);raw=b'# synthetic capsule\n';delivery={'capsuleBytes':len(raw),'capsuleSha256':hashlib.sha256(raw).hexdigest()}
   with patch.multiple(m,INSTALL=p/'correction',DELIVERY=delivery):
    m.install(raw);self.assertEqual({q.name for q in m.INSTALL.iterdir()},{'prepare-reconciliation.py','delivery.json'})
    self.assertEqual((m.INSTALL/'prepare-reconciliation.py').stat().st_mode&0o777,0o400)
    m.INSTALL.chmod(0o700);(m.INSTALL/'unknown').write_text('preserve')
    with self.assertRaises(ValueError):m.install(raw)
    self.assertEqual((m.INSTALL/'unknown').read_text(),'preserve')
 def test_no_insecure_backend_substitution(self):
  self.assertEqual(m.BACKEND_SHA,'430631fe4dfd1b844229637373ea176c2e84e81e1491919f4a25cc36c68359a8')
  self.assertNotEqual(m.INSTALL,m.BACKEND.parent)
