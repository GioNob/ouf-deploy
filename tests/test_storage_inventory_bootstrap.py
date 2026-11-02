import copy,gzip,importlib.util,os,struct,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).parents[1]
spec=importlib.util.spec_from_file_location('bootstrap',ROOT/'tools/storage_migration/inventory_bootstrap.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class DeliveryTest(unittest.TestCase):
 def setUp(self):
  binary=bytearray(64);binary[:7]=b'\x7fELF\x02\x01\x01';struct.pack_into('<H',binary,18,62);struct.pack_into('<HH',binary,54,56,0)
  self.binary=bytes(binary);self.capsule=b'# synthetic source inspection fixture\n';self.packed=gzip.compress(self.binary,mtime=0)
  self.data={'inventory.part000':self.packed,'prepare-storage-inventory.py':self.capsule}
  self.delivery={'backendInstallPath':str(m.INSTALL/'inventory'),'scopePath':str(m.SCOPE),'closedSourceCount':24,'original23SourcesUnchanged':True,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'backendBytes':len(self.binary),'backendSha256':m.sha(self.binary),'compressedBackendBytes':len(self.packed),'compressedBackendSha256':m.sha(self.packed),'capsuleSha256':m.sha(self.capsule),'parts':[{'name':'inventory.part000','bytes':len(self.packed),'sha256':m.sha(self.packed)}]}
  self.binding=patch.multiple(m,DELIVERY=self.delivery,PUBLICATION='a'*40);self.binding.start();self.addCleanup(self.binding.stop)
 def reader(self,name,limit):return self.data[name]
 def test_exact_assembly(self):m.validate_delivery();self.assertEqual(m.assemble(self.reader),(self.binary,self.capsule))
 def test_changed_part_and_capsule_denied(self):
  for name in self.data:
   original=self.data[name];self.data[name]=original+b'changed'
   with self.assertRaises(ValueError):m.assemble(self.reader)
   self.data[name]=original
 def test_extra_or_unsafe_part_denied_before_download(self):
  for name in ['../inventory','inventory.part999']:
   self.delivery['parts'][0]['name']=name
   with self.assertRaises(ValueError):m.validate_delivery()
 def test_decompression_cannot_exceed_declared_binary(self):
  self.delivery['backendBytes']=1
  with self.assertRaises(ValueError):m.assemble(self.reader)
 def test_dynamic_executable_denied(self):
  raw=bytearray(120);raw[:64]=self.binary;struct.pack_into('<Q',raw,32,64);struct.pack_into('<HH',raw,54,56,1);struct.pack_into('<I',raw,64,3)
  with self.assertRaises(ValueError):m.executable(raw)
 def test_redirect_denied(self):
  with self.assertRaises(ValueError):m.NoRedirect().redirect_request(None,None,None,None,None,None)
 @unittest.skipUnless(os.geteuid()==0,'root-owned installation fixture')
 def test_install_protects_modes_and_refuses_existing_unknown_files(self):
  with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
   root=Path(tmp);root.chmod(0o700)
   with patch.object(m,'INSTALL',root/'reader'):
    m.install(self.binary,self.capsule)
    self.assertEqual((m.INSTALL/'inventory').read_bytes(),self.binary);self.assertEqual((m.INSTALL/'inventory').stat().st_mode&0o777,0o500)
    self.assertEqual((m.INSTALL/'prepare-storage-inventory.py').stat().st_mode&0o777,0o400)
    unknown=m.INSTALL/'unknown';m.INSTALL.chmod(0o700);unknown.write_text('preserve')
    with self.assertRaises(ValueError):m.install(self.binary,self.capsule)
    self.assertEqual(unknown.read_text(),'preserve')
 def test_writable_and_symlink_ancestry_denied(self):
  with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
   p=Path(tmp);p.chmod(0o777)
   with self.assertRaises(ValueError):m.ancestry(p)
   p.chmod(0o700);link=p/'link';link.symlink_to(p,target_is_directory=True)
   with self.assertRaises(ValueError):m.ancestry(link)
