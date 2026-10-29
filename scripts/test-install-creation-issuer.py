import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('installer',Path(__file__).with_name('install-creation-issuer.py'))
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

@unittest.skipUnless(os.geteuid()==0,'root-private source installation fixture')
class InstallTests(unittest.TestCase):
    def setUp(self):
        self.parent=Path(self.enterContext(tempfile.TemporaryDirectory(dir=os.environ.get('OUF_SHARED_COORDINATION_TEST_PARENT',str(Path.cwd()))))).resolve(); self.parent.chmod(0o700)
        self.root=self.parent/'package'; self.root.mkdir(mode=0o700)
        for p in ('source','source/scripts','source/tools'): (self.root/p).mkdir(mode=0o700)
        self.write(self.root/'install-creation-issuer.py',Path(m.__file__).read_bytes())
        self.files={n:b'raise AssertionError("source must never execute during installation")\n' for n in m.NAMES}
        for n, b in self.files.items(): self.write(self.root/'source'/n,b)
        self.manifest={'sourceCommit':'a'*40,'sourceHashes':{n:m.digest(b) for n,b in self.files.items()}}
        self.write(self.root/'sources.json',m.encoded(self.manifest)); self.manifest_hash=m.digest(m.encoded(self.manifest))
        self.custody=self.parent/'custody'; self.custody.mkdir(mode=0o700)
        self.policy_path=self.parent/'policy.json'; keys=[]; hashes={}
        for i, role in enumerate(('installer','attestor')):
            der=bytes.fromhex('302a300506032b6570032100')+bytes([i+1])*32
            self.write(self.custody/(role+'.der'),der); hashes[role+'.der']=m.digest(der)
            key=b'PRIVATE-TEST-SENTINEL-DO-NOT-READ'; self.write(self.custody/(role+'.pem'),key); hashes[role+'.pem']=m.digest(key)
            keys.append({'keyRef':m.BINDINGS[role+'_key_ref'],'issuerRef':m.BINDINGS[role+'_issuer_ref'],
                'roles':['DEPLOYMENT_INTENT','FINAL_DEPLOYMENT_APPROVAL'] if i==0 else ['CREATION_ATTESTATION'],
                'state':'ACTIVE','notBefore':int(time.time())-10,'expiresAt':int(time.time())+300,'publicKey':der[12:].hex()})
        custody={'schema':'ouf.semantic-authority-key-custody-receipt.v1','bindings':m.BINDINGS,'outputHashes':hashes}
        self.write(self.custody/'key-custody-receipt.json',m.encoded(custody))
        self.policy={'schema':'ouf.semantic-deployment-trust-policy.v1','installationRef':m.BINDINGS['installation_ref'],'entityRef':m.BINDINGS['entity_ref'],'keys':keys}
        self.write(self.policy_path,m.encoded(self.policy))
        for name,value in (('CUSTODY',self.custody),('POLICY',self.policy_path),('CUSTODY_HASH',m.digest(m.encoded(custody))),('POLICY_HASH',m.digest(m.encoded(self.policy)))):
            self.enterContext(patch.object(m,name,value))
    def write(self,p,b): p.write_bytes(b); p.chmod(0o600)
    def apply(self): return m.install(self.root,self.manifest_hash)
    def test_real_private_publication_binds_existing_keys_without_reading_them(self):
        original=m.read
        def read(p):
            self.assertFalse(p.suffix=='.pem'); return original(p)
        before={p:p.read_bytes() for p in self.custody.iterdir()}; policy_before=self.policy_path.read_bytes()
        with patch.object(m,'read',read): result=self.apply()
        self.assertEqual(result['privateKeysRead'],0); self.assertFalse(result['startAuthorized']); self.assertFalse(result['transactionConfigured'])
        self.assertEqual({p:p.read_bytes() for p in self.custody.iterdir()},before); self.assertEqual(self.policy_path.read_bytes(),policy_before)
        self.assertEqual((self.root/'installation-receipt.json').stat().st_mode&0o777,0o600)
    def test_source_drift_refuses_before_claim(self):
        p=self.root/'source'/m.NAMES[0]; p.write_bytes(b'pass\n')
        with self.assertRaises(ValueError): self.apply()
        self.assertFalse((self.root/'installation-claim.json').exists())
    def test_policy_drift_refuses_before_claim(self):
        self.policy_path.write_bytes(self.policy_path.read_bytes()+b' ')
        with self.assertRaises(ValueError): self.apply()
        self.assertFalse((self.root/'installation-claim.json').exists())
    def test_symlink_key_refuses_without_key_read(self):
        p=self.custody/'installer.pem'; p.unlink(); p.symlink_to(self.custody/'attestor.pem')
        with self.assertRaises(ValueError): self.apply()
    def test_completed_or_failed_install_is_never_replayed(self):
        self.apply(); before=(self.root/'installation-receipt.json').read_bytes()
        with self.assertRaises(ValueError): self.apply()
        self.assertEqual((self.root/'installation-receipt.json').read_bytes(),before)
    def test_failed_fsync_preserves_partial_claim(self):
        with patch.object(m.os,'fsync',side_effect=OSError('fixture')):
            with self.assertRaises(OSError): self.apply()
        self.assertTrue((self.root/'installation-claim.json').exists())
        with self.assertRaises(ValueError): self.apply()
    def test_extra_symlink_directory_is_rejected(self):
        (self.root/'source'/'foreign').symlink_to(self.custody,target_is_directory=True)
        with self.assertRaises(ValueError): self.apply()

if __name__=='__main__': unittest.main()
