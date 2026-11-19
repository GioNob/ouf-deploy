"""Real OpenSSL certificate parsing/MAC; no target inputs or issuer admission."""
import hashlib
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from tools.m2_discovery_installation_profile import public_truststore as m


class PublicTruststore(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.root=Path(cls.tmp.name)
        cls.certificates={}
        for name,ca in [('iam',True),('provider',True),('other',True),('leaf',False)]:
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2',
                '-keyout',str(cls.root/(name+'.key')),'-out',str(cls.root/(name+'.pem')),
                '-subj','/CN=fixture-'+name,'-addext','basicConstraints=critical,CA:'+('TRUE' if ca else 'FALSE')],
                check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            cls.certificates[name]=(cls.root/(name+'.pem')).read_bytes()

    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()

    def inputs(self):
        iam=self.certificates['iam'];provider=self.certificates['provider']
        fingerprint=hashlib.sha256(ssl.PEM_cert_to_DER_cert(iam.decode())).hexdigest()
        return iam,[fingerprint],provider,hashlib.sha256(provider).hexdigest(),time.time()

    def test_real_openssl_loads_and_verifies_mac_with_only_exact_two_certificates(self):
        raw,receipt=m.build(*self.inputs());path=self.root/'public.p12';path.write_bytes(raw)
        result=subprocess.run(['openssl','pkcs12','-in',str(path),'-passin','pass:changeit','-nokeys'],
            capture_output=True,check=True)
        self.assertEqual(result.stdout.count(b'BEGIN CERTIFICATE'),2)
        self.assertNotIn(b'PRIVATE KEY',result.stdout);self.assertEqual(receipt['privateKeyCount'],0)
        self.assertEqual(receipt['certificateCount'],2)
        self.assertEqual(receipt['sha256'],hashlib.sha256(raw).hexdigest())
        self.assertFalse(receipt['inputsAuthenticatedHere']);self.assertFalse(receipt['providerTlsAdmissionProven'])

    def test_canonical_bytes_are_order_independent_and_repeatable(self):
        args=list(self.inputs());args[0]+=self.certificates['other']
        args[1]=sorted(hashlib.sha256(v[0]).hexdigest() for v in m._ca_certificates(args[0]))
        first=m.build(*args)[0];args[0]=self.certificates['other']+self.certificates['iam']
        self.assertEqual(first,m.build(*args)[0])

    def test_wrong_or_extra_iam_root_and_changed_provider_binding_are_denied(self):
        for case in ('extra','missing','provider'):
            args=list(self.inputs())
            if case=='extra':args[0]+=self.certificates['other']
            if case=='missing':args[1]=['e'*64]
            if case=='provider':args[3]='e'*64
            with self.subTest(case=case),self.assertRaises(ValueError):m.build(*args)

    def test_private_key_nonca_duplicate_or_unbounded_data_is_denied(self):
        for case in ('private','nonca','duplicate','empty','large'):
            args=list(self.inputs())
            if case=='private':args[0]+=(self.root/'iam.key').read_bytes()
            if case=='nonca':args[2]=self.certificates['leaf'];args[3]=hashlib.sha256(args[2]).hexdigest()
            if case=='duplicate':args[0]+=args[0]
            if case=='empty':args[0]=b''
            if case=='large':args[0]=b'x'*4194305
            with self.subTest(case=case),self.assertRaises(ValueError):m.build(*args)

    def test_provider_ca_time_is_checked_and_shared_root_is_stored_once(self):
        args=list(self.inputs());args[4]=1
        with self.assertRaisesRegex(ValueError,'CURRENT_SINGLE_PROVIDER_CA'):m.build(*args)
        args=list(self.inputs());args[2]=args[0];args[3]=hashlib.sha256(args[0]).hexdigest()
        self.assertEqual(m.build(*args)[1]['certificateCount'],1)

    def test_ambient_ca_environment_is_not_added(self):
        args=self.inputs();before=m.build(*args)[0]
        with patch.dict(os.environ,{'SSL_CERT_FILE':str(self.root/'other.pem'),'SSL_CERT_DIR':str(self.root)}):
            self.assertEqual(m.build(*args)[0],before)

    def test_tampered_mac_is_rejected_by_independent_openssl(self):
        raw=bytearray(m.build(*self.inputs())[0]);raw[-8]^=1
        path=self.root/'tampered.p12';path.write_bytes(raw)
        value=subprocess.run(['openssl','pkcs12','-in',str(path),'-passin','pass:changeit','-nokeys'],capture_output=True)
        self.assertNotEqual(value.returncode,0)

if __name__=='__main__':unittest.main()
