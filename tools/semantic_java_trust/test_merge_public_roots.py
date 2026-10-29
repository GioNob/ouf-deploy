import os,subprocess,tempfile,unittest
from pathlib import Path
import merge_public_roots as merge
class NativeJava(unittest.TestCase):
    def test_native_public_roots_preserved_added_root_trusted_unknown_denied(self):
        with tempfile.TemporaryDirectory() as d:
            d=Path(d);home=Path(os.environ['JAVA_HOME']);keytool=home/'bin/keytool'
            for name in ('baseline','provider','unknown'):
                subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(d/(name+'.key')),'-out',str(d/(name+'.crt')),'-days','2','-subj','/CN='+name,'-addext','basicConstraints=critical,CA:TRUE'],capture_output=True,check=True)
            merge.run(keytool,['-importcert','-noprompt','-alias','baseline','-file',str(d/'baseline.crt'),'-keystore',str(d/'baseline.jks'),'-storepass','changeit'])
            result=merge.merge(keytool,d/'baseline.jks',d/'provider.crt',d/'merged.p12');self.assertEqual((result['baselineCertificateCount'],result['mergedCertificateCount']),(1,2))
            java='''import java.io.*;import java.security.*;import java.security.cert.*;import javax.net.ssl.*;class TrustCheck{public static void main(String[] a)throws Exception{KeyStore k=KeyStore.getInstance("PKCS12");try(InputStream s=new FileInputStream(a[0])){k.load(s,"changeit".toCharArray());}TrustManagerFactory f=TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());f.init(k);X509TrustManager t=(X509TrustManager)f.getTrustManagers()[0];for(int i=1;i<=3;i++){X509Certificate c;try(InputStream s=new FileInputStream(a[i])){c=(X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(s);}try{t.checkServerTrusted(new X509Certificate[]{c},"RSA");if(i==3)throw new AssertionError("Unknown CA accepted");}catch(CertificateException e){if(i!=3)throw e;}}System.out.println("BASELINE_AND_PROVIDER_TRUSTED_UNKNOWN_DENIED");}}'''
            (d/'TrustCheck.java').write_text(java)
            p=subprocess.run([str(home/'bin/java'),str(d/'TrustCheck.java'),str(d/'merged.p12'),*[str(d/(n+'.crt')) for n in ('baseline','provider','unknown')]],capture_output=True,check=True);self.assertIn(b'BASELINE_AND_PROVIDER_TRUSTED_UNKNOWN_DENIED',p.stdout)
            original=(d/'merged.p12').read_bytes()
            with self.assertRaisesRegex(ValueError,'OUTPUT_EXISTS'):merge.merge(keytool,d/'baseline.jks',d/'provider.crt',d/'merged.p12')
            self.assertEqual(original,(d/'merged.p12').read_bytes())
    def test_private_key_pem_is_rejected_before_store_creation(self):
        with self.assertRaisesRegex(ValueError,'PUBLIC_CERTIFICATES'):merge.certificates(b'-----BEGIN PRIVATE KEY-----secret-----END PRIVATE KEY-----')
if __name__=='__main__':unittest.main()
