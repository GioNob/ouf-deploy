"""Actual offline keytool container qualification on disposable hosted Docker."""
import hashlib,json,os,shutil,subprocess,tempfile,unittest
from pathlib import Path
import merge_public_roots as merge
import prepare_target_trust as target
class OfflineTool(unittest.TestCase):
    def test_real_isolation_public_root_merge_and_cleanup(self):
        self.assertEqual(os.geteuid(),0)
        image=os.environ['OUF_TEST_JAVA_IMAGE_ID']
        with tempfile.TemporaryDirectory(prefix='ouf-java-fixture-',dir='/var/lib') as d:
            root=Path(d);root.chmod(0o700)
            shutil.copyfile(Path(os.environ['JAVA_HOME'])/'lib/security/cacerts',root/'candidate-cacerts')
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(root/'fixture.key'),'-out',str(root/'provider-public-ca.crt'),'-days','2','-subj','/CN=provider-fixture','-addext','basicConstraints=critical,CA:TRUE'],capture_output=True,check=True)
            (root/'fixture.key').unlink()
            report={'toolContainerLifecycleOperations':0,'toolContainerCleanupProven':False}
            def native(args,timeout=30,include_stderr=False):
                p=subprocess.run(['/usr/bin/docker',*args],capture_output=True,timeout=timeout)
                if p.returncode:raise ValueError('NATIVE_FIXTURE_OPERATION_DENIED')
                return p.stdout+(p.stderr if include_stderr else b'')
            result=target.isolated_merge(native,merge,root,image,report)
            self.assertTrue(result['publicRootsPreserved']);self.assertEqual(result['mergedCertificateCount'],result['baselineCertificateCount']+1)
            self.assertTrue(report['toolContainerCleanupProven']);self.assertEqual(report['toolContainerLifecycleOperations'],2)
            os.chown(root/'java-truststore.p12',10001,10001);(root/'java-truststore.p12').chmod(0o400)
            self.assertEqual((root/'java-truststore.p12').stat().st_uid,10001)
            before=(root/'java-truststore.p12').read_bytes()
            with self.assertRaises(ValueError):target.isolated_merge(native,merge,root,image,report)
            self.assertEqual(before,(root/'java-truststore.p12').read_bytes());self.assertTrue(report['toolContainerCleanupProven']);self.assertEqual(report['toolContainerLifecycleOperations'],4)
if __name__=='__main__':unittest.main()
