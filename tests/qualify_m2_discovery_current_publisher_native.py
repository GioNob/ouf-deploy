"""Real gh/Sigstore verification with no network namespace or credentials.

Only a disposable CI artifact is attested by the workflow. Real current parent
crypto/custody wraps its actual bundle/trust roots. No target package is admitted.
"""
import copy,os,stat,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_m2_discovery_current_publisher as fixtures
from tools.m2_discovery_installation_profile import current_publisher as m


class NativePublisher(unittest.TestCase):
    def prepared(self,change=None,wrong_id=False):
        if os.geteuid()!=0 or os.environ.get('GITHUB_ACTIONS')!='true':raise AssertionError('DISPOSABLE_HOSTED_PUBLISHER_CI_ONLY')
        case=fixtures.Publisher();case.setUp();self.addCleanup(case.doCleanups)
        old,_,_=case.prepared();root=Path(os.environ['OUF_PUBLISHER_FIXTURE_ROOT'])
        inputs=copy.deepcopy(old.inputs);row=inputs['artifacts'][0]
        for key,name in (('subject','artifact.bin'),('bundle','bundle.json')):
            source=root/name;path=case.root/name;case.write(path,source.read_bytes())
            if change==key:path.write_bytes(b'corrupt-disposable-'+key.encode())
            row[key]=fixtures.ref(path,8388608)
        inputs['trustedRoot']=fixtures.ref(root/'trusted-root.jsonl',1048576)
        inputs['ghExecutable']=fixtures.ref(Path(os.environ['OUF_GH_PUBLISHER_BINARY']),134217728)
        row.update(repository=os.environ['OUF_GITHUB_REPOSITORY'],repositoryId=os.environ['OUF_GITHUB_REPOSITORY_ID'],
            ownerId=os.environ['OUF_GITHUB_OWNER_ID'],sourceRef=os.environ['OUF_GITHUB_SOURCE_REF'],
            sourceCommit=os.environ['OUF_GITHUB_SOURCE_SHA'],signerCommit=os.environ['OUF_GITHUB_SIGNER_SHA'])
        if wrong_id:row['repositoryId']='1'
        runtime=copy.deepcopy(old.runtime_inputs);runtime.pop('additionalInputsHashes');runtime['schema']=fixtures.cohort.m.INPUT_SCHEMA
        runtime=m.bind_publisher_inputs(runtime,inputs);review=copy.deepcopy(case.review)
        review['components']['cohortInstallation']['currentAdmission']=copy.deepcopy(
            review['components']['cohortInstallation']['currentAdmission']['requirements'])
        case.review=fixtures.cohort.m.bind_runtime_review(review,runtime);parent=case.authority(seconds=300)
        reader=m.CurrentPublisherCustody(parent,runtime,inputs)
        # Fixture diagnosis only: never relax the production ancestry guard.
        # This exposes only public path/uid/mode metadata, never signatures or
        # credentials, if the hosted runner's preinstalled directory differs.
        for _,selected in reader.files():
            for path in Path(selected['path']).parents:
                info=path.lstat()
                if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:
                    raise AssertionError('NATIVE_PUBLISHER_FIXTURE_ANCESTRY '+str(path)+' uid='+str(info.st_uid)+' mode='+oct(stat.S_IMODE(info.st_mode)))
        return reader

    def test_real_offline_hosted_publisher_certificate_and_immutable_repository_ids(self):
        reader=self.prepared();first=reader.observe();self.assertEqual(reader.observe(),first)
        self.assertTrue(first['selectedArtifactPublisherCryptographyVerified'])
        self.assertTrue(first['exactCertificateRepositoryIdsAndWorkflowVerified'])
        self.assertFalse(first['targetOciOrMigrationArtifactMembershipProvenHere']);self.assertFalse(first['fullCohortProven'])
        self.assertFalse(first['runtimeAuthorityIssued']);self.assertEqual(first['runtimeSignaturesIssued'],0)

    def test_actual_crypto_denies_modified_bundle_and_modified_artifact_without_repair(self):
        for changed in ('bundle','subject'):
            reader=self.prepared(change=changed);row=reader.inputs['artifacts'][0];path=Path(row[changed]['path']);before=path.read_bytes()
            with self.subTest(changed=changed),self.assertRaisesRegex(ValueError,'OFFLINE_PUBLISHER_CRYPTOGRAPHY_UNPROVEN'):reader.observe()
            self.assertEqual(path.read_bytes(),before);self.assertIsNone(reader.cache)

    def test_real_valid_signature_does_not_override_wrong_reviewed_repository_id(self):
        reader=self.prepared(wrong_id=True)
        with self.assertRaisesRegex(ValueError,'CERTIFICATE_IDENTITY'):reader.observe()
        self.assertIsNone(reader.cache)

if __name__=='__main__':unittest.main()
