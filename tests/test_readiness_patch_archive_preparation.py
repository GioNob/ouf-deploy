"""Actual private files and image byte audits; no Docker/Owner/provider peers."""
import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),
             str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_readiness_patch_execution as fixture
import image_custody
from tools.ingestion_readiness_patch_execution import archive_preparation as a,contract as c,custody

def tar_bytes(entries):
    result=io.BytesIO()
    with tarfile.open(fileobj=result,mode='w') as tar:
        for name,body in entries:
            row=tarfile.TarInfo(name);row.size=len(body);row.mode=0o600;tar.addfile(row,io.BytesIO(body))
    return result.getvalue()

@unittest.skipUnless(os.environ.get('OUF_NATIVE_UIDS')=='1','actual root private file custody required')
class ArchivePreparation(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=os.environ['OUF_TEST_ROOT']);self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.p,review,_=fixture.fixture(self.root);self.addCleanup(self.p.doCleanups)
        self.parent=copy.deepcopy(review['preparedInputs']);self.parent.pop('nativeArchiveAudit')
        candidate=self.parent['candidate'];layer=tar_bytes([]);diff='sha256:'+hashlib.sha256(layer).hexdigest()
        config=c.encoded({'architecture':'amd64','os':'linux','config':candidate['Config'],
                         'rootfs':{'type':'layers','diff_ids':[diff]}})
        image='sha256:'+hashlib.sha256(config).hexdigest();candidate['Id']=image
        candidate['RootFS']={'Type':'layers','Layers':[diff]}
        manifest=c.encoded([{'Config':'configuration.json','RepoTags':['fixture:original'],'Layers':['layer.tar']}])
        original=tar_bytes([('configuration.json',config),('layer.tar',layer),('manifest.json',manifest)])
        source=io.BytesIO(original);audit=image_custody.archive(source,hashlib.sha256(original).hexdigest(),image,'2'*40)
        derived=io.BytesIO();result=image_custody.tagless_archive(source,derived,audit,containerd=True)
        native=image_custody.native_identity(audit)['nativeImageId'];self.expected_archive=derived.getvalue()
        folder=self.root/'retained-parent';folder.mkdir(mode=0o700)
        archive=folder/'image.tar.gz';archive.write_bytes(gzip.compress(original,mtime=0));archive.chmod(0o400)
        binding=a.seal(archive)
        self.parent['candidateFileBindings']['image.tar.gz']=binding
        self.parent['imageImportProfile']['archive']=binding
        self.parent['ingestionFrame']['requestTemplate']['Image']=image
        logical=c.digest({'operation':'INGESTION_READINESS_WORKLOAD_PATCH',
            'oldContainerId':self.parent['beforeIngestion']['Id'],'candidateImageId':image})
        self.parent['finiteIntentContract']['logicalOperationRef']=logical
        for stage in self.parent['finiteIntentContract']['stages']:
            if stage['name']=='IMPORT_INGESTION_IMAGE':
                stage['intent']={'nativeImageId':image,'archiveSha256':binding['sha256'],'maximumArchiveBytes':binding['metadata'][6]}
            elif stage['name']=='ingestion.CREATE_REPLACEMENT':stage['intent']['requestTemplate']['Image']=image
            elif stage['name']=='ingestion.RENAME_OLD':stage['intent']['retainedName']=self.parent['ingestionFrame']['name']+'-retained-'+logical[:12]
            stage['intentHash']=c.digest(stage['intent'])
        path=folder/'native-inputs.json';path.write_bytes(c.encoded(self.parent));path.chmod(0o400)
        self.case={'schema':a.SCHEMA,'snapshotRoot':str(self.root),'parentInputsPath':str(path),
            'parentInputsHash':c.digest(self.parent),'originalCompressedArchiveSha256':binding['sha256'],
            'configurationImageId':image,'nativeImageId':native,'nativeArchiveSha256':result['derivedArchiveSha256'],
            'sourceCommit':'2'*40,'expectedStageCount':12}
        self.target=self.root/('ingestion-readiness-native-archive-'+c.digest(self.case))
    def test_complete_byte_audited_successor_keeps_parent_and_cumulative_operation(self):
        before=Path(self.case['parentInputsPath']).read_bytes();result=a.prepare(self.case)
        self.assertTrue(result['complete']);self.assertEqual(result['plannedStages'],12)
        self.assertEqual(result['runtimeEffectsDispatched'],0);self.assertEqual(result['oauthRequests'],0)
        self.assertEqual((self.target/'native-image.tar').read_bytes(),self.expected_archive)
        value=custody.read(self.target/'native-inputs.json',result['bundleHash']);c.stages(value)
        self.assertEqual(value['finiteIntentContract']['logicalOperationRef'],self.parent['finiteIntentContract']['logicalOperationRef'])
        self.assertEqual(Path(self.case['parentInputsPath']).read_bytes(),before)
        self.assertEqual(custody.read(self.target/'complete.json'),result)
        self.assertEqual((self.target/'native-image.tar').stat().st_mode&0o777,0o400)
        with patch.object(custody,'read')as read,self.assertRaises(c.Denied):a.prepare(self.case)
        read.assert_not_called()
    def test_native_byte_mismatch_preserves_partial_claim_and_prevents_replay(self):
        self.case['nativeArchiveSha256']='f'*64
        target=self.root/('ingestion-readiness-native-archive-'+c.digest(self.case))
        with self.assertRaises(c.Denied):a.prepare(self.case)
        self.assertTrue((target/'source-image.tar').exists());self.assertFalse((target/'complete.json').exists())
        self.assertTrue(list(self.root.glob('*.claim.json')))
        with patch.object(custody,'read')as read,self.assertRaises(c.Denied):a.prepare(self.case)
        read.assert_not_called()
    def test_changed_original_bytes_or_parent_are_never_accepted(self):
        path=Path(self.parent['candidateFileBindings']['image.tar.gz']['path']);path.chmod(0o600);path.write_bytes(b'foreign');path.chmod(0o400)
        with self.assertRaises(c.Denied):a.prepare(self.case)
        self.assertFalse(self.target.exists())
        other=copy.deepcopy(self.case);other['parentInputsHash']='0'*64
        with self.assertRaises(c.Denied):a.prepare(other)
        self.assertFalse(list(self.root.glob('*.claim.json')))

if __name__=='__main__':unittest.main()
