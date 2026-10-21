"""Authenticate exact retained artifact and realize its tagless identity in CI."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('private_packet',ROOT/'scripts/prepare-ingestion-rollout-packet-20261020.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

def command(args):return subprocess.run(args,check=True,capture_output=True,timeout=180).stdout

class ExactCandidate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        info=json.loads(command(['docker','info','--format','{{json .}}']))
        assert info['ServerVersion']=='29.8.1'and info['Driver']=='overlayfs'
        assert ['driver-type','io.containerd.snapshotter.v1']in info['DriverStatus']
        cls.context=tempfile.TemporaryDirectory(prefix='ouf-exact-private-packet-')
        cls.addClassCleanup(cls.context.cleanup)
        with open(os.environ['OUF_CANDIDATE_ZIP'],'rb')as stream:
            cls.proof=m.authenticate_candidate(stream,Path(cls.context.name))

    def test_actual_retained_zip_rootfs_jar_and_exact18_sql_bytes(self):
        candidate=self.proof
        self.assertEqual(candidate['package']['zipSha256'],m.package.ZIP_SHA)
        self.assertEqual(candidate['jar']['migrationCount'],18)
        self.assertEqual(candidate['jar']['jarSha256'],candidate['package']['files']['application.jar']['sha256'])
        self.assertEqual(candidate['originalImageAudit']['imageId'],m.package.IMAGE)
        self.assertFalse(candidate['taglessEnvelope']['imageRebuilt'])

    def test_actual_tagless_candidate_loads_with_manifest_identity_and_same_bytes(self):
        audit=self.proof['nativeImageAudit'];image=m.custody.runtime_image_id(audit)
        self.assertNotEqual(image,m.package.IMAGE)
        command(['docker','load','-i',self.proof['nativeArchivePath']])
        native=json.loads(command(['docker','image','inspect',image]))[0]
        proof=m.custody.loaded(audit,native)
        self.assertTrue(proof['imageByteCustodyProven']);self.assertFalse(proof['targetApplyAuthorized'])
        self.assertEqual(native.get('RepoTags')or[],[])
        self.assertEqual(native['Config']['User'],'10002:10002')
        print('CI_NATIVE_IMAGE_ID='+image,flush=True)
        print('CI_TAGLESS_ARCHIVE_SHA256='+self.proof['taglessEnvelope']['derivedArchiveSha256'],flush=True)

if __name__=='__main__':unittest.main()
