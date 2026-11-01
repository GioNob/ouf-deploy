"""Actual seven-stage lineage and original thirteen Docker29 archive bytes."""
import json,sys,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import qualify_m2_retained_image_capture_native as fixture
from tools.m2_discovery_installation_profile import retained_image_capture as producer
from tools.m2_discovery_installation_profile import retained_image_reader as m


class NativeReader(unittest.TestCase):
    fixture_per_role_images=True
    @classmethod
    def setUpClass(cls):
        fixture.NativePrivateImages.setUpClass.__func__(cls)
        c=producer.ImageCapture(cls.root/'captured-native-reader-images')
        result=producer.collect(c);c.put('result.json',result)
        cls.archive_root=c.scope
        record=json.loads((c.scope/'native-image-archives.private.json').read_bytes())
        for name,value in {'CASE':producer.CASE,'ROSTER':producer.ROSTER,
            'CANDIDATE':c.scope/'native-image-archives.private.json',
            'CANDIDATE_HASH':m.digest(record),'RESULT_HASH':m.digest(result)}.items():
            context=patch.object(m,name,value);context.start();cls.addClassCleanup(context.stop)

    def test_a_actual_thirteen_native_image_identities_and_complete_seven_scope_lineage_without_engine_or_writes(self):
        files={str(p):m.attrs(p.lstat()) for p in self.root.rglob('*')}
        with patch.object(producer.socket,'socket',side_effect=AssertionError('NO_ENGINE_OR_NETWORK_DURING_BYTE_READ')):
            private,public=m.RetainedArchiveReader().read_set()
        self.assertEqual(public['imageCount'],13)
        self.assertTrue(public['nativeOrClassicImageByteIdentityProven']);self.assertTrue(public['allSevenInputScopesPreserved'])
        self.assertEqual(public['directEngineGets'],0);self.assertEqual(public['mountedHostFileContentBytesRead'],0)
        self.assertEqual(len({v['requestedImageId'] for v in private['images'].values()}),13)
        for proof in private['images'].values():
            self.assertIn(proof['requestedIdentityKind'],('OCI_MANIFEST','OCI_INDEX','OCI_CONFIGURATION','CLASSIC_CONFIGURATION'))
            self.assertEqual(proof['requestedImageId'],proof['nativeArchiveIdentityDigest']
                if proof['requestedIdentityKind'] in ('OCI_MANIFEST','OCI_INDEX') else proof['configurationDigest'])
            self.assertFalse(proof['sourcePublisherAuthenticated']);self.assertGreater(proof['layerCount'],0)
        for key in ('sourcePublisherAuthenticated','allRuntimeArtifactMembershipProven',
                'currentApplicationConfigurationOrLivenessProven','completePrivateCustodyProven',
                'newCaptureScopeCreated','runtimeAuthorityIssued','targetApplyAuthorized','releaseAcceptance'):
            self.assertIs(public[key],False)
        self.assertEqual(files,{str(p):m.attrs(p.lstat()) for p in self.root.rglob('*')})
        self.assertNotIn(str(self.root),json.dumps(public));self.assertNotIn('NEVER_EMIT',json.dumps(public))

    def test_b_changed_root_engine_generation_denies_before_archive_content(self):
        with patch.object(m,'process_pin',return_value={}),\
                patch.object(m,'verified_image',side_effect=AssertionError('NO_IMAGE_BYTES_WITH_WRONG_GENERATION')):
            with self.assertRaisesRegex(ValueError,'ROOT_ENGINE_GENERATION'):m.RetainedArchiveReader().observe()

    def test_c_extra_scope_member_denies_without_engine_or_archive_content(self):
        path=self.archive_root/'unexpected';path.touch()
        try:
            with patch.object(m,'verified_image',side_effect=AssertionError('NO_UNBOUND_ARCHIVE_BYTES')):
                with self.assertRaisesRegex(ValueError,'EXACT_CONSUMED_PRIVATE_ARCHIVE_SCOPE'):m.RetainedArchiveReader().observe()
        finally:path.unlink()


if __name__=='__main__':unittest.main()
