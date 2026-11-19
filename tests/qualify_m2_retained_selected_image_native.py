"""Actual Docker29 bytes: original thirteen, real partial vendor and denials."""
import hashlib,io,json,subprocess,sys,tarfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tests/fixtures')]
import qualify_m2_retained_image_graph_native as fixture
from retained_image_bytes import package
from tools.m2_discovery_installation_profile import retained_image_reader as reader
from tools.m2_discovery_installation_profile import retained_image_identity as old
from tools.m2_discovery_installation_profile import retained_selected_image_identity as m
PLATFORM={'os':'linux','architecture':'amd64'}


class NativeSelected(unittest.TestCase):
    fixture_per_role_images=True
    @classmethod
    def setUpClass(cls):
        fixture.NativeGraph.setUpClass.__func__(cls)
        tag='busybox:1.37.0';cls.command('pull','--platform','linux/amd64',tag)
        cls.addClassCleanup(lambda:cls.command('image','rm','-f',tag))
        cls.vendor_image=json.loads(cls.command('image','inspect',tag))[0]['Id']
        cls.vendor_raw=subprocess.run([cls.docker,'image','save',cls.vendor_image],stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60,check=True).stdout

    def test_a_thirteen_actual_original_exports_keep_old_runtime_config_layer_and_manifest_proofs(self):
        observer=reader.RetainedArchiveReader();seed,rows=observer.material();observer.roots(seed)
        before={str(p):reader.attrs(p.lstat()) for p in self.root.rglob('*')};total=0
        with patch.object(fixture.fixture.producer.socket,'socket',side_effect=AssertionError('NO_ENGINE_OR_NETWORK_DURING_BYTE_PROOF')):
            for role,row in sorted(rows.items()):
                raw=(observer.path.parent/row['filename']).read_bytes()
                previous=old.verified_image(io.BytesIO(raw),row['sha256'],row['imageIdRequested'],row['bytes'],old.VerificationBudget())
                proof=m.verified_selected_image(io.BytesIO(raw),row['sha256'],row['imageIdRequested'],row['bytes'],PLATFORM,m.VerificationBudget())
                for key in ('configurationDigest','layersHash','layerCount','executionConfigurationHash','expandedBytes'):
                    self.assertEqual(proof[key],previous[key])
                self.assertEqual(proof['selectedRuntimeManifestDigest'],previous['nativeManifestDigest'])
                self.assertTrue(proof['selectedRuntimeContentComplete']);self.assertFalse(proof['completeIndexAccepted'])
                total+=proof['layerCount']
            observer.roots(seed)
        self.assertEqual(before,{str(p):reader.attrs(p.lstat()) for p in self.root.rglob('*')})
        print(json.dumps({'actualOriginalRuntimeByteProofs':len(rows),'selectedLayers':total,
            'frozenRuntimeProofEquality':True,'allOriginalInputsUnchanged':True,'newEngineGetsDuringVerification':0},sort_keys=True))

    def test_b_real_partial_vendor_export_has_exact_native_classic_runtime_and_all_selected_layer_bytes(self):
        raw,image=self.vendor_raw,self.vendor_image;sha=hashlib.sha256(raw).hexdigest()
        with self.assertRaisesRegex(ValueError,'PRIVATE_IMAGE_BLOB_OR_EXACT_CANONICAL_EMPTY_CONFIG_REQUIRED'):
            old.verified_image(io.BytesIO(raw),sha,image,len(raw),old.VerificationBudget())
        proof=m.verified_selected_image(io.BytesIO(raw),sha,image,len(raw),PLATFORM,m.VerificationBudget())
        self.assertEqual(proof['unavailableOtherPlatformManifests'],8);self.assertEqual(proof['unavailableAuxiliaryManifests'],7)
        self.assertTrue(proof['selectedRuntimeContentComplete']);self.assertGreater(proof['layerCount'],0)
        self.assertFalse(proof['completeIndexAccepted']);self.assertFalse(proof['nonselectedBranchesAdmitted'])
        print(json.dumps({'actualVendorFixture':'docker.io/library/busybox:1.37.0','requestedNativeDigest':image,
            'archiveSha256':sha,'archiveBytes':len(raw),'unavailableOtherPlatformManifests':8,
            'unavailableAuxiliaryManifests':7,'selectedRuntimeBytesVerified':True,'targetPrivateBytesVerified':False},sort_keys=True))

    def test_c_real_vendor_selected_config_and_layer_removal_are_never_sibling_exclusions(self):
        with tarfile.open(fileobj=io.BytesIO(self.vendor_raw),mode='r:') as archive:
            entries=[(row.name,archive.extractfile(row).read()) for row in archive if row.isfile()]
        classic=json.loads(dict(entries)['manifest.json'])[0]
        for missing in (classic['Config'],classic['Layers'][0]):
            raw=package([(k,v) for k,v in entries if k!=missing]);sha=hashlib.sha256(raw).hexdigest()
            with self.assertRaises(ValueError):
                m.verified_selected_image(io.BytesIO(raw),sha,self.vendor_image,len(raw),PLATFORM,m.VerificationBudget())


if __name__=='__main__':unittest.main()
