"""Actual thirteen exports and a real vendor partial multi-platform export."""
import hashlib,io,json,subprocess,sys,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import qualify_m2_retained_image_reader_native as fixture
from tools.m2_discovery_installation_profile import retained_image_reader as reader
from tools.m2_discovery_installation_profile import retained_image_graph as m
from tools.m2_discovery_installation_profile import retained_image_identity as verifier


class NativeGraph(unittest.TestCase):
    fixture_per_role_images=True
    @classmethod
    def setUpClass(cls):fixture.NativeReader.setUpClass.__func__(cls)

    def test_a_original_thirteen_exports_and_seven_input_scopes_are_diagnosed_without_writes_or_engine(self):
        observer=reader.RetainedArchiveReader();seed,rows=observer.material();observer.roots(seed)
        before={str(p):reader.attrs(p.lstat()) for p in self.root.rglob('*')};matches=0
        with patch.object(fixture.producer.socket,'socket',side_effect=AssertionError('NO_ENGINE_OR_NETWORK_DURING_DIAGNOSIS')):
            for role,row in sorted(rows.items()):
                with (observer.path.parent/row['filename']).open('rb') as stream:
                    private,public=m.inspect_graph(stream,row['sha256'],row['imageIdRequested'],row['bytes'],m.VerificationBudget())
                matches+=public['classicMatchesPresentRuntimeManifests']
                self.assertTrue(public['requestedDigestDocumentPresent'])
                self.assertEqual(public['configurationMembersOpened'],0);self.assertEqual(public['layerMembersOpened'],0)
                self.assertFalse(public['missingBlobAdmitted']);self.assertFalse(public['nativeImageByteIdentityProven'])
                self.assertNotIn('PRIVATE_IMAGE',json.dumps(public))
            observer.roots(seed)
        self.assertGreater(matches,0);self.assertEqual(before,{str(p):reader.attrs(p.lstat()) for p in self.root.rglob('*')})
        print(json.dumps({'originalDocker29ExportsDiagnosed':len(rows),'classicRuntimeManifestBindings':matches,
            'newEngineGetsDuringDiagnosis':0,'allInputScopesUnchanged':True,'runtimeAuthorityIssued':False},sort_keys=True))

    def test_b_actual_vendor_export_reproduces_reported_stop_and_classifies_unsaved_platform_manifests(self):
        # Only isolated CI: public version-tag input, retained exact native ID
        # and archive hash. No vendor container is executed or target ID chosen.
        tag='busybox:1.37.0'
        self.command('pull','--platform','linux/amd64',tag)
        self.addCleanup(lambda:self.command('image','rm','-f',tag))
        image=json.loads(self.command('image','inspect',tag))[0]['Id']
        raw=subprocess.run([self.docker,'image','save',image],stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60,check=True).stdout
        archive_sha=hashlib.sha256(raw).hexdigest()
        private,public=m.inspect_graph(io.BytesIO(raw),archive_sha,image,len(raw),m.VerificationBudget())
        self.assertGreater(public['unobservedManifestSubgraphs'],0)
        self.assertTrue(any(v['context']=='INDEX_MEMBER' and v['platformClass']=='EXPLICIT_OTHER_PLATFORM'
            for v in public['missingReferenceGroups']))
        self.assertGreater(public['classicMatchesPresentRuntimeManifests'],0)
        with self.assertRaisesRegex(ValueError,'PRIVATE_IMAGE_BLOB_OR_EXACT_CANONICAL_EMPTY_CONFIG_REQUIRED'):
            verifier.verified_image(io.BytesIO(raw),archive_sha,image,len(raw),verifier.VerificationBudget())
        self.assertFalse(public['missingBlobAdmitted']);self.assertFalse(public['nativeImageByteIdentityProven'])
        print(json.dumps({'actualVendorFixture':'docker.io/library/'+tag,'observedNativeId':image,
            'observedArchiveSha256':archive_sha,'originalCapturedExportBytes':len(raw),
            'diagnosticSummary':public,'targetPrivateCauseProven':False,'reportedStopReproduced':True},sort_keys=True))


if __name__=='__main__':unittest.main()
