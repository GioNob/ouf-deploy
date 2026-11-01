"""Classify absence without relaxing image verification or opening member bodies."""
import hashlib,io,json,sys,tarfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests/fixtures')]
from retained_image_bytes import fixture,attested_fixture,package
from retained_image_graph_cases import partial_index
from tools.m2_discovery_installation_profile import retained_image_graph as m
from tools.m2_discovery_installation_profile import retained_image_identity as verifier


class Graph(unittest.TestCase):
    def inspect(self,raw,image,budget=None):
        return m.inspect_graph(io.BytesIO(raw),hashlib.sha256(raw).hexdigest(),image,len(raw),budget or m.VerificationBudget())

    def test_same_partial_index_reproduces_reported_verifier_stop_but_diagnosis_is_not_admission(self):
        raw,image,_=partial_index()
        with self.assertRaisesRegex(ValueError,'PRIVATE_IMAGE_BLOB_OR_EXACT_CANONICAL_EMPTY_CONFIG_REQUIRED'):
            verifier.verified_image(io.BytesIO(raw),hashlib.sha256(raw).hexdigest(),image,len(raw),verifier.VerificationBudget())
        private,public=self.inspect(raw,image)
        self.assertEqual(public['missingReferences'],2);self.assertEqual(public['unobservedManifestSubgraphs'],2)
        self.assertEqual(public['classicMatchesPresentRuntimeManifests'],1)
        self.assertEqual({v['platformClass'] for v in public['missingReferenceGroups']},
            {'EXPLICIT_OTHER_PLATFORM','UNKNOWN_NONRUNTIME'})
        for key in ('allReferencedManifestsObserved','missingBlobAdmitted','nativeImageByteIdentityProven',
                'publisherTrustAccepted','runtimeAuthorityIssued','targetApplyAuthorized','releaseAcceptance'):
            self.assertIs(public[key],False)
        self.assertNotIn('PRIVATE_TAG',json.dumps(public));self.assertNotIn('sha256:',json.dumps(public))
        self.assertIn('sha256:',json.dumps(private))

    def test_configuration_and_layer_members_are_never_opened_or_expanded(self):
        raw,image,entries=partial_index();opened=[];original=tarfile.TarFile.extractfile
        forbidden={entries[3][0],entries[4][0]}
        def guarded(archive,row):
            self.assertNotIn(row.name,forbidden);opened.append(row.name);return original(archive,row)
        with patch.object(tarfile.TarFile,'extractfile',guarded):_,public=self.inspect(raw,image)
        self.assertGreater(len(opened),0)
        self.assertEqual(public['configurationMembersOpened'],0);self.assertEqual(public['layerMembersOpened'],0)
        self.assertEqual(public['expandedLayerBytesRead'],0)

    def test_missing_selected_configuration_and_layers_are_reported_with_distinct_context(self):
        for index,context in ((3,'RUNTIME_CONFIG'),(4,'RUNTIME_LAYER')):
            _,image,entries=fixture();raw=package(entries[:index]+entries[index+1:])
            _,public=self.inspect(raw,image)
            self.assertEqual(public['missingReferenceGroups'][0]['context'],context)
            self.assertFalse(public['nativeImageByteIdentityProven']);self.assertFalse(public['missingBlobAdmitted'])

    def test_canonical_empty_presence_is_classified_without_synthesis_or_trust(self):
        raw,image,_=attested_fixture(inline_empty=True,empty_data=False)
        _,public=self.inspect(raw,image)
        self.assertEqual(public['missingReferences'],1)
        row=public['missingReferenceGroups'][0]
        self.assertEqual(row['context'],'ATTESTATION_CONFIG')
        self.assertEqual(row['presenceClass'],'ABSENT_CANONICAL_EMPTY_CONFIG');self.assertFalse(row['inlineDataPresent'])
        self.assertFalse(public['missingBlobAdmitted'])

    def test_complete_oci_and_classic_layouts_remain_diagnostic_only(self):
        for native in (False,True):
            raw,image,_=fixture(native=native);_,public=self.inspect(raw,image)
            self.assertEqual(public['layoutKind'],'OCI' if native else 'CLASSIC')
            self.assertEqual(public['missingReferences'],0);self.assertEqual(public['classicMissingMembers'],0)
            self.assertFalse(public['nativeImageByteIdentityProven'])

    def test_archive_hash_and_present_manifest_digest_tampering_fail(self):
        raw,image,entries=fixture()
        with self.assertRaisesRegex(ValueError,'ARCHIVE_BYTES_CHANGED'):
            m.inspect_graph(io.BytesIO(raw),'0'*64,image,len(raw),m.VerificationBudget())
        entries[2]=(entries[2][0],b'x'*len(entries[2][1]))
        with self.assertRaises((ValueError,UnicodeError)):self.inspect(package(entries),image)

    def test_special_members_unsafe_paths_and_oversized_extensions_deny_before_open(self):
        _,image,entries=fixture();link=tarfile.TarInfo('link');link.type=tarfile.SYMTYPE;link.linkname='/private'
        for extra in ([('link',link)],[('../escape',b'x')],[entries[0]]):
            with self.assertRaises(ValueError):self.inspect(package(entries+extra),image)
        header=tarfile.TarInfo('pax');header.type=tarfile.XHDTYPE;header.size=1048576
        with self.assertRaisesRegex(ValueError,'TAR_HEADER'):self.inspect(header.tobuf()+b'\0'*1024,image)

    def test_deadline_and_document_reference_metadata_limits_are_finite(self):
        raw,image,_=partial_index();budget=m.VerificationBudget();budget.until=0
        with self.assertRaisesRegex(ValueError,'DEADLINE'):self.inspect(raw,image,budget)
        for key in ('maximumReferences','maximumDocuments','maximumMetadataBytesPerImage'):
            with patch.dict(m.GRAPH_LIMITS,{key:1}),self.assertRaises(ValueError):self.inspect(raw,image)


if __name__=='__main__':unittest.main()
