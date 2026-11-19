"""Content-addressed archive checks with inert real tar/gzip bytes."""
import hashlib,io,json,sys,tarfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests/fixtures')]
from retained_image_bytes import fixture,attested_fixture,package,encoded,address,original_delivered_verifier
from tools.m2_discovery_installation_profile import retained_image_identity as m


class ImageBytes(unittest.TestCase):
    def verify(self,raw,image,budget=None):
        return m.verified_image(io.BytesIO(raw),hashlib.sha256(raw).hexdigest(),image,len(raw),budget or m.VerificationBudget())

    def test_real_tar_and_gzip_native_and_classic_identity_without_source_or_runtime_admission(self):
        for native in (False,True):
            for compressed in (False,True):
                raw,image,_=fixture(native=native,compressed=compressed)
                proof=self.verify(raw,image)
                self.assertEqual(proof['requestedImageId'],image);self.assertEqual(proof['layerCount'],1)
                self.assertTrue(proof['nativeOrClassicImageByteIdentityProven'])
                self.assertEqual(proof['nativeManifestDigest'],image if native else None)
                for key in ('sourcePublisherAuthenticated','scanAdmissionProven','runtimeAuthorityIssued',
                        'targetApplyAuthorized','releaseAcceptance'):self.assertIs(proof[key],False)
                self.assertNotIn('PRIVATE_IMAGE',json.dumps(proof))

    def test_archive_hash_size_and_requested_identity_are_required(self):
        raw,image,_=fixture()
        cases=[('0'*64,image,len(raw)),(hashlib.sha256(raw).hexdigest(),image,len(raw)+1),
            (hashlib.sha256(raw).hexdigest(),'sha256:'+'e'*64,len(raw))]
        for sha,identity,size in cases:
            with self.subTest(case=sha+identity),self.assertRaises(ValueError):
                m.verified_image(io.BytesIO(raw),sha,identity,size,m.VerificationBudget())

    def test_outer_links_paths_duplicate_and_special_members_are_rejected_without_extraction(self):
        raw,image,entries=fixture()
        link=tarfile.TarInfo('link');link.type=tarfile.SYMTYPE;link.linkname='/must-not-read'
        fifo=tarfile.TarInfo('fifo');fifo.type=tarfile.FIFOTYPE
        for extra in ([('../escape',b'x')],[('/absolute',b'x')],[('link',link)],[('fifo',fifo)],[entries[0]]):
            with self.subTest(extra=extra[0][0]),self.assertRaises(ValueError):self.verify(package(entries+extra),image)

    def test_manifest_configuration_and_layer_tampering_denies_even_with_new_outer_hash(self):
        _,image,entries=fixture()
        for index in (2,3,4):
            changed=list(entries);name,body=changed[index];changed[index]=(name,body+b' ')
            with self.subTest(member=index),self.assertRaises((ValueError,EOFError,OSError)):
                self.verify(package(changed),image)

    def test_rehashed_manifest_and_config_still_require_expanded_diff_id_equality(self):
        for native in (False,True):
            raw,image,_=fixture(native=native,bad_diff=True)
            with self.assertRaisesRegex(ValueError,'DIFF_ID_CHANGED'):self.verify(raw,image)

    def test_expansion_member_and_deadline_limits_are_finite(self):
        raw,image,_=fixture()
        with patch.dict(m.LIMITS,maximumExpandedImageBytes=1024),self.assertRaises(ValueError):self.verify(raw,image)
        with patch.dict(m.LIMITS,maximumMembers=1),self.assertRaises(ValueError):self.verify(raw,image)
        budget=m.VerificationBudget();budget.until=0
        with self.assertRaisesRegex(ValueError,'DEADLINE'):self.verify(raw,image,budget)

    def test_multiple_classic_images_and_wrong_oci_media_are_rejected(self):
        _,image,entries=fixture(native=False);manifest=json.loads(entries[0][1])
        changed=[(entries[0][0],json.dumps(manifest+manifest).encode()),*entries[1:]]
        with self.assertRaises(ValueError):self.verify(package(changed),image)
        _,image,entries=fixture();index=json.loads(entries[1][1]);index['manifests'][0]['mediaType']='application/json'
        entries[1]=(entries[1][0],json.dumps(index).encode())
        with self.assertRaises(ValueError):self.verify(package(entries),image)

    def test_compressed_layers_share_a_cumulative_set_budget(self):
        raw,image,_=fixture();budget=m.VerificationBudget()
        with patch.dict(m.LIMITS,maximumExpandedSetBytes=15000):
            self.verify(raw,image,budget)
            with self.assertRaisesRegex(ValueError,'EXPANDED_PRIVATE_IMAGE_SET'):self.verify(raw,image,budget)

    def test_native_index_and_configuration_addresses_have_distinct_exact_evidence(self):
        raw,image,entries=fixture()
        config=next(name for name,body in entries if name.startswith('blobs/') and b'"rootfs"' in body)
        proof=self.verify(raw,'sha256:'+config.rsplit('/',1)[1])
        self.assertEqual(proof['requestedIdentityKind'],'OCI_CONFIGURATION')
        self.assertIsNone(proof['nativeArchiveIdentityDigest']);self.assertEqual(proof['nativeManifestDigest'],image)
        index_raw=entries[1][1];root=address(index_raw)
        outer=encoded({'schemaVersion':2,'manifests':[{'mediaType':'application/vnd.oci.image.index.v1+json',
            'digest':root,'size':len(index_raw)}]})
        changed=[entries[0],('index.json',outer),*entries[2:],('blobs/sha256/'+root[7:],index_raw)]
        proof=self.verify(package(changed),root)
        self.assertEqual(proof['requestedIdentityKind'],'OCI_INDEX')
        self.assertEqual(proof['nativeArchiveIdentityDigest'],root);self.assertEqual(proof['nativeManifestDigest'],image)

    def test_oversized_pax_extension_is_denied_before_metadata_allocation(self):
        _,image,entries=fixture();header=tarfile.TarInfo('pax');header.type=tarfile.XHDTYPE;header.size=1048576
        raw=header.tobuf()+b'\0'*1024
        with self.assertRaisesRegex(ValueError,'TAR_HEADER'):self.verify(raw,image)

    def test_buildkit_modern_and_legacy_attestations_are_byte_checked_without_trusting_them(self):
        for modern,inline in ((True,False),(True,True),(False,False)):
            raw,image,_=attested_fixture(modern=modern,inline_empty=inline)
            proof=self.verify(raw,image)
            self.assertEqual(proof['requestedIdentityKind'],'OCI_INDEX')
            self.assertEqual(proof['auxiliaryAttestationCount'],1)
            self.assertFalse(proof['auxiliaryAttestationTrustAccepted']);self.assertFalse(proof['sourcePublisherAuthenticated'])
            self.assertNotIn('PRIVATE_ATTESTATION_BODY',json.dumps(proof))

    def test_changed_attestation_blob_subject_or_platform_denies(self):
        for option in ('bad_blob','wrong_subject','wrong_platform'):
            raw,image,_=attested_fixture(**{option:True})
            with self.subTest(option=option),self.assertRaises(ValueError):self.verify(raw,image)

    def test_canonical_empty_config_accepts_optional_data_and_reports_omitted_bytes_explicitly(self):
        for present in (False,True):
            for data in (False,True):
                raw,image,_=attested_fixture(inline_empty=not present,empty_data=data)
                proof=self.verify(raw,image)
                self.assertEqual(proof['canonicalEmptyAttestationConfigsReconstructed'],int(not present))
                self.assertEqual(proof['canonicalEmptyAttestationConfigsWithoutInlineData'],int(not present and not data))
                self.assertFalse(proof['missingNonemptyBlobAccepted'])
                self.assertFalse(proof['auxiliaryAttestationTrustAccepted'])

    def test_exact_consumed_verifier_reproduces_the_reported_stop_on_optional_data_omission(self):
        raw,image,_=attested_fixture(inline_empty=True,empty_data=False)
        old=original_delivered_verifier(ROOT)
        with self.assertRaisesRegex(ValueError,'PRIVATE_IMAGE_BLOB_OR_EXACT_INLINE_EMPTY_CONFIG_REQUIRED'):
            old.verified_image(io.BytesIO(raw),hashlib.sha256(raw).hexdigest(),image,len(raw),old.VerificationBudget())
        self.assertEqual(self.verify(raw,image)['canonicalEmptyAttestationConfigsWithoutInlineData'],1)

    def test_missing_empty_config_requires_exact_digest_size_media_and_optional_data(self):
        for change in ({'digest':'sha256:'+'a'*64},{'size':3},{'size':True},
                {'mediaType':'application/vnd.oci.image.config.v1+json'},
                {'data':'e30=\n'},{'data':None},{'data':'e10='}):
            raw,image,_=attested_fixture(inline_empty=True,empty_config_patch=change)
            with self.subTest(change=change),self.assertRaises(ValueError):self.verify(raw,image)

    def test_missing_runtime_config_layer_or_manifest_is_never_reconstructed_from_inline_data(self):
        for index in (2,3,4):
            _,image,entries=fixture();name,raw=entries[index]
            # Each of these is a real nonempty referenced blob; no remote lookup.
            with self.subTest(member=name),self.assertRaises(ValueError):
                self.verify(package(entries[:index]+entries[index+1:]),image)

    def test_present_empty_config_blob_is_verified_even_when_optional_data_is_absent(self):
        _,image,entries=attested_fixture(empty_data=False)
        name='blobs/sha256/'+m.EMPTY_DIGEST[7:]
        changed=[(key,b'[]' if key==name else raw) for key,raw in entries]
        with self.assertRaisesRegex(ValueError,'DIGEST_DIFFERS'):self.verify(package(changed),image)


if __name__=='__main__':unittest.main()
