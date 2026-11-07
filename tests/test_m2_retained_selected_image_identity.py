"""Native/classic/runtime binding and every selected content byte remain exact."""
import ast,hashlib,io,json,sys,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests/fixtures')]
from retained_image_bytes import package
from retained_image_graph_cases import partial_index
from retained_selected_image_cases import classic_bound,changed_partial
from tools.m2_discovery_installation_profile import retained_selected_image_identity as m
from tools.m2_discovery_installation_profile import retained_image_identity as old
PLATFORM={'os':'linux','architecture':'amd64'}


class Selected(unittest.TestCase):
    def verify(self,raw,image,platform=PLATFORM,budget=None):
        return m.verified_selected_image(io.BytesIO(raw),hashlib.sha256(raw).hexdigest(),image,len(raw),platform,budget or m.VerificationBudget())

    def test_partial_native_index_requires_exact_classic_binding_and_does_not_admit_unavailable_branches(self):
        raw,image,_=partial_index();proof=self.verify(raw,image)
        self.assertEqual(proof['requestedNativeDigest'],image)
        self.assertEqual(proof['unavailableOtherPlatformManifests'],1)
        self.assertEqual(proof['unavailableAuxiliaryManifests'],1)
        self.assertTrue(proof['selectedRuntimeContentComplete']);self.assertTrue(proof['selectedRuntimeBytesProven'])
        for key in ('completeIndexAccepted','nonselectedBranchesAdmitted','auxiliaryTrustAccepted',
                'sourcePublisherAuthenticated','scanAdmissionProven','runtimeAuthorityIssued','targetApplyAuthorized','releaseAcceptance'):
            self.assertIs(proof[key],False)
        self.assertNotIn('PRIVATE_IMAGE_ENV_VALUE',json.dumps(proof));self.assertNotIn('PRIVATE_TAG',json.dumps(proof))

    def test_complete_native_and_buildkit_inputs_keep_frozen_config_and_layer_proof_values(self):
        for options in ({},{'compressed':False},{'attested':True},{'attested':True,'modern':False}):
            raw,image,_=classic_bound(**options);proof=self.verify(raw,image)
            previous=old.verified_image(io.BytesIO(raw),hashlib.sha256(raw).hexdigest(),image,len(raw),old.VerificationBudget())
            for key in ('configurationDigest','layersHash','layerCount','executionConfigurationHash','expandedBytes'):
                self.assertEqual(proof[key],previous[key])
            self.assertEqual(proof['selectedRuntimeManifestDigest'],previous['nativeManifestDigest'])

    def test_selected_layer_digest_expansion_and_compression_checks_are_reused_verbatim(self):
        def loop(path):
            tree=ast.parse(path.read_bytes())
            fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name.startswith('verified_'))
            with_tar=next(n for n in fn.body if isinstance(n,ast.With))
            item=next(n for n in with_tar.body if isinstance(n,ast.For) and isinstance(n.target,ast.Tuple)
                and any(isinstance(v,ast.Name) and v.id=='expected' for v in ast.walk(n.target)))
            return ast.dump(item,include_attributes=False)
        directory=ROOT/'tools/m2_discovery_installation_profile'
        self.assertEqual(loop(directory/'retained_selected_image_identity.py'),loop(directory/'retained_image_identity.py'))

    def test_missing_selected_config_layer_or_manifest_is_not_an_excludable_sibling(self):
        _,image,entries=classic_bound()
        classic=json.loads(dict(entries)['manifest.json'])[0]
        for name in (classic['Config'],classic['Layers'][0],next(k for k,v in entries if k=='blobs/sha256/'+image[7:])):
            changed=[(k,v) for k,v in entries if k!=name]
            with self.subTest(member=name),self.assertRaises(ValueError):self.verify(package(changed),image)

    def test_changed_config_or_layer_bytes_fail_even_after_outer_archive_rehash(self):
        _,image,entries=classic_bound();classic=json.loads(dict(entries)['manifest.json'])[0]
        for name in (classic['Config'],classic['Layers'][0]):
            changed=[(k,(v[:-1]+bytes([v[-1]^1])) if k==name else v) for k,v in entries]
            with self.subTest(member=name),self.assertRaises((ValueError,OSError,EOFError)):self.verify(package(changed),image)

    def test_config_diff_id_must_equal_the_expanded_selected_layer(self):
        raw,image,_=classic_bound(bad_diff=True)
        with self.assertRaisesRegex(ValueError,'DIFF_ID_CHANGED'):self.verify(raw,image)

    def test_missing_same_platform_unknown_unmarked_wrong_aux_target_index_or_duplicate_denies(self):
        for kind in ('same_platform','unknown_unmarked','unknown_target','missing_index','untyped_platform','duplicate'):
            raw,image,_=changed_partial(kind)
            with self.subTest(kind=kind),self.assertRaises(ValueError):self.verify(raw,image)

    def test_only_the_exact_present_requested_native_digest_can_select_a_runtime(self):
        raw,image,_=partial_index()
        for wanted in ('sha256:'+'f'*64,'sha256:'+'a'*64):
            with self.assertRaisesRegex(ValueError,'REQUESTED_NATIVE_DOCUMENT'):self.verify(raw,wanted)
        with self.assertRaisesRegex(ValueError,'PLATFORM'):self.verify(raw,image,{'os':'linux','architecture':'arm64'})

    def test_classic_ambiguity_or_mismatch_and_missing_classic_manifest_denies(self):
        _,image,entries=partial_index();classic=json.loads(dict(entries)['manifest.json'])
        for new in (classic+classic,[{**classic[0],'Layers':[]}],None):
            changed=[(k,v) for k,v in entries if k!='manifest.json']
            if new is not None:changed.append(('manifest.json',json.dumps(new).encode()))
            with self.assertRaises(ValueError):self.verify(package(changed),image)

    def test_archive_hash_deadline_and_expansion_budgets_remain_finite(self):
        raw,image,_=partial_index()
        with self.assertRaisesRegex(ValueError,'ARCHIVE_BYTES_CHANGED'):
            m.verified_selected_image(io.BytesIO(raw),'0'*64,image,len(raw),PLATFORM,m.VerificationBudget())
        budget=m.VerificationBudget();budget.until=0
        with self.assertRaisesRegex(ValueError,'DEADLINE'):self.verify(raw,image,budget=budget)
        with patch.dict(m.LIMITS,maximumExpandedImageBytes=1),self.assertRaises(ValueError):self.verify(raw,image)


if __name__=='__main__':unittest.main()
