"""Same eleven preserved scopes, exact consumed proof, no layer/Engine replay."""
import contextlib,copy,hashlib,io,json,sys,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_m2_retained_selected_image_control as fixture
from tools.m2_discovery_installation_profile import retained_runtime_origins as m
from tools.m2_discovery_installation_profile.custody_capture import attrs


class OriginControl(unittest.TestCase):
    def prepared(self):
        case=fixture.SelectedControl();self.addCleanup(case.doCleanups);reader,root,_=case.prepared()
        with contextlib.redirect_stdout(io.StringIO()):self.assertEqual(m.previous.main(),0)
        scope=m.previous.OUTPUT;result=json.loads((scope/'result.json').read_bytes())
        proof=json.loads((scope/'selected-runtime-byte-evidence.private.json').read_bytes())
        public=copy.deepcopy(m.PUBLIC_PROFILE)
        for role,row in public['roles'].items():
            actual=proof['images'][role];row['nativeImageId']=actual['requestedNativeDigest']
            row['configurationDigest']=None if role in public['unknownConfigurationRoles'] else actual['configurationDigest']
            if 'selectedRuntimeManifestDigest' in row:row['selectedRuntimeManifestDigest']=actual['selectedRuntimeManifestDigest']
        rh,ph=m.digest(result),m.digest(proof);public.update(selectedRuntimeResultHash=rh,selectedRuntimePrivateHash=ph)
        profile={**m.PROFILE,'selectedRuntimeResultHash':rh,'selectedRuntimePrivateHash':ph,'publicOriginProfileHash':m.digest(public)}
        for name,value in [('SELECTED_SCOPE',scope),('RESULT_HASH',rh),('PRIVATE_HASH',ph),('PUBLIC_PROFILE',public),
            ('PROFILE_HASH',m.digest(public)),('PROFILE',profile),('OUTPUT',root/'runtime-origin-join')]:
            context=patch.object(m,name,value);context.start();self.addCleanup(context.stop)
        context=patch.object(sys,'argv',['origins.py']);context.start();self.addCleanup(context.stop)
        return reader,root,scope

    def invoke(self):
        output=io.StringIO()
        with contextlib.redirect_stdout(output):code=m.main()
        return code,json.loads(output.getvalue())

    def test_all_thirteen_roles_ten_configs_three_identity_reads_preserve_inputs_and_replay_is_denied(self):
        reader,root,scope=self.prepared();before={str(p):attrs(p.lstat()) for p in root.rglob('*')}
        with patch.object(fixture.fixture.fixture.producer.socket,'socket',side_effect=AssertionError('NO_ENGINE_OR_NETWORK')), \
                patch.object(m.previous,'verified_selected_image',side_effect=AssertionError('NO_BYTE_VERIFICATION_REPLAY')):
            code,result=self.invoke()
        self.assertEqual(code,0,result);self.assertEqual(result['knownPublicConfigurationBindingsMatched'],10)
        self.assertEqual(result['sourceConfigurationMembersOpened'],3);self.assertEqual(result['imageCount'],13)
        self.assertTrue(result['allElevenPriorScopesPreserved']);self.assertEqual(result['cumulativeControlAttempts'],12)
        self.assertEqual(result['cumulativeDirectEngineGets'],35);self.assertEqual(result['layerMembersOpened'],0)
        self.assertEqual(before,{p:attrs(Path(p).lstat()) for p in before})
        self.assertEqual({x['role'] for x in result['unresolvedOriginBindings']},{'gateway-owner','minio','semantic'})
        for key in ('sourcePublisherAuthenticated','allRuntimeArtifactMembershipProven','completePrivateCustodyProven',
            'currentApplicationConfigurationOrLivenessProven','runtimeAuthorityIssued','targetApplyAuthorized','releaseAcceptance'):
            self.assertIs(result[key],False)
        for sentinel in (str(root),'PRIVATE_IMAGE_ENV_VALUE','PRIVATE_TAG','image-mcp.docker.tar'):
            self.assertNotIn(sentinel,json.dumps(result))
        files={p.name:p.read_bytes() for p in m.OUTPUT.iterdir()}
        code,again=self.invoke();self.assertEqual(code,1);self.assertIsNone(again['cumulativeControlAttempts'])
        self.assertEqual(files,{p.name:p.read_bytes() for p in m.OUTPUT.iterdir()})

    def test_changed_result_private_claim_or_extra_member_denies_before_configuration_access(self):
        for kind in ('result.json','selected-runtime-byte-evidence.private.json','selected-runtime-verification.claim.json','extra'):
            with self.subTest(kind=kind):
                _,_,scope=self.prepared();(scope/kind).write_bytes(b'{}')
                with patch.object(m,'config_identity',side_effect=AssertionError('NO_UNBOUND_CONFIG_READ')):code,result=self.invoke()
                self.assertEqual(code,1);self.assertFalse((m.OUTPUT/'runtime-origin.private.json').exists())

    def test_exact_public_native_config_and_selected_manifest_reference_must_match(self):
        for field in ('nativeImageId','configurationDigest','selectedRuntimeManifestDigest'):
            with self.subTest(field=field):
                self.prepared();m.PUBLIC_PROFILE['roles']['apisix'][field]='sha256:'+'0'*64
                # Fixture reseals only the public input to test the semantic join;
                # the deployed source map prevents replacing that public profile.
                with patch.object(m,'PROFILE_HASH',m.digest(m.PUBLIC_PROFILE)),patch.dict(m.PROFILE,publicOriginProfileHash=m.digest(m.PUBLIC_PROFILE)), \
                        patch.object(m,'config_identity',side_effect=AssertionError('NO_UNMATCHED_ORIGIN_READ')):
                    code,result=self.invoke()
                self.assertEqual(code,1);self.assertFalse((m.OUTPUT/'runtime-origin.private.json').exists())

    def test_public_profile_drift_cannot_become_a_new_admitted_configuration(self):
        self.prepared();m.PUBLIC_PROFILE['roles']['mcp']['configurationDigest']='sha256:'+'0'*64
        with patch.object(m,'config_identity',side_effect=AssertionError('NO_DRIFTED_PROFILE_READ')):code,result=self.invoke()
        self.assertEqual(code,1);self.assertEqual(result['reasonCode'],'EXACT_SEALED_PUBLIC_ORIGIN_PROFILE_REQUIRED')

    def test_prior_scope_change_during_source_read_has_no_success_evidence(self):
        _,_,scope=self.prepared();original=m.config_identity
        def drift(*args):
            result=original(*args);(scope/'result.json').write_bytes(b'{}');return result
        with patch.object(m,'config_identity',drift):code,result=self.invoke()
        self.assertEqual(code,1);self.assertEqual(result['reasonCode'],'CONSUMED_SELECTED_RUNTIME_OR_PRIOR_SCOPE_CHANGED_DURING_ORIGIN_JOIN')
        self.assertFalse((m.OUTPUT/'runtime-origin.private.json').exists())

    def test_archive_metadata_drift_is_denied_without_layer_or_configuration_replay(self):
        reader,_,_=self.prepared();_,rows=reader.material();path=reader.path.parent/rows['semantic']['filename'];path.chmod(0o600)
        with patch.object(m,'config_identity',side_effect=AssertionError('NO_CHANGED_ARCHIVE_READ')):code,result=self.invoke()
        self.assertEqual(code,1);self.assertFalse((m.OUTPUT/'runtime-origin.private.json').exists())

    def test_unexpected_label_values_are_redacted_and_declared_claims_do_not_authenticate_publishers(self):
        sentinel='PRIVATE_LABEL_VALUE_NOT_FOR_OUTPUT'
        labels={'org.opencontainers.image.source':sentinel,'org.opencontainers.image.revision':sentinel,'OTHER':sentinel}
        result=m.source_claim('semantic',labels);self.assertNotIn(sentinel,json.dumps(result));self.assertFalse(result['declaredSourceAuthenticated'])
        labels={'org.opencontainers.image.source':m.PUBLIC_PROFILE['sourceLabelAllowlist']['semantic'],
            'org.opencontainers.image.revision':'a'*40}
        result=m.source_claim('semantic',labels);self.assertEqual(result['declaredRevision'],'a'*40);self.assertFalse(result['declaredSourceAuthenticated'])

    def test_extra_arguments_or_expired_deadline_do_not_issue_success(self):
        self.prepared()
        with patch.object(sys,'argv',['origins.py','PRIVATE_ARG']):code,result=self.invoke()
        self.assertEqual(code,1);self.assertNotIn('PRIVATE_ARG',json.dumps(result));self.assertFalse(m.OUTPUT.exists())
        with patch.dict(m.PROFILE,maximumSeconds=0):code,result=self.invoke()
        self.assertEqual(code,1);self.assertFalse((m.OUTPUT/'runtime-origin.private.json').exists())


if __name__=='__main__':unittest.main()
