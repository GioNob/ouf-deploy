"""Exact ten-scope diagnostic lineage and bounded new selected-runtime proof."""
import contextlib,copy,io,json,sys,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_m2_retained_image_graph_control as fixture
from tools.m2_discovery_installation_profile import retained_selected_image_verification as m
from tools.m2_discovery_installation_profile.custody_capture import attrs


class SelectedControl(unittest.TestCase):
    def prepared(self):
        case=fixture.Control();self.addCleanup(case.doCleanups)
        reader,root,_=case.prepared()
        output=io.StringIO()
        with contextlib.redirect_stdout(output):self.assertEqual(m.previous.main(),0)
        result=json.loads(output.getvalue());scope=m.previous.OUTPUT
        proof=json.loads((scope/'image-graph-diagnostic.private.json').read_bytes())
        expected={**copy.deepcopy(m.PROFILE),'candidateHash':reader.bindings['candidateHash'],
            'captureResultHash':reader.bindings['resultHash'],'graphResultHash':m.digest(result),
            'graphPrivateEvidenceHash':m.digest(proof)}
        for mod,name,value in ((m,'GRAPH_SCOPE',scope),(m,'GRAPH_RESULT_HASH',m.digest(result)),
                (m,'GRAPH_PROOF_HASH',m.digest(proof)),(m,'PROFILE',expected),
                (m,'OUTPUT',root/'selected-runtime-proof'),(sys,'argv',['selected.py'])):
            context=patch.object(mod,name,value);context.start();self.addCleanup(context.stop)
        return reader,root,scope

    def invoke(self):
        output=io.StringIO()
        with contextlib.redirect_stdout(output):code=m.main()
        return code,json.loads(output.getvalue())

    def test_verifies_thirteen_runtime_contents_preserves_ten_scopes_and_keeps_other_branches_unadmitted(self):
        reader,root,graph=self.prepared();before={str(p):attrs(p.lstat()) for p in root.rglob('*')}
        with patch.object(fixture.fixture.producer.socket,'socket',side_effect=AssertionError('NO_ENGINE_OR_NETWORK')):
            code,result=self.invoke()
        self.assertEqual(code,0,result);self.assertTrue(result['selectedRuntimeBytesProven'])
        self.assertEqual(result['imageCount'],13);self.assertEqual(result['unavailableOtherPlatformManifests'],13)
        self.assertEqual(result['unavailableAuxiliaryManifests'],13);self.assertTrue(result['allTenPriorScopesPreserved'])
        self.assertEqual(result['cumulativeControlAttempts'],11);self.assertEqual(result['cumulativeDirectEngineGets'],35)
        self.assertEqual(before,{p:attrs(Path(p).lstat()) for p in before})
        for key in ('completeIndexAccepted','nonselectedBranchesAdmitted','auxiliaryTrustAccepted',
                'sourcePublisherAuthenticated','allRuntimeArtifactMembershipProven','completePrivateCustodyProven',
                'runtimeAuthorityIssued','targetApplyAuthorized','releaseAcceptance'):
            self.assertIs(result[key],False)
        text=json.dumps(result)
        for private in (str(root),'PRIVATE_TAG','PRIVATE_IMAGE_ENV_VALUE','sha256:','image-mcp'):
            self.assertNotIn(private,text)
        self.assertEqual((m.OUTPUT/'selected-runtime-byte-evidence.private.json').stat().st_mode&0o777,0o600)
        files={p.name:p.read_bytes() for p in m.OUTPUT.iterdir()}
        code,again=self.invoke();self.assertEqual(code,1);self.assertIsNone(again['cumulativeControlAttempts'])
        self.assertEqual(files,{p.name:p.read_bytes() for p in m.OUTPUT.iterdir()})

    def test_diagnostic_result_private_proof_profile_extra_or_old_stop_drift_denies_before_content_verification(self):
        for kind in ('result','private','claim','extra','oldstop'):
            _,_,graph=self.prepared()
            if kind=='oldstop':(m.previous.FAILED_SCOPE/'result.json').write_bytes(b'{}')
            elif kind=='extra':(graph/'unexpected').touch()
            else:
                name={'result':'result.json','private':'image-graph-diagnostic.private.json',
                    'claim':'image-graph-diagnostic.claim.json'}[kind]
                (graph/name).write_bytes(b'{}')
            with patch.object(m,'verified_selected_image',side_effect=AssertionError('NO_UNBOUND_RUNTIME_READ')):
                code,result=self.invoke()
            self.assertEqual(code,1);self.assertEqual(result['cumulativeControlAttempts'],11)
            self.assertFalse((m.OUTPUT/'selected-runtime-byte-evidence.private.json').exists())

    def test_prior_graph_change_during_selected_runtime_read_denies_without_success_file(self):
        _,_,graph=self.prepared();original=m.verified_selected_image
        def changed(*args):
            value=original(*args);(graph/'result.json').write_bytes(b'{}');return value
        with patch.object(m,'verified_selected_image',changed):code,result=self.invoke()
        self.assertEqual(code,1);self.assertEqual(result['reasonCode'],
            'SUCCESSFUL_GRAPH_INPUT_CHANGED_DURING_RUNTIME_VERIFICATION')
        self.assertFalse((m.OUTPUT/'selected-runtime-byte-evidence.private.json').exists())

    def test_mismatched_unavailable_counts_or_private_report_limit_cannot_issue_a_success_proof(self):
        for kind in ('counts','limit'):
            self.prepared();original=m.verified_selected_image
            def wrong(*args):
                value=original(*args);value['unavailableAuxiliaryManifests']+=1;return value
            context=patch.object(m,'verified_selected_image',wrong) if kind=='counts' \
                else patch.dict(m.PROFILE,maximumPrivateEvidenceBytes=1)
            with context:code,result=self.invoke()
            self.assertEqual(code,1);self.assertFalse((m.OUTPUT/'selected-runtime-byte-evidence.private.json').exists())

    def test_unknown_arguments_do_not_create_a_scope_or_echo_private_data(self):
        self.prepared()
        with patch.object(sys,'argv',['selected.py','PRIVATE_SENTINEL']):code,result=self.invoke()
        self.assertEqual(code,1);self.assertNotIn('PRIVATE_SENTINEL',json.dumps(result));self.assertFalse(m.OUTPUT.exists())


if __name__=='__main__':unittest.main()
