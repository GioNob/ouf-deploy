"""Two exact terminal controls plus original seven producer inputs, no replay."""
import contextlib,copy,io,json,sys,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tests/fixtures')]
from retained_image_graph_cases import partial_index
import test_m2_retained_image_reader as fixture
from tools.m2_discovery_installation_profile import retained_image_graph_diagnostic as m
from tools.m2_discovery_installation_profile.custody_capture import attrs


class Control(unittest.TestCase):
    def prepared(self):
        case=fixture.Reader();self.addCleanup(case.doCleanups)
        context=patch.object(fixture,'image_fixture',partial_index);context.start();self.addCleanup(context.stop)
        reader,_,_,root,*_=case.prepared();case.failed_predecessor(m.previous,root,reader)
        profile={**copy.deepcopy(m.previous.PROFILE),'candidateHash':reader.bindings['candidateHash'],
            'captureResultHash':reader.bindings['resultHash']}
        previous=m.Capture(root/'consumed-byte-reconciliation')
        previous.put('image-byte-verification.claim.json',{'schema':'ouf.image-byte-verification-claim.v1',
            'profile':profile,'automaticReplayAllowed':False})
        receipt=json.loads((ROOT/'evidence/m2-image-byte-reconciliation-target-stop-20261101.json').read_bytes())['receipt']
        self.assertEqual(m.digest(receipt),m.FAILED_RESULT_HASH);previous.put('result.json',receipt)
        for mod,name,value in ((m.previous,'PROFILE',profile),(m,'FAILED_SCOPE',previous.scope),
                (m,'PROFILE',{**copy.deepcopy(m.PROFILE),'candidateHash':reader.bindings['candidateHash'],
                    'captureResultHash':reader.bindings['resultHash']}),
                (m,'OUTPUT',root/'image-graph-diagnostic-control'),(sys,'argv',['graph.py'])):
            context=patch.object(mod,name,value);context.start();self.addCleanup(context.stop)
        return reader,root,previous.scope

    def invoke(self):
        output=io.StringIO()
        with contextlib.redirect_stdout(output):code=m.main()
        return code,json.loads(output.getvalue())

    def test_diagnoses_all_thirteen_partial_archives_preserves_nine_scopes_and_never_admits_or_replays(self):
        reader,root,prior=self.prepared();before={str(p):attrs(p.lstat()) for p in root.rglob('*')}
        with patch.object(fixture.producer.socket,'socket',side_effect=AssertionError('NO_ENGINE_OR_NETWORK')):
            code,result=self.invoke()
        self.assertEqual(code,0,result);self.assertEqual(result['imageCount'],13)
        self.assertEqual(result['missingReferences'],26);self.assertEqual(result['cumulativeControlAttempts'],10)
        self.assertEqual(result['cumulativeDirectEngineGets'],35);self.assertTrue(result['allNinePriorScopesPreserved'])
        self.assertEqual(before,{p:attrs(Path(p).lstat()) for p in before})
        for key in ('nativeImageByteIdentityProven','missingBlobAdmitted','verificationReplayed','captureReplayed',
                'publisherTrustAccepted','runtimeAuthorityIssued','targetApplyAuthorized','releaseAcceptance'):
            self.assertIs(result[key],False)
        public=json.dumps(result)
        for private in (str(root),'PRIVATE_TAG','PRIVATE_IMAGE_ENV_VALUE','PRIVATE_IMAGE_VALUE_NEVER_PRINT','image-mcp','sha256:'):
            self.assertNotIn(private,public)
        self.assertEqual((m.OUTPUT/'image-graph-diagnostic.private.json').stat().st_mode&0o777,0o600)
        retained={p.name:p.read_bytes() for p in m.OUTPUT.iterdir()}
        code,again=self.invoke();self.assertEqual(code,1);self.assertIsNone(again['cumulativeControlAttempts'])
        self.assertEqual(retained,{p.name:p.read_bytes() for p in m.OUTPUT.iterdir()})

    def test_both_terminal_results_and_ninth_original_profile_are_required_before_archive_reads(self):
        for kind in ('eighth','ninth','profile','extra'):
            _,root,prior=self.prepared()
            if kind=='eighth':(m.previous.FAILED_SCOPE/'result.json').write_bytes(b'{}')
            elif kind=='ninth':(prior/'result.json').write_bytes(b'{}')
            elif kind=='profile':(prior/'image-byte-verification.claim.json').write_bytes(b'{}')
            else:(prior/'unexpected').touch()
            with patch.object(m,'inspect_graph',side_effect=AssertionError('NO_UNBOUND_ARCHIVE_READ')):
                code,result=self.invoke()
            self.assertEqual(code,1);self.assertEqual(result['cumulativeControlAttempts'],10)
            self.assertFalse((m.OUTPUT/'image-graph-diagnostic.private.json').exists())

    def test_prior_result_drift_during_diagnosis_prevents_private_success_evidence(self):
        _,_,prior=self.prepared();original=m.inspect_graph
        def changed(*args):
            value=original(*args);(prior/'result.json').write_bytes(b'{}');return value
        with patch.object(m,'inspect_graph',changed):code,result=self.invoke()
        self.assertEqual(code,1);self.assertEqual(result['reasonCode'],
            'CONSUMED_GRAPH_PREDECESSOR_CHANGED_DURING_DIAGNOSIS')
        self.assertFalse((m.OUTPUT/'image-graph-diagnostic.private.json').exists())

    def test_unknown_arguments_deny_without_echo_or_new_scope(self):
        _,root,_=self.prepared()
        with patch.object(sys,'argv',['graph.py','PRIVATE_ARGUMENT_SENTINEL']):code,result=self.invoke()
        self.assertEqual(code,1);self.assertNotIn('PRIVATE_ARGUMENT',json.dumps(result));self.assertFalse(m.OUTPUT.exists())


if __name__=='__main__':unittest.main()
