import ast
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('correlated_diag',ROOT/'scripts/probe-registry-correlated403-20261023.py')
d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)

class Classifications(unittest.TestCase):
    def response(self,headers=None):
        class Response:
            def getheader(self,k):return (headers or{}).get(k)
        return Response()
    def test_registry_capability_problem_not_mistaken_for_specific_permission_root_cause(self):
        value={'code':'SEM_CAPABILITY_REQUIRED:ouf.semantic.read','type':'urn:ouf:error:SEM_CAPABILITY_REQUIRED:ouf.semantic.read','correlationId':'fixture-request'}
        r=d.classify_origin(self.response({'X-Correlation-Id':'fixture-request'}),json.dumps(value).encode(),'fixture-request')
        self.assertEqual(r['problemClass'],'SEM_CAPABILITY_REQUIRED');self.assertTrue(r['registryProblemShape'])
        self.assertTrue(r['problemCorrelationMatchesRequest']);self.assertNotIn('NO_POLICY_BUNDLE',str(r))
    def test_gateway_expired_text_is_only_text_classification(self):
        r=d.classify_origin(self.response({'Server':'APISIX/fixture'}),b'{"message":"JWT token is expired","private":"never print"}','fixture-request')
        self.assertEqual(r['messageClass'],'TOKEN_EXPIRY_TEXT');self.assertFalse(r['registryProblemShape'])
        self.assertEqual(r['serverHeaderClass'],'APISIX');self.assertNotIn('never print',str(r))
    def test_untrusted_body_cannot_print_arbitrary_code(self):
        r=d.classify_origin(self.response(),b'{"code":"secret-value","message":"private-value"}','fixture')
        self.assertEqual(r['problemClass'],'OTHER_OR_UNCLASSIFIED');self.assertNotIn('secret-value',str(r));self.assertNotIn('private-value',str(r))
    def test_html_body_does_not_crash_or_become_registry_problem(self):
        r=d.classify_origin(self.response(),b'<html>private</html>','fixture');self.assertFalse(r['registryProblemShape'])
    def test_classifier_source_is_identical_to_parent_function(self):
        ns={'json':json};exec(d.CLASSIFIER_SOURCE,ns)
        response=self.response();body=b'{"code":"SEM_AUTHENTICATION_REQUIRED"}'
        self.assertEqual(ns['classify_origin'](response,body,'fixture'),d.classify_origin(response,body,'fixture'))
    def test_exact_sealed_transport_transformation_preserves_tls_and_get_only(self):
        modules=d.sealed_native_modules((ROOT/'releases/semantic-registry-checkpoint-successor-20261023.py').read_bytes())
        original=d.sys.modules['tools.semantic_registry_recovery_execution.semantic_request'].CHILD_SOURCE
        changed=d.attribution_child(original);compile(changed,'<fixture-child>','exec')
        self.assertEqual(changed.count("client.request('GET',"),1);self.assertNotIn("client.request('POST'",changed)
        self.assertIn('context=ssl.create_default_context(cadata=',changed)
        self.assertIn('getpeercert(binary_form=True)',changed);self.assertIn('os.setns(fd,0)',changed)
        self.assertIn("'X-Correlation-ID':request_id",changed);self.assertIn('classify_origin(response,body,request_id)',changed)
        self.assertIn('lookup',changed)
    def test_unrecognized_transport_source_cannot_be_patched(self):
        with self.assertRaisesRegex(ValueError,'EXACT_SEALED_GET_TRANSPORT_TRANSFORM_REQUIRED'):d.attribution_child('unreviewed source')
    def test_second_scope_binds_prior403_and_refuses_replay(self):
        with tempfile.TemporaryDirectory()as tmp:
            root=Path(tmp);prior=root/'prior';prior.mkdir();scope=root/'new'
            previous={'schema':'ouf.semantic-registry-current-caller-get-observation.v1','httpStatus':403,'httpRequests':1,
                      'retainedControlledGrantAttempts':321,'nativeRecoveryJournalCompleted':False}
            (prior/'result.json').write_bytes(d.encoded(previous))
            with patch.object(d,'PRIOR_DIAGNOSTIC_ROOT',str(prior)),patch.object(d,'DIAGNOSTIC_ROOT',str(scope)):
                d.claim_diagnostic(d.Reader());claim=json.loads((scope/'claim.json').read_bytes())
                self.assertEqual(claim['maximumCombinedDiagnosticHttpGetAttempts'],2)
                self.assertEqual(claim['priorDiagnosticResultHash'],d.digest(previous))
                with self.assertRaisesRegex(ValueError,'CURRENT_CALLER_GET_ALREADY_CLAIMED_NO_REPLAY'):d.claim_diagnostic(d.Reader())
    def test_non403_predecessor_cannot_allocate_second_get(self):
        class Reader:
            def json(self,*a,**kw):return {'schema':'wrong'}
        with self.assertRaisesRegex(ValueError,'EXACT_RETAINED_FIRST_DIAGNOSTIC403_REQUIRED'):d.claim_diagnostic(Reader())

if __name__=='__main__':unittest.main()
