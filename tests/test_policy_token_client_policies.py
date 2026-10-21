import ast
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools/semantic_policy_token_owner'))
import iam_binding_candidate as guard
spec=importlib.util.spec_from_file_location('client_policy_delivery',ROOT/'scripts/observe-policy-token-client-policies.py')
delivery=importlib.util.module_from_spec(spec);spec.loader.exec_module(delivery)

def load_observer():
    tree=ast.parse(delivery.ROOT_BODY)
    nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in {'observe','output_limit'}
        or isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id in {'HOST_HASH','SNAPSHOT_HASH','CORE'}for t in n.targets)]
    namespace={'guard':guard,'subprocess':subprocess,'tempfile':tempfile,'resource':resource,'time':time,'re':re}
    exec(compile(ast.Module(body=nodes,type_ignores=[]),'qualified-policy-observer','exec'),namespace)
    return namespace['observe']

class ClientPolicyTest(unittest.TestCase):
    def setUp(self):
        self.observe=load_observer();self.client={'id':'11111111-1111-1111-1111-111111111111','clientId':'fixture',
            'enabled':True,'serviceAccountsEnabled':True,'publicClient':False,'clientAuthenticatorType':'client-secret','protocol':'openid-connect'}
        self.responses=[self.client,{'policies':[],'globalPolicies':[{'name':'built-in','enabled':False}]},
            {'profiles':[],'globalProfiles':[{'name':'fixture-profile','executors':[{'executor':'secret-rotation'}]}]}]
        self.calls=[];self.report={'iamMetadataGetAttempts':0}
    def runner(self,argv,**kwargs):
        self.calls.append(argv);self.assertEqual(argv[4],'get');self.assertLessEqual(kwargs['timeout'],15)
        kwargs['stdout'].write(json.dumps(self.responses[len(self.calls)-1]).encode())
        return subprocess.CompletedProcess(argv,0)
    def test_three_exact_gets_include_global_metadata_without_acceptance(self):
        value=self.observe({'client':self.client},self.report,self.runner)
        self.assertEqual(self.report['iamMetadataGetAttempts'],3)
        self.assertIn('include-global-policies=true',self.calls[1]);self.assertIn('include-global-profiles=true',self.calls[2])
        self.assertTrue(self.report['secretRotationExecutorPresentInProfileMetadata'])
        self.assertFalse(value['effectivePolicyApplicabilityProven']);self.assertFalse(value['credentialConsumerScopeProven'])
        self.assertFalse(any('/client-secret'in arg for call in self.calls for arg in call))
    def test_missing_global_metadata_cannot_be_accepted_as_empty(self):
        self.responses[1].pop('globalPolicies')
        with self.assertRaisesRegex(guard.CandidateDenied,'COMPLETE_GLOBAL'):self.observe({'client':self.client},self.report,self.runner)
    def test_core_drift_stops_before_realm_observation(self):
        self.responses[0]={**self.client,'enabled':False}
        with self.assertRaisesRegex(guard.CandidateDenied,'CORE_DRIFT'):self.observe({'client':self.client},self.report,self.runner)
        self.assertEqual(len(self.calls),1)
    def test_failure_is_redacted_without_retry(self):
        def failed(argv,**kwargs):
            self.calls.append(argv);kwargs['stderr'].write(b'Not logged in PRIVATE_TOKEN_NEVER_PRINT')
            return subprocess.CompletedProcess(argv,1)
        with self.assertRaisesRegex(guard.CandidateDenied,'GET_UNAVAILABLE'):self.observe({'client':self.client},self.report,failed)
        self.assertEqual(len(self.calls),1);self.assertIn('SESSION_AUTH_FAILURE_TEXT_OBSERVED',self.report['diagnosticCategories'])
        self.assertNotIn('PRIVATE_TOKEN',json.dumps(self.report))
    def test_existing_portable_gh_and_hash_checked_root_delivery(self):
        raw=(ROOT/'tools/semantic_policy_token_owner/iam_binding_candidate.py').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),delivery.GUARD_SHA)
        with tempfile.TemporaryDirectory(dir=ROOT)as temp:
            home=Path(temp);gh=home/'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh';gh.parent.mkdir(parents=True)
            gh.write_text('fixture');gh.chmod(0o700);calls=[]
            def run(argv,**kwargs):
                calls.append(argv)
                if argv[0]=='sudo':
                    self.assertEqual(kwargs['input'],raw);self.assertEqual(argv[:6],['sudo','--','/usr/bin/python3','-I','-B','-S'])
                    return subprocess.CompletedProcess(argv,0)
                self.assertEqual(argv[0],str(gh));return subprocess.CompletedProcess(argv,0,stdout=base64.b64encode(raw))
            with patch.object(delivery.Path,'home',return_value=home),patch.object(delivery.shutil,'which',return_value=None),\
                patch.object(delivery.subprocess,'run',side_effect=run):self.assertEqual(delivery.main(),0)
            self.assertEqual(len(calls),2)

if __name__=='__main__':unittest.main()
