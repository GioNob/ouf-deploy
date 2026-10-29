import base64
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools/semantic_policy_token_owner'))
import iam_accounting_observation as audit
spec=importlib.util.spec_from_file_location('audit_delivery',ROOT/'scripts/observe-policy-token-owner-accounting.py')
delivery=importlib.util.module_from_spec(spec);spec.loader.exec_module(delivery)

class Reader:
    client='SYNTHETIC_SERVICE_CLIENT'
    def __init__(self,config,events=None,changed=False):self.config=config;self.events=events or {};self.changed=changed;self.calls=[]
    def get(self,path,fields,queries=()):
        self.calls.append((path,fields,queries))
        if path=='events/config':return {**self.config,'eventsEnabled':False}if self.changed and len(self.calls)>1 else copy.deepcopy(self.config)
        kind=queries[-1].split('=')[1];return copy.deepcopy(self.events.get(kind,[]))

class AccountingObservationTest(unittest.TestCase):
    def enabled(self):return {'eventsEnabled':True,'eventsExpiration':3600,'enabledEventTypes':list(audit.EVENT_TYPES)}
    def test_disabled_or_missing_types_preserves_unknown_history_without_event_get(self):
        for cfg in ({'eventsEnabled':False}, {'eventsEnabled':True,'enabledEventTypes':[]}):
            r=Reader(cfg);report={};value=audit.evaluate(r,report)
            self.assertEqual(len(r.calls),1);self.assertIsNone(report['historicalGrantAttemptCount'])
            self.assertFalse(report['historicalAccountingReconciled']);self.assertFalse(value['automaticAccountingInitializationAllowed'])
            self.assertEqual(report['eventSampleCounts'],{})
    def test_bounded_and_empty_samples_are_not_complete_history_or_grant_counters(self):
        r=Reader(self.enabled(),{'CLIENT_LOGIN':[{'time':i,'type':'CLIENT_LOGIN','clientId':Reader.client}for i in range(101)]})
        report={};value=audit.evaluate(r,report)
        self.assertEqual(len(r.calls),4);self.assertEqual(report['eventSampleCounts'],{'CLIENT_LOGIN':100,'CLIENT_LOGIN_ERROR':0})
        self.assertTrue(report['eventSampleTruncated']);self.assertTrue(report['emptyEventSampleIsNotZeroHistoricalUsage'])
        self.assertIsNone(value['historicalGrantAttemptCount']);self.assertFalse(value['completeHistoryCoverageProven'])
        self.assertNotIn(Reader.client,json.dumps(value));self.assertFalse(value['runtimeAuthorityIssued'])
    def test_other_client_type_unbounded_response_or_changed_configuration_denies(self):
        for row in ({'time':1,'type':'CLIENT_LOGIN','clientId':'OTHER'}, {'time':1,'type':'OTHER','clientId':Reader.client}, {'time':True,'type':'CLIENT_LOGIN','clientId':Reader.client}):
            with self.assertRaises(audit.binding.CandidateDenied):audit.evaluate(Reader(self.enabled(),{'CLIENT_LOGIN':[row]}),{})
        with self.assertRaisesRegex(audit.binding.CandidateDenied,'CONFIGURATION_CHANGED'):audit.evaluate(Reader(self.enabled(),changed=True),{})
        with self.assertRaisesRegex(audit.binding.CandidateDenied,'BOUNDED'):audit.evaluate(Reader(self.enabled(),{'CLIENT_LOGIN':[{}]*102}),{})
    def test_only_exact_get_resources_and_session_failure_are_publicly_diagnosed(self):
        report={'iamMetadataGetAttempts':0};r=audit.AuditReader(Reader.client,report);calls=[]
        def denied(argv,**kw):calls.append(argv);kw['stderr'].write(b'Session has expired SYNTHETIC_SECRET');return subprocess.CompletedProcess(argv,1)
        with patch.object(audit.subprocess,'run',side_effect=denied):
            with self.assertRaisesRegex(audit.binding.CandidateDenied,'AUDIT_GET_UNAVAILABLE'):r.get('events/config',audit.CONFIG_FIELDS)
            for path,fields,query in [('client-secret',audit.EVENT_FIELDS,()),('events',audit.EVENT_FIELDS,('client=OTHER','first=0','max=101','type=CLIENT_LOGIN'))]:
                with self.assertRaisesRegex(audit.binding.CandidateDenied,'READ_ONLY'):r.get(path,fields,query)
        self.assertEqual(len(calls),1);self.assertEqual(report['diagnosticCategories'],['SESSION_AUTH_FAILURE_TEXT_OBSERVED'])
        self.assertNotIn('SYNTHETIC_SECRET',json.dumps(report));self.assertEqual(report['iamMetadataGetAttempts'],1)
        self.assertEqual(calls[0][4],'get')
    def test_cli_timeout_is_bounded_and_has_no_automatic_retry(self):
        report={'iamMetadataGetAttempts':0};r=audit.AuditReader(Reader.client,report)
        with patch.object(audit.subprocess,'run',side_effect=subprocess.TimeoutExpired('SYNTHETIC',15))as run:
            with self.assertRaisesRegex(audit.binding.CandidateDenied,'GET_TIMEOUT'):r.get('events/config',audit.CONFIG_FIELDS)
        self.assertEqual(run.call_count,1);self.assertEqual(report['diagnosticCategories'],['CLI_TIMEOUT_OBSERVED'])
    def test_pinned_additional_observer_and_existing_capsule_never_enter_apply(self):
        raw=base64.b64decode(delivery.OBSERVER_SOURCE,validate=True)
        self.assertEqual(raw,(ROOT/'tools/semantic_policy_token_owner/iam_accounting_observation.py').read_bytes())
        self.assertNotIn('entry.main(',delivery.ROOT_BODY);self.assertNotIn("mode='apply'",delivery.ROOT_BODY)
        self.assertIn("review['stdlib']==entry.stdlib_binding()",delivery.ROOT_BODY)
        self.assertIn('historicalGrantAttemptCount',delivery.ROOT_BODY)
        calls=[];capsule=(ROOT/'releases/policy-token-iam-action-source-capsule-20261013.json').read_bytes()
        def run(argv,**kw):
            calls.append(argv)
            if argv[0]=='sudo':
                self.assertEqual(argv[:6],['sudo','--','/usr/bin/python3','-I','-B','-S']);self.assertEqual(kw['input'],capsule)
                self.assertEqual(kw['timeout'],140);return subprocess.CompletedProcess(argv,0)
            return subprocess.CompletedProcess(argv,0,stdout=base64.b64encode(capsule))
        with patch.object(delivery.shutil,'which',return_value='/fixture/gh'),patch.object(delivery.subprocess,'run',side_effect=run):self.assertEqual(delivery.main(),0)
        self.assertEqual(len(calls),2)

if __name__=='__main__':unittest.main()
