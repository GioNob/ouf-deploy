import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('session_review',ROOT/'scripts/prepare-chatbot-semantic-session-review-20261016.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

def fixture():
    records={'recovery.json':{'state':'CANCELLED','reason':'CANCELLED_BY_OWNER','attempts':59,
        'controlledCumulativeGrantAttempts':69},'owner-admission.json':{'state':'BLOCKED'},
        'owner-session.json':{'private':'DO_NOT_PRINT'},'owner-status.json':{'state':'CANCELLED'}}
    p={'authorization':{'plan':{'selection':{'issuer':'https://issuer.invalid','tenant':'fixture','subject':'human'}}},
       'postGrantWorkerDirectory':'/private/previous','registry':{'creationRequest':{'Env':['SECRET_VALUE']}},
       'owner':{'secretReference':'PRIVATE_REFERENCE'}}
    return p,records

class Tests(unittest.TestCase):
    def compile(self,p,records):
        pins={k:m.digest(v)for k,v in records.items()}
        with patch.object(m,'RETAINED',pins):return m.compile_review(p,records,{'containerId':m.REGISTRY},123)

    def test_finite_review_preserves_history_and_never_authorizes(self):
        p,records=fixture();before=copy.deepcopy(records);r=self.compile(p,records)
        self.assertEqual(before,records)
        b=r['proposedFiniteBudget'];self.assertEqual(b['priorControlledGrantAttempts'],69)
        self.assertEqual(b['maximumCumulativeGrantAttempts'],197)
        self.assertFalse(r['readyForExecution']);self.assertFalse(r['runtimeAuthorityIssued'])
        self.assertFalse(r['humanApprovalGranted']);self.assertIsNone(r['requiredOwnerDecision']['decisionRef'])
        self.assertTrue(r['requiredOwnerDecision']['explicitContinuationAfterOwnerCancellationRequired'])
        self.assertEqual(r['commandKey'],m.COMMAND)
        for secret in ('SECRET_VALUE','PRIVATE_REFERENCE','DO_NOT_PRINT'):self.assertNotIn(secret,json.dumps(r))

    def test_missing_inferred_or_boolean_counter_and_changed_cancellation_block(self):
        for update in ({'controlledCumulativeGrantAttempts':None},{'controlledCumulativeGrantAttempts':True},
            {'controlledCumulativeGrantAttempts':70},{'attempts':58},{'reason':'DIFFERENT_REASON'},{'state':'ACTIVE'}):
            p,records=fixture();records['recovery.json'].update(update)
            with self.assertRaises(m.ReadDenied):self.compile(p,records)

    def test_observed_predecessor_hash_cannot_be_replaced(self):
        p,records=fixture()
        with self.assertRaisesRegex(m.ReadDenied,'PREDECESSOR_RECORD_CHANGED'):
            m.compile_review(p,records,{},123)

    def test_native_exclusive_private_review_and_readback_without_authority(self):
        p,records=fixture();value=self.compile(p,records)
        with tempfile.TemporaryDirectory(dir=ROOT)as tmp:
            with patch.object(m,'CONTEXT',Path(tmp)/'unused-context'):
                first,sha=m.save_review(value);second,_=m.save_review(value)
            self.assertNotEqual(first,second)
            self.assertEqual(first.stat().st_mode&0o777,0o600)
            self.assertEqual(first.parent.stat().st_mode&0o777,0o700)
            self.assertEqual(m.hashlib.sha256(first.read_bytes()).hexdigest(),sha)
            self.assertFalse(json.loads(first.read_bytes())['runtimeAuthorityIssued'])

if __name__=='__main__':unittest.main()
