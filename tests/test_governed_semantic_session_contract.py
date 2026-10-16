"""Pure contract qualification using the exact candidate function bodies.

No imported runtime installation, signatures, IAM or target execution. AST
loading keeps these pure tests independent of the protected deployment loader.
This does not qualify full owner/signature/source-stage composition.
"""
import ast
import copy
import hashlib
import json
from pathlib import Path
import types
import unittest

ROOT=Path(__file__).resolve().parents[1]

def fingerprint(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()

def check(ok,*unused):
    if not ok:raise ValueError('INTEGRITY_UNPROVEN')

def load_contract():
    path=ROOT/'tools/semantic_policy_token_owner/installed_owner.py'
    tree=ast.parse(path.read_text());wanted=[]
    for node in tree.body:
        if isinstance(node,ast.Assign)and any(isinstance(t,ast.Name)and t.id in
            ('GOVERNED_SESSION','GOVERNED_HISTORY')for t in node.targets):wanted.append(node)
        if isinstance(node,ast.FunctionDef)and node.name=='compile_governed_session':wanted.append(node)
    assert len(wanted)==3
    ns={'copy':copy,'fingerprint':fingerprint,'check':check,'Path':Path}
    exec(compile(ast.Module(body=wanted,type_ignores=[]),str(path),'exec'),ns)
    path=ROOT/'tools/semantic_policy_token_owner/supervisor.py'
    tree=ast.parse(path.read_text())
    cls=next(n for n in tree.body if isinstance(n,ast.ClassDef)and n.name=='ScheduledRecovery')
    validate=next(n for n in cls.body if isinstance(n,ast.FunctionDef)and n.name=='validate')
    ns.update(require=check,number=lambda v:type(v)in(int,float)and v>=0)
    exec(compile(ast.Module(body=[validate],type_ignores=[]),str(path),'exec'),ns)
    return ns

C=load_contract()

def fixture():
    policy={'delays':[5,15,60,300,900],'max_attempts':128,'max_elapsed':3600,'attempt_timeout':30,'jitter':.2}
    first={'state':'TOKEN_PUBLISHED_NOT_RUNTIME_ACCEPTED','attemptSlotsConsumed':1,
        'gapRemainsOpen':True,'historicalAccountingReconciled':False,'legacyHistoricalGrantAttempts':None,
        'operation':'1'*64,'scopeHash':'2'*64,'bootId':'fixture-boot'}
    session={'schema':'ouf.policy-token-new-finite-worker-session.v10','predecessorGrantAttempts':10,
        'policy':policy,'contextRef':'3'*64,'generationRef':'4'*64,'logicalOwnerScopeHash':'5'*64,
        'predecessorFirstGrantOperation':first['operation'],'predecessorFirstGrantScopeHash':first['scopeHash']}
    old={'state':'CANCELLED','reason':'CANCELLED_BY_OWNER','attempts':59,
        'controlledPredecessorGrantAttempts':10,'controlledCumulativeGrantAttempts':69,
        'workerSessionHash':fingerprint(session),'policyHash':fingerprint(policy),
        'contextRef':session['contextRef'],'generationRef':session['generationRef'],
        'firstGrantReceiptHash':fingerprint(first),'bootId':'fixture-boot',
        'legacyHistory':{'state':'UNKNOWN','cumulativeGrantAttemptCount':None,'reconciled':False,'gapRemainsOpen':True}}
    records={'recovery.json':old,'owner-session.json':session,'owner-admission.json':{'state':'BLOCKED'},
        'owner-status.json':{'state':'CANCELLED'}}
    review={'schema':'ouf.chatbot-semantic-functional-session-review.v1','readyForExecution':False,
        'runtimeAuthorityIssued':False,'humanApprovalGranted':False,
        'predecessorRecordHashes':{k:fingerprint(v)for k,v in records.items()},
        'proposedFiniteBudget':{'priorControlledGrantAttempts':69,'predecessorWorkerAttempts':59,
            'maximumNewTokenGrantAttempts':128,'maximumCumulativeGrantAttempts':197,'maximumSeconds':3600,
            'renewalIntervalSeconds':60,'automaticRenewalAllowed':False},
        'requiredOwnerDecision':{'explicitContinuationAfterOwnerCancellationRequired':True,
            'freshAuthenticatedHumanDecisionRequired':True,'newJournalAndPersistentFencingRequired':True},
        'predecessorJournalDirectory':'/fixture/session-parent/old-worker',
        'requestedHumanActor':{'issuer':'fixture','tenant':'fixture','subject':'fixture'},
        'commandKey':'stable-command','proposalHash':'6'*64}
    return review,records,first,policy

def compile_fixture(f):return C['compile_governed_session'](*f,'7'*64,'8'*64,60)

class Tests(unittest.TestCase):
    def test_cumulative69_scope_is_explicit_and_predecessors_unchanged(self):
        f=fixture();before=copy.deepcopy(f);scope=compile_fixture(f)
        self.assertEqual(f,before);self.assertEqual(scope['predecessorGrantAttempts'],69)
        self.assertEqual(scope['maximumCumulativeGrantAttempts'],197)
        self.assertFalse(scope['consumedClaimReplayAllowed']);self.assertFalse(scope['automaticBudgetRenewalAllowed'])
        self.assertEqual(scope['commandKey'],'stable-command')
        self.assertIn('semantic-functional-session-'+('5'*64),scope['fenceBinding']['path'])
        self.assertNotEqual(scope['fenceBinding']['value']['journalPath'],f[0]['predecessorJournalDirectory'])

    def test_each_predecessor_record_is_hash_bound(self):
        for name in fixture()[1]:
            f=fixture();f[1][name]['unreviewed']='changed'
            with self.assertRaises(ValueError):compile_fixture(f)

    def test_arithmetic_is_checked_even_when_modified_record_hash_is_reviewed(self):
        for key,value in (('controlledCumulativeGrantAttempts',70),('attempts',True),
            ('controlledPredecessorGrantAttempts',9),('state','ACTIVE'),('reason','OTHER')):
            f=fixture();f[1]['recovery.json'][key]=value
            f[0]['predecessorRecordHashes']['recovery.json']=fingerprint(f[1]['recovery.json'])
            with self.assertRaises(ValueError):compile_fixture(f)

    def test_first_receipt_cannot_be_replaced_or_historical_gap_closed(self):
        for key,value in (('attemptSlotsConsumed',0),('legacyHistoricalGrantAttempts',0),('operation','9'*64)):
            f=fixture();f[2][key]=value
            with self.assertRaises(ValueError):compile_fixture(f)
        f=fixture();f[1]['recovery.json']['legacyHistory']['reconciled']=True
        f[0]['predecessorRecordHashes']['recovery.json']=fingerprint(f[1]['recovery.json'])
        with self.assertRaises(ValueError):compile_fixture(f)

    def test_new_budget_cannot_increase_or_inherit_approval(self):
        for key,value in (('max_attempts',129),('max_elapsed',3601),('jitter',0),('delays',[1])):
            f=fixture();f[3][key]=value
            with self.assertRaises(ValueError):compile_fixture(f)
        f=fixture();f[0]['humanApprovalGranted']=True
        with self.assertRaises(ValueError):compile_fixture(f)

    def row(self):
        return {'workerSessionHash':'a'*64,'controlledPredecessorGrantAttempts':69,
            'controlledCumulativeGrantAttempts':69,'attempts':0,
            'controlledHistoryProfile':C['GOVERNED_HISTORY'],'renewalProfile':'profile',
            'intervalSeconds':60,'publicationCount':0,'state':'NEW'}

    def test_scheduler_checks_cumulative_arithmetic_and_policy_bounds(self):
        receiver=types.SimpleNamespace(policy=types.SimpleNamespace(max_attempts=128),PROFILE='profile',interval=60)
        row=self.row();C['validate'](receiver,row)
        for attempt,total in ((1,70),(128,197)):
            C['validate'](receiver,{**row,'attempts':attempt,'controlledCumulativeGrantAttempts':total})
        for attempt,total in ((True,70),(129,198),(1,69)):
            with self.assertRaises(ValueError):C['validate'](receiver,{**row,'attempts':attempt,'controlledCumulativeGrantAttempts':total})

    def test_legacy_profile_does_not_accept69_or_lose_retained_pins(self):
        receiver=types.SimpleNamespace(policy=types.SimpleNamespace(max_attempts=128),PROFILE='profile',interval=60)
        row=self.row();row['controlledHistoryProfile']='ouf.policy-token-cancelled-worker-continuation.v1'
        with self.assertRaises(ValueError):C['validate'](receiver,row)
        row.update(controlledPredecessorGrantAttempts=10,controlledCumulativeGrantAttempts=10,
            predecessorCancelledWorkerHash='b'*64,predecessorWorkerSessionHash='c'*64)
        C['validate'](receiver,row)

if __name__=='__main__':unittest.main()
