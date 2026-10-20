"""One explicit finite invocation from the sealed loader; no authentication.

Initialization, one step, and reconciliation are distinct explicit modes. No
loop, timer, background worker, login, refresh or retry is started here.
"""
import hashlib
import json
import time
from pathlib import Path
from tools.ingestion_rollout_execution import contract as c,authority
from tools.ingestion_rollout_execution.runner import Runner
from tools.ingestion_rollout_execution.native import NativePorts
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_policy_token_owner.producer import protected_directory
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator
from cutover_authority import CutoverAuthority
from iam_binding_candidate import read_member

def expected_bindings(review):
    return {k:review[k]for k in('sourceClosureHash','creationRequestHash','predecessorHistoryHash','predecessorIncidentRef')}|{'intakeHash':c.digest(review)}

def validate_raw(review,raw):
    value=json.loads(raw);expected=expected_bindings(review)
    c.require(set(value)=={'schema','issuedAt','expiresAt',c.AUTHORITY_KEY,'automaticReplayAllowed',
              'databaseRestoreAuthorized','r12ReplayAuthorized',*(set(expected)-{'intakeHash'})}
              and value['schema']=='ouf.semantic-cutover-execution-authority.v1'
              and value[c.AUTHORITY_KEY]==review['scopes'][c.AUTHORITY_KEY]
              and all(value[k]==v for k,v in expected.items()if k!='intakeHash')
              and all(value[k]is False for k in('automaticReplayAllowed','databaseRestoreAuthorized','r12ReplayAuthorized')),
              'ONLY_EXACT_NEW_NATIVE_AUTHORITY_ENVELOPE_ALLOWED')

def load_action(review,decision,human,approved_decision_hash,approved_mandate_hash):
    """Read existing issued artifacts; never issue, reconstruct or reset them."""
    authority.validate_action_review(review)
    c.require(c.hashed(approved_decision_hash)and c.digest(decision)==approved_decision_hash
              and c.hashed(approved_mandate_hash),'INDEPENDENT_APPROVED_DECISION_AND_MANDATE_HASHES_REQUIRED')
    authority.decision_valid(review,decision,human,time.time())
    authority.verify_closure(review['sourceClosure'])
    authority.current_issuer(review['issuerProfile'],decision['expiresAt'])
    context=Path(review['authorityDirectory'])
    with protected_directory(context)as directory:
        c.require(read_member(directory,'review.json')==c.encoded(review)
                  and read_member(directory,'decision.json')==c.encoded(decision),'EXACT_RETAINED_ISSUED_REVIEW_REQUIRED')
        raw=read_member(directory,'authority.json');mandate=read_member(directory,'human.json')
    c.require(hashlib.sha256(mandate).hexdigest()==approved_mandate_hash,'EXACT_APPROVED_RETAINED_MANDATE_REQUIRED')
    validate_raw(review,raw)
    selected={k:review['issuerProfile']['policy'][k]for k in('path','sha256')}
    verifier=DetachedAuthenticator(selected,str(context),review['sourceClosure']['executables']['openssl'])
    gate=CutoverAuthority(verifier,{'path':str(context/'human.json'),'sha256':approved_mandate_hash},
        approved_mandate_hash,review['issuerProfile']['authorityContext'],expected_bindings(review))
    action=AggregateAction(gate,raw,review['sourceClosureHash'])
    action.guard(c.AUTHORITY_KEY,review['scopes'][c.AUTHORITY_KEY]);return action

def execute(mode,review,packet,human,action,manifest):
    c.require(mode in('initialize','step','reconcile'),'ONE_EXPLICIT_NATIVE_EXECUTION_MODE_REQUIRED')
    authority.validate_action_review(review)
    c.require(type(action)is AggregateAction and manifest==review['sourceClosure']['declaration']
              and action.closure==review['sourceClosureHash']
              and c.hashed(globals().get('__qualified_source_sha256__'))
              and globals()['__qualified_source_sha256__']==manifest['sourceHashes'].get(__name__),
              'EXACT_SEALED_NATIVE_ENTRY_AND_ACTION_REQUIRED')
    validate_raw(review,action.raw)
    authority.verify_closure(review['sourceClosure'])
    authority.current_issuer(review['issuerProfile'],json.loads(action.raw)['expiresAt'])
    c.require(c.digest(packet)==review['packetHash'],'EXACT_REVIEWED_NATIVE_PACKET_REQUIRED')
    native=review['executionReview'];action.guard(c.AUTHORITY_KEY,c.scope(native))
    c.require(human.current()==review['authenticatedHuman'],'SAME_CURRENT_HUMAN_NO_AUTHENTICATION_FALLBACK')
    journal=Journal(Path(review['authorityDirectory']));ports=NativePorts(action,journal,native,packet,human)
    runner=Runner(action,journal,native,ports)
    try:
        if mode=='initialize':
            runner.initialize();result={'initialized':True,'effectsDispatched':0,'complete':False}
        elif mode=='step':result=runner.step()
        else:result=runner.reconcile()
        return {**result,'completedTechnicalPhases':8,'functionalMilestonesProven':4,
                'runtimeAuthorityIssued':False,'newLoginPerformed':False,'refreshPerformed':False,
                'budgetReset':False,'releaseAcceptance':False}
    finally:ports.close()
