"""Fixed unsigned reprocessing after the mount-owner lifetime caller defect.

Preserve both failed intents, the complete applied prefix and three controlled
grant attempts. No previous claim, token, worker or signature can be adopted.
"""
import copy,json,os,time
from pathlib import Path
import iam_binding_candidate as evidence
from tools.chatbot_file_cohort.plan import digest,require
from tools.chatbot_file_cohort.action_process import observed_private_json,private_file
from tools.chatbot_file_cohort import paused_recovery as paused
from tools.chatbot_file_cohort import postgrant_recovery as original
from tools.semantic_policy_token_owner.producer import protected_directory
from tools.semantic_lease_recovery.recovery_journal import Journal
from native_evidence_store import NativeEvidenceStore
from file_only_profile import PHASES
PROFILE='ouf.chatbot-paused-unsigned-attestation-reprocessing.v2'
SOURCE='b7d24c57d6e45e71994ac3f99f56f249d83cde22'
AUTHORITY='8c59697f46b3ce1b54d1cff1acf1f08dde6c4087062d28e379465d9a76ec570a'
REVIEW='2380132af8e47de185894fde156470e162dab784942c8615778e7620e7f8fc60'
CONTEXT='chatbot-file-cohort-signed-d3ef7a038a6b587dde883e802080cb393732be9c4399f98e43a1a3ff6b3b2c2f'
TRANSITION_HASH='8cfb376001410bce948163aa858d88174d04612516f6537bebdf0c36a9da60c8'
WORKER_HASH='978c661b1ddcb0441486568f18864805f8885aea13049d3f2a4de3c5c7f10443'
SESSION_HASH='2c64588aa8837280713f84fb6b673a0f401b803bfd65c545cf660aeac7c11cd0'
ADMISSION_HASH='c456b40bd76bf6ac8e39da96a95e7afa73ae3a0ef83ffc65fe7a78f7c0aecd7b'
CLAIM_HASH='e440b996d5eedacfeced08b7397b78493edfdd8da937e577ba5a69702c5f3984'
CLAIM='chatbot-file-cohort-mounted-token-reprocessing-'+AUTHORITY+'.claim.json'
LATER_HASHES={'authorization':'39db895d482e84f3c9fc90158d318c5d7d4790cf67bc7882764fdf31ccf4bac8',
 'containers':'dc94596b7729a920f861b12e378524c37e9ecebbd391f1e5f8499931663d23c6',
 'databases':'77316073b71af59285082986b2daff3bac92f57f53520f074ac051c7b714c701',
 'gateway':'06343d400aa132d929c60026a430d0fb05ddab4f83042c8120c7bc758246a9fa'}

def validate_worker(first,worker,admission,session):
    require(digest(first)==original.FIRST_HASH and worker.get('state')=='CANCELLED'
        and worker.get('attempts')==1 and worker.get('publicationCount')==1
        and worker.get('controlledPredecessorGrantAttempts')==2 and worker.get('controlledCumulativeGrantAttempts')==3
        and worker.get('firstGrantReceiptHash')==digest(first)and worker.get('workerSessionHash')==digest(session)
        and admission.get('state')=='BLOCKED'and admission.get('version')==3
        and session.get('schema')=='ouf.policy-token-new-finite-worker-session.v2'
        and session.get('controlledHistoryProfile')==worker.get('controlledHistoryProfile')=='ouf.policy-token-cancelled-worker-continuation.v1'
        and session.get('predecessorGrantAttempts')==2
        and session.get('predecessorFirstGrantOperation')==first['operation']
        and session.get('predecessorFirstGrantScopeHash')==first['scopeHash'],
        'MOUNT_RECOVERY_CANCELLED_WORKER_CUMULATIVE_THREE_REQUIRED')
    return {'controlledCumulativeGrantAttempts':3,'cancelledWorkerHash':digest(worker),'workerSessionHash':digest(session)}

def validate_boundary(row,prepared,authority_hash=None):
    if authority_hash is None:authority_hash=AUTHORITY
    scope={'postGrantRecovery':prepared['postGrantRecovery'],'creationRequestHash':digest(prepared['registry']['creationRequest']),
        'phaseIntentHashes':{k:digest(v)for k,v in prepared['registry']['intents'].items()}}
    paused.verify_successor_transition(row,scope,authority_hash)
    require(row.get('version')==15 and row.get('nextPhase')==6 and row.get('state')=='IN_FLIGHT'
        and len(row.get('effects',[]))==7 and row['effects'][6].get('phase')=='ATTEST_NEW_OCI_PEER'
        and row['effects'][6].get('state')=='IN_FLIGHT'and row.get('databaseMayHaveChanged')is False
        and row.get('applicationWritesMayHaveOccurred')is True and row.get('automaticReplayAllowed')is False
        and row.get('preMigrationRestoreAllowed')is False,'EXACT_SECOND_UNSIGNED_SIX_EFFECT_BOUNDARY_REQUIRED')
    return copy.deepcopy(row)

def read_predecessor():
    prior=paused.read_predecessor();root=evidence.PARENT/CONTEXT;bindings=copy.deepcopy(prior['recordBindings'])
    def read(path,expected=None,maximum=262144):
        value,binding=observed_private_json(path,maximum)
        require(expected is None or binding['sha256']==expected,'MOUNT_RECOVERY_PINNED_RECORD_DRIFT')
        bindings.append(binding);return value
    review=read(root/'review.json',REVIEW);authority=read(root/'authority.json',AUTHORITY,131072)
    require(review['sourceClosure']['declaration']['sourceCommit']==SOURCE
        and all(authority.get(k)==v for k,v in review['scopes'].items()),'EXACT_FAILED_MOUNT_OWNER_SIGNED_REVIEW_REQUIRED')
    decision=read(root/'decision.json')
    require(decision.get('approvedReviewHash')==REVIEW and decision.get('approvedSourceClosureHash')==review['sourceClosureHash']
        and decision.get('decision')=='APPROVE_ONE_FINITE_CHATBOT_FILE_COHORT_ACTION'and decision.get('state')=='ACTIVE'
        and decision.get('expiresAt')==authority['expiresAt'],'EXACT_PRIOR_MOUNT_OWNER_DECISION_REQUIRED')
    # The old finite window may not yet have elapsed. Its executor is stopped,
    # worker CANCELLED, token admission BLOCKED and fixed claim consumed. A new
    # HUMAN decision opens a distinct session; no old authority is extended.
    process=review['scopes']['finiteActionProcess'];require(process['authorityDirectory']==str(root),'EXACT_FAILED_MOUNT_OWNER_CONTEXT_REQUIRED')
    original.stopped_process(process,review['sourceClosure']['executables']['systemctl'])
    status=read(root/'delivery-status.json');require(status.get('phase')=='PAUSED_REQUIRES_RECONCILIATION'
        and status.get('reason')=='Permanent'and status.get('authorityHash')==AUTHORITY,'EXACT_MOUNT_OWNER_FAILURE_REQUIRED')
    claim=read(evidence.PARENT/paused.CLAIM,CLAIM_HASH)
    require(claim.get('state')=='CONTINUATION_RESERVED_NO_AUTOMATIC_REPLAY'and claim.get('authorityHash')==AUTHORITY,
        'PREVIOUS_UNSIGNED_REPROCESSING_CLAIM_MUST_REMAIN_CONSUMED')
    b=process['bundle'];bundle=read(b['path'],b['sha256'],8388608);prepared=bundle['prepared']
    require(bundle['declaration']==review['sourceClosure']['declaration']and digest(prepared)==review['privateInputHashes']['preparedInputs']
        and prepared['postGrantRecovery']['profile']==paused.PROFILE,'EXACT_PREVIOUS_UNSIGNED_REPROCESSING_BUNDLE_REQUIRED')
    paths=prepared['registry']['directoryPlan'];row=read(Path(paths['transition'])/'recovery.json',TRANSITION_HASH)
    validate_boundary(row,prepared)
    owner=Path(review['scopes']['policyTokenOwnerInstallation']['journalPath'])
    worker=read(owner/'recovery.json',WORKER_HASH);session=read(owner/'owner-session.json',SESSION_HASH)
    admission=read(owner/'owner-admission.json',ADMISSION_HASH)
    require(read(owner/'owner-first-grant.json',original.FIRST_HASH)==prior['firstGrant'],'MOUNT_RECOVERY_SAME_FIRST_GRANT_REQUIRED')
    validate_worker(prior['firstGrant'],worker,admission,session)
    require(session==review['scopes']['policyTokenFiniteWorkerSession']and worker['bootId']==prior['firstGrant']['bootId'],
        'MOUNT_RECOVERY_EXACT_WORKER_SESSION_AND_BOOT_REQUIRED')
    require(read(owner/'owner-predecessor-worker.json',paused.WORKER_HASH)==prior['worker']
        and read(owner/'owner-predecessor-session.json',paused.SESSION_HASH)==prior['session'],
        'MOUNT_RECOVERY_FULL_PRIOR_WORKER_CHAIN_REQUIRED')
    payloads=copy.deepcopy(prior['payloads']);payloads['evidence']={}
    for effect in row['effects'][:6]:
        phase=effect['phase'];value=read(Path(paths['evidence'])/(phase+'.json'))
        require(digest(value)==effect['nativeEvidenceHash']and value==prior['payloads']['evidence'][phase],
            'MOUNT_RECOVERY_SIX_COMPLETED_NATIVE_PAYLOADS_CHANGED')
        payloads['evidence'][phase]=value
    policy=read(Path(paths['node'])/'frame-policy.json',maximum=131072)
    require(policy['renewableToken']['minimumRemainingSeconds']==30 and prepared['owner']['iamProfile']['minimum_remaining']==90,
        'EXACT_REPRODUCED_THIRTY_NINETY_LIFETIME_CONTRACT_REQUIRED')
    result={**prior,'recoveryProfile':PROFILE,'pausedPredecessor':prior,'review':review,'prepared':prepared,
        'authority':authority,'transition':row,'bundle':bundle,'worker':worker,'session':session,'admission':admission,
        'payloads':payloads,'recordBindings':bindings,'failedPolicy':policy}
    paused.unsigned_node(result)
    for label,pin in LATER_HASHES.items():
        value=read(Path(process['directoryPlan'][label])/'recovery.json',pin)
        require(not value.get('effects')and not value.get('backups')and not value.get('nextStep',0)
            and value.get('mcpMigration')is None and value.get('mcpAuditRole')is None,
            'MOUNT_RECOVERY_LATER_APPLICATION_EFFECT_REQUIRES_DIFFERENT_PLAN')
    return result

def proof_scope(previous,actor):
    base=paused.proof_scope(previous['pausedPredecessor'],actor);row=previous['transition']
    require(actor=={k:previous['prepared']['authorization']['plan']['selection'][k]for k in('issuer','tenant','subject')},
        'MOUNT_RECOVERY_SAME_CURRENT_HUMAN_REQUIRED')
    return {**base,'profile':PROFILE,'pausedPredecessorSource':SOURCE,'pausedPredecessorAuthorityHash':AUTHORITY,
        'pausedPredecessorReviewHash':REVIEW,'predecessorTransitionHash':TRANSITION_HASH,'appliedPrefixHash':digest(row['effects'][:6]),
        'failedUnsignedIntentHash':digest(row['effects'][6]),'previousReprocessingMarkerHash':digest(row['governedUnsignedReprocessing']),
        'cancelledWorkerHash':WORKER_HASH,'workerSessionHash':SESSION_HASH,'recordBindings':copy.deepcopy(previous['recordBindings']),
        'originalNodeRecipeHash':digest(previous['prepared']['registry']['nodeRecipe']),
        'newBudget':{'actor':copy.deepcopy(actor),'reason':'CORRECT_MOUNT_OWNER_PUBLICATION_LIFETIME_WITNESS_REPROCESS_UNSIGNED_ATTESTATION',
            'decisionRef':'CURRENT_EXACT_FULL_ACTION_HUMAN_DECISION','priorControlledGrantAttempts':3,'priorWorkerGrantAttempts':1,
            'maximumNewWorkerAttempts':128,'maximumSeconds':3600,'automaticRenewalAllowed':False},
        'previousExecutorStopped':True,'previousWorkerCancelled':True,'previousAdmissionBlocked':True,'oldAuthorityExtended':False,
        'allPreviousFailedIntentsRetained':True}

def retained_bindings(proof):
    require(proof.get('profile')==PROFILE and proof.get('pausedPredecessorAuthorityHash')==AUTHORITY
        and proof.get('predecessorTransitionHash')==TRANSITION_HASH and proof.get('cancelledWorkerHash')==WORKER_HASH
        and proof.get('workerSessionHash')==SESSION_HASH and proof.get('independentRootfsQualification')==paused.CI_WITNESS
        and proof.get('newBudget',{}).get('priorControlledGrantAttempts')==3 and proof.get('oldAuthorityExtended')is False,
        'EXACT_MOUNT_LIFETIME_GOVERNED_RECOVERY_PROOF_REQUIRED')
    for binding in proof['recordBindings']:private_file(binding,8388608)
    review=evidence.decode(private_file({'path':str(evidence.PARENT/CONTEXT/'review.json'),'sha256':REVIEW},8388608))
    bundle=evidence.decode(private_file(review['scopes']['finiteActionProcess']['bundle'],8388608))
    paused.unsigned_node({'prepared':bundle['prepared']})

def marker(old,proof,authority_hash,intent_hash):
    return {'schema':'ouf.unsigned-paused-attestation-governed-reprocessing.v2','predecessorJournalHash':digest(old),
        'failedIntent':copy.deepcopy(old['effects'][6]),'previousReprocessing':copy.deepcopy(old['governedUnsignedReprocessing']),
        'proofHash':digest(proof),'newAuthorityHash':authority_hash,'newIntentHash':intent_hash,
        'decisionRef':'CURRENT_EXACT_FULL_ACTION_HUMAN_DECISION','automaticReplayAllowed':False}

def successor_seed(previous,proof,authority_hash,intents):
    old=validate_boundary(previous['transition'],previous['prepared'])
    require(digest(old)==proof['predecessorTransitionHash']and digest(old['effects'][:6])==proof['appliedPrefixHash']
        and all(intents[phase]==previous['prepared']['registry']['intents'][phase]for phase in PHASES[:6])
        and digest(intents['ATTEST_NEW_OCI_PEER'])!=old['effects'][6]['intentHash'],
        'MOUNT_RECOVERY_MUST_KEEP_SIX_EFFECTS_AND_CHANGE_SOURCE_BOUND_INTENT')
    seed=copy.deepcopy(old);seed.update(version=16,state='READY',effects=copy.deepcopy(old['effects'][:6]))
    seed['governedUnsignedReprocessing']=marker(old,proof,authority_hash,digest(intents['ATTEST_NEW_OCI_PEER']))
    return seed

def verify_successor_transition(row,scope,authority_hash):
    proof=scope['postGrantRecovery'];m=row.get('governedUnsignedReprocessing',{})
    require(proof.get('profile')==PROFILE and proof.get('pausedPredecessorAuthorityHash')==AUTHORITY
        and proof.get('predecessorAuthorityHash')==original.AUTHORITY and proof.get('predecessorTransitionHash')==TRANSITION_HASH
        and row.get('transitionAuthorityEvidenceHash')==original.AUTHORITY and row.get('contextHash')==proof['transitionContextHash']
        and row.get('creationRequestHash')==scope['creationRequestHash']and row.get('nextPhase',-1)>=6
        and row.get('version',0)>=16 and len(row.get('effects',[]))>=6 and digest(row['effects'][:6])==proof['appliedPrefixHash']
        and all(e.get('state')=='APPLIED'for e in row['effects'][:6])
        and all(e.get('authorityEvidenceHash')==authority_hash and e.get('intentHash')==scope['phaseIntentHashes'].get(e.get('phase'))for e in row['effects'][6:])
        and set(m)=={'schema','predecessorJournalHash','failedIntent','previousReprocessing','proofHash','newAuthorityHash','newIntentHash','decisionRef','automaticReplayAllowed'}
        and m.get('schema')=='ouf.unsigned-paused-attestation-governed-reprocessing.v2'and m.get('predecessorJournalHash')==TRANSITION_HASH
        and digest(m.get('failedIntent'))==proof['failedUnsignedIntentHash']and digest(m.get('previousReprocessing'))==proof['previousReprocessingMarkerHash']
        and m.get('proofHash')==digest(proof)and m.get('newAuthorityHash')==authority_hash
        and m.get('newIntentHash')==scope['phaseIntentHashes']['ATTEST_NEW_OCI_PEER']
        and m.get('decisionRef')=='CURRENT_EXACT_FULL_ACTION_HUMAN_DECISION'and m.get('automaticReplayAllowed')is False,
        'MOUNT_RECOVERY_BOTH_FAILED_INTENTS_OR_NEW_AUTHORITY_DRIFT')
    return True

def seed_registry(previous,directories,action,scope):
    action.guard('applicationRegistryCutover',scope);proof=scope['postGrantRecovery'];retained_bindings(proof)
    intents=previous['prepared']['registry']['intents']
    old=validate_boundary(previous['transition'],previous['prepared'])
    require(digest(old)==TRANSITION_HASH and digest(old['effects'][:6])==proof['appliedPrefixHash']
        and all(scope['phaseIntentHashes'][phase]==digest(intents[phase])for phase in PHASES[:6])
        and scope['phaseIntentHashes']['ATTEST_NEW_OCI_PEER']!=old['effects'][6]['intentHash'],
        'EXACT_CHANGED_LIFETIME_RECOVERY_INTENT_AND_SEED_REQUIRED')
    seed=copy.deepcopy(old);seed.update(version=16,state='READY',effects=copy.deepcopy(old['effects'][:6]))
    seed['governedUnsignedReprocessing']=marker(old,proof,action.authority_hash,scope['phaseIntentHashes']['ATTEST_NEW_OCI_PEER'])
    verify_successor_transition(seed,scope,action.authority_hash);journal=Journal(directories['transition'])
    require(not any(os.path.lexists(journal.root/p)for p in('recovery.json','recovery.lock','invocation.lock')),'MOUNT_RECOVERY_NEW_JOURNAL_ALREADY_CONSUMED')
    for name,phases in previous['payloads'].items():
        store=NativeEvidenceStore(directories[name])
        for phase,value in phases.items():store.publish(phase,value)
    journal.initialize(seed);require(journal.read()==seed,'MOUNT_RECOVERY_SEED_PUBLICATION_DRIFT');return journal
