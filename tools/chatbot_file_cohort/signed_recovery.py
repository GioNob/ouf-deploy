"""Explicit reprocessing after accepted attestation and pre-effect admission.

Keep the signed predecessor and ambiguous migration intent immutable. A fresh
HUMAN decision binds one new attestation to the corrected source and one new
admission from an owner-proven closed database. Never clear conservative DB
flags, recreate/re-stage, restore a database, or adopt an old worker/token.
"""
import copy,os
from pathlib import Path
import iam_binding_candidate as evidence
from tools.chatbot_file_cohort.plan import digest,require
from tools.chatbot_file_cohort.action_process import observed_private_json,private_file
from tools.chatbot_file_cohort import mounted_recovery as mounted,paused_recovery as paused,postgrant_recovery as original
from tools.semantic_lease_recovery.recovery_journal import Journal
from native_evidence_store import NativeEvidenceStore
from file_only_profile import PHASES
PROFILE='ouf.chatbot-signed-paused-admission-reprocessing.v1'
SOURCE='43819bc04dc40daaf119a2098945405f42d7bc6f'
AUTHORITY='3a2c33eabd19545bf1128f5049a4fa7df79cf76edec450b6c4946144c3943fd8'
REVIEW='e375f7fe868806206c42a0609d98de65fab96d3b0aafcec375af0004d91d3e25'
CONTEXT='chatbot-file-cohort-signed-d8a817cd13770cd5a655b8b955ef8959588959ffb0751dd24ddd1ef28e49fd52'
TRANSITION_HASH='cbc366cc0b376bea82407411bbadf76e584d47455ee22e0274ad45741c89d74f'
WORKER_HASH='910c34c29816e1879dd057b473cd9175c54582fd40b37e64bceeb88fd03812f1'
SESSION_HASH='2f042183d057cf0fec673cc04fa4e229b39634bee9b0d7780e04fabcc72cfb3a'
ADMISSION_HASH='2ceb76a6bb6ecc885e3013bc336959a997f985f8ba7a7c210bef92292bccf4df'
CLAIM_HASH='b92a6cff1a688dfedd7c3b67464af99c4767e0a71af1e79d4904016de86e4f30'
NODE_HASH='037bc589146bd94b8495a0d3e1e307fb282c24fa05cd1ff2a9d76e81c7b67e61'
NODE_CLAIM_HASH='2d326ed2daccaed4c2d447bbdf82585dddbd18f6da69cb5d4ba113afb30f2d07'
NODE_RECEIPT_HASH='95e301b2174a62adca9f9f57816a1f0064d60df7ca43a913164ae74e23048312'
CLAIM='chatbot-file-cohort-signed-admission-reprocessing-'+AUTHORITY+'.claim.json'
LATER_HASHES={'authorization':'cff178639c53b81d9058801e0efb8a0980a28c2a646626da1aafa2fc10714de1',
 'containers':'85d1fdac77f2466d6f308857f764ea125490ef94e1c70f9e971f3e8cc3036e0d',
 'databases':'ac3b42f27a14eba3b5762fd0ef3ee2f576aab7087f96d5b98903dd9ca1dc683a',
 'gateway':'c9f3af5b2790ec42bfef95264836f4fdc1eaabbdc8c4b35e2b40026450679faf'}

def validate_worker(first,worker,admission,session):
    require(digest(first)==original.FIRST_HASH and worker.get('state')=='CANCELLED'
        and worker.get('attempts')==worker.get('publicationCount')==1
        and worker.get('controlledPredecessorGrantAttempts')==3 and worker.get('controlledCumulativeGrantAttempts')==4
        and worker.get('firstGrantReceiptHash')==digest(first)and worker.get('workerSessionHash')==digest(session)
        and admission.get('state')=='BLOCKED'and admission.get('version')==3
        and session.get('schema')=='ouf.policy-token-new-finite-worker-session.v3'
        and session.get('predecessorGrantAttempts')==3
        and session.get('controlledHistoryProfile')==worker.get('controlledHistoryProfile')=='ouf.policy-token-cancelled-worker-continuation.v1'
        and session.get('predecessorFirstGrantOperation')==first['operation']and session.get('predecessorFirstGrantScopeHash')==first['scopeHash'],
        'SIGNED_RECOVERY_CANCELLED_WORKER_CUMULATIVE_FOUR_REQUIRED')
    return {'controlledCumulativeGrantAttempts':4,'cancelledWorkerHash':digest(worker),'workerSessionHash':digest(session)}

def validate_boundary(row,prepared,authority_hash=None):
    if authority_hash is None:authority_hash=AUTHORITY
    scope={'postGrantRecovery':prepared['postGrantRecovery'],'creationRequestHash':digest(prepared['registry']['creationRequest']),
        'phaseIntentHashes':{k:digest(v)for k,v in prepared['registry']['intents'].items()}}
    mounted.verify_successor_transition(row,scope,authority_hash)
    require(row.get('version')==19 and row.get('nextPhase')==7 and row.get('state')=='IN_FLIGHT'
        and len(row.get('effects',[]))==8 and all(e.get('state')=='APPLIED'for e in row['effects'][:7])
        and row['effects'][7].get('phase')=='ADMIT_MIGRATION'and row['effects'][7].get('state')=='IN_FLIGHT'
        and row.get('databaseMayHaveChanged')is True and row.get('applicationWritesMayHaveOccurred')is True
        and row.get('automaticReplayAllowed')is False and row.get('preMigrationRestoreAllowed')is False,
        'EXACT_SIGNED_ATTESTATION_PENDING_ADMISSION_BOUNDARY_REQUIRED')
    return copy.deepcopy(row)

def read_predecessor():
    prior=mounted.read_predecessor();root=evidence.PARENT/CONTEXT;bindings=copy.deepcopy(prior['recordBindings'])
    def read(path,expected=None,maximum=262144):
        value,binding=observed_private_json(path,maximum)
        require(expected is None or binding['sha256']==expected,'SIGNED_RECOVERY_PINNED_RECORD_DRIFT')
        bindings.append(binding);return value
    review=read(root/'review.json',REVIEW,8388608);authority=read(root/'authority.json',AUTHORITY,131072)
    require(review['sourceClosure']['declaration']['sourceCommit']==SOURCE and all(authority.get(k)==v for k,v in review['scopes'].items()),
        'EXACT_FAILED_RETAINED_CHECKPOINT_REVIEW_REQUIRED')
    decision=read(root/'decision.json')
    require(decision.get('approvedReviewHash')==REVIEW and decision.get('approvedSourceClosureHash')==review['sourceClosureHash']
        and decision.get('decision')=='APPROVE_ONE_FINITE_CHATBOT_FILE_COHORT_ACTION'and decision.get('state')=='ACTIVE'
        and decision.get('expiresAt')==authority['expiresAt'],'EXACT_PREDECESSOR_SIGNED_DECISION_REQUIRED')
    process=review['scopes']['finiteActionProcess'];require(process['authorityDirectory']==str(root),'EXACT_SIGNED_RECOVERY_CONTEXT_REQUIRED')
    original.stopped_process(process,review['sourceClosure']['executables']['systemctl'])
    status=read(root/'delivery-status.json')
    require(status.get('phase')=='PAUSED_REQUIRES_RECONCILIATION'and status.get('reason')=='CURRENT_ATTESTATION_PHASE_AND_CREATION_SCOPE_REQUIRED'
        and status.get('authorityHash')==AUTHORITY,'EXACT_RETAINED_CHECKPOINT_FAILURE_REQUIRED')
    claim=read(evidence.PARENT/mounted.CLAIM,CLAIM_HASH)
    require(claim.get('state')=='CONTINUATION_RESERVED_NO_AUTOMATIC_REPLAY'and claim.get('authorityHash')==AUTHORITY,'PREVIOUS_MOUNTED_CLAIM_MUST_REMAIN_CONSUMED')
    b=process['bundle'];bundle=read(b['path'],b['sha256'],8388608);prepared=bundle['prepared']
    require(bundle['declaration']==review['sourceClosure']['declaration']and digest(prepared)==review['privateInputHashes']['preparedInputs']
        and prepared['postGrantRecovery']['profile']==mounted.PROFILE,'EXACT_SIGNED_PREDECESSOR_BUNDLE_REQUIRED')
    paths=prepared['registry']['directoryPlan'];row=read(Path(paths['transition'])/'recovery.json',TRANSITION_HASH);validate_boundary(row,prepared)
    require(not os.path.lexists(Path(paths['evidence'])/'ADMIT_MIGRATION.json'),'EXISTING_ADMISSION_RECEIPT_REQUIRES_DIFFERENT_RECOVERY')
    owner=Path(review['scopes']['policyTokenOwnerInstallation']['journalPath'])
    worker=read(owner/'recovery.json',WORKER_HASH);session=read(owner/'owner-session.json',SESSION_HASH);admission=read(owner/'owner-admission.json',ADMISSION_HASH)
    require(read(owner/'owner-first-grant.json',original.FIRST_HASH)==prior['firstGrant'],'SAME_ORIGINAL_FIRST_GRANT_REQUIRED')
    validate_worker(prior['firstGrant'],worker,admission,session)
    require(session==review['scopes']['policyTokenFiniteWorkerSession']and worker['bootId']==prior['firstGrant']['bootId'],'SIGNED_RECOVERY_SESSION_OR_BOOT_DRIFT')
    require(read(owner/'owner-predecessor-worker.json',mounted.WORKER_HASH)==prior['worker']
        and read(owner/'owner-predecessor-session.json',mounted.SESSION_HASH)==prior['session'],'COMPLETE_FOUR_GRANT_HISTORY_REQUIRED')
    payloads=copy.deepcopy(prior['payloads']);payloads['evidence']={}
    for effect in row['effects'][:6]:
        phase=effect['phase'];value=read(Path(paths['evidence'])/(phase+'.json'),effect['nativeEvidenceHash'])
        require(value==prior['payloads']['evidence'][phase],'SIGNED_RECOVERY_SIX_NATIVE_EFFECTS_CHANGED');payloads['evidence'][phase]=value
    node=Path(paths['node']);require(set(os.listdir(node))=={'frame-policy.json','paused-acceptance.json','attestation-issuance-claim.json'},'EXACT_PREVIOUS_SIGNED_NODE_MEMBERS_REQUIRED')
    policy=read(node/'frame-policy.json',maximum=131072);acceptance=read(node/'paused-acceptance.json',NODE_HASH,131072)
    issuance=read(node/'attestation-issuance-claim.json',NODE_CLAIM_HASH)
    receipt=read(Path(paths['evidence'])/'ATTEST_NEW_OCI_PEER.json',NODE_RECEIPT_HASH)
    signature=read(root/(NODE_HASH+'.CREATION_ATTESTATION.json'))
    require(issuance.get('authorizationHash')==NODE_HASH and issuance.get('transitionContextHash')==row['contextHash']
        and acceptance.get('sourceClosureHash')==review['sourceClosureHash']and acceptance.get('containerId')==original.CREATED_ID
        and acceptance.get('phaseIntentHash')==row['effects'][6]['intentHash']and acceptance.get('expiresAt')==authority['expiresAt']
        and signature.get('payloadHash')==NODE_HASH and signature.get('role')=='CREATION_ATTESTATION'
        and receipt.get('completeNativeObservationPerformed')is True and receipt.get('currentScopedAcceptanceSignatureVerified')is True
        and digest(receipt)==row['effects'][6]['nativeEvidenceHash'],'EXACT_PREVIOUS_SIGNED_ATTESTATION_HISTORY_REQUIRED')
    for label,pin in LATER_HASHES.items():
        value=read(Path(process['directoryPlan'][label])/'recovery.json',pin)
        require(not value.get('effects')and not value.get('backups')and not value.get('nextStep',0)
            and value.get('mcpMigration')is None and value.get('mcpAuditRole')is None,'SIGNED_RECOVERY_LATER_EFFECT_REQUIRES_DIFFERENT_PLAN')
    return {**prior,'recoveryProfile':PROFILE,'mountedPredecessor':prior,'review':review,'prepared':prepared,'authority':authority,
        'transition':row,'bundle':bundle,'worker':worker,'session':session,'admission':admission,'payloads':payloads,'recordBindings':bindings,
        'failedPolicy':policy,'acceptedNode':{'authorization':acceptance,'issuance':issuance,'receipt':receipt,'signature':signature}}

def proof_scope(previous,actor):
    base=mounted.proof_scope(previous['mountedPredecessor'],actor);row=previous['transition']
    require(actor=={k:previous['prepared']['authorization']['plan']['selection'][k]for k in('issuer','tenant','subject')},'SAME_CURRENT_SIGNED_RECOVERY_HUMAN_REQUIRED')
    return {**base,'profile':PROFILE,'pausedPredecessorSource':SOURCE,'pausedPredecessorAuthorityHash':AUTHORITY,'pausedPredecessorReviewHash':REVIEW,
        'predecessorTransitionHash':TRANSITION_HASH,'appliedPrefixHash':digest(row['effects'][:6]),
        'previousAcceptedAttestationHash':digest(row['effects'][6]),'failedMigrationIntentHash':digest(row['effects'][7]),
        'previousReprocessingMarkerHash':digest(row['governedUnsignedReprocessing']),
        'retainedNodeAuthorizationHash':NODE_HASH,'retainedNodeIssuanceHash':NODE_CLAIM_HASH,'retainedNodePhaseReceiptHash':NODE_RECEIPT_HASH,
        'cancelledWorkerHash':WORKER_HASH,'workerSessionHash':SESSION_HASH,'recordBindings':copy.deepcopy(previous['recordBindings']),
        'newBudget':{'actor':copy.deepcopy(actor),'reason':'CORRECT_RETAINED_CHECKPOINT_REATTEST_AND_ADMIT_ONLY_FROM_OWNER_PROVEN_CLOSED_DATABASE',
            'decisionRef':'CURRENT_EXACT_FULL_ACTION_HUMAN_DECISION','priorControlledGrantAttempts':4,'priorWorkerGrantAttempts':1,
            'maximumNewWorkerAttempts':128,'maximumSeconds':3600,'automaticRenewalAllowed':False},
        'signedAttestationRetainedAsHistoryNotCurrentAuthority':True,'databaseMayHaveChangedConservativelyRetained':True,
        'newAdmissionRequiresFreshOwnerFencedBackupMatch':True,'oldMigrationIntentRetainedNotAutomaticallyReplayed':True}

def retained_bindings(proof):
    require(proof.get('profile')==PROFILE and proof.get('pausedPredecessorAuthorityHash')==AUTHORITY
        and proof.get('predecessorTransitionHash')==TRANSITION_HASH and proof.get('cancelledWorkerHash')==WORKER_HASH
        and proof.get('workerSessionHash')==SESSION_HASH and proof.get('newBudget',{}).get('priorControlledGrantAttempts')==4
        and proof.get('retainedNodeAuthorizationHash')==NODE_HASH and proof.get('retainedNodeIssuanceHash')==NODE_CLAIM_HASH
        and proof.get('retainedNodePhaseReceiptHash')==NODE_RECEIPT_HASH
        and proof.get('databaseMayHaveChangedConservativelyRetained')is True and proof.get('newAdmissionRequiresFreshOwnerFencedBackupMatch')is True
        and proof.get('oldAuthorityExtended')is False,'EXACT_SIGNED_ADMISSION_REPROCESSING_PROOF_REQUIRED')
    for binding in proof['recordBindings']:private_file(binding,8388608)


def marker(old,proof,authority_hash,intent_hash):
    return {'schema':'ouf.signed-paused-admission-governed-reprocessing.v1','predecessorJournalHash':digest(old),
        'previousAcceptedAttestation':copy.deepcopy(old['effects'][6]),'failedMigrationIntent':copy.deepcopy(old['effects'][7]),
        'previousReprocessing':copy.deepcopy(old['governedUnsignedReprocessing']),'proofHash':digest(proof),
        'newAuthorityHash':authority_hash,'newIntentHash':intent_hash,'decisionRef':'CURRENT_EXACT_FULL_ACTION_HUMAN_DECISION','automaticReplayAllowed':False}

def successor_seed(previous,proof,authority_hash,intents):
    old=validate_boundary(previous['transition'],previous['prepared'])
    require(digest(old)==proof['predecessorTransitionHash']and digest(old['effects'][:6])==proof['appliedPrefixHash']
        and all(intents[p]==previous['prepared']['registry']['intents'][p]for p in PHASES if p not in('ATTEST_NEW_OCI_PEER','RELEASE_PRODUCERS'))
        and digest(intents['ATTEST_NEW_OCI_PEER'])!=old['effects'][6]['intentHash'],'SIGNED_RECOVERY_ONLY_REVIEWED_REATTESTATION_INTENT_MAY_CHANGE')
    seed=copy.deepcopy(old);seed.update(version=20,state='READY',nextPhase=6,effects=copy.deepcopy(old['effects'][:6]))
    seed['governedSignedAttestationReprocessing']=marker(old,proof,authority_hash,digest(intents['ATTEST_NEW_OCI_PEER']))
    return seed

def verify_successor_transition(row,scope,authority_hash):
    proof=scope['postGrantRecovery'];m=row.get('governedSignedAttestationReprocessing',{})
    require(proof.get('profile')==PROFILE and proof.get('pausedPredecessorAuthorityHash')==AUTHORITY
        and proof.get('predecessorAuthorityHash')==original.AUTHORITY and proof.get('predecessorTransitionHash')==TRANSITION_HASH
        and row.get('transitionAuthorityEvidenceHash')==original.AUTHORITY and row.get('contextHash')==proof['transitionContextHash']
        and row.get('creationRequestHash')==scope['creationRequestHash']and row.get('nextPhase',-1)>=6 and row.get('version',0)>=20
        and row.get('databaseMayHaveChanged')is True and row.get('preMigrationRestoreAllowed')is False
        and len(row.get('effects',[]))>=6 and digest(row['effects'][:6])==proof['appliedPrefixHash']
        and all(e.get('state')=='APPLIED'for e in row['effects'][:6])
        and all(e.get('authorityEvidenceHash')==authority_hash and e.get('intentHash')==scope['phaseIntentHashes'].get(e.get('phase'))for e in row['effects'][6:])
        and set(m)=={'schema','predecessorJournalHash','previousAcceptedAttestation','failedMigrationIntent','previousReprocessing','proofHash','newAuthorityHash','newIntentHash','decisionRef','automaticReplayAllowed'}
        and m.get('schema')=='ouf.signed-paused-admission-governed-reprocessing.v1'and m.get('predecessorJournalHash')==TRANSITION_HASH
        and digest(m.get('previousAcceptedAttestation'))==proof['previousAcceptedAttestationHash']
        and digest(m.get('failedMigrationIntent'))==proof['failedMigrationIntentHash']
        and digest(m.get('previousReprocessing'))==proof['previousReprocessingMarkerHash']
        and m.get('previousReprocessing')==row.get('governedUnsignedReprocessing')
        and m.get('proofHash')==digest(proof)and m.get('newAuthorityHash')==authority_hash
        and m.get('newIntentHash')==scope['phaseIntentHashes']['ATTEST_NEW_OCI_PEER']
        and m.get('newIntentHash')!=m.get('previousAcceptedAttestation',{}).get('intentHash')
        and scope['phaseIntentHashes']['ADMIT_MIGRATION']==m.get('failedMigrationIntent',{}).get('intentHash')
        and m.get('previousAcceptedAttestation',{}).get('phase')=='ATTEST_NEW_OCI_PEER'
        and m.get('previousAcceptedAttestation',{}).get('state')=='APPLIED'
        and m.get('failedMigrationIntent',{}).get('phase')=='ADMIT_MIGRATION'
        and m.get('failedMigrationIntent',{}).get('state')=='IN_FLIGHT'
        and m.get('decisionRef')=='CURRENT_EXACT_FULL_ACTION_HUMAN_DECISION'and m.get('automaticReplayAllowed')is False,
        'SIGNED_RECOVERY_ACCEPTED_HISTORY_PENDING_INTENT_OR_NEW_AUTHORITY_DRIFT')
    return True

def seed_registry(previous,directories,action,scope):
    action.guard('applicationRegistryCutover',scope);proof=scope['postGrantRecovery'];retained_bindings(proof)
    intents=copy.deepcopy(previous['prepared']['registry']['intents'])
    require(all(scope['phaseIntentHashes'][p]==digest(intents[p])for p in PHASES if p not in('ATTEST_NEW_OCI_PEER','RELEASE_PRODUCERS')),
        'SIGNED_RECOVERY_CONSUMED_EFFECT_OR_DATABASE_INTENT_CHANGED')
    # Complete new intents live in the reviewed scope only as hashes. The one
    # changed node intent is independently bound; keep all consumed data.
    old=validate_boundary(previous['transition'],previous['prepared'])
    require(digest(old)==TRANSITION_HASH,'SIGNED_RECOVERY_PREDECESSOR_RECORD_CHANGED')
    seed=copy.deepcopy(old);seed.update(version=20,state='READY',nextPhase=6,effects=copy.deepcopy(old['effects'][:6]))
    seed['governedSignedAttestationReprocessing']=marker(old,proof,action.authority_hash,scope['phaseIntentHashes']['ATTEST_NEW_OCI_PEER'])
    verify_successor_transition(seed,scope,action.authority_hash);journal=Journal(directories['transition'])
    require(not any(os.path.lexists(journal.root/p)for p in('recovery.json','recovery.lock','invocation.lock')),'SIGNED_RECOVERY_NEW_JOURNAL_ALREADY_CONSUMED')
    for name,phases in previous['payloads'].items():
        store=NativeEvidenceStore(directories[name])
        for phase,value in phases.items():store.publish(phase,value)
    journal.initialize(seed);require(journal.read()==seed,'SIGNED_RECOVERY_SEED_PUBLICATION_DRIFT');return journal
