"""Governed continuation after Registry verification and a failed MCP dump.

Immutable predecessor history is evidence, never renewed runtime authority.
Only a new full HUMAN action may copy complete backups and create one new MCP
archive. No Registry phase, failed archive, first grant or old token is replayed.
"""
import copy
import hashlib
import os
import stat
import time
from pathlib import Path
from types import SimpleNamespace

import iam_binding_candidate as evidence
from engine_creation import Engine
from file_only_profile import PHASES
from native_evidence_store import NativeEvidenceStore
from tools.chatbot_file_cohort.plan import digest, require
from tools.chatbot_file_cohort.action_process import observed_private_json, private_file
from tools.chatbot_file_cohort import postgrant_recovery as original, signed_recovery as signed
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.semantic_policy_token_owner.producer import protected_directory
from tools.chatbot_file_cohort.running_rootfs import QUALIFICATION as RUNNING_ROOTFS_QUALIFICATION

PROFILE='ouf.chatbot-verified-registry-mcp-backup-recovery.v1'
SOURCE='e70ca5957772e170bc762dd937e1c46a40051f0a'
AUTHORITY='936d15d844e0d11bd95ee3c463843fbb5e5e2361e10c3d9ac22901f4557a9b36'
REVIEW='9d2e5fbc8c0c0b0e14faaea7003d151fe221c94b08ca3c1204d3a402ea837219'
CONTEXT='chatbot-file-cohort-signed-37f1e44e094db4158bd12c5d83a67478786a1531142ba6c07d172ae05f80cbb9'
TRANSITION_HASH='bf4506f1f582c3806201cb76d17c72524ba779eb1ca920d1947ba1728bc91642'
WORKER_HASH='95413d06a4ed0c849b23de5bd2923ee6a79b7d4c79f8f427386a5f8257748078'
SESSION_HASH='dfa6bba5b44308576131bee5bf655ba14d5c3e503dc338b75ebbbdd5331114fc'
ADMISSION_HASH='78aaf923b6d868362a810fc3574cab64031987d41b48b60ba9acd8bcaa3b8a52'
DATABASE_HASH='2c55b26774660d1e56d6855b5425c18b2cc26a6ab09da463fe324229b744094c'
CLAIM='chatbot-file-cohort-verified-backup-recovery-'+AUTHORITY+'.claim.json'
LATER_HASHES={'authorization':'713c6d0637daee56c908b5efe6f8d436135f9696ff14d14addc1c7a46b9d6cce',
 'containers':'c08aef9f2c4bdef7bfed2018ccda5c708d05f8772bf98cda27319290c095c776',
 'gateway':'323a53a263eb9cdb87126f956da871632e20258fe999d2dfe03f5753b945ad30'}
ARCHIVES={'udp':(247357,'5f4a048ae5ebd3b752fc346b5fceaedd8011be4d5f548746a1cbcfdc2318e714'),
 'onboarding':(325831,'7a1871458b0d4e58bda32ef069996332ede8fbb2b9f0a87f45484098118ec831'),
 'ingestion':(94318,'2f185509a9404fb8f6bffa5ca0f706b32f122b0adbf19d5414a3a195f28ec373'),
 'mcp':(0,hashlib.sha256(b'').hexdigest())}


def validate_worker(first,worker,admission,session):
    require(digest(first)==original.FIRST_HASH and worker.get('state')=='CANCELLED'
        and worker.get('attempts')==worker.get('publicationCount')==1
        and worker.get('controlledPredecessorGrantAttempts')==4 and worker.get('controlledCumulativeGrantAttempts')==5
        and worker.get('firstGrantReceiptHash')==digest(first) and worker.get('workerSessionHash')==digest(session)
        and admission.get('state')=='BLOCKED' and admission.get('version')==3
        and session.get('schema')=='ouf.policy-token-new-finite-worker-session.v4'
        and session.get('predecessorGrantAttempts')==4
        and session.get('controlledHistoryProfile')==worker.get('controlledHistoryProfile')=='ouf.policy-token-cancelled-worker-continuation.v1'
        and session.get('predecessorFirstGrantOperation')==first['operation']
        and session.get('predecessorFirstGrantScopeHash')==first['scopeHash'],
        'BACKUP_RECOVERY_CANCELLED_WORKER_CUMULATIVE_FIVE_REQUIRED')


def validate_boundary(row,prepared):
    signed.verify_successor_transition(row,{'postGrantRecovery':prepared['postGrantRecovery'],
        'creationRequestHash':digest(prepared['registry']['creationRequest']),
        'phaseIntentHashes':{k:digest(v) for k,v in prepared['registry']['intents'].items()}},AUTHORITY)
    require(row.get('version')==29 and row.get('nextPhase')==10 and row.get('state')=='READY'
        and len(row.get('effects',[]))==10 and all(e['state']=='APPLIED' for e in row['effects'])
        and [e['phase'] for e in row['effects']]==list(PHASES[:10])
        and row.get('databaseMayHaveChanged') is True and row.get('applicationWritesMayHaveOccurred') is True,
        'EXACT_VERIFIED_REGISTRY_TEN_EFFECTS_REQUIRED')
    return copy.deepcopy(row)


def validate_databases(row,plan):
    require(digest(row)==DATABASE_HASH and row.get('planHash')==digest(plan) and row.get('authorityHash')==AUTHORITY
        and row.get('mcpMigration') is None and row.get('mcpAuditRole') is None
        and row.get('restorePerformed') is False and row.get('budgetReset') is False
        and set(row.get('backups',{}))==set(ARCHIVES),'EXACT_UNMIGRATED_DATABASE_BACKUP_BOUNDARY_REQUIRED')
    for module,(size,hashed) in ARCHIVES.items():
        item=row['backups'][module];binding=next(r for r in plan['modules'] if r['module']==module)
        require(item.get('scopeHash')==digest(binding),'BACKUP_RECOVERY_DATABASE_BINDING_DRIFT')
        if module=='mcp':
            require(item=={'state':'CLAIMED','scopeHash':digest(binding)},'EXACT_EMPTY_MCP_CLAIM_REQUIRED')
        else:
            require(item=={'state':'COMPLETE','scopeHash':digest(binding),'archiveBytes':size,
                'archiveSha256':hashed,'payloadParsed':True},'EXACT_COMPLETE_RETAINED_ARCHIVE_REQUIRED')


def archive_bytes(root,module,consume=None):
    """Read/copy bounded archives without following symlinks or changing them."""
    size,hashed=ARCHIVES[module]
    with protected_directory(root) as directory:
        fd=os.open(module+'.dump',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
        try:
            before=os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0
                and stat.S_IMODE(before.st_mode)==0o600 and before.st_nlink==1 and before.st_size==size,
                'RETAINED_ARCHIVE_CUSTODY_OR_SIZE_DRIFT')
            fingerprint=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_mode,s.st_nlink)
            h=hashlib.sha256();count=0
            while True:
                chunk=os.read(fd,65536)
                if not chunk:break
                count+=len(chunk);require(count<=size,'RETAINED_ARCHIVE_GREW');h.update(chunk)
                if consume is not None:consume(chunk)
            require(count==size and h.hexdigest()==hashed
                and fingerprint(before)==fingerprint(os.fstat(fd))==fingerprint(os.stat(module+'.dump',dir_fd=directory,follow_symlinks=False)),
                'RETAINED_ARCHIVE_HASH_OR_IDENTITY_DRIFT')
        finally:os.close(fd)


def read_predecessor():
    prior=signed.read_predecessor();root=evidence.PARENT/CONTEXT;bindings=copy.deepcopy(prior['recordBindings'])
    def read(path,expected=None,maximum=262144):
        value,binding=observed_private_json(path,maximum)
        require(expected is None or binding['sha256']==expected,'BACKUP_RECOVERY_PINNED_RECORD_DRIFT')
        bindings.append(binding);return value
    review=read(root/'review.json',REVIEW,8388608);authority=read(root/'authority.json',AUTHORITY,131072)
    require(review['sourceClosure']['declaration']['sourceCommit']==SOURCE
        and all(authority.get(k)==v for k,v in review['scopes'].items()),'EXACT_BACKUP_FAILED_SOURCE_AND_AUTHORITY_REQUIRED')
    decision=read(root/'decision.json')
    require(decision.get('approvedReviewHash')==REVIEW and decision.get('approvedSourceClosureHash')==review['sourceClosureHash']
        and decision.get('decision')=='APPROVE_ONE_FINITE_CHATBOT_FILE_COHORT_ACTION' and decision.get('state')=='ACTIVE'
        and decision.get('expiresAt')==authority['expiresAt']<=time.time(),'BACKUP_PREDECESSOR_WINDOW_MUST_BE_EXPIRED')
    process=review['scopes']['finiteActionProcess'];require(process['authorityDirectory']==str(root),'EXACT_BACKUP_RECOVERY_CONTEXT_REQUIRED')
    original.stopped_process(process,review['sourceClosure']['executables']['systemctl'])
    status=read(root/'delivery-status.json')
    require(status.get('phase')=='PAUSED_REQUIRES_RECONCILIATION' and status.get('reason')=='COHORT_DATABASE_DUMP_FAILED'
        and status.get('authorityHash')==AUTHORITY,'EXACT_BACKUP_FAILURE_REQUIRED')
    claim=read(evidence.PARENT/signed.CLAIM)
    require(claim.get('authorityHash')==AUTHORITY and claim.get('state')=='CONTINUATION_RESERVED_NO_AUTOMATIC_REPLAY',
        'PREVIOUS_SIGNED_CONTINUATION_MUST_REMAIN_CONSUMED')
    b=process['bundle'];bundle=read(b['path'],b['sha256'],8388608);prepared=bundle['prepared']
    require(bundle['declaration']==review['sourceClosure']['declaration'] and digest(prepared)==review['privateInputHashes']['preparedInputs']
        and prepared['postGrantRecovery']['profile']==signed.PROFILE,'EXACT_BACKUP_PREDECESSOR_BUNDLE_REQUIRED')
    paths=prepared['registry']['directoryPlan'];row=read(Path(paths['transition'])/'recovery.json',TRANSITION_HASH);validate_boundary(row,prepared)
    owner=Path(review['scopes']['policyTokenOwnerInstallation']['journalPath'])
    worker=read(owner/'recovery.json',WORKER_HASH);session=read(owner/'owner-session.json',SESSION_HASH);admission=read(owner/'owner-admission.json',ADMISSION_HASH)
    require(read(owner/'owner-first-grant.json',original.FIRST_HASH)==prior['firstGrant'],'SAME_ORIGINAL_FIRST_GRANT_REQUIRED')
    validate_worker(prior['firstGrant'],worker,admission,session)
    require(session==review['scopes']['policyTokenFiniteWorkerSession'] and worker['bootId']==prior['firstGrant']['bootId']
        and read(owner/'owner-predecessor-worker.json',signed.WORKER_HASH)==prior['worker']
        and read(owner/'owner-predecessor-session.json',signed.SESSION_HASH)==prior['session'],'COMPLETE_FIVE_GRANT_HISTORY_REQUIRED')
    payloads=copy.deepcopy(prior['payloads']);payloads['evidence']={}
    for effect in row['effects']:
        phase=effect['phase'];payloads['evidence'][phase]=read(Path(paths['evidence'])/(phase+'.json'),effect['nativeEvidenceHash'])
    release=payloads['evidence']['START_REPLACEMENT']
    payloads['before']['START_REPLACEMENT']=read(Path(paths['before'])/'START_REPLACEMENT.json',release['beforeEvidenceHash'])
    node=Path(paths['node'])
    require(set(os.listdir(node))=={'frame-policy.json','paused-acceptance.json','attestation-issuance-claim.json'},'EXACT_RETAINED_NODE_RECORDS_REQUIRED')
    policy=read(node/'frame-policy.json','b0dcfe550339c7484e5d4e48ce11b48b1c1b87a823030bcd9726569376b7c049',131072)
    acceptance=read(node/'paused-acceptance.json','bc3f9752d70b4359d37fad063a2d7da8ca2336ed4e3527205c438de754de53e5',131072)
    issuance=read(node/'attestation-issuance-claim.json','0193e47906ab85e9ecc428003ac317298b7e8bbaba26a12c552c382745e81ef5')
    read(root/(digest(acceptance)+'.CREATION_ATTESTATION.json'))
    require(acceptance.get('expiresAt')==authority['expiresAt'] and issuance.get('authorizationHash')==digest(acceptance)
        and acceptance.get('containerId')==original.CREATED_ID,'HISTORICAL_ATTESTATION_BINDING_DRIFT')
    for label,pin in LATER_HASHES.items():
        value=read(Path(process['directoryPlan'][label])/'recovery.json',pin)
        require(not value.get('effects') and not value.get('nextStep',0),'BACKUP_RECOVERY_LATER_EFFECT_REQUIRES_DIFFERENT_PLAN')
    database=read(Path(process['directoryPlan']['databases'])/'recovery.json',DATABASE_HASH)
    validate_databases(database,prepared['databasePlan']);backup_root=process['directoryPlan']['backups']
    for module in ARCHIVES:archive_bytes(backup_root,module)
    return {**prior,'recoveryProfile':PROFILE,'signedPredecessor':prior,'review':review,'prepared':prepared,'authority':authority,
        'transition':row,'bundle':bundle,'worker':worker,'session':session,'admission':admission,'payloads':payloads,
        'recordBindings':bindings,'failedPolicy':policy,'databaseJournal':database,'backupRoot':backup_root}


def proof_scope(previous,actor):
    base=signed.proof_scope(previous['signedPredecessor'],actor)
    # Old reprocessing fields remain historical only, nested in the immutable
    # prior transition. The new proof describes exactly ten completed effects.
    return {**base,'profile':PROFILE,'backupPredecessorSource':SOURCE,'backupPredecessorAuthorityHash':AUTHORITY,
        'backupPredecessorReviewHash':REVIEW,'predecessorTransitionHash':TRANSITION_HASH,
        'appliedPrefixHash':digest(previous['transition']['effects']),'appliedPrefixPhaseCount':10,
        'cancelledWorkerHash':WORKER_HASH,'workerSessionHash':SESSION_HASH,
        'databaseJournalHash':DATABASE_HASH,'retainedCohortBackupDirectory':previous['backupRoot'],
        'originalDatabasePlanHash':digest(previous['prepared']['databasePlan']),
        'recordBindings':copy.deepcopy(previous['recordBindings']),
        'runningRootfsQualification':copy.deepcopy(RUNNING_ROOTFS_QUALIFICATION),
        'newBudget':{'actor':copy.deepcopy(actor),'reason':'EXPLICIT_MCP_BACKUP_READER_AND_VERIFIED_REGISTRY_CONTINUATION',
            'decisionRef':'CURRENT_EXACT_FULL_ACTION_HUMAN_DECISION','priorControlledGrantAttempts':5,
            'priorWorkerGrantAttempts':1,'maximumNewWorkerAttempts':128,'maximumSeconds':3600,'automaticRenewalAllowed':False},
        'registryPhaseReplayAllowed':False,'newNodeAttestationAllowed':False,'databaseRestoreAllowed':False,
        'newAdmissionRequiresFreshOwnerFencedBackupMatch':False,
        'completeArchivesRetained':3,'failedMcpArchiveRetained':True,'newMcpArchiveMaximumAttempts':1}


def retained_bindings(proof):
    require(proof.get('profile')==PROFILE and proof.get('backupPredecessorAuthorityHash')==AUTHORITY
        and proof.get('backupPredecessorReviewHash')==REVIEW and proof.get('predecessorTransitionHash')==TRANSITION_HASH
        and proof.get('cancelledWorkerHash')==WORKER_HASH and proof.get('workerSessionHash')==SESSION_HASH
        and proof.get('databaseJournalHash')==DATABASE_HASH and proof.get('newBudget',{}).get('priorControlledGrantAttempts')==5
        and proof.get('registryPhaseReplayAllowed') is False and proof.get('newNodeAttestationAllowed') is False
        and proof.get('runningRootfsQualification')==RUNNING_ROOTFS_QUALIFICATION
        and proof.get('oldAuthorityExtended') is False,'EXACT_VERIFIED_BACKUP_RECOVERY_PROOF_REQUIRED')
    for binding in proof['recordBindings']:private_file(binding,8388608)
    for module in ARCHIVES:archive_bytes(proof['retainedCohortBackupDirectory'],module)


def verify_successor_transition(row,scope,authority_hash):
    proof=scope['postGrantRecovery'];marker=row.get('governedVerifiedRegistryContinuation',{})
    require(proof.get('profile')==PROFILE and proof.get('backupPredecessorAuthorityHash')==AUTHORITY
        and proof.get('predecessorTransitionHash')==TRANSITION_HASH
        and row.get('contextHash')==proof['transitionContextHash']
        and row.get('transitionAuthorityEvidenceHash')==original.AUTHORITY
        and row.get('creationRequestHash')==scope['creationRequestHash']
        and row.get('nextPhase',-1)>=10 and row.get('version',0)>=30
        and row.get('databaseMayHaveChanged') is True and row.get('applicationWritesMayHaveOccurred') is True
        and row.get('automaticReplayAllowed') is False and row.get('preMigrationRestoreAllowed') is False
        and len(row.get('effects',[]))>=10 and digest(row['effects'][:10])==proof['appliedPrefixHash']
        and all(e.get('state')=='APPLIED' for e in row['effects'][:10])
        and all(e.get('phase')=='RELEASE_PRODUCERS' and e.get('authorityEvidenceHash')==authority_hash
            and e.get('intentHash')==scope['phaseIntentHashes']['RELEASE_PRODUCERS'] for e in row['effects'][10:])
        and marker=={'schema':PROFILE,'predecessorJournalHash':TRANSITION_HASH,'proofHash':digest(proof),
            'newAuthorityHash':authority_hash,'historicalEffectsRetained':10,'automaticReplayAllowed':False},
        'VERIFIED_REGISTRY_HISTORY_OR_CURRENT_AUTHORITY_DRIFT')


def seed_registry(previous,directories,action,scope):
    action.guard('applicationRegistryCutover',scope);proof=scope['postGrantRecovery'];retained_bindings(proof)
    seed=validate_boundary(previous['transition'],previous['prepared'])
    require(digest(seed)==TRANSITION_HASH,'VERIFIED_REGISTRY_PREDECESSOR_CHANGED')
    old=previous['prepared']['registry']['intents']
    require(all(scope['phaseIntentHashes'][p]==digest(old[p]) for p in PHASES[:10] if p!='ATTEST_NEW_OCI_PEER'),
        'VERIFIED_REGISTRY_CONSUMED_INTENT_CHANGED')
    seed['version']+=1
    seed['governedVerifiedRegistryContinuation']={'schema':PROFILE,'predecessorJournalHash':TRANSITION_HASH,
        'proofHash':digest(proof),'newAuthorityHash':action.authority_hash,'historicalEffectsRetained':10,'automaticReplayAllowed':False}
    verify_successor_transition(seed,scope,action.authority_hash)
    journal=Journal(directories['transition'])
    require(not any(os.path.lexists(journal.root/p) for p in ('recovery.json','recovery.lock','invocation.lock')),
        'VERIFIED_REGISTRY_NEW_JOURNAL_ALREADY_CONSUMED')
    for name,phases in previous['payloads'].items():
        store=NativeEvidenceStore(directories[name])
        for phase,value in phases.items():store.publish(phase,value)
    journal.initialize(seed);require(journal.read()==seed,'VERIFIED_REGISTRY_SEED_PUBLICATION_DRIFT');return journal


def adopt_backups(owner,previous,proof):
    """One successor journal: retain failed claim as history, copy three archives.

    A crash during copying blocks the successor; no overwrite/adoption retry.
    The stable ContinuationFence is consumed before entering this method.
    """
    from tools.chatbot_file_cohort.databases import CohortDatabases,compile_mcp_backup_reader
    require(type(owner) is CohortDatabases,'REAL_SIGNED_BACKUP_OWNER_REQUIRED')
    owner.guard();owner.quiescence();retained_bindings(proof)
    old=previous['databaseJournal'];validate_databases(old,previous['prepared']['databasePlan'])
    require(owner.plan==compile_mcp_backup_reader(previous['prepared']['databasePlan'],owner.plan['mcpBackupReader']['preflight'])
        and previous['backupRoot']==proof['retainedCohortBackupDirectory'] and str(owner.root)!=previous['backupRoot'],
        'EXACT_NEW_BACKUP_PLAN_AND_DISTINCT_DIRECTORY_REQUIRED')
    with owner.journal.invocation():
        initial=owner.record()
        require(initial['version']==1 and not initial['backups'] and initial['mcpMigration'] is None
            and initial['mcpAuditRole'] is None,'BACKUP_ADOPTION_ALREADY_CONSUMED')
        following=copy.deepcopy(initial);following['version']+=1
        following['governedBackupRecovery']={'profile':PROFILE,'predecessorJournalHash':DATABASE_HASH,
            'predecessorAuthorityHash':AUTHORITY,'predecessorPlanHash':old['planHash'],
            'retainedBackupDirectory':previous['backupRoot'],'failedMcpClaim':copy.deepcopy(old['backups']['mcp']),
            'failedMcpArchiveSha256':ARCHIVES['mcp'][1],'proofHash':digest(proof),'state':'COPY_CLAIMED'}
        owner.journal.compare_and_save(initial,following)
        for module in ('udp','onboarding','ingestion'):
            owner.guard();owner.quiescence()
            with protected_directory(owner.root) as directory:
                fd=os.open(module+'.dump',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
                with os.fdopen(fd,'wb') as stream:
                    archive_bytes(previous['backupRoot'],module,stream.write);stream.flush();os.fsync(stream.fileno())
                os.fsync(directory)
            binding=next(r for r in owner.plan['modules'] if r['module']==module)
            owner.verify_archive(binding,old['backups'][module])
        owner.guard();owner.quiescence();retained_bindings(proof)
        final=copy.deepcopy(following);final['version']+=1
        final['backups']={m:copy.deepcopy(old['backups'][m]) for m in ('udp','onboarding','ingestion')}
        final['governedBackupRecovery']['state']='COMPLETE_ARCHIVES_COPIED_NEW_MCP_ATTEMPT_REQUIRED'
        owner.journal.compare_and_save(following,final)


from cutover_executor import CutoverDenied


class RegistryRecoveryReadinessPending(CutoverDenied):
    def __init__(self,retry_after_seconds):
        super().__init__('VERIFIED_REGISTRY_CURRENT_READINESS_UNAVAILABLE')
        self.retry_after_seconds=retry_after_seconds


def current_registry(previous,engine,*,readiness=False):
    """Fresh read of the exact released generation; no historical health adoption."""
    from gated_process_observation import GatedProcessObservation
    from application_verification_adapter import ApplicationReadinessChannel
    require(type(engine) is Engine,'REAL_RUNNING_REGISTRY_ENGINE_REQUIRED')
    prepared=previous['prepared']['registry'];transition=SimpleNamespace(context=previous['transition']['contextHash'])
    release=previous['payloads']['evidence']['START_REPLACEMENT']
    verified=previous['payloads']['evidence']['VERIFY_APPLICATION']
    request=prepared['creationRequest'];process=GatedProcessObservation(request)
    def observe():
        actual=engine.matching_configuration(transition,request,engine.inspect(transition))
        require(actual['Id']==original.CREATED_ID and actual['RestartCount']==0
            and actual['State']['Running'] is True and actual['State']['Paused'] is False
            and actual['State']['Status']=='running' and Engine.runtime_binding(actual)==release['runtimeBinding']==verified['runtimeBinding'],
            'VERIFIED_REGISTRY_RUNNING_GENERATION_DRIFT')
        proc=process.observe(actual['State']['Pid'])
        require(proc['processKind']=='APPLICATION_RUNNING' and proc['generation']==release['generation'],
            'VERIFIED_REGISTRY_PROCESS_GENERATION_DRIFT')
        require(any(n.get('IPAddress')==prepared['readinessScope']['health']['address']
            for n in actual.get('NetworkSettings',{}).get('Networks',{}).values()),'VERIFIED_REGISTRY_HEALTH_ADDRESS_DRIFT')
        return Engine.runtime_binding(actual),proc
    before=observe();result={'runtimeBindingHash':digest(before[0]),'processHash':digest(before[1])}
    if readiness:
        channel=ApplicationReadinessChannel(prepared['readinessScope']);health=channel.health()
        if health is None:raise RegistryRecoveryReadinessPending(channel.retry_after_seconds)
        database=channel.database()
        require(channel.health()==health and channel.database()==database,'VERIFIED_REGISTRY_READINESS_CHANGED_DURING_READ')
        result.update(healthHash=digest(health),databaseHash=digest(database))
    require(observe()==before,'VERIFIED_REGISTRY_GENERATION_CHANGED_DURING_READ')
    return result


def current_databases(previous):
    from tools.chatbot_file_cohort.databases import observe_database,mcp_admin_preflight,mcp_backup_preflight
    plan=previous['prepared']['databasePlan'];cid=plan['postgresRuntimeBinding']['containerId']
    for row in plan['modules']:
        observed=observe_database(cid,row['user'],row['database'],row['module'])
        require(observed['identity']=={'name':row['database'],'oid':row['databaseOid'],'allowConnections':True,'prepared':0}
            and observed['migrations']==row['beforeMigrations'],'BACKUP_RECOVERY_DATABASE_HISTORY_CHANGED')
    mcp=next(r for r in plan['modules'] if r['module']=='mcp');admin=plan['mcpAuditRoleAdministration']['admin']
    require(mcp_admin_preflight(cid,mcp['database'],mcp['user'],admin)==plan['mcpAuditRolePreflight'],
        'BACKUP_RECOVERY_MIGRATION_ADMIN_PREFLIGHT_CHANGED')
    facts=mcp_backup_preflight(cid,mcp['database'],admin)
    require(facts['databaseOid']==mcp['databaseOid'],'BACKUP_RECOVERY_DATABASE_OID_CHANGED')
    return facts
