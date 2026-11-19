"""Governed phase-2 continuation: four retained backups, one existing MCP start.

Preserve all predecessor history and six grants. No backup/create/bootstrap replay.
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
from tools.chatbot_file_cohort import backup_recovery as prior
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.semantic_policy_token_owner.producer import protected_directory
from tools.chatbot_file_cohort.running_rootfs import QUALIFICATION as RUNNING_ROOTFS_QUALIFICATION

PROFILE='ouf.chatbot-created-mcp-migration-continuation.v1'
SOURCE='b93e3570bd3e43b6c8e99d2237743bb819e43304'
AUTHORITY='ce4fcdc3b0af1aaee503582f00af4beed06786641d15afe4a55efa0cd29584d7'
REVIEW='225d317b485939ebf2a5b2582d0f5168a5ff6fe19be17e0e68109c9003dade1c'
CONTEXT='chatbot-file-cohort-signed-f9616bc49b224fa219e6ea4b8c9ff5425f9728fda0bc2175d6d877ebb5189a9a'
TRANSITION_HASH='3726eaf05fa85c1b435f84e22bc23cf87a96c619d3abb96401d045c6b9e70960'
WORKER_HASH='28561e039c735d3d170ab4f598263e2f23ae9b20a67f22c8ea1f91481f395e27'
SESSION_HASH='3a7c2ec08553d6a6b656f87fc2d33826f0cb2f1d5ce64ae8472ec4950c318734'
ADMISSION_HASH='9b01e136046f052831f556a460d4e566a82881186789e7e961bed93e45952892'
DATABASE_HASH='7dd78763e8f39db90ddb6e42da0819c6b3ea245740701a08bcb1c16c620ae587'
MIGRATION_ID='e502ee4e5ebd13ca6cbc8857756d895668a06bd9ca4a44a0b27ed1b0232a12c6'
MIGRATION_RUNTIME='d326de2b5b370344db4161a38064067195fc3dd0db6a33224780708972d21561'
MIGRATION_INTENT='1c570194bc025ee4391efdb1ce53f16414194436bc80d6b589d1176d75f226b8'
STATUS_HASH='21ab6ef3f4e961135591faf876f2f554237e3f85785b7478dfd635e386295c52'
CLAIM='chatbot-file-cohort-created-migration-recovery-'+AUTHORITY+'.claim.json'
LATER_HASHES={'authorization':'d22c7869612e941da4139e47b84686e05d0267bf98e6c8634a979a2193630af9',
 'containers':'56b968fc8a4616626836afca3d5c2aee19175ec24f9079479b9844e9d8e8ccea',
 'gateway':'d419dffa9915f6c62b6eba589d30f21ecffd387f28d7cc3915b6e9ca9d87d5c3'}
ARCHIVES={'udp':(247357,'5f4a048ae5ebd3b752fc346b5fceaedd8011be4d5f548746a1cbcfdc2318e714'),
 'onboarding':(325831,'7a1871458b0d4e58bda32ef069996332ede8fbb2b9f0a87f45484098118ec831'),
 'ingestion':(94318,'2f185509a9404fb8f6bffa5ca0f706b32f122b0adbf19d5414a3a195f28ec373'),
 'mcp':(250874,'b050f7706b650199a09115e24828858de509179f26896c92072cab6ae9946dc4')}


def validate_worker(first,worker,admission,session):
    require(digest(first)==original.FIRST_HASH and worker.get('state')=='CANCELLED'
        and worker.get('attempts')==worker.get('publicationCount')==1
        and worker.get('controlledPredecessorGrantAttempts')==5 and worker.get('controlledCumulativeGrantAttempts')==6
        and worker.get('firstGrantReceiptHash')==digest(first) and worker.get('workerSessionHash')==digest(session)
        and admission.get('state')=='BLOCKED' and admission.get('version')==3
        and session.get('schema')=='ouf.policy-token-new-finite-worker-session.v5'
        and session.get('predecessorGrantAttempts')==5
        and session.get('controlledHistoryProfile')==worker.get('controlledHistoryProfile')=='ouf.policy-token-cancelled-worker-continuation.v1'
        and session.get('predecessorFirstGrantOperation')==first['operation']
        and session.get('predecessorFirstGrantScopeHash')==first['scopeHash'],
        'BACKUP_RECOVERY_CANCELLED_WORKER_CUMULATIVE_SIX_REQUIRED')


def validate_boundary(row,prepared):
    prior.verify_successor_transition(row,{'postGrantRecovery':prepared['postGrantRecovery'],
        'creationRequestHash':digest(prepared['registry']['creationRequest']),
        'phaseIntentHashes':{k:digest(v) for k,v in prepared['registry']['intents'].items()}},AUTHORITY)
    require(row.get('version')==30 and row.get('nextPhase')==10 and row.get('state')=='READY'
        and len(row.get('effects',[]))==10 and all(e['state']=='APPLIED' for e in row['effects'])
        and [e['phase'] for e in row['effects']]==list(PHASES[:10])
        and row.get('databaseMayHaveChanged') is True and row.get('applicationWritesMayHaveOccurred') is True,
        'EXACT_VERIFIED_REGISTRY_TEN_EFFECTS_REQUIRED')
    return copy.deepcopy(row)


def validate_databases(row,plan):
    require(digest(row)==DATABASE_HASH and row.get('planHash')==digest(plan) and row.get('authorityHash')==AUTHORITY
        and row.get('restorePerformed') is False and row.get('budgetReset') is False
        and set(row.get('backups',{}))==set(ARCHIVES),'EXACT_COMPLETED_BACKUP_BOUNDARY_REQUIRED')
    for module,(size,hashed) in ARCHIVES.items():
        binding=next(r for r in plan['modules'] if r['module']==module)
        require(row['backups'][module]=={'state':'COMPLETE','scopeHash':digest(binding),'archiveBytes':size,
            'archiveSha256':hashed,'payloadParsed':True},'EXACT_COMPLETE_RETAINED_ARCHIVE_REQUIRED')
    require(row.get('mcpMigration',{}).get('state')=='CLAIMED'
        and row['mcpMigration']['intentHash']==MIGRATION_INTENT
        and row.get('mcpAuditRole',{}).get('state')=='BOOTSTRAPPED','EXACT_PRE_START_MIGRATION_CHECKPOINT_REQUIRED')


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
    previous=prior.read_predecessor();root=evidence.PARENT/CONTEXT;bindings=copy.deepcopy(previous['recordBindings'])
    def read(path,expected=None,maximum=262144):
        value,binding=observed_private_json(path,maximum)
        require(expected is None or binding['sha256']==expected,'MIGRATION_RECOVERY_PINNED_RECORD_DRIFT')
        bindings.append(binding);return value
    review=read(root/'review.json',REVIEW,8388608);authority=read(root/'authority.json',AUTHORITY,131072)
    require(review['sourceClosure']['declaration']['sourceCommit']==SOURCE
        and all(authority.get(k)==v for k,v in review['scopes'].items()),'EXACT_MIGRATION_PREDECESSOR_AUTHORITY_REQUIRED')
    decision=read(root/'decision.json')
    require(decision.get('approvedReviewHash')==REVIEW and decision.get('approvedSourceClosureHash')==review['sourceClosureHash']
        and decision.get('decision')=='APPROVE_ONE_FINITE_CHATBOT_FILE_COHORT_ACTION' and decision.get('state')=='ACTIVE'
        and decision.get('expiresAt')==authority['expiresAt'],'MIGRATION_PREDECESSOR_DECISION_DRIFT')
    # A stopped one-use process and cancelled worker are required even if the
    # old time window has not expired. No previous authority is exercised.
    process=review['scopes']['finiteActionProcess'];require(process['authorityDirectory']==str(root),'EXACT_MIGRATION_CONTEXT_REQUIRED')
    original.stopped_process(process,review['sourceClosure']['executables']['systemctl'])
    status=read(root/'delivery-status.json',STATUS_HASH)
    require(status.get('phase')=='PAUSED_REQUIRES_RECONCILIATION' and status.get('reason')=='MCP_MIGRATION_ROLE_NATIVE_IDENTITY_DRIFT'
        and status.get('authorityHash')==AUTHORITY,'EXACT_MIGRATION_FAILURE_REQUIRED')
    claim=read(evidence.PARENT/prior.CLAIM)
    require(claim.get('authorityHash')==AUTHORITY and claim.get('state')=='CONTINUATION_RESERVED_NO_AUTOMATIC_REPLAY',
        'PREVIOUS_CONTINUATION_MUST_REMAIN_CONSUMED')
    b=process['bundle'];bundle=read(b['path'],b['sha256'],8388608);prepared=bundle['prepared']
    require(bundle['declaration']==review['sourceClosure']['declaration'] and digest(prepared)==review['privateInputHashes']['preparedInputs']
        and prepared['postGrantRecovery']['profile']==prior.PROFILE,'EXACT_MIGRATION_PREDECESSOR_BUNDLE_REQUIRED')
    paths=prepared['registry']['directoryPlan'];row=read(Path(paths['transition'])/'recovery.json',TRANSITION_HASH);validate_boundary(row,prepared)
    owner=Path(review['scopes']['policyTokenOwnerInstallation']['journalPath'])
    worker=read(owner/'recovery.json',WORKER_HASH);session=read(owner/'owner-session.json',SESSION_HASH);admission=read(owner/'owner-admission.json',ADMISSION_HASH)
    require(read(owner/'owner-first-grant.json',original.FIRST_HASH)==previous['firstGrant'],'SAME_ORIGINAL_FIRST_GRANT_REQUIRED')
    validate_worker(previous['firstGrant'],worker,admission,session)
    require(session==review['scopes']['policyTokenFiniteWorkerSession'] and worker['bootId']==previous['firstGrant']['bootId']
        and read(owner/'owner-predecessor-worker.json',prior.WORKER_HASH)==previous['worker']
        and read(owner/'owner-predecessor-session.json',prior.SESSION_HASH)==previous['session'],'COMPLETE_SIX_GRANT_HISTORY_REQUIRED')
    payloads=copy.deepcopy(previous['payloads'])
    for effect in row['effects']:
        require(read(Path(paths['evidence'])/(effect['phase']+'.json'),effect['nativeEvidenceHash'])==payloads['evidence'][effect['phase']],
            'TEN_REGISTRY_NATIVE_EFFECTS_MUST_REMAIN_EXACT')
    for label,pin in LATER_HASHES.items():
        value=read(Path(process['directoryPlan'][label])/'recovery.json',pin)
        require(not value.get('effects') and not value.get('nextStep',0),'MIGRATION_RECOVERY_LATER_EFFECT_REQUIRES_DIFFERENT_PLAN')
    database=read(Path(process['directoryPlan']['databases'])/'recovery.json',DATABASE_HASH)
    validate_databases(database,prepared['databasePlan']);backup_root=process['directoryPlan']['backups']
    for module in ARCHIVES:archive_bytes(backup_root,module)
    return {**previous,'recoveryProfile':PROFILE,'backupPredecessor':previous,'review':review,'prepared':prepared,'authority':authority,
        'transition':row,'bundle':bundle,'worker':worker,'session':session,'admission':admission,'payloads':payloads,
        'recordBindings':bindings,'databaseJournal':database,'backupRoot':backup_root}


def proof_scope(previous,actor):
    base=prior.proof_scope(previous['backupPredecessor'],actor)
    migration=migration_observation(previous,Engine(previous['prepared']['engine']['socketPath'],tuple(previous['prepared']['engine']['socketBinding'])))
    # Old reprocessing fields remain historical only, nested in the immutable
    # prior transition. The new proof describes exactly ten completed effects.
    return {**base,**migration,'profile':PROFILE,'migrationPredecessorSource':SOURCE,'migrationPredecessorAuthorityHash':AUTHORITY,
        'migrationPredecessorReviewHash':REVIEW,'predecessorTransitionHash':TRANSITION_HASH,
        'appliedPrefixHash':digest(previous['transition']['effects']),'appliedPrefixPhaseCount':10,
        'cancelledWorkerHash':WORKER_HASH,'workerSessionHash':SESSION_HASH,
        'databaseJournalHash':DATABASE_HASH,'retainedCohortBackupDirectory':previous['backupRoot'],
        'originalDatabasePlanHash':digest(previous['prepared']['databasePlan']),
        'recordBindings':copy.deepcopy(previous['recordBindings']),
        'runningRootfsQualification':copy.deepcopy(RUNNING_ROOTFS_QUALIFICATION),
        'newBudget':{'actor':copy.deepcopy(actor),'reason':'EXPLICIT_CREATED_MCP_SINGLE_START_WITH_FOUR_RETAINED_BACKUPS',
            'decisionRef':'CURRENT_EXACT_FULL_ACTION_HUMAN_DECISION','priorControlledGrantAttempts':6,
            'priorWorkerGrantAttempts':1,'maximumNewWorkerAttempts':128,'maximumSeconds':3600,'automaticRenewalAllowed':False},
        'registryPhaseReplayAllowed':False,'newNodeAttestationAllowed':False,'databaseRestoreAllowed':False,
        'newAdmissionRequiresFreshOwnerFencedBackupMatch':False,
        'completeArchivesRetained':4,'failedMcpArchiveRetained':True,'newMcpArchiveMaximumAttempts':0,
        'migrationContainerId':MIGRATION_ID,'migrationRuntimeHash':MIGRATION_RUNTIME,'migrationIntentHash':MIGRATION_INTENT,
        'migrationCreateAllowed':False,'migrationStartMaximumAttempts':1}


def retained_bindings(proof):
    require(proof.get('profile')==PROFILE and proof.get('migrationPredecessorAuthorityHash')==AUTHORITY
        and proof.get('migrationPredecessorReviewHash')==REVIEW and proof.get('predecessorTransitionHash')==TRANSITION_HASH
        and proof.get('cancelledWorkerHash')==WORKER_HASH and proof.get('workerSessionHash')==SESSION_HASH
        and proof.get('databaseJournalHash')==DATABASE_HASH and proof.get('newBudget',{}).get('priorControlledGrantAttempts')==6
        and proof.get('registryPhaseReplayAllowed') is False and proof.get('newNodeAttestationAllowed') is False
        and proof.get('runningRootfsQualification')==RUNNING_ROOTFS_QUALIFICATION
        and proof.get('newMcpArchiveMaximumAttempts')==0 and proof.get('migrationCreateAllowed') is False
        and proof.get('migrationContainerId')==MIGRATION_ID and proof.get('migrationIntentHash')==MIGRATION_INTENT
        and proof.get('migrationStartMaximumAttempts')==1 and proof.get('oldAuthorityExtended') is False,'EXACT_VERIFIED_BACKUP_RECOVERY_PROOF_REQUIRED')
    for binding in proof['recordBindings']:private_file(binding,8388608)
    for module in ARCHIVES:archive_bytes(proof['retainedCohortBackupDirectory'],module)


def verify_successor_transition(row,scope,authority_hash):
    proof=scope['postGrantRecovery'];marker=row.get('governedCreatedMigrationContinuation',{})
    require(proof.get('profile')==PROFILE and proof.get('migrationPredecessorAuthorityHash')==AUTHORITY
        and proof.get('predecessorTransitionHash')==TRANSITION_HASH
        and row.get('contextHash')==proof['transitionContextHash']
        and row.get('transitionAuthorityEvidenceHash')==original.AUTHORITY
        and row.get('creationRequestHash')==scope['creationRequestHash']
        and row.get('nextPhase',-1)>=10 and row.get('version',0)>=31
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
    seed['governedCreatedMigrationContinuation']={'schema':PROFILE,'predecessorJournalHash':TRANSITION_HASH,
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
    """One successor copy of four COMPLETE archives and preserved DB checkpoints.

    No dump, migration create or bootstrap grant is issued here. Partial copies
    remain consumed and require reconciliation. Old files remain untouched.
    """
    from tools.chatbot_file_cohort.databases import CohortDatabases
    require(type(owner)is CohortDatabases,'REAL_SIGNED_DATABASE_OWNER_REQUIRED')
    owner.guard();owner.quiescence();retained_bindings(proof)
    guard_scope(owner,proof)
    old=previous['databaseJournal'];validate_databases(old,previous['prepared']['databasePlan'])
    require(owner.plan==previous['prepared']['databasePlan'] and previous['backupRoot']==proof['retainedCohortBackupDirectory']
        and str(owner.root)!=previous['backupRoot'],'EXACT_RETAINED_DATABASE_PLAN_REQUIRED')
    with owner.journal.invocation():
        initial=owner.record()
        require(initial['version']==1 and not initial['backups'] and initial['mcpMigration'] is None
            and initial['mcpAuditRole'] is None,'MIGRATION_ADOPTION_ALREADY_CONSUMED')
        following=copy.deepcopy(initial);following['version']+=1
        following['governedMigrationRecovery']={'profile':PROFILE,'predecessorJournalHash':DATABASE_HASH,
            'predecessorAuthorityHash':AUTHORITY,'proofHash':digest(proof),'state':'COPY_CLAIMED','startState':'NOT_CLAIMED'}
        owner.journal.compare_and_save(initial,following)
        for module in ARCHIVES:
            owner.guard();owner.quiescence()
            with protected_directory(owner.root)as directory:
                fd=os.open(module+'.dump',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
                with os.fdopen(fd,'wb')as stream:
                    archive_bytes(previous['backupRoot'],module,stream.write);stream.flush();os.fsync(stream.fileno())
                os.fsync(directory)
            binding=next(r for r in owner.plan['modules'] if r['module']==module)
            owner.verify_archive(binding,old['backups'][module])
        owner.guard();owner.quiescence();retained_bindings(proof)
        final=copy.deepcopy(following);final['version']+=1
        final.update(backups=copy.deepcopy(old['backups']),mcpMigration=copy.deepcopy(old['mcpMigration']),mcpAuditRole=copy.deepcopy(old['mcpAuditRole']))
        final['governedMigrationRecovery']['state']='COMPLETE_ARCHIVES_AND_CHECKPOINTS_COPIED'
        owner.journal.compare_and_save(following,final)


def migration_observation(previous,engine):
    from tools.chatbot_file_cohort.migration_native import request_for,native_matches,created,immutable_native
    from image_custody import loaded,runtime_image_id
    name,request=request_for(previous['prepared']['cohortPlan'])
    require(digest(request)==MIGRATION_INTENT and previous['databaseJournal']['mcpMigration']['name']==name,
        'ORIGINAL_MIGRATION_INTENT_MUST_REMAIN_EXACT')
    audit=next(r['audit'] for r in previous['prepared']['imagePlan']['images'] if r['module']=='mcp')
    require(runtime_image_id(audit)==request['Image'],'MIGRATION_PACKAGED_IMAGE_DRIFT')
    code,image=engine.request('GET','/v1.44/images/'+request['Image']+'/json');require(code==200,'MIGRATION_IMAGE_ABSENT');loaded(audit,image)
    code,actual=engine.request('GET','/v1.44/containers/'+MIGRATION_ID+'/json');require(code==200,'MIGRATION_CREATED_CONTAINER_ABSENT')
    native_matches(name,request,audit['imageConfig'],actual);created(actual)
    require(actual['Id']==MIGRATION_ID and digest(Engine.runtime_binding(actual))==MIGRATION_RUNTIME,
        'EXACT_RETAINED_MIGRATION_NATIVE_HASH_REQUIRED')
    return {'migrationImageAudit':copy.deepcopy(audit),'migrationNativeBinding':immutable_native(actual)}


def current_databases(previous):
    from tools.chatbot_file_cohort.databases import observe_database,incident_metadata
    from database_gate import Psql
    plan=previous['prepared']['databasePlan'];cid=plan['postgresRuntimeBinding']['containerId']
    for row in plan['modules']:
        state=observe_database(cid,row['user'],row['database'],row['module'])
        require(state['identity']=={'name':row['database'],'oid':row['databaseOid'],'allowConnections':True,'prepared':0}
            and state['migrations']==row['beforeMigrations'],'MIGRATION_RECOVERY_DATABASE_HISTORY_CHANGED')
    row=next(r for r in plan['modules'] if r['module']=='mcp')
    from tools.chatbot_file_cohort.databases import CohortDatabases
    owner=CohortDatabases.__new__(CohortDatabases);owner.plan=plan
    state=owner.audit_role_state(row)
    require(state['roleExists'] is True and state['noLogin'] is True and state['schemaCreate'] is True
        and state['membershipCount']==state['appMembership']==1 and state['functionOwnerCount']==0,
        'RETAINED_BOOTSTRAPPED_AUDIT_ROLE_CHANGED')
    owner.incident_state(state,True)
    return {'databaseOid':row['databaseOid'],'retainedAuditRoleVerified':True}


def guard_scope(owner,proof):
    import json
    scope=json.loads(owner.action.raw)['applicationRegistryCutover']
    require(scope.get('postGrantRecovery')==proof and proof.get('profile')==PROFILE
        and owner.plan_hash==proof['originalDatabasePlanHash'],'EXACT_MIGRATION_CONTINUATION_SCOPE_REQUIRED')
    owner.action.guard('applicationRegistryCutover',scope)
    return proof


def native(owner,request,name,actual):
    import json
    from tools.chatbot_file_cohort.migration_native import native_matches,immutable_native
    from image_custody import loaded,runtime_image_id
    proof=json.loads(owner.action.raw)['applicationRegistryCutover']['postGrantRecovery'];guard_scope(owner,proof)
    require(proof['migrationContainerId']==MIGRATION_ID and proof['migrationIntentHash']==digest(request)==MIGRATION_INTENT
        and actual['Id']==MIGRATION_ID,'CURRENT_MIGRATION_IDENTITY_REQUIRED')
    audit=proof['migrationImageAudit'];require(runtime_image_id(audit)==request['Image'],'CURRENT_MIGRATION_IMAGE_REQUIRED')
    code,image=owner.engine.request('GET','/v1.44/images/'+request['Image']+'/json')
    require(code==200,'MIGRATION_IMAGE_ABSENT');loaded(audit,image)
    native_matches(name,request,audit['imageConfig'],actual)
    require(immutable_native(actual)==proof['migrationNativeBinding'],'MIGRATION_FULL_NATIVE_CONFIGURATION_CHANGED')
    return actual


def start_existing(owner,request,name,actual,current):
    """Durable one-start reservation. Ambiguous or consumed start is never replayed."""
    import json
    from tools.chatbot_file_cohort.migration_native import created
    proof=json.loads(owner.action.raw)['applicationRegistryCutover']['postGrantRecovery'];guard_scope(owner,proof)
    owner.guard();owner.quiescence();retained_bindings(proof)
    previous=owner.record();marker=previous['governedMigrationRecovery']
    require(marker['proofHash']==digest(proof) and marker['predecessorJournalHash']==DATABASE_HASH
        and marker['predecessorAuthorityHash']==AUTHORITY and marker['profile']==PROFILE,
        'MIGRATION_START_REVIEW_BINDING_DRIFT')
    if marker['startState']!='NOT_CLAIMED':
        require(marker['startState'] in ('START_CLAIMED','START_OBSERVED')
            and actual['State']['Status'] in ('running','exited'),'MIGRATION_START_CONSUMED_RECONCILE_NO_REPLAY')
        return
    native(owner,request,name,actual);created(actual)
    require(digest(Engine.runtime_binding(actual))==MIGRATION_RUNTIME
        and current()==next(r for r in owner.plan['modules'] if r['module']=='mcp')['beforeMigrations'],
        'MIGRATION_PRE_START_NATIVE_OR_HISTORY_DRIFT')
    following=copy.deepcopy(previous);following['version']+=1
    following['governedMigrationRecovery'].update(startState='START_CLAIMED',startAttempts=1,containerId=MIGRATION_ID)
    owner.journal.compare_and_save(previous,following)
    owner.guard();owner.quiescence();guard_scope(owner,proof)
    code,again=owner.engine.request('GET','/v1.44/containers/'+MIGRATION_ID+'/json')
    require(code==200,'MIGRATION_PRE_START_READ_UNAVAILABLE')
    native(owner,request,name,again);created(again)
    require(digest(Engine.runtime_binding(again))==MIGRATION_RUNTIME,'MIGRATION_PRE_START_GENERATION_CHANGED')
    code,_=owner.engine.request('POST','/v1.44/containers/'+MIGRATION_ID+'/start')
    require(code==204,'MCP_MIGRATION_START_REQUIRES_RECONCILIATION')
    observed=copy.deepcopy(following);observed['version']+=1
    observed['governedMigrationRecovery']['startState']='START_OBSERVED'
    owner.journal.compare_and_save(following,observed)
