"""Exact phase-5 retained boundary. Historical hashes are incident bindings.

No installer defaults, authority issuance or runtime effects at import. The
profile is a qualification candidate; no operational launcher is released here.
"""
import copy
import os
from pathlib import Path

import iam_binding_candidate as evidence
from engine_creation import Engine
from file_only_profile import PHASES
from native_evidence_store import NativeEvidenceStore
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.semantic_policy_token_owner.producer import protected_directory
from tools.chatbot_file_cohort.plan import digest, require
from tools.chatbot_file_cohort.action_process import observed_private_json, private_file
from tools.chatbot_file_cohort import postgrant_recovery as original, migration_recovery as prior
from tools.chatbot_file_cohort.running_rootfs import QUALIFICATION as RUNNING_ROOTFS_QUALIFICATION

PROFILE='ouf.chatbot-gateway-schema-continuation.v1'
SOURCE='70af66b26d9a8dfdd7151c55f44eb5795fcc84a8'
AUTHORITY='0e3a1a76b5528704c3295eff50c92b269a4f69c7d5eeff3304b193e991b54cb8'
REVIEW='bd2cbc1e969bf3eb4c5b1b54240cf1d67d3283685bc1ca563f893d17e3430144'
CONTEXT='chatbot-file-cohort-signed-35d5c6c756feb9c4811ac6d24610698a10c82d22b831d2cc85cd5c22c94d40d5'
TRANSITION_HASH='1dc7e2b1d62d83b3d579250a661a378b2b50ec48b191e20ab7bad7b66bfa50a3'
WORKER_HASH='c1c7c1cf95c6284cbfffde90a1dd85fa14b0fc658285d0d139866b2e864068c4'
SESSION_HASH='191221d3f12268c9f796ebf3dc7e375fef9eb7b1aae0d462d7cd0051530225db'
ADMISSION_HASH='9b611d47442d13b1db53e2b98104849e39ea4a8c7a83a5f13a8f58d74670bdde'
DATABASE_HASH='94e74ee186fe054aa223808420d6e6aee018ca14f71b9c61934ec049de90a5bc'
STATUS_HASH='092c8a0f8f34ba5e672c9d53a90d07b147977410042c5678cedf777870ba8e36'
CONTAINERS_HASH='33013baf1b86fc7600e580c1d9da924301c98035d91fefd22486eeb998e73492'
GATEWAY_HASH='9d1c903c6290dca22c28c601ccfda33f440d06f6079ff7e7d104584c99b6a515'
AUTHORIZATION_HASH='d893c26a7130f12241c7b207239cb549144944c7d7c2c4b578de1201d5994936'
GATEWAY_RUNTIME_HASH='a0be8b1ebc999b5ede3f71f154d937257b5c9e7e66d7b52c3fa58afed3d52ea4'
CLAIM='chatbot-file-cohort-gateway-schema-recovery-'+AUTHORITY+'.claim.json'
ARCHIVES=prior.ARCHIVES


def validate_worker(first,worker,admission,session):
    require(digest(first)==original.FIRST_HASH and digest(worker)==WORKER_HASH
        and digest(admission)==ADMISSION_HASH and digest(session)==SESSION_HASH
        and worker.get('state')=='CANCELLED' and worker.get('attempts')==worker.get('publicationCount')==2
        and worker.get('controlledPredecessorGrantAttempts')==6 and worker.get('controlledCumulativeGrantAttempts')==8
        and worker.get('firstGrantReceiptHash')==digest(first) and worker.get('workerSessionHash')==digest(session)
        and admission.get('state')=='BLOCKED' and admission.get('version')==5
        and session.get('schema')=='ouf.policy-token-new-finite-worker-session.v6'
        and session.get('predecessorGrantAttempts')==6
        and session.get('controlledHistoryProfile')==worker.get('controlledHistoryProfile')=='ouf.policy-token-cancelled-worker-continuation.v1'
        and session.get('predecessorFirstGrantOperation')==first['operation']
        and session.get('predecessorFirstGrantScopeHash')==first['scopeHash'],
        'GATEWAY_CANCELLED_WORKER_CUMULATIVE_EIGHT_REQUIRED')


def validate_boundary(row,prepared):
    prior.verify_successor_transition(row,{'postGrantRecovery':prepared['postGrantRecovery'],
        'creationRequestHash':digest(prepared['registry']['creationRequest']),
        'phaseIntentHashes':{k:digest(v) for k,v in prepared['registry']['intents'].items()}},AUTHORITY)
    require(digest(row)==TRANSITION_HASH and row.get('version')==31 and row.get('nextPhase')==10
        and row.get('state')=='READY' and len(row.get('effects',[]))==10
        and [e['phase'] for e in row['effects']]==list(PHASES[:10])
        and all(e['state']=='APPLIED' for e in row['effects']), 'GATEWAY_RETAINED_REGISTRY_PREFIX_REQUIRED')
    return copy.deepcopy(row)


def validate_databases(row,plan):
    require(digest(row)==DATABASE_HASH and row.get('planHash')==digest(plan) and row.get('authorityHash')==AUTHORITY
        and row.get('restorePerformed')is False and row.get('budgetReset')is False
        and set(row.get('backups',{}))==set(ARCHIVES), 'GATEWAY_COMPLETED_DATABASE_CHECKPOINT_REQUIRED')
    for module,(size,hashed) in ARCHIVES.items():
        binding=next(r for r in plan['modules'] if r['module']==module)
        require(row['backups'][module]=={'state':'COMPLETE','scopeHash':digest(binding),'archiveBytes':size,
            'archiveSha256':hashed,'payloadParsed':True}, 'GATEWAY_COMPLETE_RETAINED_ARCHIVE_REQUIRED')
    binding=next(r for r in plan['modules'] if r['module']=='mcp')
    require(row.get('mcpMigration',{}).get('state')=='COMPLETE'
        and row['mcpMigration']['intentHash']==prior.MIGRATION_INTENT
        and row['mcpMigration']['containerId']==prior.MIGRATION_ID
        and row['mcpMigration']['historyHash']==digest(binding['expectedMigrations'])
        and row.get('mcpAuditRole',{}).get('state')=='CLEAN', 'GATEWAY_MCP_COMPLETED_AND_CLEAN_REQUIRED')


def validate_containers(row,plan):
    from tools.chatbot_file_cohort.containers import STAGES
    require(digest(row)==CONTAINERS_HASH and row.get('planHash')==digest(plan)
        and row.get('authorityHash')==AUTHORITY and row.get('version')==30
        and row.get('nextStep')==10 and len(row.get('effects',[]))==10 and row.get('budgetReset')is False,
        'GATEWAY_TWO_COMPLETED_MODULES_REQUIRED')
    rows={r['module']:r for r in plan['replacements']}
    steps=[m+'.'+s for m in ('udp','onboarding') for s in STAGES]
    for step,effect in zip(steps,row['effects']):
        module,stage=step.split('.')
        require(effect.get('step')==step and effect.get('state')=='APPLIED'
            and effect.get('intentHash')==digest({'modulePlan':rows[module],'stage':stage})
            and type(effect.get('evidence'))is dict and effect.get('evidenceHash')==digest(effect['evidence']),
            'GATEWAY_COMPLETED_MODULE_EVIDENCE_DRIFT')


def read_predecessor():
    previous=prior.read_predecessor();root=evidence.PARENT/CONTEXT;bindings=copy.deepcopy(previous['recordBindings'])
    def read(path,expected=None,maximum=262144):
        value,binding=observed_private_json(path,maximum)
        require(expected is None or binding['sha256']==expected,'GATEWAY_RECOVERY_PINNED_RECORD_DRIFT')
        bindings.append(binding);return value
    review=read(root/'review.json',REVIEW,8388608);authority=read(root/'authority.json',AUTHORITY,131072)
    require(review['sourceClosure']['declaration']['sourceCommit']==SOURCE
        and all(authority.get(k)==v for k,v in review['scopes'].items()),'GATEWAY_PREDECESSOR_AUTHORITY_REQUIRED')
    decision=read(root/'decision.json')
    require(decision.get('approvedReviewHash')==REVIEW and decision.get('approvedSourceClosureHash')==review['sourceClosureHash']
        and decision.get('decision')=='APPROVE_ONE_FINITE_CHATBOT_FILE_COHORT_ACTION' and decision.get('state')=='ACTIVE'
        and decision.get('expiresAt')==authority['expiresAt'],'GATEWAY_PREDECESSOR_DECISION_DRIFT')
    process=review['scopes']['finiteActionProcess'];require(process['authorityDirectory']==str(root),'EXACT_GATEWAY_CONTEXT_REQUIRED')
    original.stopped_process(process,review['sourceClosure']['executables']['systemctl'])
    status=read(root/'delivery-status.json',STATUS_HASH)
    require(status.get('phase')=='PAUSED_REQUIRES_RECONCILIATION'
        and status.get('reason')=='GATEWAY_WRITE_OUTCOME_UNPROVEN_NO_REPLAY'
        and status.get('authorityHash')==AUTHORITY,'EXACT_GATEWAY_PUBLICATION_FAILURE_REQUIRED')
    claim=read(evidence.PARENT/prior.CLAIM)
    require(claim.get('authorityHash')==AUTHORITY and claim.get('state')=='CONTINUATION_RESERVED_NO_AUTOMATIC_REPLAY',
        'PREVIOUS_MIGRATION_CONTINUATION_MUST_REMAIN_CONSUMED')
    b=process['bundle'];bundle=read(b['path'],b['sha256'],8388608);prepared=bundle['prepared']
    require(bundle['declaration']==review['sourceClosure']['declaration'] and digest(prepared)==review['privateInputHashes']['preparedInputs']
        and prepared['postGrantRecovery']['profile']==prior.PROFILE,'EXACT_GATEWAY_PREDECESSOR_BUNDLE_REQUIRED')
    paths=prepared['registry']['directoryPlan'];row=read(Path(paths['transition'])/'recovery.json',TRANSITION_HASH)
    validate_boundary(row,prepared)
    owner=Path(review['scopes']['policyTokenOwnerInstallation']['journalPath'])
    worker=read(owner/'recovery.json',WORKER_HASH);session=read(owner/'owner-session.json',SESSION_HASH)
    admission=read(owner/'owner-admission.json',ADMISSION_HASH)
    require(read(owner/'owner-first-grant.json',original.FIRST_HASH)==previous['firstGrant'],'SAME_ORIGINAL_FIRST_GRANT_REQUIRED')
    validate_worker(previous['firstGrant'],worker,admission,session)
    require(session==review['scopes']['policyTokenFiniteWorkerSession'] and worker['bootId']==previous['firstGrant']['bootId']
        and read(owner/'owner-predecessor-worker.json',prior.WORKER_HASH)==previous['worker']
        and read(owner/'owner-predecessor-session.json',prior.SESSION_HASH)==previous['session'],'COMPLETE_EIGHT_GRANT_HISTORY_REQUIRED')
    payloads=copy.deepcopy(previous['payloads'])
    for effect in row['effects']:
        require(read(Path(paths['evidence'])/(effect['phase']+'.json'),effect['nativeEvidenceHash'])==payloads['evidence'][effect['phase']],
            'TEN_REGISTRY_NATIVE_EFFECTS_MUST_REMAIN_EXACT')
    directory=process['directoryPlan']
    authorization=read(Path(directory['authorization'])/'recovery.json',AUTHORIZATION_HASH)
    require(not authorization.get('effects') and not authorization.get('nextStep',0),'UNEXPECTED_AUTHORIZATION_EFFECTS')
    containers=read(Path(directory['containers'])/'recovery.json',CONTAINERS_HASH)
    validate_containers(containers,prepared['cohortPlan'])
    gateway=read(Path(directory['gateway'])/'recovery.json',GATEWAY_HASH)
    require(gateway.get('planHash')==digest(prepared['gatewayPlan']) and gateway.get('authorityHash')==AUTHORITY
        and gateway.get('nextStep')==9 and len(gateway.get('effects',[]))==10,'GATEWAY_NINE_PLUS_CLAIM_REQUIRED')
    runtime_journal=read(Path(directory['gatewayRuntime'])/'recovery.json') if prepared.get('gatewayRuntimePlan')is not None else None
    database=read(Path(directory['databases'])/'recovery.json',DATABASE_HASH)
    validate_databases(database,prepared['databasePlan']);backup_root=directory['backups']
    for module in ARCHIVES:prior.archive_bytes(backup_root,module)
    return {**previous,'recoveryProfile':PROFILE,'migrationPredecessor':previous,'review':review,'prepared':prepared,
        'authority':authority,'transition':row,'bundle':bundle,'worker':worker,'session':session,'admission':admission,
        'payloads':payloads,'recordBindings':bindings,'databaseJournal':database,'backupRoot':backup_root,
        'containerJournal':containers,'gatewayJournal':gateway,'gatewayRuntimeJournal':runtime_journal}


def proof_scope(previous,actor):
    base=copy.deepcopy(previous['prepared']['postGrantRecovery'])
    for key in ('migrationImageAudit','migrationNativeBinding','migrationRuntimeHash'):
        base.pop(key,None)
    return {**base,'profile':PROFILE,'gatewayPredecessorSource':SOURCE,'gatewayPredecessorAuthorityHash':AUTHORITY,
        'gatewayPredecessorReviewHash':REVIEW,'predecessorTransitionHash':TRANSITION_HASH,
        'appliedPrefixHash':digest(previous['transition']['effects']),'appliedPrefixPhaseCount':10,
        'cancelledWorkerHash':WORKER_HASH,'workerSessionHash':SESSION_HASH,'databaseJournalHash':DATABASE_HASH,
        'containerJournalHash':CONTAINERS_HASH,'gatewayJournalHash':GATEWAY_HASH,
        'retainedCohortBackupDirectory':previous['backupRoot'],'originalDatabasePlanHash':digest(previous['prepared']['databasePlan']),
        'recordBindings':copy.deepcopy(previous['recordBindings']),
        'runningRootfsQualification':copy.deepcopy(RUNNING_ROOTFS_QUALIFICATION),
        'newBudget':{'actor':copy.deepcopy(actor),'reason':'EXPLICIT_GATEWAY_SCHEMA_AND_NUMERIC_COMPATIBILITY_REPROCESSING',
            'decisionRef':'CURRENT_EXACT_FULL_ACTION_HUMAN_DECISION','priorControlledGrantAttempts':8,
            'priorWorkerGrantAttempts':2,'maximumNewWorkerAttempts':128,'maximumSeconds':3600,'automaticRenewalAllowed':False},
        'registryPhaseReplayAllowed':False,'newNodeAttestationAllowed':False,'databaseRestoreAllowed':False,
        'completeArchivesRetained':4,'newMcpArchiveMaximumAttempts':0,'migrationCreateAllowed':False,
        'migrationStartMaximumAttempts':0,'auditBootstrapAllowed':False,'completedContainerEffectsRetained':10,
        'completedGatewayEffectsRetained':9,'unresolvedGatewayClaimRetained':True,'oldAuthorityExtended':False}


def retained_bindings(proof):
    require(proof.get('profile')==PROFILE and proof.get('gatewayPredecessorAuthorityHash')==AUTHORITY
        and proof.get('gatewayPredecessorSource')==SOURCE and proof.get('gatewayPredecessorReviewHash')==REVIEW
        and proof.get('predecessorTransitionHash')==TRANSITION_HASH and proof.get('cancelledWorkerHash')==WORKER_HASH
        and proof.get('workerSessionHash')==SESSION_HASH and proof.get('databaseJournalHash')==DATABASE_HASH
        and proof.get('containerJournalHash')==CONTAINERS_HASH and proof.get('gatewayJournalHash')==GATEWAY_HASH
        and proof.get('newBudget',{}).get('priorControlledGrantAttempts')==8
        and proof.get('registryPhaseReplayAllowed')is False and proof.get('newNodeAttestationAllowed')is False
        and proof.get('runningRootfsQualification')==RUNNING_ROOTFS_QUALIFICATION
        and proof.get('newMcpArchiveMaximumAttempts')==proof.get('migrationStartMaximumAttempts')==0
        and proof.get('migrationCreateAllowed')is False and proof.get('auditBootstrapAllowed')is False
        and proof.get('oldAuthorityExtended')is False,'EXACT_GATEWAY_RECOVERY_PROOF_REQUIRED')
    for binding in proof['recordBindings']:private_file(binding,8388608)
    for module in ARCHIVES:prior.archive_bytes(proof['retainedCohortBackupDirectory'],module)


def current_databases(previous):
    from tools.chatbot_file_cohort.databases import observe_database,CohortDatabases
    plan=previous['prepared']['databasePlan'];cid=plan['postgresRuntimeBinding']['containerId']
    for row in plan['modules']:
        state=observe_database(cid,row['user'],row['database'],row['module'])
        expected=row['beforeMigrations'] if row['module']=='ingestion' else row['expectedMigrations']
        require(state['identity']=={'name':row['database'],'oid':row['databaseOid'],'allowConnections':True,'prepared':0}
            and state['migrations']==expected,'GATEWAY_RECOVERY_DATABASE_HISTORY_CHANGED')
    row=next(r for r in plan['modules'] if r['module']=='mcp')
    owner=CohortDatabases.__new__(CohortDatabases);owner.plan=plan
    state=owner.audit_role_state(row)
    require(state['roleExists']is True and state['noLogin']is True and state['schemaCreate']is False
        and state['membershipCount']==state['appMembership']==0 and state['functionOwnerCount']==2,
        'GATEWAY_MCP_AUDIT_PRIVILEGES_NOT_CLEAN')
    owner.incident_state(state,False)
    return {'databaseOid':row['databaseOid'],'retainedAuditCleanupVerified':True}


def current_completed_containers(previous,engine):
    from tools.chatbot_file_cohort.containers import CohortContainers
    validate_containers(previous['containerJournal'],previous['prepared']['cohortPlan'])
    # Only established read-only predicates are used; this object has no action
    # or journal and cannot claim or execute a lifecycle effect.
    reader=CohortContainers.__new__(CohortContainers);reader.engine=engine
    reader.record=lambda:previous['containerJournal']
    result=[]
    for row in previous['prepared']['cohortPlan']['replacements']:
        if row['module']not in ('udp','onboarding'):continue
        reader.retired(row,True);actual=reader.running(row,True)
        require(actual is not None,'COMPLETED_MODULE_NO_LONGER_RUNNING')
        reader.retained_generation(row,actual)
        result.append({'module':row['module'],'runtimeBinding':Engine.runtime_binding(actual)})
    return result


def verify_successor_transition(row,scope,authority_hash):
    proof=scope['postGrantRecovery'];marker=row.get('governedGatewayContinuation',{})
    require(proof.get('profile')==PROFILE and proof.get('gatewayPredecessorAuthorityHash')==AUTHORITY
        and proof.get('predecessorTransitionHash')==TRANSITION_HASH
        and row.get('contextHash')==proof['transitionContextHash']
        and row.get('transitionAuthorityEvidenceHash')==original.AUTHORITY
        and row.get('creationRequestHash')==scope['creationRequestHash']
        and row.get('nextPhase',-1)>=10 and row.get('version',0)>=32
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
    seed['governedGatewayContinuation']={'schema':PROFILE,'predecessorJournalHash':TRANSITION_HASH,
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
    guard_database_scope(owner,proof)
    old=previous['databaseJournal'];validate_databases(old,previous['prepared']['databasePlan'])
    require(owner.plan==previous['prepared']['databasePlan'] and previous['backupRoot']==proof['retainedCohortBackupDirectory']
        and str(owner.root)!=previous['backupRoot'],'EXACT_RETAINED_DATABASE_PLAN_REQUIRED')
    with owner.journal.invocation():
        initial=owner.record()
        require(initial['version']==1 and not initial['backups'] and initial['mcpMigration'] is None
            and initial['mcpAuditRole'] is None,'MIGRATION_ADOPTION_ALREADY_CONSUMED')
        following=copy.deepcopy(initial);following['version']+=1
        following['governedGatewayRecovery']={'profile':PROFILE,'predecessorJournalHash':DATABASE_HASH,
            'predecessorAuthorityHash':AUTHORITY,'proofHash':digest(proof),'state':'COPY_CLAIMED','migrationReplayAllowed':False}
        owner.journal.compare_and_save(initial,following)
        for module in ARCHIVES:
            owner.guard();owner.quiescence()
            with protected_directory(owner.root)as directory:
                fd=os.open(module+'.dump',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
                with os.fdopen(fd,'wb')as stream:
                    prior.archive_bytes(previous['backupRoot'],module,stream.write);stream.flush();os.fsync(stream.fileno())
                os.fsync(directory)
            binding=next(r for r in owner.plan['modules'] if r['module']==module)
            owner.verify_archive(binding,old['backups'][module])
        owner.guard();owner.quiescence();retained_bindings(proof)
        final=copy.deepcopy(following);final['version']+=1
        final.update(backups=copy.deepcopy(old['backups']),mcpMigration=copy.deepcopy(old['mcpMigration']),mcpAuditRole=copy.deepcopy(old['mcpAuditRole']))
        final['governedGatewayRecovery']['state']='COMPLETE_ARCHIVES_AND_CHECKPOINTS_COPIED'
        owner.journal.compare_and_save(following,final)




def guard_database_scope(owner,proof):
    import json
    scope=json.loads(owner.action.raw)['applicationRegistryCutover']
    require(scope.get('postGrantRecovery')==proof and proof.get('profile')==PROFILE
        and owner.plan_hash==proof['originalDatabasePlanHash'],'EXACT_GATEWAY_DATABASE_CONTINUATION_SCOPE_REQUIRED')
    owner.action.guard('applicationRegistryCutover',scope)


def adopt_containers(owner,previous,proof):
    from tools.chatbot_file_cohort.containers import CohortContainers
    require(type(owner)is CohortContainers,'REAL_SIGNED_CONTAINER_OWNER_REQUIRED')
    owner.guard();retained_bindings(proof)
    import json
    scope=json.loads(owner.action.raw)['applicationRegistryCutover']
    require(scope.get('postGrantRecovery')==proof,'EXACT_GATEWAY_CONTAINER_CONTINUATION_SCOPE_REQUIRED')
    owner.action.guard('applicationRegistryCutover',scope)
    old=previous['containerJournal'];validate_containers(old,previous['prepared']['cohortPlan'])
    require(owner.plan['replacements']==previous['prepared']['cohortPlan']['replacements'],
        'COMPLETED_MODULE_PLANS_MUST_REMAIN_EXACT')
    current_completed_containers(previous,owner.engine)
    with owner.journal.invocation():
        initial=owner.record()
        require(initial['version']==1 and not initial['effects'] and initial['nextStep']==0
            and not initial['gates'] and not initial['readiness'],'CONTAINER_ADOPTION_ALREADY_CONSUMED')
        following=copy.deepcopy(initial)
        following.update(effects=copy.deepcopy(old['effects']),nextStep=10,readiness=copy.deepcopy(old['readiness']))
        following['governedGatewayRecovery']={'profile':PROFILE,'predecessorJournalHash':CONTAINERS_HASH,
            'predecessorAuthorityHash':AUTHORITY,'proofHash':digest(proof),'historicalGates':copy.deepcopy(old['gates']),
            'completedEffectsRetained':10,'lifecycleReplayAllowed':False}
        owner.save(initial,following)
        current_completed_containers(previous,owner.engine)
        owner.record()


def validate_publication(action,plan,transport):
    """A marker cannot authorize replay: bind exact history and concrete owner."""
    import json
    from tools.chatbot_file_cohort.gateway_runtime import GatewayRuntime,proposed_transport,validate_numeric_assets
    from tools.chatbot_file_cohort.gateway_recovery_plan import compile_remaining
    from tools.semantic_policy_token_owner.owner_installation import AggregateAction
    require(type(action)is AggregateAction and type(transport.runtime_owner)is GatewayRuntime,
        'GATEWAY_REPROCESSING_EXECUTOR_NOT_YET_QUALIFIED')
    scope=json.loads(action.raw)['applicationRegistryCutover'];proof=scope.get('postGrantRecovery')
    require(type(proof)is dict and proof.get('profile')==PROFILE,'EXACT_GOVERNED_GATEWAY_RECOVERY_REQUIRED')
    action.guard('applicationRegistryCutover',scope);retained_bindings(proof)
    previous=read_predecessor()
    runtime=transport.runtime_owner
    require(runtime.action is action and runtime.record()['nextStep']==8,'CURRENT_NUMERIC_GATEWAY_OWNER_REQUIRED')
    numeric=runtime.plan.get('numericCompatibility',{})
    validate_numeric_assets(runtime.plan['oldRuntimeBinding']['imageId'],numeric.get('assets'))
    runtime.generation()
    expected=compile_remaining(previous['prepared']['gatewayPlan'],previous['gatewayJournal'],
        plan['previousRoutes'],plan['previousRoutes'],proposed_transport(runtime.plan),digest(runtime.plan))
    expected['gatewayRuntimePlanHash']=digest(runtime.plan)
    expected['governedReprocessing'].pop('executionIntegrationQualified')
    expected['governedReprocessing']['executionProfile']=PROFILE
    require(plan==expected,'EXACT_REVIEWED_GATEWAY_REPROCESSING_PLAN_REQUIRED')


def current_gateway_transport(previous,engine):
    from tools.chatbot_file_cohort.gateway import NamespaceAdmin
    from tools.chatbot_file_cohort.gateway_runtime import GatewayRuntime,STEPS
    prepared=previous['prepared'];runtime=prepared.get('gatewayRuntimePlan')
    if runtime is None:
        expected=prepared['gatewayPlan']['transportBinding']
        binding=NamespaceAdmin.observe(engine,expected['configBinding']['path'])
        require(binding==expected,'RETAINED_GATEWAY_TRANSPORT_CHANGED')
    else:
        journal=previous['gatewayRuntimeJournal']
        require(journal.get('planHash')==digest(runtime) and journal.get('authorityHash')==AUTHORITY
            and journal.get('nextStep')==8 and len(journal.get('effects',[]))==8
            and journal.get('budgetReset')is False,'COMPLETED_GATEWAY_RUNTIME_REQUIRED')
        for step,effect in zip(STEPS,journal['effects']):
            require(effect.get('state')=='APPLIED' and effect.get('step')==step
                and effect.get('intentHash')==digest({'planHash':digest(runtime),'step':step}),
                'RETAINED_GATEWAY_RUNTIME_EFFECT_DRIFT')
        pin=journal['effects'][-1]['evidence']['runtimeBinding']
        require(journal['effects'][3]['evidence']['containerId']==pin['containerId']
            and all(pin[k]==v for k,v in journal['effects'][5]['evidence']['runtimeBinding'].items() if k!='hostConfigHash'),
            'RETAINED_GATEWAY_PROCESS_GENERATION_DRIFT')
        reader=GatewayRuntime.__new__(GatewayRuntime);reader.plan=runtime;reader.engine=engine
        reader.old(True);actual=reader.candidate(True,True,True)
        require(actual is not None and Engine.runtime_binding(actual)==pin,'RETAINED_GATEWAY_NATIVE_DRIFT')
        binding=NamespaceAdmin.observe(engine,runtime['newConfigBinding']['path'])
        require(binding['runtimeBinding']==pin and binding['adminKeyBinding']==runtime['adminKeyBinding']
            and binding['pythonExecutable']==runtime['pythonExecutable'],'RETAINED_GATEWAY_CUSTODY_DRIFT')
    require(digest(binding['runtimeBinding'])==GATEWAY_RUNTIME_HASH,'EXACT_GATEWAY_READBACK_GENERATION_REQUIRED')
    return binding


def current_migration(previous,engine):
    from tools.chatbot_file_cohort.migration_native import request_for,native_matches,immutable_native
    proof=previous['prepared']['postGrantRecovery'];name,request=request_for(previous['prepared']['cohortPlan'])
    code,actual=engine.request('GET','/v1.44/containers/'+prior.MIGRATION_ID+'/json')
    require(code==200 and actual['Id']==prior.MIGRATION_ID and digest(request)==prior.MIGRATION_INTENT,
        'RETAINED_COMPLETED_MIGRATION_IDENTITY_REQUIRED')
    native_matches(name,request,proof['migrationImageAudit']['imageConfig'],actual)
    require(immutable_native(actual)==proof['migrationNativeBinding'] and actual['State']['Status']=='exited'
        and actual['State']['ExitCode']==0 and actual['State']['Pid']==0 and not actual['State']['Running']
        and not actual['State']['Paused'] and not actual['State'].get('Dead') and not actual['State'].get('Restarting')
        and actual['RestartCount']==0,'COMPLETED_MIGRATION_NATIVE_DRIFT')
