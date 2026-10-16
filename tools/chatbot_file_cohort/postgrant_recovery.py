"""One explicit post-grant continuation; historical authority is never reused.

The predecessor is fixed by the complete target readback. Preparation only
reads existing private artifacts and native state. A fresh signed full action
must own adoption, new private journals and the distinct finite worker budget.
Old journals, backup and consumed claims remain byte-for-byte unchanged.
"""
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

import iam_binding_candidate as evidence
import iam_governance_intake as governance
import legacy_retirement as legacy
from tools.chatbot_file_cohort.plan import digest,encoded,require,sha
from tools.chatbot_file_cohort.action_process import private_file,observed_private_json
from tools.semantic_policy_token_owner.producer import protected_directory
from tools.semantic_lease_recovery.recovery_journal import Journal
from engine_creation import Engine
from file_only_profile import FileOnlyProfile,PHASES
from transition_journal import Transition
from native_evidence_store import NativeEvidenceStore

PROFILE='ouf.chatbot-postgrant-created-continuation.v1'
SOURCE='bc2d111200de75b90f8072a83c1739fbfb945313'
AUTHORITY='7db9ea82ed6fbbdc88cfdbd8e7315404e6c958e841731d1d12b22482f8fa8f30'
REVIEW='14ab339d3d29d3be9ad027ddad19dbd9ef3cc2b68ff1aece951a528e8c74ec29'
CONTEXT='chatbot-file-cohort-signed-b05102a00d9f20ec6a935e1de201d4a9bb800f2aac8876fe79b0ed187e5f9623'
CREATED_ID='790c62742c92eabc095d4ab22f2070e0c40a41e4a219685a7d8120e4661e4e5d'
TRANSITION_HASH='bfabae1561e4f906f23afe0c2e71d8f240774a38b9ac8b08c9ed43e4b5e1ecfb'
FIRST_HASH='4bb904ea93df0766647641fd397cac7d8504f1ca81252ce597d1db363a86105a'
WORKER_HASH='af84e55b73651d742b652df71893e2db83d2f55e68fbc8bdca25f0383421069b'
CLAIM='chatbot-file-cohort-postgrant-'+AUTHORITY+'.claim.json'


def validate_cutover_seed(row,intents,authority_hash=None):
    """Accept exactly the consumed create after four applied owner effects."""
    if authority_hash is None:authority_hash=AUTHORITY
    require(type(row)is dict and row.get('schema')=='ouf.semantic-cutover-journal.v2'
        and row.get('transitionAuthorityEvidenceHash')==authority_hash
        and row.get('state')=='IN_FLIGHT' and row.get('nextPhase')==4
        and row.get('version')==9 and row.get('databaseMayHaveChanged')is False
        and row.get('applicationWritesMayHaveOccurred')is False
        and row.get('automaticReplayAllowed')is False
        and row.get('preMigrationRestoreAllowed')is False
        and len(row.get('effects',[]))==5,'EXACT_POSTGRANT_CREATED_BOUNDARY_REQUIRED')
    for n,effect in enumerate(row['effects']):
        require(effect.get('phase')==PHASES[n]
            and effect.get('intentHash')==digest(intents[PHASES[n]])
            and effect.get('authorityEvidenceHash')==authority_hash
            and effect.get('state')==('APPLIED' if n<4 else 'IN_FLIGHT'),
            'POSTGRANT_PRIOR_EFFECT_OR_INTENT_DRIFT')
        if n<4:require(sha(effect.get('nativeEvidenceHash')),'POSTGRANT_COMPLETED_EVIDENCE_REQUIRED')
    return copy.deepcopy(row)


def recovery_component(profile):
    from tools.chatbot_file_cohort import paused_recovery,mounted_recovery,signed_recovery,backup_recovery,migration_recovery,gateway_recovery
    components={x.PROFILE:x for x in(paused_recovery,mounted_recovery,signed_recovery,backup_recovery,migration_recovery,gateway_recovery)}
    require(profile in components,'EXACT_RECOVERY_PROFILE_REQUIRED')
    return components[profile]


def validate_worker_seed(first,worker,admission,session,completed,profile=None):
    if profile is not None and profile!=PROFILE:
        return recovery_component(profile).validate_worker(first,worker,admission,session)
    require(first.get('state')=='TOKEN_PUBLISHED_NOT_RUNTIME_ACCEPTED'
        and first.get('attemptSlotsConsumed')==1 and first.get('gapRemainsOpen')is True
        and first.get('historicalAccountingReconciled')is False
        and first.get('legacyHistoricalGrantAttempts')is None,
        'EXACT_PREVIOUS_SPENT_FIRST_GRANT_REQUIRED')
    require(worker.get('state')=='CANCELLED' and worker.get('attempts')==0
        and worker.get('controlledPredecessorGrantAttempts')==1
        and worker.get('controlledCumulativeGrantAttempts')==1
        and worker.get('workerSessionHash')==digest(session)
        and worker.get('firstGrantReceiptHash')==digest(first)
        and admission.get('state')=='BLOCKED'
        and session.get('predecessorFirstGrantOperation')==first.get('operation')
        and session.get('predecessorFirstGrantScopeHash')==first.get('scopeHash')
        and completed.get('state')=='OWNER_READY_FOR_FINITE_WORKER_NOT_APPLICATION_ACCEPTED'
        and completed.get('firstGrantReceiptHash')==digest(first)
        and completed.get('workerSessionScopeHash')==digest(session),
        'POSTGRANT_CANCELLED_WORKER_AND_COMPLETED_HANDOFF_REQUIRED')
    return {'firstGrantReceiptHash':digest(first),'cancelledWorkerHash':digest(worker),
        'workerSessionHash':digest(session),'controlledCumulativeGrantAttempts':1}


def verify_successor_transition(row,scope,authority_hash):
    """Historical effects keep their original authority; new effects use current."""
    recovery=scope.get('postGrantRecovery')
    if type(recovery)is dict and recovery.get('profile')!=PROFILE:
        return recovery_component(recovery['profile']).verify_successor_transition(row,scope,authority_hash)
    require(type(recovery)is dict and recovery.get('profile')==PROFILE
        and recovery.get('predecessorAuthorityHash')==AUTHORITY
        and recovery.get('predecessorTransitionHash')==TRANSITION_HASH
        and recovery.get('createdContainerId')==CREATED_ID
        and row.get('contextHash')==recovery.get('transitionContextHash')
        and row.get('transitionAuthorityEvidenceHash')==AUTHORITY
        and row.get('nextPhase',-1)>=4 and len(row.get('effects',[]))>=5,
        'EXACT_REVIEWED_POSTGRANT_TRANSITION_REQUIRED')
    prefix=row['effects'][:4]
    require(digest(prefix)==recovery.get('appliedPrefixHash')
        and all(e['state']=='APPLIED' and e['authorityEvidenceHash']==AUTHORITY for e in prefix)
        and row['effects'][4].get('phase')=='CREATE_REPLACEMENT'
        and row['effects'][4].get('authorityEvidenceHash')==AUTHORITY
        and row['effects'][4].get('intentHash')==scope['creationRequestHash']
        and all(e.get('authorityEvidenceHash')==authority_hash for e in row['effects'][5:]),
        'POSTGRANT_HISTORY_REWRITE_OR_AUTHORITY_DRIFT')
    return True


def stopped_process(process,systemctl):
    require(governance.executable(systemctl['path'])==systemctl,'POSTGRANT_SYSTEMCTL_BINDING_DRIFT')
    r=subprocess.run([systemctl['path'],'show',process['unit'],'--property=Id,ActiveState,SubState,MainPID,Job'],
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10,
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    require(r.returncode==0 and len(r.stdout)<=8192,'POSTGRANT_PREDECESSOR_PROCESS_UNAVAILABLE')
    rows=dict(line.split('=',1) for line in r.stdout.decode().splitlines() if '='in line)
    require(rows.get('Id')==process['unit'] and rows.get('ActiveState')in ('inactive','failed')
        and rows.get('MainPID')=='0' and rows.get('Job')=='','POSTGRANT_PREDECESSOR_PROCESS_NOT_STOPPED')


def read_predecessor(profile=None):
    if profile is not None and profile!=PROFILE:
        return recovery_component(profile).read_predecessor()
    """Read fixed approved context and immutable records, never execute its code."""
    root=evidence.PARENT/CONTEXT;bindings=[]
    def read(path,expected=None,maximum=262144):
        value,binding=observed_private_json(path,maximum)
        require(expected is None or binding['sha256']==expected,'POSTGRANT_PINNED_RECORD_DRIFT')
        bindings.append(binding);return value
    review=read(root/'review.json',REVIEW)
    require(review['sourceClosure']['declaration']['sourceCommit']==SOURCE,'EXACT_POSTGRANT_PREDECESSOR_SOURCE_REQUIRED')
    authority=read(root/'authority.json',AUTHORITY,131072)
    require(all(authority.get(k)==v for k,v in review['scopes'].items()),'POSTGRANT_PREDECESSOR_SIGNED_SCOPE_DRIFT')
    decision=read(root/'decision.json')
    require(decision.get('approvedReviewHash')==REVIEW and decision.get('approvedSourceClosureHash')==review['sourceClosureHash']
        and decision.get('decision')=='APPROVE_ONE_FINITE_CHATBOT_FILE_COHORT_ACTION'
        and decision.get('state')=='ACTIVE' and decision.get('expiresAt')==authority['expiresAt']
        and authority['issuedAt']<=authority['expiresAt']<=time.time(),'POSTGRANT_OLD_WINDOW_MUST_BE_EXPIRED')
    process=review['scopes']['finiteActionProcess']
    require(process['authorityDirectory']==str(root),'POSTGRANT_CONTEXT_PATH_DRIFT')
    stopped_process(process,review['sourceClosure']['executables']['systemctl'])
    status=read(root/'delivery-status.json')
    require(status.get('phase')=='PAUSED_REQUIRES_RECONCILIATION' and status.get('reason')=='CreationDenied'
        and status.get('authorityHash')==AUTHORITY,'EXACT_POSTGRANT_CREATION_DENIAL_REQUIRED')
    start=read(evidence.PARENT/('chatbot-file-cohort-process-'+process['logicalOperationHash']+'.claim.json'))
    require(start.get('authorityHash')==AUTHORITY and start.get('planHash')==digest(process)
        and start.get('state')=='START_CONSUMED_OUTCOME_UNPROVEN','POSTGRANT_PROCESS_CLAIM_DRIFT')
    b=process['bundle'];bundle=read(b['path'],b['sha256'],8388608);prepared=bundle['prepared']
    require(bundle['declaration']==review['sourceClosure']['declaration']
        and digest(prepared)==review['privateInputHashes']['preparedInputs'],'POSTGRANT_ORIGINAL_PREPARED_INPUT_DRIFT')
    paths=prepared['registry']['directoryPlan'];transition=read(Path(paths['transition'])/'recovery.json',TRANSITION_HASH)
    validate_cutover_seed(transition,prepared['registry']['intents'])
    owner=review['scopes']['policyTokenOwnerInstallation'];old_worker=Path(owner['journalPath'])
    for previous in review.get('previousFiniteActions',[]):
        for binding in previous.get('recordBindings',[]):read(binding['path'],binding['sha256'],8388608)
    logical=review['scopes']['policyTokenFiniteWorkerSession']['logicalOwnerScopeHash']
    output_scope=review['scopes']['policyTokenOutputCustody']
    output_operation=digest({'logicalOwnerScopeHash':logical,'operation':'FIRST_GOVERNED_TOKEN_OUTPUT_CHILD','path':output_scope['path']})
    output=read(evidence.PARENT/('policy-token-output-custody-'+output_operation+'.private.json'),
        '0d176ef0fa749df76cbd636a944e1b420b33201b65741c652c9ad5c376fa01ce')
    require(output.get('state')=='OUTPUT_CUSTODIED_NOT_RUNTIME_ACCEPTED'
        and output.get('mkdirAttemptConsumed')is True,'POSTGRANT_COMPLETED_OUTPUT_RECEIPT_REQUIRED')
    with protected_directory(output_scope['path'],gid=10001,mode=0o750)as fd:
        info=os.fstat(fd)
        require(output['outputIdentity']=={'device':info.st_dev,'inode':info.st_ino},'POSTGRANT_RETAINED_OUTPUT_INODE_DRIFT')
    original_first=review['scopes']['policyTokenFirstControlledGrant']
    read(evidence.PARENT/('policy-token-credential-transaction-'+original_first['credentialOperation']+'.private.json'),
        'a9fa6304781bff2c9a795d16520881401a49124db869de87338f8978251436ae')
    legacy.credential_metadata()
    stage_hash=owner['stageManifestHash'];code=legacy.CODE
    read(code/('policy-token-source-stage-'+stage_hash+'.intent'),'71dc87128d802d6b075d2921ec53aa0177a599f33033d17e303c0198df0e1544')
    manifest=read(code/('semantic-native-v11-intake-'+stage_hash)/'intake.json',
        '90444cb2256ba789ed2ab33e063652966f3fd4de58ad74fa1bf95dc49817de0f')
    require(digest(manifest)==stage_hash,'POSTGRANT_PRIOR_SOURCE_MANIFEST_DRIFT')
    for name,hashed in manifest['fileHashes'].items():
        b={'path':str(code/('semantic-native-v11-intake-'+stage_hash)/name),'sha256':hashed}
        private_file(b,131072);bindings.append(b)
    first=read(old_worker/'owner-first-grant.json',FIRST_HASH)
    worker=read(old_worker/'recovery.json',WORKER_HASH)
    session=read(old_worker/'owner-session.json','6f27f3d34eefa3c4b10685d705b5edf97c2164d4ce994b63b8bbc853645717d1')
    admission=read(old_worker/'owner-admission.json','c1b47e5a2db2652fddfd8b905c5e80abf1b0327a01c0c6748833fd4bf0d52107')
    completed=read(evidence.PARENT/('policy-token-owner-post-credential-continuation-'+legacy.POST_AUTHORITY+'.private.json.completed'),
        '855fa3ba86b742351da2ab14ba0c1c8958cb96005aad02257bf0aceb44a4b395')
    validate_worker_seed(first,worker,admission,session,completed)
    require(first['bootId']==worker['bootId']==legacy.boot_identity(),'POSTGRANT_KERNEL_BOOT_CHANGED')
    for label,expected in PINNED_STAGE_HASHES.items():
        row=read(Path(process['directoryPlan'][label])/'recovery.json',expected)
        require(not row.get('effects') and not row.get('backups') and not row.get('nextStep',0),
            'POSTGRANT_LATER_APPLICATION_EFFECT_PRESENT')
    completed_dirs=read(root/'directories.completed.json')
    require(completed_dirs.get('authorityHash')==AUTHORITY and completed_dirs.get('planHash')==digest(process['directoryPlan']),
        'POSTGRANT_ORIGINAL_DIRECTORY_RECEIPT_DRIFT')
    for path in process['directoryPlan'].values():
        with protected_directory(path)as fd:
            info=os.fstat(fd)
            require(completed_dirs['identities'].get(path)=={'device':info.st_dev,'inode':info.st_ino},
                'POSTGRANT_ORIGINAL_DIRECTORY_IDENTITY_DRIFT')
    payloads={}
    for store,phases in (('evidence',PHASES[:4]),('before',('QUIESCE_PRODUCERS',)),
                         ('retirementBefore',('STOP_REVOKE_OLD_LEASE',))):
        payloads[store]={}
        for phase in phases:
            value=read(Path(paths[store])/(phase+'.json'))
            if store=='evidence':
                effect=next(e for e in transition['effects']if e['phase']==phase)
                require(digest(value)==effect['nativeEvidenceHash'],'POSTGRANT_APPLIED_PAYLOAD_DRIFT')
            payloads[store][phase]=value
    before=payloads['before']['QUIESCE_PRODUCERS']
    require(before['authorityHash']==AUTHORITY
        and before['authorizationPlanHash']==digest(prepared['authorization']['plan'])
        and before['authorizationHistoryHash']==PINNED_STAGE_HASHES['authorization'],
        'POSTGRANT_PRE_QUIESCENCE_AUTHORIZATION_DRIFT')
    return {'review':review,'prepared':prepared,'authority':authority,'transition':transition,
        'bundle':bundle,'output':output,
        'firstGrant':first,'worker':worker,'admission':admission,'session':session,'completed':completed,
        'payloads':payloads,'recordBindings':bindings}


PINNED_STAGE_HASHES={
 'authorization':'e62560051c95a9fcdd312843a99ee05184bfdd1727563265fe62239b7a3d437f',
 'containers':'5e06a0f2b01b9d61c1e402b31ca9544945438989fd944c4e316bf724d9c08503',
 'databases':'c5b01ae39f85ec60f0553aee90256c35ff0c3a1a01fd44ab2cb98a32bde96276',
 'gateway':'6eabc0c9a5735a173b5e305237d38bffdb5347a36953b9948fc103dfe01246c9'}


def proof_scope(predecessor,actor):
    if predecessor.get('recoveryProfile') is not None:
        return recovery_component(predecessor['recoveryProfile']).proof_scope(predecessor,actor)
    require(type(actor)is dict and set(actor)=={'issuer','tenant','subject'}
        and actor=={k:predecessor['prepared']['authorization']['plan']['selection'][k]for k in actor},
        'POSTGRANT_SAME_HUMAN_ACTOR_REQUIRED')
    row=predecessor['transition']
    return {'profile':PROFILE,'predecessorSource':SOURCE,'predecessorAuthorityHash':AUTHORITY,
        'predecessorReviewHash':REVIEW,'predecessorTransitionHash':TRANSITION_HASH,
        'transitionContextHash':row['contextHash'],'appliedPrefixHash':digest(row['effects'][:4]),
        'createdContainerId':CREATED_ID,'firstGrantReceiptHash':FIRST_HASH,'cancelledWorkerHash':WORKER_HASH,
        'sameLogicalIncident':predecessor['review']['predecessorIncidentRef'],
        'originalAuthorizationPlanHash':digest(predecessor['prepared']['authorization']['plan']),
        'originalAuthorizationHistoryHash':PINNED_STAGE_HASHES['authorization'],
        'retainedBackupDirectory':predecessor['prepared']['registry']['directoryPlan']['backup'],
        'sameLogicalOwnerScope':predecessor['session']['logicalOwnerScopeHash'],
        'recordBindings':copy.deepcopy(predecessor['recordBindings']),
        'newBudget':{'actor':copy.deepcopy(actor),'reason':'QUALIFIED_EMPTY_MOUNTS_RECONCILIATION_AFTER_FIRST_GRANT',
            'decisionRef':'CURRENT_EXACT_FULL_ACTION_HUMAN_DECISION','priorControlledGrantAttempts':1,
            'priorWorkerGrantAttempts':0,'maximumNewWorkerAttempts':128,'maximumSeconds':3600,
            'automaticRenewalAllowed':False},'firstGrantReplayAllowed':False,'credentialRotationAllowed':False,
        'containerCreationReplayAllowed':False,'oldJournalWritesAllowed':False,'budgetReset':False}


def retained_bindings(proof):
    if proof.get('profile')!=PROFILE:
        return recovery_component(proof['profile']).retained_bindings(proof)
    require(proof.get('profile')==PROFILE,'EXACT_POSTGRANT_CONTINUATION_PROFILE_REQUIRED')
    for binding in proof['recordBindings']:
        private_file(binding,8388608 if binding['path'].endswith('child-bundle.json') else 2097152)


def current_baseline(predecessor,engine):
    """Native proof before login; never start, stop, reconnect or open a DB."""
    require(type(engine)is Engine,'REAL_POSTGRANT_ENGINE_REQUIRED')
    prepared=predecessor['prepared'];row=predecessor['transition']
    from tools.chatbot_file_cohort.action_process import pregrant_native_readback
    original=evidence.decode(legacy.private(evidence.PARENT/legacy.CONTEXT/'review.json',legacy.REVIEW))
    pregrant_native_readback(original,legacy.AUTHORITY,
        gateway_successor=predecessor if 'retainedGatewayAttempt' in predecessor else None)
    profile=FileOnlyProfile(prepared['registry']['creationRequest'],prepared['registry']['configtree'])
    transition=Transition.__new__(Transition);transition.context=row['contextHash']
    from tools.chatbot_file_cohort.backup_recovery import PROFILE as BACKUP_PROFILE
    running=predecessor.get('recoveryProfile') in (BACKUP_PROFILE,'ouf.chatbot-created-mcp-migration-continuation.v1','ouf.chatbot-gateway-schema-continuation.v1')
    paused=predecessor.get('recoveryProfile') is not None
    actual=engine.matching_configuration(transition,prepared['registry']['creationRequest'],engine.inspect(transition))if paused else engine.matching_created(transition,prepared['registry']['creationRequest'],engine.inspect(transition))
    if paused:
        from tools.chatbot_file_cohort.paused_recovery import current_paused_native
        current_paused_native(predecessor,engine,actual,running=running)
    require(actual['Id']==CREATED_ID and actual.get('RestartCount')==0,'POSTGRANT_EXACT_ALREADY_CREATED_CONTAINER_REQUIRED')
    after=engine.inspect(transition)
    if running:
        from tools.chatbot_file_cohort.paused_recovery import same_running_native
        require(same_running_native(actual,after),'POSTGRANT_CREATED_GENERATION_UNSTABLE')
    else:
        require(after==actual,'POSTGRANT_CREATED_GENERATION_UNSTABLE')
    # Existing owner predicate understands the stopped host policy and detached
    # old Registry network. Never compare post-stop PID with pre-stop PID pins.
    quiescence=prepared['registry']['intents']['QUIESCE_PRODUCERS']
    for pin in quiescence['producerBindings']:
        code,native=engine.request('GET','/v1.44/containers/'+pin['containerId']+'/json')
        expected=copy.deepcopy(quiescence['initialHostConfigs'][pin['containerId']]);expected['RestartPolicy']={'Name':'no','MaximumRetryCount':0}
        require(code==200 and native['Id']==pin['containerId'] and native['Image']==pin['imageId']
            and digest(native['Config'])==pin['configHash'] and digest(native['Mounts'])==pin['mountsHash']
            and native['HostConfig']==expected and native['State']['Running']is False
            and native['State']['Paused']is False and native['State']['Status']=='exited'
            and native['State']['Pid']==0 and native['State']['StartedAt']==pin['startedAt'],
            'POSTGRANT_OLD_PRODUCER_QUIESCENCE_DRIFT')
    pgpin=prepared['registry']['postgresRuntimeBinding']
    code,pg=engine.request('GET','/v1.44/containers/'+pgpin['containerId']+'/json')
    require(code==200 and Engine.runtime_binding(pg)==pgpin and pg['State']['Running']is True,
        'POSTGRANT_POSTGRES_GENERATION_DRIFT')
    if running:
        from tools.chatbot_file_cohort.backup_recovery import current_registry,current_databases
        current_registry(predecessor,engine)
        if predecessor.get('recoveryProfile')=='ouf.chatbot-created-mcp-migration-continuation.v1':
            from tools.chatbot_file_cohort.migration_recovery import current_databases,migration_observation
            migration_observation(predecessor,engine)
        if predecessor.get('recoveryProfile')=='ouf.chatbot-gateway-schema-continuation.v1':
            from tools.chatbot_file_cohort.gateway_recovery import current_databases,current_completed_containers,current_gateway_transport,current_migration
            current_completed_containers(predecessor,engine);current_gateway_transport(predecessor,engine);current_migration(predecessor,engine)
        current_databases(predecessor)
    from database_gate import Psql
    from fenced_backup_adapter import FencedBackupAdapter
    admin=Psql(pgpin['containerId'],prepared['registry']['intents']['FENCED_BACKUP']['user'],
        prepared['registry']['adminDatabase'],'ouf-cutover-postgrant-read')
    try:
        backup=FencedBackupAdapter(admin,prepared['registry']['intents']['FENCED_BACKUP'],lambda _:None,row['contextHash'])
        retained=predecessor['payloads']['evidence']['FENCED_BACKUP']
        if running:
            expected={k:v for k,v in retained.items() if k!='currentDatabaseState'}
            require(backup.retained_snapshot()==expected and backup.retained_snapshot()==expected,
                'POSTGRANT_RETAINED_REGISTRY_BACKUP_DRIFT')
        else:
            require(backup.snapshot()==retained,'POSTGRANT_CURRENT_BACKUP_OR_DATABASE_FENCE_DRIFT')
    finally:admin.close()
    from image_custody import loaded,runtime_image_id
    for image in prepared['imagePlan']['images']:
        audit=image['audit'];code,native=engine.request('GET','/v1.44/images/'+runtime_image_id(audit)+'/json')
        require(code==200,'POSTGRANT_LOADED_IMAGE_ABSENT');loaded(audit,native)
    require(legacy.quiescent(legacy.read_units()),'POSTGRANT_LEGACY_WRITER_NOT_QUIESCENT')
    return {'createdContainerId':CREATED_ID,'createdRuntimeHash':digest(actual),
        'postgresRuntimeHash':digest(pgpin),'databaseFenceProven':not running,'imagesVerified':5,'registryAlreadyRunning':running,
        'retainedPrefixPhaseCount':10 if running else 6 if paused else 4,
        **({'historicalAppliedPhaseCount':7,'newSourceRequiresFreshAttestation':True,'conservativeDatabaseFlagRetained':True}if predecessor.get('recoveryProfile')=='ouf.chatbot-signed-paused-admission-reprocessing.v1'else{}),'controlledGrantAttemptsRetained':predecessor['worker']['controlledCumulativeGrantAttempts'] if paused else 1,'serviceMutations':0,'grantRequests':0}


def seed_registry(predecessor,directories,action,scope):
    """Copy only immutable evidence; the exact CREATE remains IN_FLIGHT."""
    if scope.get('postGrantRecovery',{}).get('profile')!=PROFILE:
        return recovery_component(scope['postGrantRecovery']['profile']).seed_registry(predecessor,directories,action,scope)
    action.guard('applicationRegistryCutover',scope)
    require(scope.get('postGrantRecovery')is not None,'REVIEWED_REGISTRY_CONTINUATION_REQUIRED')
    retained_bindings(scope['postGrantRecovery'])
    seed=validate_cutover_seed(predecessor['transition'],predecessor['prepared']['registry']['intents'])
    verify_successor_transition(seed,scope,action.authority_hash)
    journal=Journal(directories['transition'])
    require(not any(os.path.lexists(journal.root/p)for p in ('recovery.json','recovery.lock','invocation.lock')),
        'POSTGRANT_NEW_TRANSITION_ALREADY_CONSUMED')
    for store,phases in predecessor['payloads'].items():
        target=NativeEvidenceStore(directories[store])
        for phase,value in phases.items():target.publish(phase,value)
    journal.initialize(seed)
    require(journal.read()==predecessor['transition'],'POSTGRANT_COPIED_HISTORY_DRIFT')
    return journal


class ContinuationFence:
    """One global reservation for this logical incident, irrespective of source."""
    def __init__(self,action,proof):
        self.action,self.proof=action,copy.deepcopy(proof);self.fd=None;self.claim=CLAIM
        if proof.get('profile')!=PROFILE:
            component=recovery_component(proof.get('profile'))
            self.claim=component.claim_for(proof) if hasattr(component,'claim_for') else component.CLAIM
    def __enter__(self):
        scope=json.loads(self.action.raw)['applicationRegistryCutover']
        require(scope.get('postGrantRecovery')==self.proof,'EXACT_SIGNED_POSTGRANT_RESERVATION_REQUIRED')
        self.action.guard('applicationRegistryCutover',scope)
        retained_bindings(self.proof)
        with evidence.protected_parent()as directory:
            self.fd=os.open(self.claim,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
            try:
                fcntl.flock(self.fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                raw=encoded({'schema':self.proof['profile'],'authorityHash':self.action.authority_hash,'proofHash':digest(self.proof),
                    'state':'CONTINUATION_RESERVED_NO_AUTOMATIC_REPLAY','priorControlledGrantAttempts':self.proof.get('newBudget',{}).get('priorControlledGrantAttempts',1)})
                with os.fdopen(os.dup(self.fd),'wb')as out:out.write(raw);out.flush();os.fsync(out.fileno())
                os.fsync(directory)
                self.binding={'path':str(evidence.PARENT/self.claim),'sha256':hashlib.sha256(raw).hexdigest()}
                self.identity=evidence.identity(os.fstat(self.fd))
            except BaseException:os.close(self.fd);self.fd=None;raise
        self.guard();return self
    def guard(self):
        require(self.fd is not None and self.identity==evidence.identity(os.fstat(self.fd))
            ==evidence.identity((evidence.PARENT/self.claim).lstat()),'POSTGRANT_GLOBAL_RESERVATION_IDENTITY_DRIFT')
        private_file(self.binding,4096)
        return True
    def __exit__(self,*_):
        if self.fd is not None:os.close(self.fd);self.fd=None
