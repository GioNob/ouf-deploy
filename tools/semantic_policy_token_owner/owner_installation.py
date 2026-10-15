"""One governed owner installation; development permission is not authority.

All scopes use the SAME current CutoverAuthority and signed bytes. Infrastructure
effects are reserved durably before execution. This module never signs or resets
consumed legacy/migration histories. Worker budget is an explicit new finite
session linked to the reconciled first controlled grant.
"""
import copy
import dataclasses
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import time

from cutover_authority import CutoverAuthority
import iam_binding_candidate as evidence
import migration_root_custody as roots
import first_controlled_grant as first_grant
from tools.semantic_lease_recovery.bounded_recovery import Policy, fingerprint
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.semantic_policy_token_owner.producer import Binding, CredentialFile, protected_directory
from tools.semantic_policy_token_owner.iam_admission import IamProfile, PinnedIamOpener, OnlineIamAdmission
from tools.semantic_policy_token_owner.installed_owner import InstalledTokenOwner, owner_binding_inputs
from tools.semantic_policy_token_owner.source_stage import declaration, ProtectedTokenSourceStage
from tools.semantic_policy_token_owner.worker_entry import build_worker


class AggregateAction:
    """Typed current authority shared by owner and application sub-actions.

    No callback can stand in for signature/HUMAN verification. Every component
    compares its exact independently compiled scope before its dependent effect.
    """
    def __init__(self, authority, authority_raw, source_closure_hash):
        evidence.require(type(authority) is CutoverAuthority and type(authority_raw) is bytes,
                         'CURRENT_TYPED_AGGREGATE_AUTHORITY_REQUIRED')
        evidence.require(authority.expected['sourceClosureHash'] == source_closure_hash,
                         'EXACT_AGGREGATE_EXECUTING_CLOSURE_REQUIRED')
        self.authority, self.raw, self.closure = authority, bytes(authority_raw), source_closure_hash
        self.authority_hash = evidence.sha(self.raw)

    def guard(self, key, expected_scope):
        evidence.require(evidence.sha(self.raw) == self.authority_hash
                         and self.authority.expected['sourceClosureHash'] == self.closure,
                         'AGGREGATE_AUTHORITY_OR_SOURCE_DRIFT')
        evidence.require(evidence.decode(self.raw).get(key) == expected_scope,
                         'EXACT_SIGNED_AGGREGATE_COMPONENT_SCOPE_REQUIRED')
        evidence.require(self.authority(self.raw) is True,
                         'CURRENT_HUMAN_AND_DUAL_ROLE_AGGREGATE_AUTHORITY_REQUIRED')
        return True


@dataclasses.dataclass(frozen=True)
class RetainedGrantReference:
    """Read-only input reference; deliberately exposes no migration method."""
    binding: Binding
    credential: CredentialFile
    profile: IamProfile
    transport: PinnedIamOpener


class ContinuedOwnerInstallation:
    """Fresh finite worker after a proven spent grant and cancelled zero-renewal worker.

    The caller has already prepared an unused private directory, with its inode
    included in the full review. Records are initialized only after the fresh
    HUMAN decision. No old journal, credential or first-grant method is invoked.
    The first publication must result from this new worker's accounted grant.
    """
    def __init__(self,action,value,stage_files,proof,predecessor,journal_directory,
                 clock=lambda:(time.time(),time.monotonic()),*,transport=None):
        from tools.chatbot_file_cohort.postgrant_recovery import PROFILE,validate_worker_seed
        evidence.require(type(action)is AggregateAction and proof.get('profile')==PROFILE,
            'EXACT_POSTGRANT_OWNER_CONTINUATION_REQUIRED')
        validate_worker_seed(predecessor['firstGrant'],predecessor['worker'],predecessor['admission'],
            predecessor['session'],predecessor['completed'])
        self.action,self.clock,self.proof=action,clock,copy.deepcopy(proof)
        self.predecessor=copy.deepcopy(predecessor)
        private_host=value['hostInputBinding']
        from tools.chatbot_file_cohort.action_process import private_file
        self.host_raw=private_file(private_host,2097152)
        self.root_hash,self.root_source=value['rootEvidenceHash'],value['rootCreationSourceClosureHash']
        with roots.completed_roots(self.host_raw,self.root_hash,self.root_source)as current:self.roots=copy.deepcopy(current)
        binding=Binding(**value['binding']);profile_value=copy.deepcopy(value['iamProfile'])
        for key in ('required_scopes','allowed_scopes','peer_addresses'):profile_value[key]=tuple(profile_value[key])
        profile=IamProfile(**profile_value);profile.match(binding)
        transport=PinnedIamOpener(profile)if transport is None else transport
        evidence.require(type(transport)is PinnedIamOpener and transport.profile==profile
            and transport.trust_digest()==value['tlsTrustSetHash'],'POSTGRANT_CURRENT_IAM_TRUST_REQUIRED')
        credential=CredentialFile(Path(self.roots['ownerCredential']['path'])/'client-secret')
        self.first=RetainedGrantReference(binding,credential,profile,transport)
        old=predecessor['prepared']['owner']
        evidence.require(dataclasses.asdict(binding)==old['binding']
            and profile.client_id==old['iamProfile']['client_id']
            and profile.subject_id==old['iamProfile']['subject_id'],
            'POSTGRANT_SAME_CREDENTIAL_CLIENT_AND_TOKEN_BINDING_REQUIRED')
        policy=copy.deepcopy(value['policy']);policy['delays']=tuple(policy['delays']);self.policy=Policy(**policy)
        evidence.require(self.policy.max_attempts==128 and self.policy.max_elapsed<=3600,'POSTGRANT_FINITE_NEW_WORKER_POLICY_REQUIRED')
        self.context,self.generation,self.interval=value['contextRef'],value['generationRef'],value['intervalSeconds']
        self.journal=Journal(journal_directory)
        self.admission=OnlineIamAdmission(profile,credential,transport,clock)
        receipt=predecessor['firstGrant'];old_session=predecessor['session']
        self.worker_scope=finite_worker_scope(old_session['logicalOwnerScopeHash'],receipt['operation'],receipt['scopeHash'],
            self.policy,self.context,self.generation,self.interval)
        self.worker_scope['newBudget']=copy.deepcopy(proof['newBudget'])
        self.worker_scope['predecessorCancelledWorkerHash']=proof['cancelledWorkerHash']
        from tools.semantic_policy_token_owner.supervisor import ScheduledRecovery
        owner_binding=owner_binding_inputs(binding,credential,self.admission,self.journal,self.context,self.generation,
            fingerprint(dataclasses.asdict(self.policy)),ScheduledRecovery.PROFILE,self.interval,fingerprint(self.worker_scope))
        self.owner_hash=fingerprint(owner_binding);self.files=dict(stage_files)
        code=self.roots['reviewedCode']
        self.manifest=declaration(code['path'],value['sourceCommit'],self.files,
            directory_identity={k:code[k]for k in ('device','inode')},owner_binding_hash=self.owner_hash)
        self.output_scope={'schema':'ouf.policy-token-retained-output-custody.v1','operation':'VERIFY_EXISTING_OUTPUT_NO_MKDIR',
            'path':binding.output_directory,'gid':binding.output_gid,'hostInputsHash':private_host['sha256'],
            'predecessorOutputScopeHash':fingerprint(predecessor['review']['scopes']['policyTokenOutputCustody']),
            'postGrantRecoveryHash':fingerprint(proof),'maximumMkdirAttempts':0}
        self.scope={'schema':'ouf.policy-token-owner-installation.v1','sourceClosureHash':action.closure,
            'stageManifestHash':fingerprint(self.manifest),'ownerBindingHash':self.owner_hash,
            'workerSessionScopeHash':fingerprint(self.worker_scope),'operation':'CONTINUE_WITH_NEW_FINITE_WORKER_AFTER_SPENT_FIRST_GRANT',
            'journalPath':str(self.journal.root),'contextRef':self.context,'generationRef':self.generation,
            'postGrantRecoveryHash':fingerprint(proof),'firstGrantReceiptHash':fingerprint(receipt),
            'initializeJournalOnlyIfAbsent':True,'automaticReplayAllowed':False,'applicationAcceptanceGranted':False}
        self.runtime_scope={'ownerBindingHash':self.owner_hash,'operation':'RENEW_EXISTING_POLICY_READ_CREDENTIAL',
            'legacyWriterMustBeMasked':True,'credentialReestablishmentRequired':True,'automaticBudgetResetAllowed':False}

    def scopes(self):
        old=self.predecessor['review']['scopes']
        return {'policyTokenOwnerInstallation':copy.deepcopy(self.scope),
            'policyTokenOutputCustody':copy.deepcopy(self.output_scope),
            **{key:{'schema':'ouf.postgrant-retained-component.v1','operation':'VERIFY_COMPLETED_RECEIPT_NO_REPLAY',
                'predecessorScopeHash':fingerprint(old[key]),'postGrantRecoveryHash':fingerprint(self.proof),
                'newEffectAttemptsAllowed':0}for key in ('policyTokenLegacyRetirement','policyTokenCredentialReestablishment',
                    'policyTokenAccountingGapMigration','policyTokenFirstControlledGrant')},
            'policyTokenFiniteWorkerSession':copy.deepcopy(self.worker_scope),'tokenOwnerRuntime':copy.deepcopy(self.runtime_scope)}

    def guard(self):
        from tools.chatbot_file_cohort.postgrant_recovery import retained_bindings
        for key,scope in self.scopes().items():self.action.guard(key,scope)
        retained_bindings(self.proof);self.journal.check_directory()
        with roots.completed_roots(self.host_raw,self.root_hash,self.root_source)as current:
            evidence.require(current==self.roots,'POSTGRANT_COMPLETED_ROOT_CUSTODY_DRIFT')
        evidence.require(roots.legacy.quiescent(roots.legacy.read_units()),'POSTGRANT_LEGACY_WRITER_FENCE_REQUIRED')

    def install(self):
        from tools.semantic_policy_token_owner.supervisor import ScheduledRecovery
        from tools.chatbot_file_cohort.postgrant_recovery import FIRST_HASH
        self.guard()
        evidence.require(not os.listdir(self.journal.root),'POSTGRANT_NEW_WORKER_DIRECTORY_ALREADY_CONSUMED')
        ProtectedTokenSourceStage(self.manifest,self.files,self.action.authority,self.action.raw).stage()
        self.guard();wall,mono=self.clock();receipt=self.predecessor['firstGrant']
        evidence.require(fingerprint(receipt)==FIRST_HASH,'POSTGRANT_FIRST_GRANT_HISTORY_DRIFT')
        authority=evidence.decode(self.action.raw)
        evidence.require(authority['issuedAt']<=wall<authority['expiresAt'],'CURRENT_POSTGRANT_AUTHORITY_REQUIRED')
        row={'schema':'ouf.bounded-recovery.v1','contextRef':self.context,'generationRef':self.generation,
            'policyHash':fingerprint(dataclasses.asdict(self.policy)),'state':'NEW','attempts':0,
            'startedWall':wall,'startedMonotonic':mono,'lastWall':wall,'lastMonotonic':mono,
            'nextWall':None,'nextMonotonic':None,'reason':'EXPLICIT_POSTGRANT_NEW_WORKER_BUDGET',
            'renewalProfile':ScheduledRecovery.PROFILE,'intervalSeconds':self.interval,'publicationCount':0,
            'nextRenewalWall':None,'nextRenewalMonotonic':None,'tokenExpiresWall':None,'tokenExpiresMonotonic':None,
            'workerSessionHash':fingerprint(self.worker_scope),'firstGrantReceiptHash':FIRST_HASH,
            'legacyHistory':copy.deepcopy(self.predecessor['worker']['legacyHistory']),
            'controlledPredecessorGrantAttempts':1,'controlledCumulativeGrantAttempts':1,'bootId':receipt['bootId']}
        with protected_directory(self.journal.root)as directory:
            for name,value in (('owner-first-grant.json',receipt),('owner-session.json',self.worker_scope),
                ('owner-admission.json',{'schema':'ouf.policy-token-owner-admission.v1','ownerProfileHash':self.owner_hash,
                    'contextRef':self.context,'generationRef':self.generation,'version':0,'state':'BLOCKED',
                    'tokenHash':None,'blockedAttempt':None})):
                OwnerInstallation._write_once(self,directory,name,evidence.encoded(value))
        self.journal.initialize(row);self.guard()
        worker=build_worker(self.first.binding,self.first.credential,self.first.profile,self.first.transport,
            self.journal,self.policy,self.context,self.generation,self.manifest,self.action.authority,self.action.raw,
            interval_seconds=self.interval,clock=self.clock)
        evidence.require(worker.active_here is False,'POSTGRANT_EXPIRED_TOKEN_CANNOT_BE_ADOPTED')
        self.observer=InstalledTokenOwner(self.first.binding,self.first.credential,self.admission,self.journal,
            self.context,self.generation,self.manifest,self.action.authority,self.action.raw,observer=True)
        return worker


def finite_worker_scope(logical_scope, first_operation, first_scope_hash, policy,
                        context_ref, generation_ref, interval_seconds):
    evidence.require(type(policy) is Policy and 1 <= policy.max_attempts <= 128
                     and 1 <= policy.max_elapsed <= 3600 and 1 <= interval_seconds <= 3600,
                     'REVIEWED_FINITE_WORKER_WITHIN_HUMAN_WINDOW_REQUIRED')
    for value in (logical_scope, first_operation, first_scope_hash, context_ref, generation_ref):
        evidence.require(type(value) is str and len(value) == 64
                         and all(c in '0123456789abcdef' for c in value),
                         'EXACT_WORKER_HISTORY_AND_GENERATION_BINDINGS_REQUIRED')
    return {'schema': 'ouf.policy-token-new-finite-worker-session.v1',
            'logicalOwnerScopeHash': logical_scope, 'predecessorFirstGrantOperation': first_operation,
            'predecessorFirstGrantScopeHash': first_scope_hash,
            'operation': 'OPEN_NEW_FINITE_WORKER_SESSION_AFTER_RECONCILED_FIRST_GRANT',
            'contextRef': context_ref, 'generationRef': generation_ref,
            'policy': json.loads(evidence.encoded(dataclasses.asdict(policy))),
            'intervalSeconds': interval_seconds,
            'legacyHistoryDisposition': 'UNKNOWN_RETAINED_NOT_RECONCILED',
            'predecessorGrantAttempts': 1, 'automaticBudgetRenewalAllowed': False,
            'consumedClaimReplayAllowed': False}

class OwnerInstallation:
    """Compile and execute all owner effects under one aggregate action.

    Constructor only compiles the reviewable scopes from already custodied roots.
    `install` creates the output child, stages code, retires the writer, rotates
    once, performs the first controlled grant and initializes a distinct bounded
    worker session. A partial installation is reconciliation-only, never reset.
    """
    def __init__(self, action, host_raw, root_evidence_hash, root_source_hash,
                 registration, binding, profile, transport, source_commit,
                 stage_files, policy, context_ref, generation_ref, interval_seconds,
                 clock=lambda: (time.time(), time.monotonic()), *, pregrant_recovery=None,renewal_actor=None):
        evidence.require(type(action) is AggregateAction and type(binding) is Binding
                         and type(profile) is IamProfile and type(transport) is PinnedIamOpener,
                         'CONCRETE_AGGREGATE_OWNER_COMPONENTS_REQUIRED')
        self.action, self.clock = action, clock
        self.host_raw, self.root_hash, self.root_source = bytes(host_raw), root_evidence_hash, root_source_hash
        with roots.completed_roots(host_raw, root_evidence_hash, root_source_hash) as current:
            self.roots = copy.deepcopy(current)
        self.output = roots.TokenOutputCustody(action.authority, action.raw, host_raw,
                                               root_evidence_hash, root_source_hash)
        evidence.require(binding.output_directory == str(self.output.path) and binding.output_gid == 10001,
                         'OWNER_OUTPUT_MUST_USE_SAME_ACTION_CUSTODY')
        self.first = first_grant.FirstControlledGrant.from_completed_custody(
            action.authority, action.raw, host_raw, root_evidence_hash, root_source_hash,
            registration, binding, profile, transport, None, clock, output_custody=self.output)
        self.pregrant_recovery=None
        if pregrant_recovery is not None:
            self.pregrant_recovery=roots.legacy.PregrantRecovery(action.authority,action.raw,pregrant_recovery)
            self.pregrant_recovery.configure(self.output,self.first.transaction.retirement)
            self.pregrant_recovery.configure_first(self.first,renewal_actor)
            self.first.scope['outputCustodyScopeHash']=fingerprint(self.output.scope)
        self.policy, self.context, self.generation, self.interval = policy, context_ref, generation_ref, interval_seconds
        self.worker_scope = finite_worker_scope(self.first.session.scope['logicalOwnerScopeHash'],
            self.first.session.operation, fingerprint(self.first.scope), policy,
            context_ref, generation_ref, interval_seconds)
        self.journal = Journal(self.roots['durableRecovery']['path'])
        self.admission = OnlineIamAdmission(profile, self.first.credential, transport, clock)
        from tools.semantic_policy_token_owner.supervisor import ScheduledRecovery
        self.owner_binding = owner_binding_inputs(binding, self.first.credential, self.admission, self.journal,
            context_ref, generation_ref, fingerprint(dataclasses.asdict(policy)), ScheduledRecovery.PROFILE,
            interval_seconds, fingerprint(self.worker_scope))
        self.owner_hash = fingerprint(self.owner_binding)
        code = self.roots['reviewedCode']
        self.files = dict(stage_files)
        self.manifest = declaration(code['path'], source_commit, self.files,
            directory_identity={k: code[k] for k in ('device','inode')}, owner_binding_hash=self.owner_hash)
        self.scope = {'schema': 'ouf.policy-token-owner-installation.v1',
            'sourceClosureHash': action.closure, 'stageManifestHash': fingerprint(self.manifest),
            'ownerBindingHash': self.owner_hash, 'workerSessionScopeHash': fingerprint(self.worker_scope),
            'firstGrantScopeHash': fingerprint(self.first.scope),
            'completedRootEvidenceHash': root_evidence_hash, 'rootCreationSourceClosureHash': root_source_hash,
            'outputCustodyScopeHash': fingerprint(self.output.scope),
            'operation': 'INSTALL_OWNER_AFTER_FIRST_CONTROLLED_GRANT',
            'journalPath': str(self.journal.root), 'contextRef': context_ref, 'generationRef': generation_ref,
            'initializeJournalOnlyIfAbsent': True, 'legacyHistoryMustRemainUnknown': True,
            'automaticReplayAllowed': False, 'applicationAcceptanceGranted': False}
        self.runtime_scope = {'ownerBindingHash': self.owner_hash,
            'operation': 'RENEW_EXISTING_POLICY_READ_CREDENTIAL', 'legacyWriterMustBeMasked': True,
            'credentialReestablishmentRequired': True, 'automaticBudgetResetAllowed': False}
        self.operation = fingerprint({'logicalOwnerScopeHash': self.worker_scope['logicalOwnerScopeHash'],
                                      'operation': 'FIRST_COMPLETE_TOKEN_OWNER_INSTALLATION'})
        self.intent_name = 'policy-token-owner-installation-'+self.operation+'.private.json'
        if self.pregrant_recovery is not None:
            self.scope['pregrantRecovery']=copy.deepcopy(self.pregrant_recovery.proof)
            self.pregrant_recovery.owner_scope=copy.deepcopy(self.scope)
            self.intent_name=self.pregrant_recovery.continuation

    def scopes(self):
        return {'policyTokenOwnerInstallation': copy.deepcopy(self.scope),
            'policyTokenOutputCustody': copy.deepcopy(self.output.scope),
            'policyTokenLegacyRetirement': copy.deepcopy(self.first.transaction.retirement.scope),
            'policyTokenCredentialReestablishment': copy.deepcopy(self.first.transaction.scope),
            'policyTokenAccountingGapMigration': copy.deepcopy(self.first.session.scope),
            'policyTokenFirstControlledGrant': copy.deepcopy(self.first.scope),
            'policyTokenFiniteWorkerSession': copy.deepcopy(self.worker_scope),
            'tokenOwnerRuntime': copy.deepcopy(self.runtime_scope)}

    def guard(self):
        for key, scope in self.scopes().items():
            self.action.guard(key, scope)
        with roots.completed_roots(self.host_raw, self.root_hash, self.root_source) as current:
            evidence.require(current == self.roots, 'OWNER_INSTALLATION_ROOTS_CHANGED')
        evidence.require(fingerprint(self.worker_scope)==self.scope['workerSessionScopeHash']
                         and fingerprint(self.manifest)==self.scope['stageManifestHash'],
                         'OWNER_INSTALLATION_PLAN_CHANGED')

    def _write_once(self, directory, name, raw):
        fd = os.open(name, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600, dir_fd=directory)
        try:
            with os.fdopen(os.dup(fd), 'wb') as stream:
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
            os.fsync(directory)
            info=os.fstat(fd)
            evidence.require(stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==0
                and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1
                and evidence.identity(info)==evidence.identity(os.stat(name,dir_fd=directory,follow_symlinks=False)),
                'OWNER_INSTALLATION_PRIVATE_PUBLICATION_UNPROVEN')
        finally: os.close(fd)

    def install(self):
        self.guard()
        if self.pregrant_recovery is not None:
            self.pregrant_recovery.admit()
        with evidence.protected_parent() as directory:
            lock=os.open(self.intent_name+'.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=directory)
            try:
                info=os.fstat(lock)
                evidence.require(stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==0
                    and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1,'OWNER_INSTALLATION_FENCE_CUSTODY_REQUIRED')
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                seal=evidence.identity(info)
                def guarded():
                    self.guard()
                    evidence.require(seal==evidence.identity(os.fstat(lock))==evidence.identity(
                        os.stat(self.intent_name+'.lock',dir_fd=directory,follow_symlinks=False)),
                        'OWNER_INSTALLATION_INVOCATION_FENCE_CHANGED')
                guarded()
                # Stable logical reservation, irrespective of new approval/job IDs.
                try: evidence.read_member(directory,self.intent_name)
                except FileNotFoundError: pass
                else: raise evidence.CandidateDenied('OWNER_INSTALLATION_ALREADY_RESERVED_RECONCILIATION_REQUIRED')
                with protected_directory(self.journal.root) as state:
                    forbidden={'recovery.json','recovery.lock','invocation.lock','owner-admission.json',
                               'owner-first-grant.json','owner-session.json'}
                    evidence.require(not forbidden.intersection(os.listdir(state)),
                                     'EXISTING_OWNER_HISTORY_MUST_NOT_BE_INITIALIZED_AGAIN')
                self._write_once(directory,self.intent_name,evidence.encoded({
                    'schema':'ouf.policy-token-owner-installation-intent.v1','operation':self.operation,
                    'scope':self.scope,'authorityHash':self.action.authority_hash,
                    'state':'RESERVED_OUTCOME_UNPROVEN','automaticReplayAllowed':False}))
                guarded()
                self.first.prepare_output()
                guarded()
                ProtectedTokenSourceStage(self.manifest,self.files,self.action.authority,self.action.raw).stage()
                guarded()
                if self.pregrant_recovery is not None:
                    self.pregrant_recovery.prepare_credential(self.first)
                guarded()
                receipt=self.first.migrate()
                guarded()
                # Same-invocation result AND exact durable receipt are necessary;
                # a stat of a pre-existing token cannot complete installation.
                receipt_raw=evidence.read_member(directory,self.first.name)
                evidence.require(evidence.decode(receipt_raw)==receipt
                    and receipt['operation']==self.first.session.operation
                    and receipt['scopeHash']==fingerprint(self.first.scope)
                    and receipt['state']=='TOKEN_PUBLISHED_NOT_RUNTIME_ACCEPTED'
                    and receipt['attemptSlotsConsumed']==1 and receipt['gapRemainsOpen'] is True,
                    'RECONCILED_FIRST_CONTROLLED_GRANT_REQUIRED')
                worker=self._initialize_worker(receipt,receipt_raw,guarded)
                guarded()
                self._write_once(directory,self.intent_name+'.completed',evidence.encoded({
                    'schema':'ouf.policy-token-installed-owner-result.v1','operation':self.operation,
                    'scopeHash':fingerprint(self.scope),'firstGrantReceiptHash':evidence.sha(receipt_raw),
                    'state':'OWNER_READY_FOR_FINITE_WORKER_NOT_APPLICATION_ACCEPTED',
                    'workerSessionScopeHash':fingerprint(self.worker_scope),
                    'legacyHistoricalGrantAttempts':None,'historicalAccountingReconciled':False,
                    'controlledPredecessorGrantAttempts':1,'workerGrantAttempts':0,
                    'budgetReset':False,'r12Touched':False,'notReleaseAcceptance':True}))
                return worker
            except Exception:
                # Revocation is only for the newly installed generation and never
                # repairs/reinitializes partial files or refunds the first grant.
                if hasattr(self,'owner'):
                    try:self.owner.pause()
                    except Exception:pass
                raise
            finally:os.close(lock)

    def _initialize_worker(self, receipt, receipt_raw, guard):
        from tools.semantic_policy_token_owner.supervisor import ScheduledRecovery
        guard();wall,mono=self.clock()
        authority=evidence.decode(self.action.raw)
        evidence.require(authority['expiresAt']>wall and receipt['validUntilMonotonic']-mono>=self.first.binding.minimum_remaining,
                         'CURRENT_AUTHORITY_AND_FIRST_TOKEN_WINDOW_REQUIRED')
        row={'schema':'ouf.bounded-recovery.v1','contextRef':self.context,'generationRef':self.generation,
            'policyHash':fingerprint(dataclasses.asdict(self.policy)), 'state':'PUBLISHING','attempts':0,
            'startedWall':wall,'startedMonotonic':mono,'lastWall':wall,'lastMonotonic':mono,
            'nextWall':None,'nextMonotonic':None,'reason':'FIRST_CONTROLLED_GRANT_HANDOFF',
            'renewalProfile':ScheduledRecovery.PROFILE,'intervalSeconds':self.interval,'publicationCount':0,
            'nextRenewalWall':None,'nextRenewalMonotonic':None,'tokenExpiresWall':None,'tokenExpiresMonotonic':None,
            'workerSessionHash':fingerprint(self.worker_scope),'firstGrantReceiptHash':evidence.sha(receipt_raw),
            'legacyHistory':{'state':'UNKNOWN','cumulativeGrantAttemptCount':None,'reconciled':False,'gapRemainsOpen':True},
            'controlledPredecessorGrantAttempts':1,'controlledCumulativeGrantAttempts':1,
            'bootId':receipt['bootId']}
        with protected_directory(self.journal.root) as directory:
            guard()
            self._write_once(directory,'owner-first-grant.json',receipt_raw)
            self._write_once(directory,'owner-session.json',evidence.encoded(self.worker_scope))
            self.journal.initialize(row)
            marker={'schema':'ouf.policy-token-owner-admission.v1','ownerProfileHash':self.owner_hash,
                'contextRef':self.context,'generationRef':self.generation,'version':0,'state':'BLOCKED',
                'tokenHash':None,'blockedAttempt':None}
            self._write_once(directory,'owner-admission.json',evidence.encoded(marker))
        guard()
        self.owner=InstalledTokenOwner(self.first.binding,self.first.credential,self.admission,self.journal,
            self.context,self.generation,self.manifest,self.action.authority,self.action.raw)
        token=self._read_first_token(receipt)
        self.owner.admit(token,receipt['validUntilMonotonic'],self.first.binding.digest(),
                         min(mono+30,mono+authority['expiresAt']-wall))
        guard();self.owner.guard(self.first.binding.digest());wall,mono=self.clock()
        expires=receipt['validUntilMonotonic'];delay=min(self.interval,(expires-mono)/2)
        evidence.require(delay>=1,'FIRST_PUBLICATION_RENEWAL_WINDOW_REQUIRED')
        active={**row,'state':'ACTIVE','publicationCount':1,'reason':'FIRST_GRANT_ADMITTED_TO_NEW_FINITE_SESSION',
            'lastWall':wall,'lastMonotonic':mono,'nextRenewalWall':wall+delay,'nextRenewalMonotonic':mono+delay,
            'tokenExpiresWall':wall+expires-mono,'tokenExpiresMonotonic':expires}
        self.journal.compare_and_save(row,active)
        worker=build_worker(self.first.binding,self.first.credential,self.first.profile,self.first.transport,
            self.journal,self.policy,self.context,self.generation,self.manifest,self.action.authority,
            self.action.raw,interval_seconds=self.interval,clock=self.clock)
        # Fresh proven publication in this invocation only. Restart factory still
        # defaults false and requires reconciliation; no durable resume shortcut.
        worker.active_here=True
        self.observer=InstalledTokenOwner(self.first.binding,self.first.credential,self.admission,self.journal,
            self.context,self.generation,self.manifest,self.action.authority,self.action.raw,observer=True)
        return worker

    def _read_first_token(self, receipt):
        b=self.first.binding
        with protected_directory(b.output_directory,gid=b.output_gid,mode=0o750) as directory:
            fd=os.open(b.output_member,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
            try:
                before=os.fstat(fd)
                evidence.require(stat.S_ISREG(before.st_mode) and before.st_uid==0 and before.st_gid==b.output_gid
                    and stat.S_IMODE(before.st_mode)==0o440 and before.st_nlink==1 and 0<before.st_size<=65536,
                    'NEW_FIRST_TOKEN_CUSTODY_REQUIRED')
                raw=os.read(fd,65537)
                evidence.require(len(raw)==before.st_size and evidence.sha(raw)==receipt['tokenHash']
                    and evidence.identity(before)==evidence.identity(os.fstat(fd))==evidence.identity(
                        os.stat(b.output_member,dir_fd=directory,follow_symlinks=False)),
                    'EXACT_NEW_FIRST_TOKEN_RECEIPT_REQUIRED')
                return raw.decode('utf-8')
            finally:os.close(fd)
