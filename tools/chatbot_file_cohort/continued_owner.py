"""Cohort-only continuation after a proven spent first grant.

The independent owner installer keeps its original closed dependency graph.
This continuation is included only in the authenticated full cohort closure.
"""
import copy
import dataclasses
import os
from pathlib import Path
import time

import iam_binding_candidate as evidence
import migration_root_custody as roots
from tools.semantic_lease_recovery.bounded_recovery import Policy,fingerprint
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.semantic_policy_token_owner.producer import Binding,CredentialFile,protected_directory
from tools.semantic_policy_token_owner.iam_admission import IamProfile,PinnedIamOpener,OnlineIamAdmission
from tools.semantic_policy_token_owner.installed_owner import InstalledTokenOwner,owner_binding_inputs
from tools.semantic_policy_token_owner.source_stage import declaration,ProtectedTokenSourceStage
from tools.semantic_policy_token_owner.worker_entry import build_worker
from tools.semantic_policy_token_owner.owner_installation import AggregateAction,OwnerInstallation,finite_worker_scope


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
        evidence.require(type(action)is AggregateAction and proof.get('profile')in(PROFILE,'ouf.chatbot-paused-unsigned-attestation-reprocessing.v1','ouf.chatbot-paused-unsigned-attestation-reprocessing.v2','ouf.chatbot-signed-paused-admission-reprocessing.v1','ouf.chatbot-verified-registry-mcp-backup-recovery.v1','ouf.chatbot-created-mcp-migration-continuation.v1','ouf.chatbot-gateway-schema-continuation.v1'),
            'EXACT_POSTGRANT_OWNER_CONTINUATION_REQUIRED')
        validate_worker_seed(predecessor['firstGrant'],predecessor['worker'],predecessor['admission'],
            predecessor['session'],predecessor['completed'],profile=proof['profile'])
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
            self.policy,self.context,self.generation,self.interval,
            **({'predecessor_attempts':proof['newBudget']['priorControlledGrantAttempts'],'cancelled_worker_hash':proof['cancelledWorkerHash'],
                'predecessor_session_hash':proof['workerSessionHash']}if proof['newBudget']['priorControlledGrantAttempts']in(2,3,4,5,6,8,9,10) else{}))
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
            'controlledPredecessorGrantAttempts':self.proof['newBudget']['priorControlledGrantAttempts'],
            'controlledCumulativeGrantAttempts':self.proof['newBudget']['priorControlledGrantAttempts'],'bootId':receipt['bootId']}
        if row['controlledPredecessorGrantAttempts']in(2,3,4,5,6,8,9,10):
            row.update({k:self.worker_scope[k]for k in('controlledHistoryProfile','predecessorCancelledWorkerHash','predecessorWorkerSessionHash')})
        with protected_directory(self.journal.root)as directory:
            for name,value in (('owner-first-grant.json',receipt),('owner-session.json',self.worker_scope),
                ('owner-admission.json',{'schema':'ouf.policy-token-owner-admission.v1','ownerProfileHash':self.owner_hash,
                    'contextRef':self.context,'generationRef':self.generation,'version':0,'state':'BLOCKED',
                    'tokenHash':None,'blockedAttempt':None})):
                OwnerInstallation._write_once(self,directory,name,evidence.encoded(value))
        if row['controlledPredecessorGrantAttempts']in(2,3,4,5,6,8,9,10):
            with protected_directory(self.journal.root)as directory:
                for name,value in(('owner-predecessor-worker.json',self.predecessor['worker']),('owner-predecessor-session.json',self.predecessor['session'])):
                    OwnerInstallation._write_once(self,directory,name,evidence.encoded(value))
        self.journal.initialize(row);self.guard()
        worker=build_worker(self.first.binding,self.first.credential,self.first.profile,self.first.transport,
            self.journal,self.policy,self.context,self.generation,self.manifest,self.action.authority,self.action.raw,
            interval_seconds=self.interval,clock=self.clock)
        evidence.require(worker.active_here is False,'POSTGRANT_EXPIRED_TOKEN_CANNOT_BE_ADOPTED')
        self.observer=InstalledTokenOwner(self.first.binding,self.first.credential,self.admission,self.journal,
            self.context,self.generation,self.manifest,self.action.authority,self.action.raw,observer=True)
        return worker


