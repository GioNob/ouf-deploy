"""Cohort-only continuation after a proven spent first grant.

The independent owner installer keeps its original closed dependency graph.
This continuation is included only in the authenticated full cohort closure.
"""
import copy
import json
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


class GovernedSemanticOwnerContinuation:
    """Token-only continuation; construction and scope compilation have no effects.

    Requires a newly signed, finite AggregateAction. A deterministic global
    fence is consumed before source staging or journal initialization. Partial
    installation is reconciliation-only; the cancelled predecessor is untouched.
    """
    def __init__(self,action,value,stage_files,source_commit,review,records,first_receipt,
                 review_binding,engine_binding,journal_directory,
                 clock=lambda:(time.time(),time.monotonic()),*,transport=None):
        from tools.chatbot_file_cohort.action_process import private_file
        from tools.semantic_policy_token_owner.installed_owner import compile_governed_session
        from tools.semantic_policy_token_owner.supervisor import ScheduledRecovery
        evidence.require(type(action)is AggregateAction,'TYPED_CURRENT_GOVERNED_ACTION_REQUIRED')
        evidence.require(fingerprint(value)==review['retainedOwnerInputsHash']
            and evidence.sha(private_file(review_binding,8388608))==fingerprint(review),
            'EXACT_RETAINED_OWNER_AND_PRIVATE_REVIEW_REQUIRED')
        self.action,self.value,self.clock=action,copy.deepcopy(value),clock
        self.raw=action.raw
        self.review,self.records,self.receipt=copy.deepcopy(review),copy.deepcopy(records),copy.deepcopy(first_receipt)
        evidence.require(type(records['owner-session.json'].get('policy',{}).get('max_attempts'))is int
            and 0<=records['recovery.json']['attempts']<=records['owner-session.json']['policy']['max_attempts']<=128,
            'PREDECESSOR_ATTEMPTS_EXCEED_ITS_REVIEWED_BUDGET')
        self.review_binding=copy.deepcopy(review_binding)
        self.host_raw=private_file(value['hostInputBinding'],2097152)
        self.root_hash,self.root_source=value['rootEvidenceHash'],value['rootCreationSourceClosureHash']
        with roots.completed_roots(self.host_raw,self.root_hash,self.root_source)as current:self.roots=copy.deepcopy(current)
        binding=Binding(**value['binding']);profile_value=copy.deepcopy(value['iamProfile'])
        for key in ('required_scopes','allowed_scopes','peer_addresses'):profile_value[key]=tuple(profile_value[key])
        profile=IamProfile(**profile_value);profile.match(binding)
        transport=PinnedIamOpener(profile)if transport is None else transport
        evidence.require(type(transport)is PinnedIamOpener and transport.profile==profile
            and transport.trust_digest()==value['tlsTrustSetHash'],'CURRENT_RETAINED_IAM_TRUST_REQUIRED')
        credential=CredentialFile(Path(self.roots['ownerCredential']['path'])/'client-secret')
        self.first=RetainedGrantReference(binding,credential,profile,transport)
        self.policy=Policy(max_attempts=(review['proposedFiniteBudget']['maximumNewTokenGrantAttempts']
            if review.get('schema')=='ouf.chatbot-semantic-functional-session-review.v2'else 128),max_elapsed=3600,attempt_timeout=30)
        self.context=fingerprint({'operation':review['logicalOperation'],'reviewHash':fingerprint(review)})
        self.generation=fingerprint(review['registryGeneration']);self.interval=60
        self.worker_scope=compile_governed_session(review,records,first_receipt,
            evidence.decode(evidence.encoded(dataclasses.asdict(self.policy))),self.context,self.generation,self.interval)
        evidence.require(str(journal_directory)==self.worker_scope['fenceBinding']['value']['journalPath'],
            'DETERMINISTIC_NEW_SESSION_JOURNAL_REQUIRED')
        self.journal=Journal(journal_directory)
        self.admission=OnlineIamAdmission(profile,credential,transport,clock)
        self.runtime_binding={'schema':'ouf.semantic-functional-runtime-binding.v1',
            'reviewHash':fingerprint(review),'engine':copy.deepcopy(engine_binding),
            'registryGeneration':copy.deepcopy(review['registryGeneration'])}
        self.owner_binding=owner_binding_inputs(binding,credential,self.admission,self.journal,self.context,
            self.generation,fingerprint(dataclasses.asdict(self.policy)),ScheduledRecovery.PROFILE,
            self.interval,fingerprint(self.worker_scope))
        self.owner_hash=fingerprint(self.owner_binding);self.files=dict(stage_files)
        code=self.roots['reviewedCode']
        self.manifest=declaration(code['path'],source_commit,self.files,
            directory_identity={k:code[k]for k in('device','inode')},owner_binding_hash=self.owner_hash)
        self.scope={'schema':'ouf.policy-token-owner-installation.v1','sourceClosureHash':action.closure,
            'stageManifestHash':fingerprint(self.manifest),'ownerBindingHash':self.owner_hash,
            'workerSessionScopeHash':fingerprint(self.worker_scope),
            'operation':'INSTALL_TOKEN_ONLY_GOVERNED_CONTINUATION_NO_FIRST_GRANT',
            'journalPath':str(self.journal.root),'contextRef':self.context,'generationRef':self.generation,
            'privateReviewHash':fingerprint(review),'firstGrantReceiptHash':fingerprint(first_receipt),
            'journalDirectoryIdentity':list(self.journal.directory_id),
            'initializeJournalOnlyIfAbsent':True,'automaticReplayAllowed':False,
            'applicationAcceptanceGranted':False}
        self.runtime_scope={'ownerBindingHash':self.owner_hash,'operation':'RENEW_EXISTING_POLICY_READ_CREDENTIAL',
            'legacyWriterMustBeMasked':True,'credentialReestablishmentRequired':True,'automaticBudgetResetAllowed':False}

    def scopes(self):
        return {'policyTokenOwnerInstallation':copy.deepcopy(self.scope),
            'policyTokenFiniteWorkerSession':copy.deepcopy(self.worker_scope),
            'tokenOwnerRuntime':copy.deepcopy(self.runtime_scope),
            'semanticFunctionalRuntime':copy.deepcopy(self.runtime_binding)}

    def guard(self,*,fence_required):
        from tools.chatbot_file_cohort.action_process import private_file
        from tools.semantic_policy_token_owner.installed_owner import read_private
        for key,scope in self.scopes().items():self.action.guard(key,scope)
        InstalledTokenOwner.guard_governed_registry(self,self.worker_scope)
        evidence.require(evidence.sha(private_file(self.review_binding,8388608))==fingerprint(self.review),
            'GOVERNED_REVIEW_CHANGED')
        self.journal.check_directory()
        evidence.require(list(self.journal.directory_id)==self.scope['journalDirectoryIdentity'],
            'GOVERNED_SESSION_DIRECTORY_DRIFT')
        with roots.completed_roots(self.host_raw,self.root_hash,self.root_source)as current:
            evidence.require(current==self.roots,'COMPLETED_ROOT_CUSTODY_DRIFT')
        evidence.require(roots.legacy.quiescent(roots.legacy.read_units()),'LEGACY_WRITER_FENCE_REQUIRED')
        prior=Path(self.review['predecessorJournalDirectory'])
        with protected_directory(prior)as directory:
            for name,value in self.records.items():
                evidence.require(evidence.decode(read_private(directory,name,131072))==value,'CANCELLED_PREDECESSOR_CHANGED')
            evidence.require(evidence.decode(read_private(directory,'owner-first-grant.json',16384))==self.receipt,
                'FIRST_GRANT_HISTORY_CHANGED')
        if fence_required:
            fence=self.worker_scope['fenceBinding'];path=Path(fence['path'])
            with protected_directory(path.parent)as directory:
                evidence.require(evidence.decode(read_private(directory,path.name,16384))==fence['value'],
                    'GOVERNED_GLOBAL_FENCE_CHANGED')

    def install(self):
        from tools.semantic_policy_token_owner.supervisor import ScheduledRecovery
        from tools.semantic_policy_token_owner.installed_owner import InstalledTokenOwner
        self.guard(fence_required=False)
        evidence.require(not os.listdir(self.journal.root),'NEW_SESSION_JOURNAL_ALREADY_CONSUMED')
        fence=self.worker_scope['fenceBinding'];path=Path(fence['path'])
        with protected_directory(path.parent)as directory:
            # Exclusive stable-scope claim survives failure; never auto replace.
            if self.review.get('schema')=='ouf.chatbot-semantic-functional-session-review.v2':
                advance_worker_fence(self.action,self.worker_scope,self.review['predecessorJournalDirectory'])
            else:OwnerInstallation._write_once(self,directory,path.name,evidence.encoded(fence['value']))
        self.guard(fence_required=True)
        ProtectedTokenSourceStage(self.manifest,self.files,self.action.authority,self.action.raw).stage()
        self.guard(fence_required=True);wall,mono=self.clock()
        previous=self.records['recovery.json'];prior=self.worker_scope['predecessorGrantAttempts']
        row={'schema':'ouf.bounded-recovery.v1','contextRef':self.context,'generationRef':self.generation,
            'policyHash':fingerprint(dataclasses.asdict(self.policy)),'state':'NEW','attempts':0,
            'startedWall':wall,'startedMonotonic':mono,'lastWall':wall,'lastMonotonic':mono,
            'nextWall':None,'nextMonotonic':None,'reason':'EXPLICIT_GOVERNED_SEMANTIC_SESSION',
            'renewalProfile':ScheduledRecovery.PROFILE,'intervalSeconds':self.interval,'publicationCount':0,
            'nextRenewalWall':None,'nextRenewalMonotonic':None,'tokenExpiresWall':None,'tokenExpiresMonotonic':None,
            'workerSessionHash':fingerprint(self.worker_scope),'firstGrantReceiptHash':fingerprint(self.receipt),
            'legacyHistory':copy.deepcopy(previous['legacyHistory']),
            'controlledHistoryProfile':self.worker_scope['controlledHistoryProfile'],
            'controlledPredecessorGrantAttempts':prior,'controlledCumulativeGrantAttempts':prior,
            'bootId':self.receipt['bootId']}
        with protected_directory(self.journal.root)as directory:
            values={'owner-session-review.json':self.review,'owner-session.json':self.worker_scope,
                'owner-first-grant.json':self.receipt,
                'owner-admission.json':{'schema':'ouf.policy-token-owner-admission.v1',
                    'ownerProfileHash':self.owner_hash,'contextRef':self.context,'generationRef':self.generation,
                    'version':0,'state':'BLOCKED','tokenHash':None,'blockedAttempt':None},
                **{'predecessor-'+name:value for name,value in self.records.items()}}
            for name,value in values.items():OwnerInstallation._write_once(self,directory,name,evidence.encoded(value))
        self.journal.initialize(row);self.guard(fence_required=True)
        worker=build_worker(self.first.binding,self.first.credential,self.first.profile,self.first.transport,
            self.journal,self.policy,self.context,self.generation,self.manifest,self.action.authority,self.action.raw,
            interval_seconds=self.interval,clock=self.clock)
        evidence.require(worker.active_here is False,'EXPIRED_TOKEN_CANNOT_BE_ADOPTED')
        self.observer=InstalledTokenOwner(self.first.binding,self.first.credential,self.admission,self.journal,
            self.context,self.generation,self.manifest,self.action.authority,self.action.raw,observer=True)
        return worker


TOKEN_STAGE_SOURCE = {
    'bounded-recovery.py':'tools.semantic_lease_recovery.bounded_recovery',
    'recovery-journal.py':'tools.semantic_lease_recovery.recovery_journal',
    **{name.replace('_','-')+'.py':'tools.semantic_policy_token_owner.'+name for name in
       ('producer','supervisor','mount_observation','source_stage','installed_owner','worker_entry','reporter','iam_admission')}}


def token_only_session_main(prepared,sources,closure,proposal,proposal_binding,candidate,candidate_binding,
                            records,first_receipt,context_path,executor_binding,emit=print,*,transport=None,
                            interrupted_preparation=None,expired_login_window=None):
    """One sealed foreground invocation; no old delivery/phase executor is called."""
    import signal
    import threading
    import iam_governance_intake as governance
    from iam_owner_action import publish
    from cutover_authority import CutoverAuthority
    from tools.semantic_provider_deployment_authentication import DetachedAuthenticator
    from tools.chatbot_file_cohort.human_session import HumanSession,HumanSessionPaused
    from tools.chatbot_file_cohort.review import (compile_token_review,terminal_token_decision,
        issue_token_action,command_matches,digest,encoded,require)
    from tools.semantic_policy_token_owner.installed_owner import compile_governed_session
    from tools.semantic_policy_token_owner.reporter import OwnerReporter
    from tools.semantic_policy_token_owner.worker_entry import serve

    require(candidate.get('schema')=='ouf.semantic-functional-session-candidate.v1'
        and candidate.get('privateReviewHash')==proposal_binding['sha256']
        and candidate.get('firstGrantReceiptHash')==digest(first_receipt)
        and candidate.get('nativeQualification')=={'nativeUidGidModeProven':True,'atomicPublisherCodeUsed':True,
            'syntheticDataOnly':True,'fixtureRemoved':True,'applicationReadinessProven':False}
        and candidate.get('runtimeAuthorityIssued')is False and candidate.get('readyForExecution')is False,
        'EXACT_UNISSUED_NATIVE_CANDIDATE_REQUIRED')
    require(digest(proposal)==proposal_binding['sha256'] and digest(candidate)==candidate_binding['sha256'],
        'EXACT_TOKEN_SESSION_CANDIDATE_AND_PROPOSAL_BYTES_REQUIRED')
    require({k:prepared['authorization']['plan']['selection'][k] for k in ('issuer','tenant','subject')}
        ==proposal['requestedHumanActor'],'EXACT_RETAINED_AUTHENTICATED_HUMAN_SELECTION_REQUIRED')
    for program in closure['executables'].values():command_matches(program)
    context=Path(context_path)
    expected={'sourceClosureHash':digest(closure),'creationRequestHash':digest(proposal),
        'predecessorHistoryHash':digest(proposal['predecessorRecordHashes']),
        'predecessorIncidentRef':records['owner-session.json']['logicalOwnerScopeHash'],
        'intakeHash':digest(proposal)}
    verifier=DetachedAuthenticator(governance.POLICY,str(context),closure['executables']['openssl'])
    absent={'path':str(context/'UNISSUED-human.json'),'sha256':evidence.sha(b'UNISSUED_TOKEN_ONLY_PREPARATION')}
    unissued=AggregateAction(CutoverAuthority(verifier,absent,absent['sha256'],governance.CONTEXT,expected),
        encoded({'schema':'ouf.semantic-token-only-unissued-preparation.v1'}),digest(closure))
    scope=compile_governed_session(proposal,records,first_receipt,candidate['compiledSessionScope']['policy'],
        candidate['compiledSessionScope']['contextRef'],candidate['compiledSessionScope']['generationRef'],60)
    require(scope==candidate['compiledSessionScope'],'NATIVE_CANDIDATE_SCOPE_CHANGED')
    fence=Path(scope['fenceBinding']['path']);journal=Path(scope['fenceBinding']['value']['journalPath'])
    require(not os.path.lexists(fence),'TOKEN_LOGICAL_SCOPE_ALREADY_CLAIMED_RECONCILIATION_REQUIRED')
    if interrupted_preparation is None:
        with protected_directory(journal.parent)as directory:
            os.mkdir(journal.name,0o700,dir_fd=directory);os.fsync(directory)
    else:
        require(set(interrupted_preparation)=={'schema','contextPath','directoryIdentity','targetReadbackHash'}
            and interrupted_preparation['schema']=='ouf.pre-authority-token-preparation-continuation.v1'
            and interrupted_preparation['contextPath']==str(context)
            and type(interrupted_preparation['targetReadbackHash'])is str
            and len(interrupted_preparation['targetReadbackHash'])==64
            and all(c in '0123456789abcdef'for c in interrupted_preparation['targetReadbackHash']),
            'EXACT_INTERRUPTED_PREPARATION_BINDING_REQUIRED')
        with protected_directory(context)as directory:
            info=os.fstat(directory)
            require([info.st_dev,info.st_ino]==interrupted_preparation['directoryIdentity']
                and set(os.listdir(directory))=={'human-session'}, 'UNISSUED_INTERRUPTED_CONTEXT_REQUIRED')
        with protected_directory(journal)as directory:
            require(not os.listdir(directory),'INTERRUPTED_NEW_WORKER_MUST_REMAIN_UNINITIALIZED')
    files={name:sources[module]for name,module in TOKEN_STAGE_SOURCE.items()}
    args=(prepared['owner'],files,closure['declaration']['sourceCommit'],proposal,records,first_receipt,
        proposal_binding,prepared['engine'],journal)
    planned=GovernedSemanticOwnerContinuation(unissued,*args,transport=transport)
    # Scope construction above cannot use the absent preparation mandate.
    human_directory=context/'human-session'
    if interrupted_preparation is None:
        with protected_directory(context)as directory:
            os.mkdir('human-session',0o700,dir_fd=directory);os.fsync(directory)
        human_expiry=int(time.time())+7200
    else:
        previous_human=Journal(human_directory).read()
        human_expiry=previous_human['binding']['expiresAt']
    human=HumanSession(prepared['authorization']['plan']['selection'],human_directory,
        human_directory/'human-access.jwt',human_expiry)
    continuation=None
    window_receipt=None
    if expired_login_window:
        require(interrupted_preparation is not None,'BOUND_INTERRUPTED_PREPARATION_REQUIRED')
        from tools.chatbot_file_cohort.review import terminal_login_window_decision
        operation_binding={'sourceClosureHash':digest(closure),'privateReviewHash':digest(proposal),
            'candidateHash':digest(candidate),'preparationHash':digest(interrupted_preparation),
            'executorBindingHash':digest(executor_binding)}
        window_review=human.expired_window_review(operation_binding)
        require(type(expired_login_window)is dict
            and set(expired_login_window)=={'schema','priorOAuthAttempts','predecessorExpiredAt'}
            and expired_login_window['schema']=='ouf.expired-human-login-readback.v1'
            and all(window_review[k]==expired_login_window[k]for k in ('priorOAuthAttempts','predecessorExpiredAt')),
            'EXACT_OBSERVED_OAUTH_ACCOUNTING_REQUIRED')
        emit('OUF_TOKEN_SESSION_PHASE=EXPIRED_LOGIN_WINDOW_REVIEW technical=8/8 functional=0/6')
        window_decision=terminal_login_window_decision(window_review)
        require(window_review==human.expired_window_review(operation_binding),'EXPIRED_HUMAN_PREDECESSOR_CHANGED')
        window_receipt={'schema':'ouf.human-login-window-reopening-receipt.v1',
            'review':window_review,'decision':window_decision,'budgetReset':False,'runtimeAuthorityIssued':False}
        with protected_directory(context)as directory:
            require(set(os.listdir(directory))=={'human-session'},'UNISSUED_INTERRUPTED_CONTEXT_REQUIRED')
            require(publish(directory,'login-window-reopening.json',encoded(window_receipt)),
                    'LOGIN_WINDOW_REOPENING_ALREADY_CONSUMED')
        human=human.start_approved_window(window_review,window_decision,context/'human-session-window2')
        human_directory=human.directory;human_expiry=human.expires_at
        emit('OUF_TOKEN_SESSION_PHASE=EXPLICIT_NEW_HUMAN_LOGIN_WINDOW technical=8/8 functional=0/6')
    if interrupted_preparation is not None and not expired_login_window:
        human._check(previous_human)
        continuation={'schema':'ouf.pre-authority-token-login-continuation-receipt.v1',
            'binding':copy.deepcopy(interrupted_preparation),'previousHumanRowHash':digest(previous_human),
            'attemptsBefore':previous_human['attempts'],'originalHumanExpiry':human_expiry,
            'workerJournalIdentity':list(planned.journal.directory_id),'budgetReset':False}
        with protected_directory(context)as directory:
            require(publish(directory,'preparation-continuation.json',encoded(continuation)),
                    'PRE_AUTHORITY_CONTINUATION_ALREADY_CONSUMED')
        emit('OUF_TOKEN_SESSION_PHASE=CONTINUE_EXISTING_HUMAN_LOGIN technical=8/8 functional=0/6')
        while True:
            try:
                metadata=human.prepare_interrupted_login(emit=emit)
                emit('OUF_HUMAN_LOGIN_CONTINUATION='+encoded(metadata).decode());break
            except HumanSessionPaused as error:
                if error.retry_at is None:raise
                emit('OUF_HUMAN_LOGIN_WAIT='+error.reason)
                threading.Event().wait(min(30,max(0,error.retry_at-time.time())))
    elif not expired_login_window:emit('OUF_TOKEN_SESSION_PHASE=FRESH_HUMAN_LOGIN technical=8/8 functional=0/6')
    human_binding=human.login(emit=emit)
    profile=evidence.decode(governance.public_input(governance.PROFILE))
    role_policy=evidence.decode(governance.public_input(governance.POLICY))
    windows=governance.authority_metadata(profile,role_policy,int(time.time()))
    require(all(row['expiresAt']>=int(time.time())+3600 for row in windows),
        'TOKEN_SESSION_WINDOW_EXCEEDS_EXISTING_ROLE_AUTHORITY')
    final=compile_token_review(closure,planned.scopes(),proposal_binding,candidate_binding,human_binding,context)
    final['executorBinding']=dict(executor_binding)
    if window_receipt is not None:
        final['explicitLoginWindowReopening']=window_receipt
    if interrupted_preparation is not None:
        if continuation is not None:final['preAuthorityContinuation']=continuation
        planned.journal.check_directory()
        with protected_directory(journal)as directory:
            require(not os.listdir(directory),'UNINITIALIZED_WORKER_REQUIRED_BEFORE_DECISION')
        with protected_directory(context)as directory:
            require([os.fstat(directory).st_dev,os.fstat(directory).st_ino]==interrupted_preparation['directoryIdentity']
                and set(os.listdir(directory))==({'human-session','human-session-window2','login-window-reopening.json'}
                    if expired_login_window else {'human-session','preparation-continuation.json'}),
                'INTERRUPTED_CONTEXT_CHANGED_BEFORE_DECISION')
    # Recheck target generation and cancellation after the possibly long login.
    raw=encoded(planned.scopes())
    old_raw=planned.raw;planned.raw=raw
    try:InstalledTokenOwner.guard_governed_registry(planned,planned.worker_scope)
    finally:planned.raw=old_raw
    require(not os.path.lexists(fence),'TOKEN_LOGICAL_SCOPE_ALREADY_CLAIMED_RECONCILIATION_REQUIRED')
    with protected_directory(context)as directory:
        require(publish(directory,'review.json',encoded(final)),'TOKEN_REVIEW_ALREADY_PUBLISHED')
    emit('OUF_TOKEN_SESSION_PHASE=EXACT_HUMAN_REVIEW technical=8/8 functional=0/6')
    decision=terminal_token_decision(final,context/'review.json')
    emit('OUF_TOKEN_SESSION_PHASE=EXISTING_ROLE_ISSUANCE technical=8/8 functional=0/6')
    action=issue_token_action(final,decision,human)
    stop=threading.Event();remaining=decision['expiresAt']-time.time()
    require(0<remaining<=3600,'TOKEN_SESSION_AUTHORITY_EXPIRED_BEFORE_SERVE')
    # Restrict the SAME typed, dual-signed authority while a request is in
    # flight. Publication rechecks this clock, so cancellation cannot publish
    # a late token response before the outer loop observes its stop event.
    def current_session_time():
        require(not stop.is_set(),'TOKEN_SESSION_CANCELLED_OR_EXPIRED')
        return time.time()
    action.authority.clock=current_session_time
    timer=threading.Timer(remaining,stop.set);timer.daemon=True
    previous={}
    for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP):
        previous[sig]=signal.signal(sig,lambda *_:stop.set())
    timer.start()
    try:
        installer=GovernedSemanticOwnerContinuation(action,*args,transport=transport)
        require(installer.scopes()==final['scopes'],'TOKEN_ONLY_APPROVED_SCOPE_CHANGED')
        emit('OUF_TOKEN_SESSION_PHASE=GUARDED_TOKEN_INSTALLATION technical=8/8 functional=0/6')
        worker=installer.install()
        emit('OUF_TOKEN_SESSION_STARTED='+encoded({'authorityPath':str(context/'authority.json'),
            'authorityHash':action.authority_hash,'reviewHash':digest(final),'journalPath':str(journal),
            'priorControlledGrantAttempts':69,'maximumCumulativeGrantAttempts':197,
            'expiresAt':decision['expiresAt'],'completedTechnicalPhases':8,'functionalMilestonesProven':0,
            'registryEffectivePolicyProven':False,'acceptanceGranted':False,'budgetReset':False}).decode())
        serve(worker,stop,OwnerReporter(worker.r.journal,emit))
    finally:
        stop.set();timer.cancel()
        for sig,handler in previous.items():signal.signal(sig,handler)
    emit('OUF_TOKEN_SESSION_ENDED=NO_AUTOMATIC_RESTART_OR_BUDGET_RESET')


def advance_worker_fence(action,scope,predecessor_directory):
 require=evidence.require;digest=fingerprint;encoded=evidence.encoded
 from tools.semantic_policy_token_owner.installed_owner import read_private,unique
 from iam_owner_action import publish
 require(type(action)is AggregateAction,'REAL_SIGNED_FENCE_HANDOFF_AUTHORITY_REQUIRED')
 action.guard('policyTokenFiniteWorkerSession',scope)
 previous=scope.get('predecessorFenceBinding');following=scope['fenceBinding']
 require(type(previous)is dict and previous.get('path')==following.get('path')
  and previous['value']['logicalOwnerScopeHash']==following['value']['logicalOwnerScopeHash']
  and previous['value']['journalPath']==str(predecessor_directory)
  and previous['value']['reviewHash']!=following['value']['reviewHash'],'SAME_LOGICAL_FENCE_SUCCESSOR_REQUIRED')
 path=Path(following['path']);prior=Journal(predecessor_directory)
 with prior.invocation(),protected_directory(path.parent)as directory:
  old=read_private(directory,path.name,16384)
  require(json.loads(old,object_pairs_hook=unique)==previous['value'],'PREDECESSOR_GLOBAL_FENCE_CHANGED')
  # The signed scope binds the complete parent records. Check terminality under
  # its actual invocation lock before consuming the one-use handoff claim.
  with protected_directory(predecessor_directory)as predecessor:
   row=json.loads(read_private(predecessor,'recovery.json',131072),object_pairs_hook=unique)
   require(row.get('state')=='CANCELLED'and row.get('reason')=='CANCELLED_BY_OWNER'
    and digest(row)==scope['predecessorRecordHashes']['recovery.json'],'EXACT_CANCELLED_WORKER_BEFORE_HANDOFF_REQUIRED')
  claim_name=path.name+'.successor-'+digest(previous['value'])+'.claim.json'
  claim={'schema':'ouf.policy-token-fence-handoff-claim.v1','authorityHash':action.authority_hash,
   'predecessor':previous,'successor':following,'budgetReset':False,'automaticReplayAllowed':False}
  require(publish(directory,claim_name,encoded(claim)),'WORKER_HANDOFF_ALREADY_CLAIMED_RECONCILIATION_REQUIRED')
  temporary=path.name+'.next-'+digest(following['value'])
  require(publish(directory,temporary,encoded(following['value'])),'FENCE_HANDOFF_TEMPORARY_ALREADY_PRESENT')
  action.guard('policyTokenFiniteWorkerSession',scope)
  require(read_private(directory,path.name,16384)==old,'FENCE_CHANGED_BEFORE_ATOMIC_HANDOFF')
  os.replace(temporary,path.name,src_dir_fd=directory,dst_dir_fd=directory);os.fsync(directory)
  require(json.loads(read_private(directory,path.name,16384),object_pairs_hook=unique)==following['value'],'FENCE_HANDOFF_READBACK_UNPROVEN')
