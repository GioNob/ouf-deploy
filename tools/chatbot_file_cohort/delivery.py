"""Concrete whole-action execution in one finite process and one authority.

Authorization preparation/actual HUMAN confirmation precede quiescence and the
first token grant. The worker remains in this invocation during the complete
cohort rollout and the user's finite CSV acceptance window. No restart adopts an
old ACTIVE token, no database rollback or grant budget reset is supplied here.
"""
import copy
import errno
import dataclasses
import hashlib
import json
import os
import re
from pathlib import Path
import signal
import shutil
import stat
import threading
import time

import iam_binding_candidate as evidence
import iam_governance_intake as governance
from iam_owner_action import publish, stdlib_binding
from cutover_authority import CutoverAuthority
from file_only_profile import FileOnlyProfile
from engine_creation import Engine,CreationDenied
from cutover_executor import CutoverDenied
from file_only_installation import build as build_registry
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator
from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
from tools.semantic_lease_recovery.bounded_recovery import Policy,Permanent
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.semantic_policy_token_owner.owner_installation import AggregateAction, OwnerInstallation
from tools.semantic_policy_token_owner.producer import Binding, protected_directory
from tools.semantic_policy_token_owner.iam_admission import IamProfile, PinnedIamOpener
from tools.semantic_policy_token_owner.reporter import OwnerReporter
from tools.semantic_policy_token_owner.worker_entry import serve
from tools.chatbot_file_cohort.action_process import private_file,verify_previous_authorization_actions
from tools.chatbot_file_cohort.review import digest, encoded, require, validate_decision, command_matches
from tools.chatbot_file_cohort.containers import CohortContainers, CohortPaused, RegistryReadinessBudget,REGISTRY_READINESS_POLICY
from tools.chatbot_file_cohort.databases import CohortDatabases
from tools.chatbot_file_cohort.gateway import GatewayRoutes, NamespaceAdmin, private_config
from tools.chatbot_file_cohort.authorization import AuthorizationDelta, AuthorizationPaused, OwnerPrimitives, OwnerTransport
from tools.chatbot_file_cohort.images import CohortImages
from tools.chatbot_file_cohort.gateway_runtime import GatewayRuntime, runtime_scope
from tools.chatbot_file_cohort.human_session import HumanSession, HumanSessionPaused
from tools.chatbot_file_cohort.acceptance import AcceptanceObserver
from tools.chatbot_file_cohort.plan import PlanDenied
from image_custody import ImageCustodyDenied,runtime_image_id
import qualified_owner_authorization_lifecycle
import qualified_owner_scope_catalogue

SAFE_NODE_FAILURE_CODES=frozenset(['APPLIED_PAUSED_STAGE_REQUIRED', 'COMPLETED_NODE_ISSUANCE_REQUIRED_NO_RESIGNING', 'COMPLETED_OUTPUT_CREATION_RECEIPT_REQUIRED', 'CONFIGTREE_FILE_UNBOUNDED', 'CONFIGTREE_POLICY_DRIFT', 'CONFIGTREE_PRIVATE_FILE_HASH_OR_METADATA_DRIFT', 'CONFIGTREE_PROCESS_GENERATION_DRIFT', 'CONFIGTREE_PROC_READ_UNBOUNDED', 'CONFIGTREE_SOURCE_OR_MOUNT_CHANGED', 'CURRENT_ATTESTATION_PHASE_AND_CREATION_SCOPE_REQUIRED', 'CURRENT_FULL_ACTION_NODE_AUTHORITY_REQUIRED', 'DISTINCT_NONSHADOWING_FILE_ONLY_MOUNTS_REQUIRED', 'DISTINCT_ROOT_OWNED_PROPOSAL_RECEIPT_KEY_REQUIRED', 'DURABLE_SCOPED_NODE_ATTESTATION_REQUIRED', 'EFFECTIVE_CONFIGTREE_DIRECTORY_IDENTITY_DRIFT', 'EFFECTIVE_CONFIGTREE_FILE_IDENTITY_DRIFT', 'EFFECTIVE_PRIVATE_READONLY_CONFIGTREE_REQUIRED', 'EXACT_ACTUAL_OUTPUT_CUSTODY_OWNER_REQUIRED', 'EXACT_CONFIGTREE_PATH_REQUIRED', 'EXACT_CURRENT_PAUSED_WORKLOAD_GENERATION_REQUIRED', 'EXACT_FILE_ONLY_FOUR_MOUNT_POLICY_REQUIRED', 'EXACT_FILE_ONLY_FRAME_PROFILE_REQUIRED', 'EXACT_FILE_ONLY_FRAME_TRANSITION_PROFILE_REQUIRED', 'EXACT_INDEPENDENT_FILE_ONLY_NODE_RECIPE_REQUIRED', 'EXACT_NATIVE_IMAGE_MERGED_ROOTFS_REQUIRED', 'EXACT_PAUSED_NODE_CONTEXT_AND_GENERATION_REQUIRED', 'EXACT_PAUSED_NODE_OBSERVATION_CONFIGURATION_REQUIRED', 'EXACT_PRIVATE_SINGLETON_CONFIGTREE_REQUIRED', 'EXACT_REVIEWED_DOCKER_CONTEXT_PARENTS_REQUIRED', 'EXACT_ROOT_CONFIGTREE_BINDING_REQUIRED', 'EXACT_RUNC_PAUSED_ENGINE_PAUSED_IDENTITY_REQUIRED', 'EXACT_SINGLETON_CONFIGTREE_DIRECTORY_REQUIRED', 'EXPLICIT_PAUSED_NODE_PATH_PARENTS_REQUIRED', 'FILE_ONLY_FRAME_CHANGED_DURING_OBSERVATION', 'FILE_ONLY_FRAME_PROCESS_GENERATION_DRIFT', 'FILE_ONLY_KEY_METADATA_IDENTITY_DRIFT', 'FILE_ONLY_NODE_EVIDENCE_DRIFT', 'FILE_ONLY_NODE_OWNER_SCOPE_DRIFT', 'FINITE_NATIVE_NODE_OBSERVATION_REQUIRED', 'INDEPENDENT_FILE_ONLY_COMPLETE_OCI_DRIFT', 'INDEPENDENT_IMAGE_ROOTFS_SEAL_MISMATCH', 'NATIVE_NODE_OBSERVATION_DEADLINE', 'NODE_ACCEPTANCE_AUTHORIZATION_DRIFT', 'NODE_BUNDLE_OUTSIDE_REVIEWED_DOCKER_CONTEXT', 'NODE_SANDBOX_OUTSIDE_REVIEWED_PARENT', 'ORIGINAL_STATIC_CONSULTATION_KEY_REQUIRED', 'OUTPUT_CREATION_RECEIPT_CHANGED', 'OUTPUT_HOST_INPUT_RECEIPT_DRIFT', 'OUTPUT_RECEIPT_PARENT_IDENTITY_DRIFT', 'PARTIAL_NODE_ISSUANCE_RECONCILIATION_REQUIRED', 'PAUSED_DOCKER_SANDBOX_NAMESPACE_IDENTITY_DRIFT', 'PAUSED_NODE_BUNDLE_OUTSIDE_APPROVAL', 'PAUSED_NODE_CHANGED_DURING_COMPLETE_OBSERVATION', 'PAUSED_NODE_CONFIGURATION_DRIFT', 'PAUSED_NODE_FULL_OCI_DRIFT', 'PAUSED_NODE_GENERATION_DRIFT', 'PAUSED_NODE_NAMESPACE_INODE_DRIFT', 'PAUSED_NODE_NETWORK_NAMESPACE_REQUIRED', 'PAUSED_NODE_PEER_BUNDLE_OUTSIDE_APPROVAL', 'PAUSED_NODE_ROOTFS_PATH_REQUIRED', 'PAUSED_NODE_RUNTIME_ROOT_OUTSIDE_APPROVAL', 'PAUSED_NODE_TRANSPORT_DRIFT', 'PAUSED_NODE_UNAPPROVED_INTERFACE', 'PAUSED_WORKLOAD_CHANGED_DURING_OBSERVATION', 'PAUSED_WORKLOAD_OBSERVATION_STALE', 'PRIVATE_CONFIGTREE_FILE_CUSTODY_DRIFT', 'PRIVATE_NODE_OWNER_DIRECTORY_REQUIRED', 'RETAINED_COMPLETED_NODE_ATTESTATION_REQUIRED', 'RETAINED_PAUSED_NODE_CHANGED_DURING_READ', 'REVIEWED_ROOTFS_LAYOUT_REQUIRED', 'SAME_ACTUAL_INSTALLED_OWNER_FOR_FUTURE_OUTPUT_REQUIRED', 'SAME_SIGNED_OUTPUT_SCOPE_AND_OWNER_BINDING_REQUIRED', 'SHARED_APPROVED_NODE_SIGNING_CONTEXT_REQUIRED', 'SIGNED_FILE_ONLY_NODE_RECIPE_REQUIRED', 'TYPED_COMPLETE_FILE_ONLY_NODE_OWNER_REQUIRED', 'TYPED_FILE_ONLY_TOKEN_OWNER_AND_PROFILE_REQUIRED', 'TYPED_PAUSED_WORKLOAD_ENGINE_REQUIRED', 'TYPED_ROOT_PAUSED_NODE_OBSERVATION_REQUIRED'])

def public_failure_reason(error):
    if type(error)is Permanent:
        return error.code if error.code in {'AUTHORITY_EXPIRED','AUTHORITY_REVOKED','INTEGRITY_UNPROVEN',
            'GENERATION_CHANGED','PERMANENT_FAILURE','CONFIGURATION_DRIFT'}else'Permanent'
    if type(error)is ValueError and str(error)in SAFE_NODE_FAILURE_CODES:return str(error)
    if type(error)is CreationDenied:
        return str(error) if str(error) in {'CREATION_CONFIG_DRIFT','CREATION_HOST_CONFIG_DRIFT',
            'CREATION_NATIVE_IDENTITY_DRIFT','CREATION_ALREADY_STARTED_OR_STATE_UNKNOWN',
            'ENGINE_OUTCOME_REQUIRES_RECONCILIATION','EXACT_CREATION_INSPECTION_REQUIRED',
            'CREATION_OUTCOME_REQUIRES_RECONCILIATION','PAUSED_STAGE_START_OUTCOME_UNPROVEN',
            'PAUSED_STAGE_PAUSE_OUTCOME_UNPROVEN','EXACT_LIVE_PAUSED_GENERATION_REQUIRED',
            'UNPAUSE_OUTCOME_REQUIRES_RECONCILIATION','RELEASED_GENERATION_DRIFT'} else 'CreationDenied'
    reason=str(error) if type(error) in (evidence.CandidateDenied,RuntimeError,PlanDenied,ImageCustodyDenied) else type(error).__name__
    return reason if re.fullmatch('[A-Z][A-Z0-9_]{0,159}',reason) else type(error).__name__


def public_failure_diagnostic(error):
    result={'schema':'ouf.chatbot-file-cohort-safe-failure-location.v1','messagesPrinted':False}
    if isinstance(error,OSError) and type(error.errno)is int and 0<error.errno<4096:
        result.update(errno=error.errno,errnoName=errno.errorcode.get(error.errno,'UNKNOWN'))
    phase=getattr(error,'safe_diagnostics',{})
    if type(phase)is dict and phase.get('phase') in ('MIGRATION_SCOPE_PREFLIGHT','GOVERNED_LEGACY_RETIREMENT',
            'GOVERNED_CREDENTIAL_REESTABLISHMENT','FIRST_CONTROLLED_GRANT_AND_PUBLICATION'):
        result['componentPhase']=phase['phase']
    frames=[];tb=error.__traceback__
    for _ in range(64):
        if tb is None:break
        module=tb.tb_frame.f_globals.get('__name__','')
        if (module.startswith(('tools.chatbot_file_cohort.','tools.semantic_policy_token_owner.'))
            or module in ('legacy_retirement','accounting_gap_session','credential_transaction','first_controlled_grant','migration_root_custody',
                'engine_creation','creation_adapter','runtime_adapters','gated_stage_adapter','gated_release_adapter',
                'gated_process_observation','file_only_application','file_only_installation','cutover_executor',
                'file_only_node_owner','paused_node_observation','file_only_frame_observation','configtree_mount_observation','paused_workload_binding','paused_attestation_adapter','application_verification_adapter','producer_release_adapter','endpoint_adapter')):
            function=tb.tb_frame.f_code.co_name
            if re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,79}',function):
                frames.append({'module':module,'function':function,'line':tb.tb_lineno})
        tb=tb.tb_next
    result['locations']=frames[-12:]
    return result


def transient_registry_observation(application,error):
    """Only exact read-only UNKNOWN outcomes after a consumed release/verify.

    Executor observes an IN_FLIGHT phase; it cannot resend its mutation. Fresh
    native/process checks reject paused/foreign/changed generations and unknown
    integrity errors before any read-only wait is admitted.
    """
    from tools.chatbot_file_cohort.backup_recovery import RegistryRecoveryReadinessPending,PROFILE as BACKUP_PROFILE
    if type(error)is RegistryRecoveryReadinessPending:
        row=application.executor.t.read()
        recovery=(application.executor.aggregate_scope or {}).get('postGrantRecovery') or {}
        if recovery.get('profile')==BACKUP_PROFILE and row.get('state')=='READY' and row.get('nextPhase')==10:
            return 'VERIFY_APPLICATION'
        return None
    if type(error)is not CutoverDenied or str(error)!='NATIVE_AMBIGUITY_OR_NO_EFFECT_STOPS_CUTOVER':return None
    executor=application.executor;row=executor.t.read()
    if row.get('state')!='IN_FLIGHT' or not row.get('effects'):return None
    effect=row['effects'][-1];phase=effect['phase'];observed=effect.get('nativeEvidenceHash')
    if phase=='VERIFY_APPLICATION':
        expected={'applicationReadinessUnproven':True,'readOnlyReconciliationRequired':True,
            'dependentProducersRemainQuiesced':True}
        if observed!=digest(expected):return None
        executor.adapters[phase].current(executor.intents[phase])
        return phase
    if phase=='START_REPLACEMENT':
        permitted=({'processTransitionChangedDuringRead':True,'readOnlyReconciliationRequired':True,
            'unpauseReplayAllowed':False,'signalReplayAllowed':False},
            {'preapplicationReleaseUnproven':True,'unpauseReplayAllowed':False,'signalReplayAllowed':False})
        if observed not in {digest(v) for v in permitted}:return None
        try:_,native,process=executor.adapters[phase].current(executor.intents[phase])
        except ValueError as current_error:
            if str(current_error)=='GATED_PROCESS_CHANGED_DURING_READ':return phase
            raise
        if (native['State']['Running']is True and native['State']['Paused']is False
            and native['State']['Status']=='running' and process['processKind']in ('GATE_WAITING','APPLICATION_RUNNING')):
            return phase
    return None


STAGE_SOURCE = {
    'bounded-recovery.py':'tools.semantic_lease_recovery.bounded_recovery',
    'recovery-journal.py':'tools.semantic_lease_recovery.recovery_journal',
    **{name.replace('_','-')+'.py':'tools.semantic_policy_token_owner.'+name for name in
       ('producer','supervisor','mount_observation','source_stage','installed_owner','worker_entry','reporter','iam_admission')}}


def create_directories(action):
    """Create exactly the reviewed children; partial creation is never repaired."""
    plan = evidence.decode(action.raw)['finiteActionProcess']
    action.guard('finiteActionProcess', plan)
    root = Path(plan['authorityDirectory'])
    wanted = plan['directoryPlan']
    with protected_directory(root) as directory:
        marker = {'schema':'ouf.chatbot-file-cohort-directory-claim.v1',
            'planHash':digest(wanted), 'authorityHash':action.authority_hash,
            'automaticReplayAllowed':False}
        require(not os.path.lexists(root/'directories.claim.json'),
                'PRIVATE_ACTION_DIRECTORY_CREATION_ALREADY_CONSUMED')
        require(publish(directory, 'directories.claim.json', encoded(marker)),
                'PRIVATE_ACTION_DIRECTORY_CREATION_ALREADY_CONSUMED')
    made = {}
    for name, path in sorted(wanted.items(), key=lambda item:len(Path(item[1]).parts)):
        action.guard('finiteActionProcess', plan)
        child = Path(path)
        require(child.parent == root or str(child.parent) in made,
                'ACTION_DIRECTORY_PARENT_OUTSIDE_REVIEWED_PLAN')
        with protected_directory(child.parent) as parent:
            os.mkdir(child.name, 0o700, dir_fd=parent)
            os.fsync(parent)
        with protected_directory(child) as fd:
            info = os.fstat(fd)
            made[str(child)] = {'device':info.st_dev, 'inode':info.st_ino}
    with protected_directory(root) as directory:
        publish(directory, 'directories.completed.json', encoded({**marker, 'identities':made}))
    return copy.deepcopy(wanted)


def build_owner(action, prepared, sources):
    value = prepared['owner']
    if prepared.get('postGrantRecovery')is not None:
        from tools.chatbot_file_cohort.continued_owner import ContinuedOwnerInstallation
        from tools.chatbot_file_cohort.postgrant_recovery import read_predecessor
        files={name:sources[module]for name,module in STAGE_SOURCE.items()}
        return ContinuedOwnerInstallation(action,value,files,prepared['postGrantRecovery'],read_predecessor(prepared['postGrantRecovery']['profile']),
            prepared['postGrantWorkerDirectory'])
    require(set(value) == {'hostInputBinding','rootEvidenceHash','rootCreationSourceClosureHash','registration',
        'binding','iamProfile','tlsTrustSetHash','sourceCommit','policy','contextRef','generationRef','intervalSeconds'},
        'EXACT_COMPLETE_OWNER_INSTALLATION_INPUTS_REQUIRED')
    host = private_file(value['hostInputBinding'], 2097152)
    profile = copy.deepcopy(value['iamProfile'])
    for key in ('required_scopes','allowed_scopes','peer_addresses'):
        profile[key] = tuple(profile[key])
    profile = IamProfile(**profile)
    transport = PinnedIamOpener(profile)
    require(transport.trust_digest() == value['tlsTrustSetHash'], 'CURRENT_IAM_TLS_TRUST_SET_CHANGED')
    policy = copy.deepcopy(value['policy'])
    policy['delays'] = tuple(policy['delays'])
    files = {name:sources[module] for name,module in STAGE_SOURCE.items()}
    actor=prepared.get('ownerRenewalActor')
    if actor is not None and 'authorization' in prepared:
        selected=prepared['authorization']['plan']['selection']
        require(actor=={k:selected[k] for k in ('issuer','tenant','subject')},
            'OWNER_RENEWAL_ACTOR_MUST_MATCH_CURRENT_HUMAN_SELECTION')
    return OwnerInstallation(action, host, value['rootEvidenceHash'], value['rootCreationSourceClosureHash'],
        value['registration'], Binding(**value['binding']), profile, transport, value['sourceCommit'],
        files, Policy(**policy), value['contextRef'], value['generationRef'], value['intervalSeconds'],
        pregrant_recovery=prepared.get('ownerPregrantRecovery'),renewal_actor=actor)


def native_environment(engine, docker_binding, cli_directory):
    """The legacy typed Psql channel must address this same local Engine."""
    with protected_directory(cli_directory) as directory:
        require(not os.listdir(directory),'EMPTY_PRIVATE_DOCKER_CONFIGURATION_REQUIRED')
    os.environ['PATH']='/usr/sbin:/usr/bin:/sbin:/bin'
    os.environ['DOCKER_HOST']='unix://'+engine.path
    os.environ['DOCKER_CONFIG']=str(cli_directory)
    for name in ('DOCKER_CONTEXT','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'):
        os.environ.pop(name,None)
    require(shutil.which('docker') == docker_binding['path']
            and governance.executable(docker_binding['path']) == docker_binding,
            'ALL_TYPED_DOCKER_CHANNELS_MUST_USE_EXACT_NATIVE_ENGINE')


class Delivery:
    def __init__(self, action, prepared, sources, review, context, emit=print,*,continuation_fence=None):
        require(type(action) is AggregateAction and type(prepared) is dict and type(sources) is dict,
                'REAL_COMPLETE_AGGREGATE_DELIVERY_INPUTS_REQUIRED')
        require(prepared.get('schema') == 'ouf.chatbot-file-cohort-prepared-inputs.v1'
                and digest(prepared) == review['privateInputHashes']['preparedInputs']
                and str(context) == review['scopes']['finiteActionProcess']['authorityDirectory'],
                'EXACT_HUMAN_REVIEWED_PRIVATE_PREPARED_INPUTS_REQUIRED')
        self.action, self.prepared, self.sources = action, copy.deepcopy(prepared), dict(sources)
        self.review, self.context, self.emit = copy.deepcopy(review), Path(context), emit
        require(prepared['gatewayPlan']['transportBinding']['pythonExecutable']==review['sourceClosure']['executables']['python'],
                'GATEWAY_SUBPROCESS_MUST_USE_SAME_REVIEWED_PYTHON')
        self.stop, self.worker_thread, self.worker = threading.Event(), None, None
        self.human_session, self.human_thread = None, None
        self.continuation_fence=continuation_fence
        require((prepared.get('postGrantRecovery')is None)==(continuation_fence is None),
            'POSTGRANT_GLOBAL_CONTINUATION_FENCE_REQUIRED')
        self.engine = Engine(prepared['engine']['socketPath'], tuple(prepared['engine']['socketBinding']))
        self.owner = build_owner(action, prepared, sources)
        for key, scope in self.owner.scopes().items():
            action.guard(key, scope)

    def report(self, phase, **safe):
        value = {'schema':'ouf.chatbot-file-cohort-delivery-status.v1',
            'phase':phase, 'authorityHash':self.action.authority_hash,
            'authorityExpiresAt':evidence.decode(self.action.raw)['expiresAt'],
            'budgetReset':False, 'permanentRuntimeAcceptance':False,
            'chatbotEndToEndProven':False, 'notReleaseAcceptance':True, **safe}
        raw = encoded(value)
        require(len(raw) <= 8192, 'BOUNDED_PUBLIC_DELIVERY_STATUS_REQUIRED')
        # Status is replaceable observation; consumed histories remain immutable.
        with protected_directory(self.context) as directory:
            temporary = 'delivery-status-'+str(os.getpid())+'.tmp'
            fd = os.open(temporary, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600, dir_fd=directory)
            try:
                with os.fdopen(os.dup(fd),'wb') as stream:
                    stream.write(raw); stream.flush(); os.fsync(stream.fileno())
                os.rename(temporary,'delivery-status.json',src_dir_fd=directory,dst_dir_fd=directory)
                os.fsync(directory)
            finally:
                os.close(fd)
        self.emit(raw.decode())
        return value

    def current(self, require_worker=False):
        require(not self.stop.is_set(), 'FULL_ACTION_CANCELLED')
        require(self.action.authority(self.action.raw) is True, 'CURRENT_FULL_ACTION_AUTHORITY_REQUIRED')
        if self.continuation_fence is not None:self.continuation_fence.guard()
        self.engine.check_socket()
        if self.human_session is not None:
            while True:
                try:
                    self.human_session.current(); break
                except HumanSessionPaused as error:
                    require(error.retry_at is not None,error.reason)
                    self.report('HUMAN_SESSION_REFRESH_WAIT',nextAttemptAt=error.retry_at)
                    require(self.action.authority(self.action.raw) is True,'CURRENT_FULL_ACTION_AUTHORITY_REQUIRED')
                    require(not self.stop.wait(min(5,max(1,error.retry_at-time.time()))),'FULL_ACTION_CANCELLED')
        if require_worker:
            require(self.worker_thread is not None and self.worker_thread.is_alive(), 'FINITE_OWNER_WORKER_NOT_LIVE')
            self.owner.observer.await_active(self.owner.first.binding.digest())

    def wait(self, seconds, require_worker=False):
        end = time.monotonic()+max(0,seconds)
        while time.monotonic() < end:
            self.current(require_worker)
            if self.stop.wait(min(5,end-time.monotonic())):
                raise RuntimeError('FULL_ACTION_CANCELLED')

    def await_authorization(self, owner):
        attempt = 0
        while True:
            self.current()
            try:
                result = owner.apply()
                self.report('AUTHORIZATION_RECONCILED_BEFORE_FIRST_GRANT', authorizationEvidenceHash=digest(result))
                return result
            except AuthorizationPaused as error:
                retry = owner.retry_status(error)
                if retry is not None:
                    self.report('AUTHORIZATION_RECONCILIATION_WAIT',**retry)
                    self.wait(max(0,retry['nextAttemptAt']-time.time()))
                    continue
                require(error.reason == 'HUMAN_OWNER_ROLE_CONFIRMATION_REQUIRED', error.reason)
                self.report(error.reason, **{key:error.detail[key] for key in
                    ('proposalId','approvalPath','expiresAt','state') if key in error.detail})
                self.wait((5,15,60)[min(attempt,2)])
                attempt += 1

    def await_container(self, containers, module):
        while True:
            self.current(True)
            try:
                return containers.run_until(module)
            except CohortPaused as error:
                require(error.reason in ('COHORT_READINESS_WAIT','COHORT_READINESS_TRANSIENT') and error.next_attempt_at is not None,
                        error.reason)
                self.report('COHORT_READINESS_WAIT', module=module, nextAttemptAt=error.next_attempt_at)
                self.wait(max(0,error.next_attempt_at-time.time()), True)

    def await_registry(self,application,directory):
        scope=self.review['scopes']['applicationRegistryCutover']
        require(scope.get('readinessPolicy')==REGISTRY_READINESS_POLICY,'REVIEWED_REGISTRY_READINESS_POLICY_REQUIRED')
        budget=RegistryReadinessBudget(Journal(directory),digest(scope),self.action.authority_hash,
            evidence.decode(self.action.raw)['expiresAt'])
        self.current(True);budget.initialize()
        with budget.journal.invocation():
            while True:
                self.current(True)
                delay=budget.wait_seconds()
                if delay>0:
                    row=budget.record()
                    self.report('REGISTRY_READINESS_WAIT',registryPhase=row['phase'],attempts=row['attempts'],
                        nextAttemptAt=row['nextAttemptAt'],maximumAttempts=128)
                    self.wait(delay,True)
                    continue
                budget.reserve()
                try:result=application.verify_registry_and_hold()
                except CutoverDenied as error:
                    self.current(True)
                    phase=transient_registry_observation(application,error)
                    if phase is None:raise
                    channel=getattr(application.executor.adapters[phase],'channel',None)
                    retry_after=getattr(error,'retry_after_seconds',getattr(channel,'retry_after_seconds',0)) if phase=='VERIFY_APPLICATION' else 0
                    budget.schedule(phase,retry_after)
                    continue
                self.current(True);budget.complete();return result

    def run(self):
        previous = {}
        for sig in (signal.SIGINT,signal.SIGTERM):
            previous[sig] = signal.signal(sig, lambda *_:self.stop.set())
        app = None
        try:
            self.current()
            binding=self.prepared['ingestionConfigurationBinding']
            require(type(binding) is dict and set(binding)=={'path','sha256','metadata'},
                    'EXACT_REVIEWED_INGESTION_CONFIGURATION_BINDING_REQUIRED')
            private_config(binding['path'],binding)
            directories = create_directories(self.action)
            native_environment(self.engine,self.review['sourceClosure']['executables']['docker'],directories['dockerCli'])
            authorization = self.prepared['authorization']
            session = authorization['plan']['sessionBinding']
            self.human_session = HumanSession(authorization['plan']['selection'],session['sessionDirectory'],
                session['tokenPath'],session['expiresAt'],action=self.action)
            self.human_thread = self.human_session.start_refresh(self.stop,self.emit)
            self.current()
            require(self.human_session.binding()==session,'EXACT_PREPARED_HUMAN_SESSION_REQUIRED')
            primitives = OwnerPrimitives.from_qualified_modules(qualified_owner_authorization_lifecycle,
                qualified_owner_scope_catalogue, authorization['catalogue'].encode('utf-8'), authorization['helperBindings'])
            auth_owner = AuthorizationDelta(self.action, authorization['plan'], Journal(directories['authorization']),
                OwnerTransport(authorization['plan']['selection'], authorization['adminTokenFile'], authorization['mcpTokenFile'],wait=self.wait,human_session=self.human_session), primitives)
            auth_owner.initialize()
            recovery=self.prepared.get('postGrantRecovery')
            if recovery is None:auth_evidence = self.await_authorization(auth_owner)
            else:
                from tools.chatbot_file_cohort.postgrant_recovery import read_predecessor,current_baseline
                previous=read_predecessor(recovery['profile']);current_baseline(previous,self.engine)
                auth_evidence=copy.deepcopy(previous['payloads']['before']['QUIESCE_PRODUCERS']['ownerEvidence'])
                auth_evidence['planHash']=auth_owner.hash
                require(not auth_owner.record()['effects'],'POSTGRANT_NO_NEW_AUTHORIZATION_MUTATIONS_ALLOWED')
            self.current()
            images = CohortImages(self.action,self.engine,self.prepared['imagePlan'],
                {name:Journal(directories['image'+name.capitalize()]) for name in ('semantic','udp','onboarding','ingestion','mcp')},
                self.review['sourceClosure']['executables']['docker'])
            if recovery is None:
                images.initialize()
                self.report('IMPORTING_QUALIFIED_IMAGES_BEFORE_FIRST_GRANT')
                images.apply()
            else:
                self.action.guard('cohortImageImport',images.scope)
                self.report('RETAINED_IMAGES_VERIFIED_NO_IMPORT_OR_FIRST_GRANT_REPLAY',imagesVerified=5)
            image_audits={row['module']:row['audit'] for row in self.prepared['imagePlan']['images']}
            require(self.prepared['registry']['creationRequest']['Image']==runtime_image_id(image_audits['semantic'])
                and all(row['creationRequest']['Image']==runtime_image_id(image_audits[row['module']])
                    for row in self.prepared['cohortPlan']['replacements']),
                'ALL_CREATION_IMAGES_MUST_MATCH_APPROVED_NATIVE_IDENTITIES')
            self.current()
            gateway_runtime = None
            runtime_plan = self.prepared['gatewayRuntimePlan']
            if runtime_plan is not None:
                gateway_runtime = GatewayRuntime(self.action,self.engine,runtime_plan,Journal(directories['gatewayRuntime']))
                gateway_runtime.initialize()
                while True:
                    self.current()
                    try:
                        gateway_runtime.apply(); break
                    except CohortPaused as error:
                        require(error.reason in ('APISIX_READINESS_WAIT','APISIX_READINESS_TRANSIENT')
                                and error.next_attempt_at is not None,error.reason)
                        self.report('APISIX_READINESS_WAIT',nextAttemptAt=error.next_attempt_at)
                        self.wait(max(0,error.next_attempt_at-time.time()))
                transport = gateway_runtime.transport()
                auth_owner.verify()
            else:
                self.action.guard('gatewayRuntimeInstallation',{
                    'profile':'ouf.chatbot-file-cohort.gateway-runtime.v1','required':False,
                    'retainedTransportHash':digest(self.prepared['gatewayPlan']['transportBinding']),
                    'proposalKeyHash':self.prepared['gatewayPlan']['proposalKeyBinding']['sha256'],
                    'automaticRollbackAllowed':False,'automaticWriteReplayAllowed':False})
                transport = NamespaceAdmin(self.engine,self.prepared['gatewayPlan']['transportBinding'])
            self.current()
            self.report('INSTALLING_DISTINCT_POSTGRANT_FINITE_WORKER' if recovery is not None else 'INSTALLING_FINITE_TOKEN_OWNER')
            self.worker = self.owner.install()
            reporter = OwnerReporter(self.worker.r.journal, self.emit)
            self.worker_thread = threading.Thread(target=serve, args=(self.worker,self.stop,reporter),
                name='finite-policy-token-owner', daemon=False)
            self.worker_thread.start()
            self.current(True)
            plan = self.prepared['cohortPlan']
            containers = CohortContainers(self.action,self.engine,Journal(directories['containers']),plan)
            databases = CohortDatabases(self.action,self.engine,Journal(directories['databases']),plan,
                self.prepared['databasePlan'],directories['backups'],self.review['sourceClosure']['executables']['docker'])
            gateway = GatewayRoutes(self.action,plan,self.prepared['gatewayPlan'],Journal(directories['gateway']),
                transport)
            containers.initialize(); databases.initialize(); gateway.initialize()
            if recovery is not None and recovery.get('profile')=='ouf.chatbot-verified-registry-mcp-backup-recovery.v1':
                from tools.chatbot_file_cohort.backup_recovery import adopt_backups
                adopt_backups(databases,previous,recovery)
            containers.accept_owner_gate('authorization',plan['authorizationPlanHash'],digest(auth_evidence))
            profile = evidence.decode(governance.public_input(governance.PROFILE))
            verifier = self.action.authority.verifier
            signer = ExistingEd25519Signer(profile['keyBindings']['attestor'],profile['keyRefs']['attestor'],verifier,
                {'role':'CREATION_ATTESTATION','issuerRef':governance.CONTEXT['attestorRef'],
                    'installationRef':governance.CONTEXT['installationRef'],'entityRef':governance.CONTEXT['entityRef']})
            registry_directories = self.prepared['registry']['directoryPlan']
            allowed_registry_paths={str(self.context),*directories.values()}
            if recovery is not None:allowed_registry_paths.add(recovery['retainedBackupDirectory'])
            require(all(path in allowed_registry_paths for path in registry_directories.values()),
                    'REGISTRY_DIRECTORIES_OUTSIDE_WHOLE_ACTION_PLAN')
            if recovery is not None:
                from tools.chatbot_file_cohort.postgrant_recovery import seed_registry
                seed_registry(previous,registry_directories,self.action,self.review['scopes']['applicationRegistryCutover'])
            app = build_registry(self.prepared['registry'],self.action,self.owner.observer,self.engine,verifier,signer,
                registry_directories,{'containers':containers,'databases':databases,'gateway':gateway,'authorization':auth_owner})
            self.report('REGISTRY_REPLACEMENT_AND_VERIFICATION')
            registry_evidence = self.await_registry(app,registry_directories['before'])
            self.current(True)
            containers.accept_owner_gate('registry',plan['registryModulePackageHash'],digest(registry_evidence))
            backup_evidence = databases.backup_quiesced()
            containers.accept_owner_gate('database',plan['databasePlanHash'],digest(backup_evidence))
            self.report('MIGRATING_MCP_SCHEMA_WITH_PACKAGED_SEPARATE_ROLE')
            databases.migrate_mcp()
            for module in ('udp','onboarding'):
                self.report('REPLACING_COHORT_MODULE',module=module)
                self.await_container(containers,module); databases.verify_module(module)
            self.current(True)
            self.report('PUBLISHING_REVIEWED_GATEWAY_ROUTES')
            gateway.apply(); gateway_evidence = gateway.verify()
            containers.accept_owner_gate('gateway',plan['gatewayPlanHash'],digest(gateway_evidence))
            for module in ('ingestion','mcp'):
                if module=='ingestion':private_config(binding['path'],binding)
                self.report('REPLACING_COHORT_MODULE',module=module)
                self.await_container(containers,module); databases.verify_module(module)
            self.current(True)
            verified = containers.verify_all()
            gateway.verify(); auth_owner.verify()
            app.release_after_cohort_verification()
            self.report('COHORT_READY_FOR_ACTUAL_CHATBOT_CSV_ACCEPTANCE',cohortEvidenceHash=digest(verified),
                maximumSessionSeconds=self.review['maximumElapsedSeconds'])
            # Remain live in this same finite systemd invocation for the actual
            # user loop. Successful infrastructure setup is never E2E proof.
            observer=AcceptanceObserver(databases,containers,self.prepared['acceptancePlan'])
            last_acceptance=None;next_observation=0
            while not self.stop.wait(5):
                self.current(True)
                if time.monotonic()>=next_observation:
                    next_observation=time.monotonic()+30
                    try:
                        acceptance=observer.observe()
                        if digest(acceptance)!=last_acceptance:
                            self.report('ACTUAL_CSV_OWNER_ACCEPTANCE_OBSERVED',ownerAcceptance=acceptance)
                            last_acceptance=digest(acceptance)
                    except Exception as observation_error:
                        # Read-only proof collection cannot claim readiness lost
                        # or stop the already governed healthy acceptance window.
                        reason=str(observation_error)
                        if not reason or len(reason)>160 or any(c not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789' for c in reason):
                            reason=type(observation_error).__name__
                        self.report('CSV_ACCEPTANCE_EVIDENCE_UNAVAILABLE',reason=reason)
        except Exception as error:
            self.report('PAUSED_REQUIRES_RECONCILIATION',reason=public_failure_reason(error),
                diagnostic=public_failure_diagnostic(error))
            raise
        finally:
            self.stop.set()
            if self.worker_thread is not None:
                self.worker_thread.join(timeout=30)
                require(not self.worker_thread.is_alive(),'FINITE_OWNER_STOP_NOT_RECONCILED')
            if self.human_thread is not None:
                self.human_thread.join(timeout=45)
                require(not self.human_thread.is_alive(),'FINITE_HUMAN_SESSION_STOP_NOT_RECONCILED')
            if app is not None:
                app.close()
            for sig,handler in previous.items():
                signal.signal(sig,handler)


def child_main(prepared, sources, manifest, context_path):
    """Only the verified-memory bootstrap calls this with the complete bundle."""
    context = Path(context_path)
    with protected_directory(context) as directory:
        review = evidence.decode(evidence.read_member(directory,'review.json'))
        decision = evidence.decode(evidence.read_member(directory,'decision.json'))
        authority_raw = evidence.read_member(directory,'authority.json')
        mandate_raw = evidence.read_member(directory,'human.json')
    validate_decision(review,decision,int(time.time()))
    require(manifest == review['sourceClosure']['declaration']
            and digest(review['sourceClosure']) == review['sourceClosureHash']
            and digest(prepared) == review['privateInputHashes']['preparedInputs'],
            'EXACT_EXECUTED_SOURCES_AND_PREPARED_INPUTS_REQUIRED')
    for value in review['sourceClosure']['executables'].values():
        command_matches(value)
    require(digest(stdlib_binding()) == review['sourceClosure']['stdlibHash'], 'EXECUTED_STDLIB_DRIFT')
    execution_profile = FileOnlyProfile(prepared['registry']['creationRequest'],prepared['registry']['configtree'])
    expected = {key:review[key] for key in ('sourceClosureHash','creationRequestHash','predecessorHistoryHash','predecessorIncidentRef')}
    expected['intakeHash'] = digest(review)
    verifier = DetachedAuthenticator(governance.POLICY,str(context),review['sourceClosure']['executables']['openssl'])
    mandate_hash = hashlib.sha256(mandate_raw).hexdigest()
    gate = CutoverAuthority(verifier,{'path':str(context/'human.json'),'sha256':mandate_hash},mandate_hash,
        governance.CONTEXT,expected,execution_profile=execution_profile)
    action = AggregateAction(gate,authority_raw,review['sourceClosureHash'])
    for key,scope in review['scopes'].items():
        action.guard(key,scope)
    recovery=prepared.get('postGrantRecovery')
    if recovery is None:
        verify_previous_authorization_actions(prepared.get('previousFiniteActions',[]),
            prepared['imagePlan']['cohortManifestHash'],review['sourceClosure']['executables']['systemctl'],context)
        Delivery(action,prepared,sources,review,context).run()
    else:
        from tools.chatbot_file_cohort.postgrant_recovery import ContinuationFence
        with ContinuationFence(action,recovery)as fence:
            Delivery(action,prepared,sources,review,context,continuation_fence=fence).run()
