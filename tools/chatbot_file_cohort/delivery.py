"""Concrete whole-action execution in one finite process and one authority.

Authorization preparation/actual HUMAN confirmation precede quiescence and the
first token grant. The worker remains in this invocation during the complete
cohort rollout and the user's finite CSV acceptance window. No restart adopts an
old ACTIVE token, no database rollback or grant budget reset is supplied here.
"""
import copy
import dataclasses
import hashlib
import json
import os
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
from engine_creation import Engine
from file_only_installation import build as build_registry
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator
from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
from tools.semantic_lease_recovery.bounded_recovery import Policy
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.semantic_policy_token_owner.owner_installation import AggregateAction, OwnerInstallation
from tools.semantic_policy_token_owner.producer import Binding, protected_directory
from tools.semantic_policy_token_owner.iam_admission import IamProfile, PinnedIamOpener
from tools.semantic_policy_token_owner.reporter import OwnerReporter
from tools.semantic_policy_token_owner.worker_entry import serve
from tools.chatbot_file_cohort.action_process import private_file
from tools.chatbot_file_cohort.review import digest, encoded, require, validate_decision
from tools.chatbot_file_cohort.containers import CohortContainers, CohortPaused
from tools.chatbot_file_cohort.databases import CohortDatabases
from tools.chatbot_file_cohort.gateway import GatewayRoutes, NamespaceAdmin
from tools.chatbot_file_cohort.authorization import AuthorizationDelta, AuthorizationPaused, OwnerPrimitives, OwnerTransport
from tools.chatbot_file_cohort.images import CohortImages
import qualified_owner_authorization_lifecycle
import qualified_owner_scope_catalogue

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
    return OwnerInstallation(action, host, value['rootEvidenceHash'], value['rootCreationSourceClosureHash'],
        value['registration'], Binding(**value['binding']), profile, transport, value['sourceCommit'],
        files, Policy(**policy), value['contextRef'], value['generationRef'], value['intervalSeconds'])


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
    def __init__(self, action, prepared, sources, review, context, emit=print):
        require(type(action) is AggregateAction and type(prepared) is dict and type(sources) is dict,
                'REAL_COMPLETE_AGGREGATE_DELIVERY_INPUTS_REQUIRED')
        require(prepared.get('schema') == 'ouf.chatbot-file-cohort-prepared-inputs.v1'
                and digest(prepared) == review['privateInputHashes']['preparedInputs']
                and str(context) == review['scopes']['finiteActionProcess']['authorityDirectory'],
                'EXACT_HUMAN_REVIEWED_PRIVATE_PREPARED_INPUTS_REQUIRED')
        self.action, self.prepared, self.sources = action, copy.deepcopy(prepared), dict(sources)
        self.review, self.context, self.emit = copy.deepcopy(review), Path(context), emit
        self.stop, self.worker_thread, self.worker = threading.Event(), None, None
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
        self.engine.check_socket()
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

    def run(self):
        previous = {}
        for sig in (signal.SIGINT,signal.SIGTERM):
            previous[sig] = signal.signal(sig, lambda *_:self.stop.set())
        app = None
        try:
            self.current()
            directories = create_directories(self.action)
            native_environment(self.engine,self.review['sourceClosure']['executables']['docker'],directories['dockerCli'])
            authorization = self.prepared['authorization']
            primitives = OwnerPrimitives.from_qualified_modules(qualified_owner_authorization_lifecycle,
                qualified_owner_scope_catalogue, authorization['catalogue'].encode('utf-8'), authorization['helperBindings'])
            auth_owner = AuthorizationDelta(self.action, authorization['plan'], Journal(directories['authorization']),
                OwnerTransport(authorization['plan']['selection'], authorization['adminTokenFile'], authorization['mcpTokenFile']), primitives)
            auth_owner.initialize()
            auth_evidence = self.await_authorization(auth_owner)
            self.current()
            images = CohortImages(self.action,self.engine,self.prepared['imagePlan'],
                {name:Journal(directories['image'+name.capitalize()]) for name in ('semantic','udp','onboarding','ingestion','mcp')},
                self.review['sourceClosure']['executables']['docker'])
            images.initialize()
            self.report('IMPORTING_QUALIFIED_IMAGES_BEFORE_FIRST_GRANT')
            images.apply()
            self.current()
            self.report('INSTALLING_FINITE_TOKEN_OWNER')
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
                NamespaceAdmin(self.engine,self.prepared['gatewayPlan']['transportBinding']))
            containers.initialize(); databases.initialize(); gateway.initialize()
            containers.accept_owner_gate('authorization',plan['authorizationPlanHash'],digest(auth_evidence))
            profile = evidence.decode(governance.public_input(governance.PROFILE))
            verifier = self.action.authority.verifier
            signer = ExistingEd25519Signer(profile['keyBindings']['attestor'],profile['keyRefs']['attestor'],verifier,
                {'role':'CREATION_ATTESTATION','issuerRef':governance.CONTEXT['attestorRef'],
                    'installationRef':governance.CONTEXT['installationRef'],'entityRef':governance.CONTEXT['entityRef']})
            registry_directories = self.prepared['registry']['directoryPlan']
            require(all(path in {str(self.context),*directories.values()} for path in registry_directories.values()),
                    'REGISTRY_DIRECTORIES_OUTSIDE_WHOLE_ACTION_PLAN')
            app = build_registry(self.prepared['registry'],self.action,self.owner.observer,self.engine,verifier,signer,
                registry_directories,{'containers':containers,'databases':databases,'gateway':gateway,'authorization':auth_owner})
            self.report('REGISTRY_REPLACEMENT_AND_VERIFICATION')
            registry_evidence = app.verify_registry_and_hold()
            self.current(True)
            containers.accept_owner_gate('registry',plan['registryModulePackageHash'],digest(registry_evidence))
            backup_evidence = databases.backup_quiesced()
            containers.accept_owner_gate('database',plan['databasePlanHash'],digest(backup_evidence))
            for module in ('udp','onboarding'):
                self.report('REPLACING_COHORT_MODULE',module=module)
                self.await_container(containers,module); databases.verify_module(module)
            self.current(True)
            self.report('PUBLISHING_REVIEWED_GATEWAY_ROUTES')
            gateway.apply(); gateway_evidence = gateway.verify()
            containers.accept_owner_gate('gateway',plan['gatewayPlanHash'],digest(gateway_evidence))
            for module in ('ingestion','mcp'):
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
            while not self.stop.wait(5):
                self.current(True)
        except Exception as error:
            reason = str(error) if type(error) in (evidence.CandidateDenied, RuntimeError) else type(error).__name__
            if not reason or len(reason)>160 or any(c not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789' for c in reason):
                reason = type(error).__name__
            self.report('PAUSED_REQUIRES_RECONCILIATION',reason=reason)
            raise
        finally:
            self.stop.set()
            if self.worker_thread is not None:
                self.worker_thread.join(timeout=30)
                require(not self.worker_thread.is_alive(),'FINITE_OWNER_STOP_NOT_RECONCILED')
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
        require(governance.executable(value['path']) == value, 'EXECUTED_NATIVE_COMMAND_DRIFT')
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
    Delivery(action,prepared,sources,review,context).run()
