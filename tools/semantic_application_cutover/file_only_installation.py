"""Registry factory and native checkpoints for one current full cohort action.

Only the grouped installer creates the reviewed private directories. This
factory opens existing sealed paths, preserves partial journals, and constructs
all eleven concrete owners. It never issues HUMAN authority or imports an image.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat

from transition_journal import Transition,digest,hash_value,require
from file_only_profile import FileOnlyProfile,PHASES
from file_only_application import FileOnlyApplication
from engine_creation import Engine
from native_evidence_store import NativeEvidenceStore
from r12_retirement_adapter import R12RetirementChannel
from application_verification_adapter import ApplicationReadinessChannel
from database_gate import Psql,literal
from image_custody import loaded,runtime_image_id
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.semantic_lease_recovery.reader import lease_projection
from tools.semantic_target_review import prepare_application_runtime_inputs as custody
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_policy_token_owner.installed_owner import InstalledTokenOwner
from tools.chatbot_file_cohort.containers import CohortContainers
from tools.chatbot_file_cohort.containers import REGISTRY_READINESS_POLICY
from tools.chatbot_file_cohort.databases import CohortDatabases
from tools.chatbot_file_cohort.gateway import GatewayRoutes
from tools.chatbot_file_cohort.authorization import AuthorizationDelta

DIRECTORIES=('transition','evidence','before','retirementBefore','node','backup')
FIELDS={'schema','creationRequest','configtree','intents','retirementScope','nodeRecipe','readinessScope',
        'postgresRuntimeBinding','imageAudit','commandBindings','directoryPlan','cohortPlanHash','adminDatabase'}

def directory_bindings(paths):
    result={}
    for name,path in paths.items():
        path=Path(path)
        for parent in path.parents:
            info=parent.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022,
                    'REGISTRY_DIRECTORY_ANCESTOR_CUSTODY_REQUIRED')
        info=path.lstat()
        require(path.resolve()==path and stat.S_ISDIR(info.st_mode) and info.st_uid==info.st_gid==0
                and stat.S_IMODE(info.st_mode)==0o700,'REGISTRY_PRIVATE_DIRECTORY_CUSTODY_CHANGED')
        result[name]=(info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode)
    return result

def compile_scope(prepared,source_closure_hash):
    """The complete private collector output, before any effect or signature."""
    require(type(prepared) is dict and set(prepared)in (FIELDS,FIELDS|{'postGrantRecovery'})
            and prepared['schema']=='ouf.semantic-file-only-installation-inputs.v1'
            and hash_value(source_closure_hash) and hash_value(prepared['cohortPlanHash']),
            'EXACT_COMPLETE_REGISTRY_INSTALLATION_INPUTS_REQUIRED')
    require(len(json.dumps(prepared,allow_nan=False))<=1048576,'BOUNDED_REGISTRY_INSTALLATION_INPUTS_REQUIRED')
    profile=FileOnlyProfile(prepared['creationRequest'],prepared['configtree'])
    intents=prepared['intents'];require(type(intents) is dict and set(intents)==set(PHASES)
        and intents['CREATE_REPLACEMENT']==prepared['creationRequest'],'COMPLETE_REGISTRY_NATIVE_PHASE_INTENTS_REQUIRED')
    paths=prepared['directoryPlan'];require(type(paths) is dict and set(paths)=={'root',*DIRECTORIES},'EXACT_GROUPED_REGISTRY_DIRECTORIES_REQUIRED')
    root=Path(paths['root']);require(root.is_absolute() and '..' not in root.parts and str(root)!='/', 'ABSOLUTE_PRIVATE_REGISTRY_ROOT_REQUIRED')
    recovery=prepared.get('postGrantRecovery')
    require(all(paths[n]==str(root/n) for n in DIRECTORIES if n!='backup' or recovery is None),
        'REGISTRY_DIRECTORIES_MUST_STAY_IN_GROUPED_ROOT')
    if recovery is not None:
        from tools.chatbot_file_cohort.postgrant_recovery import PROFILE
        from tools.chatbot_file_cohort.paused_recovery import PROFILE as PAUSED_PROFILE
        from tools.chatbot_file_cohort.mounted_recovery import PROFILE as MOUNTED_PROFILE
        from tools.chatbot_file_cohort.signed_recovery import PROFILE as SIGNED_PROFILE
        require(recovery.get('profile')in(PROFILE,PAUSED_PROFILE,MOUNTED_PROFILE,SIGNED_PROFILE)and paths['backup']==recovery['retainedBackupDirectory'],
            'EXACT_REVIEWED_RETAINED_BACKUP_DIRECTORY_REQUIRED')
    require(intents['FENCED_BACKUP']['directory']==paths['backup'],'REGISTRY_BACKUP_DIRECTORY_SCOPE_DRIFT')
    require(prepared['nodeRecipe']['sourceClosureHash']==source_closure_hash
        and runtime_image_id(prepared['imageAudit'])==prepared['creationRequest']['Image']
        and prepared['readinessScope']['flywaySchema']=='ouf_sem'
        and prepared['readinessScope']['database']!=prepared['adminDatabase'], 'REGISTRY_REVIEWED_IMAGE_SOURCE_OR_DATABASE_DRIFT')
    ApplicationReadinessChannel(prepared['readinessScope'])
    return {**({'postGrantRecovery':copy.deepcopy(recovery)}if recovery is not None else {}),
        'schema':'ouf.semantic-file-only-installation-scope.v1','preparedHash':digest(prepared),
        'readinessPolicy':copy.deepcopy(REGISTRY_READINESS_POLICY),
        'creationRequestHash':digest(prepared['creationRequest']),'executionProfileHash':profile.sha256,
        'sourceClosureHash':source_closure_hash,'cohortPlanHash':prepared['cohortPlanHash'],
        'phaseIntentHashes':{p:digest(intents[p]) for p in PHASES},'directoryPlanHash':digest(paths)}

class RegistryCheckpoints:
    def __init__(self,prepared,action,engine,transition,store,before_store,retirement,token_owner,cohort):
        require(type(action) is AggregateAction and type(engine) is Engine and type(transition) is Transition
                and type(store) is NativeEvidenceStore and type(before_store) is NativeEvidenceStore
                and before_store.root!=store.root and type(retirement) is R12RetirementChannel
                and type(token_owner) is InstalledTokenOwner,'REAL_REGISTRY_CHECKPOINT_OWNERS_REQUIRED')
        require(type(cohort) is dict and set(cohort)=={'containers','databases','gateway','authorization'}
                and type(cohort['containers']) is CohortContainers and type(cohort['databases']) is CohortDatabases
                and type(cohort['gateway']) is GatewayRoutes and type(cohort['authorization']) is AuthorizationDelta
                and all(v.action is action for v in cohort.values()),'SAME_AGGREGATE_NATIVE_COHORT_OWNERS_REQUIRED')
        self.prepared=copy.deepcopy(prepared);self.action,self.engine,self.transition,self.store=action,engine,transition,store
        self.retirement,self.token_owner,self.cohort,self.before_store=retirement,token_owner,cohort,before_store
        self.scope=compile_scope(prepared,action.closure);self.application=None;self.directory_bindings={}
        require(digest(cohort['containers'].plan)==self.scope['cohortPlanHash'],'SAME_COMPLETE_APPLICATION_COHORT_PLAN_REQUIRED')
        retired={r['oldRuntimeBinding']['containerId'] for r in cohort['containers'].plan['replacements']}
        old_registry=prepared['intents']['RELEASE_OLD_ENDPOINT']['containerId']
        release=prepared['intents']['RELEASE_PRODUCERS']
        require(set(release['retiredContainerIds'])==retired|{old_registry}
                and not set(release['releaseProducerIds'])&retired
                and release['cohortReviewHash']==self.scope['cohortPlanHash'], 'ALL_OLD_REPLACED_GENERATIONS_MUST_REMAIN_RETIRED')
        self.guard()

    def guard(self):
        require(compile_scope(self.prepared,self.action.closure)==self.scope,'REGISTRY_PREPARED_SCOPE_CHANGED')
        self.action.guard('applicationRegistryCutover',self.scope)
        self.engine.check_socket()
        paths=self.prepared['directoryPlan']
        current=directory_bindings(paths)
        require(not self.directory_bindings or current==self.directory_bindings,'REGISTRY_PRIVATE_DIRECTORY_CUSTODY_CHANGED')
        self.directory_bindings=current
        commands=self.prepared['commandBindings']
        require(type(commands) is dict and set(commands)=={'docker'},'EXACT_REGISTRY_COMMAND_BINDINGS_REQUIRED')
        binding=commands['docker'];require(set(binding)=={'path','sha256'} and hash_value(binding['sha256']), 'EXACT_REGISTRY_DOCKER_REQUIRED')
        custody.file_bytes(binding['path'],0,{0o755,0o750,0o700},limit=67108864,expected=binding['sha256'])
        require(shutil.which('docker')==binding['path'] and os.environ.get('DOCKER_HOST') in (None,'unix://'+self.engine.path)
                and not any(os.environ.get(k) for k in ('DOCKER_CONTEXT','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH')),
                'REGISTRY_COMMAND_MUST_USE_SAME_LOCAL_ENGINE')
        pin=self.prepared['postgresRuntimeBinding']
        status,pg=self.engine.request('GET','/v1.44/containers/'+pin['containerId']+'/json')
        require(status==200 and Engine.runtime_binding(pg)==pin and pg['State']['Running'] is True
                and pg['State']['Paused'] is False,'REGISTRY_POSTGRES_GENERATION_CHANGED')
        image=self.prepared['creationRequest']['Image']
        status,native=self.engine.request('GET','/v1.44/images/'+image+'/json')
        require(status==200,'REVIEWED_REGISTRY_IMAGE_NOT_LOADED')
        proof=loaded(self.prepared['imageAudit'],native)
        self.token_owner.await_active(self.token_owner.binding.digest())
        return {'postgresRuntimeHash':digest(pin),'imageCustodyHash':digest(proof)}

    def phase(self,phase,point,row):
        require(phase in PHASES and row==self.transition.read(),'CURRENT_REGISTRY_PHASE_CHECKPOINT_REQUIRED')
        proof=self.guard();completed={e['phase']:e for e in row['effects'] if e['state']=='APPLIED'}
        for name,effect in completed.items():self.store.read(name,effect['nativeEvidenceHash'])
        if phase=='STOP_REVOKE_OLD_LEASE':
            producers=self.application.executor.adapters['QUIESCE_PRODUCERS']
            for pin in self.prepared['intents']['QUIESCE_PRODUCERS']['producerBindings']:producers.running(pin)
        if 'STOP_REVOKE_OLD_LEASE' in completed:
            previous=self.store.read('STOP_REVOKE_OLD_LEASE',completed['STOP_REVOKE_OLD_LEASE']['nativeEvidenceHash'])
            current=self.retirement.current()
            require(current==previous['nativeAfter'],'RETIRED_PROVIDER_WORKER_OR_LEASE_CHANGED')
            proof['retirementHash']=digest(current)
        if 'QUIESCE_PRODUCERS' in completed:
            # At final release, the adapter owns the explicit remaining restart
            # effects. All five replaced old generations remain stopped always.
            selected=self.prepared['intents']['QUIESCE_PRODUCERS']['producerBindings']
            if phase=='RELEASE_PRODUCERS':
                retired=set(self.prepared['intents']['RELEASE_PRODUCERS']['retiredContainerIds'])
                selected=[p for p in selected if p['containerId'] in retired]
            quiesced=self.application.executor.adapters['QUIESCE_PRODUCERS']
            require(all(quiesced.stopped(pin) is not None for pin in selected),'REGISTRY_DEPENDENT_PRODUCER_FENCE_LOST')
        proof['authorizationHash']=digest(self.authorization(phase,point))
        if 'ATTEST_NEW_OCI_PEER' in completed and ((phase=='ADMIT_MIGRATION' and point=='BEFORE_NATIVE_EFFECT')
                or (phase=='START_REPLACEMENT' and point=='BEFORE_UNPAUSE')):
            proof['pausedNodeHash']=digest(self.application.node_owner.verify_retained())
        if phase=='ADMIT_MIGRATION' and point=='BEFORE_NATIVE_EFFECT':
            # Recheck the retained archive and live closed/empty database from
            # the admin channel immediately before the sole admission owner.
            # This does not rerun backup or connect to the fenced target DB.
            expected=self.store.read('FENCED_BACKUP',completed['FENCED_BACKUP']['nativeEvidenceHash'])
            current=self.application.executor.adapters['FENCED_BACKUP'].snapshot()
            require(current==expected,'REGISTRY_RETAINED_BACKUP_OR_DATABASE_FENCE_CHANGED')
            proof['fencedBackupHash']=digest(current)
        if phase=='RELEASE_PRODUCERS':
            proof['containersHash']=digest(self.cohort['containers'].verify_all())
            proof['databasesHash']=digest([self.cohort['databases'].verify_module(m) for m in ('udp','onboarding','ingestion','mcp')])
            proof['gatewayHash']=digest(self.cohort['gateway'].verify())
        self.action.guard('applicationRegistryCutover',self.scope)
        require(row==self.transition.read(),'REGISTRY_HISTORY_CHANGED_DURING_NATIVE_CHECKPOINT')
        return {'schema':'ouf.semantic-cutover-native-checkpoint.v1','phase':phase,'point':point,
            'journalVersion':row['version'],'intentHash':self.scope['phaseIntentHashes'][phase],
            'authorityHash':self.action.authority_hash,'sourceClosureHash':self.action.closure,'nativeEvidenceHash':digest(proof)}

    def backup(self,point):
        return self.phase('FENCED_BACKUP',point,self.transition.read())

    def authorization(self,phase,point):
        """Owner HTTP is deliberately unavailable while Onboarding is quiesced.

        Preserve its actual pre-quiescence proof and immutable effect ledger;
        validate the current full HUMAN authority locally throughout downtime.
        Fresh owner verification is mandatory again before any producer release.
        """
        owner=self.cohort['authorization'];owner.guard()
        prior_phase=phase=='STOP_REVOKE_OLD_LEASE' or (phase=='QUIESCE_PRODUCERS'
            and point in ('BEFORE_DURABLE_INTENT','BEFORE_NATIVE_EFFECT'))
        if prior_phase:
            proof=owner.verify()
            if phase=='QUIESCE_PRODUCERS' and point=='BEFORE_NATIVE_EFFECT':
                self.before_store.publish('QUIESCE_PRODUCERS',{'schema':'ouf.registry-authorization-before-quiescence.v1',
                    'transitionContextHash':self.transition.context,'intentHash':self.scope['phaseIntentHashes']['QUIESCE_PRODUCERS'],
                    'authorityHash':self.action.authority_hash,'authorizationPlanHash':owner.hash,
                    'authorizationHistoryHash':digest(owner.record()),'ownerEvidence':proof})
            return {'currentOwnerEvidence':proof,'ownerQuiesced':False}
        baseline=self.before_store.read_baseline('QUIESCE_PRODUCERS',self.transition.context,
            self.scope['phaseIntentHashes']['QUIESCE_PRODUCERS'])
        recovery=self.scope.get('postGrantRecovery')
        expected_authority=self.action.authority_hash if recovery is None else recovery['predecessorAuthorityHash']
        expected_plan=owner.hash if recovery is None else recovery['originalAuthorizationPlanHash']
        expected_history=digest(owner.record()) if recovery is None else recovery['originalAuthorizationHistoryHash']
        require(baseline.get('schema')=='ouf.registry-authorization-before-quiescence.v1'
            and baseline.get('authorityHash')==expected_authority and baseline.get('authorizationPlanHash')==expected_plan
            and baseline.get('authorizationHistoryHash')==expected_history,'PRE_QUIESCENCE_OWNER_PROOF_OR_HISTORY_CHANGED')
        retained_evidence=copy.deepcopy(baseline['ownerEvidence'])
        if recovery is not None:
            require(not owner.record()['effects'],'POSTGRANT_AUTHORIZATION_EFFECT_REPLAY_DENIED')
            retained_evidence['planHash']=owner.hash
        if phase=='RELEASE_PRODUCERS':
            current=owner.verify();require(current==retained_evidence,'OWNER_AUTHORIZATION_CHANGED_ACROSS_COHORT_CUTOVER')
            return {'currentOwnerEvidence':current,'ownerQuiesced':False}
        return {'retainedPreQuiescenceEvidenceHash':digest(baseline),'ownerQuiesced':True,
                'currentOwnerHttpProven':False,'currentLocalAuthorityHash':self.action.authority_hash}

def build(prepared,action,token_owner,engine,verifier,attestation_signer,directories,cohort):
    require(type(action) is AggregateAction and type(engine) is Engine and type(token_owner) is InstalledTokenOwner,
            'ACTUAL_AGGREGATE_REGISTRY_AND_TOKEN_OWNER_REQUIRED')
    scope=compile_scope(prepared,action.closure)
    require(directories==prepared['directoryPlan'],'EXACT_GROUPED_REGISTRY_DIRECTORIES_REQUIRED')
    action.guard('applicationRegistryCutover',scope)
    directory_bindings(directories)  # Before creating even the new journal locks.
    profile=action.authority.execution_profile
    require(type(profile) is FileOnlyProfile and profile.verify(prepared['creationRequest'])==scope['executionProfileHash'],
            'ONE_SHARED_FILE_ONLY_AUTHORITY_PROFILE_REQUIRED')
    journal=Journal(directories['transition'])
    recovery=prepared.get('postGrantRecovery')
    prior_authority=action.authority_hash if recovery is None else recovery['predecessorAuthorityHash']
    initial=Transition.initial_file_only(prior_authority,scope['creationRequestHash'],
        action.authority.expected['predecessorHistoryHash'],action.authority.expected['predecessorIncidentRef'],profile)
    if recovery is not None:
        from tools.chatbot_file_cohort.postgrant_recovery import verify_successor_transition
        verify_successor_transition(journal.read(),scope,action.authority_hash)
    elif not any(os.path.lexists(journal.root/name) for name in ('recovery.lock','invocation.lock','recovery.json')):
        journal.initialize(initial)
    transition=Transition(journal,initial['contextHash'],execution_profile=profile);transition.read()
    store=NativeEvidenceStore(directories['evidence']);before=NativeEvidenceStore(directories['before'])
    retirement_before=NativeEvidenceStore(directories['retirementBefore'])
    retirement=R12RetirementChannel(prepared['retirementScope'],custody,lease_projection)
    checkpoints=RegistryCheckpoints(prepared,action,engine,transition,store,before,retirement,token_owner,cohort)
    backup=prepared['intents']['FENCED_BACKUP']
    admin=Psql(backup['containerId'],backup['user'],prepared['adminDatabase'],'ouf-cutover-registry-admin')
    try:
        application=FileOnlyApplication(engine=engine,transition=transition,request=prepared['creationRequest'],
            intents=prepared['intents'],store=store,before_store=before,admin=admin,retirement_channel=retirement,
            retirement_before_store=retirement_before,profile=profile,authority=action.authority,authority_raw=action.raw,
            verifier=verifier,attestation_signer=attestation_signer,token_owner=token_owner,node_recipe=prepared['nodeRecipe'],
            node_directory=directories['node'],readiness_scope=prepared['readinessScope'],checkpoint=checkpoints.phase,
            phase_checkpoint=checkpoints.phase,backup_checkpoint=checkpoints.backup,aggregate_action=action,aggregate_scope=scope)
    except BaseException:
        admin.close();raise
    checkpoints.application=application
    application.close=admin.close
    application.checkpoints=checkpoints
    return application
