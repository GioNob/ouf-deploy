"""Separate read-only final retirement mode and retained backup witness.

The frozen live-worker STOP adapter is unchanged. A new reviewed parent can
select OBSERVE_ALREADY_FINAL_RETIREMENT before the new transition starts. This
owner reads the actual retained channel/final marker under CURRENT authority;
it never invokes stop/marker creation, adopts old recovery authority or claims
that the old retirement was executed by this new action. Backups are checked
with retained_snapshot after migration, without asserting a still-closed DB.
"""
import copy,hashlib,stat
from pathlib import Path
from .custody_capture import decode,digest,encoded,require
from .application import DiscoveryApplication
from .executor import DiscoveryExecutor
from .current_cohort import INPUT_SCHEMA_V2,REVIEW_SCHEMA,validate_inputs
from .node_owner import ObservationBudget
from .private_review import hashed
from tools.semantic_provider_deployment_authentication import ancestors
from r12_retirement_adapter import R12RetirementAdapter,R12RetirementChannel
from fenced_backup_adapter import FencedBackupAdapter
from native_evidence_store import NativeEvidenceStore

SCHEMA='ouf.discovery-current-retirement-backup-inputs.v1'
MODE='OBSERVE_ALREADY_FINAL_RETIREMENT'
PHASE='STOP_REVOKE_OLD_LEASE'


def validate(inputs):
    fields={'schema','sourceClosureHash','installationInputsHash','desiredProfileHash','cohortManifestHash',
        'retirement','backupIntentHash'}
    require(type(inputs) is dict and set(inputs)==fields and inputs['schema']==SCHEMA
        and all(hashed(inputs[k]) for k in fields-{'schema','retirement'}) and len(encoded(inputs))<=4096,
        'EXACT_CURRENT_RETIREMENT_AND_BACKUP_INPUTS_REQUIRED')
    r=inputs['retirement']
    require(type(r) is dict and set(r)=={'mode','scopeHash','expectedFinalStateHash','existingMarkerSha256'}
        and r['mode']==MODE and all(hashed(r[k]) for k in r if k!='mode'),
        'EXPLICIT_REVIEWED_ALREADY_FINAL_RETIREMENT_MODE_REQUIRED')
    return digest(inputs)


def bind_retirement_inputs(runtime_inputs,inputs):
    validate_inputs(runtime_inputs);sha=validate(inputs)
    require(all(runtime_inputs[k]==inputs[k] for k in ('sourceClosureHash','installationInputsHash','desiredProfileHash','cohortManifestHash')),
        'SAME_CURRENT_COHORT_RETIREMENT_AND_BACKUP_REVIEW_REQUIRED')
    result=copy.deepcopy(runtime_inputs);extra=result.setdefault('additionalInputsHashes',{})
    require('retirementAndBackup' not in extra or extra['retirementAndBackup']==sha,
        'CURRENT_RETIREMENT_AND_BACKUP_BINDING_CANNOT_BE_REPLACED')
    extra['retirementAndBackup']=sha;result['schema']=INPUT_SCHEMA_V2;validate_inputs(result);return result


def final_retirement(value):
    require(type(value) is dict,'CURRENT_FINAL_RETIREMENT_METADATA_REQUIRED')
    service,worker,history,lease=(value[k] for k in ('service','worker','history','lease'))
    require(service['ActiveState']=='inactive' and service['SubState']=='dead'
        and (service['MainPID']=='0' or service['MainPID'] is None and service.get('LoadState')=='not-found')
        and value['processGeneration'] is None and history['state']=='CANCELLED' and history['reason']=='CANCELLED_BY_OWNER'
        and worker['state']=='CANCELLED' and worker['ready'] is False and worker['live'] is False and worker['setsRevoked'] is True
        and all(type(history[k]) is int and history[k]>=0 for k in ('attempts','publicationCount'))
        and type(worker['attempts']) is int and type(worker['refreshCount']) is int
        and worker['attempts']==history['attempts'] and worker['refreshCount']==history['publicationCount'],
        'CURRENT_ALREADY_FINAL_RETIRED_WORKER_REQUIRED')
    require(lease['journalState']=='QUIESCED' and lease['leaseAuthorized'] is False and lease['startAuthorized'] is False
        and all(lease[k] is True for k in ('providerSetsEmpty','journalAndMembershipConsistent','nativeStructureVerified'))
        and type(lease['flowCount']) is int and lease['flowCount']==2 and type(lease['flows']) is list and len(lease['flows'])==2
        and all(type(f.get(k)) is int and f[k]==0 for f in lease['flows'] for k in ('inetAddressCount','bridgeAddressCount')),
        'CURRENT_ALREADY_FINAL_RETIRED_LEASES_MUST_BE_EMPTY')
    return digest(value)


class CurrentRetirementAndBackup:
    def __init__(self,application,runtime_inputs,inputs):
        require(type(application) is DiscoveryApplication and type(application.executor) is DiscoveryExecutor,
            'ACTUAL_CURRENT_DISCOVERY_APPLICATION_AND_EXECUTOR_REQUIRED')
        self.app=application;self.runtime_inputs=copy.deepcopy(runtime_inputs);self.inputs=copy.deepcopy(inputs)
        self.runtime_hash=validate_inputs(runtime_inputs);self.input_hash=validate(inputs);self.parent=application.discovery_parent
        self.legacy=application.executor.adapters[PHASE];self.backup=application.executor.adapters['FENCED_BACKUP']
        require(type(self.legacy) is R12RetirementAdapter and type(self.legacy.channel) is R12RetirementChannel
            and type(self.backup) is FencedBackupAdapter and type(application.store) is NativeEvidenceStore,
            'ACTUAL_RETAINED_RETIREMENT_CHANNEL_AND_BACKUP_ADAPTER_REQUIRED')
        self.phase=PHASE;self.transition,self.store,self.authority,self.authority_raw=(application.transition,application.store,
            application.authority,application.raw)
        self.request_hash=application.request_hash;self.intent=copy.deepcopy(application.intents[PHASE]);self.intent_hash=digest(self.intent)
        self.ids=tuple(map(id,(application,application.executor,self.parent,self.legacy,self.legacy.channel,self.backup)))
        self.installed=False;self.guard()

    def guard(self):
        app,p,i,r=self.app,self.parent,self.inputs,self.runtime_inputs;app.verify_scope()
        require(self.ids==tuple(map(id,(app,app.executor,p,self.legacy,self.legacy.channel,self.backup)))
            and app.discovery_parent is app.executor.discovery_parent is p and app.transition is self.transition
            and app.store is self.store and app.authority is self.authority and app.raw==self.authority_raw
            and app.request_hash==self.request_hash and digest(self.intent)==self.intent_hash
            and app.executor.adapters[PHASE] is (self if self.installed else self.legacy)
            and app.executor.adapters['FENCED_BACKUP'] is self.backup
            and self.legacy.transition is self.transition and self.legacy.store is self.store
            and self.backup.evidence_store is self.store and self.backup.context['transitionContextHash']==self.transition.context
            and validate(i)==self.input_hash and validate_inputs(r)==self.runtime_hash and r['schema']==INPUT_SCHEMA_V2
            and r['additionalInputsHashes'].get('retirementAndBackup')==self.input_hash
            and all(r[k]==i[k]==p.scope[k] for k in ('sourceClosureHash','installationInputsHash','desiredProfileHash'))
            and r['cohortManifestHash']==i['cohortManifestHash'],
            'SAME_CURRENT_RETIREMENT_BACKUP_PARENT_CHILD_OWNER_AND_INPUTS_REQUIRED')
        component=p.review['components']['cohortInstallation'];admission=component['currentAdmission']
        require(admission['schema']==REVIEW_SCHEMA and admission['nativeRuntimeInputsHash']==self.runtime_hash
            and admission['requirements']['registryCreationRequestHash']==self.request_hash
            and admission['requirements']['cohortManifestHash']==i['cohortManifestHash']
            and digest(app.intents[PHASE])==self.intent_hash==self.legacy.intent_hash
            and self.intent['scopeHash']==self.legacy.channel.scope_hash==i['retirement']['scopeHash']
            and digest(app.intents['FENCED_BACKUP'])==self.backup.intent_hash==i['backupIntentHash']
            and self.backup.intent['containerId']==r['peers']['postgres']['runtimeBinding']['containerId'],
            'EXACT_REVIEWED_RETIREMENT_MODE_AND_BACKUP_PHASE_REQUIRED')
        p.registry_child(self.authority,self.authority_raw);p.guard('cohortInstallation',component)
        old=Path(self.legacy.channel.scope['r12Root'])
        require(not self.store.root.is_relative_to(old) and not old.is_relative_to(self.store.root),
            'NEW_RETIREMENT_WITNESS_MUST_NOT_REWRITE_OLD_HISTORY')

    def attach_before_transition(self):
        """Source-sealed assembly only, before any new durable phase claim."""
        self.guard();row=self.transition.read()
        require(self.installed is False and row['state']=='READY' and row['nextPhase']==0 and row['effects']==[]
            and row['creationRequestHash']==self.request_hash
            and row['transitionAuthorityEvidenceHash']==hashlib.sha256(self.authority_raw).hexdigest(),
            'READONLY_FINAL_RETIREMENT_MODE_MUST_BE_SELECTED_BEFORE_TRANSITION_START')
        proof=self.retired(ObservationBudget(90))
        require(self.transition.read()==row,'RETIREMENT_READ_PREFLIGHT_HISTORY_CHANGED')
        self.app.executor.adapters[PHASE]=self;self.installed=True;self.guard();return proof

    def retired(self,budget):
        self.guard();c=self.legacy.channel;r=self.inputs['retirement'];budget.check()
        current=c.current();require(final_retirement(current)==r['expectedFinalStateHash'],
            'CURRENT_FINAL_RETIREMENT_DIFFERS_FROM_EXACT_REVIEWED_STATE')
        raw=c.read(Path(c.scope['r12Root'])/'revoked',r['existingMarkerSha256']);marker=decode(raw)
        require(type(marker) is dict and set(marker)=={'schema','transitionContextHash','intentHash','authorizationHash',
                'r12ReplayAuthorized','budgetReset'} and marker['schema']=='ouf.semantic-r12-retirement-marker.v1'
            and all(hashed(marker[k]) for k in ('transitionContextHash','intentHash','authorizationHash'))
            and marker['authorizationHash']==c.scope['authorizationBinding']['sha256']
            and marker['r12ReplayAuthorized'] is marker['budgetReset'] is False,
            'EXACT_EXISTING_FINAL_RETIREMENT_MARKER_REQUIRED')
        require(c.current()==current and c.read(Path(c.scope['r12Root'])/'revoked',r['existingMarkerSha256'])==raw,
            'CURRENT_FINAL_RETIREMENT_CHANGED_DURING_READ')
        self.guard();budget.check()
        return {'schema':'ouf.discovery-current-already-final-retirement.v1','inputHash':self.input_hash,
            'scopeHash':r['scopeHash'],'currentFinalStateHash':digest(current),'existingMarkerHash':r['existingMarkerSha256'],
            'finalRetirementCurrentlyObserved':True,'retirementExecutedByThisAction':False,'retirementMutations':0,
            'historicalAuthorityReused':False,'oldRecoveryHistoryAdopted':False,'budgetReset':False}

    def exact(self,intent):
        self.guard();row=self.transition.read()
        require(self.installed is True and digest(intent)==self.intent_hash and row['state']=='IN_FLIGHT'
            and row['nextPhase']==0 and len(row['effects'])==1 and row['effects'][0]['phase']==PHASE
            and row['effects'][0]['state']=='IN_FLIGHT' and row['effects'][0]['intentHash']==self.intent_hash
            and row['creationRequestHash']==self.request_hash
            and row['transitionAuthorityEvidenceHash']==hashlib.sha256(self.authority_raw).hexdigest(),
            'EXACT_CURRENT_READONLY_RETIREMENT_PHASE_REQUIRED')
        return row

    def apply(self,intent):
        row=self.exact(intent);self.retired(ObservationBudget(90));require(self.exact(intent)==row,'RETIREMENT_READ_HISTORY_CHANGED')

    def observe(self,intent):
        row=self.exact(intent);proof=self.retired(ObservationBudget(90))
        value={'schema':'ouf.discovery-existing-final-retirement-observation.v1','transitionContextHash':self.transition.context,
            'intentHash':self.intent_hash,'currentHistoryHash':digest(row),'retirementEvidence':proof,
            'r12ReplayAuthorized':False,'budgetReset':False,'newRecoveryAuthorityIssued':False}
        require(self.exact(intent)==row,'RETIREMENT_READ_HISTORY_CHANGED');self.store.publish(PHASE,value)
        require(self.exact(intent)==row,'RETIREMENT_READ_HISTORY_CHANGED');return 'APPLIED',value

    def retained_backup(self):
        budget=ObservationBudget(180);self.guard();row=self.transition.read()
        completed=[e for e in row['effects'] if e['phase']=='FENCED_BACKUP' and e['state']=='APPLIED']
        require(len(completed)==1 and completed[0]['intentHash']==self.backup.intent_hash,'EXACT_COMPLETED_CURRENT_BACKUP_PHASE_REQUIRED')
        expected=self.store.read('FENCED_BACKUP',completed[0]['nativeEvidenceHash']);root=self.backup.root
        ancestors(root/'placeholder');info=root.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o700,
            'CURRENT_RETAINED_BACKUP_PRIVATE_ROOT_REQUIRED')
        current=self.backup.retained_snapshot();budget.check()
        require(encoded(current)==encoded({k:expected[k] for k in current})
            and expected['transitionContextHash']==self.transition.context and expected['intentHash']==self.backup.intent_hash
            and self.backup.retained_snapshot()==current,'CURRENT_RETAINED_BACKUP_DIFFERS_FROM_COMPLETED_PHASE')
        self.guard();require(self.transition.read()==row,'RETAINED_BACKUP_HISTORY_CHANGED');budget.check()
        return {'schema':'ouf.discovery-current-retained-backup-witness.v1','inputHash':self.input_hash,
            'currentHistoryHash':digest(row),'retainedBackupHash':digest(current),'retainedArchiveObserved':True,
            'currentDatabaseFenceProvenHere':False,'backupOrRestoreDispatched':False,'fullCohortProven':False,
            'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'releaseAcceptance':False}
