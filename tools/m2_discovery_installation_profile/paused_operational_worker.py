"""Current installed worker at the original paused migration/unpause gates.

Only completed phase8 can hand off to this reader at IN_FLIGHT9/10. The actual
paused node owner still verifies retained native acceptance. Current installed
signatures/leases are read without reentering initial provider authority, signing
or taking a worker writer lock. No new lifecycle path or checkpoint is supplied.
"""
import copy
from .custody_capture import digest,require
from .application import DiscoveryApplication
from .lease_materialization import WorkerMaterialization
from .lease_start_owner import PHASE
from .current_worker import read_installed_material
from .current_operational_worker import verify_operational_installation
from .node_owner import ObservationBudget
from . import lease_observation
from transition_journal import PHASES

POINTS={'ADMIT_MIGRATION':'BEFORE_NATIVE_EFFECT','START_REPLACEMENT':'BEFORE_UNPAUSE'}


class PausedOperationalWorker:
    def __init__(self,application):
        require(type(application) is DiscoveryApplication,'ACTUAL_DISCOVERY_APPLICATION_FOR_PAUSED_HANDOFF_REQUIRED')
        self.app=application;self.worker=application.infrastructure_owners[PHASE]
        require(type(self.worker) is WorkerMaterialization,'ACTUAL_COMPLETED_WORKER_FOR_PAUSED_HANDOFF_REQUIRED')
        self.ids=(id(application),id(self.worker),id(self.worker.node),id(self.worker.parent))

    def guard(self,phase,point,row):
        app,w=self.app,self.worker;app.verify_scope();w.check_scope()
        require(self.ids==(id(app),id(w),id(w.node),id(w.parent))
            and app.infrastructure_owners[PHASE] is w and app.node_owner is w.node
            and app.discovery_parent is w.parent and app.transition is w.transition and app.store is w.store
            and app.authority is w.authority and app.raw==w.authority_raw
            and phase in POINTS and point==POINTS[phase] and row==w.transition.read(),
            'EXACT_CURRENT_PAUSED_OPERATIONAL_WORKER_CHECKPOINT_REQUIRED')
        w.parent.registry_child(w.authority,w.authority_raw);w.parent.guard('operationalLeaseInstallation',w.component)
        index=PHASES.index(phase);effects=row.get('effects')
        require(row.get('state')=='IN_FLIGHT' and type(row.get('nextPhase')) is int and row['nextPhase']==index
            and row.get('creationRequestHash')==w.request_hash and type(effects) is list and len(effects)==index+1
            and [e.get('phase') for e in effects]==list(PHASES[:index+1])
            and all(e.get('state')=='APPLIED' for e in effects[:index]) and effects[-1].get('state')=='IN_FLIGHT'
            and all(e.get('intentHash')==app.intent_hashes[e['phase']] for e in effects),
            'COMPLETED_PREFIX_AND_EXACT_PAUSED_MIGRATION_OR_UNPAUSE_CURSOR_REQUIRED')
        effect=effects[PHASES.index(PHASE)]
        require(effect['intentHash']==w.intent_hash,'ORIGINAL_COMPLETED_PAUSED_WORKER_INTENT_REQUIRED')
        receipt=w.store.read(PHASE,effect['nativeEvidenceHash'])
        require(receipt['schema']=='ouf.discovery-distinct-installed-lease-worker-started.v1'
            and receipt['transitionContextHash']==w.transition.context and receipt['intentHash']==w.intent_hash
            and receipt['creationRequestHash']==w.request_hash and receipt['templateHash']==w.template_hash,
            'EXACT_COMPLETED_PAUSED_WORKER_NATIVE_RECEIPT_REQUIRED')
        return receipt

    def observe(self,phase,point,current_row):
        row=copy.deepcopy(current_row);budget=ObservationBudget(90);retained=self.guard(phase,point,row);w=self.worker
        paused=self.app.node_owner.verify_retained();budget.check()
        material,proposal,snapshot,configuration,prefix,claim_hash,completed_hash=read_installed_material(w,budget)
        require(retained['configurationHash']==digest(proposal['configuration']) and retained['claimHash']==claim_hash
            and completed_hash==digest(retained) and all(retained[k]==v for k,v in prefix.items()),
            'PAUSED_WORKER_COMPLETED_PHASE_AND_ORIGINAL_MATERIAL_DIFFER')
        handoff=verify_operational_installation(w,material,proposal,configuration);w.verify_generation(material)
        observed=lease_observation.observe(configuration,proposal['serviceUnit']['configurationAnchor'],
            unit_name=w.start_scope['unitName'],systemctl=w.start_scope['manager'])
        old=retained['installedWorkerObservation']
        require(all(observed[k]==old[k] for k in ('configurationHash','scopeHash','generationRef','managerProcessId'))
            and all(observed[k] is True for k in ('managerProcessRunning','workerCheckpointActive','bothOwnedLeaseFamiliesPositive'))
            and all(type(observed[k]) is int and observed[k]>=old[k] for k in ('recoveryAttempts','publications')),
            'CURRENT_PAUSED_OPERATIONAL_WORKER_AND_POSITIVE_LEASES_REQUIRED')
        w.verify_generation(material)
        require(verify_operational_installation(w,material,proposal,configuration)==handoff
            and read_installed_material(w,budget)==(material,proposal,snapshot,configuration,prefix,claim_hash,completed_hash)
            and self.app.node_owner.verify_retained()==paused and self.guard(phase,point,row)==retained,
            'CURRENT_PAUSED_OPERATIONAL_HANDOFF_CHANGED_DURING_READ')
        budget.check()
        return {'schema':'ouf.discovery-current-paused-operational-worker.v1','phase':phase,'point':point,
            'currentHistoryHash':digest(row),'pausedNodeEvidenceHash':digest(paused),'operationalHandoffHash':digest(handoff),
            'installedWorkerObservationHash':digest(observed),'currentSignedOperationalInstallationVerified':True,
            'currentWorkerAndPositiveOwnedLeasesObserved':True,'initialProviderMandateExtended':False,
            'newGenerationAuthorized':False,'fullCohortProven':False,'signaturesIssued':0,
            'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'budgetReset':False,'releaseAcceptance':False}
