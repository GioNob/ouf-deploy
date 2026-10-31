"""Current normal handoff while VERIFY_APPLICATION owns its durable phase.

The Registry has already execed Java, but READY12 has not yet been reached.
Only exact in-flight application verification points are admitted. This reader
does not mark application readiness, extend initial authority or release anyone.
"""
import copy
from .custody_capture import digest,require
from .application import DiscoveryApplication
from .lease_materialization import WorkerMaterialization
from .lease_start_owner import PHASE as WORKER_PHASE
from .current_worker import read_installed_material
from .current_operational_worker import verify_operational_installation
from .node_owner import ObservationBudget
from . import lease_observation
from .verifying_registry_binding import VerifyingRegistryBinding
from transition_journal import PHASES

PHASE='VERIFY_APPLICATION'
POINTS={'BEFORE_NATIVE_EFFECT','BEFORE_APPLICATION_VERIFICATION','BEFORE_APPLICATION_READINESS','AFTER_APPLICATION_READINESS'}


class VerifyingOperationalWorker:
    def __init__(self,application):
        require(type(application) is DiscoveryApplication,'ACTUAL_APPLICATION_FOR_VERIFYING_HANDOFF_REQUIRED')
        self.app=application;self.worker=application.infrastructure_owners[WORKER_PHASE]
        require(type(self.worker) is WorkerMaterialization,'ACTUAL_COMPLETED_WORKER_FOR_VERIFYING_HANDOFF_REQUIRED')
        self.ids=(id(application),id(self.worker),id(self.worker.node),id(self.worker.parent))

    def guard(self,phase,point,row):
        app,w=self.app,self.worker;app.verify_scope();w.check_scope()
        require(self.ids==(id(app),id(w),id(w.node),id(w.parent))
            and app.infrastructure_owners[WORKER_PHASE] is w and app.node_owner is w.node
            and app.discovery_parent is w.parent and app.transition is w.transition and app.store is w.store
            and app.authority is w.authority and app.raw==w.authority_raw
            and phase==PHASE and point in POINTS and row==w.transition.read(),
            'EXACT_CURRENT_VERIFYING_OPERATIONAL_WORKER_CHECKPOINT_REQUIRED')
        w.parent.registry_child(w.authority,w.authority_raw);w.parent.guard('operationalLeaseInstallation',w.component)
        index=PHASES.index(PHASE);effects=row.get('effects')
        require(row.get('state')=='IN_FLIGHT' and type(row.get('nextPhase')) is int and row['nextPhase']==index
            and row.get('creationRequestHash')==w.request_hash and type(effects) is list and len(effects)==index+1
            and [e.get('phase') for e in effects]==list(PHASES[:index+1])
            and all(e.get('state')=='APPLIED' for e in effects[:index]) and effects[-1].get('state')=='IN_FLIGHT'
            and all(e.get('intentHash')==app.intent_hashes[e['phase']] for e in effects),
            'COMPLETED_UNPAUSE_AND_EXACT_IN_FLIGHT_VERIFICATION_CURSOR_REQUIRED')
        effect=effects[PHASES.index(WORKER_PHASE)]
        require(effect['intentHash']==w.intent_hash,'ORIGINAL_COMPLETED_VERIFYING_WORKER_INTENT_REQUIRED')
        receipt=w.store.read(WORKER_PHASE,effect['nativeEvidenceHash'])
        require(receipt['schema']=='ouf.discovery-distinct-installed-lease-worker-started.v1'
            and receipt['transitionContextHash']==w.transition.context and receipt['intentHash']==w.intent_hash
            and receipt['creationRequestHash']==w.request_hash and receipt['templateHash']==w.template_hash,
            'EXACT_COMPLETED_VERIFYING_WORKER_NATIVE_RECEIPT_REQUIRED')
        return receipt

    def observe(self,phase,point,current_row):
        row=copy.deepcopy(current_row);budget=ObservationBudget(90);retained=self.guard(phase,point,row);w=self.worker
        running=VerifyingRegistryBinding(w.node.engine,w.transition,w.node.request,w.store).observe();budget.check()
        material,proposal,snapshot,configuration,prefix,claim_hash,completed_hash=read_installed_material(w,budget)
        require(retained['configurationHash']==digest(proposal['configuration']) and retained['claimHash']==claim_hash
            and completed_hash==digest(retained) and all(retained[k]==v for k,v in prefix.items()),
            'VERIFYING_WORKER_COMPLETED_PHASE_AND_ORIGINAL_MATERIAL_DIFFER')
        handoff=verify_operational_installation(w,material,proposal,configuration);w.verify_generation(material)
        observed=lease_observation.observe(configuration,proposal['serviceUnit']['configurationAnchor'],
            unit_name=w.start_scope['unitName'],systemctl=w.start_scope['manager'])
        old=retained['installedWorkerObservation']
        require(all(observed[k]==old[k] for k in ('configurationHash','scopeHash','generationRef','managerProcessId'))
            and all(observed[k] is True for k in ('managerProcessRunning','workerCheckpointActive','bothOwnedLeaseFamiliesPositive'))
            and all(type(observed[k]) is int and observed[k]>=old[k] for k in ('recoveryAttempts','publications')),
            'CURRENT_VERIFYING_WORKER_AND_POSITIVE_LEASES_REQUIRED')
        w.verify_generation(material)
        require(verify_operational_installation(w,material,proposal,configuration)==handoff
            and read_installed_material(w,budget)==(material,proposal,snapshot,configuration,prefix,claim_hash,completed_hash)
            and VerifyingRegistryBinding(w.node.engine,w.transition,w.node.request,w.store).observe()==running
            and self.guard(phase,point,row)==retained,'CURRENT_VERIFYING_OPERATIONAL_HANDOFF_CHANGED_DURING_READ')
        budget.check()
        return {'schema':'ouf.discovery-current-verifying-operational-worker.v1','phase':phase,'point':point,
            'currentHistoryHash':digest(row),'runningGenerationHash':digest(running),'operationalHandoffHash':digest(handoff),
            'installedWorkerObservationHash':digest(observed),'currentSignedOperationalInstallationVerified':True,
            'currentWorkerAndPositiveOwnedLeasesObserved':True,'initialProviderMandateExtended':False,
            'newGenerationAuthorized':False,'applicationReadinessProvenHere':False,'fullCohortProven':False,
            'producerReleaseDispatched':False,'signaturesIssued':0,'runtimeAuthorityIssued':False,
            'targetApplyAuthorized':False,'budgetReset':False,'releaseAcceptance':False}
