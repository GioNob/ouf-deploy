"""Read the installed worker after the same Registry gate has execed Java.

Reconstruct the original material and clocks without re-entering the paused
installation phase. The existing read-only observer authenticates the current
installed signatures, two peers, systemd worker and positive owned nft leases.
No worker/kernel/recovery writer lock, manager mutation, signature or reset occurs.
"""
from pathlib import Path
from .custody_capture import digest,encoded,require
from .selected_runtime import DiscoverySelectedRuntime
from .lease_materialization import WorkerMaterialization
from .lease_installation_template import materialize
from .lease_file_installation import compile_material,inode
from .lease_start_owner import LeaseStartAdapter,PHASE
from .lease_installation_phase import checked_row,read_prefix
from .installation_lock import observed_logical_inode
from .installed_lease_guard import boot_id
from . import lease_observation
from .node_owner import ObservationBudget
from .private_review import hashed
from tools.semantic_registry_operational_owner.guard import private_json,protected_file
from tools.semantic_provider_deployment_authentication import private_bytes
from gated_process_observation import RunningWorkloadBinding


class CurrentInstalledWorker:
    def __init__(self,selected):
        require(type(selected) is DiscoverySelectedRuntime,'ACTUAL_SELECTED_RUNTIME_FOR_CURRENT_WORKER_REQUIRED')
        self.selected=selected;self.worker=selected.installation.worker
        require(type(self.worker) is WorkerMaterialization,'ACTUAL_INSTALLED_DISCOVERY_WORKER_MATERIALIZATION_REQUIRED')
        self.ids=(id(selected),id(self.worker));self.guard()

    def guard(self):
        s,w=self.selected,self.worker;app=s.installation.application
        require(self.ids==(id(s),id(w)) and s.installation.worker is w and w.node is app.node_owner
            and w.provider is s.installation.provider.runtime.admission and w.parent is s.images.parent
            and w.transition is app.transition and w.store is app.store
            and w.authority is app.authority and w.authority_raw==app.raw,
            'SAME_SELECTED_PARENT_CHILD_REGISTRY_PROVIDER_AND_WORKER_REQUIRED')
        s.guard();w.check_scope();w.parent.registry_child(w.authority,w.authority_raw)
        w.parent.guard('operationalLeaseInstallation',w.component)
        row=s.held();effects=[e for e in row['effects'] if e['phase']==PHASE and e['state']=='APPLIED']
        require(len(effects)==1 and effects[0]['intentHash']==w.intent_hash,
            'COMPLETED_EXACT_WORKER_PHASE_REQUIRED_FOR_RUNNING_ADMISSION')
        receipt=w.store.read(PHASE,effects[0]['nativeEvidenceHash'])
        require(receipt['schema']=='ouf.discovery-distinct-installed-lease-worker-started.v1'
            and receipt['transitionContextHash']==w.transition.context and receipt['intentHash']==w.intent_hash
            and receipt['creationRequestHash']==w.request_hash and receipt['templateHash']==w.template_hash,
            'EXACT_COMPLETED_WORKER_NATIVE_RECEIPT_REQUIRED')
        return row,receipt

    def material(self,budget):
        """Original owned material only; no issuance, publication or phase entry."""
        w=self.worker;budget.check();claim=private_json(w.root/'materialization-claim.json')
        require(claim==w.claim(claim['initialTime']),'RETAINED_CURRENT_WORKER_MATERIALIZATION_CLAIM_CHANGED')
        owned=private_json(w.root/'materialization-owned.json')
        fields={'schema','claimHash','logicalLockIdentity','snapshotHash','snapshotIdentity','proposalHash','materialSealHash'}
        require(set(owned)==fields and owned['schema']=='ouf.discovery-worker-materialization-owned.v1'
            and owned['claimHash']==digest(claim) and all(hashed(owned[k]) for k in ('snapshotHash','proposalHash','materialSealHash')),
            'EXACT_CURRENT_WORKER_OWNED_MATERIAL_REQUIRED')
        path=w.probe.root/(owned['snapshotHash']+'.json');snapshot=private_json(path,owned['snapshotHash'])
        require(inode(path)==owned['snapshotIdentity'] and snapshot['bootId']==boot_id('/proc/sys/kernel/random/boot_id'),
            'CURRENT_WORKER_ORIGINAL_SNAPSHOT_OR_BOOT_CHANGED')
        with observed_logical_inode(w.template['configurationTemplate']['commonInvocationLock'],owned['logicalLockIdentity']):
            proposal=materialize(w.template,snapshot,owned['logicalLockIdentity'])
            material=compile_material(w.template,proposal,w.capsule,initial_time=claim['initialTime'],installation_sources=w.extra)
            require(digest(proposal)==owned['proposalHash'] and digest(material['seal'])==owned['materialSealHash'],
                'CURRENT_WORKER_ORIGINAL_MATERIAL_OR_CLOCKS_CHANGED')
        configuration=Path(w.template['installationRoot'])/'configuration.json'
        require(private_bytes(configuration,1048576)==encoded(proposal['configuration']),
            'CURRENT_WORKER_INSTALLED_CONFIGURATION_DIFFERS_FROM_OWNED_MATERIAL')
        start=LeaseStartAdapter(parent=w.parent,authority=w.authority,authority_raw=w.authority_raw,
            transition=w.transition,store=w.store,node_owner=w.node,template=w.template,proposal=proposal,
            scope=w.start_scope,intent=w.intent,publication_directory=w.publication,
            attestation_scope=w.issuance,registration_scope=w.registration,sequence_scope=w.sequence)
        sequence=checked_row(start);require(sequence['state']=='DONE','COMPLETE_WORKER_INSTALLATION_SEQUENCE_REQUIRED')
        prefix=read_prefix(start);start_claim=start.journal.read()
        require(start_claim==start.claim() and protected_file(start.root/'start-dispatch.json',128,modes=(0o600,))==b'{"attempt":1}',
            'ORIGINAL_ONE_USE_WORKER_START_CLAIM_REQUIRED')
        budget.check()
        return material,proposal,snapshot,configuration,prefix,digest(start_claim),digest(sequence['effects'][-1]['evidence'])

    def observe(self):
        budget=ObservationBudget(90);row,retained=self.guard();w=self.worker
        running=RunningWorkloadBinding(w.node.engine,w.transition,w.node.request,w.store).observe()
        material,proposal,snapshot,configuration,prefix,claim_hash,completed_hash=self.material(budget)
        require(retained['configurationHash']==digest(proposal['configuration']) and retained['claimHash']==claim_hash
            and completed_hash==digest(retained) and all(retained[k]==v for k,v in prefix.items()),
            'CURRENT_WORKER_COMPLETED_PHASE_AND_MATERIAL_DIFFER')
        # Probe the independently signed same two-peer generation; the Registry
        # contract explicitly permits the attested gate to exec Java in-place.
        w.verify_generation(material);provider=w.provider.current(snapshot);budget.check()
        observed=lease_observation.observe(configuration,proposal['serviceUnit']['configurationAnchor'],
            unit_name=w.start_scope['unitName'],systemctl=w.start_scope['manager'])
        old=retained['installedWorkerObservation']
        require(all(observed[k]==old[k] for k in ('configurationHash','scopeHash','generationRef','managerProcessId'))
            and all(observed[k] is True for k in ('managerProcessRunning','workerCheckpointActive','bothOwnedLeaseFamiliesPositive'))
            and observed['recoveryAttempts']>=old['recoveryAttempts'] and observed['publications']>=old['publications'],
            'CURRENT_WORKER_ORIGINAL_SCOPE_PROCESS_OR_POSITIVE_LEASES_REQUIRED')
        w.verify_generation(material);require(w.provider.current(snapshot)==provider,'CURRENT_PROVIDER_ADMISSION_CHANGED')
        again=self.material(budget)
        require(again==(material,proposal,snapshot,configuration,prefix,claim_hash,completed_hash)
            and RunningWorkloadBinding(w.node.engine,w.transition,w.node.request,w.store).observe()==running
            and self.guard()==(row,retained),'CURRENT_WORKER_ADMISSION_CHANGED_DURING_READ')
        budget.check();self.selected.held(row)
        return {'schema':'ouf.discovery-current-installed-worker-admission.v1','heldHistoryHash':digest(row),
            'materialSealHash':digest(material['seal']),'providerAdmissionHash':digest(provider),
            'installedWorkerObservationHash':digest(observed),'currentTwoPeerGenerationObserved':True,
            'currentSignedProviderProtocolVerified':True,'currentWorkerAndPositiveOwnedLeasesObserved':True,
            'originalMaterialAndClocksRetained':True,'fullCohortProven':False,'producerReleaseDispatched':False,
            'signaturesIssued':0,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
            'budgetReset':False,'releaseAcceptance':False}
