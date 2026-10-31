"""Current signed operational handoff after completed finite installation.

The initial provider start/admission paths remain unchanged and finite. This
separate reader verifies current scoped installation signatures and the same
independently admitted two-peer generation under reviewed normal operation.
It never backdates a verifier, extends a mandate or authorizes a new generation.
"""
from pathlib import Path
from .custody_capture import digest,encoded,require
from .current_worker import CurrentInstalledWorker
from .node_owner import ObservationBudget
from .parent_authority import SEMANTICS
from . import lease_observation
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator,private_bytes
from gated_process_observation import RunningWorkloadBinding


class CurrentOperationalWorker:
    def __init__(self,selected):
        self.base=CurrentInstalledWorker(selected);self.worker=self.base.worker;self.selected=selected
        self.ids=(id(self.base),id(self.worker),id(selected));self.guard()

    def guard(self):
        require(type(self.base) is CurrentInstalledWorker
            and self.ids==(id(self.base),id(self.worker),id(self.selected))
            and self.base.worker is self.worker and self.base.selected is self.selected
            and self.worker.parent.review['operationalSemantics']==SEMANTICS
            and SEMANTICS['reviewedNormalOperationAfterInstallation'] is True,
            'CURRENT_REVIEWED_NORMAL_OPERATION_HANDOFF_REQUIRED')
        return self.base.guard()

    def operational(self,material,proposal,configuration):
        w=self.worker;root=Path(configuration).parent;c=proposal['configuration'];verification=c['verification']
        ctx={k:w.parent.context[k] for k in ('installationRef','entityRef','attestorRef')}
        receipt=material['receipt']
        require(verification['context']==ctx and receipt['complete'] is True
            and receipt['finiteApprovalAuthorizesInstallationOnly'] is True
            and receipt['operationalLifetime']=='UNTIL_DISABLE_CUSTODY_OR_INSTALLATION_TRUST_REVOCATION'
            and receipt['runtimeSigningKeyAccessAllowed'] is False
            and receipt['containerLifecycleOperationsAllowed'] is False,
            'EXACT_COMPLETED_OPERATIONAL_INSTALLATION_SCOPE_REQUIRED')
        # Current policy/key validity is checked at NOW. The installed receipt
        # has no new finite execution window and grants no lifecycle operation.
        verifier=DetachedAuthenticator(verification['trustPolicy'],str(root/'receipt-signatures'),
            verification['openssl'],clock=w.parent.clock)
        paths={'seal':root/'publication-seal.json','receipt':root/'installed.json','generation':root/'current-generation.json'}
        raws={name:private_bytes(path,131072) for name,path in paths.items()}
        for name,raw in raws.items():
            require(raw==encoded(material[name]),'CURRENT_OPERATIONAL_INSTALLATION_PAYLOAD_CHANGED')
            require(verifier(raw,'CREATION_ATTESTATION',ctx['attestorRef'],ctx['installationRef'],ctx['entityRef']) is True,
                'CURRENT_OPERATIONAL_INSTALLATION_SIGNATURE_REQUIRED')
        generation=material['generation'];peer=proposal['nativeObservation']['peers']['provider']
        require(generation['configurationHash']==digest(c) and generation['generationRef']==proposal['nativeObservation']['generationRef']
            and proposal['nativeObservation']['profiles']['provider']['nodeRecipeHash']==w.template['expectedNodeProfiles']['provider']['nodeRecipeHash']
            and peer['imageId']==w.template['expectedImages']['provider'],
            'SAME_INDEPENDENTLY_ADMITTED_OPERATIONAL_PROVIDER_GENERATION_REQUIRED')
        require(all(private_bytes(paths[name],131072)==raw for name,raw in raws.items()),
            'CURRENT_OPERATIONAL_INSTALLATION_CHANGED_DURING_SIGNATURE_READ')
        return {'schema':'ouf.discovery-current-operational-provider-handoff.v1','configurationHash':digest(c),
            'signedMaterialHash':digest({name:digest(material[name]) for name in paths}),
            'providerContainerId':peer['containerId'],'generationRef':generation['generationRef'],
            'currentScopedSignaturesVerified':True,'reviewedNormalOperationVerified':True,
            'initialProviderMandateExtended':False,'newGenerationAuthorized':False}

    def observe(self):
        budget=ObservationBudget(90);row,retained=self.guard();w=self.worker
        running=RunningWorkloadBinding(w.node.engine,w.transition,w.node.request,w.store).observe()
        material,proposal,snapshot,configuration,prefix,claim_hash,completed_hash=self.base.material(budget)
        require(retained['configurationHash']==digest(proposal['configuration']) and retained['claimHash']==claim_hash
            and completed_hash==digest(retained) and all(retained[k]==v for k,v in prefix.items()),
            'OPERATIONAL_WORKER_COMPLETED_PHASE_AND_MATERIAL_DIFFER')
        handoff=self.operational(material,proposal,configuration);w.verify_generation(material);budget.check()
        observed=lease_observation.observe(configuration,proposal['serviceUnit']['configurationAnchor'],
            unit_name=w.start_scope['unitName'],systemctl=w.start_scope['manager'])
        old=retained['installedWorkerObservation']
        require(all(observed[k]==old[k] for k in ('configurationHash','scopeHash','generationRef','managerProcessId'))
            and all(observed[k] is True for k in ('managerProcessRunning','workerCheckpointActive','bothOwnedLeaseFamiliesPositive'))
            and observed['recoveryAttempts']>=old['recoveryAttempts'] and observed['publications']>=old['publications'],
            'CURRENT_OPERATIONAL_WORKER_AND_POSITIVE_LEASES_REQUIRED')
        w.verify_generation(material)
        require(self.operational(material,proposal,configuration)==handoff
            and self.base.material(budget)==(material,proposal,snapshot,configuration,prefix,claim_hash,completed_hash)
            and RunningWorkloadBinding(w.node.engine,w.transition,w.node.request,w.store).observe()==running
            and self.guard()==(row,retained),'CURRENT_OPERATIONAL_HANDOFF_CHANGED_DURING_READ')
        budget.check();self.selected.held(row)
        return {'schema':'ouf.discovery-current-operational-worker-admission.v1','heldHistoryHash':digest(row),
            'operationalHandoffHash':digest(handoff),'installedWorkerObservationHash':digest(observed),
            'currentSignedOperationalInstallationVerified':True,'currentTwoPeerGenerationObserved':True,
            'currentWorkerAndPositiveOwnedLeasesObserved':True,'initialProviderMandateExtended':False,
            'newGenerationAuthorized':False,'providerApplicationReadinessProvenHere':False,
            'fullCohortProven':False,'producerReleaseDispatched':False,'signaturesIssued':0,
            'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'budgetReset':False,'releaseAcceptance':False}
