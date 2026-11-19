"""Compose the existing Registry cutover, provider sequence and late worker.

The same signed Registry child stops at its paused gate before the provider's
one-use sequence. Registry attestation can continue only after current provider
admission and durable gate closure. Cohort verification/release retains the
existing application's sealed checkpoint; construction grants no authority.
"""
import os
from .custody_capture import require
from .application import DiscoveryApplication
from .provider_installation_phase import ProviderInstallationPhase,transient
from .lease_materialization import WorkerMaterialization
from transition_journal import PHASES

BOUNDARY=PHASES.index('ATTEST_NEW_OCI_PEER')


class DiscoveryInstallationApplication:
    def __init__(self,*,application,provider,worker):
        require(type(application) is DiscoveryApplication and type(provider) is ProviderInstallationPhase
            and type(worker) is WorkerMaterialization,'TYPED_DISCOVERY_INSTALLATION_COMPOSITION_REQUIRED')
        self.application,self.provider,self.worker=application,provider,worker
        self.owner_ids=tuple(map(id,(application,provider,worker)))
        self.verify_scope()

    def verify_scope(self):
        app,provider,worker=self.application,self.provider,self.worker;window=provider.window
        require(self.owner_ids==tuple(map(id,(app,provider,worker)))
            and type(app) is DiscoveryApplication and type(provider) is ProviderInstallationPhase
            and type(worker) is WorkerMaterialization and worker.node is app.node_owner
            and worker.provider is provider.runtime.admission and worker.parent is provider.parent
            and window.parent is provider.parent and worker.node.engine is window.engine
            and app.node_owner.engine is window.engine and window.transition is app.transition
            and worker.transition is app.transition and worker.store is app.store and window.store is app.store
            and window.child is worker.authority is app.authority
            and window.raw==worker.authority_raw==app.raw
            and window.profile is app.profile and window.request==app.request==worker.node.request
            and window.request_hash==worker.request_hash==app.request_hash
            and app.infrastructure_owners.get(worker.phase) is worker,
            'SAME_PARENT_CHILD_ENGINE_REGISTRY_PROVIDER_AND_WORKER_REQUIRED')
        app.verify_scope();provider.current();worker.check_scope()

    def provider_barrier(self):
        """Reconcile an existing sequence; never reopen or redispatch it."""
        self.verify_scope();app=self.application;provider=self.provider
        if app.transition.read()['nextPhase']<BOUNDARY:
            app.executor.run(BOUNDARY)
        row=app.transition.read()
        if not os.path.lexists(provider.journal.record):
            require(row['state']=='READY' and row['nextPhase']==BOUNDARY,
                'PROVIDER_INSTALLATION_REQUIRED_BEFORE_REGISTRY_ATTESTATION')
            provider.window.boundary()
            try:provider.apply()
            except Exception as error:
                if not transient(error):raise
                # Only the already dispatched sequence may be observed. The
                # original provider owner retains its finite read budget.
        outcome,evidence=provider.observe()
        require(outcome=='APPLIED' and evidence.get('schema')=='ouf.discovery-provider-installation-sequence-complete.v1'
            and evidence.get('registryGateClosedBeforeReturn') is True,
            'CURRENT_PROVIDER_ADMISSION_AND_RETAINED_GATE_CLOSURE_REQUIRED')
        require(app.transition.read()==row,'REGISTRY_TRANSITION_CHANGED_DURING_PROVIDER_INSTALLATION')
        self.verify_scope();return evidence

    def verify_registry_and_hold(self):
        self.provider_barrier()
        return self.application.verify_registry_and_hold()

    def continue_worker_installation(self):
        """Explicit current-authority continuation of untouched worker stages."""
        self.provider_barrier();app=self.application
        self.worker.continue_installation(app.intents[self.worker.phase])
        return app.verify_registry_and_hold()

    def release_after_cohort_verification(self):
        self.provider_barrier()
        return self.application.release_after_cohort_verification()
