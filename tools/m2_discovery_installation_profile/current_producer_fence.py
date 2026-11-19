"""Read the signed producer inventory at READY12 without dispatch or release.

Reuses the actual quiescence adapter's native generation/configuration checks.
The inventory remains explicitly reviewed, not dynamically discovered here.
"""
from .custody_capture import decode,digest,require
from .selected_runtime import DiscoverySelectedRuntime
from .application import DiscoveryApplication
from .executor import DiscoveryExecutor
from .node_owner import ObservationBudget
from producer_adapter import ProducerAdapter
from producer_release_adapter import ProducerReleaseAdapter
from transition_journal import PHASES


class CurrentProducerFence:
    def __init__(self,selected):
        require(type(selected) is DiscoverySelectedRuntime,'ACTUAL_SELECTED_RUNTIME_FOR_PRODUCER_FENCE_REQUIRED')
        self.selected=selected;self.app=selected.installation.application
        require(type(self.app) is DiscoveryApplication and type(self.app.executor) is DiscoveryExecutor,
            'ACTUAL_DISCOVERY_APPLICATION_FOR_CURRENT_PRODUCER_FENCE_REQUIRED')
        self.quiesced=self.app.executor.adapters['QUIESCE_PRODUCERS']
        self.release=self.app.executor.adapters['RELEASE_PRODUCERS']
        require(type(self.quiesced) is ProducerAdapter and type(self.release) is ProducerReleaseAdapter,
            'ACTUAL_NATIVE_QUIESCENCE_AND_RELEASE_OWNERS_REQUIRED')
        self.ids=tuple(map(id,(selected,self.app,self.app.executor,self.quiesced,self.release)))
        self.guard()

    def guard(self):
        s,app,q,r=self.selected,self.app,self.quiesced,self.release;s.guard();app.verify_scope()
        require(self.ids==tuple(map(id,(s,app,app.executor,q,r))) and s.installation.application is app
            and app.executor.adapters['QUIESCE_PRODUCERS'] is q and app.executor.adapters['RELEASE_PRODUCERS'] is r
            and q.engine is r.engine is s.images.engine and q.transition is r.transition is app.transition
            and q.store is r.store is app.store and r.request==app.request
            and q.intent==r.quiescence==app.intents['QUIESCE_PRODUCERS']
            and r.intent==app.intents['RELEASE_PRODUCERS'] and r.request_hash==app.request_hash
            and digest(q.intent)==q.intent_hash==r.intent['quiescenceIntentHash']==app.intent_hashes['QUIESCE_PRODUCERS']
            and digest(r.intent)==r.intent_hash==app.intent_hashes['RELEASE_PRODUCERS']
            and decode(app.raw)['phaseIntentHashes']==app.intent_hashes,
            'SAME_SIGNED_CURRENT_PRODUCER_FENCE_OWNERS_AND_INTENTS_REQUIRED')
        retired={app.intents['RELEASE_OLD_ENDPOINT']['containerId'],
            s.mcp.plan['replacement']['oldRuntimeBinding']['containerId'],s.gateway.plan['oldRuntimeBinding']['containerId']}
        require(len(retired)==3 and set(r.intent['retiredContainerIds'])==retired
            and not retired&set(r.intent['releaseProducerIds']) and len(q.intent['producerBindings'])<=8,
            'ALL_THREE_SELECTED_PREDECESSORS_MUST_REMAIN_RETIRED')
        row=s.held();effects=row.get('effects');index=PHASES.index('RELEASE_PRODUCERS')
        require(type(effects) is list and len(effects)==index
            and [e.get('phase') for e in effects]==list(PHASES[:index])
            and all(e.get('state')=='APPLIED' and e.get('intentHash')==app.intent_hashes[e['phase']] for e in effects),
            'EXACT_COMPLETED_PREFIX_WITH_ALL_PRODUCERS_HELD_REQUIRED')
        effect=effects[PHASES.index('QUIESCE_PRODUCERS')]
        retained=app.store.read('QUIESCE_PRODUCERS',effect['nativeEvidenceHash'])
        require(retained['schema']=='ouf.semantic-inventoried-producers-quiesced.v1'
            and retained['transitionContextHash']==app.transition.context and retained['intentHash']==q.intent_hash,
            'EXACT_RETAINED_CURRENT_PRODUCER_QUIESCENCE_EVIDENCE_REQUIRED')
        return row,retained

    def observe(self):
        budget=ObservationBudget(90);row,retained=self.guard();q=self.quiesced
        def snapshot():
            result=[]
            for pin in q.intent['producerBindings']:
                budget.check();value=q.stopped(pin);budget.check()
                require(value is not None,'CURRENT_REVIEWED_PRODUCER_FENCE_LOST')
                result.append(value)
            return result
        first=snapshot()
        require(first==retained['producers'] and snapshot()==first,
            'CURRENT_PRODUCER_FENCE_DIFFERS_FROM_COMPLETED_QUIESCENCE')
        require(self.guard()==(row,retained),'CURRENT_PRODUCER_FENCE_HISTORY_CHANGED_DURING_READ');budget.check()
        return {'schema':'ouf.discovery-current-producer-fence-witness.v1','heldHistoryHash':digest(row),
            'quiescenceEvidenceHash':digest(retained),'currentProducerEvidenceHash':digest(first),
            'reviewedProducerCount':len(first),'retiredSelectedPredecessorCount':3,'producerInspectionGets':len(first)*2,
            'currentReviewedProducerFenceObserved':True,'completeDatabaseWriterInventoryProvenHere':False,
            'fullCohortProven':False,'producerReleaseDispatched':False,'nativeMutationDispatched':False,
            'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'releaseAcceptance':False}
