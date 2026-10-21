"""Release only reviewed independent producers; keep the old application retired.

Each update/start is sent once under Executor's durable phase claim. Partial or
unknown effects stay IN_FLIGHT for native reconciliation; no automatic start,
restart-policy replay, rollback or restoration of the old registry is performed.
"""
import copy
from engine_creation import Engine
from producer_adapter import ProducerAdapter
from application_verification_adapter import ApplicationReadinessChannel
from native_evidence_store import NativeEvidenceStore
from transition_journal import digest,hash_value,require

PHASE='RELEASE_PRODUCERS'
NO_RESTART={'Name':'no','MaximumRetryCount':0}

class ProducerReleaseAdapter:
    def __init__(self,engine,transition,request,intent,quiescence,store,before_store,readiness,checkpoint):
        require(type(engine) is Engine and type(store) is NativeEvidenceStore and type(before_store) is NativeEvidenceStore
                and store.root!=before_store.root and type(readiness) is ApplicationReadinessChannel and callable(checkpoint),
                'TYPED_PRODUCER_RELEASE_CHANNELS_REQUIRED')
        fields={'creationRequestHash','quiescenceIntentHash','retiredContainerIds','releaseProducerIds','restartPolicies','cohortReviewHash'}
        require(type(intent) is dict and set(intent)==fields and intent['creationRequestHash']==digest(request)
                and intent['quiescenceIntentHash']==digest(quiescence) and hash_value(intent['cohortReviewHash']),
                'EXACT_PRODUCER_RELEASE_INTENT_REQUIRED')
        pins=quiescence['producerBindings'];selected=intent['releaseProducerIds'];retired=intent['retiredContainerIds']
        require(type(selected) is list and len(selected)<=7 and all(hash_value(v) for v in selected) and len(set(selected))==len(selected)
                and type(retired) is list and 1<=len(retired)<=8 and all(hash_value(v) for v in retired) and len(set(retired))==len(retired)
                and set(retired)<={p['containerId'] for p in pins} and set(selected)=={p['containerId'] for p in pins}-set(retired)
                and type(intent['restartPolicies']) is dict and set(intent['restartPolicies'])==set(selected),
                'COMPLETE_INDEPENDENT_PRODUCER_RELEASE_SCOPE_REQUIRED')
        for cid in selected:
            require(intent['restartPolicies'][cid] in (NO_RESTART,quiescence['initialHostConfigs'][cid]['RestartPolicy']),
                    'UNREVIEWED_PRODUCER_RESTART_POLICY_DENIED')
        self.engine,self.transition,self.store,self.before_store,self.readiness,self.checkpoint=engine,transition,store,before_store,readiness,checkpoint
        self.request,self.intent,self.quiescence=map(copy.deepcopy,(request,intent,quiescence))
        self.intent_hash=digest(intent);self.request_hash=digest(request);self.pins={p['containerId']:p for p in pins}
        self.quiesced=ProducerAdapter(engine,transition,quiescence,store)
    def current(self,intent):
        require(digest(intent)==self.intent_hash==digest(self.intent) and digest(self.request)==self.request_hash
                and digest(self.quiescence)==self.intent['quiescenceIntentHash'],'PRODUCER_RELEASE_SCOPE_DRIFT')
        row=self.transition.read()
        require(row['state']=='IN_FLIGHT' and row['effects'][-1]['phase']==PHASE and row['effects'][-1]['intentHash']==self.intent_hash
                and row['creationRequestHash']==self.request_hash,'DURABLE_PRODUCER_RELEASE_BOUNDARY_REQUIRED')
        stopped=next(e for e in row['effects'] if e['phase']=='QUIESCE_PRODUCERS' and e['state']=='APPLIED')
        require(stopped['intentHash']==self.intent['quiescenceIntentHash'],'PRODUCER_RELEASE_QUIESCENCE_HISTORY_DRIFT')
        self.store.read('QUIESCE_PRODUCERS',stopped['nativeEvidenceHash'])
        verification=next(e for e in row['effects'] if e['phase']=='VERIFY_APPLICATION' and e['state']=='APPLIED')
        verified=self.store.read('VERIFY_APPLICATION',verification['nativeEvidenceHash'])
        actual=self.engine.matching_configuration(self.transition,self.request,self.engine.inspect(self.transition))
        require(verified.get('schema')=='ouf.semantic-application-verified.v1' and verified.get('transitionContextHash')==self.transition.context
                and verified.get('readinessScopeHash')==self.readiness.scope_hash and verified.get('runtimeBinding')==self.engine.runtime_binding(actual)
                and actual['State']['Running'] is True and actual['State']['Paused'] is False and actual['State']['Status']=='running'
                and actual.get('RestartCount')==0,'VERIFIED_APPLICATION_GENERATION_BEFORE_PRODUCER_RELEASE_REQUIRED')
        require(all(self.quiesced.stopped(self.pins[cid]) is not None for cid in self.intent['retiredContainerIds']),
                'OLD_APPLICATION_MUST_REMAIN_RETIRED')
        return verified
    def health(self):
        require(self.readiness.health() is not None,'APPLICATION_NOT_READY_FOR_PRODUCER_RELEASE')
    def stopped(self,cid,policy):
        pin=self.pins[cid];actual=self.quiesced.inspect(pin);host=copy.deepcopy(self.quiescence['initialHostConfigs'][cid]);host['RestartPolicy']=policy
        require(actual is not None and actual['Image']==pin['imageId'] and digest(actual['Config'])==pin['configHash']
                and digest(actual['HostConfig'])==digest(host) and digest(actual['Mounts'])==pin['mountsHash']
                and actual['State']['StartedAt']==pin['startedAt'] and actual['State']['Running'] is False
                and actual['State']['Paused'] is False and actual['State']['Status']=='exited' and actual['State']['Pid']==0,
                'EXACT_STOPPED_PRODUCER_BEFORE_RELEASE_REQUIRED')
        return actual
    def apply(self,intent):
        self.checkpoint('BEFORE_PRODUCER_RELEASE');verified=self.current(intent);self.health()
        selected=self.intent['releaseProducerIds']
        baseline={cid:self.stopped(cid,NO_RESTART) for cid in selected}
        self.before_store.publish(PHASE,{'schema':'ouf.semantic-producer-release-before.v1','transitionContextHash':self.transition.context,
            'intentHash':self.intent_hash,'verifiedApplicationHash':digest(verified),'stoppedProducers':baseline})
        for cid in selected:
            self.current(intent);self.health();self.stopped(cid,NO_RESTART);policy=self.intent['restartPolicies'][cid]
            if policy!=NO_RESTART:
                self.checkpoint('BEFORE_PRODUCER_RESTART_POLICY')
                status,_=self.engine.request('POST','/v1.44/containers/'+cid+'/update',{'RestartPolicy':policy})
                require(status==200,'PRODUCER_RELEASE_POLICY_OUTCOME_REQUIRES_RECONCILIATION')
            self.stopped(cid,policy);self.current(intent);self.checkpoint('BEFORE_PRODUCER_START')
            status,_=self.engine.request('POST','/v1.44/containers/'+cid+'/start')
            require(status==204,'PRODUCER_RELEASE_START_OUTCOME_REQUIRES_RECONCILIATION')
    def observed_producers(self,before):
        result=[]
        for cid in self.intent['releaseProducerIds']:
            pin=self.pins[cid];actual=self.quiesced.inspect(pin)
            if actual is None:return None
            host=copy.deepcopy(self.quiescence['initialHostConfigs'][cid]);host['RestartPolicy']=self.intent['restartPolicies'][cid]
            require(actual['Image']==pin['imageId'] and digest(actual['Config'])==pin['configHash']
                    and digest(actual['Mounts'])==pin['mountsHash'] and digest(actual['HostConfig'])==digest(host),
                    'RELEASED_PRODUCER_CONFIGURATION_DRIFT')
            state=actual['State']
            if state['Running'] is not True:return None
            require(state['Paused'] is False and state['Status']=='running' and state['Pid']>1
                    and state['StartedAt']!=before[cid]['State']['StartedAt'] and actual['RestartCount']==before[cid]['RestartCount'],
                    'NEW_RELEASED_PRODUCER_GENERATION_REQUIRED')
            prior=self.quiescence['initialNetworkSettings'][cid]['Networks'];current=actual['NetworkSettings']['Networks']
            require(set(current)==set(prior) and all(all(current[n].get(k)==prior[n].get(k)
                    for k in ('NetworkID','IPAddress','GlobalIPv6Address','MacAddress')) for n in prior),
                    'RELEASED_PRODUCER_NETWORK_SCOPE_DRIFT')
            result.append(self.engine.runtime_binding(actual))
        return result
    def observe(self,intent):
        self.checkpoint('BEFORE_RELEASED_PRODUCER_RECONCILIATION');verified=self.current(intent)
        try:baseline=self.before_store.read_baseline(PHASE,self.transition.context,self.intent_hash)
        except FileNotFoundError:return 'UNKNOWN',{'producerReleaseBaselineAbsent':True,'startReplayAllowed':False}
        require(baseline.get('schema')=='ouf.semantic-producer-release-before.v1' and baseline.get('verifiedApplicationHash')==digest(verified)
                and set(baseline.get('stoppedProducers',{}))==set(self.intent['releaseProducerIds']),
                'EXACT_RELEASED_PRODUCER_BASELINE_REQUIRED')
        before=self.observed_producers(baseline['stoppedProducers'])
        if before is None:return 'UNKNOWN',{'producerReleaseOutcomeUnproven':True,'startReplayAllowed':False,'oldApplicationRestartAllowed':False}
        self.health();require(self.current(intent)==verified and self.observed_producers(baseline['stoppedProducers'])==before,
                'RELEASED_PRODUCER_GENERATIONS_CHANGED_DURING_READ')
        evidence={'schema':'ouf.semantic-inventoried-producers-released.v1','transitionContextHash':self.transition.context,
            'intentHash':self.intent_hash,'newApplicationBinding':verified['runtimeBinding'],'retiredContainerIds':self.intent['retiredContainerIds'],
            'cohortReviewHash':self.intent['cohortReviewHash'],
            'releasedProducers':before,'beforeEvidenceHash':digest(baseline),'oldApplicationStillRetired':True,
            'releasedProducerCount':len(before),'retiredProducerCount':len(self.intent['retiredContainerIds']),
            'startReplayAllowed':False,'oldApplicationRestartAllowed':False,'releaseAcceptance':False}
        self.store.publish(PHASE,evidence);return 'APPLIED',evidence
