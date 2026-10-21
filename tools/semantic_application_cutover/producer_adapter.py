"""Quiesce only inventoried producer generations under Executor's intent.

The caller's sealed checkpoint proves the complete database-writer inventory,
authority and command custody. This module never discovers/stops other services,
restarts a producer, retries an update/stop or releases the DB. The signed intent
explicitly authorizes disabling only its reviewed legacy restart policy.
"""
import json,re
from engine_creation import digest,require

class ProducerAdapter:
    def __init__(self,engine,transition,intent,store):
        self.engine,self.transition,self.store=engine,transition,store
        self.intent=json.loads(json.dumps(intent,allow_nan=False))
        require(set(self.intent)=={'producerBindings','initialNetworkSettings','initialHostConfigs','quiescentRestartPolicy','stopTimeoutSeconds'},'EXACT_PRODUCER_QUIESCENCE_INTENT_REQUIRED')
        pins=self.intent['producerBindings']
        require(type(pins) is list and 1<=len(pins)<=8 and type(self.intent['stopTimeoutSeconds']) is int
                and 1<=self.intent['stopTimeoutSeconds']<=10,'FINITE_INVENTORIED_PRODUCERS_REQUIRED')
        fields={'containerId','imageId','pid','startedAt','configHash','hostConfigHash','mountsHash','networkSettingsHash'}
        for pin in pins:
            require(type(pin) is dict and set(pin)==fields and type(pin['pid']) is int and pin['pid']>1
                    and type(pin['startedAt']) is str and 1<=len(pin['startedAt'])<=64,'EXACT_PRODUCER_GENERATION_REQUIRED')
            require(type(pin['containerId']) is str and re.fullmatch('[0-9a-f]{64}',pin['containerId']) is not None
                    and type(pin['imageId']) is str and re.fullmatch('sha256:[0-9a-f]{64}',pin['imageId']) is not None
                    and all(type(pin[k]) is str and re.fullmatch('[0-9a-f]{64}',pin[k]) is not None for k in fields if k.endswith('Hash')),'EXACT_PRODUCER_CONFIGURATION_HASHES_REQUIRED')
        require(len({p['containerId'] for p in pins})==len(pins),'DUPLICATE_PRODUCER_SCOPE_DENIED')
        networks=self.intent['initialNetworkSettings']
        require(type(networks) is dict and set(networks)=={p['containerId'] for p in pins}
                and all(type(networks[p['containerId']]) is dict and digest(networks[p['containerId']])==p['networkSettingsHash'] for p in pins),'SIGNED_INITIAL_PRODUCER_NETWORK_SETTINGS_REQUIRED')
        hosts=self.intent['initialHostConfigs']
        require(type(hosts) is dict and set(hosts)=={p['containerId'] for p in pins}
                and all(type(hosts[p['containerId']]) is dict and digest(hosts[p['containerId']])==p['hostConfigHash'] for p in pins),'SIGNED_INITIAL_PRODUCER_HOST_CONFIGS_REQUIRED')
        require(self.intent['quiescentRestartPolicy']=={'Name':'no','MaximumRetryCount':0},'EXPLICIT_QUIESCENT_RESTART_POLICY_REQUIRED')
        for host in hosts.values():
            require(host.get('RestartPolicy') in ({'Name':'no','MaximumRetryCount':0},{'Name':'unless-stopped','MaximumRetryCount':0}), 'REVIEWED_LEGACY_RESTART_POLICY_REQUIRED')
        self.intent_hash=digest(self.intent)
    def quiescent_host(self,pin):
        host=json.loads(json.dumps(self.intent['initialHostConfigs'][pin['containerId']]))
        host['RestartPolicy']=self.intent['quiescentRestartPolicy']
        return host
    def exact(self,intent):
        require(digest(intent)==self.intent_hash,'IMMUTABLE_PRODUCER_INTENT_REQUIRED')
        row=self.transition.read()
        require(row['state']=='IN_FLIGHT' and row['effects'][-1]['phase']=='QUIESCE_PRODUCERS'
                and row['effects'][-1]['intentHash']==self.intent_hash,'EXECUTOR_OWNED_QUIESCENCE_INTENT_REQUIRED')
    def inspect(self,pin):
        status,value=self.engine.request('GET','/v1.44/containers/'+pin['containerId']+'/json')
        if status==404:return None
        require(status==200 and type(value) is dict and value.get('Id')==pin['containerId'],'EXACT_PRODUCER_INSPECTION_REQUIRED')
        return value
    def running(self,pin,policy_disabled=False):
        actual=self.inspect(pin)
        expected={**pin,'hostConfigHash':digest(self.quiescent_host(pin))} if policy_disabled else pin
        require(actual is not None and self.engine.runtime_binding(actual)==expected
                and actual['State']['Running'] is True and actual['State']['Paused'] is False
                and actual['State']['Status']=='running' and type(actual['RestartCount']) is int and actual['RestartCount']>=0,'CURRENT_PRODUCER_GENERATION_OR_RESTART_POLICY_UNPROVEN')
        return actual
    def apply(self,intent):
        self.exact(intent)
        # Check the entire reviewed scope before the first mutation. Recheck each
        # particular generation immediately before its single stop request.
        for pin in self.intent['producerBindings']:self.running(pin)
        for pin in self.intent['producerBindings']:
            self.running(pin)
            if self.intent['initialHostConfigs'][pin['containerId']]['RestartPolicy']!=self.intent['quiescentRestartPolicy']:
                status,_=self.engine.request('POST','/v1.44/containers/'+pin['containerId']+'/update',{'RestartPolicy':self.intent['quiescentRestartPolicy']})
                require(status==200,'PRODUCER_RESTART_POLICY_OUTCOME_REQUIRES_RECONCILIATION')
            self.running(pin,policy_disabled=True)
            status,_=self.engine.request('POST','/v1.44/containers/'+pin['containerId']+'/stop?t='+str(self.intent['stopTimeoutSeconds']))
            require(status==204,'PRODUCER_STOP_OUTCOME_REQUIRES_RECONCILIATION')
    def stopped(self,pin):
        actual=self.inspect(pin)
        if actual is None:return None
        require(actual['Image']==pin['imageId'] and actual['State']['StartedAt']==pin['startedAt']
                and type(actual['RestartCount']) is int and actual['RestartCount']>=0 and digest(actual['Config'])==pin['configHash']
                and digest(actual['HostConfig']) in {pin['hostConfigHash'],digest(self.quiescent_host(pin))}
                and digest(actual['Mounts'])==pin['mountsHash'], 'PRODUCER_GENERATION_OR_CONFIGURATION_DRIFT')
        state=actual['State']
        if state['Running'] is True:return None
        require(digest(actual['HostConfig'])==digest(self.quiescent_host(pin)),'QUIESCENT_RESTART_POLICY_NOT_INSTALLED')
        require(state['Status']=='exited' and state['Paused'] is False and state['Pid']==0
                and state.get('Error','')=='' and type(state.get('FinishedAt')) is str
                and state['FinishedAt']!='0001-01-01T00:00:00Z','EXACT_STOPPED_PRODUCER_REQUIRED')
        return {'containerId':pin['containerId'],'imageId':pin['imageId'],'startedAt':pin['startedAt'],'initialRuntimeBinding':pin,
                'initialNetworkSettings':self.intent['initialNetworkSettings'][pin['containerId']],
                'finishedAt':state['FinishedAt'],'configHash':pin['configHash'],'hostConfigHash':digest(self.quiescent_host(pin)),
                'mountsHash':pin['mountsHash'],'running':False,'pid':0,'restartCount':actual['RestartCount'],
                'restartPolicyDisabled':True}
    def observe(self,intent):
        self.exact(intent)
        before=[self.stopped(pin) for pin in self.intent['producerBindings']]
        if any(value is None for value in before):
            return 'UNKNOWN',{'completeInventoriedQuiescenceUnproven':True,'absenceDoesNotProveNoEffect':True,'stopReplayAllowed':False}
        after=[self.stopped(pin) for pin in self.intent['producerBindings']]
        require(before==after,'QUIESCENT_PRODUCER_GENERATIONS_CHANGED_DURING_READ')
        evidence={'schema':'ouf.semantic-inventoried-producers-quiesced.v1','transitionContextHash':self.transition.context,
                  'intentHash':self.intent_hash,'producers':before,'restartPerformed':False,'databaseAdmissionGranted':False}
        self.store.publish('QUIESCE_PRODUCERS',evidence)
        return 'APPLIED',evidence
