"""Four closed native lifecycle effects for one new gated Registry generation.

Component only: no production Ports/factory/CLI is provided. Full native owner
checkpoints and signed paused OCI attestation must guard dispatch separately.
"""
import copy,os
from pathlib import Path
from .core import require,digest,generation,Store,validate_plan
from .authorization import AuthorityScope

NAMES={'START_NEW_WAIT_GATE':'start','PAUSE_NEW_WAIT_GATE':'pause',
       'UNPAUSE_ATTESTED_GENERATION':'unpause','RELEASE_SAME_GENERATION_SIGUSR1':'kill?signal=SIGUSR1'}

def engine_type():
    from engine_creation import Engine
    return Engine
def process_type():
    from gated_process_observation import GatedProcessObservation
    return GatedProcessObservation

def observe_generation(process,pid,cid):
    observed=process.observe(pid);g=observed['generation']
    with open('/proc/sys/kernel/random/boot_id','r',encoding='ascii') as source:boot=source.read(129).strip()
    ns=Path('/proc')/str(pid)/'ns/net';s=ns.stat()
    require(s.st_ino==g['namespaceInode'],'CURRENT_PROCESS_NAMESPACE_CHANGED')
    value={'containerId':cid,'bootId':boot,'pid':pid,'startTicks':g['startTicks'],
           'namespaceDevice':s.st_dev,'namespaceInode':s.st_ino}
    generation(value);return value,observed

class Lifecycle:
    def __init__(self,engine,authority,store,plan,request,stopped_snapshot,proposal):
        require(type(engine) is engine_type() and type(authority) is AuthorityScope and type(store) is Store,
                'TYPED_NATIVE_REGISTRY_LIFECYCLE_REQUIRED')
        validate_plan(plan);authority.guard()
        self.engine,self.authority,self.store=engine,authority,store
        self.plan,self.request,self.baseline,self.proposal=map(copy.deepcopy,(plan,request,stopped_snapshot,proposal))
        self.cid=plan['stages'][0]['intent']['registryId'];self.process=process_type()(request)
        self.binding=digest({'request':request,'snapshot':stopped_snapshot,'proposal':proposal})
        require(proposal['registry']['containerId']==self.cid==stopped_snapshot['Id']
                and proposal['registry']['imageId']==stopped_snapshot['Image']==request['Image']
                and proposal['registry']['configHash']==digest(stopped_snapshot['Config'])
                and proposal['registry']['hostConfigHash']==digest(stopped_snapshot['HostConfig'])
                and proposal['registry']['mountsHash']==digest(sorted(stopped_snapshot['Mounts'],key=lambda m:m['Destination']))
                and stopped_snapshot['State']['Status']=='exited' and stopped_snapshot['State']['Pid']==0,
                'EXACT_REVIEWED_STOPPED_REGISTRY_BASELINE_REQUIRED')
    def current(self,stage):
        require(stage in self.plan['stages'] and stage['name'] in NAMES,'CLOSED_REGISTRY_LIFECYCLE_STAGE_REQUIRED')
        require(digest({'request':self.request,'snapshot':self.baseline,'proposal':self.proposal})==self.binding,
                'REGISTRY_LIFECYCLE_BASELINE_CHANGED')
        row=self.store.read();self.authority.guard(row)
        require(row['planHash']==digest(self.plan) and row['state']=='IN_FLIGHT'
                and row['nextStage']<len(self.plan['stages']) and self.plan['stages'][row['nextStage']]==stage
                and row['effects'][-1]['state']=='CLAIMED' and row['effects'][-1]['stage']==stage['name']
                and row['effects'][-1]['intentHash']==stage['intentHash'],'EXACT_DURABLE_NATIVE_EFFECT_CLAIM_REQUIRED')
        return row
    def inspect(self):
        status,actual=self.engine.request('GET','/v1.44/containers/'+self.cid+'/json')
        require(status==200 and type(actual) is dict and actual['Id']==self.cid
                and actual['Image']==self.baseline['Image'] and digest(actual['Config'])==digest(self.baseline['Config'])
                and digest(sorted(actual['Mounts'],key=lambda m:m['Destination']))==digest(sorted(self.baseline['Mounts'],key=lambda m:m['Destination']))
                and actual.get('RestartCount')==self.baseline.get('RestartCount')==0,
                'CURRENT_REVIEWED_REGISTRY_CONFIGURATION_CHANGED')
        before=self.baseline['HostConfig'];after=actual['HostConfig']
        require(set(before)==set(after) and all(digest(after[k])==digest(v) or
                (k=='OomKillDisable' and (v is None or v is False) and (after[k] is None or after[k] is False)) for k,v in before.items()),
                'CURRENT_REVIEWED_REGISTRY_HOST_CONFIGURATION_CHANGED')
        return actual
    def process_evidence(self,actual):
        state=actual['State']
        require(state['Running'] is True and state['Status'] in ('running','paused')
                and not state.get('Restarting') and not state.get('Dead') and state['Pid']>1,
                'CURRENT_NEW_REGISTRY_PROCESS_REQUIRED')
        new,process=observe_generation(self.process,state['Pid'],self.cid)
        return {'newGeneration':new,'processKind':process['processKind'],'startedAt':state['StartedAt'],
                'paused':state['Paused'] is True}
    def _save_effect(self,row,**changes):
        effects=copy.deepcopy(row['effects']);effects[-1].update(changes)
        self.store.cas(row,{**row,'effects':effects,'version':row['version']+1})
    def apply(self,stage):
        row=self.current(stage);effect=row['effects'][-1]
        require(effect.get('nativeRequestAttempted') is not True,'NATIVE_REGISTRY_EFFECT_ALREADY_ATTEMPTED_RECONCILE_ONLY')
        actual=self.inspect();name=stage['name']
        if name=='START_NEW_WAIT_GATE':
            require(actual['State']==self.baseline['State'] and actual['NetworkSettings']==self.baseline['NetworkSettings'],
                    'STOPPED_REGISTRY_CHANGED_BEFORE_NEW_START')
        else:
            proof=self.process_evidence(actual)
            require(proof['newGeneration']==row['newGeneration'] and proof['processKind']=='GATE_WAITING'
                    and proof['paused']==(name=='UNPAUSE_ATTESTED_GENERATION'),'SAME_GATED_GENERATION_BEFORE_EFFECT_REQUIRED')
        self.authority.guard(row)
        self._save_effect(row,nativeRequestAttempted=True)
        row=self.current(stage);self.authority.guard(row)
        status,_=self.engine.request('POST','/v1.44/containers/'+self.cid+'/'+NAMES[name])
        require(status==204,'NATIVE_REGISTRY_EFFECT_OUTCOME_REQUIRES_RECONCILIATION')
        row=self.current(stage)
        if name=='START_NEW_WAIT_GATE':
            # Capture the first PID/ticks/namespace only in the initial successful
            # call. A later reader never adopts a process after this gap.
            actual=self.inspect();proof=self.process_evidence(actual)
            require(proof['paused'] is False,'FRESH_WAIT_GATE_MUST_NOT_ALREADY_BE_PAUSED')
            self._save_effect(row,nativeResponse204=True,nativeFirstProcess=proof)
        else:self._save_effect(row,nativeResponse204=True)
    def observe(self,stage):
        row=self.current(stage);effect=row['effects'][-1]
        if effect.get('nativeRequestAttempted') is not True:return 'UNKNOWN',{}
        if stage['name']=='START_NEW_WAIT_GATE' and (effect.get('nativeResponse204') is not True
                or type(effect.get('nativeFirstProcess')) is not dict):return 'UNKNOWN',{}
        actual=self.inspect();proof=self.process_evidence(actual)
        if stage['name']=='START_NEW_WAIT_GATE':
            first=effect['nativeFirstProcess']
            require(proof['newGeneration']==first['newGeneration'] and proof['startedAt']==first['startedAt'],
                    'FIRST_DURABLY_CAPTURED_REGISTRY_GENERATION_CHANGED')
            if proof['processKind']!='GATE_WAITING' or proof['paused']:return 'UNKNOWN',{}
            proof['durableNativeStartEvidence']=True
        else:
            require(proof['newGeneration']==row['newGeneration'],'RECOVERY_GENERATION_CHANGED_NO_ADOPTION')
            paused=stage['name']=='PAUSE_NEW_WAIT_GATE'
            kind='APPLICATION_RUNNING' if stage['name']=='RELEASE_SAME_GENERATION_SIGUSR1' else 'GATE_WAITING'
            if proof['paused']!=paused or proof['processKind']!=kind:return 'UNKNOWN',{}
        self.authority.guard(row);return 'APPLIED',proof
