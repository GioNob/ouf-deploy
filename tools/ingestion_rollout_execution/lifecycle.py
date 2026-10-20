"""Claimed-once native lifecycle effects for an already reviewed rollout.

Component only: full current DB/Owner/admission, image import, route HTTP and
issuer/entrypoint still belong to the complete Ports composition. This module
never discovers a replacement by name after an ambiguous creation. An unknown
CID remains UNKNOWN, retaining the claim rather than repeating POST /create.
"""
import copy
import re
from urllib.parse import quote
from engine_creation import Engine
from tools.ingestion_rollout_execution.contract import AUTHORITY_KEY,require,scope,digest
from tools.ingestion_rollout_execution.replacement import validate,generation
from tools.ingestion_rollout_execution.key import NativeKey
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.chatbot_file_cohort.human_session import HumanSession

ID=re.compile('[0-9a-f]{64}')
OPERATIONS={'DISABLE_OLD_RESTART','STOP_OLD','RENAME_OLD','CREATE_REPLACEMENT','START_REPLACEMENT','RESTORE_RESTART'}

class NativeLifecycle:
    def __init__(self,action,journal,review,packet,human,engine,key):
        require(type(action)is AggregateAction and type(journal)is Journal
                and type(human)is HumanSession and type(engine)is Engine and type(key)is NativeKey,
                'CONCRETE_SIGNED_NATIVE_LIFECYCLE_COMPONENTS_REQUIRED')
        self.action,self.journal,self.human,self.engine,self.key=action,journal,human,engine,key
        self.review,self.packet=copy.deepcopy(review),copy.deepcopy(packet)
        self.scope=scope(self.review)
        require(digest(packet)==review['packetBinding']['sha256']
                and key.action is action and key.journal is journal
                and key.scope==self.scope,'SAME_PACKET_KEY_JOURNAL_AND_AUTHORITY_REQUIRED')
        self.indices={s['name']:i for i,s in enumerate(review['stages'])}
    @staticmethod
    def handles(stage):
        parts=stage['name'].split('.',1)
        return len(parts)==2 and parts[0]in('ingestion','gateway') and (
            parts[1]in OPERATIONS or re.fullmatch('DETACH_[0-9a-f]{64}',parts[1])is not None)
    def guard(self,stage):
        require(self.handles(stage)and self.review['stages'][self.indices[stage['name']]]==stage,
                'EXACT_REVIEWED_LIFECYCLE_STAGE_REQUIRED')
        require(scope(self.review)==self.scope and digest(self.packet)==self.review['packetBinding']['sha256'],
                'LIFECYCLE_REVIEW_OR_PACKET_DRIFT')
        self.action.guard(AUTHORITY_KEY,self.scope)
        require(self.human.current()==self.scope['humanBinding'],'SAME_CURRENT_AUTHENTICATED_HUMAN_REQUIRED')
        self.engine.check_socket()
        row=self.journal.read();i=self.indices[stage['name']]
        require(row.get('scopeHash')==digest(self.scope)and row.get('authorityHash')==self.action.authority_hash
                and row.get('budgetReset')is False and row['nextStage']==i
                and len(row['effects'])==i+1 and all(e['state']=='APPLIED'for e in row['effects'][:i]),
                'EXACT_ORDERED_LIFECYCLE_EFFECT_CLAIM_REQUIRED')
        effect=row['effects'][i]
        require(effect['stage']==stage['name']and effect['intentHash']==stage['intentHash']
                and effect['state']=='CLAIMED','SAME_CLAIMED_LIFECYCLE_INTENT_REQUIRED')
        return row,effect
    def save_resource(self,stage,resource):
        row,effect=self.guard(stage)
        require(effect.get('nativeRequestAttempted')is True,'NATIVE_REQUEST_RESERVATION_REQUIRED')
        if 'nativeResource'in effect:
            require(effect['nativeResource']==resource,'ALLOCATED_NATIVE_RESOURCE_IDENTITY_CHANGED')
            return
        effects=copy.deepcopy(row['effects']);effects[-1]['nativeResource']=copy.deepcopy(resource)
        self.journal.compare_and_save(row,{**row,'effects':effects,'version':row['version']+1})
    def reserve(self,stage):
        row,effect=self.guard(stage)
        require(not effect.get('nativeRequestAttempted',False),'NATIVE_EFFECT_ALREADY_ATTEMPTED_RECONCILE_ONLY')
        effects=copy.deepcopy(row['effects']);effects[-1]['nativeRequestAttempted']=True
        self.journal.compare_and_save(row,{**row,'effects':effects,'version':row['version']+1})
        self.guard(stage)
    def request(self,method,path,body=None):
        self.engine.check_socket();result=self.engine.request(method,path,body);self.engine.check_socket()
        return result
    def container(self,cid):
        require(type(cid)is str and ID.fullmatch(cid),'FULL_DURABLE_CONTAINER_ID_REQUIRED')
        status,value=self.request('GET','/v1.44/containers/'+cid+'/json')
        require(status==200 and type(value)is dict and value.get('Id')==cid,'EXACT_CONTAINER_ID_READ_REQUIRED')
        return value
    def resource(self,name):
        row=self.journal.read();i=self.indices[name]
        if len(row['effects'])<=i:return None
        effect=row['effects'][i]
        require(effect['stage']==name and effect['intentHash']==self.review['stages'][i]['intentHash'],
                'DURABLE_NATIVE_RESOURCE_HISTORY_DRIFT')
        return effect.get('nativeResource')
    def created(self,module):
        resource=self.resource(module+'.CREATE_REPLACEMENT')
        require(type(resource)is dict and type(resource.get('containerId'))is str
                and ID.fullmatch(resource['containerId']),'DURABLE_CREATED_CONTAINER_ID_REQUIRED')
        return resource['containerId']
    def key_value(self,module):
        return self.key.read_for_gateway()if module=='gateway'else None
    def replacement(self,module,*,phase,process=None,restored=False):
        cid=self.created(module);actual=self.container(cid)
        proof=validate(self.packet['frames'][module],actual,self.image_config(module),
            self.packet['expectedRuntimeBindings'][module]['containerId'],created_id=cid,
            process=process,phase=phase,restart_restored=restored,
            resolved_owner_key=self.key_value(module))
        return actual,proof
    def image_config(self,module):
        if module=='ingestion':return self.packet['candidate']['imageConfig']
        image=self.packet['expectedRuntimeBindings']['gateway']['imageId']
        status,value=self.request('GET','/v1.44/images/'+quote(image,safe='')+'/json')
        require(status==200 and type(value)is dict and value.get('Id')==image
                and type(value.get('Config'))is dict,'EXACT_GATEWAY_IMAGE_CONFIG_REQUIRED')
        return value['Config']
    def old(self,module):
        pin=self.packet['expectedRuntimeBindings'][module]
        actual=self.container(pin['containerId'])
        require(actual['Image']==pin['imageId'],'RETAINED_CONTAINER_IMAGE_CHANGED')
        return actual
    def process(self,module):
        return self.resource(module+'.START_REPLACEMENT')
    def apply(self,stage):
        self.guard(stage);module,operation=stage['name'].split('.',1);intent=stage['intent']
        old_id=self.packet['expectedRuntimeBindings'][module]['containerId']
        if operation in('DISABLE_OLD_RESTART','STOP_OLD','RENAME_OLD')or operation.startswith('DETACH_'):
            actual=self.old(module)
            if operation!='DISABLE_OLD_RESTART':
                require(actual['HostConfig']['RestartPolicy']=={'Name':'no','MaximumRetryCount':0},
                        'OLD_RESTART_MUST_REMAIN_DISABLED')
            if operation=='STOP_OLD':
                require(actual['State']['Running']is True and actual['State']['Paused']is False,
                        'EXPECTED_RUNNING_UNPAUSED_PREDECESSOR_REQUIRED')
            if operation.startswith('DETACH_'):
                require(any(v.get('NetworkID')==intent['networkId']for v in actual['NetworkSettings']['Networks'].values()),
                        'EXPECTED_OLD_NETWORK_MUST_EXIST_BEFORE_DETACH')
            if operation=='RENAME_OLD'or operation.startswith('DETACH_'):
                require(actual['State']['Running']is False and actual['State']['Pid']==0,
                        'STOPPED_QUIESCENT_PREDECESSOR_REQUIRED')
        elif operation=='START_REPLACEMENT':
            self.replacement(module,phase='CREATED')
        elif operation=='RESTORE_RESTART':
            require(self.process(module)is not None,'DURABLE_FIRST_PROCESS_REQUIRED')
            self.replacement(module,phase='RUNNING',process=self.process(module))
        else:
            old=self.old(module)
            retained=self.review['stages'][self.indices[module+'.RENAME_OLD']]['intent']['retainedName']
            require(old['State']['Running']is False and old['State']['Pid']==0
                    and not old['NetworkSettings']['Networks']and old['Name']=='/'+retained,
                    'STOPPED_DETACHED_RENAMED_OLD_BEFORE_CREATION_REQUIRED')
            request=copy.deepcopy(intent['requestTemplate'])
            if module=='gateway':
                from tools.ingestion_rollout_preparation.frames import OWNER_ENV,SECRET_SLOT
                require(OWNER_ENV+'='+SECRET_SLOT in request['Env'],'EXACT_UNRESOLVED_KEY_SLOT_REQUIRED')
                value=self.key_value(module)
                request['Env']=[OWNER_ENV+'='+value if v==OWNER_ENV+'='+SECRET_SLOT else v for v in request['Env']]
        # No mutation may precede the durable attempted marker. A caller cannot
        # invoke apply twice even if it bypasses Runner's higher-level guard.
        self.reserve(stage)
        if operation=='DISABLE_OLD_RESTART':
            status,_=self.request('POST','/v1.44/containers/'+old_id+'/update',{'RestartPolicy':intent['restartPolicy']})
            require(status==200,'DISABLE_RESTART_OUTCOME_UNPROVEN')
        elif operation=='STOP_OLD':
            status,_=self.request('POST','/v1.44/containers/'+old_id+'/stop?t='+str(intent['timeoutSeconds']))
            require(status==204,'STOP_OUTCOME_UNPROVEN')
        elif operation.startswith('DETACH_'):
            status,_=self.request('POST','/v1.44/networks/'+intent['networkId']+'/disconnect',{'Container':old_id,'Force':False})
            require(status==200,'DETACH_OUTCOME_UNPROVEN')
        elif operation=='RENAME_OLD':
            status,_=self.request('POST','/v1.44/containers/'+old_id+'/rename?name='+quote(intent['retainedName'],safe=''))
            require(status==204,'RENAME_OUTCOME_UNPROVEN')
        elif operation=='CREATE_REPLACEMENT':
            status,value=self.request('POST','/v1.44/containers/create?name='+quote(intent['name'],safe=''),request)
            require(status==201 and type(value)is dict and type(value.get('Id'))is str and ID.fullmatch(value['Id']),
                    'CREATE_OUTCOME_WITH_EXACT_CID_UNPROVEN')
            require(value['Id']!=old_id,'NEW_NATIVE_CONTAINER_ID_REQUIRED')
            self.save_resource(stage,{'containerId':value['Id']})
            # Persist the returned CID before any subsequent read can fail.
            self.replacement(module,phase='CREATED')
        elif operation=='START_REPLACEMENT':
            cid=self.created(module);status,_=self.request('POST','/v1.44/containers/'+cid+'/start')
            require(status==204,'START_OUTCOME_UNPROVEN')
            _,process=self.replacement(module,phase='RUNNING')
            self.save_resource(stage,process)
        else:
            cid=self.created(module);status,_=self.request('POST','/v1.44/containers/'+cid+'/update',{'RestartPolicy':intent['restartPolicy']})
            require(status==200,'RESTORE_RESTART_OUTCOME_UNPROVEN')
        self.guard(stage)
    def observe(self,stage):
        _,effect=self.guard(stage)
        if effect.get('nativeRequestAttempted')is not True:return 'UNKNOWN',{}
        module,operation=stage['name'].split('.',1);intent=stage['intent']
        if operation=='CREATE_REPLACEMENT':
            if effect.get('nativeResource')is None:return 'UNKNOWN',{}
            _,proof=self.replacement(module,phase='CREATED')
            return 'APPLIED',proof
        if operation in('START_REPLACEMENT','RESTORE_RESTART'):
            process=self.process(module)
            if operation=='RESTORE_RESTART':require(process is not None,'DURABLE_FIRST_PROCESS_REQUIRED')
            _,proof=self.replacement(module,phase='RUNNING',process=process,restored=operation=='RESTORE_RESTART')
            if operation=='START_REPLACEMENT'and process is None:
                # Read-only adoption of the FIRST process of our durable CID;
                # never another start call or a container discovered by name.
                self.save_resource(stage,proof)
            return 'APPLIED',proof
        old=self.old(module)
        if operation=='DISABLE_OLD_RESTART':
            done=old['HostConfig']['RestartPolicy']==intent['restartPolicy']
        elif operation=='STOP_OLD':
            done=old['State']['Running']is False and old['State']['Pid']==0
        elif operation=='RENAME_OLD':
            done=old['Name']=='/'+intent['retainedName']
        else:
            networks=old['NetworkSettings']['Networks']
            done=all(n.get('NetworkID')!=intent['networkId']for n in networks.values())
        return ('APPLIED',{'containerId':old['Id'],'nativePostconditionProven':True})if done else('UNKNOWN',{})
