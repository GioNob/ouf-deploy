"""One persisted direct-HTTP budget shared by all typed Engine components.

Wraps the exact existing Engine instance without editing its historical source.
Docker CLI load/SQL sessions have their own finite counters; these counters name
direct HTTP calls only. Failed or ambiguous requests consume their reservation.
"""
import copy
import re
import time
from engine_creation import Engine
from tools.ingestion_rollout_execution.contract import AUTHORITY_KEY,require,scope,digest,encoded
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.chatbot_file_cohort.human_session import HumanSession

LIMITS={'GET':4096,'POST':32}
COUNTERS={'GET':'nativeDirectEngineGets','POST':'nativeDirectEnginePosts'}
GET=re.compile(r'/v1\.44/(?:containers/[0-9a-f]{64}|images/sha256%3A[0-9a-f]{64})/json')

class NativeEngineChannel:
    def __init__(self,action,journal,review,human,engine):
        require(type(action)is AggregateAction and type(journal)is Journal and type(human)is HumanSession
                and type(engine)is Engine,'CONCRETE_SIGNED_ENGINE_CHANNEL_REQUIRED')
        require('request'not in engine.__dict__,'ONE_NATIVE_ENGINE_CHANNEL_PER_INSTANCE_REQUIRED')
        self.action,self.journal,self.human,self.engine=action,journal,human,engine
        self.review=copy.deepcopy(review);self.scope=scope(self.review)
        require(review.get('maximumDirectEngineGets')==LIMITS['GET']
                and review.get('maximumDirectEnginePosts')==LIMITS['POST'], 'FINITE_SIGNED_ENGINE_BUDGET_REQUIRED')
        self.check();engine.request=self.request

    def check(self):
        require(scope(self.review)==self.scope,'ENGINE_CHANNEL_REVIEW_DRIFT')
        self.action.guard(AUTHORITY_KEY,self.scope)
        require(self.human.current()==self.scope['humanBinding'],'SAME_CURRENT_AUTHENTICATED_HUMAN_REQUIRED')
        selected=self.review['engineBinding'];self.engine.check_socket()
        require(self.engine.path==selected['socketPath']and list(self.engine.binding)==selected['socketBinding'],
                'SAME_SIGNED_ENGINE_CHANNEL_REQUIRED')
        row=self.journal.read()
        require(row.get('scopeHash')==digest(self.scope)and row.get('authorityHash')==self.action.authority_hash
                and row.get('budgetReset')is False,'SAME_PERSISTENT_ENGINE_JOURNAL_REQUIRED')
        for method,key in COUNTERS.items():
            require(type(row.get(key,0))is int and 0<=row.get(key,0)<=LIMITS[method],
                    'PERSISTENT_ENGINE_COUNTER_INVALID')
        require(min(row['expiresAt']-time.time(),row['expiresMonotonic']-time.monotonic())>16,
                'FINITE_CURRENT_DIRECT_ENGINE_WINDOW_REQUIRED')
        return row

    def request(self,method,path,body=None):
        require(method in LIMITS and type(path)is str,'CLOSED_DIRECT_ENGINE_OPERATION_REQUIRED')
        if method=='GET':require(GET.fullmatch(path)and body is None,'EXACT_ID_ENGINE_GET_ONLY')
        row=self.check();key=COUNTERS[method]
        require(row.get(key,0)<LIMITS[method],'CUMULATIVE_DIRECT_ENGINE_BUDGET_EXHAUSTED')
        following={**row,key:row.get(key,0)+1,'version':row['version']+1}
        if method=='POST':
            i=row['nextStage'];require(i<len(self.review['stages'])and len(row['effects'])==i+1,
                                      'EXISTING_NATIVE_EFFECT_CLAIM_REQUIRED_FOR_ENGINE_POST')
            stage=self.review['stages'][i];effect=row['effects'][i]
            require(stage['kind']=='EFFECT'and stage['name'].startswith(('ingestion.','gateway.'))
                    and effect['stage']==stage['name']and effect['intentHash']==stage['intentHash']
                    and effect['state']=='CLAIMED'and effect.get('nativeRequestAttempted')is True
                    and effect.get('nativeEnginePostAttempted',False)is False,
                    'EXACT_ONCE_CLAIMED_NATIVE_ENGINE_POST_REQUIRED')
            expected_path,expected_body=self.post_intent(stage,row)
            require(path==expected_path,'EXACT_REVIEWED_ENGINE_POST_RESOURCE_REQUIRED')
            if not stage['name'].endswith('.CREATE_REPLACEMENT'):
                require(encoded(body)==encoded(expected_body),'EXACT_REVIEWED_ENGINE_POST_BODY_REQUIRED')
            else:
                wanted=copy.deepcopy(expected_body);actual=copy.deepcopy(body)
                require(type(actual)is dict,'EXACT_CREATE_FRAME_REQUIRED')
                if stage['name'].startswith('gateway.'):
                    slot='OUF_INGESTION_READ_OWNER_KEY=@ouf-secret-reference:ingestionReadOwnerKey'
                    entries=actual.get('Env');prefix='OUF_INGESTION_READ_OWNER_KEY='
                    require(type(entries)is list and len([v for v in entries if type(v)is str and v.startswith(prefix)])==1,
                            'ONE_RESOLVED_GATEWAY_SECRET_SLOT_REQUIRED')
                    secret=next(v[len(prefix):]for v in entries if type(v)is str and v.startswith(prefix))
                    require(re.fullmatch('[0-9a-f]{64}',secret),'RESOLVED_PRIVATE_GATEWAY_KEY_REQUIRED')
                    actual['Env']=[slot if v.startswith(prefix)else v for v in entries]
                require(encoded(actual)==encoded(wanted),'EXACT_REVIEWED_CREATE_FRAME_REQUIRED')
            effects=copy.deepcopy(row['effects']);effects[-1]['nativeEnginePostAttempted']=True
            following['effects']=effects
        self.journal.compare_and_save(row,following)
        self.check()
        result=Engine.request(self.engine,method,path,body)
        self.check();return result

    def post_intent(self,stage,row):
        from urllib.parse import quote
        module,operation=stage['name'].split('.',1);intent=stage['intent']
        if operation=='DISABLE_OLD_RESTART':return '/v1.44/containers/'+intent['oldContainerId']+'/update',{'RestartPolicy':intent['restartPolicy']}
        if operation=='STOP_OLD':return '/v1.44/containers/'+intent['oldContainerId']+'/stop?t='+str(intent['timeoutSeconds']),None
        if operation.startswith('DETACH_'):return '/v1.44/networks/'+intent['networkId']+'/disconnect',{'Container':intent['oldContainerId'],'Force':False}
        if operation=='RENAME_OLD':return '/v1.44/containers/'+intent['oldContainerId']+'/rename?name='+quote(intent['retainedName'],safe=''),None
        if operation=='CREATE_REPLACEMENT':return '/v1.44/containers/create?name='+quote(intent['name'],safe=''),intent['requestTemplate']
        require(operation in('START_REPLACEMENT','RESTORE_RESTART'),'CLOSED_NATIVE_ENGINE_POST_INTENT_REQUIRED')
        index=next(i for i,s in enumerate(self.review['stages'])if s['name']==module+'.CREATE_REPLACEMENT')
        effect=row['effects'][index]
        require(effect['state']=='APPLIED','DURABLE_CREATED_RUNTIME_REQUIRED')
        cid=effect.get('nativeResource',{}).get('containerId')
        require(type(cid)is str and re.fullmatch('[0-9a-f]{64}',cid),'EXACT_DURABLE_CREATED_RUNTIME_REQUIRED')
        return ('/v1.44/containers/'+cid+'/start',None)if operation=='START_REPLACEMENT'else(
            '/v1.44/containers/'+cid+'/update',{'RestartPolicy':intent['restartPolicy']})
