"""GET-only route baseline from the retained, still-running Gateway process.

This object can never become the replacement transport. Once the old process
stops the FD is unusable; only NativeGatewayTransport can bind the new runtime.
"""
import copy
import os
import iam_governance_intake as governance
from tools.ingestion_rollout_execution.contract import AUTHORITY_KEY,require,scope,digest
from tools.ingestion_rollout_execution.replacement import EngineReader
from tools.ingestion_rollout_execution.namespace import identity
from tools.ingestion_rollout_execution import runtime_guard
from tools.ingestion_rollout_execution.gateway_transport import NativeGatewayTransport,validate_profile
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.chatbot_file_cohort.human_session import HumanSession

class RetainedGatewayPin:
    def __init__(self,reader,profile,packet,review,journal,binding):
        require(type(reader)is EngineReader and type(journal)is Journal,'EXACT_RETAINED_GATEWAY_READER_AND_JOURNAL_REQUIRED')
        runtime_guard.validate_profile(profile,packet)
        require(type(binding)is dict and set(binding)=={'device','inode'}and all(type(v)is int and v>0 for v in binding.values()),
                'EXPLICIT_RETAINED_GATEWAY_NAMESPACE_REQUIRED')
        self.reader,self.journal=reader,journal
        self.runtime_profile,self.packet,self.review,self.binding=map(copy.deepcopy,(profile,packet,review,binding));self.fd=None
        try:
            self.check();self.fd=os.open(self.path,os.O_RDONLY|os.O_CLOEXEC)
            require(identity(os.fstat(self.fd))==self.binding,'RETAINED_GATEWAY_NAMESPACE_FD_CHANGED');self.check()
        except BaseException:self.close();raise
    @property
    def path(self):return '/proc/'+str(self.runtime_profile['beforeContainers']['gateway']['State']['Pid'])+'/ns/net'
    def check(self):
        cid=self.packet['expectedRuntimeBindings']['gateway']['containerId'];actual=self.reader.container(cid)
        proof=runtime_guard.predecessor('gateway',actual,self.runtime_profile,self.packet,self.review,self.journal.read())
        require(proof['stopped']is False,'STOPPED_GATEWAY_NAMESPACE_CANNOT_BE_USED')
        require(identity(os.stat(self.path))==self.binding,'RETAINED_GATEWAY_PROCESS_NAMESPACE_CHANGED')
        if self.fd is not None:require(identity(os.fstat(self.fd))==self.binding,'RETAINED_GATEWAY_HELD_FD_CHANGED')
    def close(self):
        if self.fd is not None:os.close(self.fd);self.fd=None

class RetainedGatewayMap:
    def __init__(self,action,journal,review,packet,human,reader):
        require(type(action)is AggregateAction and type(journal)is Journal and type(human)is HumanSession
                and type(reader)is EngineReader,'CONCRETE_SIGNED_RETAINED_GATEWAY_COMPONENTS_REQUIRED')
        self.action,self.journal,self.human=action,journal,human
        self.review,self.packet=copy.deepcopy(review),copy.deepcopy(packet);self.scope=scope(self.review)
        self.profile=copy.deepcopy(review.get('retainedGatewayTransportProfile'));validate_profile(self.profile)
        require(digest(packet)==review['packetBinding']['sha256']and str(journal.root)==review['executionContext']
                and review.get('maximumGatewayGetAttempts')==512
                and {k:self.profile['config'][k]for k in('path','sha256','metadata')}==packet['gatewayConfigBefore'],
                'SAME_SIGNED_RETAINED_GATEWAY_CONFIG_AND_READ_BUDGET_REQUIRED')
        self.action.guard(AUTHORITY_KEY,self.scope)
        require(human.current()==self.scope['humanBinding'],'SAME_CURRENT_AUTHENTICATED_HUMAN_REQUIRED')
        self.pin=RetainedGatewayPin(reader,review['runtimeGuardProfile'],packet,review,journal,review['retainedGatewayNamespace'])
        try:self.check()
        except BaseException:self.close();raise
    def check(self):
        require(scope(self.review)==self.scope and self.profile==self.review['retainedGatewayTransportProfile']
                and digest(self.packet)==self.review['packetBinding']['sha256']
                and self.pin.runtime_profile==self.review['runtimeGuardProfile']
                and self.pin.binding==self.review['retainedGatewayNamespace']and self.pin.fd is not None,
                'RETAINED_GATEWAY_TRANSPORT_REVIEW_OR_FD_DRIFT')
        self.action.guard(AUTHORITY_KEY,self.scope)
        require(self.human.current()==self.scope['humanBinding'],'SAME_CURRENT_AUTHENTICATED_HUMAN_REQUIRED')
        row=self.journal.read();count=row.get('nativeGatewayGetAttempts',0)
        require(row.get('scopeHash')==digest(self.scope)and row.get('authorityHash')==self.action.authority_hash
                and row.get('budgetReset')is False and type(count)is int and 0<=count<=512,
                'SAME_PERSISTENT_RETAINED_GATEWAY_READ_BUDGET_REQUIRED')
        require(self.profile['pythonExecutable']==governance.executable(self.profile['pythonExecutable']['path']),
                'RETAINED_GATEWAY_NAMESPACE_PROGRAM_CHANGED')
        self.pin.check()
    def reserve_get(self):return NativeGatewayTransport.reserve_get(self)
    def _request(self,method,resource,body=None):
        require(method=='GET'and resource=='/apisix/admin/routes'and body is None,
                'RETAINED_GATEWAY_MAP_IS_GET_ONLY')
        return NativeGatewayTransport._request(self,method,resource,body)
    def routes(self):return NativeGatewayTransport.routes(self)
    def close(self):self.pin.close()
