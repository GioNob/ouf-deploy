"""Concrete signed one-Ingestion Ports. No login, key creation or Gateway writes."""
import copy
import time
from engine_creation import Engine
from tools.ingestion_readiness_patch_execution import contract as c,native_review,runtime_guard,human_reader
from tools.ingestion_readiness_patch_execution.runner import Ports
from tools.ingestion_readiness_patch_execution.engine_channel import NativeEngineChannel
from tools.ingestion_readiness_patch_execution.replacement import EngineReader,validate
from tools.ingestion_readiness_patch_execution.key import NativeKey
from tools.ingestion_readiness_patch_execution.lifecycle import NativeLifecycle
from tools.ingestion_readiness_patch_execution.image_import import NativeImageImport
from tools.ingestion_readiness_patch_execution.owner_read import OwnerNamespacePin,NativeOwnerRead
from tools.ingestion_readiness_patch_execution.database_read import NativeDatabaseRead
from tools.ingestion_readiness_patch_execution.readiness import NativeIngestionReadiness
from tools.ingestion_readiness_patch_execution.namespace import GatewayNamespacePin
from tools.ingestion_readiness_patch_execution.gateway_transport import NativeGatewayTransport,GatewayTransient
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.chatbot_file_cohort.human_session import HumanSession

class NativePorts(Ports):
    def __init__(self,action,journal,review,packet,human):
        c.require(type(action)is AggregateAction and type(journal)is Journal and type(human)is HumanSession,
                  'CONCRETE_SIGNED_PATCH_PORTS_REQUIRED')
        native_review.validate_review(review,packet)
        self.action,self.journal,self.human=action,journal,human
        self.review,self.packet=copy.deepcopy(review),copy.deepcopy(packet);self.scope=c.scope(review)
        human_reader.require_profile(human,review)
        c.require(str(journal.root)==review['executionContext'],'SAME_SIGNED_PATCH_CONTEXT_REQUIRED')
        self.indices={s['name']:i for i,s in enumerate(review['stages'])}
        self.engine=self.owner_pin=self.gateway=None;self.last_gates=None
    def current(self):
        c.require(c.scope(self.review)==self.scope and c.digest(self.packet)==self.review['packetBinding']['sha256'],
                  'PATCH_PORTS_REVIEW_OR_PACKET_DRIFT')
        self.action.guard(c.AUTHORITY_KEY,self.scope);human_reader.require_profile(self.human,self.review)
        c.require(self.human.current()==self.scope['humanBinding'],'SAME_CURRENT_AUTHENTICATED_HUMAN_REQUIRED')
        row=self.journal.read()
        c.require(row.get('scopeHash')==c.digest(self.scope)and row.get('authorityHash')==self.action.authority_hash
                  and row.get('budgetReset')is False,'SAME_PATCH_JOURNAL_REQUIRED')
        c.require(time.time()<row['expiresAt']and time.monotonic()<row['expiresMonotonic'],'CURRENT_PATCH_WINDOW_REQUIRED')
        return row
    def prepare(self):
        self.current()
        if self.engine is not None:return
        try:
            b=self.review['engineBinding'];self.engine=Engine(b['socketPath'],tuple(b['socketBinding']))
            self.channel=NativeEngineChannel(self.action,self.journal,self.review,self.human,self.engine)
            self.reader=EngineReader(self.engine);key=NativeKey(self.action,self.journal,self.review,self.human)
            self.lifecycle=NativeLifecycle(self.action,self.journal,self.review,self.packet,self.human,self.engine,key)
            self.image=NativeImageImport(self.action,self.journal,self.review,self.packet,self.human,self.reader)
            self.owner_pin=OwnerNamespacePin(self.reader,self.review['ownerControlProfile'])
            self.owner=NativeOwnerRead(self.action,self.journal,self.review,self.human,self.owner_pin)
            self.database=NativeDatabaseRead(self.action,self.journal,self.review,self.human,self.reader)
            self.readiness=NativeIngestionReadiness(self.lifecycle)
        except BaseException:self.close();raise
    def effect(self,row,name):
        i=self.indices[name]
        if len(row['effects'])<=i:return None
        e=row['effects'][i];s=self.review['stages'][i]
        c.require(e['stage']==name and e['intentHash']==s['intentHash'],'EXACT_PATCH_STAGE_HISTORY_REQUIRED')
        return e
    def restored(self,row,actual=None):
        e=self.effect(row,'ingestion.RESTORE_RESTART')
        return e is not None and (e['state']=='APPLIED' or (e['state']=='CLAIMED'
            and e.get('nativeRequestAttempted')is True and actual is not None
            and actual['HostConfig']['RestartPolicy']==self.packet['frames']['ingestion']['restoreRestartPolicy']))
    def generations(self):
        row=self.current();p=self.review['runtimeGuardProfile']
        for pin in p['unchangedApplications'].values():
            runtime_guard.unchanged(self.reader.container(pin['binding']['containerId']),pin)
        old_id=self.packet['expectedRuntimeBindings']['ingestion']['containerId']
        runtime_guard.predecessor('ingestion',self.reader.container(old_id),p,self.packet,self.review,row)
        create=self.effect(row,'ingestion.CREATE_REPLACEMENT')
        if create is None:return
        if create['state']=='APPLIED':c.require(create.get('nativeResource')is not None,'DURABLE_PATCH_CREATE_ID_REQUIRED')
        if not create.get('nativeResource'):return
        cid=create['nativeResource']['containerId'];actual=self.reader.container(cid)
        start=self.effect(row,'ingestion.START_REPLACEMENT');running=actual['State']['Running']is True
        if running:c.require(start is not None and (start['state']=='APPLIED'or start.get('nativeRequestAttempted')is True),
                             'NO_UNOWNED_PATCH_START_ALLOWED')
        process=None if start is None else start.get('nativeResource')
        if start is not None and start['state']=='APPLIED':c.require(process is not None,'DURABLE_PATCH_FIRST_PROCESS_REQUIRED')
        validate(self.packet['frames']['ingestion'],actual,self.packet['candidate']['imageConfig'],old_id,created_id=cid,
                 phase='RUNNING'if running else'CREATED',process=process,restart_restored=self.restored(row,actual))
    def routes(self):
        self.current()
        if self.gateway is None:
            pin=GatewayNamespacePin(self.reader,self.review['runtimeGuardProfile']['unchangedApplications']['gateway'])
            try:self.gateway=NativeGatewayTransport(self.action,self.journal,self.review,self.packet,self.human,pin)
            except BaseException:pin.close();raise
        self.gateway.check();return self.gateway.routes()
    def guard_current(self,stage):
        self.last_gates=None;self.current()
        c.require(stage==self.review['stages'][self.indices[stage['name']]],'EXACT_PATCH_STAGE_REQUIRED')
        self.prepare();self.generations()
        owner=self.owner.verify()
        try:routes=self.routes()
        except GatewayTransient as e:raise c.ReadTransient(e.retry_after_seconds) from None
        c.require(c.encoded(routes)==c.encoded(self.packet['routeDraft']['beforeRoutes']),
                  'UNCHANGED_COMPLETE_GATEWAY_ROUTE_MAP_REQUIRED')
        db=self.database.snapshot()  # Last remote gate; reads/HTTP cannot extend this timestamp.
        self.current();self.last_gates={'stage':stage['name'],'owner':owner,'database':db};self.fresh(stage)
    def fresh(self,stage):
        self.current();p=self.last_gates
        c.require(p is not None and p['stage']==stage['name'] and p['owner']['ownerActiveAndStrongEtagMatched']is True
            and p['database']['databaseReadPrerequisitesProven']is True
            and 0<=time.time()-p['database']['observedAtUnix']<=5,'FRESH_PATCH_HUMAN_OWNER_ROUTE_DATABASE_GATES_REQUIRED')
    def apply(self,stage):
        self.fresh(stage)
        try:
            if stage['name']=='IMPORT_INGESTION_IMAGE':self.image.apply()
            elif NativeLifecycle.handles(stage):self.lifecycle.apply(stage)
            else:c.require(False,'CLOSED_PATCH_EFFECT_REQUIRED')
        finally:self.last_gates=None
    def observe(self,stage):
        self.fresh(stage);name=stage['name']
        try:
            if name=='IMPORT_INGESTION_IMAGE':return self.image.observe()
            if NativeLifecycle.handles(stage):return self.lifecycle.observe(stage)
            if name=='VERIFY_CURRENT_GATES':return 'APPLIED',{'currentHumanOwnerDatabasePrerequisites':True,
                'unchangedGatewayRouteMapMatched':True,'databaseAdmissionProven':False}
            if name=='ingestion.READINESS':return self.readiness.observe()
            c.require(name in ('VERIFY_FINAL','VERIFY_RESTORED_FINAL'),'CLOSED_PATCH_OBSERVATION_REQUIRED')
            status,proof=self.readiness.observe()
            if status!='APPLIED':return status,proof
            self.guard_current(stage)
            return 'APPLIED',{'candidateFirstProcessReady':True,'validateOnlyFrameMatched':True,
                'currentOwnerAndDatabaseReadPrerequisites':True,'all82RoutesUnchanged':True,
                'databaseAdmissionProven':False,'releaseAcceptance':False}
        finally:self.last_gates=None
    def close(self):
        if self.gateway is not None:self.gateway.close();self.gateway=None
        if self.owner_pin is not None:self.owner_pin.close();self.owner_pin=None
        self.engine=None;self.last_gates=None
