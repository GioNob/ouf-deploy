"""Explicit local native Ports composition; not an executable or an issuer.

No discovery, login, refresh, migration, owner writes or predecessor replay.
Representative Docker/APISIX/JVM/DB qualification remains a release gate.
"""
import copy
import os
import time
from engine_creation import Engine
from tools.ingestion_rollout_execution import contract as c,native_review,runtime_guard
from tools.ingestion_rollout_execution.runner import Ports
from tools.ingestion_rollout_execution.engine_channel import NativeEngineChannel
from tools.ingestion_rollout_execution.replacement import EngineReader,validate
from tools.ingestion_rollout_execution.key import NativeKey
from tools.ingestion_rollout_execution.lifecycle import NativeLifecycle
from tools.ingestion_rollout_execution.image_import import NativeImageImport
from tools.ingestion_rollout_execution.owner_read import OwnerNamespacePin,NativeOwnerRead
from tools.ingestion_rollout_execution.database_read import NativeDatabaseRead
from tools.ingestion_rollout_execution.readiness import NativeIngestionReadiness
from tools.ingestion_rollout_execution.retained_gateway import RetainedGatewayMap
from tools.ingestion_rollout_execution.namespace import GatewayNamespacePin,identity
from tools.ingestion_rollout_execution.gateway_transport import NativeGatewayTransport,GatewayTransient
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.chatbot_file_cohort.human_session import HumanSession

class NativePorts(Ports):
    def __init__(self,action,journal,review,packet,human):
        c.require(type(action)is AggregateAction and type(journal)is Journal and type(human)is HumanSession,
                  'CONCRETE_SIGNED_NATIVE_PORTS_REQUIRED')
        native_review.validate_review(review,packet)
        self.action,self.journal,self.human=action,journal,human
        self.review,self.packet=copy.deepcopy(review),copy.deepcopy(packet);self.scope=c.scope(self.review)
        c.require(str(journal.root)==review['executionContext'],'SAME_SIGNED_NATIVE_PORTS_CONTEXT_REQUIRED')
        self.indices={s['name']:i for i,s in enumerate(review['stages'])}
        self.engine=self.owner_pin=self.gateway=None;self.last_gates=None

    def current(self):
        c.require(c.scope(self.review)==self.scope and c.digest(self.packet)==self.review['packetBinding']['sha256'],
                  'NATIVE_PORTS_REVIEW_OR_PACKET_DRIFT')
        self.action.guard(c.AUTHORITY_KEY,self.scope)
        c.require(self.human.current()==self.scope['humanBinding'],'SAME_CURRENT_AUTHENTICATED_HUMAN_REQUIRED')
        row=self.journal.read()
        c.require(row.get('scopeHash')==c.digest(self.scope)and row.get('authorityHash')==self.action.authority_hash
                  and row.get('budgetReset')is False,'SAME_NATIVE_PORTS_JOURNAL_REQUIRED')
        c.require(time.time()<row['expiresAt']and time.monotonic()<row['expiresMonotonic'],
                  'CURRENT_NATIVE_PORTS_WINDOW_REQUIRED')
        return row

    def prepare(self):
        self.current()
        if self.engine is not None:return
        try:
            binding=self.review['engineBinding'];self.engine=Engine(binding['socketPath'],tuple(binding['socketBinding']))
            self.channel=NativeEngineChannel(self.action,self.journal,self.review,self.human,self.engine)
            self.reader=EngineReader(self.engine)
            self.key=NativeKey(self.action,self.journal,self.review,self.human)
            self.lifecycle=NativeLifecycle(self.action,self.journal,self.review,self.packet,self.human,self.engine,self.key)
            self.image=NativeImageImport(self.action,self.journal,self.review,self.packet,self.human,self.reader)
            self.owner_pin=OwnerNamespacePin(self.reader,self.review['ownerControlProfile'])
            self.owner=NativeOwnerRead(self.action,self.journal,self.review,self.human,self.owner_pin)
            self.database=NativeDatabaseRead(self.action,self.journal,self.review,self.human,self.reader)
            self.readiness=NativeIngestionReadiness(self.lifecycle)
        except BaseException:self.close();raise

    def effect(self,row,name):
        i=self.indices[name]
        if len(row['effects'])<=i:return None
        effect=row['effects'][i];stage=self.review['stages'][i]
        c.require(effect['stage']==name and effect['intentHash']==stage['intentHash'],
                  'EXACT_NATIVE_PORTS_STAGE_HISTORY_REQUIRED')
        return effect

    def restored(self,row,module,actual=None):
        effect=self.effect(row,module+'.RESTORE_RESTART')
        if effect is None:return False
        if effect['state']=='APPLIED':return True
        return (effect['state']=='CLAIMED'and effect.get('nativeRequestAttempted')is True
                and actual is not None and actual['HostConfig']['RestartPolicy']==self.packet['frames'][module]['restoreRestartPolicy'])

    def generations(self):
        row=self.current();profile=self.review['runtimeGuardProfile']
        for pin in profile['unchangedApplications'].values():
            runtime_guard.unchanged(self.reader.container(pin['binding']['containerId']),pin)
        for module in('ingestion','gateway'):
            before=self.reader.container(self.packet['expectedRuntimeBindings'][module]['containerId'])
            runtime_guard.predecessor(module,before,profile,self.packet,self.review,row)
            create=self.effect(row,module+'.CREATE_REPLACEMENT')
            if create is not None and create['state']=='APPLIED':
                c.require(create.get('nativeResource')is not None,'APPLIED_CREATE_WITHOUT_DURABLE_ID')
            if create is None or not create.get('nativeResource'):continue
            cid=create['nativeResource'].get('containerId');actual=self.reader.container(cid)
            start=self.effect(row,module+'.START_REPLACEMENT');running=actual['State']['Running']is True
            if running:
                c.require(start is not None and (start['state']=='APPLIED'or start.get('nativeRequestAttempted')is True),
                          'NO_UNOWNED_REPLACEMENT_START_ALLOWED')
            process=None if start is None else start.get('nativeResource')
            if start is not None and start['state']=='APPLIED':
                c.require(process is not None,'APPLIED_START_WITHOUT_DURABLE_FIRST_PROCESS')
            validate(self.packet['frames'][module],actual,self.lifecycle.image_config(module),
                self.packet['expectedRuntimeBindings'][module]['containerId'],created_id=cid,
                phase='RUNNING'if running else'CREATED',process=process,
                restart_restored=self.restored(row,module,actual),resolved_owner_key=self.lifecycle.key_value(module))

    def guard_current(self,stage):
        self.last_gates=None
        self.current();c.require(stage==self.review['stages'][self.indices[stage['name']]],'EXACT_NATIVE_PORTS_STAGE_REQUIRED')
        self.prepare();self.generations()
        owner=self.owner.verify()
        database=self.database.snapshot()  # Last remote gate: freshness is not extended by prior probes.
        self.current()
        self.last_gates={'stage':stage['name'],'owner':owner,'database':database}
        self.fresh(stage)

    def fresh(self,stage):
        self.current();proof=self.last_gates
        c.require(proof is not None and proof['stage']==stage['name']
                  and proof['owner']['ownerActiveAndStrongEtagMatched']is True
                  and proof['database']['databaseReadPrerequisitesProven']is True
                  and 0<=time.time()-proof['database']['observedAtUnix']<=5,
                  'FRESH_COMPOSED_HUMAN_OWNER_DATABASE_GATES_REQUIRED')

    def new_gateway(self):
        self.current();row=self.journal.read();process=self.lifecycle.process('gateway')
        c.require(process is not None,'DURABLE_NEW_GATEWAY_PROCESS_REQUIRED')
        actual=self.reader.container(self.lifecycle.created('gateway'));restored=self.restored(row,'gateway',actual)
        if self.gateway is not None and self.gateway.pin.restored!=restored:
            self.gateway.pin.close();self.gateway=None
        if self.gateway is not None:self.gateway.check();return self.gateway
        selected='/proc/'+str(process['pid'])+'/ns/net';binding=identity(os.stat(selected))
        rebind=self.effect(row,'REBIND_GATEWAY_TRANSPORT')
        if rebind is not None and rebind.get('nativeResource'):
            c.require(rebind['nativeResource']=={'containerId':self.lifecycle.created('gateway'),
                'process':process,'namespace':binding},'REBOUND_GATEWAY_NAMESPACE_GENERATION_CHANGED')
        pin=GatewayNamespacePin(self.reader,self.packet['frames']['gateway'],self.lifecycle.image_config('gateway'),
            self.packet['expectedRuntimeBindings']['gateway']['containerId'],self.lifecycle.created('gateway'),
            process,binding,self.review['retainedGatewayNamespace'],
            resolved_owner_key=self.key.read_for_gateway(),restart_restored=restored)
        try:self.gateway=NativeGatewayTransport(self.action,self.journal,self.review,self.packet,self.human,pin)
        except BaseException:pin.close();raise
        return self.gateway

    def apply(self,stage):
        self.fresh(stage)
        try:
            if stage['name']=='CREATE_DEDICATED_KEY':self.key.create()
            elif stage['name']=='IMPORT_INGESTION_IMAGE':self.image.apply()
            elif NativeLifecycle.handles(stage):self.lifecycle.apply(stage)
            elif stage['name'].startswith('PUT_ROUTE.'):self.new_gateway().put(stage)
            else:c.require(False,'CLOSED_NATIVE_PORTS_EFFECT_REQUIRED')
        finally:self.last_gates=None

    def observe(self,stage):
        self.fresh(stage);name=stage['name']
        try:
            if name=='CREATE_DEDICATED_KEY':return self.key.observe()
            if name=='IMPORT_INGESTION_IMAGE':return self.image.observe()
            if NativeLifecycle.handles(stage):return self.lifecycle.observe(stage)
            if name=='VERIFY_CURRENT_GATES':
                retained=RetainedGatewayMap(self.action,self.journal,self.review,self.packet,self.human,self.reader)
                try:c.require(retained.routes()==self.packet['routeDraft']['beforeRoutes'],'RETAINED_COMPLETE_ROUTE_BASELINE_CHANGED')
                finally:retained.close()
                return 'APPLIED',{'currentHumanOwnerAndDatabaseReadPrerequisites':True,'retained82RoutesMatched':True,
                    'databaseAdmissionProven':False,'startupProofPending':True}
            if name=='ingestion.READINESS':return self.readiness.observe()
            if name=='gateway.READINESS':
                c.require(self.new_gateway().routes()==self.packet['routeDraft']['beforeRoutes'],'NEW_GATEWAY_BASELINE_ROUTES_CHANGED')
                return 'APPLIED',{'newGatewayAdminReady':True,'all82BaselineRoutesMatched':True}
            if name=='REBIND_GATEWAY_TRANSPORT':
                gateway=self.new_gateway();proof=gateway.pin.check();row=self.current()
                i=self.indices[name];c.require(row['nextStage']==i and len(row['effects'])==i+1,
                                               'DURABLE_REBIND_READ_CLAIM_REQUIRED')
                resource={'containerId':gateway.pin.created_id,'process':gateway.pin.process,'namespace':gateway.pin.binding}
                old=row['effects'][i].get('nativeResource')
                c.require(old is None or old==resource,'RETAINED_REBIND_RESOURCE_CHANGED')
                if old is None:
                    effects=copy.deepcopy(row['effects']);effects[i]['nativeResource']=copy.deepcopy(resource)
                    self.journal.compare_and_save(row,{**row,'effects':effects,'version':row['version']+1})
                return 'APPLIED',proof
            if name.startswith(('PUT_ROUTE.','READ_ROUTE.'))or name=='VERIFY_REBOUND_ROUTE_MAP':
                return self.new_gateway().observe(stage)
            c.require(name in('VERIFY_FINAL','VERIFY_RESTORED_FINAL'),'CLOSED_NATIVE_PORTS_OBSERVATION_REQUIRED')
            status,proof=self.readiness.observe()
            if status!='APPLIED':return status,proof
            c.require(self.new_gateway().routes()==self.packet['routeDraft']['afterRoutes'],'FINAL_COMPLETE_ROUTE_MAP_CHANGED')
            # Refresh after readiness and route I/O; no stale snapshot is promoted.
            self.guard_current(stage);self.generations();self.fresh(stage)
            return 'APPLIED',{'candidateFirstProcessReady':True,'validateOnlyFrameMatched':True,
                'currentOwnerAndDatabaseReadPrerequisites':True,'all82RoutesMatched':True,'other80RoutesPreserved':True,
                'databaseAdmissionProven':True,'runtimeStartupMigrationPolicyProven':True,'releaseAcceptance':False}
        except GatewayTransient as error:
            return 'TRANSIENT',{'retryAfterSeconds':error.retry_after_seconds}

    def close(self):
        if self.gateway is not None:self.gateway.pin.close();self.gateway=None
        if self.owner_pin is not None:self.owner_pin.close();self.owner_pin=None
        self.engine=None;self.last_gates=None
