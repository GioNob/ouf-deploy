"""Read-only application verification after the exact admitted release.

Health is not authorization or CSV acceptance. The reviewed image retains IAM,
consultation and THS; this phase proves its running generation, exact completed
Flyway history and bounded readiness response before other producers resume.
"""
import copy,http.client,ipaddress,json
from database_gate import Psql,identifier,GateDenied
from engine_creation import Engine
from native_evidence_store import NativeEvidenceStore
from transition_journal import digest,hash_value,require

PHASE='VERIFY_APPLICATION'

class ApplicationReadinessChannel:
    """Lazy local database channel and direct, bounded container health GET.

    The sealed checkpoint retains command custody. No connection to the
    application database is opened while it is fenced or during construction.
    No secrets, redirects, proxy environment or arbitrary SQL/URL are accepted.
    """
    def __init__(self,scope):
        fields={'databaseContainerId','databaseUser','database','databaseOid','flywaySchema','flywayHistoryHash','health'}
        require(type(scope) is dict and set(scope)==fields and hash_value(scope['databaseContainerId'])
                and type(scope['databaseOid']) is int and scope['databaseOid']>0 and hash_value(scope['flywayHistoryHash']),
                'EXACT_APPLICATION_READINESS_SCOPE_REQUIRED')
        identifier(scope['databaseUser']);identifier(scope['database'])
        require(scope['flywaySchema']=='ouf_sem','EXACT_REGISTRY_FLYWAY_SCHEMA_REQUIRED')
        h=scope['health'];require(type(h) is dict and set(h)=={'address','port','path','timeoutSeconds'},'EXACT_APPLICATION_HEALTH_SCOPE_REQUIRED')
        address=ipaddress.ip_address(h['address'])
        require(address.version==4 and address.is_private and not address.is_unspecified and not address.is_multicast
                and type(h['port']) is int and 1<=h['port']<=65535 and h['path'] in ('/actuator/health','/actuator/health/readiness')
                and type(h['timeoutSeconds']) is int and 1<=h['timeoutSeconds']<=5,'BOUNDED_DIRECT_APPLICATION_HEALTH_REQUIRED')
        self.scope=copy.deepcopy(scope);self.scope_hash=digest(scope)
    def exact(self):require(digest(self.scope)==self.scope_hash,'APPLICATION_READINESS_SCOPE_DRIFT')
    def database(self):
        self.exact();s=self.scope
        channel=Psql(s['databaseContainerId'],s['databaseUser'],s['database'],'ouf-cutover-readiness')
        try:
            value=channel.query("SELECT json_build_object('name',current_database(),'oid',oid::bigint,'allowConnections',datallowconn) FROM pg_database WHERE datname=current_database()",timeout=10)
            rows=channel.query("SELECT COALESCE(json_agg(json_build_object('version',version,'type',type,'script',script,'checksum',checksum,'success',success) ORDER BY installed_rank),'[]'::json) FROM "+identifier(s['flywaySchema'])+".flyway_schema_history",timeout=10)
        finally:channel.close()
        require(value=={'name':s['database'],'oid':s['databaseOid'],'allowConnections':True},'CURRENT_APPLICATION_DATABASE_IDENTITY_DRIFT')
        require(type(rows) is list and 1<=len(rows)<=256 and all(type(r) is dict and r.get('success') is True for r in rows)
                and digest(rows)==s['flywayHistoryHash'],'CURRENT_APPLICATION_MIGRATION_HISTORY_UNPROVEN')
        self.exact();return {'databaseScopeHash':digest(value),'flywayHistoryHash':digest(rows),'migrationCount':len(rows)}
    def health(self):
        self.exact();s=self.scope['health'];client=http.client.HTTPConnection(s['address'],s['port'],timeout=s['timeoutSeconds'])
        try:
            client.request('GET',s['path'],headers={'Accept':'application/json','Connection':'close'})
            reply=client.getresponse();raw=reply.read(65537)
            require(len(raw)<=65536,'BOUNDED_APPLICATION_HEALTH_RESPONSE_REQUIRED')
            if reply.status in (502,503,504):return None
            require(reply.status==200,'APPLICATION_HEALTH_HTTP_UNPROVEN')
            try:value=json.loads(raw)
            except ValueError:raise ValueError('APPLICATION_HEALTH_JSON_UNPROVEN') from None
            require(type(value) is dict and value.get('status')=='UP','APPLICATION_READINESS_NOT_UP')
            self.exact();return {'httpStatus':200,'status':'UP','responseHash':digest(value)}
        except (OSError,http.client.HTTPException):return None
        finally:client.close()

class ApplicationVerificationAdapter:
    def __init__(self,engine,transition,request,intent,store,channel,checkpoint):
        require(type(engine) is Engine and type(store) is NativeEvidenceStore
                and type(channel) is ApplicationReadinessChannel and callable(checkpoint),'TYPED_APPLICATION_VERIFICATION_CHANNELS_REQUIRED')
        self.engine,self.transition,self.store,self.channel,self.checkpoint=engine,transition,store,channel,checkpoint
        self.request=copy.deepcopy(request);self.request_hash=digest(request);self.intent=copy.deepcopy(intent);self.intent_hash=digest(intent)
        require(intent=={'creationRequestHash':self.request_hash,'readinessScopeHash':channel.scope_hash,
                         'priorReleaseEvidencePhase':'START_REPLACEMENT'},'EXACT_APPLICATION_VERIFICATION_INTENT_REQUIRED')
    def current(self,intent):
        require(digest(intent)==self.intent_hash and digest(self.intent)==self.intent_hash and digest(self.request)==self.request_hash
                and self.channel.scope_hash==self.intent['readinessScopeHash'],'APPLICATION_VERIFICATION_SCOPE_DRIFT')
        row=self.transition.read()
        require(row['state']=='IN_FLIGHT' and row['effects'][-1]['phase']==PHASE and row['effects'][-1]['intentHash']==self.intent_hash
                and row['creationRequestHash']==self.request_hash,'DURABLE_APPLICATION_VERIFICATION_BOUNDARY_REQUIRED')
        release=next(e for e in row['effects'] if e['phase']=='START_REPLACEMENT' and e['state']=='APPLIED')
        prior=self.store.read('START_REPLACEMENT',release['nativeEvidenceHash']);binding=prior.get('runtimeBinding',prior)
        actual=self.engine.matching_configuration(self.transition,self.request,self.engine.inspect(self.transition))
        require(self.engine.runtime_binding(actual)==binding and actual['State']['Running'] is True
                and actual['State']['Paused'] is False and actual['State']['Status']=='running' and actual.get('RestartCount')==0,
                'EXACT_RELEASED_APPLICATION_GENERATION_REQUIRED')
        networks=actual.get('NetworkSettings',{}).get('Networks',{})
        require(any(n.get('IPAddress')==self.channel.scope['health']['address'] for n in networks.values()),'HEALTH_ADDRESS_OUTSIDE_EXACT_REPLACEMENT')
        return binding
    def apply(self,intent):
        self.checkpoint('BEFORE_APPLICATION_VERIFICATION');self.current(intent)
    def observe(self,intent):
        self.checkpoint('BEFORE_APPLICATION_READINESS');before=self.current(intent)
        health=self.channel.health()
        if health is None:return 'UNKNOWN',{'applicationReadinessUnproven':True,'readOnlyReconciliationRequired':True,'dependentProducersRemainQuiesced':True}
        database=self.channel.database();self.checkpoint('AFTER_APPLICATION_READINESS')
        require(self.current(intent)==before and self.channel.health()==health
                and self.channel.database()==database,'APPLICATION_READINESS_CHANGED_DURING_VERIFICATION')
        evidence={'schema':'ouf.semantic-application-verified.v1','transitionContextHash':self.transition.context,
            'intentHash':self.intent_hash,'creationRequestHash':self.request_hash,'runtimeBinding':before,
            'readinessScopeHash':self.channel.scope_hash,'health':health,'database':database,
            'csvCycleProven':False,'releaseAcceptance':False}
        self.store.publish(PHASE,evidence);return 'APPLIED',evidence
