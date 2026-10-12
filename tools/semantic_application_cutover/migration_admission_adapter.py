"""Explicit one-use admission under a source-bound migration authority.

Sealed checkpoints additionally prove inventoried producers stay quiescent,
complete attested paused OCI/peer, distinct current lease/transport and exclusive
DB access for that workload. ALLOW_CONNECTIONS alone proves none of those gates.
No automatic reopen/retry, schema migration, restore or producer restart.
"""
import json
from database_gate import digest,identifier,literal,require
from database_channel_scope import verify_admin

class MigrationAdmissionAdapter:
    def __init__(self,admin,engine,transition,intent,store):
        self.admin,self.engine,self.transition,self.store=admin,engine,transition,store
        self.intent=json.loads(json.dumps(intent,allow_nan=False))
        require(set(self.intent)=={'containerId','user','database','databaseOid','priorBackupEvidencePhase','priorPausedEvidencePhase'},'EXACT_MIGRATION_ADMISSION_INTENT_REQUIRED')
        require(type(self.intent['databaseOid']) is int and self.intent['databaseOid']>0
                and self.intent['priorBackupEvidencePhase']=='FENCED_BACKUP'
                and self.intent['priorPausedEvidencePhase']=='STAGE_PAUSED_REPLACEMENT','EXACT_SCOPED_ADMISSION_REFERENCES_REQUIRED')
        self.intent_hash=digest(self.intent)
    def exact(self,intent):
        require(digest(intent)==self.intent_hash,'IMMUTABLE_MIGRATION_ADMISSION_INTENT_REQUIRED')
        verify_admin(self.admin,self.intent['containerId'],self.intent['user'],self.intent['database'])
        row=self.transition.read()
        require(row['state']=='IN_FLIGHT' and row['effects'][-1]['phase']=='ADMIT_MIGRATION'
                and row['effects'][-1]['intentHash']==self.intent_hash and row['databaseMayHaveChanged'] is True,'DURABLE_MIGRATION_BOUNDARY_REQUIRED')
        for phase in ('FENCED_BACKUP','STAGE_PAUSED_REPLACEMENT','ATTEST_NEW_OCI_PEER','INSTALL_AUTHENTICATED_TRANSPORT','START_DISTINCT_LEASE_WORKER'):
            require(any(e['phase']==phase and e['state']=='APPLIED' for e in row['effects']),'APPLIED_MIGRATION_PREREQUISITE_REQUIRED')
        backup=next(e for e in row['effects'] if e['phase']=='FENCED_BACKUP')
        record=self.store.read('FENCED_BACKUP',backup['nativeEvidenceHash'])
        scope=digest({'name':self.intent['database'],'oid':self.intent['databaseOid']})
        require(record.get('schema')=='ouf.semantic-fenced-backup-executor-evidence.v1' and record.get('transitionContextHash')==self.transition.context
                and record.get('databaseContainerId')==self.intent['containerId'] and record.get('databaseScopeHash')==scope
                and record.get('currentDatabaseState')=={'oid':self.intent['databaseOid'],'closed':True,'prepared':0,'sessions':0},'EXACT_FRESH_FENCED_BACKUP_SCOPE_REQUIRED')
        return row
    def paused(self,row):
        effect=next(e for e in row['effects'] if e['phase']=='STAGE_PAUSED_REPLACEMENT')
        native=self.store.read('STAGE_PAUSED_REPLACEMENT',effect['nativeEvidenceHash'])
        actual=self.engine.inspect(self.transition)
        require(type(actual) is dict and self.engine.runtime_binding(actual)==self.engine.runtime_binding(native)
                and actual['State']['Running'] is True and actual['State']['Paused'] is True and actual['State']['Status']=='paused','EXACT_PAUSED_WORKLOAD_BEFORE_MIGRATION_ADMISSION_REQUIRED')
        return self.engine.runtime_binding(actual)
    def state(self):
        db=self.intent['database'];oid=self.intent['databaseOid']
        value=self.admin.query("SELECT json_build_object('oid',oid::bigint,'allowConnections',datallowconn,'prepared',(SELECT count(*) FROM pg_prepared_xacts WHERE database="+literal(db)+"),'sessions',(SELECT count(*) FROM pg_stat_activity WHERE datid="+str(oid)+")) FROM pg_database WHERE datname="+literal(db),"SELECT pg_stat_clear_snapshot();")
        require(type(value) is dict and value.get('oid')==oid and value.get('prepared')==0 and value.get('sessions')==0,'CURRENT_EXCLUSIVE_DATABASE_ADMISSION_SCOPE_REQUIRED')
        return value
    def apply(self,intent):
        row=self.exact(intent);self.paused(row);state=self.state()
        require(state['allowConnections'] is False,'DATABASE_ADMISSION_ALREADY_CHANGED_RECONCILE_REQUIRED')
        self.admin.query('true','ALTER DATABASE '+identifier(self.intent['database'])+' ALLOW_CONNECTIONS true;')
    def observe(self,intent):
        row=self.exact(intent);paused=self.paused(row);before=self.state()
        if before['allowConnections'] is not True:return 'UNKNOWN',{'migrationAdmissionUnproven':True,'openReplayAllowed':False,'preMigrationRestoreAllowed':False}
        require(before==self.state() and paused==self.paused(row),'MIGRATION_ADMISSION_OR_PAUSED_GENERATION_CHANGED_DURING_READ')
        evidence={'schema':'ouf.semantic-explicit-migration-admission.v1','transitionContextHash':self.transition.context,
                'intentHash':self.intent_hash,'databaseScopeHash':digest({'name':self.intent['database'],'oid':self.intent['databaseOid']}),
                'currentDatabaseState':before,'pausedWorkloadBinding':paused,'databaseMayHaveChanged':True,
                'automaticReopen':False,'restorePerformed':False,'preMigrationRestoreAllowed':False}
        self.store.publish('ADMIT_MIGRATION',evidence)
        return 'APPLIED',evidence
