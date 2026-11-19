"""Current PostgreSQL/image prerequisites through one readonly native session.

No grant, migration, fence, database reopening or credential acquisition. The
approved Docker executable uses the exact Engine socket explicitly; ambient
Docker contexts and client credentials never select the server.
"""
import copy,json,os,subprocess,tempfile
from .core import require,digest,encoded
from .lifecycle import Lifecycle
from .read_budget import ReadBudget
from application_verification_adapter import ApplicationReadinessChannel
from database_gate import identifier
from image_custody import loaded
from tools.ingestion_readiness_patch_execution import private_file,runtime_guard

def database_scope(lifecycle,readiness,postgres,program,image_audit):
    return {'schema':'ouf.semantic-registry-recovery-database-scope.v1',
        'planHash':digest(lifecycle.plan),'readinessScopeHash':digest(readiness),
        'postgresRuntimeHash':digest(postgres),'dockerProgramHash':digest(program),
        'engineBindingHash':digest({'socketPath':lifecycle.engine.path,'socketBinding':list(lifecycle.engine.binding)}),
        'imageAuditHash':digest(image_audit),'readOnlyTransactionRequired':True,
        'databaseMutationAllowed':False,'credentialAcquisitionAllowed':False}

class CurrentDatabase:
    def __init__(self,lifecycle,readiness,postgres,program,image_audit,budget):
        require(type(lifecycle) is Lifecycle and type(budget) is ReadBudget
            and budget.store is lifecycle.store and budget.authority is lifecycle.authority,
            'ACTUAL_RECOVERY_DATABASE_LIFECYCLE_AND_BUDGET_REQUIRED')
        self.lifecycle,self.budget=lifecycle,budget
        self.readiness,self.postgres,self.program,self.image_audit=map(copy.deepcopy,(readiness,postgres,program,image_audit))
        self.channel=ApplicationReadinessChannel(readiness)
        require(set(postgres)=={'binding','bindingProfile','restartCount'}
            and postgres['binding']['containerId']==readiness['databaseContainerId'],
            'SAME_CURRENT_POSTGRES_AND_READINESS_SCOPE_REQUIRED')
        private_file.validate(program,maximum=67108864)
        require(program['metadata'][2]==0 and program['metadata'][4]&0o111,
            'ROOT_CONTROLLED_DOCKER_PROGRAM_REQUIRED')
        self.scope=database_scope(lifecycle,readiness,postgres,program,image_audit)
        self.guard()

    def guard(self):
        row=self.lifecycle.journal()
        require(database_scope(self.lifecycle,self.readiness,self.postgres,self.program,self.image_audit)==self.scope
            and self.channel.scope==self.readiness
            and json.loads(self.lifecycle.authority.raw).get('semanticRegistryRecoveryDatabase')==self.scope,
            'CURRENT_SIGNED_RECOVERY_DATABASE_SCOPE_REQUIRED')
        self.lifecycle.engine.check_socket()
        # File contents/custody are checked without invoking a CLI/config hook.
        with private_file.opened(self.program,maximum=67108864):pass
        status,actual=self.lifecycle.engine.request('GET','/v1.44/containers/'+self.readiness['databaseContainerId']+'/json')
        require(status==200,'CURRENT_POSTGRES_INSPECTION_REQUIRED')
        runtime_guard.unchanged(actual,self.postgres)
        status,image=self.lifecycle.engine.request('GET','/v1.44/images/'+self.lifecycle.request['Image']+'/json')
        require(status==200,'CURRENT_REVIEWED_REGISTRY_IMAGE_REQUIRED')
        loaded(self.image_audit,image)
        require(self.lifecycle.journal()==row,'RECOVERY_DATABASE_GUARD_HISTORY_CHANGED')
        return row

    def snapshot(self):
        before=self.guard();s=self.readiness
        # Closed source SQL; the only interpolated identifier is validated.
        sql=("SELECT json_build_object('database',current_database(),'databaseOid',d.oid::bigint,"
            "'allowConnections',d.datallowconn,'role',current_user,"
            "'transactionReadOnly',current_setting('transaction_read_only')='on',"
            "'history',(SELECT COALESCE(json_agg(json_build_object('version',version,'type',type,"
            "'script',script,'checksum',checksum,'success',success) ORDER BY installed_rank),'[]'::json) FROM "
            +identifier(s['flywaySchema'])+".flyway_schema_history)) FROM pg_database d WHERE d.datname=current_database();")
        self.budget.reserve('databaseSessions')
        with tempfile.TemporaryDirectory(prefix='ouf-recovery-readonly-pg-') as empty_config, tempfile.TemporaryFile() as output:
            argv=[self.program['path'],'--host','unix://'+self.lifecycle.engine.path,'--config',empty_config,
                'exec','-i',s['databaseContainerId'],'env','PGAPPNAME=ouf-cutover-recovery-readiness',
                'PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=10000 -c lock_timeout=3000',
                'psql','-X','-q','-A','-t','--single-transaction','-v','ON_ERROR_STOP=1',
                '-U',s['databaseUser'],'-d',s['database'],'-c',sql]
            try:
                result=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.DEVNULL,
                    timeout=15,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},cwd='/')
            except (OSError,subprocess.TimeoutExpired):
                require(False,'CURRENT_READONLY_POSTGRES_SESSION_UNCONFIRMED')
            output.seek(0);raw=output.read(262145)
        require(result.returncode==0 and 0<len(raw)<=262144,'CURRENT_READONLY_POSTGRES_SESSION_UNCONFIRMED')
        def unique(pairs):
            value={}
            for k,v in pairs:require(k not in value,'DUPLICATE_POSTGRES_RESULT_KEY');value[k]=v
            return value
        try:value=json.loads(raw,object_pairs_hook=unique)
        except (ValueError,UnicodeError):require(False,'READONLY_POSTGRES_JSON_UNCONFIRMED')
        require(type(value) is dict and set(value)=={'database','databaseOid','allowConnections','role','transactionReadOnly','history'}
            and value['database']==s['database'] and value['databaseOid']==s['databaseOid']
            and value['role']==s['databaseUser'] and value['allowConnections'] is True
            and value['transactionReadOnly'] is True,'CURRENT_READONLY_DATABASE_IDENTITY_REQUIRED')
        history=value['history']
        require(type(history) is list and 1<=len(history)<=256
            and all(type(r) is dict and r.get('success') is True for r in history)
            and digest(history)==s['flywayHistoryHash'],'CURRENT_RECOVERY_FLYWAY_HISTORY_CHANGED')
        require(self.guard()==before,'RECOVERY_DATABASE_CHANGED_DURING_READONLY_SESSION')
        return {'schema':'ouf.semantic-registry-recovery-current-database.v1',
            'databaseScopeHash':digest(self.scope),'resultHash':digest(value),
            'flywayHistoryHash':digest(history),'migrationCount':len(history),
            'databaseIdentityProven':True,'transactionReadOnly':True,'databaseMutations':0}
