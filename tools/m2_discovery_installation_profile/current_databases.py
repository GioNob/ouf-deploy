"""Bounded read-only current schemas from four reviewed migration artifacts.

The parent-bound runtime inputs v2 bind this independent input hash. Fixed SQL
reads the exact current database identity/history in READ ONLY transactions.
No backup, migration, grant, restore, source publication or full admission occurs.
Artifact provenance must be qualified separately by the sealed controller.
"""
import copy,os,re,shutil
from pathlib import Path
from .custody_capture import digest,encoded,require
from .current_cohort import CurrentCohortRuntime,CurrentCohortEngine,INPUT_SCHEMA_V2,validate_inputs
from .node_owner import ObservationBudget
from .private_review import absolute,hashed
from tools.semantic_provider_deployment_authentication import attributes,ancestors
from tools.semantic_target_review.prepare_application_runtime_inputs import file_bytes
from tools.chatbot_file_cohort.databases import MODULES,SCHEMAS,java_migrations,mcp_migrations
from database_gate import Psql,identifier
from engine_creation import Engine

SCHEMA='ouf.discovery-current-database-inputs.v1'


def validate(inputs):
    fields={'schema','sourceClosureHash','installationInputsHash','desiredProfileHash','cohortManifestHash',
        'postgresRuntimeBinding','dockerBinding','modules'}
    require(type(inputs) is dict and set(inputs)==fields and inputs['schema']==SCHEMA
        and all(hashed(inputs[k]) for k in ('sourceClosureHash','installationInputsHash','desiredProfileHash','cohortManifestHash'))
        and len(encoded(inputs))<=131072,'EXACT_CURRENT_DATABASE_INPUTS_REQUIRED')
    docker=inputs['dockerBinding'];require(type(docker) is dict and set(docker)=={'path','sha256'}
        and hashed(docker['sha256']),'PINNED_CURRENT_DATABASE_DOCKER_REQUIRED');absolute(docker['path'])
    rows=inputs['modules'];require(type(rows) is list and [v.get('module') for v in rows]==list(MODULES),
        'FOUR_EXACT_CURRENT_DATABASE_MODULES_REQUIRED')
    databases=set()
    for row in rows:
        require(type(row) is dict and set(row)=={'module','database','user','databaseOid','expectedMigrations','artifact'}
            and type(row['databaseOid']) is int and row['databaseOid']>0
            and type(row['expectedMigrations']) is list and 1<=len(row['expectedMigrations'])<=256,
            'EXACT_CURRENT_DATABASE_IDENTITY_AND_MIGRATIONS_REQUIRED')
        identifier(row['database']);identifier(row['user']);databases.add(row['database'])
        artifact=row['artifact'];require(type(artifact) is dict and set(artifact)=={'format','root','files'}
            and artifact['format']==('MCP_SQL' if row['module']=='mcp' else 'JAR')
            and type(artifact['files']) is list and 1<=len(artifact['files'])<=256,
            'EXACT_CURRENT_DATABASE_MIGRATION_ARTIFACT_REQUIRED');absolute(artifact['root'])
        selected=set()
        for ref in artifact['files']:
            require(type(ref) is dict and set(ref)=={'path','sha256','maximumBytes'} and hashed(ref['sha256'])
                and type(ref['maximumBytes']) is int and 0<ref['maximumBytes']<=(268435456 if artifact['format']=='JAR' else 1048576),
                'EXACT_CURRENT_DATABASE_MIGRATION_SOURCE_BINDING_REQUIRED')
            path=absolute(ref['path']);selected.add(str(path))
            if artifact['format']=='MCP_SQL':
                require(path.parent==Path(artifact['root'])/'internal/adapter/postgres/migrations'
                    and re.fullmatch('[0-9]{3}_[a-z0-9_]+[.]sql',path.name),'EXACT_CURRENT_MCP_MIGRATION_FILE_REQUIRED')
        require(len(selected)==len(artifact['files']) and (artifact['format']!='JAR'
            or len(selected)==1 and selected=={artifact['root']}),'EXACT_CURRENT_MIGRATION_SOURCE_SET_REQUIRED')
    require(len(databases)==4,'FOUR_DISTINCT_CURRENT_DATABASES_REQUIRED')
    return digest(inputs)


def bind_database_inputs(runtime_inputs,inputs):
    validate_inputs(runtime_inputs);sha=validate(inputs)
    require(all(runtime_inputs[k]==inputs[k] for k in ('sourceClosureHash','installationInputsHash','desiredProfileHash','cohortManifestHash'))
        and runtime_inputs['peers']['postgres']['runtimeBinding']==inputs['postgresRuntimeBinding'],
        'SAME_CURRENT_COHORT_AND_DATABASE_INPUTS_REQUIRED')
    result=copy.deepcopy(runtime_inputs);extra=result.setdefault('additionalInputsHashes',{})
    require('databases' not in extra or extra['databases']==sha,'CURRENT_DATABASE_INPUT_BINDING_CANNOT_BE_REPLACED')
    result.update(schema=INPUT_SCHEMA_V2);extra['databases']=sha;validate_inputs(result);return result


class CurrentCohortDatabases:
    def __init__(self,runtime,inputs):
        require(type(runtime) is CurrentCohortRuntime,'ACTUAL_PARENT_BOUND_CURRENT_COHORT_RUNTIME_REQUIRED')
        self.runtime=runtime;self.inputs=copy.deepcopy(inputs);self.input_hash=validate(inputs)
        self.owner_ids=(id(runtime),id(runtime.selected));self.guard()

    def guard(self):
        r=self.runtime;i=self.inputs;r.guard();runtime=r.inputs
        require(self.owner_ids==(id(r),id(r.selected)) and validate(i)==self.input_hash
            and runtime['schema']==INPUT_SCHEMA_V2
            and runtime['additionalInputsHashes'].get('databases')==self.input_hash
            and all(runtime[k]==i[k] for k in ('sourceClosureHash','installationInputsHash','desiredProfileHash','cohortManifestHash'))
            and runtime['peers']['postgres']['runtimeBinding']==i['postgresRuntimeBinding'],
            'EXACT_PARENT_BOUND_CURRENT_DATABASE_INPUTS_REQUIRED')
        d=i['dockerBinding'];file_bytes(d['path'],0,{0o755,0o750,0o700},limit=67108864,expected=d['sha256'])
        engine=r.selected.images.engine
        host=os.environ.get('DOCKER_HOST')
        same_endpoint=(host=='unix://'+engine.path if host is not None else
            os.path.realpath('/var/run/docker.sock')==os.path.realpath(engine.path))
        require(shutil.which('docker')==d['path'] and same_endpoint
            and not any(os.environ.get(k) for k in ('DOCKER_CONTEXT','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH')),
            'CURRENT_DATABASE_COMMAND_MUST_USE_SAME_LOCAL_ENGINE')

    def sources(self,budget):
        result={};pins={}
        for row in self.inputs['modules']:
            a=row['artifact'];expected_paths=set()
            for ref in a['files']:
                budget.check();path=Path(ref['path']);before=attributes(path.lstat())
                file_bytes(path,0,{0o400,0o600,0o644},limit=ref['maximumBytes'],expected=ref['sha256'])
                require(attributes(path.lstat())==before,'CURRENT_DATABASE_MIGRATION_SOURCE_CHANGED')
                pins[str(path)]=before;expected_paths.add(str(path))
            if a['format']=='MCP_SQL':
                directory=Path(a['root'])/'internal/adapter/postgres/migrations';ancestors(directory/'placeholder')
                require({str(p) for p in directory.iterdir()}==expected_paths,'EXACT_CURRENT_MCP_MIGRATION_DIRECTORY_REQUIRED')
                migrations=mcp_migrations(a['root'])
            else:
                migrations=java_migrations(a['root'])
                marker={'version':None,'script':'"'+SCHEMAS[row['module']]+'"','type':'SCHEMA','checksum':None,'success':True}
                if row['expectedMigrations'][0]==marker:migrations=[marker,*migrations]
            require(migrations==row['expectedMigrations'],'CURRENT_DATABASE_HISTORY_MUST_MATCH_REVIEWED_ARTIFACT_BYTES')
            result[row['module']]=digest(migrations)
        require(all(attributes(Path(path).lstat())==pin for path,pin in pins.items()),'CURRENT_DATABASE_ARTIFACT_CHANGED_DURING_READ')
        budget.check();return result,pins

    def database(self,row,budget):
        self.guard();budget.check();i=self.inputs
        channel=Psql(i['postgresRuntimeBinding']['containerId'],row['user'],row['database'],'ouf-cutover-discovery-read')
        try:
            identity=channel.query("SELECT json_build_object('name',current_database(),'oid',oid::bigint,'allowConnections',datallowconn,'prepared',(SELECT count(*) FROM pg_prepared_xacts WHERE database=current_database()),'readOnly',current_setting('transaction_read_only')='on') FROM pg_database WHERE datname=current_database()",
                "BEGIN READ ONLY; SET LOCAL statement_timeout='5s';",timeout=budget.remaining(5))
            schema=identifier(SCHEMAS[row['module']])
            expression=("SELECT COALESCE(json_agg(json_build_object('version',version,'checksum',checksum) ORDER BY version),'[]'::json) FROM "+schema+'.schema_migration'
                if row['module']=='mcp' else "SELECT COALESCE(json_agg(json_build_object('version',version,'script',script,'type',type,'checksum',checksum,'success',success) ORDER BY installed_rank),'[]'::json) FROM "+schema+'.flyway_schema_history')
            migrations=channel.query(expression,timeout=budget.remaining(5))
        finally:channel.close()
        require(encoded(identity)==encoded({'name':row['database'],'oid':row['databaseOid'],'allowConnections':True,'prepared':0,'readOnly':True})
            and encoded(migrations)==encoded(row['expectedMigrations']),
            'CURRENT_DATABASE_IDENTITY_OR_PACKAGED_MIGRATIONS_CHANGED')
        budget.check();self.guard()
        return {'databaseOid':row['databaseOid'],'migrationHistoryHash':digest(migrations),'migrationCount':len(migrations)}

    def observe(self):
        budget=ObservationBudget(180);self.guard();r=self.runtime;held=r.selected.held();i=self.inputs
        ids=[v['runtimeBinding']['containerId'] for v in r.inputs['peers'].values()]
        reader=CurrentCohortEngine(r.selected.images.engine,r.inputs['engineBinding'],ids,budget)
        def postgres():
            actual=reader.get(i['postgresRuntimeBinding']['containerId']);state=actual['State']
            require(Engine.runtime_binding(actual)==i['postgresRuntimeBinding'] and state['Running'] is True
                and state['Paused'] is False and state['Restarting'] is False and state['Status']=='running'
                and actual['RestartCount']==0,'CURRENT_DATABASE_POSTGRES_GENERATION_CHANGED')
        postgres();source,pins=self.sources(budget)
        first={row['module']:self.database(row,budget) for row in i['modules']}
        require({row['module']:self.database(row,budget) for row in i['modules']}==first,
            'CURRENT_DATABASES_CHANGED_DURING_TWO_PASS_READ')
        require(self.sources(budget)==(source,pins),'CURRENT_DATABASE_ARTIFACTS_CHANGED_ACROSS_READS')
        postgres();self.guard();r.selected.held(held);budget.check()
        return {'schema':'ouf.discovery-current-four-database-witness.v1','inputHash':self.input_hash,
            'heldHistoryHash':digest(held),'databaseEvidenceHash':digest(first),'migrationSourcesHash':digest(source),
            'databaseCount':4,'moduleReadSessions':8,'readOnlyTransactions':True,'reviewedArtifactBytesMatchHistories':True,
            'artifactPublisherProvenanceVerifiedHere':False,'fullCohortProven':False,'runtimeAuthorityIssued':False,
            'targetApplyAuthorized':False,'migrationDispatched':False,'releaseAcceptance':False}
