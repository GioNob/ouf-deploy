"""Closed operational state fence, not a profiling diagnostic or domain read API.

Only technical metadata, hashes and the retained job identity/state are returned.
Exception text, samples, mappings, source records and credentials never leave SQL.
The execution controller must supply a NEW reviewed maintenance authority before
dispatch. An old V35 database profile is only an identity/transport binding.
"""
import hashlib,json,re

ASSET='9c502da5-b5d8-405e-b3f5-60eb31ecb513'
JOB='677480c8-3d10-44fd-9dad-f72ddeed20a4'
TABLES=('managed_file_asset','file_profile','file_profile_job','managed_file_quarantine',
        'source','onboarding_version','managed_onboarding_review',
        'managed_readiness_budget_session','source_property_revision')

class StateFenceDenied(RuntimeError):pass
def require(ok,reason):
    if not ok:raise StateFenceDenied(reason)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(v):return hashlib.sha256(encoded(v)).hexdigest()

def query():
    states=[]
    for table in TABLES:
        states.append("'%s',(SELECT jsonb_build_object('rows',count(*),'sha256',encode(sha256(convert_to(coalesce(string_agg(encode(sha256(convert_to(t.payload::text,'UTF8')),'hex'),E'\\n' ORDER BY encode(sha256(convert_to(t.payload::text,'UTF8')),'hex')),''),'UTF8')),'hex')) FROM (SELECT to_jsonb(x) AS payload FROM ouf_onboarding.%s x LIMIT 10001) t)"%(table,table))
    return """BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SELECT jsonb_build_object(
 'readOnly',current_setting('transaction_read_only'),
 'database',current_database(),
 'databaseOid',(SELECT oid::bigint FROM pg_database WHERE datname=current_database()),
 'user',current_user,'serverVersionNum',current_setting('server_version_num')::int,
 'standby',pg_is_in_recovery(),
 'pendingProfiles',(SELECT count(*) FROM ouf_onboarding.file_profile_job WHERE state IN ('READY','RETRY_WAIT','RUNNING')),
 'activeReadiness',(SELECT count(*) FROM ouf_onboarding.managed_onboarding_review WHERE readiness_lease_until>clock_timestamp() OR readiness_phase IN ('CHECKING_IDENTITY','ACTIVATING')),
 'job',coalesce((SELECT jsonb_build_object('jobId',job_id::text,'assetId',asset_id::text,'state',state,'attempts',attempts,'profileId',profile_id::text) FROM ouf_onboarding.file_profile_job WHERE job_id='"""+JOB+"""'::uuid AND asset_id='"""+ASSET+"""'::uuid),'{}'::jsonb),
 'history',coalesce((SELECT jsonb_agg(jsonb_build_object('version',version,'script',script,'checksum',checksum,'success',success,'type',type) ORDER BY installed_rank) FROM ouf_onboarding.flyway_schema_history),'[]'::jsonb),
 'states',jsonb_build_object("""+','.join(states)+"""));
ROLLBACK;"""

def validate(facts,profile,migrations,baseline=None):
    identity=profile['identity']
    require(facts['readOnly']=='on'and facts['standby']is False and facts['database']==identity['database']
            and facts['databaseOid']==identity['databaseOid'] and facts['user']==identity['adminRole']
            and type(facts['serverVersionNum'])is int and facts['serverVersionNum']//10000==17,
            'EXACT_READ_ONLY_POSTGRES_OWNER_IDENTITY_REQUIRED')
    require(facts['pendingProfiles']==facts['activeReadiness']==0,'OWNER_WORK_MUST_BE_QUIESCENT_BEFORE_REPLACEMENT')
    require(facts['job']=={'jobId':JOB,'assetId':ASSET,'state':'FAILED','attempts':5,'profileId':None},
            'EXACT_RETAINED_FAILED_PROFILE_JOB_REQUIRED')
    require(type(migrations)is list and len(migrations)==35 and {m['version']for m in migrations}=={str(i)for i in range(1,36)},
            'EXACT_PACKAGED_35_MIGRATIONS_REQUIRED')
    expected={row['version']:row for row in migrations}
    sql=[row for row in facts['history']if row['type']=='SQL']
    require(len(sql)==35 and len({row['version']for row in sql})==35 and {row['version']for row in sql}==set(expected),
            'EXACT_EXISTING_35_SQL_HISTORY_ROWS_REQUIRED')
    for row in sql:
        wanted=expected[row['version']]
        require(row['success']is True and row['script']==wanted['script']and row['checksum']==wanted['flywayChecksum'],
                'PACKAGED_AND_INSTALLED_MIGRATION_HISTORY_MUST_MATCH')
    require(all(row['success']is True and row['type']in('SQL','SCHEMA','BASELINE')for row in facts['history']),
            'NO_FAILED_OR_UNKNOWN_MIGRATION_HISTORY_ALLOWED')
    require(type(facts['states'])is dict and set(facts['states'])==set(TABLES),'EXACT_OPERATIONAL_TABLE_FENCE_REQUIRED')
    for row in facts['states'].values():
        require(set(row)=={'rows','sha256'}and type(row['rows'])is int and 0<=row['rows']<=10000
                and type(row['sha256'])is str and re.fullmatch('[a-f0-9]{64}',row['sha256']),
                'BOUNDED_TECHNICAL_STATE_FINGERPRINT_REQUIRED')
    if baseline is not None:
        require(facts==baseline,'OWNER_STATE_OR_COUNTER_CHANGED_DURING_MAINTENANCE')
    return {'operationalStateHash':digest(facts),'retainedFailedJobUnchanged':True,
            'migrationHistoryExact':True,'noPendingProfileOrReadinessWork':True}

def arguments(profile,empty_config,sql):
    """Closed new-maintenance SQL invocation; no credential/environment inheritance."""
    require(sql==query(),'ONLY_ONE_CLOSED_OPERATIONAL_QUERY_ALLOWED')
    require(profile['schema']=='ouf.current-onboarding-database-snapshot-profile.v1','EXISTING_ONBOARDING_TRANSPORT_IDENTITY_ONLY')
    identity=profile['identity'];program=profile['containerPrograms']
    for field in('database','runtimeRole','adminRole'):
        require(type(identity[field])is str and re.fullmatch('[a-z_][a-z0-9_]{0,62}',identity[field]),'CLOSED_DATABASE_IDENTIFIER_REQUIRED')
    require(type(identity['postgresPort'])is int and 1<=identity['postgresPort']<=65535,'BOUND_POSTGRES_PORT_REQUIRED')
    require(type(profile['postgresRuntimeBinding']['containerId'])is str and re.fullmatch('[a-f0-9]{64}',profile['postgresRuntimeBinding']['containerId']),
            'EXACT_FROZEN_POSTGRES_CONTAINER_REQUIRED')
    for path in [profile['dockerExecutable']['path'],profile['engineBinding']['socketPath'],profile['unixSocketDirectory'],str(empty_config),*program.values()]:
        require(type(path)is str and path.startswith('/')and'..'not in path.split('/')and '\x00'not in path,'EXACT_NATIVE_TRANSPORT_PATH_REQUIRED')
    return [profile['dockerExecutable']['path'],'--host','unix://'+profile['engineBinding']['socketPath'],'--config',str(empty_config),
        'exec',profile['postgresRuntimeBinding']['containerId'],program['env'],'-i','LC_ALL=C',
        'PGPASSFILE=/dev/null','PGSERVICEFILE=/dev/null','PGSYSCONFDIR=/nonexistent',
        'PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=5000 -c lock_timeout=1000 -c idle_in_transaction_session_timeout=5000',
        program['timeout'],'-s','KILL','15',program['psql'],'-X','-w','-q','-A','-t','-v','ON_ERROR_STOP=1',
        '-v','VERBOSITY=sqlstate','-h',profile['unixSocketDirectory'],'-p',str(identity['postgresPort']),
        '-U',identity['adminRole'],'-d',identity['database'],'-c',sql]
