"""Fixed candidate SQL/catalog policy, extracted without historical selectors.

Release invariants are preserved from the qualified postboot reader. This is a
new reusable component, not permission to rerun that completed diagnostic.
Identity, role, database OID and native channel remain explicit profile inputs.
No HUMAN/Owner authority or startup-policy proof is inferred from DB facts.
"""
import re
import math
from tools.ingestion_readiness_patch_execution.contract import require,digest

MANIFEST = {'migrations': [{'checksum': 28809713, 'resourceSha256': '8b439684da2cc31c62cfebf4ce4d939f9c8ac9b533a8c9490f5455384c064bb8', 'script': 'V1__ingestion_runtime_core.sql', 'success': True, 'type': 'SQL', 'version': '1'}, {'checksum': -1190230229, 'resourceSha256': '5e3b53341e396f7bf4ba937db2c61e96e9fdedac6420eb0de15350457ee6c528', 'script': 'V2__durable_ack_and_replay.sql', 'success': True, 'type': 'SQL', 'version': '2'}, {'checksum': 1677862093, 'resourceSha256': 'a6e9eb043defdcd8590b94c690911955ec8957ba016b70967e9aef90943bedf4', 'script': 'V3__trusted_operations.sql', 'success': True, 'type': 'SQL', 'version': '3'}, {'checksum': 960152441, 'resourceSha256': 'b112711bd994cff5b0bdd3671937754f6e33fd85a705a102eed23fe9f207b44c', 'script': 'V4__scheduler_and_source_health.sql', 'success': True, 'type': 'SQL', 'version': '4'}, {'checksum': -2033393121, 'resourceSha256': '4e24738272c8fae7233d2601736662eff80d5913fbef6c88ab6dc1f511f65763', 'script': 'V5__replay_execution_lifecycle.sql', 'success': True, 'type': 'SQL', 'version': '5'}, {'checksum': -2023917644, 'resourceSha256': '5bf72f99f9c861678d3e8469ed2f71cd9cd55fccb835dbcd685e9c0d9fe6d46f', 'script': 'V6__protected_operational_log.sql', 'success': True, 'type': 'SQL', 'version': '6'}, {'checksum': -848911848, 'resourceSha256': '48527993d3d8b50d98dc396e6d9b013410cd9db28d35fb76bff14cc23e46f9f2', 'script': 'V7__execution_worker_and_snapshot.sql', 'success': True, 'type': 'SQL', 'version': '7'}, {'checksum': -61585214, 'resourceSha256': '33853cbd55d09ad901d4af6589ad36c1d4d6da1116f10a14bdb3bb2f0bd8332c', 'script': 'V8__schema_surveillance.sql', 'success': True, 'type': 'SQL', 'version': '8'}, {'checksum': -1413097987, 'resourceSha256': 'ed0236c8b6b6c66767813a0da7d3d92457ba0968c7e4376a35b0119f22a752d9', 'script': 'V9__runtime_issue_governance.sql', 'success': True, 'type': 'SQL', 'version': '9'}, {'checksum': 1627974653, 'resourceSha256': '41f8c2362122caa3e9e4d82df0588452a87efdde0f2c518ee47e1bd3570a03dc', 'script': 'V10__quarantine_lifecycle.sql', 'success': True, 'type': 'SQL', 'version': '10'}, {'checksum': -1835304128, 'resourceSha256': '97243be62e65879aed425855895456ef0f9e1579cf0b271bcbfc2b0864069e17', 'script': 'V11__classified_source_resilience.sql', 'success': True, 'type': 'SQL', 'version': '11'}, {'checksum': -1198212964, 'resourceSha256': '9fa09325985424125528420db82bce2c52f7ae75dffc7759207c7eb1666b5b2c', 'script': 'V12__governed_lifecycle_and_historical_replay.sql', 'success': True, 'type': 'SQL', 'version': '12'}, {'checksum': 1850262212, 'resourceSha256': '30402c3c225297436b9bc4e65dceca2c3ba29a3caeffc79692ea7cccf50a000d', 'script': 'V13__pressure_admission_retry_budget.sql', 'success': True, 'type': 'SQL', 'version': '13'}, {'checksum': -1324686996, 'resourceSha256': '5d6acf3516504590fe84d833803db55b87b3858a35c31a88a56e3599ceba916d', 'script': 'V14__published_activation_schedule.sql', 'success': True, 'type': 'SQL', 'version': '14'}, {'checksum': -1837994869, 'resourceSha256': 'e9abf1e1c192be62a4624f8a7ba551be28013ab3a58698a4ad13231fba29abaa', 'script': 'V15__human_recovery_sessions.sql', 'success': True, 'type': 'SQL', 'version': '15'}, {'checksum': -405299983, 'resourceSha256': '6fcf10b6bfbc8e71002fb9378e6a1ff45b70abb4a8f5cd863a1f207c42cb2eb9', 'script': 'V16__incident_observation_time.sql', 'success': True, 'type': 'SQL', 'version': '16'}, {'checksum': -1241321010, 'resourceSha256': '3695a5853afac3923a3428a54739d55d09cf31cc147bf46bfab8505f1c2d0716', 'script': 'V17__incident_publication_and_cursor.sql', 'success': True, 'type': 'SQL', 'version': '17'}, {'checksum': 1281376280, 'resourceSha256': '7519073ac4075c40ed743489a2aefc7f63d8dcd3b1078e6108e50104f2fa8220', 'script': 'V18__incident_publication_bookmarks.sql', 'success': True, 'type': 'SQL', 'version': '18'}]}

SQL = "-- Closed read-only native diagnostic. No application functions, locks or writes.\nBEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;\nSET LOCAL statement_timeout = '5s';\nSET LOCAL lock_timeout = '1s';\nSET LOCAL idle_in_transaction_session_timeout = '5s';\nSET LOCAL search_path = pg_catalog;\nSELECT jsonb_build_object(\n 'serverPort',current_setting('port')::integer,\n 'observedAtUnix',floor(extract(epoch FROM transaction_timestamp()))::bigint,\n 'database',current_database(),'role',current_user,\n 'databaseOid',(SELECT oid::bigint FROM pg_database WHERE datname=current_database()),\n 'readOnly',current_setting('transaction_read_only')='on',\n 'serverVersionNum',current_setting('server_version_num')::integer,\n 'encoding',current_setting('server_encoding'),\n 'allowConnections',(SELECT datallowconn FROM pg_database WHERE datname=current_database()),\n 'preparedTransactions',(SELECT count(*) FROM pg_prepared_xacts WHERE database=current_database()),\n 'connectAllowed',has_database_privilege(current_user,current_database(),'CONNECT'),\n 'schemaUsage',has_schema_privilege(current_user,'ouf_ingestion','USAGE'),\n 'schemaCreate',has_schema_privilege(current_user,'ouf_ingestion','CREATE'),\n 'roleFlags',(SELECT jsonb_build_object('superuser',rolsuper,'createRole',rolcreaterole,\n   'createDb',rolcreatedb,'replication',rolreplication,'bypassRls',rolbypassrls)\n   FROM pg_roles WHERE rolname=current_user),\n 'broadRoleMemberships',jsonb_build_object(\n   'pg_read_all_data',pg_has_role(current_user,'pg_read_all_data','MEMBER'),\n   'pg_write_all_data',pg_has_role(current_user,'pg_write_all_data','MEMBER'),\n   'pg_execute_server_program',pg_has_role(current_user,'pg_execute_server_program','MEMBER'),\n   'pg_read_server_files',pg_has_role(current_user,'pg_read_server_files','MEMBER'),\n   'pg_write_server_files',pg_has_role(current_user,'pg_write_server_files','MEMBER'),\n   'pg_signal_backend',pg_has_role(current_user,'pg_signal_backend','MEMBER')),\n 'history',COALESCE((SELECT jsonb_agg(x ORDER BY installed_rank) FROM\n   (SELECT installed_rank,version,script,type,checksum,success\n    FROM ouf_ingestion.flyway_schema_history ORDER BY installed_rank LIMIT 65)x),'[]'::jsonb),\n 'catalog',jsonb_build_object(\n  'relations',COALESCE((SELECT jsonb_agg(x ORDER BY name) FROM\n   (SELECT c.relname AS name,c.relkind::text AS kind,c.relrowsecurity AS rls,c.relforcerowsecurity AS force_rls\n    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace\n    WHERE n.nspname='ouf_ingestion' AND c.relkind IN('r','p','S','v','m')\n      AND c.relname<>'flyway_schema_history' ORDER BY c.relname LIMIT 129)x),'[]'::jsonb),\n  'columns',COALESCE((SELECT jsonb_agg(x ORDER BY relation,position) FROM\n   (SELECT c.relname AS relation,a.attnum AS position,a.attname AS name,\n      format_type(a.atttypid,a.atttypmod) AS type,a.attnotnull AS not_null,\n      pg_get_expr(d.adbin,d.adrelid) AS default_expression,a.attidentity::text AS identity,\n      a.attgenerated::text AS generated,coll.collname AS collation\n    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace\n      JOIN pg_attribute a ON a.attrelid=c.oid\n      LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum\n      LEFT JOIN pg_collation coll ON coll.oid=a.attcollation\n    WHERE n.nspname='ouf_ingestion' AND c.relkind IN('r','p','v','m') AND c.relname<>'flyway_schema_history'\n      AND a.attnum>0 AND NOT a.attisdropped ORDER BY c.relname,a.attnum LIMIT 2049)x),'[]'::jsonb),\n  'constraints',COALESCE((SELECT jsonb_agg(x ORDER BY relation,name) FROM\n   (SELECT c.relname AS relation,p.conname AS name,p.contype::text AS type,\n      p.convalidated AS validated,p.condeferrable AS deferrable,p.condeferred AS deferred,\n      pg_get_constraintdef(p.oid,true) AS definition\n    FROM pg_constraint p JOIN pg_namespace n ON n.oid=p.connamespace\n      LEFT JOIN pg_class c ON c.oid=p.conrelid\n    WHERE n.nspname='ouf_ingestion' AND COALESCE(c.relname,'')<>'flyway_schema_history'\n    ORDER BY c.relname,p.conname LIMIT 513)x),'[]'::jsonb),\n  'indexes',COALESCE((SELECT jsonb_agg(x ORDER BY name) FROM\n   (SELECT ic.relname AS name,i.indisvalid AS valid,i.indisready AS ready,\n      i.indisunique AS unique_index,i.indisprimary AS primary_index,pg_get_indexdef(i.indexrelid) AS definition\n    FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid JOIN pg_namespace n ON n.oid=c.relnamespace\n      JOIN pg_class ic ON ic.oid=i.indexrelid\n    WHERE n.nspname='ouf_ingestion' AND c.relname<>'flyway_schema_history'\n    ORDER BY ic.relname LIMIT 257)x),'[]'::jsonb),\n  'triggers',COALESCE((SELECT jsonb_agg(x ORDER BY relation,name) FROM\n   (SELECT c.relname AS relation,t.tgname AS name,t.tgtype::integer AS type,t.tgenabled::text AS enabled,\n      pg_get_triggerdef(t.oid,true) AS definition\n    FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace\n    WHERE n.nspname='ouf_ingestion' AND NOT t.tgisinternal AND c.relname<>'flyway_schema_history'\n    ORDER BY c.relname,t.tgname LIMIT 257)x),'[]'::jsonb),\n  'functions',COALESCE((SELECT jsonb_agg(x ORDER BY name,arguments) FROM\n   (SELECT p.proname AS name,pg_get_function_identity_arguments(p.oid) AS arguments,\n      pg_get_functiondef(p.oid) AS definition\n    FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace\n    WHERE n.nspname='ouf_ingestion' AND p.prokind IN('f','p')\n    ORDER BY p.proname,pg_get_function_identity_arguments(p.oid) LIMIT 129)x),'[]'::jsonb),\n  'sequences',COALESCE((SELECT jsonb_agg(x ORDER BY name) FROM\n   (SELECT c.relname AS name,s.seqstart AS start,s.seqincrement AS increment,s.seqmin AS minimum,\n      s.seqmax AS maximum,s.seqcache AS cache,s.seqcycle AS cycle\n    FROM pg_sequence s JOIN pg_class c ON c.oid=s.seqrelid JOIN pg_namespace n ON n.oid=c.relnamespace\n    WHERE n.nspname='ouf_ingestion' ORDER BY c.relname LIMIT 129)x),'[]'::jsonb),\n  'policies',COALESCE((SELECT jsonb_agg(x ORDER BY relation,name) FROM\n   (SELECT c.relname AS relation,p.polname AS name,p.polcmd::text AS command,p.polpermissive AS permissive,\n      pg_get_expr(p.polqual,p.polrelid) AS qualifier,pg_get_expr(p.polwithcheck,p.polrelid) AS with_check\n    FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid JOIN pg_namespace n ON n.oid=c.relnamespace\n    WHERE n.nspname='ouf_ingestion' ORDER BY c.relname,p.polname LIMIT 129)x),'[]'::jsonb)),\n 'tablePrivileges',COALESCE((SELECT jsonb_agg(x ORDER BY name) FROM\n   (SELECT c.relname AS name,has_table_privilege(current_user,c.oid,'SELECT') AS select_allowed,\n      has_table_privilege(current_user,c.oid,'INSERT') AS insert_allowed,\n      has_table_privilege(current_user,c.oid,'UPDATE') AS update_allowed,\n      has_table_privilege(current_user,c.oid,'DELETE') AS delete_allowed\n    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace\n    WHERE n.nspname='ouf_ingestion' AND c.relkind IN('r','p') ORDER BY c.relname LIMIT 129)x),'[]'::jsonb),\n 'sequencePrivileges',COALESCE((SELECT jsonb_agg(x ORDER BY name) FROM\n   (SELECT c.relname AS name,has_sequence_privilege(current_user,c.oid,'USAGE') AS usage_allowed\n    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace\n    WHERE n.nspname='ouf_ingestion' AND c.relkind='S' ORDER BY c.relname LIMIT 129)x),'[]'::jsonb),\n 'functionExecuteAllowed',COALESCE((SELECT bool_and(has_function_privilege(current_user,p.oid,'EXECUTE'))\n    FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='ouf_ingestion'),false),\n 'pressurePolicies',COALESCE((SELECT jsonb_agg(x) FROM\n   (SELECT policy_key,state,global_running_limit,soft_outbox_limit,hard_outbox_limit,recovery_outbox_limit\n    FROM ouf_ingestion.runtime_pressure_policy ORDER BY policy_key LIMIT 2)x),'[]'::jsonb),\n 'work',jsonb_build_object(\n   'runnableRuns',(SELECT count(*) FROM (SELECT 1 FROM ouf_ingestion.ing_run\n       WHERE state IN('READY','PREFLIGHT','RUNNING','DRAINING') LIMIT 10001)x),\n   'eligibleSchedules',(SELECT count(*) FROM (SELECT 1 FROM ouf_ingestion.ing_schedule\n       WHERE state='ACTIVE' AND publication_enabled AND NOT activation_blocked\n       AND (NOT trigger_once OR consumed_publication_id IS DISTINCT FROM publication_id) LIMIT 10001)x),\n   'liveScheduleLeases',(SELECT count(*) FROM (SELECT 1 FROM ouf_ingestion.ing_schedule\n       WHERE lease_until>transaction_timestamp() LIMIT 10001)x),\n   'unackedOutbox',(SELECT count(*) FROM (SELECT 1 FROM ouf_ingestion.handoff_outbox WHERE state<>'ACKED' LIMIT 10001)x),\n   'liveOutboxLeases',(SELECT count(*) FROM (SELECT 1 FROM ouf_ingestion.handoff_outbox\n       WHERE lease_until>transaction_timestamp() AND state='DELIVERING' LIMIT 10001)x)),\n 'connections',jsonb_build_object(\n   'serverMaximum',current_setting('max_connections')::integer,\n   'serverObserved',(SELECT count(*) FROM pg_stat_activity),\n   'databaseObserved',(SELECT count(*) FROM pg_stat_activity WHERE datname=current_database()),\n   'databaseLimit',(SELECT datconnlimit FROM pg_database WHERE datname=current_database()),\n   'lockWaiters',(SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock'),\n   'unobservablePeers',(SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND state IS NULL),\n   'advisoryLocks',(SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND pid<>pg_backend_pid()))\n);\nROLLBACK;\n"

TABLES = frozenset(['audit_event', 'checkpoint_history', 'handoff_outbox', 'historical_contract_legal_hold_event', 'incident_bookmark_page', 'incident_bookmark_scope', 'incident_history_coverage', 'incident_publication_bookmark', 'incident_publication_clock', 'incident_publication_history_floor', 'incident_read_cursor', 'incident_read_item', 'incident_read_session', 'incident_transition', 'ing_lineage', 'ing_partition', 'ing_quarantine', 'ing_run', 'ing_schedule', 'ing_watermark', 'onboarding_review_outbox', 'operational_event', 'processing_attempt', 'protected_log_access_audit', 'replay_attempt', 'replay_execution', 'replay_request', 'run_recovery_session', 'runtime_configuration_snapshot', 'runtime_issue', 'runtime_pressure_policy', 'schema_observation', 'source_health'])

SEQUENCES = frozenset(['operational_event_event_id_seq', 'incident_transition_transition_id_seq'])

REFERENCE_CATALOG_SHA256 = '0ae9e4f3fda6fd7f4432c1816139a53eba471077730badf2beb61712585ed209'

def identifier(value):
    require(type(value) is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,62}', value), 'BOUNDED_DATABASE_IDENTIFIER_REQUIRED')
    return value

def expected_history():
    return [{k: row[k] for k in ('version', 'script', 'type', 'checksum', 'success')} for row in MANIFEST['migrations']]

def history_without_marker(rows):
    require(type(rows) is list and 1 <= len(rows) <= 64, 'BOUNDED_MIGRATION_HISTORY_REQUIRED')
    result = [{k: row[k] for k in ('version', 'script', 'type', 'checksum', 'success')} for row in rows]
    marker = {'version': None, 'script': '"ouf_ingestion"', 'type': 'SCHEMA', 'checksum': None, 'success': True}
    retained_marker = bool(result and result[0] == marker)
    return (result[1:] if retained_marker else result), retained_marker

APPEND_ONLY = frozenset({'audit_event','checkpoint_history','historical_contract_legal_hold_event','ing_lineage',
                        'operational_event','processing_attempt','protected_log_access_audit','replay_attempt',
                        'replay_request','runtime_configuration_snapshot'})

NO_DELETE = frozenset({'incident_transition','run_recovery_session','incident_publication_history_floor'})

NO_UPDATE = frozenset({'incident_bookmark_scope','incident_read_item','incident_publication_bookmark'})

def _analyze_qualified_snapshot(facts, selected):
    require(facts['readOnly'] is True and facts['database'] == selected['database']
            and facts['role'] == selected['user'] and facts['databaseOid'] == selected['databaseOid'],
            'EXACT_READ_ONLY_DATABASE_AND_RUNTIME_ROLE_REQUIRED')
    actual, marker = history_without_marker(facts['history'])
    history_matches = actual == expected_history()
    catalog = facts['catalog']
    limits = {'relations':128,'columns':2048,'constraints':512,'indexes':256,'triggers':256,'functions':128,'sequences':128,'policies':128}
    catalog_bounded = set(catalog) == set(limits) and all(type(catalog[k]) is list and len(catalog[k]) <= n for k,n in limits.items())
    catalog_hash = digest(catalog)
    reference_qualified = type(REFERENCE_CATALOG_SHA256) is str and re.fullmatch('[0-9a-f]{64}', REFERENCE_CATALOG_SHA256) is not None
    catalog_matches = bool(reference_qualified and catalog_bounded and catalog_hash == REFERENCE_CATALOG_SHA256)
    rows = {r['name']: r for r in facts['tablePrivileges']}
    gaps = []
    for table in sorted(TABLES | {'flyway_schema_history'}):
        permissions = {'select_allowed'} if table == 'flyway_schema_history' else {'select_allowed','insert_allowed','update_allowed','delete_allowed'}
        if table in APPEND_ONLY: permissions -= {'update_allowed','delete_allowed'}
        if table in NO_DELETE: permissions.discard('delete_allowed')
        if table in NO_UPDATE: permissions.discard('update_allowed')
        for permission in sorted(permissions):
            if rows.get(table, {}).get(permission) is not True: gaps.append({'table': table, 'permission': permission})
    seq = {r['name']:r for r in facts['sequencePrivileges']}
    privileges_match = (set(rows) == TABLES | {'flyway_schema_history'} and not gaps
                        and set(seq) == SEQUENCES and all(r['usage_allowed'] is True for r in seq.values())
                        and facts['connectAllowed'] is True and facts['schemaUsage'] is True
                        and facts['functionExecuteAllowed'] is True)
    narrow_role = (set(facts['roleFlags']) == {'superuser','createRole','createDb','replication','bypassRls'}
                   and all(v is False for v in facts['roleFlags'].values())
                   and all(v is False for v in facts['broadRoleMemberships'].values()))
    policies = facts['pressurePolicies']
    policy_valid = (len(policies) == 1 and policies[0]['policy_key'] == 'GLOBAL'
                    and 0 < policies[0]['recovery_outbox_limit'] < policies[0]['soft_outbox_limit'] < policies[0]['hard_outbox_limit']
                    and 1 <= policies[0]['global_running_limit'] <= 128)
    policy = policies[0] if policy_valid else None
    work, connections = facts['work'], facts['connections']
    counts_bounded = all(type(v) is int and 0 <= v <= 10001 for v in work.values())
    work_drained = counts_bounded and all(work[k] == 0 for k in ('runnableRuns','eligibleSchedules','liveScheduleLeases','liveOutboxLeases'))
    headroom = connections['serverMaximum'] - connections['serverObserved']
    database_headroom = connections['databaseLimit'] < 0 or connections['databaseLimit'] - connections['databaseObserved'] >= 2
    pressure_safe = bool(policy_valid and policy['state'] == 'NORMAL' and counts_bounded
                         and work['unackedOutbox'] < min(10001, policy['soft_outbox_limit'])
                         and headroom >= 5 and database_headroom and connections['lockWaiters'] == 0
                         and connections['unobservablePeers'] == 0 and connections['advisoryLocks'] == 0
                         and facts['preparedTransactions'] == 0 and facts['allowConnections'] is True)
    postgres_compatible = 170000 <= facts['serverVersionNum'] < 180000 and facts['encoding'] == 'UTF8'
    return {'databaseIdentityAndRoleMatched':True,'transactionReadOnly':True,
            'installedSqlMigrationCount':len(actual),'schemaCreationMarkerRetained':marker,
            'sqlHistoryMatchesCandidate':history_matches,'noSqlResourcesPendingByHistory':history_matches,
            'catalogDigest':REFERENCE_CATALOG_SHA256 if catalog_matches else None,'catalogReferenceQualified':reference_qualified,
            'runtimeCatalogMatchesQualifiedCandidate':catalog_matches,'catalogWithinBounds':catalog_bounded,
            'runtimeTableCount':len(TABLES),'requiredRuntimePrivilegesAvailable':privileges_match,'privilegeGaps':gaps,
            'runtimeRoleBroadFlagsAbsent':narrow_role,'runtimeRoleFlags':facts['roleFlags'],
            'runtimeRoleBroadMemberships':facts['broadRoleMemberships'],'schemaCreatePrivilegePresent':facts['schemaCreate'],
            'postgres17Utf8':postgres_compatible,'storedPressureState':policy['state'] if policy and policy['state'] in ('NORMAL','SOFT_PRESSURE','HARD_PRESSURE','RECOVERY') else 'UNKNOWN',
            'pressureAndControlHeadroomWithinReadProfile':pressure_safe,'observedConnectionHeadroom':headroom,
            'workCountsBounded':counts_bounded,'workCountsLowerBounds':work,'runtimeWorkDrainedAtSnapshot':work_drained,
            'databaseReadPrerequisitesProven':bool(history_matches and catalog_matches and privileges_match and narrow_role
                                                 and pressure_safe and work_drained and postgres_compatible)}

ROLE_FLAGS={'superuser','createRole','createDb','replication','bypassRls'}
BROAD_ROLES={'pg_read_all_data','pg_write_all_data','pg_execute_server_program',
             'pg_read_server_files','pg_write_server_files','pg_signal_backend'}
WORK={'runnableRuns','eligibleSchedules','liveScheduleLeases','unackedOutbox','liveOutboxLeases'}
CONNECTIONS={'serverMaximum','serverObserved','databaseObserved','databaseLimit',
             'lockWaiters','unobservablePeers','advisoryLocks'}
CATALOG_LIMITS={'relations':128,'columns':2048,'constraints':512,'indexes':256,
                'triggers':256,'functions':128,'sequences':128,'policies':128}
FACT_FIELDS={'observedAtUnix','database','databaseOid','role','readOnly','serverVersionNum','serverPort',
             'encoding','allowConnections','preparedTransactions','connectAllowed','schemaUsage','schemaCreate',
             'roleFlags','broadRoleMemberships','history','catalog','tablePrivileges','sequencePrivileges',
             'functionExecuteAllowed','pressurePolicies','work','connections'}

def named_rows(rows,names,fields):
    require(type(rows)is list and len(rows)==len(names)
            and all(type(r)is dict and set(r)==fields for r in rows)
            and all(type(r['name'])is str for r in rows)
            and len({r['name']for r in rows})==len(rows)and {r['name']for r in rows}==names,
            'COMPLETE_UNIQUE_DATABASE_PRIVILEGE_ROWS_REQUIRED')
    require(all(type(v)is bool for r in rows for k,v in r.items()if k!='name'),
            'BOOLEAN_DATABASE_PRIVILEGE_VALUES_REQUIRED')

def validate_facts(facts,selected,now):
    require(type(selected)is dict and set(selected)=={'database','user','databaseOid','postgresPort'},
            'EXPLICIT_DATABASE_IDENTITY_PROFILE_REQUIRED')
    identifier(selected['database']);identifier(selected['user'])
    require(type(selected['databaseOid'])is int and selected['databaseOid']>0
            and type(selected['postgresPort'])is int and 1<=selected['postgresPort']<=65535,
            'EXPLICIT_DATABASE_OID_AND_PORT_REQUIRED')
    require(type(facts)is dict and set(facts)==FACT_FIELDS,'EXACT_BOUNDED_SQL_FACTS_REQUIRED')
    require(type(now)in(int,float)and math.isfinite(now)
            and type(facts['observedAtUnix'])is int and 0<=now-facts['observedAtUnix']<=5,
            'FRESH_CURRENT_DATABASE_SNAPSHOT_REQUIRED')
    require(type(facts['database'])is str and type(facts['role'])is str
            and type(facts['databaseOid'])is int and type(facts['serverPort'])is int
            and facts['serverPort']==selected['postgresPort'],'EXACT_CURRENT_DATABASE_PORT_REQUIRED')
    for name in ('readOnly','allowConnections','connectAllowed','schemaUsage','schemaCreate','functionExecuteAllowed'):
        require(type(facts[name])is bool,'BOOLEAN_DATABASE_FACT_REQUIRED')
    for name in ('serverVersionNum','preparedTransactions'):
        require(type(facts[name])is int and facts[name]>=0,'INTEGER_DATABASE_FACT_REQUIRED')
    for name,keys in (('roleFlags',ROLE_FLAGS),('broadRoleMemberships',BROAD_ROLES)):
        require(type(facts[name])is dict and set(facts[name])==keys
                and all(type(v)is bool for v in facts[name].values()),'COMPLETE_DATABASE_ROLE_PROOF_REQUIRED')
    named_rows(facts['tablePrivileges'],TABLES|{'flyway_schema_history'},
               {'name','select_allowed','insert_allowed','update_allowed','delete_allowed'})
    named_rows(facts['sequencePrivileges'],SEQUENCES,{'name','usage_allowed'})
    require(type(facts['work'])is dict and set(facts['work'])==WORK
            and all(type(v)is int and 0<=v<=10001 for v in facts['work'].values()),'COMPLETE_BOUNDED_WORK_COUNTS_REQUIRED')
    require(type(facts['connections'])is dict and set(facts['connections'])==CONNECTIONS
            and all(type(v)is int and v>=(-1 if k=='databaseLimit'else 0)for k,v in facts['connections'].items()),
            'COMPLETE_DATABASE_CONTROL_HEADROOM_REQUIRED')
    policies=facts['pressurePolicies']
    require(type(policies)is list and len(policies)==1 and type(policies[0])is dict
            and set(policies[0])=={'policy_key','state','global_running_limit','soft_outbox_limit',
                                   'hard_outbox_limit','recovery_outbox_limit'}
            and all(type(v)is int and v>=0 for k,v in policies[0].items()if k not in('policy_key','state')),
            'EXACT_TYPED_DATABASE_PRESSURE_POLICY_REQUIRED')
    catalog=facts['catalog']
    require(type(catalog)is dict and set(catalog)==set(CATALOG_LIMITS)
            and all(type(catalog[k])is list and len(catalog[k])<=limit for k,limit in CATALOG_LIMITS.items()),
            'COMPLETE_BOUNDED_DATABASE_CATALOG_REQUIRED')
    history=facts['history']
    require(type(history)is list and 1<=len(history)<=64
            and all(type(r)is dict and set(r)=={'installed_rank','version','script','type','checksum','success'}
                    and type(r['installed_rank'])is int and r['installed_rank']>=0
                    and type(r['success'])is bool and type(r['script'])is str and type(r['type'])is str
                    and (r['version']is None or type(r['version'])is str)
                    and (r['checksum']is None or type(r['checksum'])is int)for r in history)
            and [r['installed_rank']for r in history]==sorted({r['installed_rank']for r in history}),
            'COMPLETE_ORDERED_UNIQUE_MIGRATION_HISTORY_REQUIRED')

def qualify_snapshot(facts,selected,*,now):
    validate_facts(facts,selected,now)
    report=_analyze_qualified_snapshot(facts,selected)
    return {'schema':'ouf.ingestion-rollout-database-snapshot.v1','observedAtUnix':facts['observedAtUnix'],
            **report,'databaseAdmissionProven':False,'runtimeStartupMigrationPolicyProven':False,
            'runtimeAuthorityIssued':False,'readOnly':True,'schemaOrDataMutations':0,
            'freshHUMANOwnerGenerationAndStartupProofStillRequired':True}
