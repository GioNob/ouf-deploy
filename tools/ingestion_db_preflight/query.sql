-- Closed read-only native diagnostic. No application functions, locks or writes.
BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = '5s';
SET LOCAL lock_timeout = '1s';
SET LOCAL idle_in_transaction_session_timeout = '5s';
SET LOCAL search_path = pg_catalog;
SELECT jsonb_build_object(
 'observedAtUnix',extract(epoch FROM transaction_timestamp())::bigint,
 'database',current_database(),'role',current_user,
 'databaseOid',(SELECT oid::bigint FROM pg_database WHERE datname=current_database()),
 'readOnly',current_setting('transaction_read_only')='on',
 'serverVersionNum',current_setting('server_version_num')::integer,
 'encoding',current_setting('server_encoding'),
 'allowConnections',(SELECT datallowconn FROM pg_database WHERE datname=current_database()),
 'preparedTransactions',(SELECT count(*) FROM pg_prepared_xacts WHERE database=current_database()),
 'connectAllowed',has_database_privilege(current_user,current_database(),'CONNECT'),
 'schemaUsage',has_schema_privilege(current_user,'ouf_ingestion','USAGE'),
 'schemaCreate',has_schema_privilege(current_user,'ouf_ingestion','CREATE'),
 'roleFlags',(SELECT jsonb_build_object('superuser',rolsuper,'createRole',rolcreaterole,
   'createDb',rolcreatedb,'replication',rolreplication,'bypassRls',rolbypassrls)
   FROM pg_roles WHERE rolname=current_user),
 'broadRoleMemberships',jsonb_build_object(
   'pg_read_all_data',pg_has_role(current_user,'pg_read_all_data','MEMBER'),
   'pg_write_all_data',pg_has_role(current_user,'pg_write_all_data','MEMBER'),
   'pg_execute_server_program',pg_has_role(current_user,'pg_execute_server_program','MEMBER'),
   'pg_read_server_files',pg_has_role(current_user,'pg_read_server_files','MEMBER'),
   'pg_write_server_files',pg_has_role(current_user,'pg_write_server_files','MEMBER'),
   'pg_signal_backend',pg_has_role(current_user,'pg_signal_backend','MEMBER')),
 'history',COALESCE((SELECT jsonb_agg(x ORDER BY installed_rank) FROM
   (SELECT installed_rank,version,script,type,checksum,success
    FROM ouf_ingestion.flyway_schema_history ORDER BY installed_rank LIMIT 65)x),'[]'::jsonb),
 'catalog',jsonb_build_object(
  'relations',COALESCE((SELECT jsonb_agg(x ORDER BY name) FROM
   (SELECT c.relname AS name,c.relkind::text AS kind,c.relrowsecurity AS rls,c.relforcerowsecurity AS force_rls
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='ouf_ingestion' AND c.relkind IN('r','p','S','v','m')
      AND c.relname<>'flyway_schema_history' ORDER BY c.relname LIMIT 129)x),'[]'::jsonb),
  'columns',COALESCE((SELECT jsonb_agg(x ORDER BY relation,position) FROM
   (SELECT c.relname AS relation,a.attnum AS position,a.attname AS name,
      format_type(a.atttypid,a.atttypmod) AS type,a.attnotnull AS not_null,
      pg_get_expr(d.adbin,d.adrelid) AS default_expression,a.attidentity::text AS identity,
      a.attgenerated::text AS generated,coll.collname AS collation
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      JOIN pg_attribute a ON a.attrelid=c.oid
      LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum
      LEFT JOIN pg_collation coll ON coll.oid=a.attcollation
    WHERE n.nspname='ouf_ingestion' AND c.relkind IN('r','p','v','m') AND c.relname<>'flyway_schema_history'
      AND a.attnum>0 AND NOT a.attisdropped ORDER BY c.relname,a.attnum LIMIT 2049)x),'[]'::jsonb),
  'constraints',COALESCE((SELECT jsonb_agg(x ORDER BY relation,name) FROM
   (SELECT c.relname AS relation,p.conname AS name,p.contype::text AS type,
      p.convalidated AS validated,p.condeferrable AS deferrable,p.condeferred AS deferred,
      pg_get_constraintdef(p.oid,true) AS definition
    FROM pg_constraint p JOIN pg_namespace n ON n.oid=p.connamespace
      LEFT JOIN pg_class c ON c.oid=p.conrelid
    WHERE n.nspname='ouf_ingestion' AND COALESCE(c.relname,'')<>'flyway_schema_history'
    ORDER BY c.relname,p.conname LIMIT 513)x),'[]'::jsonb),
  'indexes',COALESCE((SELECT jsonb_agg(x ORDER BY name) FROM
   (SELECT ic.relname AS name,i.indisvalid AS valid,i.indisready AS ready,
      i.indisunique AS unique_index,i.indisprimary AS primary_index,pg_get_indexdef(i.indexrelid) AS definition
    FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid JOIN pg_namespace n ON n.oid=c.relnamespace
      JOIN pg_class ic ON ic.oid=i.indexrelid
    WHERE n.nspname='ouf_ingestion' AND c.relname<>'flyway_schema_history'
    ORDER BY ic.relname LIMIT 257)x),'[]'::jsonb),
  'triggers',COALESCE((SELECT jsonb_agg(x ORDER BY relation,name) FROM
   (SELECT c.relname AS relation,t.tgname AS name,t.tgtype::integer AS type,t.tgenabled::text AS enabled,
      pg_get_triggerdef(t.oid,true) AS definition
    FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='ouf_ingestion' AND NOT t.tgisinternal AND c.relname<>'flyway_schema_history'
    ORDER BY c.relname,t.tgname LIMIT 257)x),'[]'::jsonb),
  'functions',COALESCE((SELECT jsonb_agg(x ORDER BY name,arguments) FROM
   (SELECT p.proname AS name,pg_get_function_identity_arguments(p.oid) AS arguments,
      pg_get_functiondef(p.oid) AS definition
    FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='ouf_ingestion' AND p.prokind IN('f','p')
    ORDER BY p.proname,pg_get_function_identity_arguments(p.oid) LIMIT 129)x),'[]'::jsonb),
  'sequences',COALESCE((SELECT jsonb_agg(x ORDER BY name) FROM
   (SELECT c.relname AS name,s.seqstart AS start,s.seqincrement AS increment,s.seqmin AS minimum,
      s.seqmax AS maximum,s.seqcache AS cache,s.seqcycle AS cycle
    FROM pg_sequence s JOIN pg_class c ON c.oid=s.seqrelid JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='ouf_ingestion' ORDER BY c.relname LIMIT 129)x),'[]'::jsonb),
  'policies',COALESCE((SELECT jsonb_agg(x ORDER BY relation,name) FROM
   (SELECT c.relname AS relation,p.polname AS name,p.polcmd::text AS command,p.polpermissive AS permissive,
      pg_get_expr(p.polqual,p.polrelid) AS qualifier,pg_get_expr(p.polwithcheck,p.polrelid) AS with_check
    FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='ouf_ingestion' ORDER BY c.relname,p.polname LIMIT 129)x),'[]'::jsonb)),
 'tablePrivileges',COALESCE((SELECT jsonb_agg(x ORDER BY name) FROM
   (SELECT c.relname AS name,has_table_privilege(current_user,c.oid,'SELECT') AS select_allowed,
      has_table_privilege(current_user,c.oid,'INSERT') AS insert_allowed,
      has_table_privilege(current_user,c.oid,'UPDATE') AS update_allowed,
      has_table_privilege(current_user,c.oid,'DELETE') AS delete_allowed
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='ouf_ingestion' AND c.relkind IN('r','p') ORDER BY c.relname LIMIT 129)x),'[]'::jsonb),
 'sequencePrivileges',COALESCE((SELECT jsonb_agg(x ORDER BY name) FROM
   (SELECT c.relname AS name,has_sequence_privilege(current_user,c.oid,'USAGE') AS usage_allowed
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='ouf_ingestion' AND c.relkind='S' ORDER BY c.relname LIMIT 129)x),'[]'::jsonb),
 'functionExecuteAllowed',COALESCE((SELECT bool_and(has_function_privilege(current_user,p.oid,'EXECUTE'))
    FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='ouf_ingestion'),false),
 'pressurePolicies',COALESCE((SELECT jsonb_agg(x) FROM
   (SELECT policy_key,state,global_running_limit,soft_outbox_limit,hard_outbox_limit,recovery_outbox_limit
    FROM ouf_ingestion.runtime_pressure_policy ORDER BY policy_key LIMIT 2)x),'[]'::jsonb),
 'work',jsonb_build_object(
   'runnableRuns',(SELECT count(*) FROM (SELECT 1 FROM ouf_ingestion.ing_run
       WHERE state IN('READY','PREFLIGHT','RUNNING','DRAINING') LIMIT 10001)x),
   'eligibleSchedules',(SELECT count(*) FROM (SELECT 1 FROM ouf_ingestion.ing_schedule
       WHERE state='ACTIVE' AND publication_enabled AND NOT activation_blocked
       AND (NOT trigger_once OR consumed_publication_id IS DISTINCT FROM publication_id) LIMIT 10001)x),
   'liveScheduleLeases',(SELECT count(*) FROM (SELECT 1 FROM ouf_ingestion.ing_schedule
       WHERE lease_until>transaction_timestamp() LIMIT 10001)x),
   'unackedOutbox',(SELECT count(*) FROM (SELECT 1 FROM ouf_ingestion.handoff_outbox WHERE state<>'ACKED' LIMIT 10001)x),
   'liveOutboxLeases',(SELECT count(*) FROM (SELECT 1 FROM ouf_ingestion.handoff_outbox
       WHERE lease_until>transaction_timestamp() AND state='DELIVERING' LIMIT 10001)x)),
 'connections',jsonb_build_object(
   'serverMaximum',current_setting('max_connections')::integer,
   'serverObserved',(SELECT count(*) FROM pg_stat_activity),
   'databaseObserved',(SELECT count(*) FROM pg_stat_activity WHERE datname=current_database()),
   'databaseLimit',(SELECT datconnlimit FROM pg_database WHERE datname=current_database()),
   'lockWaiters',(SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock'),
   'unobservablePeers',(SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND state IS NULL),
   'advisoryLocks',(SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND pid<>pg_backend_pid()))
);
ROLLBACK;
