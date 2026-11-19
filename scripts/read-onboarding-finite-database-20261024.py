#!/usr/bin/env python3
"""Distinct one-session Onboarding DB snapshot; no migration/runtime authority.

The completed Onboarding owner supplies its database identity. The retained
Ingestion profile supplies ONLY the unchanged native PostgreSQL transport.
Private Docker metadata and SQL rows are never emitted on stdout/stderr.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import types
from urllib.parse import urlsplit,unquote,parse_qsl

HELPER='/etc/ouf/deploy-snapshots/onboarding-finite-inputs-232309bf78af54ea/prepare.py'
HELPER_HASH='232309bf78af54ea238d0046d5104f02dab939cedfb20873bc7ca1a7212f786f'
INPUT='/etc/ouf/deploy-snapshots/onboarding-finite-session-ee8b7756f72f82a6/input-preparation-v1/inputs.json'
INPUT_HASH='b8040ef1c49af2455d9a28d26bac4ef4bbf297315c69c0b48256aa83f18b614b'
BASE='/etc/ouf/deploy-snapshots/chatbot-file-cohort-signed-16e5f80e40d09772048f1575850b643a69d4d46520db1a56ccd79a7b1a9e055b'
BASE_REVIEW='07ee9e8adf0d645018fb70212884f43c22e85cf3c7288bd78dad5bf0d02413bc'
OWNER='/etc/ouf/deploy-snapshots/onboarding-audit-execution-i220f2c0'
OWNER_REVIEW='21ca88f1c5aa682eb74612ead95c9bc6154ddf79a18a52af8f5d281e32abc605'
SCOPE='onboarding-database-snapshot-v1'
SOURCE='teatri-csv-6609b245'
VERSION='c9fec43c-19b3-4ffb-9111-781bc347c5b0'
CONFIGURATION='sha256:b13c5fe234168bdb8b315087917bccfe428ceaa8e136ed1c0f56f5bf43deed3d'
COUNTS={'engineGetAttempts':0,'sqlSessionAttempts':0,'containerExecAttempts':0}


class Stop(RuntimeError):pass


def require(ok,code):
    if not ok:raise Stop(code)


def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(v):return hashlib.sha256(encoded(v)).hexdigest()


def identifier(value):
    require(type(value)is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,62}',value),'EXACT_ONBOARDING_DATABASE_IDENTIFIER_REQUIRED')
    return value


def literal(value):return "'"+identifier(value)+"'"


def seed():
    # The already target-proven metadata reader is the exact shared dependency.
    # No old entrypoint/diagnostic/claim is invoked here.
    p=Path(HELPER);require(p.is_absolute() and p.resolve()==p,'EXACT_PROTECTED_HELPER_REQUIRED')
    for parent in p.parents:
        s=parent.lstat();require(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,'ROOT_HELPER_ANCESTRY_REQUIRED')
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0 and before.st_nlink==1
                and stat.S_IMODE(before.st_mode)==0o400 and 0<before.st_size<=131072,'PRIVATE_PINNED_HELPER_REQUIRED')
        raw=os.read(fd,131073)
        def pin(s):return tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
        require(len(raw)==before.st_size and hashlib.sha256(raw).hexdigest()==HELPER_HASH
                and pin(before)==pin(os.fstat(fd))==pin(p.lstat()),'PINNED_HELPER_BYTES_CHANGED')
    finally:os.close(fd)
    m=types.ModuleType('ouf_finite_inputs_dependencies');m.__file__=str(p)
    exec(compile(raw,str(p),'exec'),m.__dict__)
    r=m.initialize();m.raw(str(Path(__file__).resolve()),131072)
    return m,r


def environment(actual):
    values={}
    for row in actual['Config'].get('Env')or[]:
        require(type(row)is str and '='in row,'EXPLICIT_CURRENT_ENVIRONMENT_REQUIRED')
        key,value=row.split('=',1);require(key not in values,'DUPLICATE_CURRENT_ENVIRONMENT_KEY');values[key]=value
    return values


def database_selection(actual,binding,transport):
    # These declarations are private; external config selectors remain a limit.
    env=environment(actual)
    urls={env[k]for k in('OUF_ONB_DB_URL','SPRING_DATASOURCE_URL')if env.get(k)}
    users={env[k]for k in('OUF_ONB_DB_USER','SPRING_DATASOURCE_USERNAME')if env.get(k)}
    require(len(urls)==len(users)==1,'EXPLICIT_UNAMBIGUOUS_ONBOARDING_DATABASE_ENV_REQUIRED')
    url=next(iter(urls));require(url.startswith('jdbc:postgresql://'),'RETAINED_POSTGRES_JDBC_DECLARATION_REQUIRED')
    parsed=urlsplit(url[5:])
    require(parsed.scheme=='postgresql' and parsed.hostname and not parsed.username and not parsed.password
            and not parsed.fragment and unquote(parsed.path)=='/'+binding['database']
            and next(iter(users))==binding['user'],'CURRENT_ONBOARDING_DB_DECLARATION_CHANGED')
    options=parse_qsl(parsed.query,keep_blank_values=True)
    require(len(options)<=8 and len({k for k,_ in options})==len(options)
            and all(k in('currentSchema','sslmode','ApplicationName')for k,_ in options)
            and all(v=='ouf_onboarding'for k,v in options if k=='currentSchema'),
            'CLOSED_ONBOARDING_JDBC_OPTIONS_REQUIRED')
    port=transport['identity']['postgresPort']
    require(parsed.port is None or parsed.port==port,'SAME_BOUND_POSTGRES_PORT_REQUIRED')
    selectors={k:v for k,v in env.items()if v and k.startswith('SPRING_CONFIG_')}
    options_present=any(env.get(k)for k in('SPRING_APPLICATION_JSON','JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','JAVA_OPTS'))
    application_args=(actual['Config'].get('Entrypoint')or[])+(actual['Config'].get('Cmd')or[])
    overrides=bool(selectors)or options_present or any(v.startswith(('--','-D'))for v in application_args)
    return {'database':identifier(binding['database']),'databaseOid':binding['databaseOid'],
        'runtimeRole':identifier(binding['user']),'schema':'ouf_onboarding','postgresPort':port,
        'currentEnvironmentDatabaseDeclarationMatchesRetainedOnboarding':True,
        'allCurrentConfigurationPrecedenceResolved':not overrides,
        'externalConfigurationContentsRead':False}


def query(runtime_role):
    role=literal(runtime_role)
    return """BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout='5s'; SET LOCAL lock_timeout='1s';
SET LOCAL idle_in_transaction_session_timeout='5s'; SET LOCAL search_path=pg_catalog;
SELECT jsonb_build_object(
 'database',current_database(),'databaseOid',(SELECT oid::bigint FROM pg_database WHERE datname=current_database()),
 'role',current_user,'transactionReadOnly',current_setting('transaction_read_only')='on',
 'serverVersionNumber',current_setting('server_version_num')::integer,'serverEncoding',current_setting('server_encoding'),
 'postgresPort',current_setting('port')::integer,'standby',pg_is_in_recovery(),
 'capacity',jsonb_build_object('maximumConnections',current_setting('max_connections')::integer,
   'reservedForSuperusers',current_setting('superuser_reserved_connections')::integer,
   'currentConnections',(SELECT count(*) FROM pg_stat_activity),
   'selectedDatabaseConnections',(SELECT count(*) FROM pg_stat_activity WHERE datname=current_database()),
   'preparedTransactions',(SELECT count(*) FROM pg_prepared_xacts WHERE database=current_database())),
 'roles',coalesce((SELECT jsonb_agg(jsonb_build_object('name',rolname,'superuser',rolsuper,'inherit',rolinherit,
   'createRole',rolcreaterole,'createDb',rolcreatedb,'login',rolcanlogin,'replication',rolreplication,'bypassRls',rolbypassrls)
   ORDER BY rolname) FROM pg_roles WHERE rolname IN(current_user,"""+role+""")),'[]'::jsonb),
 'schema',coalesce((SELECT jsonb_build_object('oid',n.oid::bigint,'owner',pg_get_userbyid(n.nspowner),
   'runtimeUsage',has_schema_privilege("""+role+""",n.oid,'USAGE'),
   'runtimeCreate',has_schema_privilege("""+role+""",n.oid,'CREATE'),
   'adminUsage',has_schema_privilege(current_user,n.oid,'USAGE'),
   'adminCreate',has_schema_privilege(current_user,n.oid,'CREATE'))
   FROM pg_namespace n WHERE n.nspname='ouf_onboarding'),'null'::jsonb),
 'relations',coalesce((SELECT jsonb_agg(jsonb_build_object('oid',c.oid::bigint,'name',c.relname,'kind',c.relkind,
   'owner',pg_get_userbyid(c.relowner),'runtimeOwns',pg_has_role("""+role+""",c.relowner,'USAGE'),
   'runtimeSelect',CASE WHEN c.relkind IN('r','p','v','m','f')THEN has_table_privilege("""+role+""",c.oid,'SELECT')ELSE null END)
   ORDER BY c.relname) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='ouf_onboarding' AND c.relkind IN('r','p','v','m','S','f')),'[]'::jsonb),
 'columns',coalesce((SELECT jsonb_agg(jsonb_build_object('relation',c.relname,'name',a.attname,
   'type',format_type(a.atttypid,a.atttypmod),'notNull',a.attnotnull,
   'default',pg_get_expr(d.adbin,d.adrelid)) ORDER BY c.relname,a.attnum)
   FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid
   LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum
   WHERE n.nspname='ouf_onboarding' AND c.relname IN('managed_onboarding_review','managed_readiness_budget_session','flyway_schema_history')
     AND a.attnum>0 AND NOT a.attisdropped),'[]'::jsonb),
 'constraints',coalesce((SELECT jsonb_agg(jsonb_build_object('relation',c.relname,'name',k.conname,
   'validated',k.convalidated,'definition',pg_get_constraintdef(k.oid,true)) ORDER BY c.relname,k.conname)
   FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='ouf_onboarding' AND c.relname IN('managed_onboarding_review','managed_readiness_budget_session')),'[]'::jsonb),
 'history',coalesce((SELECT jsonb_agg(jsonb_build_object('rank',installed_rank,'version',version,'script',script,
   'type',type,'checksum',checksum,'success',success) ORDER BY installed_rank)
   FROM ouf_onboarding.flyway_schema_history),'[]'::jsonb),
 'selectedReview',coalesce((SELECT jsonb_agg(to_jsonb(r)) FROM ouf_onboarding.managed_onboarding_review r
   WHERE source_id='"""+SOURCE+"""' AND onboarding_version_id='"""+VERSION+"""'::uuid),'[]'::jsonb),
 'activeReadinessLeases',(SELECT count(*) FROM ouf_onboarding.managed_onboarding_review WHERE readiness_lease_until>clock_timestamp())
);ROLLBACK;"""


def arguments(profile,config_directory):
    p=profile;program=p['containerPrograms'];identity=p['identity']
    require(p['schema']=='ouf.onboarding-finite-database-snapshot-profile.v1'
            and p['maximumSqlSessionAttempts']==1 and p['sqlSha256']==hashlib.sha256(query(identity['runtimeRole']).encode()).hexdigest(),
            'DISTINCT_ONE_SESSION_ONBOARDING_PROFILE_REQUIRED')
    for value in(identity['database'],identity['runtimeRole'],identity['adminRole']):identifier(value)
    return [p['dockerExecutable']['path'],'--host','unix://'+p['engineBinding']['socketPath'],'--config',str(config_directory),
        'exec',p['postgresRuntimeBinding']['containerId'],program['env'],'-i','LC_ALL=C',
        'PGPASSFILE=/dev/null','PGSERVICEFILE=/dev/null','PGSYSCONFDIR=/nonexistent',
        'PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=5000 -c lock_timeout=1000 -c idle_in_transaction_session_timeout=5000',
        program['timeout'],'-s','KILL','15',program['psql'],'-X','-w','-q','-A','-t','-v','ON_ERROR_STOP=1',
        '-v','VERBOSITY=sqlstate','-h',p['unixSocketDirectory'],'-p',str(identity['postgresPort']),
        '-U',identity['adminRole'],'-d',identity['database'],'-c',query(identity['runtimeRole'])]


def qualify_snapshot(facts,profile):
    identity=profile['identity']
    require(type(facts)is dict and facts['database']==identity['database'] and facts['databaseOid']==identity['databaseOid']
            and facts['role']==identity['adminRole'] and facts['postgresPort']==identity['postgresPort']
            and facts['transactionReadOnly']is True,'EXACT_ONBOARDING_READ_ONLY_DATABASE_IDENTITY_REQUIRED')
    require(0<len(facts['history'])<=128 and len(facts['selectedReview'])<=1 and len(facts['roles'])in(1,2)
            and len(facts['relations'])<=256 and len(facts['columns'])<=4096 and len(facts['constraints'])<=256,
            'BOUNDED_ONBOARDING_DATABASE_SNAPSHOT_REQUIRED')
    rows=facts['history'];versions=[v['version']for v in rows if v['type']=='SQL']
    require(len(versions)==len(set(versions)) and all(type(v)is str and re.fullmatch('[0-9]{1,4}',v)for v in versions),
            'DISTINCT_NUMERIC_ONBOARDING_SQL_HISTORY_REQUIRED')
    selected=facts['selectedReview'];retained=selected[0]if selected else{}
    # Observations only: drift, newer schema or missing review are retained,
    # never silently converted into migration/activation admission.
    return {'historyRows':len(rows),'allHistoryRowsSuccessful':all(v['success']is True for v in rows),
        'highestSqlVersion':max(map(int,versions),default=0),'v34AlreadyRecorded':'34'in versions,
        'selectedReviewCount':len(selected),'selectedConfigurationMatches':retained.get('configuration_hash')==CONFIGURATION,
        'selectedReadinessAttempts':retained.get('readiness_attempts'),'selectedReadinessGeneration':retained.get('readiness_generation'),
        'selectedReadinessPhase':retained.get('readiness_phase')if retained.get('readiness_phase')in
            ('NOT_STARTED','CHECKING_COMPATIBILITY','CHECKING_DEPENDENCIES','PUBLISHING_PROFILE','ACTIVE','PAUSED','EXHAUSTED','BLOCKED')else'OTHER_OR_ABSENT',
        'activeReadinessLeases':facts['activeReadinessLeases'],'postgres17Utf8':170000<=facts['serverVersionNumber']<180000
            and facts['serverEncoding']=='UTF8','databaseAdmissionProven':False,'migrationAuthorized':False}


def prepare(m,r):
    from tools.ingestion_readiness_patch_execution import runtime_bindings,database_read
    require(not os.path.lexists(Path(m.PACKAGE)/SCOPE),'ONBOARDING_DATABASE_SCOPE_ALREADY_CLAIMED_NO_REPLAY')
    files=m.Facts();inputs=files.json(INPUT,INPUT_HASH)
    require(inputs['schema']=='ouf.onboarding-finite-session-private-inputs.v1'
            and inputs['kind']=='INPUTS_NOT_EXECUTABLE_AUTHORITY' and inputs['targetApplyAuthorized']is False
            and inputs['automaticReplayAllowed']is False and inputs['budgetReset']is False
            and inputs['bootId']==Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'EXACT_COMPLETED_CURRENT_INPUTS_REQUIRED')
    complete=files.json(Path(INPUT).parent/'complete.json')
    require(complete['complete']is True and complete['privateInputsHash']==INPUT_HASH
            and complete['engineGetAttempts']==14 and complete['currentCohortStable']is True,'COMPLETED_INPUT_CAPTURE_REQUIRED')
    for reference in inputs['retainedFacts']:files.json(reference['path'],reference['sha256'])
    observations={}
    for name in('onboarding','postgres'):
        ref=inputs['runtimeObservations'][name];observations[name]=files.json(ref['path'],ref['sha256'])
    base=files.json(Path(BASE)/'review.json',BASE_REVIEW);ref=base['scopes']['finiteActionProcess']['bundle']
    prepared=files.json(ref['path'],ref['sha256'])['prepared']
    require(digest(prepared)==base['privateInputHashes']['preparedInputs'],'RETAINED_ONBOARDING_DATABASE_PLAN_CHANGED')
    dbplan=prepared['databasePlan'];bindings=[v for v in dbplan['modules']if v['module']=='onboarding']
    require(len(bindings)==1 and bindings[0]['schema']=='ouf_onboarding','ONE_RETAINED_ONBOARDING_DATABASE_REQUIRED')
    binding=bindings[0];identifier(binding['database']);identifier(binding['user'])
    require(type(binding['databaseOid'])is int and binding['databaseOid']>0,'RETAINED_ONBOARDING_DATABASE_OID_REQUIRED')
    review=files.json(Path(OWNER)/'review.json',OWNER_REVIEW);plan=files.json(Path(OWNER)/'execution-plan.json')
    journal=files.json(Path(OWNER)/'recovery.json');authority=files.json(Path(OWNER)/'authority.json')
    decision=files.json(Path(OWNER)/'decision.json');human=files.json(Path(OWNER)/'human.json')
    scope=review['scopes']['onboardingAuditUpdate']
    require(review['kind']=='ONBOARDING_AUDIT_FIX' and digest(plan)==scope['planHash']
        and journal['scopeHash']==digest(scope) and journal['authorityHash']==digest(authority)
        and journal['incidentState']=='RECOVERED' and journal['version']==29
        and journal['nextStage']==len(journal['effects'])==len(scope['stages'])==11
        and [v['stage']for v in journal['effects']]==scope['stages']
        and all(v['state']=='APPLIED'for v in journal['effects']) and journal['effects'][-1]['stage']=='VERIFY_FINAL'
        and set(plan['replacements'])=={'onboarding'} and plan['maximumGatewayWrites']==0,
        'EXACT_COMPLETED_ONBOARDING_NATIVE_OWNER_LINEAGE_REQUIRED')
    require(authority['scopedExecution']['reviewHash']==digest(review)==decision['reviewHash']==human['intakeHash']
        and human['executionAuthorityHash']==digest(authority)
        and authority['scopedExecution']['approvalRef']==decision['approvalRef']==human['approvalRef']
        and decision['decision']=='APPROVE_EXACT_FINITE_SCOPED_ACTION','RETAINED_HISTORICAL_APPROVAL_LINKS_CHANGED')
    require(prepared['engine']==plan['engine']==inputs['engineBinding'],'SAME_RETAINED_ONBOARDING_ENGINE_REQUIRED')
    actual=observations['onboarding'];oldpin=journal['effects'][-1]['evidence']['applications']['onboarding']['runtimeBinding']
    require(runtime_bindings.observed(actual,runtime_bindings.SORTED)==oldpin
        and plan['replacements']['onboarding']['name']==actual['Name'].lstrip('/'),
        'CURRENT_ONBOARDING_NOT_COMPLETED_LOCAL_OWNER_GENERATION')
    require(m.lifecycle_declaration(actual)=='NO_RECOGNIZED_MANAGER_LABEL','LIFECYCLE_MANAGER_DECLARATION_REQUIRES_REVIEW')
    transport=database_read.validate_profile(inputs['legacyIngestionDatabaseControlProfile'])
    require(runtime_bindings.observed(observations['postgres'],transport['runtimeBindingProfile'])==transport['postgresRuntimeBinding']
            and transport['engineBinding']==inputs['engineBinding'],'CURRENT_RETAINED_POSTGRES_NATIVE_TRANSPORT_REQUIRED')
    selection=database_selection(actual,binding,transport)
    admin=identifier(dbplan['mcpAuditRoleAdministration']['admin'])
    require(environment(observations['postgres']).get('POSTGRES_USER')==admin,'CURRENT_POSTGRES_ADMIN_DECLARATION_CHANGED')
    program=transport['dockerExecutable'];m.raw(program['path'],67108864,program['sha256'],private=False)
    profile={'schema':'ouf.onboarding-finite-database-snapshot-profile.v1','inputHash':INPUT_HASH,
        'identity':{**selection,'adminRole':admin},'engineBinding':inputs['engineBinding'],
        'postgresRuntimeBinding':inputs['currentBindings']['postgres'],'runtimeBindingProfile':runtime_bindings.NATIVE,
        'dockerExecutable':program,'containerPrograms':transport['containerPrograms'],
        'unixSocketDirectory':transport['unixSocketDirectory'],'nativeTransportOnlyFromIngestionProfile':True,
        'databaseIdentityFromCompletedOnboardingOwner':True,'maximumSqlSessionAttempts':1,
        'sqlSha256':hashlib.sha256(query(selection['runtimeRole']).encode()).hexdigest(),
        'runtimeAuthorityIssued':False,'historicalAuthorityNotReissued':True,'migrationAuthorized':False}
    root=r.exclusive_root(m.PACKAGE,SCOPE)
    m.new_file(root,'claim.json',{'schema':'ouf.onboarding-finite-db-claim.v1','inputHash':INPUT_HASH,
        'maximumEngineGets':4,'maximumSqlSessionAttempts':1,'maximumSeconds':90,'automaticReplayAllowed':False,
        'budgetReset':False,'runtimeAuthorityIssued':False,'profileHash':digest(profile)})
    config=root/'empty-docker-config';config.mkdir(mode=0o700)
    m.new_file(root,'profile.json',profile)
    engine=m.Engine(inputs['engineBinding'],{v['containerId']for v in inputs['currentBindings'].values()},root)
    def current(name):
        require(engine.calls<4,'FOUR_EXACT_DATABASE_ENGINE_GETS_ONLY')
        try:row,_=engine.get(inputs['currentBindings'][name]['containerId'])
        finally:COUNTS['engineGetAttempts']=engine.calls
        require(runtime_bindings.observed(row,runtime_bindings.NATIVE)==inputs['currentBindings'][name]
                and m.process(row)==inputs['currentProcessIdentities'][name]
                and row['RestartCount']==inputs['restartCounts'][name],'CURRENT_DATABASE_OR_ONBOARDING_GENERATION_CHANGED')
        return row
    current('onboarding');current('postgres');files.recheck()
    require(not os.listdir(config),'EMPTY_CREDENTIAL_FREE_DOCKER_CONFIG_REQUIRED')
    argv=arguments(profile,config)
    m.new_file(root,'sql-attempt-01.json',{'attempt':1,'attemptNotCompletion':True,'profileHash':digest(profile),
        'queryHash':profile['sqlSha256'],'credentialFilesAllowed':False,'writesAllowed':False})
    COUNTS['sqlSessionAttempts']=COUNTS['containerExecAttempts']=1
    status,body,unused_errors=database_read.bounded_read(argv)
    current('postgres');current('onboarding');files.recheck()
    require(not os.listdir(config),'EMPTY_DOCKER_CONFIG_CHANGED')
    require(status==0 and 0<len(body)<=524288,'READ_ONLY_ONBOARDING_DATABASE_SNAPSHOT_UNPROVEN')
    facts=m.decode(body);report=qualify_snapshot(facts,profile)
    m.new_file(root,'database-snapshot.json',body)
    bundle={'schema':'ouf.onboarding-finite-database-private-snapshot.v1','inputHash':INPUT_HASH,
        'profile':profile,'report':report,'snapshotPath':str(root/'database-snapshot.json'),
        'snapshotSha256':hashlib.sha256(body).hexdigest(),'retainedFiles':list(files.files.values()),
        'historicalNativeLifecycleLineageMatched':True,'historicalApprovalMetadataLinksMatched':True,
        'historicalSignaturesReverified':False,'historicalAuthorityReused':False,
        'lifecycleMutationAuthorized':False,'databaseAdmissionProven':False,'targetApplyAuthorized':False,
        'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}
    m.new_file(root,'snapshot-inputs.json',bundle)
    result={'schema':'ouf.onboarding-finite-database-snapshot-result.v1','status':'ONBOARDING_DATABASE_SNAPSHOT_OBSERVED',
        'complete':True,'privateSnapshotInputsPath':str(root/'snapshot-inputs.json'),'privateSnapshotInputsHash':digest(bundle),
        **COUNTS,'maximumSqlSessionAttempts':1,'maximumEngineGets':4,'transactionReadOnly':True,
        'onboardingDatabaseIdentityMatchesRetainedOwner':True,
        'currentEnvironmentDatabaseDeclarationMatchesRetainedOnboarding':True,
        'allCurrentConfigurationPrecedenceResolved':selection['allCurrentConfigurationPrecedenceResolved'],
        'currentOnboardingAndPostgresStable':True,'historicalNativeLifecycleLineageMatched':True,
        'historicalAuthorityReused':False,'lifecycleMutationAuthorized':False,**report,
        'serviceCredentialFilesOpened':0,'bearerFilesOpened':0,'privateSigningKeysRead':0,'credentialValuesPrinted':False,
        'addressesPrinted':False,'rawDatabaseRowsPrinted':False,'containerWrites':0,'imageImports':0,
        'databaseMigrations':0,'sourceActivations':0,'humanBudgetsGranted':0,'retainedContextWrites':0,
        'readOnlyRuntime':True,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
        'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}
    m.new_file(root,'complete.json',result);return result


def main():
    try:
        require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
                and len(sys.argv)==1,'ONE_ISOLATED_ROOT_DATABASE_OBSERVATION_REQUIRED')
        def expired(*_):raise Stop('DATABASE_SNAPSHOT_DEADLINE_EXCEEDED')
        signal.signal(signal.SIGALRM,expired);signal.alarm(90)
        result=prepare(*seed())
    except Exception as error:
        reason=str(error)if type(error)is Stop and re.fullmatch('[A-Z0-9_]{1,120}',str(error))else'ONBOARDING_DATABASE_OBSERVATION_UNPROVEN'
        result={'schema':'ouf.onboarding-finite-database-snapshot-result.v1','status':'STOP_RECONCILE','complete':False,
            'reasonCode':reason,'attemptsNotCompletion':dict(COUNTS),'privateObservationMayBePartial':True,
            'databaseMigrations':0,'sourceActivations':0,'humanBudgetsGranted':0,'targetApplyAuthorized':False,
            'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}
    finally:signal.alarm(0)
    print(encoded(result).decode(),flush=True)
    return 0 if result.get('complete')is True else 2


if __name__=='__main__':raise SystemExit(main())
