"""Private cohort backups and exact owner migration verification.

Java applications keep their own Flyway migrations. MCP's existing schema must
already match its embedded migration bytes; no root SQL substitutes for its
separate migration role. No automatic database restore or repair is provided.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import time
from urllib.parse import quote
import zipfile
import zlib

from database_gate import Psql, identifier, literal
from engine_creation import Engine
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.chatbot_file_cohort.plan import MODULES, NO_RESTART, digest, require, sha, runtime_pin, environment
from tools.chatbot_file_cohort.containers import installation_scope

SCHEMAS = {'onboarding':'ouf_onboarding','ingestion':'ouf_ingestion','udp':'ouf_udp','mcp':'ouf_mcp'}


def flyway_checksum(raw):
    """Flyway ChecksumCalculator: first BOM removed, CR/LF excluded, signed CRC32."""
    text = raw.decode('utf-8')
    if text.startswith('\ufeff'):
        text = text[1:]
    value = 0
    for line in re.split(r'\r\n|\n|\r', text):
        value = zlib.crc32(line.encode('utf-8'), value)
    return value if value < 2**31 else value-2**32


def java_migrations(jar):
    """Read migration bytes from the already verified packaged executable JAR."""
    rows = []
    with zipfile.ZipFile(jar) as archive:
        members = [m for m in archive.infolist() if m.filename.startswith('BOOT-INF/classes/db/migration/') and not m.is_dir()]
        require(1 <= len(members) <= 256 and sum(m.file_size for m in members) <= 8388608,
                'BOUNDED_PACKAGED_MIGRATIONS_REQUIRED')
        for member in members:
            name = member.filename.split('/')[-1]
            match = re.fullmatch(r'V([0-9]+(?:[._][0-9]+)*)__([A-Za-z0-9_-]+)\.sql',name)
            require(match is not None and member.filename == 'BOOT-INF/classes/db/migration/'+name,
                    'REPEATABLE_OR_CUSTOM_MIGRATION_REQUIRES_REVIEW')
            raw = archive.read(member)
            rows.append({'version':match[1].replace('_','.'),'script':name,'type':'SQL',
                         'checksum':flyway_checksum(raw),'success':True})
    rows.sort(key=lambda r:tuple(int(v) for v in r['version'].split('.')))
    require(len({r['version'] for r in rows}) == len(rows), 'DUPLICATE_MIGRATION_VERSION_DENIED')
    return rows


def mcp_migrations(source_directory):
    rows = []
    directory = Path(source_directory)/'internal/adapter/postgres/migrations'
    for path in sorted(directory.iterdir()):
        require(path.is_file() and not path.is_symlink(), 'EXACT_MCP_MIGRATION_SOURCE_REQUIRED')
        match = re.fullmatch(r'([0-9]{3})_[a-z0-9_]+\.sql',path.name)
        require(match is not None and path.stat().st_size <= 1048576, 'BOUNDED_MCP_MIGRATION_REQUIRED')
        rows.append({'version':int(match[1]),'checksum':hashlib.sha256(path.read_bytes()).hexdigest()})
    require(1 <= len(rows) <= 256 and len({r['version'] for r in rows}) == len(rows),
            'COMPLETE_MCP_MIGRATION_MANIFEST_REQUIRED')
    return rows


def observe_database(container_id, user, database, module):
    require(module in MODULES, 'EXACT_COHORT_DATABASE_MODULE_REQUIRED')
    identifier(user)
    identifier(database)
    channel = Psql(container_id,user,database,'ouf-cutover-cohort-observe')
    try:
        identity = channel.query("SELECT json_build_object('name',current_database(),'oid',oid::bigint,'allowConnections',datallowconn,'prepared',(SELECT count(*) FROM pg_prepared_xacts WHERE database=current_database())) FROM pg_database WHERE datname=current_database()",timeout=10)
        schema = identifier(SCHEMAS[module])
        if module == 'mcp':
            expression = "SELECT COALESCE(json_agg(json_build_object('version',version,'checksum',checksum) ORDER BY version),'[]'::json) FROM "+schema+'.schema_migration'
        else:
            expression = "SELECT COALESCE(json_agg(json_build_object('version',version,'script',script,'type',type,'checksum',checksum,'success',success) ORDER BY installed_rank),'[]'::json) FROM "+schema+'.flyway_schema_history'
        migrations = channel.query(expression,timeout=10)
        require(type(identity) is dict and identity.get('name') == database
                and type(identity.get('oid')) is int and identity['oid'] > 0
                and identity.get('allowConnections') is True and identity.get('prepared') == 0
                and type(migrations) is list and 1 <= len(migrations) <= 256,
                'EXACT_DATABASE_IDENTITY_AND_HISTORY_REQUIRED')
        return {'identity':identity, 'migrations':migrations}
    finally:
        channel.close()


def compile_database_plan(pg_observation, module_bindings, candidate_migrations, current_observations):
    require(set(module_bindings) == set(candidate_migrations) == set(current_observations) == set(MODULES),
            'ALL_FOUR_COHORT_DATABASES_REQUIRED')
    pin = runtime_pin(pg_observation)
    rows = []
    for module in MODULES:
        binding, current, expected = module_bindings[module], current_observations[module], candidate_migrations[module]
        require(set(binding) == {'database','user'}, 'EXACT_DATABASE_BINDING_REQUIRED')
        identifier(binding['database'])
        identifier(binding['user'])
        before = current['migrations']
        # Flyway can record its creation of a previously absent schema at rank
        # one. It is retained in the signed history and post-install check, but
        # has no corresponding SQL file in the application JAR.
        marker = {'version':None,'script':'"'+SCHEMAS[module]+'"','type':'SCHEMA',
                  'checksum':None,'success':True}
        if module != 'mcp' and before and before[0] == marker:
            expected = [marker,*expected]
        require(current['identity']['name'] == binding['database'] and current['identity']['allowConnections'] is True
                and current['identity']['prepared'] == 0 and type(before) is list
                and type(expected) is list and 1 <= len(before) <= len(expected) <= 256
                and before == expected[:len(before)], 'INSTALLED_MIGRATION_PREFIX_MUST_MATCH_PACKAGED_BYTES')
        rows.append({'module':module, **binding, 'schema':SCHEMAS[module], 'databaseOid':current['identity']['oid'],
                     'beforeMigrations':copy.deepcopy(before),'expectedMigrations':copy.deepcopy(expected),
                     'pendingMigrationCount':len(expected)-len(before), 'maximumArchiveBytes':1073741824})
    require(len({r['database'] for r in rows}) == 4, 'SHARED_DATABASE_NEEDS_EXPLICIT_OWNER_FENCE')
    mcp = next(r for r in rows if r['module'] == 'mcp')
    if mcp['pendingMigrationCount']:
        require([r['version'] for r in mcp['expectedMigrations'][-3:]] == [10,11,12]
                and mcp['pendingMigrationCount'] == 3,
                'EXACT_MCP_AUDIT_ROLE_MIGRATION_REQUIRED')
        admin = environment(pg_observation['Config'].get('Env') or []).get('POSTGRES_USER','')
        identifier(admin)
    return {'schema':'ouf.chatbot-cohort-database-plan.v1','postgresRuntimeBinding':pin,
            'modules':rows,'automaticRestoreAllowed':False,'manualSqlMigrationAllowed':False,
            'mcpAuditRoleAdministration':({
                'role':'ouf_mcp_operational_audit_owner','admin':admin,
                'temporarySetMembership':True,'temporarySchemaCreate':True,
                'cleanupRequiredBeforeCohortStart':True} if mcp['pendingMigrationCount'] else None),
            'notReleaseAcceptance':True}


def mcp_backup_preflight(container_id, database, admin_user):
    """Read the exact selected backup principal; no GRANT or owner changes."""
    identifier(database); identifier(admin_user)
    channel = Psql(container_id,admin_user,database,'ouf-cutover-backup-reader')
    try:
        facts = channel.query("SELECT json_build_object('databaseOid',d.oid::bigint,"
            "'databaseMatched',current_database()="+literal(database)+","
            "'roleMatched',current_user="+literal(admin_user)+","
            "'superuser',r.rolsuper,'readOnly',current_setting('transaction_read_only')='on') "
            "FROM pg_database d CROSS JOIN pg_roles r WHERE d.datname=current_database() AND r.rolname=current_user",
            "BEGIN READ ONLY; SET LOCAL statement_timeout='10s';",timeout=15)
        require(type(facts) is dict and set(facts)=={'databaseOid','databaseMatched','roleMatched','superuser','readOnly'}
            and type(facts['databaseOid']) is int and facts['databaseOid']>0
            and all(facts[k] is True for k in ('databaseMatched','roleMatched','superuser','readOnly')),
            'MCP_BACKUP_ADMINISTRATIVE_READER_UNPROVEN')
        return facts
    finally:
        channel.close()


def compile_mcp_backup_reader(plan, facts):
    """Explicit changed plan for fresh review; never an error-triggered fallback.

    The previous database plan and application credentials remain intact. This
    opt-in is deliberately restricted to the already reviewed MCP administrator.
    It does not reconcile an old backup claim or grant runtime authority.
    """
    require('mcpBackupReader' not in plan,'BACKUP_READER_ALREADY_COMPILED')
    mcp = next(row for row in plan['modules'] if row['module']=='mcp')
    admin = (plan.get('mcpAuditRoleAdministration') or {}).get('admin')
    identifier(admin)
    expected = {'databaseOid':mcp['databaseOid'],'databaseMatched':True,
                'roleMatched':True,'superuser':True,'readOnly':True}
    require(facts==expected and type(facts.get('databaseOid')) is int,
            'MCP_BACKUP_READER_PREFLIGHT_DRIFT')
    following=copy.deepcopy(plan)
    following['mcpBackupReader']={'profile':'ouf.mcp-explicit-administrative-backup-reader.v1',
        'sourceDatabasePlanHash':digest(plan),'module':'mcp','user':admin,
        'database':mcp['database'],'databaseOid':mcp['databaseOid'],
        'preflight':copy.deepcopy(facts),'applicationPrivilegesChanged':False,
        'automaticFallbackAllowed':False}
    return following


def selected_backup_user(plan,binding):
    """Pure signed-plan validation. Runtime also repeats the owner preflight."""
    if 'mcpBackupReader' not in plan or binding['module']!='mcp':return binding['user']
    prior=copy.deepcopy(plan);reader=prior.pop('mcpBackupReader')
    require(compile_mcp_backup_reader(prior,reader.get('preflight'))==plan
        and binding==next(row for row in plan['modules'] if row['module']=='mcp'),
        'SIGNED_MCP_BACKUP_READER_DRIFT')
    return reader['user']


def dump_failure_reason(raw):
    """Only static categories reach delivery status; raw stderr stays private."""
    for pattern,code in (
        (rb'permission denied for (?:table|sequence|schema|relation)','INSUFFICIENT_PRIVILEGE'),
        (rb'query would be affected by row-level security policy','ROW_LEVEL_SECURITY'),
        (rb'password authentication failed|Peer authentication failed|no pg_hba.conf entry','AUTHENTICATION'),
        (rb'aborting because of server version mismatch','VERSION_MISMATCH'),
        (rb'canceling statement due to lock timeout','LOCK_TIMEOUT')):
        if re.search(pattern,raw):return 'COHORT_DATABASE_DUMP_'+code
    return 'COHORT_DATABASE_DUMP_FAILED'


def incident_metadata(application_user, omit_temporary=False):
    """Canonical ACL preserves existing privileges and ownership across cleanup.

    A superuser grant is recorded as the table owner's grant. Only the reviewed
    non-grantable TRIGGER edge to the application role may be excluded.
    """
    identifier(application_user)
    app = '(SELECT oid FROM pg_roles WHERE rolname='+literal(application_user)+')'
    edge = "a.grantee="+app+" AND a.grantor=c.relowner AND a.privilege_type='TRIGGER' AND NOT a.is_grantable"
    acl = ("COALESCE((SELECT jsonb_agg(jsonb_build_array(a.grantor,a.grantee,a.privilege_type,a.is_grantable) "
           "ORDER BY a.grantor,a.grantee,a.privilege_type,a.is_grantable) "
           "FROM aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a"+
           (' WHERE NOT ('+edge+')' if omit_temporary else '')+"),'[]'::jsonb)")
    return ("SELECT json_build_object('oid',c.oid::bigint,'ownerOid',c.relowner::bigint,"
            "'aclHash',encode(sha256(convert_to(("+acl+")::text,'UTF8')),'hex'),"
            "'triggerAuthority',has_table_privilege("+app+",c.oid,'TRIGGER'),"
            "'triggerGrantCount',(SELECT count(*) FROM aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a WHERE "+edge+")) "
            "FROM pg_class c WHERE c.oid=to_regclass('ouf_mcp.security_incident') AND c.relkind='r'")


def validate_incident_binding(value):
    require(type(value) is dict and set(value)=={'oid','ownerOid','aclHash','triggerAuthority','triggerGrantCount'}
            and all(type(value[k]) is int and value[k]>0 for k in ('oid','ownerOid'))
            and sha(value['aclHash']) and type(value['triggerAuthority']) is bool
            and type(value['triggerGrantCount']) is int and value['triggerGrantCount'] in (0,1),
            'EXACT_SECURITY_INCIDENT_TABLE_AND_ACL_REQUIRED')


def incident_guard(application_user, binding, omit_temporary=False):
    validate_incident_binding(binding)
    return ("LOCK TABLE ouf_mcp.security_incident IN SHARE ROW EXCLUSIVE MODE; "
            "DO $incident$ BEGIN IF ("+incident_metadata(application_user,omit_temporary)+")::jsonb "
            "IS DISTINCT FROM "+literal(json.dumps(binding,sort_keys=True,separators=(',',':')))+
            "::jsonb THEN RAISE EXCEPTION 'SECURITY_INCIDENT_BINDING_DRIFT'; END IF; END $incident$; ")


def mcp_admin_preflight(container_id, database, application_user, admin_user):
    """Read the selected PostgreSQL administrator and the role's exact absence."""
    identifier(database);identifier(application_user);identifier(admin_user)
    channel = Psql(container_id,admin_user,database,'ouf-cutover-cohort-admin-read')
    try:
        user = literal(application_user)
        role = literal('ouf_mcp_operational_audit_owner')
        facts = channel.query("SELECT json_build_object("
            "'serverVersion',current_setting('server_version_num')::int,"
            "'adminSuperuser',(SELECT rolsuper FROM pg_roles WHERE rolname=current_user),"
            "'adminRoleMatched',current_user="+literal(admin_user)+","
            "'applicationRoleExists',EXISTS(SELECT 1 FROM pg_roles WHERE rolname="+user+"),"
            "'auditRoleAbsent',NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname="+role+"),"
            "'applicationSchemaOwnerAuthority',EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='ouf_mcp' AND pg_has_role((SELECT oid FROM pg_roles WHERE rolname="+user+"),nspowner,'USAGE')) ,"
            "'applicationAuditTableOwnerAuthority',EXISTS(SELECT 1 FROM pg_class WHERE oid=to_regclass('ouf_mcp.audit_event') AND pg_has_role((SELECT oid FROM pg_roles WHERE rolname="+user+"),relowner,'USAGE')) ,"
            "'applicationAttemptTableOwnerAuthority',EXISTS(SELECT 1 FROM pg_class WHERE oid=to_regclass('ouf_mcp.tool_attempt') AND pg_has_role((SELECT oid FROM pg_roles WHERE rolname="+user+"),relowner,'USAGE')) ,"
            "'applicationIncidentTableOwnerAuthority',EXISTS(SELECT 1 FROM pg_class WHERE oid=to_regclass('ouf_mcp.security_incident') AND pg_has_role((SELECT oid FROM pg_roles WHERE rolname="+user+"),relowner,'USAGE')) ,"
            "'applicationAuditSequenceOwnerAuthority',EXISTS(SELECT 1 FROM pg_class WHERE oid=to_regclass('ouf_mcp.audit_event_sequence_id_seq') AND pg_has_role((SELECT oid FROM pg_roles WHERE rolname="+user+"),relowner,'USAGE')),"
            "'incidentBinding',("+incident_metadata(application_user)+"))")
        require(type(facts) is dict and facts.get('serverVersion',0) >= 170000
                and all(facts.get(key) is True for key in facts if key not in
                        ('serverVersion','applicationIncidentTableOwnerAuthority','incidentBinding'))
                and type(facts.get('applicationIncidentTableOwnerAuthority')) is bool
                and set(facts) == {'serverVersion','adminSuperuser','adminRoleMatched','applicationRoleExists','auditRoleAbsent',
                                   'applicationSchemaOwnerAuthority','applicationAuditTableOwnerAuthority',
                                   'applicationAttemptTableOwnerAuthority','applicationIncidentTableOwnerAuthority',
                                   'applicationAuditSequenceOwnerAuthority','incidentBinding'},
                'MCP_AUDIT_ROLE_ADMIN_PREFLIGHT_UNPROVEN')
        validate_incident_binding(facts['incidentBinding'])
        return facts
    finally:
        channel.close()


class CohortDatabases:
    def __init__(self,action,engine,journal,installation_plan,database_plan,directory,docker_binding):
        require(type(action) is AggregateAction and type(engine) is Engine and type(journal) is Journal,
                'REAL_COHORT_DATABASE_OWNERS_REQUIRED')
        require(digest(database_plan) == installation_plan['databasePlanHash']
                and database_plan.get('schema') == 'ouf.chatbot-cohort-database-plan.v1'
                and [r['module'] for r in database_plan['modules']] == list(MODULES),
                'SIGNED_COHORT_DATABASE_PLAN_REQUIRED')
        self.action,self.engine,self.journal = action,engine,journal
        self.installation_plan,self.plan = copy.deepcopy(installation_plan),copy.deepcopy(database_plan)
        self.scope,self.plan_hash = installation_scope(installation_plan),digest(database_plan)
        self.root,self.docker = Path(directory),copy.deepcopy(docker_binding)
        require(self.root.is_absolute() and self.root.resolve() == self.root
                and set(self.docker) == {'path','sha256'}, 'PRIVATE_COHORT_BACKUP_AND_EXACT_DOCKER_REQUIRED')
        self.root_id = None

    def guard(self):
        require(digest(self.plan) == self.plan_hash and installation_scope(self.installation_plan) == self.scope,
                'COHORT_DATABASE_INTENT_DRIFT')
        self.action.guard('applicationCohortInstallation', self.scope)
        info = self.root.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
                'COHORT_PRIVATE_BACKUP_CUSTODY_REQUIRED')
        binding = (info.st_dev,info.st_ino)
        require(self.root_id is None or self.root_id == binding, 'COHORT_BACKUP_DIRECTORY_REPLACED')
        self.root_id = binding
        binary = Path(self.docker['path'])
        info = binary.lstat()
        require(binary.is_absolute() and stat.S_ISREG(info.st_mode) and info.st_uid == 0
                and not info.st_mode & 0o022 and hashlib.sha256(binary.read_bytes()).hexdigest() == self.docker['sha256'],
                'COHORT_DATABASE_DOCKER_EXECUTABLE_DRIFT')
        pin = self.plan['postgresRuntimeBinding']
        code, actual = self.engine.request('GET','/v1.44/containers/'+pin['containerId']+'/json')
        require(code == 200 and Engine.runtime_binding(actual) == pin,
                'COHORT_POSTGRES_PROCESS_GENERATION_DRIFT')

    def initialize(self):
        self.guard()
        self.journal.initialize({'schema':'ouf.chatbot-cohort-database-journal.v1',
            'planHash':self.plan_hash,'authorityHash':self.action.authority_hash,
            'version':1,'backups':{},'mcpMigration':None,'mcpAuditRole':None,
            'budgetReset':False,'restorePerformed':False})

    def record(self):
        row = self.journal.read()
        require(row.get('schema') == 'ouf.chatbot-cohort-database-journal.v1' and row.get('planHash') == self.plan_hash
                and row.get('authorityHash') == self.action.authority_hash
                and row.get('restorePerformed') is False and row.get('budgetReset') is False,
                'COHORT_DATABASE_JOURNAL_DRIFT')
        recovery=row.get('governedGatewayRecovery')
        if recovery is not None:
            require(recovery.get('state')=='COMPLETE_ARCHIVES_AND_CHECKPOINTS_COPIED',
                'PARTIAL_GATEWAY_CHECKPOINT_ADOPTION_REQUIRES_RECONCILIATION')
        recovery=row.get('governedBackupRecovery')
        if recovery is not None:
            require(recovery.get('state')=='COMPLETE_ARCHIVES_COPIED_NEW_MCP_ATTEMPT_REQUIRED',
                'PARTIAL_BACKUP_ADOPTION_REQUIRES_RECONCILIATION')
        recovery=row.get('governedMigrationRecovery')
        if recovery is not None:
            require(recovery.get('state')=='COMPLETE_ARCHIVES_AND_CHECKPOINTS_COPIED',
                'PARTIAL_MIGRATION_ADOPTION_REQUIRES_RECONCILIATION')
        return row

    def quiescence(self):
        for row in self.installation_plan['replacements']:
            pin = row['oldRuntimeBinding']
            code, actual = self.engine.request('GET','/v1.44/containers/'+pin['containerId']+'/json')
            host = copy.deepcopy(row['oldHostConfig'])
            host['RestartPolicy'] = NO_RESTART
            require(code == 200 and actual['Id'] == pin['containerId'] and actual['Image'] == pin['imageId']
                    and digest(actual['Config']) == pin['configHash'] and digest(actual['HostConfig']) == digest(host)
                    and actual['State']['Running'] is False and actual['State']['Pid'] == 0
                    and actual['State']['StartedAt'] == pin['startedAt'], 'COHORT_PRODUCERS_MUST_REMAIN_QUIESCENT_DURING_BACKUP')

    def backup_quiesced(self):
        with self.journal.invocation():
            self.guard()
            self.quiescence()
            for binding in self.plan['modules']:
                module = binding['module']
                previous = self.record()
                if module in previous['backups']:
                    require(previous['backups'][module]['state'] == 'COMPLETE',
                            'PARTIAL_DATABASE_ARCHIVE_REQUIRES_RECONCILIATION_NOT_REPLAY')
                    self.verify_archive(binding,previous['backups'][module])
                    continue
                self.guard()
                self.quiescence()
                current = observe_database(self.plan['postgresRuntimeBinding']['containerId'],binding['user'],binding['database'],module)
                require(current['identity']['oid'] == binding['databaseOid']
                        and current['migrations'] == binding['beforeMigrations'], 'COHORT_DATABASE_CHANGED_BEFORE_BACKUP')
                following = copy.deepcopy(previous)
                following['version'] += 1
                following['backups'][module] = {'state':'CLAIMED','scopeHash':digest(binding)}
                self.journal.compare_and_save(previous,following)
                result = self.capture(binding)
                self.guard()
                self.quiescence()
                require(observe_database(self.plan['postgresRuntimeBinding']['containerId'],binding['user'],binding['database'],module) == current,
                        'COHORT_DATABASE_IDENTITY_CHANGED_DURING_BACKUP')
                previous = self.record()
                following = copy.deepcopy(previous)
                following['version'] += 1
                following['backups'][module] = result
                self.journal.compare_and_save(previous,following)
            result = self.record()
            return {'schema':'ouf.chatbot-cohort-private-backups.v1','planHash':self.plan_hash,
                    'journalHash':digest(result),'backupCount':len(result['backups']),
                    'restorePerformed':False,'notReleaseAcceptance':True}

    def capture(self,binding):
        user=selected_backup_user(self.plan,binding)
        cid = self.plan['postgresRuntimeBinding']['containerId']
        if binding['module']=='mcp' and 'mcpBackupReader' in self.plan:
            self.guard()
            require(mcp_backup_preflight(cid,binding['database'],user)==self.plan['mcpBackupReader']['preflight'],
                    'CURRENT_MCP_BACKUP_READER_DRIFT')
            self.guard()
        path = self.root/(binding['module']+'.dump')
        fd = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        args = [self.docker['path'],'--host','unix://'+self.engine.path,'--config',str(self.root),'exec',cid,'pg_dump','-U',user,
                '-d',binding['database'],'--format=custom','--no-owner','--no-acl','--lock-wait-timeout=10s']
        try:
            proc = subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        except Exception:
            os.close(fd)
            raise
        count,h,deadline = 0,hashlib.sha256(),time.monotonic()+90
        selector = selectors.DefaultSelector()
        selector.register(proc.stdout,selectors.EVENT_READ,'dump')
        selector.register(proc.stderr,selectors.EVENT_READ,'diagnostic')
        diagnostic=bytearray()
        try:
            with os.fdopen(fd,'wb') as output:
                while selector.get_map():
                    require(time.monotonic() < deadline,'COHORT_BACKUP_TIME_BOUND_EXHAUSTED')
                    for key,_ in selector.select(min(1,max(0,deadline-time.monotonic()))):
                        raw = os.read(key.fd,65536)
                        if not raw:
                            selector.unregister(key.fileobj);continue
                        if key.data=='diagnostic':
                            require(len(diagnostic)+len(raw)<=65536,'COHORT_BACKUP_DIAGNOSTIC_BOUND_EXHAUSTED')
                            diagnostic.extend(raw);continue
                        count += len(raw)
                        require(count <= binding['maximumArchiveBytes'],'COHORT_BACKUP_SIZE_BOUND_EXHAUSTED')
                        output.write(raw)
                        h.update(raw)
                require(proc.wait(timeout=5) == 0 and count > 100,dump_failure_reason(diagnostic))
                output.flush()
                os.fsync(output.fileno())
        finally:
            selector.close()
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
            proc.stdout.close()
            proc.stderr.close()
        self.guard()
        with path.open('rb') as stream:
            result = subprocess.run([self.docker['path'],'--host','unix://'+self.engine.path,'--config',str(self.root),'exec','-i',cid,
                                     'pg_restore','--file=/dev/null'],stdin=stream,
                                    stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=90)
        require(result.returncode == 0,'COHORT_COMPLETE_ARCHIVE_PAYLOAD_INVALID')
        directory = os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return {'state':'COMPLETE','scopeHash':digest(binding),'archiveSha256':h.hexdigest(),
                'archiveBytes':count,'payloadParsed':True}

    def verify_archive(self,binding,evidence):
        path = self.root/(binding['module']+'.dump')
        fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                    and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
                    and 100 < before.st_size <= binding['maximumArchiveBytes'], 'PRIVATE_COHORT_ARCHIVE_CUSTODY_DRIFT')
            h = hashlib.sha256()
            while raw := os.read(fd,65536):
                h.update(raw)
            after = os.fstat(fd)
            named = path.lstat()
            require((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns) == (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns)
                    == (named.st_dev,named.st_ino,named.st_size,named.st_mtime_ns)
                    and evidence == {'state':'COMPLETE','scopeHash':digest(binding),'archiveSha256':h.hexdigest(),
                                     'archiveBytes':before.st_size,'payloadParsed':True}, 'COHORT_ARCHIVE_CHANGED')
        finally:
            os.close(fd)

    def audit_role_state(self,binding,statement=''):
        """One local administrative channel; no host credential or SQL output."""
        admin = self.plan['mcpAuditRoleAdministration']['admin']; identifier(admin)
        temporary = self.plan['mcpAuditRoleAdministration']['temporaryIncidentTrigger']
        channel = Psql(self.plan['postgresRuntimeBinding']['containerId'],admin,
                       binding['database'],'ouf-cutover-cohort-audit-admin')
        try:
            app = literal(binding['user'])
            role = literal('ouf_mcp_operational_audit_owner')
            expression = ("SELECT json_build_object("
                "'adminSuperuser',(SELECT rolsuper FROM pg_roles WHERE rolname=current_user),"
                "'adminRoleMatched',current_user="+literal(admin)+","
                "'roleExists',EXISTS(SELECT 1 FROM pg_roles WHERE rolname="+role+"),"
                "'noLogin',COALESCE((SELECT NOT rolcanlogin AND NOT rolsuper AND NOT rolcreaterole FROM pg_roles WHERE rolname="+role+"),false),"
                "'schemaCreate',COALESCE((SELECT has_schema_privilege(oid,'ouf_mcp','CREATE') FROM pg_roles WHERE rolname="+role+"),false),"
                "'membershipCount',(SELECT count(*) FROM pg_auth_members WHERE roleid=(SELECT oid FROM pg_roles WHERE rolname="+role+")),"
                "'appMembership',(SELECT count(*) FROM pg_auth_members WHERE roleid=(SELECT oid FROM pg_roles WHERE rolname="+role+") AND member=(SELECT oid FROM pg_roles WHERE rolname="+app+") AND set_option AND NOT inherit_option AND NOT admin_option),"
                "'functionOwnerCount',(SELECT count(*) FROM pg_proc WHERE oid IN ("
                "to_regprocedure('ouf_mcp.capture_operational_attempt_audit()'),"
                "to_regprocedure('ouf_mcp.capture_operational_security_audit()')) "
                "AND proowner=(SELECT oid FROM pg_roles WHERE rolname="+role+")),"
                "'incidentBinding',("+incident_metadata(binding['user'],temporary)+"))")
            state = channel.query(expression,statement,timeout=15)
            require(type(state) is dict and state.get('adminSuperuser') is True and state.get('adminRoleMatched') is True,
                    'EXACT_MCP_AUDIT_ADMIN_CHANNEL_REQUIRED')
            self.incident_state(state)
            return state
        finally:
            channel.close()

    def incident_state(self,state,active=None):
        original = self.plan['mcpAuditRolePreflight']['incidentBinding']
        actual = state.get('incidentBinding');validate_incident_binding(original);validate_incident_binding(actual)
        require(all(actual[k]==original[k] for k in ('oid','ownerOid','aclHash')),
                'SECURITY_INCIDENT_OWNER_OR_PRIVILEGES_DRIFT')
        temporary = self.plan['mcpAuditRoleAdministration']['temporaryIncidentTrigger']
        require(type(temporary) is bool and temporary is (not original['triggerAuthority']),
                'EXACT_REVIEWED_INCIDENT_TRIGGER_DELTA_REQUIRED')
        if temporary:
            require(original['triggerGrantCount']==0,'INCIDENT_TRIGGER_BASELINE_CONFLICT')
            if active is not None:
                require(actual['triggerAuthority'] is active and actual['triggerGrantCount']==int(active),
                        'INCIDENT_TRIGGER_BOOTSTRAP_OR_CLEANUP_UNPROVEN')
        else:
            require(actual==original,'EXISTING_INCIDENT_PRIVILEGES_CHANGED')

    def prepare_mcp_audit_role(self,binding):
        expected = self.plan.get('mcpAuditRolePreflight')
        admin = self.plan['mcpAuditRoleAdministration'].get('admin');identifier(admin)
        temporary = not expected['incidentBinding']['triggerAuthority']
        require(self.plan.get('mcpAuditRoleAdministration') == {
            'role':'ouf_mcp_operational_audit_owner','admin':admin,'temporaryIncidentTrigger':temporary,
            'temporarySetMembership':True,'temporarySchemaCreate':True,
            'cleanupRequiredBeforeCohortStart':True}, 'SIGNED_MCP_AUDIT_ROLE_ADMINISTRATION_REQUIRED')
        previous = self.record()
        role = previous.get('mcpAuditRole')
        if role is None:
            require(mcp_admin_preflight(self.plan['postgresRuntimeBinding']['containerId'],
                                        binding['database'],binding['user'],admin) == expected,
                    'CURRENT_MCP_ADMIN_PREFLIGHT_CHANGED')
            following = copy.deepcopy(previous)
            following['version'] += 1
            following['mcpAuditRole'] = {'state':'BOOTSTRAP_CLAIMED',
                                          'intentHash':digest(self.plan['mcpAuditRoleAdministration'])}
            self.journal.compare_and_save(previous,following)
            sql = ('BEGIN; SET LOCAL lock_timeout=\'5s\'; '+incident_guard(binding['user'],expected['incidentBinding'])+
                   'CREATE ROLE ouf_mcp_operational_audit_owner NOLOGIN NOSUPERUSER NOCREATEROLE; '
                   'GRANT CREATE ON SCHEMA ouf_mcp TO ouf_mcp_operational_audit_owner; '
                   'GRANT ouf_mcp_operational_audit_owner TO '+identifier(binding['user'])+
                   ' WITH ADMIN FALSE, INHERIT FALSE, SET TRUE; '+
                   ('GRANT TRIGGER ON TABLE ouf_mcp.security_incident TO '+identifier(binding['user'])+'; ' if temporary else '')+
                   'COMMIT;')
            state = self.audit_role_state(binding,sql)
        else:
            require(role.get('intentHash') == digest(self.plan['mcpAuditRoleAdministration']),
                    'MCP_AUDIT_ROLE_RETAINED_INTENT_DRIFT')
            state = self.audit_role_state(binding)
        require(state['roleExists'] is True and state['noLogin'] is True
                and state['schemaCreate'] is True and state['membershipCount'] == 1
                and state['appMembership'] == 1 and state['functionOwnerCount'] in (0,2),
                'MCP_AUDIT_BOOTSTRAP_REQUIRES_RECONCILIATION')
        self.incident_state(state,True)
        previous = self.record()
        if previous['mcpAuditRole']['state'] == 'BOOTSTRAP_CLAIMED':
            following = copy.deepcopy(previous)
            following['version'] += 1
            following['mcpAuditRole']['state'] = 'BOOTSTRAPPED'
            self.journal.compare_and_save(previous,following)
        else:
            require(previous['mcpAuditRole']['state'] in ('BOOTSTRAPPED','CLEANUP_CLAIMED','CLEAN'),
                    'MCP_AUDIT_ROLE_STATE_DRIFT')

    def clean_mcp_audit_role(self,binding):
        previous = self.record()
        require(previous['mcpMigration']['state'] == 'COMPLETE'
                and previous['mcpAuditRole']['state'] in ('BOOTSTRAPPED','CLEANUP_CLAIMED','CLEAN'),
                'MCP_AUDIT_ROLE_CLEANUP_ORDER_REQUIRED')
        if previous['mcpAuditRole']['state'] == 'BOOTSTRAPPED':
            state = self.audit_role_state(binding)
            self.incident_state(state,True)
            require(state['roleExists'] is True and state['noLogin'] is True
                    and state['schemaCreate'] is True and state['membershipCount'] == 1
                    and state['appMembership'] == 1 and state['functionOwnerCount'] == 2,
                    'MCP_AUDIT_ROLE_PRE_CLEANUP_DRIFT')
            following = copy.deepcopy(previous)
            following['version'] += 1
            following['mcpAuditRole']['state'] = 'CLEANUP_CLAIMED'
            self.journal.compare_and_save(previous,following)
            temporary=self.plan['mcpAuditRoleAdministration']['temporaryIncidentTrigger']
            sql = ('BEGIN; SET LOCAL lock_timeout=\'5s\'; '+incident_guard(binding['user'],state['incidentBinding'],temporary)+
                   'REVOKE ouf_mcp_operational_audit_owner FROM '+identifier(binding['user'])+'; '
                   'REVOKE CREATE ON SCHEMA ouf_mcp FROM ouf_mcp_operational_audit_owner; '+
                   ('REVOKE TRIGGER ON TABLE ouf_mcp.security_incident FROM '+identifier(binding['user'])+'; ' if temporary else '')+
                   'COMMIT;')
            state = self.audit_role_state(binding,sql)
        else:
            state = self.audit_role_state(binding)
        require(state['roleExists'] is True and state['noLogin'] is True
                and state['schemaCreate'] is False and state['membershipCount'] == 0
                and state['appMembership'] == 0 and state['functionOwnerCount'] == 2,
                'MCP_AUDIT_ROLE_CLEANUP_REQUIRES_RECONCILIATION')
        self.incident_state(state,False)
        previous = self.record()
        if previous['mcpAuditRole']['state'] == 'CLEANUP_CLAIMED':
            following = copy.deepcopy(previous)
            following['version'] += 1
            following['mcpAuditRole']['state'] = 'CLEAN'
            self.journal.compare_and_save(previous,following)

    def migrate_mcp(self):
        """Run the package's separate, finite MCP migration role after backup.

        A claimed create/start is never replayed. On a resumed invocation the
        retained native container and database history must prove completion.
        """
        binding = next(r for r in self.plan['modules'] if r['module'] == 'mcp')
        row = next(r for r in self.installation_plan['replacements'] if r['module'] == 'mcp')
        suffix = row['retiredName'].removeprefix('ouf-mcp-before-')
        require(suffix and re.fullmatch('[a-z0-9-]{1,60}',suffix), 'EXACT_MCP_MIGRATION_COHORT_REQUIRED')
        name = 'ouf-mcp-migrate-'+suffix
        values = [v for v in row['creationRequest']['Env'] if v.startswith('MCP_DATABASE_URL=')]
        require(len(values) == 1 and row['creationRequest']['User'] == '10005:10005'
                and row['creationRequest']['Entrypoint'] == ['/usr/local/bin/ouf-mcp']
                and row['creationRequest']['Image'].startswith('sha256:'),
                'EXACT_PACKAGED_MCP_MIGRATION_ROLE_REQUIRED')
        endpoint = row['creationRequest']['NetworkingConfig']['EndpointsConfig']['ouf-backend']
        request = {'Image':row['creationRequest']['Image'],'User':'10005:10005',
                   'Entrypoint':['/usr/local/bin/ouf-mcp'],'Cmd':['migrate'],
                   'WorkingDir':'/app','Env':values,
                   'Labels':{'it.ouf.file-cohort':suffix,'it.ouf.role':'mcp-migration'},
                   'HostConfig':{'NetworkMode':'ouf-backend','RestartPolicy':{'Name':'no','MaximumRetryCount':0},
                                 'AutoRemove':False,'ReadonlyRootfs':True},
                   'NetworkingConfig':{'EndpointsConfig':{'ouf-backend':{'NetworkID':endpoint['NetworkID']}}}}
        intent = digest(request)

        def current():
            self.guard(); self.quiescence()
            state = observe_database(self.plan['postgresRuntimeBinding']['containerId'],
                                     binding['user'],binding['database'],'mcp')
            require(state['identity']['oid'] == binding['databaseOid'], 'MCP_DATABASE_IDENTITY_DRIFT')
            return state['migrations']

        def native():
            status, actual = self.engine.request('GET','/v1.44/containers/'+quote(name,safe='')+'/json')
            require(status in (200,404), 'MCP_MIGRATION_CONTAINER_READ_UNAVAILABLE')
            if status == 404:return None
            if self.record().get('governedMigrationRecovery') is not None:
                from tools.chatbot_file_cohort.migration_recovery import native as recovered_native
                return recovered_native(self,request,name,actual)
            require(actual['Name'] == '/'+name and actual['Image'] == request['Image']
                    and all(actual['Config'].get(k) == request[k] for k in
                            ('User','Entrypoint','Cmd','WorkingDir','Env','Labels'))
                    and actual['HostConfig'].get('NetworkMode') == 'ouf-backend'
                    and actual['HostConfig'].get('ReadonlyRootfs') is True
                    and actual['HostConfig'].get('Privileged') is False
                    and actual['HostConfig'].get('AutoRemove') is False
                    and actual.get('Mounts') == []
                    and actual['NetworkSettings']['Networks']['ouf-backend']['NetworkID'] == endpoint['NetworkID'],
                    'MCP_MIGRATION_ROLE_NATIVE_IDENTITY_DRIFT')
            return actual

        with self.journal.invocation():
            self.guard(); self.quiescence()
            backup = self.record()['backups'].get('mcp')
            require(backup is not None and backup.get('state') == 'COMPLETE',
                    'MCP_MIGRATION_REQUIRES_COMPLETE_BACKUP')
            self.verify_archive(binding,backup)
            previous = self.record()
            claim = previous.get('mcpMigration')
            if binding['pendingMigrationCount'] == 0:
                require(claim is None and current() == binding['expectedMigrations'],
                        'MCP_UNEXPECTED_MIGRATION_HISTORY')
                return {'pendingMigrationCount':0,'historyHash':digest(binding['expectedMigrations'])}
            role_state = previous.get('mcpAuditRole') or {}
            if previous.get('governedMigrationRecovery') is not None:
                require(role_state.get('state') in ('BOOTSTRAPPED','CLEANUP_CLAIMED','CLEAN'),
                    'RETAINED_AUDIT_BOOTSTRAP_MUST_NOT_REPEAT')
                if role_state['state']=='BOOTSTRAPPED':
                    state=self.audit_role_state(binding)
                    require(state['roleExists'] and state['noLogin'] and state['schemaCreate']
                        and state['appMembership']==state['membershipCount']==1,'RETAINED_AUDIT_PRIVILEGES_DRIFT')
                    self.incident_state(state,True)
            elif role_state.get('state') not in ('CLEANUP_CLAIMED','CLEAN'):
                self.prepare_mcp_audit_role(binding)
            previous = self.record()
            claim = previous.get('mcpMigration')
            if claim is None:
                require(previous.get('governedMigrationRecovery') is None,'MIGRATION_RECOVERY_CREATE_DENIED')
                require(current() == binding['beforeMigrations'] and native() is None,
                        'MCP_MIGRATION_PRECONDITION_DRIFT')
                following = copy.deepcopy(previous)
                following['version'] += 1
                following['mcpMigration'] = {'state':'CLAIMED','name':name,'intentHash':intent}
                self.journal.compare_and_save(previous,following)
                status, created = self.engine.request('POST','/v1.44/containers/create?name='+quote(name,safe=''),request)
                require(status == 201 and type(created) is dict and sha(created.get('Id')),
                        'MCP_MIGRATION_CREATION_REQUIRES_RECONCILIATION')
                actual = native()
                require(actual is not None and actual['Id'] == created['Id']
                        and actual['State']['Status'] == 'created', 'MCP_MIGRATION_CREATION_NOT_PROVEN')
                status, _ = self.engine.request('POST','/v1.44/containers/'+created['Id']+'/start')
                require(status == 204, 'MCP_MIGRATION_START_REQUIRES_RECONCILIATION')
            else:
                require(claim.get('name') == name and claim.get('intentHash') == intent
                        and claim.get('state') in ('CLAIMED','COMPLETE'),
                        'MCP_MIGRATION_RETAINED_INTENT_DRIFT')
            if previous.get('governedMigrationRecovery') is not None:
                from tools.chatbot_file_cohort.migration_recovery import start_existing
                start_existing(self,request,name,native(),current)
            deadline = time.monotonic()+120
            while True:
                self.guard();self.quiescence()
                actual = native()
                require(actual is not None, 'MCP_MIGRATION_ABSENT_REQUIRES_HUMAN_RECONCILIATION')
                state = actual['State']
                if state['Status'] == 'exited':
                    require(state['ExitCode'] == 0 and state['Pid'] == 0 and actual['RestartCount'] == 0,
                            'MCP_MIGRATION_EXIT_REQUIRES_HUMAN_RECONCILIATION')
                    break
                require(state['Status'] == 'running' and time.monotonic() < deadline,
                        'MCP_MIGRATION_INCOMPLETE_REQUIRES_RECONCILIATION')
                time.sleep(2)
            require(current() == binding['expectedMigrations'], 'MCP_MIGRATION_HISTORY_NOT_PACKAGED')
            previous = self.record()
            if previous['mcpMigration']['state'] == 'CLAIMED':
                following = copy.deepcopy(previous)
                following['version'] += 1
                following['mcpMigration'] = {'state':'COMPLETE','name':name,'intentHash':intent,
                                             'containerId':actual['Id'],
                                             'historyHash':digest(binding['expectedMigrations'])}
                self.journal.compare_and_save(previous,following)
            else:
                require(previous['mcpMigration']['containerId'] == actual['Id']
                        and previous['mcpMigration']['historyHash'] == digest(binding['expectedMigrations']),
                        'MCP_MIGRATION_RETAINED_PROOF_DRIFT')
            self.clean_mcp_audit_role(binding)
            return {'pendingMigrationCount':binding['pendingMigrationCount'],
                    'historyHash':digest(binding['expectedMigrations']),'containerId':actual['Id']}

    def verify_module(self,module):
        self.guard()
        require(module in MODULES, 'EXACT_COHORT_DATABASE_MODULE_REQUIRED')
        binding = next(r for r in self.plan['modules'] if r['module'] == module)
        backup = self.record()['backups'].get(module)
        require(backup is not None and backup.get('state') == 'COMPLETE','COMPLETE_MODULE_BACKUP_REQUIRED')
        self.verify_archive(binding,backup)
        current = observe_database(self.plan['postgresRuntimeBinding']['containerId'],binding['user'],binding['database'],module)
        require(current['identity']['oid'] == binding['databaseOid']
                and current['migrations'] == binding['expectedMigrations'], 'COHORT_INSTALLED_SCHEMA_NOT_PACKAGED_VERSION')
        self.guard()
        return {'schema':'ouf.chatbot-cohort-current-schema.v1','module':module,'databasePlanHash':self.plan_hash,
                'databaseOid':binding['databaseOid'],'migrationHistoryHash':digest(current['migrations']),
                'migrationCount':len(current['migrations']),'notReleaseAcceptance':True}
