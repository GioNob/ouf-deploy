"""Private cohort backups and exact owner migration verification.

Java applications keep their own Flyway migrations. MCP's existing schema must
already match its embedded migration bytes; no root SQL substitutes for its
separate migration role. No automatic database restore or repair is provided.
"""
import copy
import hashlib
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import time
import zipfile
import zlib

from database_gate import Psql, identifier, literal
from engine_creation import Engine
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.chatbot_file_cohort.plan import MODULES, NO_RESTART, digest, require, sha, runtime_pin
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
        require(module != 'mcp' or before == expected, 'MCP_MIGRATION_ROLE_REQUIRED_FOR_SCHEMA_UPGRADE')
        rows.append({'module':module, **binding, 'schema':SCHEMAS[module], 'databaseOid':current['identity']['oid'],
                     'beforeMigrations':copy.deepcopy(before),'expectedMigrations':copy.deepcopy(expected),
                     'pendingMigrationCount':len(expected)-len(before), 'maximumArchiveBytes':1073741824})
    require(len({r['database'] for r in rows}) == 4, 'SHARED_DATABASE_NEEDS_EXPLICIT_OWNER_FENCE')
    return {'schema':'ouf.chatbot-cohort-database-plan.v1','postgresRuntimeBinding':pin,
            'modules':rows,'automaticRestoreAllowed':False,'manualSqlMigrationAllowed':False,
            'notReleaseAcceptance':True}


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
            'version':1,'backups':{},'budgetReset':False,'restorePerformed':False})

    def record(self):
        row = self.journal.read()
        require(row.get('schema') == 'ouf.chatbot-cohort-database-journal.v1' and row.get('planHash') == self.plan_hash
                and row.get('authorityHash') == self.action.authority_hash
                and row.get('restorePerformed') is False and row.get('budgetReset') is False,
                'COHORT_DATABASE_JOURNAL_DRIFT')
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
        path = self.root/(binding['module']+'.dump')
        fd = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        cid = self.plan['postgresRuntimeBinding']['containerId']
        args = [self.docker['path'],'--host','unix://'+self.engine.path,'--config',str(self.root),'exec',cid,'pg_dump','-U',binding['user'],
                '-d',binding['database'],'--format=custom','--no-owner','--no-acl','--lock-wait-timeout=10s']
        try:
            proc = subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        except Exception:
            os.close(fd)
            raise
        count,h,deadline = 0,hashlib.sha256(),time.monotonic()+90
        selector = selectors.DefaultSelector()
        selector.register(proc.stdout,selectors.EVENT_READ)
        try:
            with os.fdopen(fd,'wb') as output:
                while True:
                    require(time.monotonic() < deadline,'COHORT_BACKUP_TIME_BOUND_EXHAUSTED')
                    if not selector.select(min(1,max(0,deadline-time.monotonic()))):
                        continue
                    raw = os.read(proc.stdout.fileno(),65536)
                    if not raw:
                        break
                    count += len(raw)
                    require(count <= binding['maximumArchiveBytes'],'COHORT_BACKUP_SIZE_BOUND_EXHAUSTED')
                    output.write(raw)
                    h.update(raw)
                require(proc.wait(timeout=5) == 0 and count > 100,'COHORT_DATABASE_DUMP_FAILED')
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
