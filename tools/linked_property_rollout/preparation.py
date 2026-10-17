"""Private, installation-bound release preparation. No runtime mutations.

Native Flyway remains the migration owner. This code only checks inputs and
catalog privileges and writes a new private review; it never starts applications,
executes DDL, signs authority, publishes a profile or replays domain decisions.
"""
import hashlib
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import zipfile
import zlib

DOCUMENT_LIMIT = 8388608
PACKAGE_LIMIT = 1200000000
MODULES = ('udp', 'onboarding')


def require(ok, code):
    if not ok:
        raise ValueError(code)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def parsed(raw):
    def unique(rows):
        result = {}
        for k, v in rows:
            require(k not in result, 'DUPLICATE_JSON_KEY')
            result[k] = v
        return result
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: require(False, 'FINITE_JSON_REQUIRED'))


def file_pin(s):
    return tuple(getattr(s, k) for k in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid',
                                        'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def root_directory(path):
    path = Path(path)
    require(path.is_absolute() and path.resolve() == path, 'EXACT_ROOT_DIRECTORY_REQUIRED')
    for p in (path, *path.parents):
        s = p.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022,
                'ROOT_DIRECTORY_CUSTODY_REQUIRED')


def read_file(path, expected, maximum=DOCUMENT_LIMIT, protected=True):
    path = Path(path)
    if protected:
        root_directory(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and 0 < s.st_size <= maximum,
                'BOUNDED_REGULAR_INPUT_REQUIRED')
        if protected:
            require(s.st_uid == 0 and not s.st_mode & 0o022, 'ROOT_INPUT_CUSTODY_REQUIRED')
        raw = bytearray()
        while len(raw) <= maximum:
            block = os.read(fd, min(65536, maximum + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        require(len(raw) == s.st_size and file_pin(s) == file_pin(os.fstat(fd))
                and hashlib.sha256(raw).hexdigest() == expected, 'INPUT_BYTE_DRIFT')
        return bytes(raw)
    finally:
        os.close(fd)


def write_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(os.dup(fd), 'wb') as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(fd)


def document(context, name, value):
    require(name in ('prepared-plan.json', 'review.json'), 'EXACT_PRIVATE_DOCUMENT_REQUIRED')
    raw = encoded(value)
    require(0 < len(raw) <= DOCUMENT_LIMIT, 'PRIVATE_DOCUMENT_BOUND_EXHAUSTED')
    write_new(context / name, raw)
    fd = os.open(context, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    binding = {'path': str(context / name), 'sha256': hashlib.sha256(raw).hexdigest()}
    require(read_file(binding['path'], binding['sha256']) == raw, 'PRIVATE_DOCUMENT_READBACK_FAILED')
    return binding


def runtime(actual):
    return {'containerId': actual['Id'], 'imageId': actual['Image'],
            'pid': actual['State']['Pid'], 'startedAt': actual['State']['StartedAt'],
            **{name + 'Hash': digest(actual[key]) for name, key in
               (('config', 'Config'), ('hostConfig', 'HostConfig'), ('mounts', 'Mounts'),
                ('networkSettings', 'NetworkSettings'))}}


def application_checks(actual, expected, config_hash):
    """Compare one API1.44 observation without removing compatibility fields."""
    if not actual:
        return {'containerPresent': False}
    return {
        'containerPresent': True,
        'running': actual['State']['Running'] is True,
        'notPaused': actual['State']['Paused'] is False,
        'containerIdMatches': actual['Id'] == expected['containerId'],
        'imageIdMatches': actual['Image'] == expected['imageId'],
        'sourceCommitMatches': actual['Config'].get('Labels', {}).get('org.opencontainers.image.revision') == expected['sourceCommit'],
        'configurationHashMatches': digest(actual['Config']) == config_hash,
    }


def copy_package(source, target, expected):
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and 0 < before.st_size <= PACKAGE_LIMIT, 'BOUNDED_PACKAGE_REQUIRED')
        out = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        count, h = 0, hashlib.sha256()
        with os.fdopen(out, 'wb') as dest:
            while True:
                block = os.read(fd, 1048576)
                if not block:
                    break
                count += len(block)
                require(count <= PACKAGE_LIMIT, 'PACKAGE_SIZE_BOUND_EXHAUSTED')
                h.update(block)
                dest.write(block)
            dest.flush()
            os.fsync(dest.fileno())
        require(count == before.st_size and file_pin(before) == file_pin(os.fstat(fd))
                and h.hexdigest() == expected, 'QUALIFIED_PACKAGE_DIGEST_CHANGED')
    finally:
        os.close(fd)


def zip_index(archive):
    result = {}
    names = set()
    for row in archive.infolist():
        p = PurePosixPath(row.filename)
        require(str(p) == row.filename.rstrip('/') and not p.is_absolute() and '..' not in p.parts
                and row.filename not in names and not row.flag_bits & 1
                and stat.S_IFMT(row.external_attr >> 16) in (0, stat.S_IFREG, stat.S_IFDIR)
                and row.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                and 0 <= row.file_size <= PACKAGE_LIMIT, 'SAFE_UNIQUE_PACKAGE_MEMBER_REQUIRED')
        names.add(row.filename)
        require(len(names) <= 4096, 'PACKAGE_MEMBER_COUNT_EXHAUSTED')
        if not row.is_dir():
            result[row.filename] = row
    require(0 < len(result) <= 4096 and sum(r.file_size for r in result.values()) <= PACKAGE_LIMIT,
            'PACKAGE_EXPANSION_BOUND_EXHAUSTED')
    return result


def member(archive, index, name, maximum):
    require(name in index and index[name].file_size <= maximum, 'BOUNDED_PACKAGE_MEMBER_REQUIRED')
    return archive.read(name)


def verify_package(archive, index):
    mapping = {}
    for line in member(archive, index, 'SHA256SUMS', 1048576).decode('ascii').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        require(match is not None and match[2] not in mapping, 'UNIQUE_HASH_MANIFEST_REQUIRED')
        mapping[match[2]] = match[1]
    require(set(mapping) == set(index) - {'SHA256SUMS', 'SHA256SUMS.sigstore.json'}
            and 'SHA256SUMS.sigstore.json' in index, 'COMPLETE_PACKAGE_MANIFEST_REQUIRED')
    for name, expected in mapping.items():
        h = hashlib.sha256()
        with archive.open(name) as stream:
            while block := stream.read(1048576):
                h.update(block)
        require(h.hexdigest() == expected, 'PACKAGE_MEMBER_HASH_CHANGED')
    return mapping


def extract(archive, index, name, target):
    require(name in index, 'EXACT_PACKAGE_MEMBER_REQUIRED')
    with archive.open(name) as src, target.open('xb') as dest:
        os.chmod(target, 0o600)
        shutil.copyfileobj(src, dest, 1048576)
        dest.flush()
        os.fsync(dest.fileno())


def migration_rows(jar):
    rows = []
    with zipfile.ZipFile(jar) as archive:
        members = [r for r in archive.infolist()
                   if r.filename.startswith('BOOT-INF/classes/db/migration/') and not r.is_dir()]
        require(1 <= len(members) <= 256 and sum(r.file_size for r in members) <= DOCUMENT_LIMIT,
                'BOUNDED_MIGRATION_SET_REQUIRED')
        for row in members:
            name = row.filename.split('/')[-1]
            match = re.fullmatch(r'V([1-9][0-9]*)__[A-Za-z0-9_]+\.sql', name)
            require(match is not None and row.filename == 'BOOT-INF/classes/db/migration/' + name,
                    'EXACT_VERSIONED_MIGRATION_REQUIRED')
            raw = archive.read(row)
            text = raw.decode('utf-8').removeprefix('\ufeff')
            value = zlib.crc32(''.join(re.split(r'\r\n|\n|\r', text)).encode())
            rows.append({'version': match[1], 'script': name, 'checksum': value if value < 2**31 else value - 2**32,
                         'success': True, 'sha256': hashlib.sha256(raw).hexdigest()})
    rows.sort(key=lambda r: int(r['version']))
    require(len({r['version'] for r in rows}) == len(rows), 'DUPLICATE_MIGRATION_VERSION')
    return rows


def verify_history(observed, expected, schema, allow_existing_schema=False):
    require(type(observed) is list and observed, 'INSTALLED_HISTORY_REQUIRED')
    marker = {'installed_rank': 0, 'version': None, 'script': '"' + schema + '"',
              'checksum': None, 'success': True}
    if observed[0] == marker:
        observed = observed[1:]
    else:
        require(allow_existing_schema, 'EXACT_SCHEMA_CREATION_REQUIRED')
    require(len(observed) == len(expected), 'EXACT_MIGRATION_COUNT_REQUIRED')
    for rank, (actual, migration) in enumerate(zip(observed, expected), 1):
        require(actual == {'installed_rank': rank, **{k: migration[k] for k in
                        ('version', 'script', 'checksum', 'success')}}, 'INSTALLED_MIGRATION_PREFIX_CHANGED')


def bounded(argv):
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    output, error = bytearray(), bytearray()
    deadline = time.monotonic() + 25
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ, output)
            selector.register(proc.stderr, selectors.EVENT_READ, error)
            while selector.get_map():
                require(time.monotonic() < deadline, 'SQL_READ_DEADLINE_EXHAUSTED')
                for key, _ in selector.select(0.2):
                    raw = os.read(key.fd, 65536)
                    if not raw:
                        selector.unregister(key.fileobj)
                    else:
                        key.data.extend(raw)
                        require(len(key.data) <= 131072, 'SQL_OUTPUT_BOUND_EXHAUSTED')
            require(proc.wait(timeout=2) == 0, 'READ_ONLY_SQL_FAILED')
        return parsed(output)
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=5)
        proc.stdout.close()
        proc.stderr.close()


def database_facts(ns, prepared, executable, module, config_directory):
    plan = prepared['databasePlan']
    binding = next(r for r in plan['modules'] if r['module'] == module)
    admin = plan['mcpAuditRoleAdministration']['admin']
    app, schema = binding['user'], binding['schema']
    require(all(type(v) is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,62}', v)
                for v in (admin, app, schema, binding['database'])), 'EXACT_DATABASE_IDENTIFIERS_REQUIRED')
    privileges = ''
    if module == 'udp':
        privileges = f""",'rolePreflight',jsonb_build_object(
          'applicationRoleExists',exists(select 1 from pg_roles where rolname='{app}'),
          'applicationSuperuser',(select rolsuper from pg_roles where rolname='{app}'),
          'ownsPropertyValue',(select pg_get_userbyid(relowner)='{app}' from pg_class where oid='{schema}.property_value'::regclass),
          'schemaUsage',has_schema_privilege('{app}','{schema}','USAGE'),
          'schemaCreate',has_schema_privilege('{app}','{schema}','CREATE'),
          'referenceHandoff',has_table_privilege('{app}','{schema}.handoff_intake','REFERENCES'),
          'executeAppendOnly',has_function_privilege('{app}','{schema}.reject_append_only_mutation()','EXECUTE'),
          'insertHistory',has_table_privilege('{app}','{schema}.flyway_schema_history','INSERT'),
          'selectHistory',has_table_privilege('{app}','{schema}.flyway_schema_history','SELECT')),
          'profileTablePresent',to_regclass('{schema}.handoff_property_profile') is not null,
          'evidenceColumnPresent',exists(select 1 from information_schema.columns where table_schema='{schema}' and table_name='property_value' and column_name='reconciliation_evidence')"""
    sql = f"""BEGIN READ ONLY; SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='3s';
      SELECT jsonb_build_object('database',current_database(),'databaseOid',(select oid::bigint from pg_database where datname=current_database()),
       'role',current_user,'transactionReadOnly',current_setting('transaction_read_only')='on',
       'applicationRole','{app}','databaseBytes',pg_database_size(current_database()),
       'preparedTransactions',(select count(*) from pg_prepared_xacts where database=current_database()),
       'migrations',(select jsonb_agg(x order by installed_rank) from (select installed_rank,version,script,checksum,success from {schema}.flyway_schema_history order by installed_rank limit 100)x)
       {privileges}); ROLLBACK;"""
    pg = plan['postgresRuntimeBinding']
    actual = ns['engine_get'](prepared['engine'], 'containers', pg['containerId'])
    require(actual and actual['State']['Running'] and not actual['State']['Paused'] and runtime(actual) == pg,
            'EXACT_POSTGRES_GENERATION_REQUIRED')
    require([r.split('=', 1)[1] for r in actual['Config']['Env'] if r.startswith('POSTGRES_USER=')] == [admin],
            'EXACT_EXISTING_ADMINISTRATOR_REQUIRED')
    args = [executable, '--host', 'unix://' + prepared['engine']['socketPath'], '--config', str(config_directory),
            'exec', pg['containerId'],
            'env', 'LC_ALL=C', 'PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=10000 -c lock_timeout=3000',
            'timeout', '-s', 'KILL', '20', 'psql', '-X', '-q', '-A', '-t', '-v', 'ON_ERROR_STOP=1',
            '-U', admin, '-d', binding['database'], '-c', sql]
    facts = bounded(args)
    require(facts['database'] == binding['database'] and facts['databaseOid'] == binding['databaseOid']
            and facts['role'] == admin and facts['transactionReadOnly'] is True and facts['preparedTransactions'] == 0,
            'DATABASE_IDENTITY_OR_PREPARED_TRANSACTION_CHANGED')
    return facts


def containerd_store(engine):
    def guard():
        s = os.stat(engine['socketPath'], follow_symlinks=False)
        require(stat.S_ISSOCK(s.st_mode) and (s.st_dev, s.st_ino, s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode))
                == tuple(engine['socketBinding']), 'ENGINE_SOCKET_CHANGED')
    class Local(http.client.HTTPConnection):
        def connect(self):
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.settimeout(10)
            self.sock.connect(engine['socketPath'])
    guard()
    conn = Local('localhost', timeout=10)
    try:
        conn.request('GET', '/v1.44/info')
        response = conn.getresponse()
        raw = response.read(2097153)
        require(response.status == 200 and len(raw) <= 2097152, 'ENGINE_INFO_UNAVAILABLE')
        guard()
        info = parsed(raw)
        containerd = info.get('Driver') == 'overlayfs' and dict(info.get('DriverStatus') or []).get('driver-type') == 'io.containerd.snapshotter.v1'
        require(containerd or info.get('Driver') == 'overlay2', 'NATIVE_IMAGE_STORE_UNQUALIFIED')
        return containerd
    finally:
        conn.close()


def candidate(archive_path, context, release, manifest, custody, containerd, progress):
    copy_package(archive_path, context / 'candidate.zip', release['package']['githubArtifactDigest'].removeprefix('sha256:'))
    result = {}
    with zipfile.ZipFile(context / 'candidate.zip') as archive:
        index = zip_index(archive)
        hashes = verify_package(archive, index)
        lock = member(archive, index, 'source-lock.json', 1048576)
        require(hashlib.sha256(lock).hexdigest() == release['package']['sourceLockSha256'], 'SOURCE_LOCK_CHANGED')
        sources = {r['module']: r['commit'] for r in parsed(lock)['modules']}
        require(set(sources) == set(MODULES), 'EXACT_RELEASE_MODULES_REQUIRED')
        for module in MODULES:
            target = context / module
            target.mkdir(mode=0o700)
            prefix = 'parts/linked-property-part-' + module + '-' + str(release['package']['runId']) + '/'
            meta = parsed(member(archive, index, prefix + 'candidate-manifest.json', 1048576))
            require(meta['imageId'] == release['candidateImageIds'][module] and meta['sourceCommit'] == sources[module]
                    and meta['module'] == module and meta['sourceLockSha256'] == release['package']['sourceLockSha256']
                    and meta['scanGate'] == 'PASS_HIGH_CRITICAL_UNKNOWN_INCLUDING_UNFIXED'
                    and meta['targetApplyAuthorized'] is False and meta['runtimeAuthorityIssued'] is False,
                    'EXACT_QUALIFIED_CANDIDATE_REQUIRED')
            jar = target / 'application.jar'
            extract(archive, index, prefix + 'application.jar', jar)
            migrations = migration_rows(jar)
            if module == 'udp':
                require([{k: r[k] for k in ('version', 'script', 'checksum', 'success')} for r in migrations]
                        == manifest['migrations'] and migrations[-1]['sha256'] == release['migrationQualification']['migrationSha256'],
                        'PACKAGED_UDP_MIGRATIONS_CHANGED')
            original, derived = target / 'original.tar', target / 'candidate.tagless.tar'
            extract(archive, index, prefix + 'image.docker.tar', original)
            with original.open('rb') as source:
                audit = custody['archive'](source, hashes[prefix + 'image.docker.tar'], meta['imageId'], sources[module])
                with derived.open('x+b') as dest:
                    os.chmod(derived, 0o600)
                    converted = custody['tagless_archive'](source, dest, audit, containerd=containerd)
                    dest.flush()
                    os.fsync(dest.fileno())
            with derived.open('rb') as source:
                audit = custody['archive'](source, converted['derivedArchiveSha256'], meta['imageId'], sources[module])
            require(not audit['repositoryTags'], 'TAGLESS_IMAGE_REQUIRED')
            if containerd:
                audit['nativeIdentity'] = custody['native_identity'](audit)
            original.unlink()
            result[module] = {'metadata': meta, 'migrations': migrations, 'imageAudit': audit,
                              'imageArchive': {'path': str(derived), 'sha256': converted['derivedArchiveSha256']},
                              'nativeImageId': custody['runtime_image_id'](audit),
                              'jar': {'path': str(jar), 'sha256': hashes[prefix + 'application.jar']}}
            progress('CANDIDATE_VERIFIED', module=module)
    return result


def main(code, archive_path, package_hash, progress):
    require(os.geteuid() == os.getegid() == 0 and sys.flags.isolated and sys.flags.no_site
            and sys.dont_write_bytecode, 'ISOLATED_ROOT_PREPARATION_REQUIRED')
    os.umask(0o077)
    signal.signal(signal.SIGALRM, lambda *_: require(False, 'PREPARATION_DEADLINE_EXHAUSTED'))
    signal.alarm(300)
    code = Path(code)
    package = parsed(read_file(code / 'package.json', package_hash))
    contents = {name: read_file(code / name, expected) for name, expected in package['files'].items()}
    require(set(contents) == {'prepare.py', 'image_custody.py', 'release.json', 'migrations.json', 'selection.json'},
            'EXACT_PREPARATION_CODE_PACKAGE_REQUIRED')
    release, manifest, selection = (parsed(contents[k]) for k in ('release.json', 'migrations.json', 'selection.json'))
    require(selection.get('engineApiVersion') == '1.44', 'RETAINED_ENGINE_API_VERSION_REQUIRED')
    ns = {'__name__': 'verified_linked_property_retained_helpers'}
    boot = selection['retainedBootstrap']
    exec(compile(read_file(boot['path'], boot['sha256'], 131072), '<verified-retained-helper>', 'exec'), ns)
    old = ns['read'](ns['CONTEXT'] / 'review.json', 8388608, ns['REVIEW'])
    link = old['scopes']['finiteActionProcess']['bundle']
    prepared = ns['read'](link['path'], 8388608, link['sha256'])['prepared']
    require(digest(prepared) == old['privateInputHashes']['preparedInputs'], 'RETAINED_PREPARED_BINDING_CHANGED')
    program = old['sourceClosure']['executables']['docker']
    read_file(program['path'], program['sha256'], 134217728)
    parent = Path(selection['privateParent'])
    root_directory(parent)
    require(shutil.disk_usage(parent).free >= 5 * 1024**3, 'PRIVATE_PREPARATION_DISK_HEADROOM_REQUIRED')
    context = Path(tempfile.mkdtemp(prefix='linked-property-review-', dir=parent))
    progress('PRIVATE_CONTEXT', contextPath=str(context))
    def applications():
        result = {}
        for module in MODULES:
            expected = release['targetRead'][module]
            actual = ns['engine_get'](prepared['engine'], 'containers', expected['containerId'])
            checks = application_checks(actual, expected, selection['configHashes'][module])
            if not all(checks.values()):
                progress('APPLICATION_BINDING_MISMATCH', module=module, engineApiVersion='1.44',
                         checks=checks, configurationValuesPrinted=False)
                require(False, 'EXACT_CURRENT_APPLICATION_REQUIRED')
            result[module] = actual
        return result
    actuals = applications()
    facts = {m: database_facts(ns, prepared, program['path'], m, context) for m in MODULES}
    verify_history(facts['udp']['migrations'], manifest['migrations'][:-1], 'ouf_udp')
    require(facts['udp']['profileTablePresent'] is False and facts['udp']['evidenceColumnPresent'] is False,
            'UDP_V35_ALREADY_PRESENT_OR_PARTIAL')
    roles = facts['udp']['rolePreflight']
    require(all(v is True for k, v in roles.items() if k != 'applicationSuperuser'), 'UDP_MIGRATION_ROLE_PRIVILEGES_MISSING')
    progress('DATABASE_PREFLIGHT', installedUdpVersion=34, pendingUdpVersion=35,
             catalogPrivilegesSufficient=True, applicationRoleIsSuperuser=roles['applicationSuperuser'])
    custody = {'__name__': 'verified_linked_property_image_custody'}
    exec(compile(contents['image_custody.py'], '<verified-image-custody>', 'exec'), custody)
    candidates = candidate(archive_path, context, release, manifest, custody,
                           containerd_store(prepared['engine']), progress)
    verify_history(facts['onboarding']['migrations'], candidates['onboarding']['migrations'], 'ouf_onboarding',
                   allow_existing_schema=True)
    require({m: runtime(v) for m, v in applications().items()} == {m: runtime(v) for m, v in actuals.items()},
            'APPLICATION_GENERATION_CHANGED_DURING_PREPARATION')
    pg = prepared['databasePlan']['postgresRuntimeBinding']
    require(runtime(ns['engine_get'](prepared['engine'], 'containers', pg['containerId'])) == pg,
            'POSTGRES_GENERATION_CHANGED_DURING_PREPARATION')
    plan = {'schema': 'ouf.linked-property-private-preparation.v1', 'installationSpecific': True,
            'engineApiVersion': '1.44',
            'retainedBootstrap': boot, 'releaseHash': digest(release), 'candidatePackageHash': release['package']['githubArtifactDigest'],
            'beforeApplications': {m: runtime(v) for m, v in actuals.items()},
            'privateApplicationObservations': actuals, 'databaseFacts': facts,
            'postgresRuntimeBinding': pg, 'engine': prepared['engine'], 'candidates': candidates,
            'proposedDatabaseChange': {'module': 'udp', 'from': 34, 'to': 35, 'owner': 'APPLICATION_FLYWAY',
                'migration': candidates['udp']['migrations'][-1], 'backupRequiredBeforeMigration': True,
                'backupPayloadVerificationRequired': True, 'automaticRestoreAllowed': False},
            'backupPerformed': False, 'runtimeAuthorityIssued': False, 'readyForExecution': False,
            'nativeProfilePublished': False, 'serviceMutations': 0, 'databaseMutations': 0,
            'identityDecisionsPerformed': False, 'jobsRetried': 0}
    binding = document(context, 'prepared-plan.json', plan)
    review = {'schema': 'ouf.linked-property-private-review.v1', 'preparedPlanBinding': binding,
              'contextPath': str(context), 'candidateNativeImageIds': {m: v['nativeImageId'] for m, v in candidates.items()},
              'udpMigrationPrefixMatched': 34, 'pendingUdpMigrations': 1, 'onboardingMigrationsUnchanged': True,
              'migrationRoleCatalogPrivilegesSufficient': True, 'effectiveFlywayConfigurationProven': False,
              'packageDigestMatchesQualifiedCI': True, 'sigstoreVerifiedLocally': False,
              'backupPerformed': False, 'readyForExecution': False, 'runtimeAuthorityIssued': False,
              'newPrivateFilesOnly': True, 'serviceMutations': 0, 'databaseMutations': 0,
              'grantRequests': 0, 'oauthRequests': 0, 'credentialFilesRead': 0, 'credentialValuesPrinted': False,
              'completedTechnicalPhases': 8, 'functionalMilestonesProven': 2}
    rb = document(context, 'review.json', review)
    return {**review, 'reviewPath': rb['path'], 'reviewSha256': rb['sha256'], 'complete': True}


if __name__ == '__main__':
    def progress(check, **values):
        print(json.dumps({'schema': 'ouf.linked-property-private-review.v1', 'check': check,
                          'completedTechnicalPhases': 8, 'functionalMilestonesProven': 2,
                          'runtimeAuthorityIssued': False, **values}, sort_keys=True), flush=True)
    try:
        require(len(sys.argv) == 4, 'EXACT_PREPARATION_ARGUMENTS_REQUIRED')
        result = main(sys.argv[1], sys.argv[2], sys.argv[3], progress)
        print('OUF_LINKED_PROPERTY_PRIVATE_REVIEW=' + json.dumps(result, sort_keys=True), flush=True)
    except (Exception, KeyboardInterrupt) as error:
        reason = str(error) if isinstance(error, ValueError) and re.fullmatch('[A-Z_]{1,160}', str(error)) else type(error).__name__
        progress('STOP', reason=reason, exceptionMessagePrinted=False, automaticRetry=False,
                 databaseMutations=0, serviceMutations=0, grantRequests=0, credentialValuesPrinted=False)
        raise SystemExit(2)
