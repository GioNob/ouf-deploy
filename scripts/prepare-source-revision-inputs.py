#!/usr/bin/env python3
"""One installation-selected private snapshot/custody; no runtime authority.

The completed signed release is read as history. Its expiry/claims are never
renewed or reused. Only its already-qualified read helpers are loaded.
"""
import hashlib
import importlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import stat
import sys
import tempfile


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def pin(info):
    return tuple(getattr(info, key) for key in ('st_dev','st_ino','st_mode','st_uid','st_gid',
                 'st_nlink','st_size','st_mtime_ns','st_ctime_ns'))


def read(path, expected=None, maximum=8388608, protected=True):
    path = Path(path)
    require(path.is_absolute() and path.resolve() == path, 'EXACT_NO_LINK_PATH_REQUIRED')
    for parent in path.parents:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and (not protected or
                info.st_uid == 0 and not info.st_mode & 0o022), 'INPUT_DIRECTORY_CUSTODY_REQUIRED')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                0 < before.st_size <= maximum, 'BOUNDED_REGULAR_INPUT_REQUIRED')
        require(not protected or before.st_uid == 0 and not before.st_mode & 0o022,
                'ROOT_INPUT_CUSTODY_REQUIRED')
        chunks = []; size = 0
        while True:
            block = os.read(fd, min(65536, maximum + 1 - size))
            if not block:
                break
            size += len(block); require(size <= maximum, 'INPUT_BOUND_EXHAUSTED'); chunks.append(block)
        raw = b''.join(chunks)
        require(size == before.st_size and pin(before) == pin(os.fstat(fd)) == pin(path.lstat())
                and (expected is None or hashlib.sha256(raw).hexdigest() == expected), 'INPUT_BYTES_CHANGED')
        return raw
    finally:
        os.close(fd)


def load_retained(profile):
    boot = profile['retainedBootstrap']
    namespace = {'__name__':'source_revision_retained_read_helpers'}
    exec(compile(read(boot['path'], boot['sha256'], 131072), '<verified-retained-read-helpers>', 'exec'), namespace)
    original = namespace['read'](namespace['CONTEXT']/'review.json', 8388608, namespace['REVIEW'])
    binding = original['scopes']['finiteActionProcess']['bundle']
    bundle = namespace['read'](binding['path'], 8388608, binding['sha256'])
    _, sources = namespace['decode_sources'](bundle)
    prepared = bundle['prepared']
    require(digest(prepared) == original['privateInputHashes']['preparedInputs'], 'ORIGINAL_INPUT_BINDING_CHANGED')
    completed = profile['completedUpdate']
    review = namespace['read'](completed['path'], 8388608, completed['sha256'])
    declaration = review['sourceClosure']['declaration']
    directory = Path(profile['retainedExecutorDirectory'])
    bootstrap = read(directory/'execute.py', declaration['bootstrapBindings']['executorSha256'], 131072)
    selected = {'__name__':'source_revision_retained_overlay_declaration'}
    exec(compile(bootstrap, '<verified-retained-overlay-declaration>', 'exec'), selected)
    for module, (filename, _) in selected['OVERLAYS'].items():
        sources[module] = read(directory/filename, declaration['sourceHashes'][module], 262144)
    require({name:hashlib.sha256(raw).hexdigest() for name,raw in sorted(sources.items())}
            == declaration['sourceHashes'], 'COMPLETED_SOURCE_CLOSURE_CHANGED')
    loader = read(directory/'runtime.py', declaration['loaderHash'], 65536)
    memory = {'__name__':'source_revision_retained_memory_loader'}
    exec(compile(loader, '<verified-retained-memory-loader>', 'exec'), memory)
    _, actual = memory['load_entry'](declaration['sourceCommit'], sources, loader, digest(declaration),
                                    declaration['sourcePins'], declaration['bootstrapBindings'])
    require(actual == declaration, 'EXACT_COMPLETED_READ_CLOSURE_REQUIRED')
    entry = importlib.import_module('tools.linked_property_rollout.entry')
    _, plan, record = entry.completed_plan(completed, namespace['read'])
    require(record['version'] == profile['completedJournalVersion'], 'COMPLETED_JOURNAL_CHANGED')
    helper = importlib.import_module('tools.linked_property_rollout.preparation')
    custody = importlib.import_module('image_custody')
    gateway = importlib.import_module('tools.chatbot_file_cohort.gateway')
    engine = importlib.import_module('engine_creation').Engine
    return namespace, prepared, plan, record, helper, custody, gateway, engine


def manifest(raw):
    result = {}
    for line in raw.decode('ascii').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        require(match is not None, 'EXACT_HASH_LIST_REQUIRED')
        name = match[2]; path = PurePosixPath(name)
        require(str(path) == name and not path.is_absolute() and '..' not in path.parts
                and name not in result, 'SAFE_UNIQUE_MANIFEST_PATH_REQUIRED')
        result[name] = match[1]
    require(0 < len(result) <= 256, 'BOUNDED_MANIFEST_REQUIRED')
    return result


def stage(profile, context, helper, custody):
    package = profile['package']; root = Path(package['directory'])
    raw = read(root/'SHA256SUMS', package['manifestSha256'], 1048576, False)
    hashes = manifest(raw)
    require(set(hashes) == {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}
            - {'SHA256SUMS','SHA256SUMS.sigstore.json'}, 'COMPLETE_PACKAGE_MEMBERS_REQUIRED')
    lock = json.loads(read(root/'source-lock.json', package['sourceLockSha256'], 1048576, False))
    require({m['module']:m['commit'] for m in lock['modules']} == profile['candidateSourceCommits']
            and lock['targetApplyAuthorized'] is False and lock['runtimeAuthorityIssued'] is False,
            'EXACT_QUALIFIED_SOURCES_REQUIRED')
    review_binding = profile['runnerImageReview']
    review = json.loads(read(review_binding['path'], review_binding['sha256'], 8388608, False))
    require(review['schema'] == 'ouf.source-revision-image-custody-review.v1'
            and set(review['candidates']) == {'onboarding','mcp'} and review['imagesImported'] == 0,
            'EXACT_UNIMPORTED_CANDIDATE_REVIEW_REQUIRED')
    candidates = {}
    for module in ('onboarding','mcp'):
        row = review['candidates'][module]; audit = row['imageAudit']
        require(audit['sourceCommit'] == profile['candidateSourceCommits'][module]
                and row['nativeImageId'] == profile['candidateNativeImageIds'][module], 'CANDIDATE_SOURCE_DRIFT')
        source = Path(row['imageArchive']['path'])
        require(source == Path(review_binding['path']).parent/(module+'.tagless.tar')
                and source.resolve() == source, 'EXACT_ARCHIVE_PATH_REQUIRED')
        target = context/(module+'.tagless.tar')
        helper.copy_package(source, target, row['imageArchive']['sha256'])
        with target.open('rb') as stream:
            checked = custody.archive(stream, row['imageArchive']['sha256'], audit['imageId'], audit['sourceCommit'])
        if review['containerd']:
            checked['nativeIdentity'] = custody.native_identity(checked)
        require(checked == audit and not checked['repositoryTags']
                and custody.runtime_image_id(checked) == row['nativeImageId'], 'ROOT_IMAGE_READBACK_DRIFT')
        prefix = 'parts/source-revision-part-'+module+'-'+str(package['buildRunId'])+'/'
        metadata = json.loads(read(root/(prefix+'candidate-manifest.json'), hashes[prefix+'candidate-manifest.json'], 1048576, False))
        require(metadata['sourceCommit'] == audit['sourceCommit'] and metadata['imageId'] == audit['imageId']
                and metadata['sourceLockSha256'] == package['sourceLockSha256']
                and metadata['scanGate'] == 'PASS_HIGH_CRITICAL_UNKNOWN_INCLUDING_UNFIXED', 'QUALIFIED_CANDIDATE_METADATA_CHANGED')
        candidates[module] = {**row, 'imageArchive':{'path':str(target),'sha256':row['imageArchive']['sha256']}}
        if module == 'onboarding':
            name = prefix+'application.jar'; target = context/'application.jar'
            helper.copy_package(root/name, target, hashes[name])
            candidates[module]['jar'] = {'path':str(target),'sha256':hashes[name]}
            candidates[module]['migrations'] = helper.migration_rows(target)
    name = 'parts/source-revision-part-gateway-'+str(package['buildRunId'])+'/source.tar'
    helper.copy_package(root/name, context/'gateway-source.tar', hashes[name])
    for name in ('SHA256SUMS','SHA256SUMS.sigstore.json','source-lock.json'):
        value = read(root/name, package.get({'SHA256SUMS':'manifestSha256','source-lock.json':'sourceLockSha256'}.get(name,'')), 1048576, False)
        helper.write_new(context/name, value)
    return candidates, review['containerd'], {'path':str(context/'gateway-source.tar'),'sha256':hashes[
        'parts/source-revision-part-gateway-'+str(package['buildRunId'])+'/source.tar']}


def sql(module, binding):
    schema, app = binding['schema'], binding['user']
    require(module in ('onboarding','udp','mcp') and all(re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,62}', x)
            for x in (schema,app,binding['database'])), 'EXACT_DATABASE_IDENTIFIERS_REQUIRED')
    history = (f"select version,checksum::text from {schema}.schema_migration order by version limit 100"
               if module == 'mcp' else f"select installed_rank,version,script,checksum,success from {schema}.flyway_schema_history order by installed_rank limit 100")
    order = 'version' if module == 'mcp' else 'installed_rank'
    extra = ''
    if module == 'onboarding':
        extra = f""",'revisionTablePresent',to_regclass('{schema}.source_property_revision') is not null,
          'migrationRolePrivileges',jsonb_build_object('schemaCreate',has_schema_privilege('{app}','{schema}','CREATE'),
          'sourceReferences',has_table_privilege('{app}','{schema}.source','REFERENCES'),
          'versionReferences',has_table_privilege('{app}','{schema}.onboarding_version','REFERENCES'),
          'reviewReferences',has_table_privilege('{app}','{schema}.managed_onboarding_review','REFERENCES'),
          'auditFunctionExecute',has_function_privilege('{app}','{schema}.reject_audit_change()','EXECUTE'),
          'historyInsert',has_table_privilege('{app}','{schema}.flyway_schema_history','INSERT'),
          'historySelect',has_table_privilege('{app}','{schema}.flyway_schema_history','SELECT'))"""
    return f"""BEGIN READ ONLY; SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='3s';
      SELECT jsonb_build_object('database',current_database(),'databaseOid',(select oid::bigint from pg_database where datname=current_database()),
      'role',current_user,'transactionReadOnly',current_setting('transaction_read_only')='on','applicationRole','{app}',
      'databaseBytes',pg_database_size(current_database()),'preparedTransactions',(select count(*) from pg_prepared_xacts where database=current_database()),
      'migrations',(select jsonb_agg(x order by {order}) from ({history})x){extra}); ROLLBACK;"""


def facts(module, prepared, helper, program, context):
    plan = prepared['databasePlan']; binding = next(m for m in plan['modules'] if m['module'] == module)
    admin = plan['mcpAuditRoleAdministration']['admin']
    require(re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,62}', admin), 'EXACT_DATABASE_ADMINISTRATOR_REQUIRED')
    command = [program['path'],'--host','unix://'+prepared['engine']['socketPath'],'--config',str(context),
        'exec',plan['postgresRuntimeBinding']['containerId'],'env','LC_ALL=C',
        'PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=10000 -c lock_timeout=3000',
        'timeout','-s','KILL','20','psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1',
        '-U',admin,'-d',binding['database'],'-c',sql(module,binding)]
    found = helper.bounded(command)
    require(found['database'] == binding['database'] and found['databaseOid'] == binding['databaseOid']
            and found['role'] == admin and found['transactionReadOnly'] is True
            and found['preparedTransactions'] == 0, 'DATABASE_IDENTITY_CHANGED')
    return found


def emit(check, **values):
    print(json.dumps({'schema':'ouf.source-revision-private-preparation.v1','check':check,
        'installationSpecific':True,'completedTechnicalPhases':8,'functionalMilestonesProven':4,
        'runtimeMutations':0,'profilePublications':0,'jobsRetried':0,'grantRequests':0,'oauthRequests':0,
        'credentialValuesPrinted':False,'runtimeAuthorityIssued':False,'readyForExecution':False,**values},sort_keys=True),flush=True)


def main(profile):
    require(os.geteuid() == os.getegid() == 0 and sys.flags.isolated and sys.flags.no_site
            and sys.dont_write_bytecode, 'ISOLATED_ROOT_PREPARATION_REQUIRED')
    require(profile['schema'] == 'ouf.source-revision-private-preparation-selection.v1', 'EXACT_VERSIONED_SELECTION_REQUIRED')
    os.umask(0o077)
    signal.signal(signal.SIGALRM, lambda *_: require(False,'PRIVATE_PREPARATION_DEADLINE'))
    signal.alarm(300)
    namespace, prepared, latest, record, helper, custody, gateway, Engine = load_retained(profile)
    engine = Engine(prepared['engine']['socketPath'], tuple(prepared['engine']['socketBinding']))
    entry = importlib.import_module('tools.linked_property_rollout.entry')
    _, linked, linked_record = entry.completed_plan(profile['completedLinkedUpdate'], namespace['read'])
    actuals = {}
    for module, selected in profile['currentApplications'].items():
        value = namespace['engine_get'](prepared['engine'], 'containers', selected['containerId'])
        expected = (linked_record if module == 'onboarding' else record)['effects'][-1]['evidence']['applications'][module]['runtimeBinding']
        require(value is not None and gateway_runtime(value) == expected and value['Image'] == selected['imageId']
                and value['Config']['Labels']['org.opencontainers.image.revision'] == selected['sourceCommit']
                and value['State']['Running'] is True and not value['State']['Paused'] and not value['State']['Restarting'],
                'EXACT_COMPLETED_APPLICATION_GENERATION_REQUIRED')
        actuals[module] = value
    postgres = prepared['databasePlan']['postgresRuntimeBinding']
    require(helper.runtime(namespace['engine_get'](prepared['engine'],'containers',postgres['containerId'])) == postgres,
            'POSTGRES_GENERATION_CHANGED')
    program = namespace['read'](profile['completedUpdate']['path'],8388608,profile['completedUpdate']['sha256'])['sourceClosure']['executables']['docker']
    read(program['path'], program['sha256'], 134217728)
    admin = gateway.NamespaceAdmin(engine, latest['gateway']['transport'])
    routes = admin.routes()
    require(routes == latest['gateway']['beforeRoutes'] == latest['gateway']['afterRoutes'], 'GATEWAY_ROUTE_BASELINE_CHANGED')
    require(not any(key in routes for key in ('mcp-source-revision-prepare','mcp-source-revision-read')), 'REVISION_ROUTES_ALREADY_PRESENT_RECONCILE')
    parent = Path(profile['privateParent']); helper.root_directory(parent)
    context = Path(tempfile.mkdtemp(prefix='source-revision-prepared-', dir=parent)); context.chmod(0o700)
    emit('PRIVATE_CONTEXT', contextPath=str(context))
    candidates, containerd, gateway_package = stage(profile, context, helper, custody)
    require(helper.containerd_store(prepared['engine']) == containerd, 'IMAGE_STORE_CHANGED')
    database = {module:facts(module,prepared,helper,program,context) for module in ('onboarding','udp','mcp')}
    migrations = candidates['onboarding']['migrations']
    require(len(migrations) == 34 and migrations[-1]['version'] == '34'
            and migrations[-1]['script'] == 'V34__source_property_revision.sql'
            and database['onboarding']['revisionTablePresent'] is False
            and all(database['onboarding']['migrationRolePrivileges'].values()), 'ONBOARDING_V34_PREFLIGHT_UNPROVEN')
    helper.verify_history(database['onboarding']['migrations'], migrations[:-1], 'ouf_onboarding', allow_existing_schema=True)
    old_case = json.loads(read(Path(profile['retainedExecutorDirectory'])/'case.json',
        namespace['read'](profile['completedUpdate']['path'],8388608,profile['completedUpdate']['sha256'])['sourceClosure']['declaration']['bootstrapBindings']['caseSha256']))
    helper.verify_history(database['udp']['migrations'], old_case['udpMigrations'], 'ouf_udp', allow_existing_schema=True)
    require(database['mcp']['migrations'] == old_case['mcpMigrations'], 'UNCHANGED_MCP_MIGRATIONS_REQUIRED')
    for module in actuals:
        require(helper.runtime(namespace['engine_get'](prepared['engine'],'containers',actuals[module]['Id']))
                == helper.runtime(actuals[module]), 'APPLICATION_CHANGED_DURING_PREPARATION')
    require(admin.routes() == routes and helper.runtime(namespace['engine_get'](prepared['engine'],'containers',postgres['containerId']))
            == postgres, 'TARGET_CHANGED_DURING_PREPARATION')
    value = {'schema':'ouf.source-revision-private-inputs.v1','selection':profile,'engine':prepared['engine'],
        'databasePlan':prepared['databasePlan'],'databaseFacts':database,'beforeApplications':actuals,
        'retainedReplacements':{'onboarding':linked['replacements']['onboarding'],'mcp':latest['replacements']['mcp']},
        'unchangedApplications':latest['unchangedApplications'],'gateway':{**latest['gateway'],'beforeRoutes':routes},
        'candidates':candidates,'gatewayPackage':gateway_package,'packageRootCustodyProven':True,
        'backupPerformed':False,'effectiveFlywayConfigurationProven':False,'authorizationDeltaPrepared':False,
        'runtimeAuthorityIssued':False,'readyForExecution':False,'runtimeMutations':0}
    binding = helper.document(context,'prepared-plan.json',value)
    emit('END', complete=True, contextPath=str(context), preparedInputsBinding=binding,
         packageRootCustodyProven=True, onboardingFromVersion=33,onboardingToVersion=34,
         udpMigrationVersion=36,mcpMigrationsUnchanged=True,gatewayBaselineCaptured=True,
         backupPerformed=False,effectiveFlywayConfigurationProven=False,authorizationDeltaPrepared=False)


def gateway_runtime(actual):
    helper = importlib.import_module('tools.linked_property_rollout.preparation')
    value = helper.runtime(actual)
    value['mountsHash'] = digest(sorted(actual['Mounts'], key=lambda m:m['Destination']))
    return value


if __name__ == '__main__':
    try:
        require(len(sys.argv) == 3 and re.fullmatch('[0-9a-f]{64}',sys.argv[2]), 'EXACT_SELECTION_BINDING_REQUIRED')
        main(json.loads(read(sys.argv[1],sys.argv[2],1048576)))
    except (Exception,KeyboardInterrupt) as error:
        reason = str(error) if type(error) is ValueError and re.fullmatch('[A-Z_]{1,160}',str(error)) else type(error).__name__
        emit('STOP', reason=reason, exceptionMessagePrinted=False, automaticRetry=False)
        raise SystemExit(2)
