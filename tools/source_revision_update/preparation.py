"""Consume the completed private snapshot; freeze the exact release before login."""
import copy
import hashlib
import importlib
import json
from pathlib import Path
import re
from tools.chatbot_file_cohort.gateway import NamespaceAdmin, private_config
from tools.chatbot_file_cohort import authorization
from tools.linked_property_rollout import preparation as shared
from tools.linked_property_rollout.entry import completed_plan, current_human
from tools.semantic_mcp_update.native import command, private_file
from tools.source_revision_update import configuration, gateway, plan as compiler
from tools.source_revision_update.database import Database, raw_runtime
from tools.source_revision_update.native import runtime
from tools.source_revision_update.owner import require,digest,MIGRATION,scope
from engine_creation import Engine


def package_files(private):
    selected = private['selection']['package']; root = Path(selected['directory'])
    raw = shared.read_file(root/'SHA256SUMS', selected['manifestSha256'],1048576,protected=False)
    mapping = {}
    for line in raw.decode('ascii').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)',line)
        require(match is not None and match[2] not in mapping,'EXACT_SOURCE_MANIFEST_REQUIRED')
        path = Path(match[2]); require(not path.is_absolute() and '..' not in path.parts,'SAFE_SOURCE_MEMBER_REQUIRED')
        mapping[match[2]] = match[1]
    def member(module,name,maximum=8388608):
        relative = 'parts/source-revision-part-'+module+'-'+str(selected['buildRunId'])+'/'+name
        require(relative in mapping,'EXACT_QUALIFIED_PACKAGE_MEMBER_REQUIRED')
        return shared.read_file(root/relative,mapping[relative],maximum,protected=False)
    return member


def write_sources(context, name, members):
    directory = context/name; directory.mkdir(mode=0o700)
    for relative,raw in members.items():
        path = directory/relative; path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        shared.write_new(path,raw)
    return directory


def compiler_inputs(private, context):
    member = package_files(private)
    inventory = json.loads(member('gateway','source-inventory.json'))
    package = private['gatewayPackage']
    raw = shared.read_file(package['path'],package['sha256'],67108864)
    sources = gateway.source_members(raw,inventory)
    directory = write_sources(context,'gateway-compiler',sources)
    compiled = json.loads(member('gateway','compiled-route-declarations.json'))
    owner_inventory = json.loads(member('onboarding','source-inventory.json'))
    owner_names = ('scripts/r4a_authorization_lifecycle.py','scripts/r4a_keycloak_client_scope_catalogue.py',
                   'catalogue/chatbot-source-review-capabilities.json')
    owner_sources = gateway.source_members(member('onboarding','source.tar',67108864),owner_inventory,owner_names)
    bindings = {n:hashlib.sha256(raw).hexdigest() for n,raw in owner_sources.items()}
    lifecycle = importlib.import_module('qualified_owner_authorization_lifecycle')
    scopes = importlib.import_module('qualified_owner_scope_catalogue')
    primitives = authorization.OwnerPrimitives.from_qualified_modules(lifecycle,scopes,
        owner_sources[owner_names[2]],bindings,profile=authorization.REVISION_PROFILE)
    mcp_inventory = json.loads(member('mcp','source-inventory.json'))
    names = sorted(r['path'] for r in mcp_inventory['tree'] if re.fullmatch(
        r'internal/adapter/postgres/migrations/[0-9]{3}_[A-Za-z0-9_]+\.sql',r['path']))
    require(names,'EXACT_MCP_MIGRATION_FILES_REQUIRED')
    mcp_sources = gateway.source_members(member('mcp','source.tar',67108864),mcp_inventory,names)
    migrations = [{'version':int(Path(name).name.split('_',1)[0]),'checksum':hashlib.sha256(mcp_sources[name]).hexdigest()}
                  for name in names]
    require(migrations == private['databaseFacts']['mcp']['migrations'],'CANDIDATE_MCP_MIGRATIONS_CHANGED')
    return directory,sources,compiled,primitives,bindings


def retained_metadata(latest, actual, read):
    candidate = read(latest['privateReviewBinding']['path'],8388608,latest['privateReviewBinding']['sha256'])
    _, previous, _ = completed_plan(candidate['completedMcpReview'],read)
    metadata = previous['metadata']; target = metadata['target']
    mounts = [m for m in actual['Mounts'] if m['Destination'] == target]
    require(len(mounts) == 1 and mounts[0]['Type'] == 'bind' and mounts[0]['RW'] is False
            and mounts[0]['Source'] == metadata['directory'],'RETAINED_MCP_METADATA_MOUNT_CHANGED')
    result = []
    require(set(metadata['files']) == {'profile.json','policy.json','permit.json'},'EXACT_MCP_METADATA_MEMBERS_REQUIRED')
    for name,text in metadata['files'].items():
        binding = {'path':str(Path(metadata['directory'])/name),'sha256':hashlib.sha256(text.encode()).hexdigest()}
        require(shared.read_file(binding['path'],binding['sha256'],65536) == text.encode(), 'RETAINED_MCP_METADATA_BYTES_CHANGED')
        result.append(binding)
    return result


def compile_private(original, closure, case, context, read, ns):
    context = Path(context); shared.root_directory(context)
    binding = case['preparedPlanBinding']; private = read(binding['path'],8388608,binding['sha256'])
    require(private['schema'] == 'ouf.source-revision-private-inputs.v1'
            and private['readyForExecution'] is False and private['runtimeAuthorityIssued'] is False
            and private['packageRootCustodyProven'] is True and private['engine'] == original['engine'],
            'EXACT_COMPLETED_SOURCE_REVISION_INPUTS_REQUIRED')
    actuals = {}
    for module, before in private['beforeApplications'].items():
        actual = ns['engine_get'](private['engine'],'containers',before['Id'])
        require(actual is not None and raw_runtime(actual) == raw_runtime(before)
                and actual['State']['Running'] is True and not actual['State']['Paused']
                and not actual['State']['Restarting'],'APPLICATION_CHANGED_SINCE_PRIVATE_PREPARATION')
        actuals[module] = actual
    engine = Engine(private['engine']['socketPath'],tuple(private['engine']['socketBinding']))
    gateway_binding = copy.deepcopy(private['gateway'])
    raw, projection_binding = private_config(gateway_binding['projectionBinding']['path'],gateway_binding['projectionBinding'])
    require(raw.decode() == gateway_binding['projectionRaw'],'RETAINED_INSTALLATION_PROJECTION_CHANGED')
    admin = NamespaceAdmin(engine,gateway_binding['transport'])
    require(admin.routes() == gateway_binding['beforeRoutes'],'GATEWAY_CHANGED_SINCE_PRIVATE_PREPARATION')
    directory,sources,compiled,primitives,owner_bindings = compiler_inputs(private,context)
    generated = gateway.compile_routes(directory,sources,compiled,json.loads(raw),gateway_binding['beforeRoutes'])
    gateway_plan = {**generated,'transport':gateway_binding['transport'],'projectionBinding':projection_binding}
    selected = private['selection']
    policy = {'deployedSourceCommits':{m:v['sourceCommit'] for m,v in selected['currentApplications'].items()},
              'candidateSourceCommits':selected['candidateSourceCommits'],
              'readiness':{m:private['retainedReplacements'][m]['readiness'] for m in ('onboarding','mcp')}}
    replacements = {}
    for module in ('onboarding','mcp'):
        saved = private['retainedReplacements'][module]; image = private['candidates'][module]
        private_file(image['imageArchive']['path'],image['imageArchive']['sha256'],1200000000)
        replacements[module] = compiler.replacement({'module':module,'name':saved['name'],
            'creationRequest':saved['request'],'restoreRestartPolicy':saved['restoreRestartPolicy']},
            actuals[module],image,policy,module)
    migration = private['candidates']['onboarding']['migrations'][-1]
    require(all(migration[k] == MIGRATION[k] for k in ('script','checksum','sha256'))
            and migration['version'] == '34','EXACT_QUALIFIED_ONBOARDING_V34_REQUIRED')
    pg_pin = private['databasePlan']['postgresRuntimeBinding']
    postgres = ns['engine_get'](private['engine'],'containers',pg_pin['containerId'])
    require(postgres is not None and raw_runtime(postgres) == pg_pin,'POSTGRES_GENERATION_CHANGED')
    db_binding = next(m for m in private['databasePlan']['modules'] if m['module'] == 'onboarding')
    flyway = configuration.verify(actuals['onboarding'],private['candidates']['onboarding'],postgres,db_binding,
        case['postgresNativePort'],case['onboardingApplicationConfigurationSha256'])
    _, latest, _ = completed_plan(selected['completedUpdate'],read)
    metadata = retained_metadata(latest,actuals['mcp'],read)
    review = {'schema':'ouf.source-revision-candidate-review.v1','preparedPlanBinding':binding,
        'nativeFlywayConfiguration':flyway,'ownerHelperBindings':owner_bindings,
        'gatewayCompilationHash':digest(generated),'retainedMcpMetadata':metadata,
        'databaseMigration':MIGRATION,'backupRequiredBeforeMigration':True,
        'readyForExecution':False,'runtimeAuthorityIssued':False}
    shared.publish_json(context,'candidate-review.json',review)
    unchanged = {k:v for k,v in private['unchangedApplications'].items() if k != 'onboarding'}
    unchanged['udp'] = runtime(actuals['udp'])
    plan = {'schema':'ouf.source-revision-native-update-plan.v1','authorityDirectory':str(context),
        'privateReviewBinding':{'path':str(context/'candidate-review.json'),'sha256':digest(review)},
        'engine':private['engine'],'programs':{'docker':closure['executables']['docker']},
        'replacements':replacements,'unchangedApplications':unchanged,'gateway':gateway_plan,
        'nativeFlywayConfiguration':flyway,'retainedMcpMetadata':metadata,'databaseMigration':MIGRATION,
        'database':{'postgresRuntimeBinding':pg_pin,'before':private['databaseFacts']},
        'mcpMigrationsUnchanged':True,'backupRequiredBeforeMigration':True,
        'maximumExecutionSeconds':900,'maximumEffectAttemptsPerStage':1,'maximumGatewayWrites':2,
        **{k:False for k in ('automaticReplayAllowed','manualSqlMigrationAllowed','grantChangesAllowed',
            'semanticDispatchAllowed','automaticRollbackAllowed','identityDecisionsAllowed','profilePublicationAllowed','jobRetriesAllowed')}}
    plan['logicalUpdateRef'] = digest({'retiredContainerIds':sorted(v['oldRuntimeBinding']['containerId'] for v in replacements.values()),'migration':MIGRATION})
    scope(plan)
    database = Database(plan,original,ns)
    # Read-only preparation verifies the real retained Engine. No substitute
    # AggregateAction/credentials and no effect port are created before consent.
    def guard():
        actual = ns['engine_get'](private['engine'],'containers',pg_pin['containerId'])
        require(actual is not None and raw_runtime(actual) == pg_pin,'POSTGRES_GENERATION_CHANGED')
        command(closure['executables']['docker'])
    database.guard = guard
    database.verify_before()
    for pin in unchanged.values():
        actual = ns['engine_get'](private['engine'],'containers',pin['containerId'])
        require(actual is not None and actual['State']['Running'] is True and runtime(actual) == pin,
                'UNCHANGED_APPLICATION_GENERATION_REQUIRED')
    require(admin.routes() == gateway_plan['beforeRoutes'],'GATEWAY_CHANGED_DURING_COMPILATION')
    shared.publish_json(context,'prepared-plan.json',plan)
    return plan,primitives,private
