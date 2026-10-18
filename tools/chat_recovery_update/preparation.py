"""Private release compilation. Reads target state; no runtime mutation or login."""
import copy,hashlib,json,re
from pathlib import Path
from engine_creation import Engine
from image_custody import archive,native_identity,runtime_image_id
from tools.chatbot_file_cohort.gateway import NamespaceAdmin
from tools.linked_property_rollout import configuration
from tools.linked_property_rollout.preparation import read_file,copy_package,publish_json,root_directory,migration_rows,verify_history
from tools.linked_property_rollout.entry import completed_plan
from tools.semantic_mcp_update.native import env,private_file
from tools.chat_recovery_update import plan as compiler
from tools.chat_recovery_update.native import runtime
from tools.chat_recovery_update.database import Database,raw_runtime
from tools.chat_recovery_update.owner import require,digest,MIGRATION,scope

def protected_review(binding,read):
    return read(binding['path'],8388608,binding['sha256'])

def stage_candidates(case,context):
    """Copy and re-audit the exact attested runner artifacts before any login."""
    binding=case['runnerImageReview']
    path=Path(binding['path'])
    require(path.is_absolute() and path.resolve()==path,'EXACT_IMAGE_REVIEW_PATH_REQUIRED')
    review=json.loads(read_file(path,binding['sha256'],protected=False))
    require(review['schema']=='ouf.chat-recovery-image-custody-review.v1'
        and set(review['candidates'])=={'udp','mcp'} and review['imagesImported']==0,
        'EXACT_RUNNER_CUSTODY_REVIEW_REQUIRED')
    candidates={}
    for module,row in review['candidates'].items():
        source=Path(row['imageArchive']['path'])
        require(source==path.parent/(module+'.tagless.tar') and source.resolve()==source,
                'EXACT_REVIEWED_ARCHIVE_REQUIRED')
        audit=row['imageAudit']
        require(audit['sourceCommit']==case['candidateSourceCommits'][module],
                'CANDIDATE_SOURCE_CHANGED')
        target=context/(module+'.tagless.tar')
        copy_package(source,target,row['imageArchive']['sha256'])
        with target.open('rb') as stream:
            checked=archive(stream,row['imageArchive']['sha256'],audit['imageId'],audit['sourceCommit'])
        if review['containerd']:checked['nativeIdentity']=native_identity(checked)
        require(checked==audit and not checked['repositoryTags']
            and runtime_image_id(checked)==row['nativeImageId'],'ROOT_IMAGE_READBACK_DRIFT')
        candidates[module]={**row,'imageArchive':{'path':str(target),'sha256':row['imageArchive']['sha256']}}
    package=case['package']
    root=Path(package['directory'])
    require(root.is_absolute() and root.resolve()==root,'EXACT_PACKAGE_DIRECTORY_REQUIRED')
    raw=read_file(root/'SHA256SUMS',package['manifestSha256'],1048576,protected=False)
    mapping={}
    for line in raw.decode('ascii').splitlines():
        match=re.fullmatch(r'([0-9a-f]{64})  (.+)',line)
        require(match is not None and match[2] not in mapping,'EXACT_PACKAGE_MANIFEST_REQUIRED')
        mapping[match[2]]=match[1]
    relative=package['udpJarRelativePath'];source=root/relative
    require(not Path(relative).is_absolute() and '..' not in Path(relative).parts
        and source.resolve()==source and relative in mapping,'EXACT_QUALIFIED_JAR_REQUIRED')
    target=context/'application.jar'
    copy_package(source,target,mapping[relative])
    candidates['udp']['jar']={'path':str(target),'sha256':mapping[relative]}
    rows=migration_rows(target)
    require(rows==case['udpMigrations'],'QUALIFIED_JAR_MIGRATIONS_CHANGED')
    return candidates

def completed_mcp(actual,case,read):
    """Select the historical update by its currently mounted metadata, not mtime."""
    mounts=[m for m in actual['Mounts'] if m['Destination']==case['mcpMetadataMountTarget']]
    require(len(mounts)==1 and mounts[0]['Type']=='bind' and mounts[0]['RW'] is False,
            'RETAINED_MCP_METADATA_MOUNT_REQUIRED')
    directory=Path(mounts[0]['Source']);context=directory.parent
    require(context.parent==Path(case['privateParent'])
        and context.name.startswith('semantic-mcp-update-execution-')
        and directory.name=='public','RETAINED_MCP_METADATA_CONTEXT_REQUIRED')
    root_directory(context)
    review=read(context/'review.json',8388608)
    binding={'path':str(context/'review.json'),'sha256':digest(review),'scope':'mcpSingleUpdate'}
    _,plan,record=completed_plan(binding,read)
    require(plan['metadata']['directory']==str(directory)
        and plan['metadata']['target']==case['mcpMetadataMountTarget']
        and record['effects'][-1]['evidence']['runtimeHash']==digest(raw_runtime(actual)),
        'COMPLETED_MCP_GENERATION_CHANGED')
    # Preserve exact public metadata and mount permissions, never republish it.
    for name,text in plan['metadata']['files'].items():
        require(name in ('profile.json','policy.json','permit.json'),'EXACT_METADATA_MEMBER_REQUIRED')
        raw=read_file(directory/name,hashlib.sha256(text.encode()).hexdigest(),65536)
        require(raw==text.encode(),'RETAINED_MCP_METADATA_CHANGED')
    return plan,binding

def compile_private(prepared,closure,case,context,read,ns):
    context=Path(context);root_directory(context)
    retained=protected_review(case['preparedPlanBinding'],read)
    require(retained['schema']=='ouf.chat-recovery-private-inputs.v1'
        and retained['readyForExecution'] is False and retained['runtimeAuthorityIssued'] is False
        and retained['engine']==prepared['engine'],'EXACT_PREPARED_RUNTIME_REQUIRED')
    actuals={}
    for module in ('udp','mcp','onboarding'):
        pin=retained['beforeApplications'][module]
        actual=ns['engine_get'](prepared['engine'],'containers',pin['containerId'])
        require(actual is not None and actual['State']['Running'] is True
            and actual['State']['Paused'] is False and actual['State']['Restarting'] is False
            and raw_runtime(actual)==pin,'APPLICATION_CHANGED_SINCE_PREPARATION')
        actuals[module]=actual
    _,previous,record=completed_plan(case['completedLinkedUpdate'],read)
    for module in ('udp','onboarding'):
        require(record['effects'][-1]['evidence']['applications'][module]['runtimeBinding']==runtime(actuals[module]),
                'COMPLETED_LINKED_GENERATION_CHANGED')
    mcp,mcp_binding=completed_mcp(actuals['mcp'],case,read)
    engine=Engine(prepared['engine']['socketPath'],tuple(prepared['engine']['socketBinding']))
    gateway=copy.deepcopy(previous['gateway'])
    require(gateway['beforeRoutes']==gateway['afterRoutes']
        and NamespaceAdmin(engine,gateway['transport']).routes()==gateway['beforeRoutes'],'GATEWAY_CONFIGURATION_CHANGED')
    candidates=stage_candidates(case,context)
    saved={'udp':previous['replacements']['udp'],'mcp':mcp['replacement']}
    readiness={'udp':saved['udp']['readiness'],
               'mcp':{'readinessPort':mcp['readiness']['port'],'readinessPath':mcp['readiness']['path']}}
    replacements={module:compiler.replacement(
        {'module':module,'name':saved[module]['name'],'creationRequest':saved[module]['request']},
        actuals[module],candidates[module],{**case,'readiness':readiness},module) for module in ('udp','mcp')}
    pg_pin=retained['databasePlan']['postgresRuntimeBinding']
    pg=ns['engine_get'](prepared['engine'],'containers',pg_pin['containerId'])
    require(pg is not None and raw_runtime(pg)==pg_pin,'POSTGRES_GENERATION_CHANGED')
    flyway=configuration.verify(actuals['udp'],candidates['udp'],pg,case['udpApplicationConfigurationSha256'])
    before=retained['databaseFacts']
    verify_history(before['udp']['migrations'],case['udpMigrations'][:-1],before['udp']['database'],allow_existing_schema=True)
    require(before['mcp']['migrations']==case['mcpMigrations']
        and case['udpMigrations'][-1]['version']=='36'
        and all(case['udpMigrations'][-1][k]==MIGRATION[k] for k in ('script','checksum','sha256')),
        'EXACT_V36_AND_UNCHANGED_MCP_HISTORY_REQUIRED')
    review={'schema':'ouf.chat-recovery-candidate-review.v1',
        'preparedPlanBinding':case['preparedPlanBinding'],'runnerImageReview':case['runnerImageReview'],
        'completedMcpReview':mcp_binding,'completedLinkedUpdate':case['completedLinkedUpdate'],
        'candidates':candidates,'nativeFlywayConfiguration':flyway,
        'databaseMigration':MIGRATION,'runtimeAuthorityIssued':False,'readyForExecution':False}
    publish_json(context,'candidate-review.json',review)
    plan={'schema':'ouf.chat-recovery-native-update-plan.v1','authorityDirectory':str(context),
        'privateReviewBinding':{'path':str(context/'candidate-review.json'),'sha256':digest(review)},
        'engine':copy.deepcopy(prepared['engine']),'programs':{'docker':closure['executables']['docker']},
        'replacements':replacements,'unchangedApplications':{
            **previous['unchangedApplications'],'onboarding':runtime(actuals['onboarding'])},
        'gateway':gateway,'databaseMigration':MIGRATION,'mcpMigrationsUnchanged':True,
        'backupRequiredBeforeMigration':True,
        'database':{'postgresRuntimeBinding':pg_pin,'before':before},
        'maximumExecutionSeconds':900,'maximumEffectAttemptsPerStage':1,'maximumGatewayWrites':0,
        **{k:False for k in ('automaticReplayAllowed','manualSqlMigrationAllowed','grantChangesAllowed',
            'semanticDispatchAllowed','automaticRollbackAllowed','identityDecisionsAllowed',
            'profilePublicationAllowed','jobRetriesAllowed')}}
    plan['logicalUpdateRef']=digest({'retiredContainerIds':sorted(r['oldRuntimeBinding']['containerId'] for r in replacements.values()),'migration':MIGRATION})
    scope(plan)
    db=Database(plan,retained,ns)
    # Read-only preparation uses the retained Engine binding; no fake authority.
    def guard():
        live=ns['engine_get'](prepared['engine'],'containers',pg_pin['containerId'])
        require(live is not None and raw_runtime(live)==pg_pin,'POSTGRES_GENERATION_CHANGED')
    db.guard=guard
    db.verify_before()
    publish_json(context,'prepared-plan.json',plan)
    return plan,retained,engine
