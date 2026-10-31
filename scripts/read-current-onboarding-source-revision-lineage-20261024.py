#!/usr/bin/env python3
"""Match the later completed source-revision deployment to captured inputs.

Filesystem/proc metadata only: no old entry, Engine, SQL or lifecycle effects.
The old staged budget image remains blocked, irrespective of these results.
"""
import hashlib,json,os,re,signal,stat,sys,types
from pathlib import Path

HELPER='/etc/ouf/deploy-snapshots/onboarding-engine-reconcile-16cbb89e42b8dfed/reconcile.py'
HELPER_HASH='16cbb89e42b8dfed0e3a32b9248224d86fa21ed000b5d1e10c95c5ca04461ded'
RECON='/etc/ouf/deploy-snapshots/onboarding-finite-session-ee8b7756f72f82a6/engine-binding-reconciliation-v1/reconciliation.json'
RECON_HASH='c831dc09f4f54c99f41d4ea563c7b0629c13648f0e8c82a5f00dba5c74f299d7'
OWNER='/etc/ouf/deploy-snapshots/source-revision-execution-uow4n8lp'
PREPARATION='/etc/ouf/deploy-snapshots/source-revision-human-recovery-inmfuoj2/postboot-preparation-result.json'
PREPARATION_HASH='3eb2fd4fff1048accdb954322faa58979bb490250c8535c1dd8512253e603587'
ORIGINAL='/etc/ouf/deploy-snapshots/source-revision-postboot-prepared-kfy691gh/current-original-preparation.json'
ORIGINAL_HASH='b3988d964a3c60b06b17952863f4fc62fc9a8f1626ced82bfb864721eb7b740a'
DEPLOYED_SOURCE='be388e1462778438a208c2e00e166370fee32189'
SCOPE='current-source-revision-lineage-v1'
PREFIX=('IMPORT_IMAGE','DISABLE_OLD_RESTART','STOP_OLD')
SUFFIX=('DETACH_OLD_ENDPOINT','RENAME_OLD','CREATE_REPLACEMENT','START_REPLACEMENT','READINESS','RESTORE_RESTART_POLICY')
STAGES=('VERIFY_INPUTS',)+tuple(n+'.'+s for n in('onboarding','mcp')for s in PREFIX)+('BACKUP_ONBOARDING',)+tuple('onboarding.'+s for s in SUFFIX[:-1])+('VERIFY_MIGRATION','onboarding.RESTORE_RESTART_POLICY')+tuple('mcp.'+s for s in SUFFIX)+('GATEWAY_PREPARE_ROUTE','GATEWAY_READ_ROUTE','VERIFY_FINAL')
MIGRATION={'module':'onboarding','from':33,'to':34,'owner':'APPLICATION_FLYWAY','script':'V34__source_property_revision.sql','checksum':-1996496299,'sha256':'08161423d63540db5ee5e3084361370e0e774448ed0bd9d37acacd6ae42ff4e5'}

class Stop(RuntimeError):pass
def require(ok,code):
    if not ok:raise Stop(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(v):return hashlib.sha256(encoded(v)).hexdigest()
def pin(s):return tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))

def bootstrap():
    p=Path(HELPER);require(p.is_absolute()and p.resolve()==p,'EXACT_PROTECTED_HELPER_REQUIRED')
    for parent in p.parents:
        s=parent.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022,'PROTECTED_HELPER_ANCESTRY_REQUIRED')
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd);require(stat.S_ISREG(before.st_mode)and before.st_uid==before.st_gid==0 and before.st_nlink==1
            and stat.S_IMODE(before.st_mode)==0o400 and 0<before.st_size<=131072,'PRIVATE_HELPER_REQUIRED')
        raw=os.read(fd,131073);require(len(raw)==before.st_size and hashlib.sha256(raw).hexdigest()==HELPER_HASH
            and pin(before)==pin(os.fstat(fd))==pin(p.lstat()),'EXACT_HELPER_BYTES_REQUIRED')
    finally:os.close(fd)
    c=types.ModuleType('verified_engine_lineage_definitions');c.__file__=str(p)
    exec(compile(raw,str(p),'exec'),c.__dict__)
    d,m,r=c.bootstrap();m.raw(str(Path(__file__).resolve()),131072)
    return c,d,m,r

def verify_history(preparation,plan,review,authority,journal,authority_hash):
    require(preparation['schema']=='ouf.source-revision-postboot-preparation-result.v1'
        and preparation['runtimeAuthorityIssued']is False,'EXACT_SOURCE_REVISION_PREPARATION_REQUIRED')
    require(plan['schema']=='ouf.source-revision-native-update-plan.v1'and plan['authorityDirectory']==OWNER
        and review['authorityDirectory']==OWNER and set(plan['replacements'])=={'onboarding','mcp'}
        and plan['databaseMigration']==MIGRATION,'EXACT_SOURCE_REVISION_PLAN_REQUIRED')
    scope=review['scopes']['sourceRevisionUpdate']
    require(scope['planHash']==digest(plan)and scope['stages']==list(STAGES)and scope['databaseMigration']==MIGRATION
        and review['sourceClosureHash']==preparation['sourceClosureSha256']==authority['sourceClosureHash']
        and authority['scopedExecution']['reviewHash']==digest(review),'SOURCE_REVISION_REVIEW_LINKS_CHANGED')
    require(journal['schema']=='ouf.source-revision-update-journal.v1'and journal['budgetReset']is False
        and journal['scopeHash']==digest(scope)and journal['authorityHash']==authority_hash
        and journal['incidentState']=='RECOVERED'and journal['version']==57
        and journal['nextStage']==len(journal['effects'])==len(STAGES),'COMPLETED_SOURCE_REVISION_HISTORY_REQUIRED')
    for name,effect in zip(STAGES,journal['effects']):
        require(effect['stage']==name and effect['state']=='APPLIED'
            and effect['intentHash']==digest({'planHash':digest(plan),'stage':name}),'SOURCE_REVISION_STAGE_HISTORY_CHANGED')
    final=journal['effects'][-1]['evidence']
    require(set(final['applications'])=={'onboarding','mcp'}and final['routeMapHash']==digest(plan['gateway']['afterRoutes']),
        'SOURCE_REVISION_FINAL_EVIDENCE_CHANGED')
    return final

def prepare(c,d,m,r):
    from tools.ingestion_readiness_patch_execution import runtime_bindings
    require(not os.path.lexists(Path(m.PACKAGE)/SCOPE),'CURRENT_LINEAGE_SCOPE_ALREADY_CLAIMED_NO_REPLAY')
    root=r.exclusive_root(m.PACKAGE,SCOPE)
    m.new_file(root,'claim.json',{'schema':'ouf.current-source-revision-lineage-claim.v1','reconciliationHash':RECON_HASH,
        'inputHash':d.INPUT_HASH,'maximumSeconds':45,'engineRequestsAllowed':False,'sqlAllowed':False,
        'subprocessesAllowed':False,'oldBudgetImageBlocked':True,'automaticReplayAllowed':False,'budgetReset':False})
    files=m.Facts();previous=files.json(RECON,RECON_HASH);inputs=files.json(d.INPUT,d.INPUT_HASH)
    require(previous['schema']=='ouf.onboarding-engine-metadata-private-reconciliation.v1'
        and previous['inputHash']==d.INPUT_HASH and previous['newSqlAttemptAuthorized']is False
        and inputs['schema']=='ouf.onboarding-finite-session-private-inputs.v1'
        and inputs['kind']=='INPUTS_NOT_EXECUTABLE_AUTHORITY'and inputs['targetApplyAuthorized']is False
        and inputs['automaticReplayAllowed']is False and inputs['budgetReset']is False
        and inputs['bootId']==Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        'EXACT_CAPTURED_INPUT_AND_RECONCILIATION_REQUIRED')
    complete=files.json(Path(d.INPUT).parent/'complete.json')
    require(complete['complete']is True and complete['privateInputsHash']==d.INPUT_HASH
        and complete['engineGetAttempts']==14 and complete['currentCohortStable']is True,'COMPLETED_CAPTURE_REQUIRED')
    prep=files.json(PREPARATION,PREPARATION_HASH)
    ref=prep['currentOriginalPreparationBinding']
    require(ref=={'path':ORIGINAL,'sha256':ORIGINAL_HASH},'EXACT_POSTBOOT_ORIGINAL_REFERENCE_REQUIRED')
    original=files.json(ORIGINAL,ORIGINAL_HASH)
    plan=files.json(Path(OWNER)/'execution-plan.json');review=files.json(Path(OWNER)/'review.json')
    authority=files.json(Path(OWNER)/'authority.json');journal=files.json(Path(OWNER)/'recovery.json')
    final=verify_history(prep,plan,review,authority,journal,files.files[str(Path(OWNER)/'authority.json')]['sha256'])
    observations={}
    for name in('onboarding','postgres'):
        ref=inputs['runtimeObservations'][name];observations[name]=files.json(ref['path'],ref['sha256'])
        require(runtime_bindings.observed(observations[name],runtime_bindings.NATIVE)==inputs['currentBindings'][name],
            'EXACT_CAPTURED_RUNTIME_REQUIRED')
    runtime={'onboarding':c.runtime_comparison(final['applications']['onboarding']['runtimeBinding'],observations['onboarding'],runtime_bindings),
        'postgres':c.runtime_comparison(plan['database']['postgresRuntimeBinding'],observations['postgres'],runtime_bindings)}
    label=(observations['onboarding']['Config'].get('Labels')or{}).get('org.opencontainers.image.revision')
    safe_label=label if type(label)is str and re.fullmatch('[a-f0-9]{40}',label)else'UNVERIFIED_OR_ABSENT'
    declared=(plan['replacements']['onboarding']['request'].get('Labels')or{}).get('org.opencontainers.image.revision')
    require(declared==DEPLOYED_SOURCE,'HISTORICAL_SOURCE_REVISION_DECLARATION_CHANGED')
    engines={'prepared':c.validate_engine(plan['engine']),'plan':c.validate_engine(plan['engine']),
        'current':c.validate_engine(inputs['engineBinding'])}
    views={k:c.socket_view(v)for k,v in engines.items()};engine_report=c.classify(engines,views)
    processes=c.process_comparison(m,inputs,observations);prior=c.prior_scope_state(m,d)
    db=original['databasePlan'];rows=[v for v in db['modules']if v['module']=='onboarding']
    require(len(rows)==1 and rows[0]['schema']=='ouf_onboarding','ONE_SOURCE_REVISION_ONBOARDING_DATABASE_REQUIRED')
    binding=rows[0];before=plan['database']['before']['onboarding'];admin=d.identifier(db['mcpAuditRoleAdministration']['admin'])
    require(binding['database']==before['database']and binding['databaseOid']==before['databaseOid']and admin==before['role'],
        'SOURCE_REVISION_DATABASE_IDENTITY_LINK_CHANGED')
    require(type(binding['databaseOid'])is int and binding['databaseOid']>0,'BOUND_DATABASE_OID_REQUIRED')
    selection=None;selection_code='MATCHED_CURRENT_ENVIRONMENT_DECLARATION'
    try:selection=d.database_selection(observations['onboarding'],binding,inputs['legacyIngestionDatabaseControlProfile'])
    except Exception as error:
        selection_code=str(error)if type(error).__name__=='Stop'and re.fullmatch('[A-Z0-9_]{1,120}',str(error))else'CURRENT_ENVIRONMENT_DECLARATION_UNPROVEN'
    admin_match=d.environment(observations['postgres']).get('POSTGRES_USER')==admin
    assessment={'historicalOnboardingRuntimeMatchesCaptured':runtime['onboarding']['sortedMounts']['equal'],
        'historicalPostgresRuntimeMatchesCaptured':runtime['postgres']['native']['equal'],
        'declaredCapturedOnboardingSourceCommit':safe_label,'capturedOnboardingSourceLabelMatchesDocumentedDeployment':label==DEPLOYED_SOURCE,
        'currentDatabaseEnvMatchesSourceRevisionBinding':selection is not None,'databaseEnvAssessment':selection_code,
        'allCurrentConfigurationPrecedenceResolved':selection['allCurrentConfigurationPrecedenceResolved']if selection else False,
        'currentPostgresAdminDeclarationMatchesSourceRevision':admin_match,
        'sameBootAsSourceRevisionDeployment':journal['bootId']==inputs['bootId'],
        'historicalMigrationV34IsSourcePropertyRevision':True,'currentDatabaseSchemaRead':False,
        'engineApiIdentityProvenByThisReader':False,'databaseAdmissionProven':False,'lifecycleOwnershipProven':False}
    files.recheck()
    require(views=={k:c.socket_view(v)for k,v in engines.items()},'ENGINE_FILESYSTEM_METADATA_CHANGED')
    require(processes==c.process_comparison(m,inputs,observations),'CAPTURED_PROCESS_METADATA_CHANGED')
    require(prior==c.prior_scope_state(m,d),'PRIOR_SQL_SCOPE_CHANGED')
    require(inputs['bootId']==Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'BOOT_CHANGED_DURING_CURRENT_LINEAGE_READ')
    bundle={'schema':'ouf.current-source-revision-lineage-private.v1','inputHash':d.INPUT_HASH,'reconciliationHash':RECON_HASH,
        'currentOwnerContext':OWNER,'preparationHash':PREPARATION_HASH,'originalHash':ORIGINAL_HASH,
        'retainedFiles':list(files.files.values()),'historicalVsCapturedRuntime':runtime,'engineComparison':engine_report,
        'capturedProcessPins':processes,'priorScopeState':prior,'assessment':assessment,
        'proposedOnboardingIdentity':{'binding':binding,'adminRole':admin,'currentEnvironmentDeclaration':selection},
        'identitySource':'SOURCE_REVISION_BOUND_ORIGINAL_ONBOARDING_ROW_NOT_INGESTION_IDENTITY',
        'historicalAuthorityNotAcceptedForExecution':True,'historicalSignaturesReverified':False,
        'oldBudgetImageBlocked':True,'newSqlAttemptAuthorized':False,'newBindingAcceptedForRuntime':False,
        'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}
    m.new_file(root,'lineage.json',bundle)
    result={'schema':'ouf.current-source-revision-lineage-result.v1','status':'CURRENT_SOURCE_REVISION_LINEAGE_OBSERVED','complete':True,
        'privateLineagePath':str(root/'lineage.json'),'privateLineageHash':digest(bundle),**assessment,
        'historicalVsCapturedRuntime':runtime,'sourceRevisionEngineComparison':engine_report,
        'capturedProcessPins':processes,'priorScopeState':prior,'engineGetAttempts':0,'engineConnections':0,
        'sqlSessionAttempts':0,'containerExecAttempts':0,'subprocessesDispatched':0,'serviceCredentialFilesOpened':0,
        'bearerFilesOpened':0,'privateSigningKeysRead':0,'addressesPrinted':False,'credentialValuesPrinted':False,
        'databaseMigrations':0,'imageImports':0,'containerWrites':0,'sourceActivations':0,'humanBudgetsGranted':0,
        'retainedFileWrites':0,'privateEvidenceWrites':True,'readOnlyRuntime':True,'oldBudgetImageBlocked':True,
        'originalRequestRepeated':False,'newSqlAttemptAuthorized':False,'newBindingAcceptedForRuntime':False,
        'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}
    m.new_file(root,'complete.json',result);return result

def main():
    try:
        require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
            and len(sys.argv)==1,'ONE_ISOLATED_ROOT_CURRENT_LINEAGE_READ_REQUIRED')
        def expired(*_):raise Stop('CURRENT_LINEAGE_READ_DEADLINE')
        signal.signal(signal.SIGALRM,expired);signal.alarm(45)
        result=prepare(*bootstrap())
    except Exception as error:
        reason=str(error)if type(error).__name__in('Stop','Denied')and re.fullmatch('[A-Z0-9_]{1,120}',str(error))else'CURRENT_LINEAGE_READ_UNPROVEN'
        result={'schema':'ouf.current-source-revision-lineage-result.v1','status':'STOP_RECONCILE','complete':False,
            'reasonCode':reason,'privateReadMayBePartial':True,'engineGetAttempts':0,'sqlSessionAttempts':0,
            'containerExecAttempts':0,'oldBudgetImageBlocked':True,'newSqlAttemptAuthorized':False,
            'targetApplyAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}
    finally:signal.alarm(0)
    print(encoded(result).decode(),flush=True);return 0 if result.get('complete')is True else 2
if __name__=='__main__':raise SystemExit(main())
