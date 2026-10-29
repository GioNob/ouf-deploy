#!/usr/bin/env python3
"""One new read-only SQL snapshot, bound to the completed b0 installation owner.

Old metadata/SQL entrypoints and claims are never invoked or rewritten. Historical
authority is evidence only. No current application config or migration admission.
"""
import hashlib,json,os,re,signal,stat,sys,types
from pathlib import Path

HELPER='/etc/ouf/deploy-snapshots/onboarding-current-lineage-4afbab94d27472c7/read.py'
HELPER_HASH='4afbab94d27472c7584e7d16ceb92e6aa3468707152dfc3dc4c25ea7bd432399'
LINEAGE='/etc/ouf/deploy-snapshots/onboarding-finite-session-ee8b7756f72f82a6/current-source-revision-lineage-v1/lineage.json'
LINEAGE_HASH='6c7aecaae138c31b35a7adbc20e2fa53c5657aba477f92d52e82c77d53fe8f32'
OWNER='/etc/ouf/deploy-snapshots/installation-owner-update-execution-hnfn0zwg'
SOURCE='b0f5e3dacbe59ebf87e22dd6af2575e41249f51d'
SCOPE='current-onboarding-database-snapshot-v1'
STAGES=('VERIFY_INPUTS',)+tuple('onboarding.'+s for s in ('IMPORT_IMAGE','DISABLE_OLD_RESTART','STOP_OLD',
 'DETACH_OLD_ENDPOINT','RENAME_OLD','CREATE_REPLACEMENT','START_REPLACEMENT','READINESS','RESTORE_RESTART_POLICY'))+('VERIFY_FINAL',)
HISTORICAL_RUNTIME={'configHash':'7083a2ab8e42a9b5b2c601bfb588ea47a8bc378f63f04de6d7624e55fa9381c8',
 'containerId':'0165a7d260a9c146101ac1471c843b1300587c579a18e99ea0c3a78cadcb0aae',
 'hostConfigHash':'102e08cc114b3f9459d5c691a46c9bbb3634b7243a6bddd81d0bd5ad7a14bde9',
 'imageId':'sha256:c124a832a1f9f07967a8f3ef9ba9692610ab5c97aa4719e614867f44e6aa63ae',
 'mountsHash':'831a67eb22989130c63d836388f2509b6d3924dd04f8feef3dfab1b040d54763',
 'networkSettingsHash':'2efff26b2a7699091f048c65dc147e36ba5f54eae42ac02f7a4e0d12ca02490c',
 'pid':335586,'startedAt':'2026-10-19T14:55:21.10058135Z'}

class Stop(RuntimeError):pass
def require(ok,code):
    if not ok:raise Stop(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(v):return hashlib.sha256(encoded(v)).hexdigest()

def bootstrap():
    p=Path(HELPER);require(p.is_absolute()and p.resolve()==p,'EXACT_CURRENT_LINEAGE_HELPER_REQUIRED')
    for parent in p.parents:
        s=parent.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022,'PROTECTED_HELPER_ANCESTRY_REQUIRED')
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        s=os.fstat(fd);pin=lambda v:tuple(getattr(v,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
        require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o400
            and s.st_nlink==1 and 0<s.st_size<=131072,'PRIVATE_HELPER_REQUIRED')
        raw=os.read(fd,131073);require(len(raw)==s.st_size and hashlib.sha256(raw).hexdigest()==HELPER_HASH
            and pin(s)==pin(os.fstat(fd))==pin(p.lstat()),'EXACT_CURRENT_LINEAGE_HELPER_BYTES_REQUIRED')
    finally:os.close(fd)
    l=types.ModuleType('verified_current_lineage_definitions');l.__file__=str(p)
    exec(compile(raw,str(p),'exec'),l.__dict__)
    c,d,m,r=l.bootstrap();m.raw(str(Path(__file__).resolve()),131072)
    return l,c,d,m,r

def verify_owner(plan,review,authority,journal,authority_hash,engine,boot):
    require(plan['schema']=='ouf.installation-binding-owner-update-plan.v1'and plan['authorityDirectory']==OWNER
        and plan['engine']==engine and set(plan['replacements'])=={'onboarding'}
        and plan['replacements']['onboarding']['imageAudit']['sourceCommit']==SOURCE
        and plan['databaseMigration']is None and plan['onboardingMigrationsUnchanged']is True
        and plan['maximumGatewayWrites']==0,'EXACT_COMPLETED_CURRENT_INSTALLATION_OWNER_REQUIRED')
    scope=review['scopes']['installationOwnerUpdate']
    require(scope['planHash']==digest(plan)and scope['stages']==list(STAGES)
        and scope['candidateSourceCommit']==SOURCE and scope['onboardingMigrationsUnchanged']is True
        and authority['scopedExecution']['reviewHash']==digest(review),'CURRENT_INSTALLATION_OWNER_REVIEW_LINKS_CHANGED')
    require(journal['schema']=='ouf.installation-binding-owner-update-journal.v1'and journal['version']==29
        and journal['scopeHash']==digest(scope)and journal['authorityHash']==authority_hash
        and journal['bootId']==boot and journal['budgetReset']is False and journal['incidentState']=='RECOVERED'
        and journal['nextStage']==len(journal['effects'])==len(STAGES),'COMPLETED_CURRENT_INSTALLATION_OWNER_HISTORY_REQUIRED')
    for stage,e in zip(STAGES,journal['effects']):
        require(e['stage']==stage and e['state']=='APPLIED'
            and e['intentHash']==digest({'planHash':digest(plan),'stage':stage}),'CURRENT_INSTALLATION_OWNER_EFFECT_HISTORY_CHANGED')
    final=journal['effects'][-1]['evidence']
    require(final['onboarding']['runtimeBinding']==HISTORICAL_RUNTIME and final['databaseMigrationsPerformed']==0
        and final['metadataChanged']is False and final['routeMapHash']=='d5a4040e30e289c150f9d2862ff41e83e22809a9e2202ac19388e744f2c5e927',
        'CURRENT_INSTALLATION_OWNER_FINAL_EVIDENCE_CHANGED')
    return final

def query(d,role):
    sql=d.query(role)
    extra=""" 'revisionJournalTriggers',coalesce((SELECT jsonb_agg(jsonb_build_object('name',t.tgname,
   'enabled',t.tgenabled,'definition',pg_get_triggerdef(t.oid,true)) ORDER BY t.tgname)
   FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='ouf_onboarding' AND c.relname='source_property_revision' AND NOT t.tgisinternal),'[]'::jsonb),
"""
    require(sql.count(" 'history',coalesce")==1,'EXACT_SHARED_READ_ONLY_QUERY_REQUIRED')
    return sql.replace(" 'history',coalesce",extra+" 'history',coalesce").replace(
        "'managed_onboarding_review','managed_readiness_budget_session','flyway_schema_history'",
        "'managed_onboarding_review','managed_readiness_budget_session','flyway_schema_history','source_property_revision'")

def arguments(d,profile,config):
    p=profile;identity=p['identity'];program=p['containerPrograms']
    require(p['schema']=='ouf.current-onboarding-database-snapshot-profile.v1'and p['maximumSqlSessionAttempts']==1
        and p['sqlSha256']==hashlib.sha256(query(d,identity['runtimeRole']).encode()).hexdigest(),'CURRENT_ONE_SESSION_PROFILE_REQUIRED')
    for v in(identity['database'],identity['runtimeRole'],identity['adminRole']):d.identifier(v)
    return [p['dockerExecutable']['path'],'--host','unix://'+p['engineBinding']['socketPath'],'--config',str(config),
        'exec',p['postgresRuntimeBinding']['containerId'],program['env'],'-i','LC_ALL=C',
        'PGPASSFILE=/dev/null','PGSERVICEFILE=/dev/null','PGSYSCONFDIR=/nonexistent',
        'PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=5000 -c lock_timeout=1000 -c idle_in_transaction_session_timeout=5000',
        program['timeout'],'-s','KILL','15',program['psql'],'-X','-w','-q','-A','-t','-v','ON_ERROR_STOP=1',
        '-v','VERBOSITY=sqlstate','-h',p['unixSocketDirectory'],'-p',str(identity['postgresPort']),
        '-U',identity['adminRole'],'-d',identity['database'],'-c',query(d,identity['runtimeRole'])]

def prepare(l,c,d,m,r):
    from tools.ingestion_readiness_patch_execution import runtime_bindings,database_read
    require(not os.path.lexists(Path(m.PACKAGE)/SCOPE),'CURRENT_DATABASE_SCOPE_ALREADY_CLAIMED_NO_REPLAY')
    root=r.exclusive_root(m.PACKAGE,SCOPE)
    m.new_file(root,'claim.json',{'schema':'ouf.current-onboarding-database-claim.v1','inputHash':d.INPUT_HASH,
        'lineageHash':LINEAGE_HASH,'maximumSeconds':90,'maximumEngineGets':4,'maximumSqlSessionAttempts':1,
        'oldBudgetImageBlocked':True,'automaticReplayAllowed':False,'budgetReset':False})
    files=m.Facts();lineage=files.json(LINEAGE,LINEAGE_HASH);inputs=files.json(d.INPUT,d.INPUT_HASH)
    require(lineage['schema']=='ouf.current-source-revision-lineage-private.v1'and lineage['inputHash']==d.INPUT_HASH
        and lineage['assessment']['historicalPostgresRuntimeMatchesCaptured']is True
        and lineage['assessment']['declaredCapturedOnboardingSourceCommit']==SOURCE
        and lineage['newBindingAcceptedForRuntime']is False and lineage['newSqlAttemptAuthorized']is False
        and lineage['oldBudgetImageBlocked']is True and lineage['targetApplyAuthorized']is False,
        'EXACT_COMPLETED_CURRENT_LINEAGE_REQUIRED')
    require(inputs['schema']=='ouf.onboarding-finite-session-private-inputs.v1'and inputs['kind']=='INPUTS_NOT_EXECUTABLE_AUTHORITY'
        and inputs['targetApplyAuthorized']is False and inputs['automaticReplayAllowed']is False and inputs['budgetReset']is False
        and inputs['bootId']==Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'SAME_CAPTURED_INPUTS_AND_BOOT_REQUIRED')
    completion=files.json(Path(LINEAGE).parent/'complete.json')
    require(completion['complete']is True and completion['privateLineageHash']==LINEAGE_HASH
        and completion['status']=='CURRENT_SOURCE_REVISION_LINEAGE_OBSERVED','COMPLETED_LINEAGE_RECEIPT_REQUIRED')
    for ref in lineage['retainedFiles']:files.json(ref['path'],ref['sha256'])
    observations={name:files.json(ref['path'],ref['sha256'])for name,ref in inputs['runtimeObservations'].items()if name in('onboarding','postgres')}
    require(set(observations)=={'onboarding','postgres'},'TWO_BOUND_CAPTURED_APPLICATIONS_REQUIRED')
    plan=files.json(Path(OWNER)/'execution-plan.json');review=files.json(Path(OWNER)/'review.json')
    authority=files.json(Path(OWNER)/'authority.json');journal=files.json(Path(OWNER)/'recovery.json')
    verify_owner(plan,review,authority,journal,files.files[str(Path(OWNER)/'authority.json')]['sha256'],inputs['engineBinding'],inputs['bootId'])
    actual=observations['onboarding'];label=(actual['Config'].get('Labels')or{}).get('org.opencontainers.image.revision')
    require(label==SOURCE and runtime_bindings.observed(actual,runtime_bindings.SORTED)==HISTORICAL_RUNTIME
        and plan['replacements']['onboarding']['name']==actual['Name'].lstrip('/'),'CAPTURED_ONBOARDING_NOT_COMPLETED_B0_OWNER')
    for name,row in observations.items():
        require(runtime_bindings.observed(row,runtime_bindings.NATIVE)==inputs['currentBindings'][name]
            and m.process(row)==inputs['currentProcessIdentities'][name],'SAME_CAPTURED_PROCESS_AND_RUNTIME_REQUIRED')
    require(m.lifecycle_declaration(actual)=='NO_RECOGNIZED_MANAGER_LABEL','LIFECYCLE_DECLARATION_CHANGED_REQUIRES_REVIEW')
    require(c.prior_scope_state(m,d)=={'databaseScopeExists':False,'sqlAttemptMarkerPresent':False,'databaseCompleteMarkerPresent':False},
        'OLD_DATABASE_SCOPE_CHANGED_RECONCILIATION_REQUIRED')
    transport=database_read.validate_profile(inputs['legacyIngestionDatabaseControlProfile'])
    require(runtime_bindings.observed(observations['postgres'],transport['runtimeBindingProfile'])==transport['postgresRuntimeBinding']
        and transport['engineBinding']==inputs['engineBinding'],'CURRENT_RETAINED_POSTGRES_TRANSPORT_REQUIRED')
    proposal=lineage['proposedOnboardingIdentity'];binding=proposal['binding']
    selection=d.database_selection(actual,binding,transport);admin=d.identifier(proposal['adminRole'])
    require(selection==proposal['currentEnvironmentDeclaration']and d.environment(observations['postgres']).get('POSTGRES_USER')==admin,
        'BOUND_CURRENT_ONBOARDING_DATABASE_DECLARATION_CHANGED')
    program=transport['dockerExecutable'];m.raw(program['path'],67108864,program['sha256'],private=False)
    profile={'schema':'ouf.current-onboarding-database-snapshot-profile.v1','inputHash':d.INPUT_HASH,'lineageHash':LINEAGE_HASH,
        'identity':{**selection,'adminRole':admin},'engineBinding':inputs['engineBinding'],
        'postgresRuntimeBinding':inputs['currentBindings']['postgres'],'runtimeBindingProfile':runtime_bindings.NATIVE,
        'dockerExecutable':program,'containerPrograms':transport['containerPrograms'],'unixSocketDirectory':transport['unixSocketDirectory'],
        'maximumSqlSessionAttempts':1,'sqlSha256':hashlib.sha256(query(d,selection['runtimeRole']).encode()).hexdigest(),
        'databaseIdentityFromBoundOnboardingRow':True,'nativeTransportOnlyFromIngestionProfile':True,
        'historicalAuthorityReused':False,'migrationAuthorized':False}
    m.new_file(root,'profile.json',profile);config=root/'empty-docker-config';config.mkdir(mode=0o700)
    engine=m.Engine(inputs['engineBinding'],{v['containerId']for v in inputs['currentBindings'].values()},root)
    def current(name):
        require(engine.calls<4,'FOUR_CURRENT_DATABASE_ENGINE_GETS_ONLY')
        try:row,_=engine.get(inputs['currentBindings'][name]['containerId'])
        finally:d.COUNTS['engineGetAttempts']=engine.calls
        require(runtime_bindings.observed(row,runtime_bindings.NATIVE)==inputs['currentBindings'][name]
            and m.process(row)==inputs['currentProcessIdentities'][name]and row['RestartCount']==inputs['restartCounts'][name],
            'CURRENT_DATABASE_OR_ONBOARDING_GENERATION_CHANGED')
    current('onboarding');current('postgres');files.recheck()
    require(not os.listdir(config),'EMPTY_CREDENTIAL_FREE_DOCKER_CONFIG_REQUIRED')
    argv=arguments(d,profile,config)
    m.new_file(root,'sql-attempt-01.json',{'attempt':1,'attemptNotCompletion':True,'profileHash':digest(profile),
        'queryHash':profile['sqlSha256'],'writesAllowed':False,'credentialFilesAllowed':False})
    d.COUNTS['sqlSessionAttempts']=d.COUNTS['containerExecAttempts']=1
    status,body,_=database_read.bounded_read(argv)
    current('postgres');current('onboarding');files.recheck()
    require(not os.listdir(config),'EMPTY_DOCKER_CONFIG_CHANGED')
    require(status==0 and 0<len(body)<=524288,'CURRENT_READ_ONLY_DATABASE_SNAPSHOT_UNPROVEN')
    facts=m.decode(body);report=d.qualify_snapshot(facts,profile)
    v34=[v for v in facts['history']if v['type']=='SQL'and v['version']=='34']
    report.update(v34SourcePropertyRevisionObserved=len(v34)==1 and v34[0]['script']=='V34__source_property_revision.sql'
        and v34[0]['checksum']==-1996496299 and v34[0]['success']is True,
        v35AlreadyRecorded=any(v['type']=='SQL'and v['version']=='35'for v in facts['history']),
        sourceRevisionAppendOnlyTriggerObserved=any(v['name']=='source_property_revision_append_only'and v['enabled']in('O','A')
            for v in facts['revisionJournalTriggers']))
    m.new_file(root,'database-snapshot.json',body)
    bundle={'schema':'ouf.current-onboarding-database-private-snapshot.v1','inputHash':d.INPUT_HASH,'lineageHash':LINEAGE_HASH,
        'profile':profile,'report':report,'snapshotPath':str(root/'database-snapshot.json'),'snapshotSha256':hashlib.sha256(body).hexdigest(),
        'retainedFiles':list(files.files.values()),'historicalNativeLifecycleLineageMatched':True,
        'historicalSignaturesReverified':False,'historicalAuthorityReused':False,'lifecycleMutationAuthorized':False,
        'databaseAdmissionProven':False,'targetApplyAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}
    m.new_file(root,'snapshot-inputs.json',bundle)
    result={'schema':'ouf.current-onboarding-database-snapshot-result.v1','status':'CURRENT_ONBOARDING_DATABASE_SNAPSHOT_OBSERVED',
        'complete':True,'privateSnapshotInputsPath':str(root/'snapshot-inputs.json'),'privateSnapshotInputsHash':digest(bundle),
        **d.COUNTS,'maximumEngineGets':4,'maximumSqlSessionAttempts':1,'transactionReadOnly':True,
        'onboardingDatabaseIdentityMatchesRetainedOwner':True,'currentEnvironmentDatabaseDeclarationMatchesRetainedOnboarding':True,
        'allCurrentConfigurationPrecedenceResolved':selection['allCurrentConfigurationPrecedenceResolved'],
        'currentOnboardingAndPostgresStable':True,'historicalNativeLifecycleLineageMatched':True,'currentInstallationOwnerSourceCommit':SOURCE,
        **report,'historicalAuthorityReused':False,'lifecycleMutationAuthorized':False,'serviceCredentialFilesOpened':0,
        'bearerFilesOpened':0,'privateSigningKeysRead':0,'addressesPrinted':False,'credentialValuesPrinted':False,
        'rawDatabaseRowsPrinted':False,'containerWrites':0,'imageImports':0,'databaseMigrations':0,'sourceActivations':0,
        'humanBudgetsGranted':0,'retainedContextWrites':0,'readOnlyRuntime':True,'runtimeAuthorityIssued':False,
        'targetApplyAuthorized':False,'oldBudgetImageBlocked':True,'originalRequestRepeated':False,
        'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}
    m.new_file(root,'complete.json',result);return result

def main():
    d=None
    try:
        require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
            and len(sys.argv)==1,'ONE_ISOLATED_ROOT_CURRENT_DATABASE_READ_REQUIRED')
        signal.signal(signal.SIGALRM,lambda *_:(_ for _ in()).throw(Stop('CURRENT_DATABASE_READ_DEADLINE')));signal.alarm(90)
        l,c,d,m,r=bootstrap();result=prepare(l,c,d,m,r)
    except Exception as error:
        reason=str(error)if type(error).__name__in('Stop','Denied')and re.fullmatch('[A-Z0-9_]{1,120}',str(error))else'CURRENT_DATABASE_SNAPSHOT_UNPROVEN'
        result={'schema':'ouf.current-onboarding-database-snapshot-result.v1','status':'STOP_RECONCILE','complete':False,'reasonCode':reason,
            'attemptsNotCompletion':dict(d.COUNTS)if d else{},'privateObservationMayBePartial':True,'oldBudgetImageBlocked':True,
            'databaseMigrations':0,'sourceActivations':0,'humanBudgetsGranted':0,'targetApplyAuthorized':False,
            'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}
    finally:signal.alarm(0)
    print(encoded(result).decode(),flush=True);return 0 if result.get('complete')is True else 2
if __name__=='__main__':raise SystemExit(main())
