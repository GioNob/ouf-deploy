#!/usr/bin/env python3
"""Stage-bound private review inputs from the already completed SQL snapshot.

No Engine/SQL/subprocess or runtime authority. This is a proposal, never an apply
entry. Configuration overlays are observed by metadata only, not opened.
"""
import hashlib,json,os,re,signal,stat,sys,types,zipfile,zlib
from pathlib import Path

HELPER='/etc/ouf/deploy-snapshots/onboarding-current-database-7fa2cd6dae5d4730/read.py'
HELPER_HASH='7fa2cd6dae5d47306ebf8c1122643fa9a5449c3fbb43571b33c9bf856511588e'
SNAPSHOT='/etc/ouf/deploy-snapshots/onboarding-finite-session-ee8b7756f72f82a6/current-onboarding-database-snapshot-v1/snapshot-inputs.json'
SNAPSHOT_HASH='000bf9de27a5a89d6132c2e594650282818957d322baa7b9166762fd0ac0eb0c'
PACKAGE='/etc/ouf/deploy-snapshots/onboarding-budget-v35-54d86bbcd2ea47fd'
CONTRACT_HASH='4de8d18fe3cb4c3a8f8ad3e3e8448bbc0c6510c596b8964b1c7782c2b1a2a0dd'
SCOPE='review-inputs-v1'
SOURCE='1b1222ceaa5af85a25c20857e7c8c1b548b12dc1'
TESTED='194b586508c6661b40a74d9c7f99ed3b876f5fbc'

class Stop(RuntimeError):pass
def require(ok,reason):
    if not ok:raise Stop(reason)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(v):return hashlib.sha256(encoded(v)).hexdigest()
def crc(raw):
    value=0
    for line in raw.decode('utf-8-sig').splitlines():value=zlib.crc32(line.encode('utf-8'),value)
    return value if value<2**31 else value-2**32

def bootstrap():
    p=Path(HELPER);require(p.is_absolute()and p.resolve()==p,'EXACT_CURRENT_DATABASE_HELPER_REQUIRED')
    for parent in p.parents:
        s=parent.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022,'ROOT_HELPER_ANCESTRY_REQUIRED')
    fd=os.open(p,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW)
    try:
        s=os.fstat(fd);pin=lambda v:tuple(getattr(v,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
        require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o400
            and s.st_nlink==1 and 0<s.st_size<=131072,'PRIVATE_HELPER_REQUIRED')
        raw=os.read(fd,131073);require(len(raw)==s.st_size and hashlib.sha256(raw).hexdigest()==HELPER_HASH
            and pin(s)==pin(os.fstat(fd))==pin(p.lstat()),'EXACT_HELPER_BYTES_REQUIRED')
    finally:os.close(fd)
    q=types.ModuleType('verified_current_database_definitions');q.__file__=str(p)
    exec(compile(raw,str(p),'exec'),q.__dict__)
    l,c,d,m,r=q.bootstrap();m.raw(str(Path(__file__).resolve()),131072)
    return q,l,c,d,m,r

def hash_file(m,path,maximum,expected):
    with m.opened(path,maximum)as(fd,s):
        h=hashlib.sha256()
        with os.fdopen(os.dup(fd),'rb')as stream:
            for block in iter(lambda:stream.read(1048576),b''):h.update(block)
        require(h.hexdigest()==expected,'EXACT_STAGED_PACKAGE_BYTES_REQUIRED')
        return {'path':str(path),'sha256':expected,'bytes':s.st_size,'metadata':list(m.identity(s))}

def packaged(m,files):
    root=Path(PACKAGE);contract=files.json(root/'source-contract.json',CONTRACT_HASH)
    require(contract['schema']=='ouf.onboarding-v35-image-source-migration-contract.v1'and contract['sourceCommit']==SOURCE
        and contract['testedCommit']==TESTED and contract['sourceAndPackagedResourcesMatched']is True
        and contract['targetApplyAuthorized']is False,'EXACT_CI_SOURCE_IMAGE_CONTRACT_REQUIRED')
    manifest=files.json(root/'manifest.json',contract['manifestSha256'])
    require(manifest['reviewedSourceCommit']==SOURCE and manifest['testedCommit']==TESTED
        and manifest['archiveSha256']==contract['archiveSha256']and manifest['archiveBytes']==contract['archiveBytes']
        and manifest['imageId']==contract['imageId']and manifest['imageRevisionLabel']==TESTED
        and manifest['preservedDeploymentSourceCommit']=='b0f5e3dacbe59ebf87e22dd6af2575e41249f51d'
        and manifest['preservedAtomicInstallationOwner']is True and manifest['sourceSchemaMigration']=='V35__managed_readiness_budget_sessions.sql'
        and manifest['targetApplyAuthorized']is False and manifest['humanBudgetGranted']is False,'EXACT_CORRECTED_IMAGE_MANIFEST_REQUIRED')
    image=hash_file(m,root/'image.tar.gz',contract['archiveBytes'],contract['archiveSha256'])
    require(image['bytes']==contract['archiveBytes'],'EXACT_IMAGE_ARCHIVE_SIZE_REQUIRED')
    jar=hash_file(m,root/'application.jar',268435456,contract['jarSha256'])
    require(jar['bytes']==contract['jarBytes'],'EXACT_TESTED_JAR_SIZE_REQUIRED')
    expected=contract['migrations'];require(len(expected)==35 and {v['version']for v in expected}=={str(i)for i in range(1,36)},'EXACT_V1_THROUGH_V35_RESOURCES_REQUIRED')
    with m.opened(root/'application.jar',268435456)as(fd,_),os.fdopen(os.dup(fd),'rb')as stream,zipfile.ZipFile(stream)as archive:
        names=archive.namelist();require(len(names)==len(set(names))and len(names)<200000,'DISTINCT_BOUNDED_JAR_MEMBERS_REQUIRED')
        configs=[v for v in names if re.fullmatch(r'BOOT-INF/classes/application(?:-[^/]+)?\.(?:yml|yaml|properties)',v)]
        require(configs==['BOOT-INF/classes/application.yml']and archive.getinfo(configs[0]).file_size<=131072
            and hashlib.sha256(archive.read(configs[0])).hexdigest()==contract['applicationYamlSha256'],'ONE_EXACT_PACKAGED_SPRING_CONFIGURATION_REQUIRED')
        members=[v for v in names if v.startswith('BOOT-INF/classes/db/migration/')and v.endswith('.sql')]
        require(set(members)=={'BOOT-INF/classes/db/migration/'+v['script']for v in expected},'EXACT_PACKAGED_MIGRATION_SET_REQUIRED')
        for row in expected:
            name='BOOT-INF/classes/db/migration/'+row['script'];require(archive.getinfo(name).file_size<=1048576,'BOUNDED_MIGRATION_RESOURCE_REQUIRED')
            raw=archive.read(name);require(hashlib.sha256(raw).hexdigest()==row['sha256']and crc(raw)==row['flywayChecksum'],'PACKAGED_MIGRATION_BYTES_CHANGED')
        require(any(v.startswith('BOOT-INF/lib/flyway-core-')and v.endswith('.jar')for v in names),'NATIVE_FLYWAY_LIBRARY_REQUIRED')
    return contract,manifest,image,jar

def assess_history(facts,contract):
    expected={v['version']:v for v in contract['migrations']if v['version']!='35'}
    rows=[v for v in facts['history']if v['type']=='SQL'];versions=[v['version']for v in rows]
    exact=len(rows)==34 and len(set(versions))==34 and set(versions)==set(expected)
    if exact:exact=all(v['success']is True and v['script']==expected[v['version']]['script']and v['checksum']==expected[v['version']]['flywayChecksum']for v in rows)
    other=[v for v in facts['history']if v['type']!='SQL']
    return {'all34SqlMigrationChecksumsMatchCandidate':exact,'nonSqlHistoryRows':len(other),
        'nonSqlHistoryTypesRecognized':all(v['type']in('SCHEMA','BASELINE')and v['success']is True for v in other),
        'allHistoryRowsSuccessful':all(v['success']is True for v in facts['history']),
        'v35AlreadyRecorded':any(v['version']=='35'for v in rows)}

def assess_schema(facts,identity):
    role=identity['runtimeRole'];relations={v['name']:v for v in facts['relations']}
    targets=('managed_onboarding_review','flyway_schema_history','source_property_revision')
    columns={v['name']for v in facts['columns']if v['relation']=='managed_onboarding_review'}
    constraints={v['name']:v for v in facts['constraints']if v['relation']=='managed_onboarding_review'}
    legacy=constraints.get('managed_onboarding_review_readiness_attempts_check',{})
    definition=legacy.get('definition','');norm=re.sub(r'\s+','',definition).lower()
    old_limit=legacy.get('validated')is True and 'readiness_attempts>=0'in norm and 'readiness_attempts<=128'in norm
    return {'runtimeOwnsV35AffectedRelations':all(v in relations and relations[v]['owner']==role and relations[v]['runtimeOwns']is True for v in targets),
        'runtimeHasSchemaCreate':facts['schema'].get('runtimeCreate')is True if type(facts['schema'])is dict else False,
        'legacyAttemptConstraintRecognized':old_limit,'budgetTableAbsent':'managed_readiness_budget_session'not in relations,
        'readinessSessionColumnAbsent':'readiness_session_id'not in columns,
        'v35PrerequisiteReviewColumnsPresent':{'challenge_id','readiness_attempts','readiness_generation','readiness_started_at'}<=columns}

def assess_configuration(d,actual,plan,contract):
    env=d.environment(actual);native=plan['nativeFlywayConfiguration'];overlays=native.get('ownerOverlays',[])
    # Do not reopen potentially secret-bearing owner/OAuth overlays. Their full
    # historical hashes remain private inputs for the separately reviewed entry.
    channels={k:bool(env.get(k))for k in('SPRING_APPLICATION_JSON','SPRING_CONFIG_ADDITIONAL_LOCATION','JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','JAVA_OPTS','_JAVA_OPTIONS')}
    metadata=[]
    for selected in overlays:
        binding=selected['binding'];p=Path(binding['path'])
        require(p.is_absolute()and p.resolve()==p,'EXACT_RETAINED_OWNER_OVERLAY_PATH_REQUIRED')
        root_ancestry=True
        for parent in p.parents:
            s=parent.lstat();require(stat.S_ISDIR(s.st_mode),'DIRECTORY_OWNER_OVERLAY_ANCESTRY_REQUIRED')
            root_ancestry=root_ancestry and s.st_uid==0 and not s.st_mode&0o022
        s=p.lstat();require(stat.S_ISREG(s.st_mode)and s.st_nlink==1,'REGULAR_RETAINED_OWNER_OVERLAY_REQUIRED')
        observed=list((s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns))
        matches=[v for v in actual['Mounts']if v['Destination']==selected['target']]
        metadata.append({'rootAncestryCustodied':bool(root_ancestry),'sameRetainedMetadata':observed==binding['metadata'],'readOnlyExactMount':len(matches)==1 and matches[0]['Type']=='bind'
            and matches[0]['RW']is False and matches[0]['Source']==str(p),'contentsRead':False})
    return {'packagedSpringConfigurationMatchesRetainedOwner':native.get('configurationSha256')==contract['applicationYamlSha256'],
        'retainedNativeFlywayEnabledByDefault':native.get('nativeFlywayEnabledByDefault')is True,
        'retainedConfigurationClassificationDeclared':native.get('sameDatasourceAsApplication')is True and native.get('higherPriorityMigrationOverridesAbsent')is True,
        'currentDeclarationChannelsPresent':channels,'ownerOverlayCount':len(overlays),
        'ownerOverlayMetadataMatchesRetained':all(v['sameRetainedMetadata']and v['readOnlyExactMount']for v in metadata),
        'ownerOverlayRootAncestryCustodied':all(v['rootAncestryCustodied']for v in metadata),
        'ownerOverlayContentsRead':False,'allCurrentConfigurationPrecedenceResolved':False,
        'currentConfigurationMustBeRevalidatedByQualifiedApplyEntry':True}

def prepare(q,l,c,d,m,r):
    require(not os.path.lexists(Path(PACKAGE)/SCOPE),'V35_REVIEW_INPUTS_ALREADY_CLAIMED_NO_REPLAY')
    root=r.exclusive_root(PACKAGE,SCOPE)
    m.new_file(root,'claim.json',{'schema':'ouf.onboarding-v35-review-inputs-claim.v1','snapshotInputsHash':SNAPSHOT_HASH,
        'maximumSeconds':90,'engineRequestsAllowed':False,'sqlAllowed':False,'runtimeEffectsAllowed':False,'automaticReplayAllowed':False,'budgetReset':False})
    files=m.Facts();saved=files.json(SNAPSHOT,SNAPSHOT_HASH);completion=files.json(Path(SNAPSHOT).parent/'complete.json')
    require(saved['schema']=='ouf.current-onboarding-database-private-snapshot.v1'and saved['inputHash']==d.INPUT_HASH
        and saved['historicalNativeLifecycleLineageMatched']is True and saved['targetApplyAuthorized']is False
        and saved['historicalAuthorityReused']is False and saved['automaticReplayAllowed']is False and saved['budgetReset']is False
        and completion['privateSnapshotInputsHash']==SNAPSHOT_HASH and completion['status']=='CURRENT_ONBOARDING_DATABASE_SNAPSHOT_OBSERVED'
        and completion['complete']is True,'EXACT_COMPLETED_READ_ONLY_SNAPSHOT_REQUIRED')
    for ref in saved['retainedFiles']:files.json(ref['path'],ref['sha256'])
    inputs=files.json(d.INPUT,d.INPUT_HASH);require(inputs['bootId']==Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'SAME_RETAINED_HOST_BOOT_REQUIRED')
    pin={v['path']:v['sha256']for v in saved['retainedFiles']};ownerpath=str(Path(q.OWNER)/'execution-plan.json')
    require(ownerpath in pin,'CURRENT_OWNER_PLAN_MUST_BE_BOUND_BY_SQL_SNAPSHOT')
    plan=files.json(ownerpath,pin[ownerpath]);observations={name:files.json(ref['path'],ref['sha256'])for name,ref in inputs['runtimeObservations'].items()if name in('onboarding','postgres')}
    processes=c.process_comparison(m,inputs,observations)
    require(all(v['observable']and v['matchesCaptured']for v in processes.values()),'CAPTURED_APPLICATION_PROCESS_CHANGED')
    facts=files.json(saved['snapshotPath'],saved['snapshotSha256']);sql_report=d.qualify_snapshot(facts,saved['profile'])
    require(sql_report['selectedConfigurationMatches']is True and sql_report['selectedReviewCount']==1
        and sql_report['selectedReadinessAttempts']==3 and sql_report['selectedReadinessGeneration']==4
        and sql_report['selectedReadinessPhase']=='PAUSED'and sql_report['activeReadinessLeases']==0,'EXACT_RETAINED_PAUSED_REVIEW_REQUIRED')
    contract,manifest,image,jar=packaged(m,files);history=assess_history(facts,contract);schema=assess_schema(facts,saved['profile']['identity'])
    configuration=assess_configuration(d,observations['onboarding'],plan,contract)
    capacity=facts['capacity'];capacity_observed=(facts['standby']is False and capacity['preparedTransactions']==0
        and capacity['currentConnections']+3<capacity['maximumConnections']-capacity['reservedForSuperusers'])
    proposal={'schema':'ouf.onboarding-v35-private-review-inputs.v1','kind':'PROPOSAL_NOT_EXECUTABLE_AUTHORITY',
        'snapshotInputsHash':SNAPSHOT_HASH,'inputHash':d.INPUT_HASH,'packageContractHash':CONTRACT_HASH,
        'candidateManifest':manifest,'imageArchive':image,'applicationJar':jar,'historyAssessment':history,'schemaAssessment':schema,
        'configurationAssessment':configuration,'capacitySnapshotHasHeadroom':capacity_observed,
        'boundDatabaseProfile':saved['profile'],'currentOwnerPlanBinding':{'path':ownerpath,'sha256':pin[ownerpath]},
        'capturedOnboardingBinding':inputs['currentBindings']['onboarding'],'capturedProcessPins':processes,
        'proposedMigration':next(v for v in contract['migrations']if v['version']=='35'),
        'proposedEffectOrder':['FRESH_CURRENT_BINDING_CONFIG_DATABASE_ADMISSION_AND_SIGNED_REVIEW','IMPORT_EXACT_IMAGE',
            'QUIESCE_ONLY_ONBOARDING','VERIFIED_QUIESCED_BACKUP','REPLACE_ONLY_ONBOARDING_WITH_RETAINED_SPEC',
            'EXPLICIT_REVIEWED_APPLICATION_FLYWAY_V35','VERIFY_HISTORY_SCHEMA_AND_SOURCE_COUNTERS','RESTORE_REVIEWED_RESTART_POLICY'],
        'applyEntryQualified':False,'currentConfigurationPrecedenceResolved':False,'databaseSnapshotFreshForApplyProven':False,
        'databaseAdmissionProven':False,'lifecycleMutationAuthorized':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
        'sourceActivationAllowed':False,'humanBudgetGranted':False,'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False,
        'retainedFiles':list(files.files.values())}
    files.recheck();require(processes==c.process_comparison(m,inputs,observations),'PROCESS_CHANGED_DURING_PREPARATION')
    require(configuration==assess_configuration(d,observations['onboarding'],plan,contract),'CONFIGURATION_METADATA_CHANGED_DURING_PREPARATION')
    for row in(image,jar):
        with m.opened(row['path'],row['bytes'])as(_,s):require(list(m.identity(s))==row['metadata'],'STAGED_PACKAGE_METADATA_CHANGED')
    m.new_file(root,'review-inputs.json',proposal)
    result={'schema':'ouf.onboarding-v35-review-inputs-result.v1','status':'ONBOARDING_V35_PACKAGE_AND_REVIEW_INPUTS_PREPARED','complete':True,
        'packagePath':PACKAGE,'privateReviewInputsPath':str(root/'review-inputs.json'),'privateReviewInputsHash':digest(proposal),
        **history,**schema,**configuration,'capacitySnapshotHasHeadroom':capacity_observed,'candidatePackagedMigrationsMatchSource':True,
        'candidateSourceCommit':SOURCE,'newMigrationVersion':35,'newMigrationFlywayChecksum':1095739786,
        'selectedReadinessAttempts':3,'selectedReadinessGeneration':4,'selectedReadinessPhase':'PAUSED','capturedProcessPins':processes,
        'engineGetAttempts':0,'sqlSessionAttempts':0,'subprocessesDispatched':0,'containerExecAttempts':0,'imageLoaded':False,
        'databaseMigrations':0,'sourceActivations':0,'humanBudgetsGranted':0,'serviceCredentialFilesOpened':0,
        'bearerFilesOpened':0,'privateSigningKeysRead':0,'configurationValuesPrinted':False,'addressesPrinted':False,
        'oldBudgetImagesRemainBlocked':True,'retainedContextWrites':0,'runtimeEffectsDispatched':0,'originalRequestRepeated':False,
        'applyEntryQualified':False,'databaseSnapshotFreshForApplyProven':False,'databaseAdmissionProven':False,
        'migrationAuthorized':False,'lifecycleMutationAuthorized':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
        'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}
    m.new_file(root,'complete.json',result);return result

def main():
    try:
        require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
            and len(sys.argv)==1,'ONE_ISOLATED_ROOT_REVIEW_PREPARATION_REQUIRED')
        signal.signal(signal.SIGALRM,lambda *_:(_ for _ in()).throw(Stop('REVIEW_INPUTS_PREPARATION_DEADLINE')));signal.alarm(90)
        result=prepare(*bootstrap())
    except Exception as error:
        reason=str(error)if type(error).__name__in('Stop','Denied')and re.fullmatch('[A-Z0-9_]{1,120}',str(error))else'V35_REVIEW_INPUTS_UNPROVEN'
        result={'schema':'ouf.onboarding-v35-review-inputs-result.v1','status':'STOP_RECONCILE','complete':False,'reasonCode':reason,
            'privatePreparationMayBePartial':True,'engineGetAttempts':0,'sqlSessionAttempts':0,'runtimeEffectsDispatched':0,
            'imageLoaded':False,'databaseMigrations':0,'sourceActivations':0,'humanBudgetsGranted':0,
            'targetApplyAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}
    finally:signal.alarm(0)
    print(encoded(result).decode(),flush=True);return 0 if result.get('complete')is True else 2
if __name__=='__main__':raise SystemExit(main())
