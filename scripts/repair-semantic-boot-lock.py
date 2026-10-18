#!/usr/bin/env python3
"""Provision the sealed common lock through tmpfiles; preserve native guard and authority."""
import fcntl,hashlib,json,os,re,stat,subprocess,tempfile,time
from pathlib import Path

def require(value,reason):
    if not value:raise ValueError(reason)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def parents(path):
    require(path.is_absolute()and'..'not in path.parts,'EXPLICIT_PATH_REQUIRED')
    for item in path.parents:
        info=item.lstat();require(stat.S_ISDIR(info.st_mode)and info.st_uid==info.st_gid==0 and not info.st_mode&0o022,'UNSAFE_PARENT')
def new(path,raw,mode=0o600):
    parents(path);fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    try:os.write(fd,raw);os.fsync(fd)
    finally:os.close(fd)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)
def invoke(argv,timeout=20):
    result=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,timeout=timeout,
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    require(result.returncode==0,'NATIVE_OPERATION_UNPROVEN')
    require(len(result.stdout)<=1048576 and len(result.stderr)<=1048576,'OUTPUT_BOUND')
    return result.stdout

def plan(reader,selection,recovery):
    require(recovery['schema']=='ouf.semantic-boot-lock-recovery-selection.v1','SELECTION_SCHEMA')
    actual=reader.collect(selection)
    require(actual.get('readComplete')and actual['knownBootSource']and actual['nftExecutableMatches']
        and actual['restorerMatchesProfile']and actual['compilerMatchesProfile'],'NATIVE_CLOSURE_CHANGED')
    require(actual['loadedBinding']['sha256']==recovery['expectedBootProfileSha256'],'BOOT_PROFILE_CHANGED')
    require(actual['units'][selection['dockerUnit']]['ActiveState']=='inactive'
        and actual['units'][selection['guardUnit']]['ActiveState']=='failed','SERVICE_STATE_CHANGED')
    require(all(row.get('passed')and row['metadata']['matches']for row in actual['ownerSourceHashesMatch'].values())
        and all(actual['pairedConfigurationMatches'].values()),'SOURCE_OR_PAIR_DRIFT')
    require(actual['nativeBootValidation'].get('passed')and actual.get('ownedTableFamilies')==[],'EMPTY_BOOT_REQUIRED')
    failure=actual['nativeOwnerReadConfiguration']
    require(failure.get('passed')is False and failure.get('errorClass')=='FileNotFoundError'
        and any(f.get('function')=='read_configuration'and f.get('line')==91 for f in failure.get('frames',[])),
        'DIFFERENT_NATIVE_FAILURE')
    require(actual['ownerJournal'].get('passed')and actual['ownerJournal']['metadata'].get('state')=='QUIESCED'
        and actual['ownerJournal']['metadata'].get('leaseAuthorized')is False
        and actual['ownerJournal']['metadata'].get('startAuthorized')is False
        and actual['bootJournal'].get('passed')and actual['bootJournal']['metadata'].get('state')=='RUNTIME_EMPTY'
        and actual['bootJournal']['metadata'].get('startAuthorized')is False,'JOURNAL_CHANGED')
    for path,expected in recovery['expectedUnitHashes'].items():
        require(sha(reader.read(path))==expected,'UNIT_CHANGED')
    profile=reader.parse(reader.sealed(actual['loadedBinding']['profile'],actual['loadedBinding']['sha256']))
    owner=reader.parse(reader.sealed(profile['coordinatedConfiguration'],profile['coordinatedConfigurationHash']))
    boot=reader.parse(reader.sealed(profile['bootConfiguration'],profile['bootConfigurationHash']))
    lock=Path(owner['commonLockFile']);parents(lock)
    require(re.fullmatch(r'/[A-Za-z0-9_./-]+',str(lock))and any(lock.is_relative_to(Path(root))for root in recovery['volatileRoots']),
        'VOLATILE_LOCK_REFERENCE_REQUIRED')
    require(not os.path.lexists(lock)and boot['lockFile']==str(lock),'MISSING_COMMON_LOCK_REQUIRED')
    # Prove that the journal, the other input at native line91, still exists under its seal/custody.
    reader.read(owner['journalFile']);reader.read(boot['journalFile'])
    for name,expected in profile['sourceHashes'].items():
        require(re.fullmatch(r'(scripts|tools)/[A-Za-z0-9_]+\.py',name),'SOURCE_REFERENCE')
        reader.sealed(Path(actual['loadedBinding']['source']).parents[1]/name,expected)
    tmpfile=Path(recovery['tmpfilesRule']);parents(tmpfile)
    files={tmpfile:('f '+str(lock)+' 0600 root root - -\n').encode()}
    setup=recovery['tmpfilesSetupUnit'];require(re.fullmatch('[A-Za-z0-9_.-]+\.service',setup),'SETUP_UNIT')
    dropin=('[Unit]\nRequires='+setup+'\nAfter='+setup+'\n').encode()
    for unit,path in recovery['dropins'].items():
        require(unit in (selection['guardUnit'],selection['dockerUnit']),'EXACT_UNIT_PAIR')
        path=Path(path);parents(path if path.parent.exists()else path.parent)
        require(not os.path.lexists(path),'MANAGED_DROPIN_ALREADY_PRESENT')
        if path.parent.exists():parents(path)
        files[path]=dropin
    require(len(recovery['dropins'])==2 and all(not os.path.lexists(p)for p in files),'EXISTING_MANAGED_ARTIFACT')
    for path in (recovery['systemctl'],recovery['tmpfilesExecutable']):
        # Native package-manager executable: root-owned, executable, no writable ancestors or aliases.
        info=Path(path).lstat();parents(Path(path))
        require(stat.S_ISREG(info.st_mode)and info.st_uid==info.st_gid==0 and info.st_mode&0o111 and not info.st_mode&0o022,'EXECUTABLE_CUSTODY')
    parents(Path(recovery['incidentPointer']))
    require(not os.path.lexists(recovery['incidentPointer']),'INCIDENT_ALREADY_PREPARED_RECONCILE')
    return {'files':files,'lock':lock,'owner':owner,'profile':profile,'bootBinding':actual['loadedBinding'],
        'selection':selection,'recovery':recovery}

def apply(reader,value,call=invoke):
    recovery=value['recovery'];selection=value['selection'];root=Path(selection['privateParent'])
    case=Path(tempfile.mkdtemp(prefix='boot-lock-recovery-',dir=root));case.chmod(0o700)
    journal=case/'journal.json';phase='PREPARED';fd=None
    def record(name):
        nonlocal phase
        phase=name;raw=encoded({'schema':'ouf.semantic-boot-lock-recovery-journal.v1','phase':phase,
            'runtimeAuthorityIssued':False,'automaticRetry':False})
        temp=case/(name+'.json');new(temp,raw);os.replace(temp,journal)
    review={'schema':'ouf.semantic-boot-lock-recovery-review.v1','lockFile':str(value['lock']),
        'artifactHashes':{str(p):sha(raw)for p,raw in value['files'].items()},'bootBinding':value['bootBinding'],
        'nativeGuardUnchanged':True,'providerLeaseIssued':False,'profilePublicationPerformed':False,
        'explicitJobRetries':0,'existingServicesMayAutoResume':True,'maximumSeconds':300}
    new(case/'review.json',encoded(review));new(Path(recovery['incidentPointer']),encoded({'contextPath':str(case),'reviewSha256':sha(encoded(review))}))
    try:
        record('ARTIFACT_INSTALL_INTENT')
        for path,raw in value['files'].items():
            if not path.parent.exists():path.parent.mkdir(mode=0o755)
            new(path,raw,0o644);require(reader.read(path)==raw,'ARTIFACT_READBACK')
        record('LOCK_PROVISION_INTENT')
        # f creates a missing file; no f+, truncation, chmod of an existing lock, unlink or replacement.
        call([recovery['tmpfilesExecutable'],'--create',recovery['tmpfilesRule']])
        lock=value['lock'];info=lock.lstat()
        require(stat.S_ISREG(info.st_mode)and info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o600
            and info.st_nlink==1 and info.st_size==0,'PROVISIONED_LOCK_CUSTODY')
        fd=os.open(lock,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        inode=(os.fstat(fd).st_dev,os.fstat(fd).st_ino)
        # The original pure native validator must now pass without any patched condition.
        source=Path(value['bootBinding']['source']).parents[1]/'scripts/run_semantic_coordinated_lease_owner.py'
        native=reader.load_known(source,reader.KNOWN['owner'],'recovery_native_read_only_owner')
        native.read_configuration(Path(value['profile']['coordinatedConfiguration']),value['profile']['coordinatedConfigurationHash'],source.parents[1])
        fcntl.flock(fd,fcntl.LOCK_UN);os.close(fd);fd=None
        record('MANAGER_RELOAD_INTENT');call([recovery['systemctl'],'daemon-reload'])
        # Restore/start only through the existing unit dependencies and original sealed boot guard.
        # No guard invocation replacement, sentinel, cached lease or provider authorization is supplied.
        record('DOCKER_START_INTENT');call([recovery['systemctl'],'start',selection['dockerUnit']],120)
        record('READBACK')
        after=reader.collect(selection)
        require(after.get('readComplete')and after['nativeOwnerReadConfiguration'].get('passed')
            and after['units'][selection['dockerUnit']]['ActiveState']=='active'
            and after['units'][selection['guardUnit']]['Result']=='success'
            and after.get('ownedTableFamilies')==['bridge','inet'],'NATIVE_RECOVERY_READBACK_UNPROVEN')
        require(inode==(lock.lstat().st_dev,lock.lstat().st_ino),'LOCK_REPLACED')
        journal_state=after['ownerJournal']['metadata']
        require(journal_state.get('leaseAuthorized')is False and journal_state.get('startAuthorized')is False,
            'UNEXPECTED_PROVIDER_AUTHORITY')
        require(after['loadedBinding']==value['bootBinding'],'BOOT_BINDING_CHANGED')
        for path,expected in recovery['expectedUnitHashes'].items():require(sha(reader.read(path))==expected,'ORIGINAL_UNIT_CHANGED')
        record('COMPLETE')
        return {'complete':True,'contextPath':str(case),'dockerActive':True,'nativeGuardPassed':True,
            'providerLeaseIssued':False,'providerReconciliationRequired':True,'runtimeAuthorityIssued':False,
            'applicationReadinessProven':False,'functionalMilestonesProven':4,'completedTechnicalPhases':8,
            'sourceRevisionReleasePerformed':False,'explicitJobRetries':0,'existingServicesMayAutoResume':True}
    except Exception as error:
        # Intent is durable; never auto-retry a timed-out start or roll back kernel/DB state.
        return {'complete':False,'contextPath':str(case),'phase':phase,'errorClass':type(error).__name__,
            'reconciliationRequired':True,'automaticRetry':False,'exceptionMessagePrinted':False,
            'runtimeAuthorityIssued':False,'completedTechnicalPhases':8,'functionalMilestonesProven':4}
    finally:
        if fd is not None:os.close(fd)
