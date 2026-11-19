#!/usr/bin/env python3
"""Reconcile a stopped host recovery and allow only its native atomic journal directory."""
import fcntl,json,os,re,stat,tempfile
from pathlib import Path

def require(ok,code):
    if not ok:raise ValueError(code)
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def new(path,raw,mode=0o600):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    try:
        remaining=memoryview(raw)
        while remaining:
            written=os.write(fd,remaining);require(written>0,'SHORT_WRITE');remaining=remaining[written:]
        os.fsync(fd)
    finally:os.close(fd)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)
def properties(reader,selection):
    fields=('ProtectSystem','ProtectHome','PrivateTmp','RuntimeDirectoryPreserve','ReadWritePaths','ReadOnlyPaths',
            'NeedDaemonReload','DropInPaths','ActiveState','SubState','Result','CapabilityBoundingSet',
            'AmbientCapabilities','NoNewPrivileges','PrivateNetwork','NetworkNamespacePath','RestrictAddressFamilies')
    reply=reader.command([selection['systemctl'],'show','--no-pager','--property='+','.join(fields),selection['guardUnit']],65536)
    require(reply.returncode==0,'GUARD_PROPERTIES_UNAVAILABLE')
    return dict(line.split('=',1)for line in reply.stdout.decode().splitlines()if'='in line)
def protected_siblings(reader,journal):
    require(journal.parent.is_absolute()and'..'not in journal.parts,'EXPLICIT_JOURNAL')
    result=[];entries=list(journal.parent.iterdir());require(len(entries)<=64,'BOUNDED_SIBLING_SET')
    for path in sorted(entries):
        require(re.fullmatch(r'/[A-Za-z0-9_./-]+',str(path)),'EXPLICIT_PROTECTED_PATH')
        info=path.lstat()
        require((stat.S_ISREG(info.st_mode)or stat.S_ISDIR(info.st_mode))and info.st_uid==info.st_gid==0
            and not info.st_mode&0o022 and(not stat.S_ISREG(info.st_mode)or info.st_nlink==1),'SIBLING_CUSTODY')
        if path!=journal:result.append(str(path))
    require(journal.exists()and result,'JOURNAL_AND_SEALED_SIBLINGS_REQUIRED')
    return result
def preflight(reader,selection,profile):
    require(profile['schema']=='ouf.boot-journal-recovery-selection.v1','SELECTION_SCHEMA')
    pointer=reader.parse(reader.read(profile['incidentPointer']))
    case=Path(pointer['contextPath']);require(str(case)==profile['stoppedContext'],'EXACT_STOPPED_CONTEXT')
    review=reader.parse(reader.sealed(case/'review.json',pointer['reviewSha256']))
    stopped=reader.parse(reader.read(case/'journal.json'))
    require(stopped['schema']=='ouf.semantic-boot-lock-recovery-journal.v1'and stopped['phase']=='DOCKER_START_INTENT'
        and stopped['runtimeAuthorityIssued']is False,'STOPPED_INTENT_CHANGED')
    require(review['bootBinding']==profile['expectedBootBinding']and review['artifactHashes']==profile['installedArtifacts'],
        'STOPPED_REVIEW_CHANGED')
    for path,digest in profile['installedArtifacts'].items():reader.sealed(path,digest)
    for path,digest in profile['originalUnitHashes'].items():reader.sealed(path,digest)
    actual=reader.collect(selection)
    require(actual.get('readComplete')and actual['loadedBinding']==review['bootBinding']and actual['knownBootSource']
        and actual['nativeOwnerReadConfiguration'].get('passed')and actual['nativeBootValidation'].get('passed')
        and actual['nftExecutableMatches']and actual['compilerMatchesProfile']and actual['restorerMatchesProfile']
        and all(actual['pairedConfigurationMatches'].values())
        and all(v.get('passed')and v['metadata']['matches']for v in actual['ownerSourceHashesMatch'].values()),'NATIVE_READBACK_DRIFT')
    require(actual['units'][selection['dockerUnit']]['ActiveState']=='inactive'
        and actual['units'][selection['guardUnit']]['ActiveState']=='failed'
        and actual['units'][selection['guardUnit']]['Result']=='exit-code'
        and actual.get('ownedTableFamilies')==[],'RECONCILE_OTHER_RUNTIME_STATE')
    bootprofile=reader.parse(reader.sealed(actual['loadedBinding']['profile'],actual['loadedBinding']['sha256']))
    owner=reader.parse(reader.sealed(bootprofile['coordinatedConfiguration'],bootprofile['coordinatedConfigurationHash']))
    boot=reader.parse(reader.sealed(bootprofile['bootConfiguration'],bootprofile['bootConfigurationHash']))
    journal=Path(owner['journalFile']);require(journal.parent==Path(actual['loadedBinding']['profile']).parent,'DEDICATED_COHORT_DIRECTORY')
    state=reader.parse(reader.read(journal));binding=owner['binding']
    require(set(state)=={'schema','state','leaseAuthorized','startAuthorized','leaseAddresses',*binding}
        and state['schema']=='ouf.semantic-lease-coordination.v1'and state['state']in ('QUIESCED','BLOCKED')
        and all(state[k]==v for k,v in binding.items())and state['startAuthorized']is False and state['leaseAuthorized']is False
        and state['leaseAddresses']==[[]for _ in owner['kernel']['providerFlows']],'NATIVE_JOURNAL_BINDING_UNPROVEN')
    oldboot=reader.parse(reader.read(boot['journalFile']))
    require(oldboot['schema']=='ouf.semantic-runtime-transition.v1'and oldboot['state']=='RUNTIME_EMPTY'
        and oldboot['transactionId']==boot['transactionId']and oldboot['configurationHash']==bootprofile['bootConfigurationHash']
        and oldboot['startAuthorized']is False,'BOOT_TRANSITION_UNPROVEN')
    lock=Path(review['lockFile']);info=lock.lstat();reader.read(lock)
    require(str(lock)==owner['commonLockFile']==boot['lockFile']and stat.S_IMODE(info.st_mode)==0o600,'COMMON_LOCK_CHANGED')
    require(not lock.is_relative_to(journal.parent),'SEPARATE_LOCK_AND_JOURNAL_DIRECTORIES_REQUIRED')
    props=properties(reader,selection)
    for name,expected in profile['expectedSandbox'].items():require(props.get(name)==expected,'SANDBOX_CHANGED')
    require(props.get('ReadOnlyPaths')==''and props.get('NeedDaemonReload')=='no'
        and str(journal.parent)not in props.get('ReadWritePaths','').split(),'DIFFERENT_SANDBOX_RECOVERY')
    siblings=protected_siblings(reader,journal)
    raw=('[Service]\nReadWritePaths='+str(journal.parent)+'\nReadOnlyPaths='+' '.join(siblings)+'\n').encode()
    target=Path(profile['managedDropin']);reader.read(target.parent/profile['existingGuardDropinName'])
    require(not os.path.lexists(target)and not os.path.lexists(case/profile['successorClaim']),'RECOVERY_SUCCESSOR_EXISTS_RECONCILE')
    return {'case':case,'review':review,'profile':profile,'selection':selection,'journal':journal,'siblings':siblings,
        'target':target,'raw':raw,'lock':lock,'lockIdentity':(info.st_dev,info.st_ino),'sandbox':props,'before':actual}
def apply(reader,value):
    case=value['case'];profile=value['profile'];selection=value['selection'];phase='SUCCESSOR_PREPARED';lockfd=None
    root=Path(tempfile.mkdtemp(prefix='journal-sandbox-',dir=case));root.chmod(0o700)
    review={'schema':'ouf.boot-journal-recovery-review.v1','previousContext':str(case),
        'previousPhase':'DOCKER_START_INTENT','managedDropin':str(value['target']),'dropinSha256':reader.sha(value['raw']),
        'journalDirectory':str(value['journal'].parent),'readOnlySiblings':value['siblings'],
        'nativeGuardUnchanged':True,'protectSystemStrictRetained':True,'existingServicesMayAutoResume':True,
        'runtimeAuthorityIssued':False,'maximumSeconds':300,'maximumStartAttempts':1}
    new(root/'review.json',encoded(review));new(case/profile['successorClaim'],encoded({'contextPath':str(root),'reviewSha256':reader.sha(encoded(review))}))
    def record(nextphase):
        nonlocal phase
        phase=nextphase;temp=root/(phase+'.json');new(temp,encoded({'schema':'ouf.boot-journal-recovery-journal.v1',
            'phase':phase,'previousContext':str(case),'automaticRetry':False,'runtimeAuthorityIssued':False}))
        os.replace(temp,root/'journal.json')
    def call(argv,timeout=20):
        result=reader.command(argv)if timeout==15 else None
        if result is None:
            import subprocess
            result=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,timeout=timeout,
                env={'PATH':'/usr/bin:/usr/sbin:/bin:/sbin','LC_ALL':'C'})
        require(result.returncode==0,'NATIVE_OPERATION_FAILED')
        require(len(result.stdout)<=1048576 and len(result.stderr)<=1048576,'OPERATION_OUTPUT_BOUND')
        return result.stdout
    try:
        record('RECONCILED_FAILED_START')
        lockfd=os.open(value['lock'],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);fcntl.flock(lockfd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        require(value['lockIdentity']==(os.fstat(lockfd).st_dev,os.fstat(lockfd).st_ino),'LOCK_INODE_CHANGED')
        require(protected_siblings(reader,value['journal'])==value['siblings'],'SEALED_SIBLING_SET_CHANGED')
        require(properties(reader,selection)==value['sandbox'],'MANAGER_GENERATION_CHANGED')
        record('SANDBOX_DROPIN_INTENT');new(value['target'],value['raw'],0o644)
        require(reader.read(value['target'])==value['raw'],'DROPIN_READBACK')
        record('UNIT_GRAPH_VERIFY');call([profile['systemdAnalyze'],'verify','--man=no',*profile['unitFilesToVerify']])
        record('MANAGER_RELOAD_INTENT');call([selection['systemctl'],'daemon-reload'])
        props=properties(reader,selection)
        for name in profile['expectedSandbox']:
            if name!='ReadWritePaths':require(props.get(name)==value['sandbox'][name],'PROTECTION_WEAKENED')
        require(set(props['ReadWritePaths'].split())==set(value['sandbox']['ReadWritePaths'].split())|{str(value['journal'].parent)}
            and set(props['ReadOnlyPaths'].split())==set(value['siblings'])
            and str(value['target'])in props['DropInPaths'].split()and props['NeedDaemonReload']=='no','LOADED_SANDBOX_UNPROVEN')
        fcntl.flock(lockfd,fcntl.LOCK_UN);os.close(lockfd);lockfd=None
        record('DOCKER_START_INTENT');call([selection['systemctl'],'start',selection['dockerUnit']],120)
        record('READBACK');after=reader.collect(selection)
        require(after.get('readComplete')and after['units'][selection['dockerUnit']]['ActiveState']=='active'
            and after['units'][selection['guardUnit']]['Result']=='success'and after['ownedTableFamilies']==['bridge','inet']
            and after['nativeOwnerReadConfiguration'].get('passed')and after['loadedBinding']==value['before']['loadedBinding'],
            'RECOVERY_READBACK_UNPROVEN')
        require(after['ownerJournal']['metadata'].get('leaseAuthorized')is False
            and after['ownerJournal']['metadata'].get('startAuthorized')is False,'UNEXPECTED_AUTHORITY')
        require(value['lockIdentity']==(value['lock'].stat().st_dev,value['lock'].stat().st_ino),'LOCK_REPLACED')
        for path,digest in {**profile['installedArtifacts'],**profile['originalUnitHashes']}.items():reader.sealed(path,digest)
        record('COMPLETE')
        return {'complete':True,'contextPath':str(root),'previousContext':str(case),'dockerActive':True,'nativeGuardPassed':True,
            'runtimeAuthorityIssued':False,'providerReconciliationRequired':True,'applicationReadinessProven':False,
            'existingServicesMayAutoResume':True,'completedTechnicalPhases':8,'functionalMilestonesProven':4}
    except Exception as error:
        import traceback
        result={'complete':False,'contextPath':str(root),'previousContext':str(case),'phase':phase,
            'errorClass':type(error).__name__,'exceptionMessagePrinted':False,'automaticRetry':False,'reconciliationRequired':True,
            'frames':[{'file':Path(f.filename).name,'function':f.name,'line':f.lineno}for f in traceback.extract_tb(error.__traceback__)[-4:]],
            'runtimeAuthorityIssued':False,'completedTechnicalPhases':8,'functionalMilestonesProven':4}
        # One passive readback in the same finite window, never a second start or mutation.
        try:result['failureReadback']=reader.collect(selection)
        except Exception as observed:result['failureReadbackErrorClass']=type(observed).__name__
        try:result['failureSandbox']=properties(reader,selection)
        except Exception as observed:result['failureSandboxErrorClass']=type(observed).__name__
        return result
    finally:
        if lockfd is not None:os.close(lockfd)
