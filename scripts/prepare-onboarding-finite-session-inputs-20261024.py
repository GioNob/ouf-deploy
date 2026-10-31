#!/usr/bin/env python3
"""Fresh bounded metadata inputs for an Onboarding migration/deployment review.

No SQL, credentials, application HTTP, Docker writes or previous executor entry.
The completed Ingestion DB profile is retained as evidence, never rebound to
Onboarding. Candidate source provenance is the exact verified CI manifest.
"""
import contextlib
import copy
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import sys
import tarfile
import types

PACKAGE='/etc/ouf/deploy-snapshots/onboarding-finite-session-ee8b7756f72f82a6'
SCOPE='input-preparation-v1'
CONTEXT='/etc/ouf/deploy-snapshots/ingestion-readiness-stage8-execution-e1c13776c158064f9e1012a4993a409b459ae0711a77486dc59f7dd7a722ce92'
OPERATION='6c7d73cbc2d9c613d5fe0b4fafe5ac20853478a883bf15371dadbb3f201afbc5'
REGISTRY_PREP='/etc/ouf/deploy-snapshots/semantic-registry-postboot-inputs-a29d05c2b1d11fbd8d2bad38a17a23416230c693879ad3c835bd40b76533ca68'
REGISTRY_PREP_HASH='9298a73a41fe51f4035745fc9bcb822f6956bb9752df26a54f715d35bbeb17a9'
GET_ROOT='/etc/ouf/deploy-snapshots/semantic-registry-operational-7cb59501000058b5dc5030adf8624c5b38567de0c8bfeb21dd49435644ea3da2/network-projection-repair-v1/post-network-original-get-v1'
REPAIR='/etc/ouf/deploy-snapshots/semantic-network-repair-dbd7bccc32904974/repair.py'
REPAIR_HASH='dbd7bccc32904974e0b9e85491c9dc3a5100c9c51d550e0951e773523fcbd808'
MANIFEST_HASH='879b3f05c43483f8a2dfeeb5d84c0453d7dbd39ec075e0c0f9ef0a043d65394a'
ARCHIVE_HASH='ee8b7756f72f82a6b699bafa43cd9cbc4714a828c620df1146668f5bce8583a9'
ARCHIVE_BYTES=210844914
SOURCE_COMMIT='431c601de9b7faa9769b0a210300cd466bf82cfc'
TESTED_COMMIT='2959efa53f44d0eec353753a4c8bcc5e11f1a89b'
IMAGE_ID='sha256:6692cd902bf554791a99daff30ca92175f61467d97546cc507220f22b9c7f52b'
MAXIMUM_ENGINE_GETS=14
PROGRESS={'engineGetAttempts':0,'privateMetadataReads':0,'privateMetadataBytes':0}


class Stop(RuntimeError):pass


def require(ok,code):
    if not ok:raise Stop(code)


def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(v):return hashlib.sha256(v).hexdigest()
def digest(v):return sha(encoded(v))
def identity(s):return (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)


def unique(pairs):
    result={}
    for k,v in pairs:
        require(k not in result,'DUPLICATE_METADATA_KEY');result[k]=v
    return result


def decode(raw):
    return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in()).throw(Stop('NONFINITE_METADATA')))


@contextlib.contextmanager
def opened(path,maximum,private=True):
    path=Path(path);require(path.is_absolute() and '..'not in path.parts and len(path.parts)<48,'EXACT_CUSTODIED_PATH_REQUIRED')
    fds=[];pins=[]
    frame=lambda s:(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode)
    try:
        fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);fds.append(fd)
        for part in path.parts[1:-1]:
            s=os.fstat(fd);require(s.st_uid==0 and not s.st_mode&0o022,'ROOT_METADATA_ANCESTRY_REQUIRED')
            parent=fd;fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);fds.append(fd)
            pins.append((parent,part,fd,frame(os.fstat(fd))))
        s=os.fstat(fd);require(s.st_uid==0 and not s.st_mode&0o022,'ROOT_METADATA_ANCESTRY_REQUIRED')
        leaf=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd);fds.append(leaf);before=os.fstat(leaf)
        require(stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0 and before.st_nlink==1
                and 0<before.st_size<=maximum and not before.st_mode&0o022,'PROTECTED_BOUNDED_FILE_REQUIRED')
        if private:require(stat.S_IMODE(before.st_mode)in(0o400,0o600),'PRIVATE_METADATA_MODE_REQUIRED')
        yield leaf,before
        require(identity(before)==identity(os.fstat(leaf))==identity(os.stat(path.name,dir_fd=fd,follow_symlinks=False)),
                'METADATA_FILE_CHANGED_DURING_READ')
        for parent,name,child,pin in pins:
            require(pin==frame(os.fstat(child))==frame(os.stat(name,dir_fd=parent,follow_symlinks=False)),
                    'METADATA_ANCESTRY_CHANGED_DURING_READ')
    finally:
        for fd in reversed(fds):os.close(fd)


def raw(path,maximum,expected=None,private=True):
    with opened(path,maximum,private)as(fd,s):
        with os.fdopen(os.dup(fd),'rb')as source:value=source.read(maximum+1)
        require(len(value)==s.st_size and (expected is None or sha(value)==expected),'EXACT_METADATA_BYTES_REQUIRED')
        return value


def new_file(root,name,value):
    require(re.fullmatch('[A-Za-z0-9_.-]{1,120}',name)is not None,'CLOSED_EVIDENCE_NAME_REQUIRED')
    value=value if type(value)is bytes else encoded(value)
    require(len(value)<=16777216,'BOUNDED_PRIVATE_EVIDENCE_REQUIRED')
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        s=os.fstat(fd);require(s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700,'EXCLUSIVE_PRIVATE_SCOPE_REQUIRED')
        out=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400,dir_fd=fd)
        try:
            with os.fdopen(os.dup(out),'wb')as stream:stream.write(value);stream.flush();os.fsync(stream.fileno())
        finally:os.close(out)
        os.fsync(fd)
    finally:os.close(fd)


class Facts:
    def __init__(self):self.files={}
    def json(self,path,expected=None):
        require(PROGRESS['privateMetadataReads']<48,'METADATA_READ_COUNT_BOUND')
        data=raw(path,16777216,expected)
        PROGRESS['privateMetadataReads']+=1;PROGRESS['privateMetadataBytes']+=len(data)
        require(PROGRESS['privateMetadataBytes']<=67108864,'METADATA_BYTE_BOUND')
        value=decode(data);require(type(value)is dict,'METADATA_OBJECT_REQUIRED')
        key=str(path);pin={'path':key,'sha256':sha(data)}
        require(key not in self.files or self.files[key]==pin,'RETAINED_METADATA_DRIFT')
        self.files[key]=pin;return value
    def recheck(self):
        for path,pin in self.files.items():raw(path,16777216,pin['sha256'])


def candidate(facts):
    m=facts.json(Path(PACKAGE)/'manifest.json',MANIFEST_HASH)
    require(m['schema']=='ouf.onboarding-tested-image.v1' and m['repository']=='GioNob/ouf-source-onboarding'
        and m['reviewedSourceCommit']==SOURCE_COMMIT and m['testedCommit']==TESTED_COMMIT
        and m['imageId']==IMAGE_ID and m['archiveName']=='image.tar.gz'
        and m['archiveSha256']==ARCHIVE_HASH and m['archiveBytes']==ARCHIVE_BYTES
        and m['qualifiedInCiOnly']is True and m['targetApplyAuthorized']is False
        and m['humanBudgetGranted']is False and m['releaseAcceptance']is False,'EXACT_STAGED_CI_MANIFEST_REQUIRED')
    path=Path(PACKAGE)/'image.tar.gz';config=None
    with opened(path,ARCHIVE_BYTES)as(fd,s):
        require(s.st_size==ARCHIVE_BYTES,'EXACT_STAGED_ARCHIVE_SIZE_REQUIRED')
        h=hashlib.sha256()
        with os.fdopen(os.dup(fd),'rb')as stream:
            for block in iter(lambda:stream.read(1048576),b''):h.update(block)
        require(h.hexdigest()==ARCHIVE_HASH,'EXACT_STAGED_ARCHIVE_HASH_REQUIRED')
        os.lseek(fd,0,os.SEEK_SET)
        with os.fdopen(os.dup(fd),'rb')as stream,tarfile.open(fileobj=stream,mode='r|gz')as archive:
            for entry in archive:
                if entry.name in(IMAGE_ID[7:]+'.json','blobs/sha256/'+IMAGE_ID[7:]):
                    require(entry.isfile() and 0<entry.size<=1048576,'BOUNDED_IMAGE_CONFIGURATION_REQUIRED')
                    body=archive.extractfile(entry).read(1048577)
                    require(sha(body)==IMAGE_ID[7:],'EXACT_IMAGE_CONFIGURATION_HASH_REQUIRED')
                    config=decode(body);break
        binding={'path':str(path),'sha256':ARCHIVE_HASH,'metadata':list(identity(s))}
    require(type(config)is dict and config['os']=='linux' and config['architecture']=='amd64'
            and config['config']['User']=='10003:10003' and config['rootfs']['type']=='layers'
            and type(config['rootfs']['diff_ids'])is list and config['rootfs']['diff_ids']
            and all(re.fullmatch('sha256:[a-f0-9]{64}',v)for v in config['rootfs']['diff_ids']),
            'QUALIFIED_LINUX_IMAGE_CONFIGURATION_REQUIRED')
    return {'manifest':m,'archiveBinding':binding,'imageConfiguration':config,
            'sourceProvenance':'VERIFIED_CI_ARTIFACT_MANIFEST_NOT_BASE_IMAGE_LABELS',
            'applicationRevisionLabelPresent':'org.opencontainers.image.revision'in(config['config'].get('Labels')or{})}


class Engine:
    def __init__(self,binding,ids,root):
        require(type(ids)is set and len(ids)==7 and all(re.fullmatch('[a-f0-9]{64}',v)for v in ids),
                'SEVEN_EXACT_RETAINED_CONTAINERS_REQUIRED')
        self.binding,self.ids,self.root,self.calls=binding,ids,root,0
    def check(self):
        b=self.binding;p=Path(b['socketPath'])
        require(p.is_absolute() and str(p.resolve())==str(p),'EXACT_ENGINE_SOCKET_PATH_REQUIRED')
        s=p.lstat();require(stat.S_ISSOCK(s.st_mode) and s.st_uid==0
            and stat.S_IMODE(s.st_mode)in(0o600,0o660)
            and [s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)]==b['socketBinding'],
            'RETAINED_ENGINE_SOCKET_CHANGED')
    def get(self,cid):
        require(cid in self.ids and self.calls<MAXIMUM_ENGINE_GETS,'FOURTEEN_EXACT_ENGINE_GETS_ONLY')
        self.check();self.calls+=1;PROGRESS['engineGetAttempts']=self.calls
        new_file(self.root,'engine-attempt-%02d.json'%self.calls,{'containerId':cid,'method':'GET','attempt':self.calls,'attemptNotCompletion':True})
        selected=self.binding['socketPath']
        class Local(http.client.HTTPConnection):
            def connect(connection):
                connection.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
                connection.sock.settimeout(4);connection.sock.connect(selected)
        connection=Local('custodied-engine',timeout=4)
        try:
            connection.request('GET','/v1.44/containers/'+cid+'/json',headers={'Connection':'close'})
            response=connection.getresponse();body=response.read(1048577);self.check()
            require(response.status==200 and 0<len(body)<=1048576,'BOUNDED_EXACT_ENGINE_RESPONSE_REQUIRED')
            value=decode(body);require(type(value)is dict and value.get('Id')==cid,'ENGINE_SELECTED_ID_SUBSTITUTED')
            name='engine-response-%02d.json'%self.calls;new_file(self.root,name,body)
            return value,{'path':str(self.root/name),'sha256':sha(body)}
        finally:connection.close()


def process(actual):
    state=actual['State'];pid=state['Pid']
    require(state['Running']is True and not any(state.get(k)for k in('Paused','Restarting','Dead','OOMKilled'))
            and not state.get('Error') and type(pid)is int and pid>1,'CURRENT_RUNNING_PROCESS_REQUIRED')
    body=Path('/proc/'+str(pid)+'/stat').read_bytes();require(len(body)<=16384 and b') 'in body,'BOUNDED_PROCESS_STAT_REQUIRED')
    ticks=int(body.rsplit(b') ',1)[1].split()[19]);ns={}
    for name in('net','mnt'):
        s=Path('/proc/'+str(pid)+'/ns/'+name).stat();ns[name]={'device':s.st_dev,'inode':s.st_ino}
    return {'pid':pid,'startTicks':ticks,'namespaces':ns}


def lifecycle_declaration(actual):
    labels=actual['Config'].get('Labels')or{}
    if any(k.startswith('io.kubernetes.')for k in labels):return 'KUBERNETES_LABELS_ONLY'
    if 'com.docker.compose.project'in labels:return 'COMPOSE_LABELS_ONLY'
    return 'NO_RECOGNIZED_MANAGER_LABEL'


def prepare(r):
    from tools.ingestion_readiness_patch_execution import runtime_bindings,runtime_guard,replacement
    require(not os.path.lexists(Path(PACKAGE)/SCOPE),'INPUT_SCOPE_ALREADY_CLAIMED_NO_REPLAY')
    package_stat=Path(PACKAGE).lstat()
    require(stat.S_ISDIR(package_stat.st_mode) and package_stat.st_uid==package_stat.st_gid==0
            and stat.S_IMODE(package_stat.st_mode)==0o700,'PROTECTED_STAGED_PACKAGE_REQUIRED')
    facts=Facts();image=candidate(facts)
    review=facts.json(Path(CONTEXT)/'review.json');journal=facts.json(Path(CONTEXT)/'recovery.json')
    native=review['executionReview'];stages=native['stages'];effects=journal['effects']
    require(native['logicalOperationRef']==OPERATION and len(stages)==len(effects)==journal['nextStage']==12
            and all(e['state']=='APPLIED' and e['stage']==s['name'] and e['intentHash']==s['intentHash']for e,s in zip(effects,stages)),
            'EXACT_COMPLETED_TWELVE_STAGE_PATCH_REQUIRED')
    packet=facts.json(native['packetBinding']['path'])
    require(digest(packet)==native['packetBinding']['sha256'],'RETAINED_PACKET_BINDING_REQUIRED')
    indices={s['name']:i for i,s in enumerate(stages)}
    require(effects[indices['ingestion.RESTORE_RESTART']]['state']=='APPLIED','RETAINED_RESTART_RESTORATION_REQUIRED')
    started=effects[indices['ingestion.START_REPLACEMENT']]['nativeResource']
    created=effects[indices['ingestion.CREATE_REPLACEMENT']]['nativeResource']['containerId']
    require(started['containerId']==created,'DURABLE_INGESTION_REPLACEMENT_PROCESS_REQUIRED')
    unchanged=native['runtimeGuardProfile']['unchangedApplications']
    require(set(unchanged)=={'gateway','onboarding','mcp','udp'},'EXACT_RETAINED_UNCHANGED_COHORT_REQUIRED')
    db=native['databaseControlProfile'];require(db['engineBinding']==native['engineBinding'],'SAME_RETAINED_DATABASE_ENGINE_REQUIRED')
    prepared=facts.json(Path(REGISTRY_PREP)/'prepared.json',REGISTRY_PREP_HASH)
    registry_journal=facts.json(Path(prepared['nativeContext']['executionRoot'])/'recovery.json')
    require(registry_journal['nextStage']==11 and len(registry_journal['effects'])==12
        and all(e['state']=='APPLIED'for e in registry_journal['effects'][:11])
        and registry_journal['effects'][11]['state']=='CLAIMED'
        and prepared['nativeContext']['engineBinding']==native['engineBinding'],'RETAINED_REGISTRY_PREFIX_AND_ENGINE_REQUIRED')
    prior_get=facts.json(Path(GET_ROOT)/'acceptance-result.json')
    require(prior_get['status']=='POST_NETWORK_ORIGINAL_CALLER_GET_OBSERVED' and prior_get['complete']is True
            and prior_get['originalRequestResource200Proven']is True and prior_get['allConfiguredReferencesProven']is True,
            'COMPLETED_ORIGINAL_REQUEST200_PROOF_REQUIRED')
    registry_id=prepared['nativeContext']['plan']['stages'][0]['intent']['registryId']
    pins={name:value['binding']['containerId']for name,value in unchanged.items()}
    pins.update(ingestion=created,postgres=db['postgresRuntimeBinding']['containerId'],registry=registry_id)
    require(len(set(pins.values()))==7,'DISTINCT_SEVEN_COHORT_IDENTITIES_REQUIRED')
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    require(boot==registry_journal['bootId'],'SAME_RETAINED_HOST_BOOT_REQUIRED')
    root=r.exclusive_root(PACKAGE,SCOPE)
    new_file(root,'claim.json',{'schema':'ouf.onboarding-finite-input-claim.v1','manifestHash':MANIFEST_HASH,
        'archiveHash':ARCHIVE_HASH,'maximumEngineGets':14,'maximumSeconds':90,'databaseSessions':0,
        'serviceCredentialReadsAllowed':False,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False})
    engine=Engine(native['engineBinding'],set(pins.values()),root)
    observations={};initial={};processes={};bindings={}
    def validate(name,actual):
        if name in unchanged:runtime_guard.unchanged(actual,unchanged[name])
        elif name=='postgres':
            require(runtime_bindings.observed(actual,db['runtimeBindingProfile'])==db['postgresRuntimeBinding']
                and actual['RestartCount']==db['postgresRestartCount'],'RETAINED_POSTGRES_GENERATION_CHANGED')
        elif name=='ingestion':
            replacement.validate(packet['frames']['ingestion'],actual,packet['candidate']['imageConfig'],
                packet['expectedRuntimeBindings']['ingestion']['containerId'],created_id=created,
                process=started,restart_restored=True)
        else:
            g=registry_journal['newGeneration'];p=process(actual)
            require(actual['Image']==prepared['registryInputs']['creationRequest']['Image']
                and actual['State']['Pid']==g['pid'] and p['startTicks']==g['startTicks']
                and p['namespaces']['net']=={'device':g['namespaceDevice'],'inode':g['namespaceInode']},
                'RETAINED_REGISTRY_GENERATION_CHANGED')
        return process(actual)
    for name,cid in pins.items():
        actual,observation=engine.get(cid);p=validate(name,actual)
        if name=='onboarding':require(p['namespaces']['net']==native['ownerControlProfile']['networkNamespace'],
                                     'RETAINED_ONBOARDING_NAMESPACE_CHANGED')
        initial[name]=actual;observations[name]=observation;processes[name]=p
        bindings[name]=runtime_bindings.observed(actual,runtime_bindings.NATIVE)
    for name,cid in pins.items():
        actual,_=engine.get(cid);p=validate(name,actual)
        require(runtime_bindings.observed(actual,runtime_bindings.NATIVE)==bindings[name]
            and p==processes[name] and actual['RestartCount']==initial[name]['RestartCount'],
            'CURRENT_COHORT_CHANGED_DURING_PREPARATION')
    facts.recheck()
    with opened(Path(PACKAGE)/'image.tar.gz',ARCHIVE_BYTES)as(_,archive_stat):
        require(list(identity(archive_stat))==image['archiveBinding']['metadata'],'STAGED_ARCHIVE_CHANGED_DURING_CAPTURE')
    require(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==boot,'HOST_BOOT_CHANGED_DURING_CAPTURE')
    bundle={'schema':'ouf.onboarding-finite-session-private-inputs.v1','kind':'INPUTS_NOT_EXECUTABLE_AUTHORITY',
        'candidate':image,'retainedFacts':list(facts.files.values()),'completedPatchOperation':OPERATION,
        'completedPatchContext':CONTEXT,'bootId':boot,'engineBinding':native['engineBinding'],
        'runtimeObservations':observations,'currentBindings':bindings,'currentProcessIdentities':processes,
        'restartCounts':{k:v['RestartCount']for k,v in initial.items()},
        'onboardingLifecycleDeclaration':lifecycle_declaration(initial['onboarding']),
        'lifecycleOwnershipNotProvenByLabels':True,'retainedOwnerControlProfile':native['ownerControlProfile'],
        'legacyIngestionDatabaseControlProfile':db,'legacyDatabaseProfileMustNotBeReboundToOnboarding':True,
        'onboardingConfigurationInPrivateObservation':observations['onboarding'],
        'databaseReadPerformed':False,'databaseAdmissionProven':False,'onboardingDatabaseProfileReviewed':False,
        'currentApplicationReadinessProven':False,'retainedOriginalResource200Verified':True,
        'targetApplyAuthorized':False,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,
        'budgetReset':False,'sourceActivationAllowed':False,'humanBudgetGranted':False,'releaseAcceptance':False}
    new_file(root,'inputs.json',bundle)
    result={'schema':'ouf.onboarding-finite-session-input-result.v1','status':'CURRENT_ONBOARDING_COHORT_INPUTS_CAPTURED',
        'complete':True,'privateInputsPath':str(root/'inputs.json'),'privateInputsHash':digest(bundle),
        'engineGetAttempts':engine.calls,'maximumEngineGets':14,'currentCohortStable':True,
        'stagedArchiveAndImageConfigVerified':True,'candidateSourceBoundByVerifiedCiManifest':True,
        'candidateApplicationRevisionLabelPresent':image['applicationRevisionLabelPresent'],
        'onboardingLifecycleDeclaration':bundle['onboardingLifecycleDeclaration'],'lifecycleOwnershipProven':False,
        'serviceCredentialFilesOpened':0,'bearerFilesOpened':0,'privateSigningKeysRead':0,
        'engineConfigurationRetainedPrivately':True,'environmentValuesPrinted':False,
        'sqlSessions':0,'databaseAdmissionProven':False,'onboardingDatabaseProfileReviewed':False,
        'imageImports':0,'containerWrites':0,'databaseMigrations':0,'sourceActivations':0,'humanBudgetsGranted':0,
        'retainedContextWrites':0,'runtimeEffectsDispatched':0,'privateEvidenceWrites':True,'readOnlyRuntime':True,
        'addressesPrinted':False,'credentialValuesPrinted':False,'targetApplyAuthorized':False,
        'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}
    new_file(root,'complete.json',result);return result


def initialize():
    require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site
            and sys.dont_write_bytecode and len(sys.argv)==1,'ONE_ISOLATED_ROOT_PREPARATION_REQUIRED')
    source=raw(REPAIR,131072,REPAIR_HASH)
    r=types.ModuleType('ouf_verified_retained_repair_dependencies');exec(compile(source,REPAIR,'exec'),r.__dict__)
    old=r.json_at(r.REVIEW,r.REVIEW_HASH);r.rebind_python(old);r.load_legacy()
    from tools.semantic_registry_recovery_execution.postboot_authority import authority_metadata
    from tools.semantic_policy_token_owner.iam_owner_action import stdlib_binding
    binding=old['proposal']['inputsBinding'];retained=r.json_at(binding['path'],binding['sha256'])
    public=retained['review']['authorityInputs'];authority_metadata(public)
    require(digest(stdlib_binding())==public['stdlibHash'],'RETAINED_INTERPRETER_STDLIB_CUSTODY_REQUIRED')
    raw(str(Path(__file__).resolve()),131072)
    return r


def main():
    try:
        def expired(*_):raise Stop('PREPARATION_DEADLINE_EXCEEDED')
        signal.signal(signal.SIGALRM,expired);signal.alarm(90)
        result=prepare(initialize())
    except Exception as error:
        code=str(error)if type(error)is Stop and re.fullmatch('[A-Z0-9_]{1,120}',str(error))else'ONBOARDING_INPUT_PREPARATION_UNPROVEN'
        result={'schema':'ouf.onboarding-finite-session-input-result.v1','status':'STOP_RECONCILE','complete':False,
            'reasonCode':code,'attemptsNotCompletion':dict(PROGRESS),'runtimeEffectsDispatched':0,
            'privatePreparationMayBePartial':True,'sqlSessions':0,'databaseMigrations':0,'sourceActivations':0,
            'humanBudgetsGranted':0,'targetApplyAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}
    finally:signal.alarm(0)
    print(encoded(result).decode(),flush=True)
    return 0 if result.get('complete')is True else 2


if __name__=='__main__':raise SystemExit(main())
