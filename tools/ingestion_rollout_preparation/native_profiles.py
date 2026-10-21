"""Compile private native control profiles from one retained input capture.

No Engine request, service HTTP, SQL, credentials, authentication or runtime
effect. Files already audited are checked by retained metadata, not re-audited.
All endpoints are selected from process-owned listeners in their own namespace.
"""
import copy
import ipaddress
import os
from pathlib import Path,PurePosixPath
import re
import stat
import sys
import tempfile
import time
import iam_governance_intake as governance
from tools.ingestion_rollout_execution import contract as c,private_file,native_review
from tools.ingestion_rollout_preparation import native_inputs as inputs
from tools.governed_human_successor import inspection
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.chatbot_file_cohort.gateway import apisix_runtime_binding

PROFILE='ouf.ingestion-native-profile-preparation.v1'
CHECKPOINT={'phase':'NOT_STARTED','contextPath':None}

def listener_endpoint(metadata,selected_port=None):
    c.require(metadata.get('tcpProcessOwnershipProven')is True,'PROCESS_OWNED_ENDPOINT_EVIDENCE_REQUIRED')
    rows=metadata.get('tcpListeners');c.require(type(rows)is list and 1<=len(rows)<=512,'BOUNDED_OWNED_LISTENERS_REQUIRED')
    ports={v['port']for v in rows}
    if selected_port is None:
        c.require(len(ports)==1,'UNAMBIGUOUS_OWNED_SERVICE_PORT_REQUIRED');selected_port=next(iter(ports))
    c.require(type(selected_port)is int and 1<=selected_port<=65535 and selected_port in ports,'EXACT_RETAINED_LISTENER_PORT_REQUIRED')
    endpoints=set()
    for row in rows:
        if row['port']!=selected_port:continue
        family=row['family'];raw=bytes.fromhex(row['addressHex'])
        c.require((family==4 and len(raw)==4)or(family==6 and len(raw)==16),'EXACT_PROC_LISTENER_ADDRESS_REQUIRED')
        # The qualified target/Engine architecture is Linux amd64. Proc encodes
        # each IPv6 u32 in host byte order, not a single reversed128-bit word.
        c.require(sys.byteorder=='little','QUALIFIED_PROC_LITTLE_ENDIAN_PROFILE_REQUIRED')
        address=ipaddress.ip_address(raw[::-1]if family==4 else b''.join(raw[i:i+4][::-1]for i in range(0,16,4)))
        if address.is_loopback:endpoints.add((family,str(address)))
        elif address.is_unspecified:endpoints.add((family,'127.0.0.1'if family==4 else'::1'))
    c.require(endpoints,'OWNED_LISTENER_MUST_ADMIT_SAME_NAMESPACE_LOOPBACK')
    # Protocol loopback addresses are not Ente network defaults. Prefer an
    # actually observed loopback over a wildcard-derived address of that family.
    family,host=sorted(endpoints)[0]
    return {'host':host,'port':selected_port}

def metadata_seal(binding,allowed_ancestors,*,maximum=1048576):
    c.require(type(binding)is dict and set(binding)=={'path','sha256','metadata'},'EXACT_RETAINED_METADATA_BINDING_REQUIRED')
    selected=PurePosixPath(c.path(binding['path']));ancestors=[];fds=[]
    try:
        fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);fds.append(fd);current='/'
        for name in[*selected.parts[1:-1],None]:
            row=os.fstat(fd);mode=stat.S_IMODE(row.st_mode)
            c.require(stat.S_ISDIR(row.st_mode)and not row.st_mode&0o022 and
                ((row.st_uid==row.st_gid==0)or allowed_ancestors.get(current)==[row.st_uid,row.st_gid,mode]),
                'EXACT_RETAINED_INSTALLATION_ANCESTOR_CUSTODY_REQUIRED')
            ancestors.append({'path':current,'identity':[row.st_dev,row.st_ino,row.st_uid,row.st_gid,row.st_mode]})
            if name is None:break
            fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);fds.append(fd)
            current=current.rstrip('/')+'/'+name
        row=os.stat(selected.name,dir_fd=fd,follow_symlinks=False)
        c.require(private_file.metadata(row)==binding['metadata'],'RETAINED_SELECTED_FILE_METADATA_CHANGED')
        result={**copy.deepcopy(binding),'ancestors':ancestors};private_file.check_metadata(result,maximum=maximum)
        return result
    finally:
        for fd in reversed(fds):os.close(fd)

def projection_seal(selected,expected_hash,allowed_ancestors):
    # Hash is the already published projection7 receipt, not a new content read.
    c.path(selected);row=os.lstat(selected)
    c.require(stat.S_ISREG(row.st_mode)and row.st_uid==row.st_gid==0 and stat.S_IMODE(row.st_mode)==0o600,
        'EXACT_PRIVATE_ACTIVE_PROJECTION_METADATA_REQUIRED')
    return metadata_seal({'path':selected,'sha256':expected_hash,'metadata':private_file.metadata(row)},allowed_ancestors)

def exact_executable(binding):
    c.require(type(binding)is dict and set(binding)=={'path','sha256'}and governance.executable(binding['path'])==binding,
        'SAME_RETAINED_NATIVE_EXECUTABLE_REQUIRED')
    return copy.deepcopy(binding)

def process_root_program(root,selected):
    """Resolve bounded symlinks inside an already selected container root FD.

    Absolute symlink targets are relative to the container root, never the host.
    Return the selected invocation path, preserving BusyBox argv[0] semantics.
    """
    c.path(selected);pending=list(PurePosixPath(selected).parts[1:]);stack=[os.dup(root)];links=0
    try:
        while pending:
            part=pending.pop(0)
            if part in('','.'):continue
            if part=='..':
                if len(stack)>1:os.close(stack.pop())
                continue
            before=os.stat(part,dir_fd=stack[-1],follow_symlinks=False)
            if stat.S_ISLNK(before.st_mode):
                links+=1;c.require(links<=32,'BOUNDED_CONTAINER_PROGRAM_LINKS_REQUIRED')
                target=os.readlink(part,dir_fd=stack[-1]);c.require(0<len(target)<=4096,'BOUNDED_CONTAINER_PROGRAM_LINK_REQUIRED')
                if target.startswith('/'):
                    while len(stack)>1:os.close(stack.pop())
                pending=[*PurePosixPath(target).parts[1 if target.startswith('/')else 0:],*pending];continue
            c.require(before.st_uid==0 and not before.st_mode&0o022,'CUSTODIED_CONTAINER_PROGRAM_PATH_REQUIRED')
            flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK
            if pending:flags|=os.O_DIRECTORY
            fd=os.open(part,flags,dir_fd=stack[-1]);after=os.fstat(fd)
            c.require(private_file.metadata(before)==private_file.metadata(after),'CONTAINER_PROGRAM_CHANGED_DURING_SELECTION')
            if pending:stack.append(fd)
            else:
                try:c.require(stat.S_ISREG(after.st_mode)and after.st_mode&0o111,'EXECUTABLE_CONTAINER_PROGRAM_REQUIRED')
                finally:os.close(fd)
                return selected
        c.require(False,'EXACT_CONTAINER_PROGRAM_REQUIRED')
    finally:
        for fd in reversed(stack):os.close(fd)

def container_programs(actual):
    entries=actual['Config'].get('Env')or[];paths=[v.split('=',1)[1]for v in entries if v.startswith('PATH=')]
    c.require(len(paths)==1,'EXACT_RETAINED_CONTAINER_PATH_REQUIRED')
    directories=paths[0].split(':');c.require(1<=len(directories)<=32 and len(set(directories))==len(directories),
        'BOUNDED_DISTINCT_CONTAINER_SEARCH_PATH_REQUIRED')
    for directory in directories:c.path(directory)
    root=os.open('/proc/'+str(actual['State']['Pid'])+'/root',os.O_RDONLY|os.O_DIRECTORY)
    try:
        result={}
        for name in('env','timeout','psql'):
            for directory in directories:
                candidate=directory.rstrip('/')+'/'+name
                try:result[name]=process_root_program(root,candidate);break
                except FileNotFoundError:continue
            c.require(name in result,'RETAINED_IMAGE_REQUIRED_SQL_PROGRAM_NOT_FOUND')
        return result
    finally:os.close(root)

def postgres_socket(actual):
    pid=actual['State']['Pid'];base=Path('/proc')/str(pid);fds=list((base/'fd').iterdir())
    c.require(len(fds)<=512,'BOUNDED_POSTGRES_FDS_REQUIRED');inodes=set()
    for fd in fds:
        try:link=os.readlink(fd)
        except FileNotFoundError:continue
        match=re.fullmatch(r'socket:\[([0-9]{1,20})\]',link)
        if match:inodes.add(match[1])
    with(base/'net/unix').open('rb')as stream:raw=stream.read(262145)
    c.require(len(raw)<=262144,'BOUNDED_POSTGRES_UNIX_METADATA_REQUIRED')
    rows=raw.decode('ascii').splitlines();c.require(len(rows)<=1025,'BOUNDED_POSTGRES_UNIX_ROWS_REQUIRED');selected=set()
    for row in rows[1:]:
        fields=row.split();c.require(len(fields)>=7,'TYPED_POSTGRES_UNIX_METADATA_REQUIRED')
        if len(fields)!=8 or fields[6]not in inodes:continue
        match=re.fullmatch(r'(/[^\s]*)/\.s\.PGSQL\.([1-9][0-9]{0,4})',fields[7])
        if match:
            c.path(match[1]);port=int(match[2]);c.require(port<=65535,'VALID_POSTGRES_SOCKET_PORT_REQUIRED')
            selected.add((match[1],port))
    c.require(len(selected)==1,'ONE_PROCESS_OWNED_POSTGRES_UNIX_SOCKET_REQUIRED')
    directory,port=next(iter(selected));return {'directory':directory,'port':port}

def load_capture(case):
    preparation=case['nativeProfilePreparation'];c.require(preparation['schema']=='ouf.retained-native-profile-preparation-input.v1',
        'EXACT_NATIVE_PROFILE_PREPARATION_INPUT_REQUIRED')
    context=preparation['captureContext'];selected=inputs.load_inputs(case)
    checked=inputs.observe(context,case,preparation['captureSourceClosureHash'])
    c.require(checked['complete']is True and checked['engineGetsReserved']==12,'COMPLETED_RETAINED_CAPTURE_REQUIRED_NO_REPLAY')
    context=Path(context);snapshots={};seals=[]
    for name in sorted(selected['expected']):
        snapshot,seal=inspection.read_selected(str(context/(name+'.json')),maximum=2097152);seals.append(seal)
        c.require(snapshot['bindingProfile']==inputs.match(snapshot['container'],selected['expected'][name]),
            'CAPTURED_RUNTIME_BINDING_PROFILE_CHANGED')
        snapshots[name]=snapshot
    record,seal=inspection.read_selected(str(context/'inputs.json'),maximum=2097152);seals.append(seal)
    c.require(record['schema']=='ouf.ingestion-private-native-input-snapshot.v1'
        and record['sourceClosureHash']==preparation['captureSourceClosureHash']
        and record['packetBinding']==case['packetBinding']and record['ownerPlanBinding']==case['ownerPlanBinding']
        and record['ownerResultBinding']==case['ownerResultBinding']and record['databaseIdentity']==selected['databaseIdentity'],
        'SAME_RETAINED_CAPTURE_INPUT_MANIFEST_REQUIRED')
    for name,snapshot in snapshots.items():
        c.require(record['processMetadata'][name]==snapshot['processMetadata']and record['bindingProfiles'][name]==snapshot['bindingProfile'],
            'CAPTURED_PROCESS_METADATA_CHANGED')
        if name in preparation['observedNamespaces']:
            c.require(snapshot['processMetadata']['networkNamespace']==preparation['observedNamespaces'][name],
                'CAPTURED_NAMESPACE_MUST_MATCH_TARGET_RECEIPT')
    return selected,snapshots,seals

def compile_profiles(selected,snapshots,environment):
    packet=selected['packet'];plan=selected['ownerPlan'];completed=selected['ownerResult']
    before={n:copy.deepcopy(snapshots[n]['container'])for n in('ingestion','gateway')}
    unchanged={n:{'binding':copy.deepcopy(selected['expected'][n]),'bindingProfile':snapshots[n]['bindingProfile'],
        'restartCount':snapshots[n]['container']['RestartCount']}for n in('onboarding','mcp','udp')}
    owner={**copy.deepcopy(unchanged['onboarding'])};owner['runtimeBinding']=owner.pop('binding');owner['runtimeBindingProfile']=owner.pop('bindingProfile')
    owner.update(schema='ouf.ingestion-rollout-owner-local-namespace-http.v1',
        networkNamespace=copy.deepcopy(snapshots['onboarding']['processMetadata']['networkNamespace']),
        endpoint=environment['ownerEndpoint'],pythonExecutable=environment['pythonExecutable'],
        installationId=completed['active']['installationId'],expectedActive=copy.deepcopy(completed['active']),
        expectedPayload=copy.deepcopy(plan['bindingPlan']['candidatePayload']),projection=environment['projection'])
    db={'schema':'ouf.ingestion-rollout-native-database-read.v1','engineBinding':copy.deepcopy(plan['engine']),
        'postgresRuntimeBinding':copy.deepcopy(selected['expected']['postgres']),'runtimeBindingProfile':snapshots['postgres']['bindingProfile'],
        'postgresRestartCount':snapshots['postgres']['container']['RestartCount'],
        'identity':{k:v for k,v in selected['databaseIdentity'].items()if k!='schema'},
        **{k:copy.deepcopy(environment[k])for k in('dockerExecutable','dockerConfigDirectory','dockerConfigIdentity','containerPrograms','unixSocketDirectory')}}
    db['identity']['postgresPort']=environment['postgresPort']
    gateway=lambda config:{'schema':'ouf.ingestion-rollout-gateway-transport.v1','endpoint':copy.deepcopy(environment['gatewayEndpoint']),
        'pythonExecutable':copy.deepcopy(environment['pythonExecutable']),'config':config,'adminKey':environment['adminKey']}
    profiles={'schema':native_review.PROFILE,'engineBinding':copy.deepcopy(plan['engine']),
        'runtimeGuardProfile':{'schema':'ouf.ingestion-rollout-runtime-guard.v1','beforeContainers':before,'unchangedApplications':unchanged},
        'ownerControlProfile':owner,'databaseControlProfile':db,
        'imageImportProfile':{'schema':'ouf.ingestion-rollout-native-image-load.v1',
            **{k:copy.deepcopy(db[k])for k in('engineBinding','dockerExecutable','dockerConfigDirectory','dockerConfigIdentity')},'archive':environment['archive']},
        'retainedGatewayTransportProfile':gateway(environment['oldGatewayConfig']),
        'retainedGatewayNamespace':copy.deepcopy(snapshots['gateway']['processMetadata']['networkNamespace']),
        'gatewayTransportProfile':gateway(environment['stagedGatewayConfig']),
        'ingestionReadinessProfile':{'schema':'ouf.ingestion-rollout-ingestion-readiness-local-ns.v1',
            'endpoint':environment['ingestionEndpoint'],'pythonExecutable':environment['pythonExecutable']}}
    native_review.validate_profiles(profiles,packet);native_review.reconcile_owner(packet,profiles,plan,completed)
    return profiles

def check_process_namespaces(snapshots):
    for name,snapshot in snapshots.items():
        row=os.stat('/proc/'+str(snapshot['container']['State']['Pid'])+'/ns/net')
        c.require({'device':row.st_dev,'inode':row.st_ino}==snapshot['processMetadata']['networkNamespace'],'CAPTURED_PROCESS_NAMESPACE_CHANGED')

def prepare(case,source_hash):
    started=time.time();clock=time.monotonic();CHECKPOINT.update(phase='RETAINED_CAPTURE',contextPath=None)
    selected,snapshots,seals=load_capture(case);p=case['nativeProfilePreparation'];packet=selected['packet'];plan=selected['ownerPlan']
    logical=c.digest({'profile':PROFILE,'captureContext':p['captureContext'],'packetBinding':case['packetBinding']})
    parent=Path(selected['parent']);claim=parent/('ingestion-native-profiles-'+logical+'.claim.json')
    c.require(not os.path.lexists(claim),'NATIVE_PROFILE_PREPARATION_ALREADY_CLAIMED_RECONCILE_ONLY')
    with inputs.protected_directory(parent):context=Path(tempfile.mkdtemp(prefix='ingestion-native-profiles-',dir=parent));context.chmod(0o700)
    CHECKPOINT.update(phase='PRIVATE_PROFILE_CLAIM',contextPath=str(context))
    with inputs.protected_directory(parent)as fd:
        c.require(inputs.publish(fd,claim.name,c.encoded({'schema':PROFILE,'logicalRef':logical,'contextPath':str(context),
            'sourceClosureHash':source_hash,'captureContext':p['captureContext'],'runtimeAuthorityIssued':False,'automaticReplayAllowed':False})),
            'NATIVE_PROFILE_PREPARATION_ALREADY_CLAIMED_RECONCILE_ONLY')
    journal=Journal(context);journal.initialize({'schema':PROFILE,'logicalRef':logical,'sourceClosureHash':source_hash,
        'phase':'METADATA_AND_EXECUTABLES','complete':False,'runtimeAuthorityIssued':False,'budgetReset':False})
    CHECKPOINT['phase']='METADATA_AND_EXECUTABLES';transport=plan['gateway']['transport']
    c.require(apisix_runtime_binding(snapshots['gateway']['container'],transport.get('runtimeBindingProfile'))==transport['runtimeBinding']
        and transport['networkNamespace']==snapshots['gateway']['processMetadata']['networkNamespace']
        and transport['configBinding']==packet['gatewayConfigBefore'],'SAME_RETAINED_GATEWAY_TRANSPORT_REQUIRED')
    allowed=p['allowedAncestorOwners'];environment={
        'pythonExecutable':exact_executable(transport['pythonExecutable']),
        'dockerExecutable':exact_executable(selected['original']['authorization']['plan']['selection']['docker']),
        'ownerEndpoint':listener_endpoint(snapshots['onboarding']['processMetadata']),
        'ingestionEndpoint':listener_endpoint(snapshots['ingestion']['processMetadata']),
        'gatewayEndpoint':listener_endpoint(snapshots['gateway']['processMetadata'],transport['port']),
        'oldGatewayConfig':metadata_seal(packet['gatewayConfigBefore'],allowed),
        'stagedGatewayConfig':metadata_seal(packet['retainedGatewayConfig'],allowed),
        'adminKey':None if transport['adminKeyBinding']is None else metadata_seal(transport['adminKeyBinding'],allowed),
        'archive':metadata_seal(packet['candidate']['nativeArchiveBinding'],{},maximum=2147483648)}
    c.require(selected['ownerResult']['projectionBinding']['sha256']==p['publishedProjection']['sha256'],
        'SAME_COMPLETED_OWNER_EXPORTED_AND_PUBLISHED_PROJECTION_REQUIRED')
    environment['projection']=projection_seal(p['publishedProjection']['path'],p['publishedProjection']['sha256'],allowed)
    CHECKPOINT['phase']='PROCESS_METADATA_ONLY'
    check_process_namespaces(snapshots)
    environment['containerPrograms']=container_programs(snapshots['postgres']['container'])
    unix=postgres_socket(snapshots['postgres']['container']);environment.update(unixSocketDirectory=unix['directory'],postgresPort=unix['port'])
    config=context/'empty-docker-config';config.mkdir(mode=0o700);row=config.lstat()
    environment.update(dockerConfigDirectory=str(config),dockerConfigIdentity=[row.st_dev,row.st_ino,row.st_uid,row.st_gid,row.st_mode])
    CHECKPOINT['phase']='COMPILE_QUALIFIED_NATIVE_PROFILES';profiles=compile_profiles(selected,snapshots,environment)
    check_process_namespaces(snapshots)
    for seal in seals:private_file.check_metadata(seal,maximum=2097152)
    journal.create(context/'profiles.json',c.encoded(profiles));journal.sync()
    row=journal.read();journal.compare_and_save(row,{**row,'phase':'COMPLETE','complete':True})
    CHECKPOINT['phase']='COMPLETE'
    return {'status':'PRIVATE_NATIVE_PROFILES_COMPILED_NO_AUTHORITY','complete':True,'contextPath':str(context),
        'retainedCaptureContext':p['captureContext'],'startedAtUnix':started,'finishedAtUnix':time.time(),'elapsedSeconds':time.monotonic()-clock,
        'privateNativeControlProfilesCompiled':True,'nativeClientProfilePublished':False,'runtimeAuthorityIssued':False,
        'databaseAdmissionProven':False,'serviceReachabilityProven':False,'engineRequests':0,'databaseCalls':0,'gatewayRequests':0,
        'ownerRequests':0,'oauthRequests':0,'bearerFilesOpened':0,'humanCredentialJournalsRead':0,'dedicatedCredentialFilesRead':0,
        'containerLifecycleOperations':0,'newLoginPerformed':False,'windowExtended':False,'budgetReset':False,'automaticReplayAllowed':False,
        'completedCaptureReplayed':False,'completedDbPreflightReplayed':False,'completedOwnerActionReplayed':False,
        'completedPublicationReplayed':False,'completedArchiveAuditReplayed':False,'completedGatewayConfigStagingReplayed':False,
        'selectedEndpoints':{n:environment[n+'Endpoint']for n in('owner','ingestion','gateway')},
        'credentialValuesPrinted':False,'credentialHashesPrinted':False,'completedTechnicalPhases':8,'functionalMilestonesProven':4,'notReleaseAcceptance':True}

def execute(mode,control,case,confirmed_read,source_closure_hash):
    c.require((mode=='prepare'and control is None)or(mode=='inspect'and type(control)is str),
        'ONE_EXPLICIT_PRIVATE_PROFILE_MODE_REQUIRED')
    if mode=='prepare':result=prepare(case,source_closure_hash)
    else:
        selected,snapshots,seals=load_capture(case);target=Path(c.path(control))
        c.require(target.parent==Path(selected['parent'])and re.fullmatch('ingestion-native-profiles-[A-Za-z0-9_-]{8,64}',target.name),
            'EXACT_NATIVE_PROFILE_CONTEXT_REQUIRED')
        row=Journal(target).read();logical=c.digest({'profile':PROFILE,
            'captureContext':case['nativeProfilePreparation']['captureContext'],'packetBinding':case['packetBinding']})
        claim,_=inspection.read_selected(str(target.parent/('ingestion-native-profiles-'+logical+'.claim.json')))
        c.require(row.get('schema')==PROFILE and row.get('logicalRef')==logical
            and row.get('sourceClosureHash')==source_closure_hash and row.get('budgetReset')is False
            and claim.get('contextPath')==control and claim.get('logicalRef')==logical
            and claim.get('sourceClosureHash')==source_closure_hash,'EXACT_NATIVE_PROFILE_CLAIM_AND_SOURCE_REQUIRED')
        result={'status':'RETAINED_NATIVE_PROFILE_PREPARATION_METADATA_ONLY','complete':row['complete'],
            'phase':row['phase'],'contextPath':control,'readOnly':True,'engineRequests':0,'oauthRequests':0,
            'automaticReplayAllowed':False,'budgetReset':False,'runtimeAuthorityIssued':False}
    return {'schema':'ouf.ingestion-native-profile-preparation-result.v1',**result}
