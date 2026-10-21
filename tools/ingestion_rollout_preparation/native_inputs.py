"""One bounded private capture of native runtime inputs, before HUMAN login.

Only exact retained JSON files, twelve Engine container GET reservations and
bounded process/namespace metadata. No SQL, HTTP application/admin request,
secret-file content, login, key generation, lifecycle or runtime authority.
Snapshots contain private container configuration and must never be printed.
"""
import hashlib
import os
from pathlib import Path
import re
import stat
import tempfile
import time
from tools.ingestion_rollout_execution import contract as c,private_file,runtime_bindings as rb
from tools.governed_human_successor import inspection
from tools.semantic_lease_recovery.recovery_journal import Journal
from contextlib import contextmanager
from engine_creation import Engine

APP_NAMES={'ingestion','gateway','onboarding','udp','mcp'}
CHECKPOINT={'phase':'NOT_STARTED','contextPath':None}
PROFILE='ouf.ingestion-native-input-capture.v1'

@contextmanager
def protected_directory(selected):
    selected=Path(c.path(str(selected)));fds=[]
    try:
        fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);fds.append(fd)
        for part in selected.parts[1:]:
            row=os.fstat(fd)
            c.require(stat.S_ISDIR(row.st_mode)and row.st_uid==row.st_gid==0 and not row.st_mode&0o022,
                'ROOT_CUSTODIED_CAPTURE_PARENT_REQUIRED')
            fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);fds.append(fd)
        row=os.fstat(fd)
        c.require(stat.S_ISDIR(row.st_mode)and row.st_uid==row.st_gid==0 and not row.st_mode&0o022,
            'ROOT_CUSTODIED_CAPTURE_PARENT_REQUIRED')
        yield fd
        c.require((row.st_dev,row.st_ino)==(selected.lstat().st_dev,selected.lstat().st_ino),
            'CAPTURE_PARENT_IDENTITY_CHANGED')
    finally:
        for fd in reversed(fds):os.close(fd)

def publish(directory,name,raw):
    try:fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
    except FileExistsError:return False
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(os.dup(fd),'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
        os.fsync(directory)
    finally:os.close(fd)
    return True

def document(binding,*,maximum=1048576,raw_hash=False):
    c.require(type(binding)is dict and set(binding)=={'path','sha256'}and c.hashed(binding['sha256']),
        'EXACT_CAPTURE_DOCUMENT_SELECTION_REQUIRED')
    value,seal=inspection.read_selected(binding['path'],maximum=maximum)
    c.require((seal['sha256']if raw_hash else c.digest(value))==binding['sha256'],
        'RETAINED_CAPTURE_DOCUMENT_HASH_CHANGED')
    return value,seal

def load_inputs(case):
    CHECKPOINT.update(phase='RETAINED_CAPTURE_INPUTS',contextPath=None)
    c.require(case.get('schema')=='ouf.ingestion-rollout-retained-case.v1'
        and case.get('purpose')=='EXACT_RETAINED_INSTALLATION_CASE_NOT_PORTABLE_DEFAULT'
        and case.get('runtimeAuthorityIssued')is False and case.get('budgetReset')is False,
        'EXACT_RETAINED_CAPTURE_CASE_REQUIRED')
    values={};seals=[]
    for key in('packetBinding','verifiedInputsBinding','ownerPlanBinding','ownerResultBinding'):
        values[key],seal=document(case[key]);seals.append(seal)
    packet,inputs,plan,result=(values[k]for k in('packetBinding','verifiedInputsBinding','ownerPlanBinding','ownerResultBinding'))
    c.require(packet.get('schema')=='ouf.ingestion-rollout-private-packet.v3'
        and packet.get('kind')=='PRIVATE_TEMPLATES_NOT_EXECUTABLE_AUTHORITY'
        and packet.get('verifiedInputsHash')==c.digest(inputs)
        and packet.get('ownerPlanSha256')==c.digest(plan)
        and result.get('complete')is True and result.get('planHash')==c.digest(plan)
        and all(packet.get(k)is False for k in('runtimeAuthorityIssued','targetApplyAuthorized',
            'automaticReplayAllowed','budgetReset','newLoginAllowed')),
        'SAME_UNAUTHORIZED_PACKET_AND_COMPLETED_OWNER_HISTORY_REQUIRED')
    parent=Path(c.path(plan['authorityDirectory']))
    c.require(parent==Path(case['ownerPlanBinding']['path']).parent,'EXACT_OWNER_CAPSULE_DIRECTORY_REQUIRED')
    capsule,seal=inspection.read_selected(str(parent/'case.json'));seals.append(seal)
    original,seal=document(capsule['originalBinding'],maximum=8388608,raw_hash=True);seals.append(seal)
    c.require(original.get('schema')=='ouf.chatbot-file-cohort-prepared-inputs.v1'
        and original.get('engine')==plan.get('engine')
        and c.digest(original['authorization']['plan']['selection'])==plan['humanBinding']['selectionHash'],
        'FULL_ORIGINAL_CAPTURE_SELECTION_AND_ENGINE_REQUIRED')
    database=original['databasePlan']
    c.require(database.get('schema')=='ouf.chatbot-cohort-database-plan.v1'
        and type(database.get('modules'))is list,'RETAINED_POSTBOOT_DATABASE_SELECTION_REQUIRED')
    rows={v['module']:v for v in database['modules']}
    c.require(len(rows)==len(database['modules'])==4 and set(rows)=={'onboarding','udp','ingestion','mcp'},
        'EXACT_FOUR_RETAINED_DATABASE_MODULES_REQUIRED')
    selected=rows['ingestion']
    c.require(selected.get('schema')=='ouf_ingestion'and type(selected.get('databaseOid'))is int
        and selected['databaseOid']>0 and all(type(selected.get(k))is str
        and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,62}',selected[k])for k in('database','user')),
        'EXACT_RETAINED_INGESTION_DATABASE_IDENTITY_REQUIRED')
    applications=plan['currentApplications']
    c.require(type(applications)is dict and set(applications)==APP_NAMES
        and all(applications[n]==packet['expectedRuntimeBindings'][n]for n in('ingestion','gateway')),
        'EXACT_FIVE_RETAINED_CAPTURE_APPLICATIONS_REQUIRED')
    expected={**applications,'postgres':database['postgresRuntimeBinding']}
    ids=[v['containerId']for v in expected.values()]
    c.require(len(set(ids))==6 and all(c.hashed(v)for v in ids),'EXACT_SIX_CAPTURE_CONTAINER_IDS_REQUIRED')
    for seal in seals:private_file.check_metadata(seal,maximum=8388608 if seal['path']==capsule['originalBinding']['path']else 1048576)
    return {'packet':packet,'inputs':inputs,'ownerPlan':plan,'ownerResult':result,
        'original':original,'databaseIdentity':{k:selected[k]for k in('database','user','databaseOid','schema')},
        'expected':expected,'seals':seals,'parent':str(parent.parent)}

def match(actual,expected):
    c.require(type(actual)is dict and actual.get('Id')==expected['containerId'],
        'EXACT_RETAINED_CAPTURE_CONTAINER_REQUIRED')
    selected=[p for p in(rb.SORTED,rb.NATIVE)if rb.observed(actual,p)==expected]
    c.require(selected and actual['State']['Running']is True and actual['State']['Paused']is False
        and actual['State']['Restarting']is False and type(actual.get('RestartCount'))is int
        and actual['RestartCount']>=0,'RETAINED_CAPTURE_RUNTIME_GENERATION_DRIFT')
    return selected[0]

def process_metadata(pid):
    c.require(type(pid)is int and pid>0,'EXACT_CAPTURE_PROCESS_REQUIRED')
    selected=Path('/proc')/str(pid)/'ns/net';before=os.stat(selected)
    c.require(stat.S_ISREG(before.st_mode),'NETWORK_NAMESPACE_DESCRIPTOR_REQUIRED')
    value={'networkNamespace':{'device':before.st_dev,'inode':before.st_ino},
        'tcpListeners':[],'tcpProcessOwnershipProven':False}
    # Only listening sockets owned by this exact process; no namespace-wide
    # inference from unrelated DNS/helper listeners. Unsupported visibility is
    # reported as an input gap, never guessed into a runtime endpoint.
    try:
        fds=Path('/proc')/str(pid)/'fd';names=list(fds.iterdir())
        c.require(len(names)<=512,'BOUNDED_CAPTURE_PROCESS_FDS_REQUIRED')
        sockets=set()
        for item in names:
            try:link=os.readlink(item)
            except FileNotFoundError:continue
            found=re.fullmatch(r'socket:\[([0-9]{1,20})\]',link)
            if found:sockets.add(found[1])
        listeners=[]
        for name in('tcp','tcp6'):
            with(Path('/proc')/str(pid)/'net'/name).open('rb')as stream:raw=stream.read(262145)
            c.require(len(raw)<=262144,'BOUNDED_CAPTURE_TCP_METADATA_REQUIRED')
            rows=raw.decode('ascii').splitlines();c.require(len(rows)<=513,'BOUNDED_CAPTURE_TCP_ROWS_REQUIRED')
            for row in rows[1:]:
                fields=row.split()
                c.require(len(fields)>=10,'TYPED_CAPTURE_TCP_METADATA_REQUIRED')
                if fields[3]!='0A'or fields[9]not in sockets:continue
                address,port=fields[1].split(':')
                c.require(re.fullmatch('[0-9A-Fa-f]{8}'if name=='tcp'else'[0-9A-Fa-f]{32}',address)
                    and re.fullmatch('[0-9A-Fa-f]{4}',port),'EXACT_CAPTURE_TCP_ADDRESS_METADATA_REQUIRED')
                listeners.append({'family':4 if name=='tcp'else 6,'addressHex':address.upper(),'port':int(port,16)})
        value.update(tcpListeners=sorted(listeners,key=lambda v:(v['family'],v['port'],v['addressHex'])),tcpProcessOwnershipProven=True)
    except (OSError,UnicodeError):pass
    after=os.stat(selected)
    c.require((before.st_dev,before.st_ino)==(after.st_dev,after.st_ino),'CAPTURE_PROCESS_NAMESPACE_CHANGED')
    return value

def store(context,name,value):
    c.require(name in {'inputs.json','selection.json',*[n+'.json'for n in APP_NAMES|{'postgres'}]},
        'EXACT_PRIVATE_CAPTURE_MEMBER_REQUIRED')
    journal=Journal(context);journal.create(Path(context)/name,c.encoded(value));journal.sync()

class ReadOnlyEngine:
    def __init__(self,binding,journal,ids):
        c.require(type(binding)is dict and set(binding)=={'socketPath','socketBinding'},'EXACT_CAPTURE_ENGINE_BINDING_REQUIRED')
        self.engine=Engine(binding['socketPath'],tuple(binding['socketBinding']));self.journal=journal;self.ids=set(ids)
    def get(self,cid):
        c.require(cid in self.ids and c.hashed(cid),'CAPTURE_ENGINE_CLOSED_ID_REQUIRED')
        row=self.journal.read();c.require(row['engineGetsReserved']<row['maximumEngineGets']==12,
            'CAPTURE_ENGINE_BUDGET_EXHAUSTED_NO_RESET')
        self.journal.compare_and_save(row,{**row,'engineGetsReserved':row['engineGetsReserved']+1})
        status,value=self.engine.request('GET','/v1.44/containers/'+cid+'/json')
        c.require(status==200 and type(value)is dict and value.get('Id')==cid,'EXACT_CAPTURE_ENGINE_RESPONSE_REQUIRED')
        return value

def capture(case,source_closure_hash):
    started=time.time();monotonic=time.monotonic()
    selected=load_inputs(case);packet=selected['packet'];expected=selected['expected']
    logical=c.digest({'profile':PROFILE,'packetHash':c.digest(packet),
        'containerIds':{n:v['containerId']for n,v in expected.items()}})
    parent=Path(selected['parent']);claim=parent/('ingestion-native-inputs-'+logical+'.claim.json')
    c.require(not os.path.lexists(claim),'NATIVE_INPUT_CAPTURE_ALREADY_CLAIMED_RECONCILE_ONLY')
    with protected_directory(parent):
        context=Path(tempfile.mkdtemp(prefix='ingestion-native-inputs-',dir=parent));context.chmod(0o700)
    CHECKPOINT.update(phase='RESERVE_PRIVATE_INPUT_CAPTURE',contextPath=str(context))
    with protected_directory(parent)as directory:
        c.require(publish(directory,claim.name,c.encoded({'schema':PROFILE,'contextPath':str(context),
            'logicalRef':logical,'sourceClosureHash':source_closure_hash,
            'maximumEngineGets':12,'automaticReplayAllowed':False,'budgetReset':False,
            'runtimeAuthorityIssued':False})),'NATIVE_INPUT_CAPTURE_ALREADY_CLAIMED_RECONCILE_ONLY')
    journal=Journal(context);journal.initialize({'schema':PROFILE,'logicalRef':logical,
        'sourceClosureHash':source_closure_hash,'phase':'BEFORE_READS','engineGetsReserved':0,
        'maximumEngineGets':12,'complete':False,'budgetReset':False,'runtimeAuthorityIssued':False})
    store(context,'selection.json',{'packetBinding':case['packetBinding'],'ownerPlanBinding':case['ownerPlanBinding'],
        'expected':expected,'databaseIdentity':selected['databaseIdentity'],'logicalRef':logical})
    engine=ReadOnlyEngine(selected['ownerPlan']['engine'],journal,[v['containerId']for v in expected.values()])
    observations={};metadata={};profiles={}
    for name in sorted(expected):
        CHECKPOINT['phase']='CAPTURE_'+name.upper()
        row=journal.read();journal.compare_and_save(row,{**row,'phase':CHECKPOINT['phase']})
        actual=engine.get(expected[name]['containerId']);profiles[name]=match(actual,expected[name])
        metadata[name]=process_metadata(actual['State']['Pid']);observations[name]=actual
        store(context,name+'.json',{'container':actual,'processMetadata':metadata[name],'bindingProfile':profiles[name]})
    for name in sorted(expected):
        CHECKPOINT['phase']='RECHECK_'+name.upper()
        row=journal.read();journal.compare_and_save(row,{**row,'phase':CHECKPOINT['phase']})
        actual=engine.get(expected[name]['containerId']);match(actual,expected[name])
        c.require(actual['RestartCount']==observations[name]['RestartCount'], 'CAPTURE_RUNTIME_RESTART_CHANGED')
        ns=process_metadata(actual['State']['Pid'])['networkNamespace']
        c.require(ns==metadata[name]['networkNamespace'],'CAPTURE_NETWORK_NAMESPACE_DRIFT')
    for seal in selected['seals']:private_file.check_metadata(seal,maximum=8388608)
    finished=time.time();elapsed=time.monotonic()-monotonic
    store(context,'inputs.json',{'startedAtUnix':started,'finishedAtUnix':finished,'elapsedSeconds':elapsed,'schema':'ouf.ingestion-private-native-input-snapshot.v1',
        'sourceClosureHash':source_closure_hash,'packetBinding':case['packetBinding'],
        'ownerPlanBinding':case['ownerPlanBinding'],'ownerResultBinding':case['ownerResultBinding'],
        'containerSnapshots':{n:n+'.json'for n in expected},'bindingProfiles':profiles,
        'processMetadata':metadata,'databaseIdentity':selected['databaseIdentity'],
        'runtimeAuthorityIssued':False,'nativeProfilesCompiled':False,'databaseAdmissionProven':False})
    row=journal.read();journal.compare_and_save(row,{**row,'phase':'COMPLETE','complete':True})
    CHECKPOINT['phase']='COMPLETE'
    return {'status':'PRIVATE_NATIVE_INPUTS_CAPTURED_NO_AUTHORITY','complete':True,'contextPath':str(context),
        'startedAtUnix':started,'finishedAtUnix':finished,'elapsedSeconds':elapsed,'targetServicesReadOnly':True,
        'applicationCount':5,'postgresSelectedSeparately':True,'engineGetsReserved':journal.read()['engineGetsReserved'],
        'maximumEngineGets':12,'runtimeBindingsStableThroughoutRead':True,
        'observedTcpListeners':{n:metadata[n]for n in('onboarding','ingestion','gateway')},
        'nativeProfilesCompiled':False,'databaseAdmissionProven':False,'humanCredentialJournalsRead':0,
        'bearerFilesOpened':0,'dedicatedCredentialFilesRead':0,'oauthRequests':0,'databaseCalls':0,
        'gatewayRequests':0,'ownerRequests':0,'containerLifecycleOperations':0,
        'privatePreparationWrites':True,'oldDocumentsModified':False,'newLoginPerformed':False,
        'windowExtended':False,'budgetReset':False,'automaticReplayAllowed':False,'runtimeAuthorityIssued':False,
        'credentialValuesPrinted':False,'credentialHashesPrinted':False,'completedTechnicalPhases':8,
        'functionalMilestonesProven':4,'notReleaseAcceptance':True}

def observe(context,case,source_closure_hash):
    selected=load_inputs(case);target=Path(c.path(context));c.require(target.parent==Path(selected['parent'])
        and re.fullmatch('ingestion-native-inputs-[A-Za-z0-9_-]{8,64}',target.name),
        'EXACT_RETAINED_NATIVE_INPUT_CONTEXT_REQUIRED')
    row=Journal(target).read()
    logical=c.digest({'profile':PROFILE,'packetHash':c.digest(selected['packet']),
        'containerIds':{n:v['containerId']for n,v in selected['expected'].items()}})
    claim,_=inspection.read_selected(str(target.parent/('ingestion-native-inputs-'+logical+'.claim.json')))
    c.require(claim.get('contextPath')==str(target)and claim.get('logicalRef')==logical
        and claim.get('sourceClosureHash')==source_closure_hash and row.get('logicalRef')==logical,
        'EXACT_CONSUMED_CAPTURE_CLAIM_REQUIRED')
    c.require(row.get('schema')==PROFILE and row.get('sourceClosureHash')==source_closure_hash
        and row.get('budgetReset')is False and type(row.get('engineGetsReserved'))is int
        and 0<=row['engineGetsReserved']<=row.get('maximumEngineGets')==12,'RETAINED_CAPTURE_BUDGET_REQUIRED')
    return {'status':'RETAINED_CAPTURE_METADATA_ONLY','contextPath':context,'complete':row['complete'],
        'phase':row['phase'],'engineGetsReserved':row['engineGetsReserved'],'engineGetsThisInvocation':0,
        'automaticReplayAllowed':False,'budgetReset':False,'runtimeAuthorityIssued':False,'readOnly':True}

def execute(mode,control,case,confirmed_read,source_closure_hash):
    c.require(mode in('capture','inspect'),'ONE_EXPLICIT_NATIVE_INPUT_MODE_REQUIRED')
    c.require((mode=='capture'and control is None)or(mode=='inspect'and type(control)is str),
        'EXACT_CAPTURE_MODE_CONTEXT_REQUIRED')
    c.require(c.hashed(source_closure_hash),'EXACT_CAPTURE_SOURCE_HASH_REQUIRED')
    result=capture(case,source_closure_hash)if mode=='capture'else observe(control,case,source_closure_hash)
    return {'schema':'ouf.ingestion-native-input-capture-result.v1',**result}
