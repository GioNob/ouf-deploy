#!/usr/bin/env python3
"""Read retained stop metadata only; never execute capsule or enter application."""
import ast
import base64, gzip, io, fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

CAPSULE = '/etc/ouf/deploy-snapshots/semantic-checkpoint-review-launch.cgFB2WhS/capsule.py'
CAPSULE_HASH = 'f7d5c566dc3bab63873970ed781682d65f18f10aa69b01b74c037c9e1780cb57'
CLOSURE_HASH = 'e78fca8785b3424271e9edbb1900a78944f68d2bd512417f093360b772195200'
DECLARATION_HASH = 'dd316d42ee61038c17342a14ad12c424bd0c407347c5f3d881c5fb40ad4c5cdc'
PREPARATION_ROOT = '/etc/ouf/deploy-snapshots/semantic-registry-postboot-inputs-a29d05c2b1d11fbd8d2bad38a17a23416230c693879ad3c835bd40b76533ca68'
PREPARATION_HASH = '9298a73a41fe51f4035745fc9bcb822f6956bb9752df26a54f715d35bbeb17a9'
REVIEW_HASH = 'fff2e8499488147c3ca602f352e3ecf3dbd21d606809d123a3060c3c4f7fb800'
AUTHORITY_HASH = '8ef16658d484ca613957460a8e0d5684c003cb0b09da43919ecf8f4277f6a76d'
PARENT = '/etc/ouf/deploy-snapshots'


def require(ok, reason):
    if not ok: raise ValueError(reason)


def encoded(v): return json.dumps(v, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
def digest(v): return hashlib.sha256(encoded(v)).hexdigest()
def identity(v): return (v.st_dev, v.st_ino, v.st_uid, v.st_gid, v.st_mode, v.st_nlink, v.st_size, v.st_mtime_ns, v.st_ctime_ns)


class Reader:
    def __init__(self): self.reads = 0; self.bytes = 0; self.until = time.monotonic() + 30

    def raw(self, path, maximum, sha=None, private=True):
        require(time.monotonic() < self.until and self.reads < 48, 'BOUNDED_METADATA_READ_REQUIRED')
        # Traverse protected ancestry through held descriptors, refusing links.
        path = Path(path)
        require(path.is_absolute() and '..' not in path.parts, 'EXACT_METADATA_PATH_REQUIRED')
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in path.parts[1:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                info = os.fstat(child)
                require(not info.st_mode & 0o022 and (info.st_uid == 0 or not private), 'PROTECTED_METADATA_ANCESTRY_REQUIRED')
                os.close(fd); fd = child
            leaf = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            try:
                before = os.fstat(leaf)
                require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and not before.st_mode & 0o022
                    and (before.st_uid == 0 or not private) and 0 < before.st_size <= maximum,
                    'BOUNDED_PROTECTED_METADATA_REQUIRED')
                chunks = []; count = 0
                while count <= before.st_size:
                    block = os.read(leaf, min(65536, before.st_size + 1 - count))
                    if not block: break
                    chunks.append(block); count += len(block)
                raw = b''.join(chunks)
                require(len(raw) == before.st_size and identity(before) == identity(os.fstat(leaf))
                    == identity(os.stat(path.name, dir_fd=fd, follow_symlinks=False)), 'METADATA_CHANGED')
            finally: os.close(leaf)
        finally: os.close(fd)
        self.reads += 1; self.bytes += len(raw)
        require(self.bytes <= 33554432 and (sha is None or hashlib.sha256(raw).hexdigest() == sha), 'METADATA_HASH_OR_BYTE_BOUND')
        return raw

    def json(self, path, sha=None, maximum=8388608):
        raw = self.raw(path, maximum, sha); value = json.loads(raw)
        require(type(value) is dict and encoded(value) == raw, 'CANONICAL_METADATA_REQUIRED')
        return value


FIELDS=('device','inode','uid','gid','mode','links','size','mtimeNs','ctimeNs')
SCHEMA='ouf.semantic-registry-running-policy-repair-inputs-result.v1'

def inside(value):
    require(type(value)is str and value.startswith(PARENT+'/') and '..' not in Path(value).parts
            and str(Path(value))==value,'EXACT_PRIVATE_METADATA_PATH_REQUIRED')
    return Path(value)

def binding_metadata(binding):
    """O_PATH only: no source file data, executable entry or network access."""
    require(type(binding)is dict and set(binding)=={'path','sha256','metadata','ancestors'},'EXACT_FILE_BINDING_REQUIRED')
    path=Path(binding['path']);require(path.is_absolute() and '..' not in path.parts,'ABSOLUTE_BOUND_SOURCE_REQUIRED')
    require(type(binding['metadata'])is list and len(binding['metadata'])==9
            and all(type(v)is int and v>=0 for v in binding['metadata']),'EXACT_BOUND_METADATA_REQUIRED')
    expected=['/']+['/'+'/'.join(path.parts[1:i]) for i in range(2,len(path.parts))]
    require(type(binding['ancestors'])is list and [a['path']for a in binding['ancestors']]==expected,
            'COMPLETE_BOUND_ANCESTRY_REQUIRED')
    fds=[];held=[]
    ident=lambda s:[s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode]
    try:
        fd=os.open('/',os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW);fds.append(fd)
        if ident(os.fstat(fd))!=binding['ancestors'][0]['identity']:return {'status':'ANCESTRY_CHANGED'}
        for a in binding['ancestors'][1:]:
            parent=fd;name=Path(a['path']).name
            fd=os.open(name,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);fds.append(fd)
            if ident(os.fstat(fd))!=a['identity']:return {'status':'ANCESTRY_CHANGED'}
            held.append((parent,name,fd,a['identity']))
        leaf=os.open(path.name,os.O_PATH|os.O_NOFOLLOW,dir_fd=fd);fds.append(leaf)
        current=list(identity(os.fstat(leaf)))
        if current!=list(identity(os.stat(path.name,dir_fd=fd,follow_symlinks=False))):return {'status':'CHANGED_DURING_METADATA_OBSERVATION'}
        for parent,name,child,wanted in held:
            if ident(os.fstat(child))!=wanted or ident(os.stat(name,dir_fd=parent,follow_symlinks=False))!=wanted:return {'status':'ANCESTRY_CHANGED'}
        changed=[name for name,a,b in zip(FIELDS,binding['metadata'],current)if a!=b]
        return {'status':'METADATA_CHANGED'if changed else'METADATA_MATCHES','changedFields':changed}
    except FileNotFoundError:return {'status':'MISSING_AT_OBSERVATION'}
    except (PermissionError,NotADirectoryError,OSError):return {'status':'METADATA_UNAVAILABLE'}
    finally:
        for fd in reversed(fds):os.close(fd)

def candidates(prepared):
    rows={};nodes=0
    explicit=prepared['nativeContext']['originalRequest']
    special={digest(explicit['tokenSource']):'ORIGINAL_CALLER_TOKEN_SOURCE'}
    if explicit['ca']is not None:special[digest(explicit['ca'])]='ORIGINAL_CALLER_TLS_CA'
    def walk(v,depth=0):
        nonlocal nodes
        nodes+=1;require(nodes<=100000 and depth<=48,'BOUNDED_REVIEW_SHAPE_REQUIRED')
        if type(v)is dict:
            if set(v)=={'path','sha256','metadata','ancestors'}:
                h=digest(v);rows[h]=v;require(len(rows)<=256,'BOUNDED_FILE_METADATA_INVENTORY_REQUIRED');return
            for x in v.values():walk(x,depth+1)
        elif type(v)is list:
            for x in v:walk(x,depth+1)
    for key in ('nativeContext','ownerContext','authorityInputs'):walk(prepared[key])
    return [(special.get(h,'OTHER_REVIEW_BOUND_FILE'),v)for h,v in sorted(rows.items())]

def inspect(reader):
    raw=reader.raw(CAPSULE,1048576,CAPSULE_HASH)
    selected=[n.value for n in ast.parse(raw).body if isinstance(n,ast.Assign)and len(n.targets)==1
              and isinstance(n.targets[0],ast.Name)and n.targets[0].id=='DELIVERY']
    require(len(selected)==1,'EXACT_CAPSULE_DECLARATION_REQUIRED');declaration=ast.literal_eval(selected[0])
    require(digest(declaration)==DECLARATION_HASH and digest(declaration['nativeDeclaration'])==CLOSURE_HASH,
            'EXACT_REVIEWED_SOURCE_CLOSURE_REQUIRED')
    root=inside(PREPARATION_ROOT)
    prepared=reader.json(str(root/'prepared.json'),PREPARATION_HASH,maximum=16777216)
    review=reader.json(str(root/'review.json'),REVIEW_HASH)
    require(prepared['nativeContext']==review['currentContext']and prepared['ownerContext']==review['ownerContext']
            and prepared['sourceClosure']==review['sourceClosure']==declaration['nativeDeclaration'],
            'EXACT_COMPLETED_REVIEW_REQUIRED')
    receipt=reader.json(str(root/'authority/receipt.json'),maximum=131072)
    require(receipt['authorityHash']==AUTHORITY_HASH and receipt['reviewHash']==REVIEW_HASH,
            'EXACT_SUCCESSOR_AUTHORITY_RECEIPT_REQUIRED')
    context=prepared['nativeContext'];execution=inside(context['executionRoot'])
    journal=reader.json(str(execution/'recovery.json'),maximum=2097152)
    require(journal['authorityHash']==AUTHORITY_HASH and journal['logicalOperationRef']==context['plan']['logicalOperationRef']
            and journal['nextStage']==11 and len(journal['effects'])in(11,12), 'EXACT_CHECKPOINT_ELEVEN_STOP_REQUIRED')
    reads=reader.json(str(execution/'native-reads.json'),maximum=8192)
    require(reads['authorityHash']==AUTHORITY_HASH and reads['scopeHash']==digest(review['scopes']['semanticRegistryRecoveryReads']),
            'EXACT_SUCCESSOR_READ_ACCOUNTING_REQUIRED')
    counts=reads['counts'];limits=review['scopes']['semanticRegistryRecoveryReads']['maximumRequests']
    require(set(counts)==set(limits)and all(type(v)is int and 0<=v<=limits[k]for k,v in counts.items()),'BOUNDED_NATIVE_READ_COUNTS_REQUIRED')
    scope=review['scopes']['semanticRegistryPostbootOwner'];ownerroot=inside(scope['journalPath'])
    owner=reader.json(str(ownerroot/'recovery.json'),maximum=65536)
    require(owner['contextRef']==scope['contextRef']and owner['generationRef']==scope['generationRef']
            and owner['controlledPredecessorGrantAttempts']==320 and type(owner['attempts'])is int and 0<=owner['attempts']<=1
            and owner['controlledCumulativeGrantAttempts']==320+owner['attempts'],'EXACT_SUCCESSOR_OWNER_ACCOUNTING_REQUIRED')
    bindings=candidates(prepared)
    first=[binding_metadata(b)for _,b in bindings]
    second=[binding_metadata(b)for _,b in bindings]
    require(time.monotonic()<reader.until,'BOUNDED_METADATA_TIME_REQUIRED')
    stable=all(a==b for a,b in zip(first,second))
    observations=[{'ordinal':i,'role':role,**a,'sameClassificationOnSecondPass':a==b}
                  for i,((role,_),a,b)in enumerate(zip(bindings,first,second))]
    require(reader.json(str(execution/'recovery.json'),maximum=2097152)==journal
            and reader.json(str(execution/'native-reads.json'),maximum=8192)==reads
            and reader.json(str(ownerroot/'recovery.json'),maximum=65536)==owner,'RETAINED_JOURNALS_CHANGED_DURING_OBSERVATION')
    states=[e.get('state')for e in journal['effects']]
    require(all(type(s)is str and s in('PENDING','CLAIMED','APPLIED','UNKNOWN','FAILED')for s in states),'CLOSED_EFFECT_STATES_REQUIRED')
    return {'schema':SCHEMA,'status':'CHECKPOINT_ELEVEN_FILE_METADATA_OBSERVED','complete':True,
        'checkpoint':11,'effectStates':states,'nativeReadCounts':counts,
        'originalSemanticGetSucceeded':journal.get('originalSemanticGetSucceeded')is True,
        'retainedServiceGrantAttempts':owner['attempts'],'retainedControlledGrantAttempts':owner['controlledCumulativeGrantAttempts'],
        'ownerState':owner['state']if owner['state']in('NEW','ACTIVE','BLOCKED','CANCELLED','PAUSED_EXHAUSTED','RECONCILE_REQUIRED','PUBLISHING')else'OTHER',
        'boundFileCount':len(bindings),'metadataClassificationsStable':stable,'fileMetadataObservations':observations,
        'matchingMetadataDoesNotProveMatchingContents':True,'metadataChangeDoesNotIdentifyWriter':True,
        'credentialContentReads':0,'sourceFileContentReads':0,'metadataOnlySourcePasses':2,
        'metadataReads':reader.reads,'metadataBytesRead':reader.bytes,'currentContainerStateObserved':False,
        'addressesPrinted':False,'filePathsPrinted':False,'capsuleExecuted':False,'applicationEntryInvoked':False,
        'engineGets':0,'adminGets':0,'databaseCalls':0,'oauthRequests':0,'httpRequests':0,
        'runtimeEffectsDispatched':0,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False,
        'readOnly':True,'serviceReadinessEstablished':False,'rootCauseEstablished':False,'releaseAcceptance':False}

def sealed_native_modules(raw):
    values={n.targets[0].id:ast.literal_eval(n.value)for n in ast.parse(raw).body
        if isinstance(n,ast.Assign)and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)}
    manifest=values['DELIVERY']['nativeDeclaration']
    with gzip.GzipFile(fileobj=io.BytesIO(base64.b64decode(values['PACKED'],validate=True)))as stream:
        raw=stream.read(16777217)
    require(0<len(raw)<=16777216,'BOUNDED_SEALED_PAYLOAD_REQUIRED')
    payload=json.loads(raw);loader=payload['loader'].encode();sources={k:v.encode()for k,v in payload['sources'].items()}
    require(len(sources)==142 and set(sources)==set(manifest['sourceHashes'])
            and hashlib.sha256(loader).hexdigest()==manifest['loaderHash']
            and all(hashlib.sha256(v).hexdigest()==manifest['sourceHashes'][k]for k,v in sources.items()),
            'EXACT_REVIEWED_SOURCE_MODULES_REQUIRED')
    namespace={};exec(compile(loader,'<verified-readonly-native-loader>','exec'),namespace)
    _,observed=namespace['load_entry'](manifest['sourceCommit'],sources,loader,digest(manifest),manifest['sourcePins'])
    require(observed==manifest,'EXACT_NATIVE_PRELOAD_MANIFEST_REQUIRED')
    return (sys.modules['engine_creation'].Engine,
            sys.modules['tools.ingestion_readiness_patch_execution.runtime_guard'],
            sys.modules['tools.semantic_registry_recovery_execution.caller_configuration'],
            sys.modules['tools.semantic_live_route_diagnostic.reader'])

class DiagnosticEngine:
    def __init__(self,engine,ids):
        require(len(ids)==2 and all(type(v)is str and re.fullmatch('[0-9a-f]{64}',v)for v in ids),
                'TWO_EXACT_REVIEWED_CONTAINER_IDENTITIES_REQUIRED')
        self.engine,self.ids,self.attempts=engine,set(ids),0
        self.observed={}
    def get(self,cid):
        require(cid in self.ids and self.attempts<4,'FOUR_EXACT_DIAGNOSTIC_ENGINE_GETS_ONLY')
        self.attempts+=1
        status,value=self.engine.request('GET','/v1.44/containers/'+cid+'/json')
        require(status==200 and type(value)is dict and value['Id']==cid,'EXACT_CURRENT_CONTAINER_OBSERVATION_REQUIRED')
        self.observed[cid]=value
        return value

def mount_shape(actual,profile):
    target=Path(profile['tokenTarget']);matches=[]
    for m in actual['Mounts']:
        dest=Path(m['Destination'])
        if target==dest or dest in target.parents:matches.append((len(dest.parts),m))
    require(bool(matches),'CONFIGURED_TOKEN_MOUNT_REQUIRED')
    mount=max(matches,key=lambda x:x[0])[1];dest=Path(mount['Destination'])
    source=Path(mount['Source'])/target.relative_to(dest)
    return {'exactFileMount':dest==target,'parentDirectoryMount':dest!=target,
            'readOnlyMount':mount.get('RW')is False,
            'sourcePathMatchesReviewed':str(source)==profile['tokenSource']['path']}

def mounted_metadata(pid,target):
    target=Path(target);require(target.is_absolute()and'..'not in target.parts,'ABSOLUTE_REVIEWED_TOKEN_TARGET_REQUIRED')
    fds=[]
    try:
        fd=os.open('/proc/'+str(pid)+'/root',os.O_PATH|os.O_DIRECTORY);fds.append(fd)
        for part in target.parts[1:-1]:
            fd=os.open(part,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);fds.append(fd)
        leaf=os.open(target.name,os.O_PATH|os.O_NOFOLLOW,dir_fd=fd);fds.append(leaf)
        value=list(identity(os.fstat(leaf)))
        require(value==list(identity(os.stat(target.name,dir_fd=fd,follow_symlinks=False))),
                'MOUNTED_TOKEN_CHANGED_DURING_METADATA_OBSERVATION')
        require(stat.S_ISREG(value[4]),'MOUNTED_TOKEN_REGULAR_FILE_REQUIRED')
        return value
    finally:
        for fd in reversed(fds):os.close(fd)

def publish_private(path,value):
    raw=encoded(value);fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
    try:
        with os.fdopen(os.dup(fd),'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    finally:os.close(fd)
    parent=os.open(Path(path).parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(parent)
    finally:os.close(parent)

def validate_repair_prefix(journal,owner,scope,records,reads):
    require(journal['authorityHash']==AUTHORITY_HASH and journal['nextStage']==11
            and len(journal['effects'])==12 and all(e['state']=='APPLIED'for e in journal['effects'][:11])
            and journal['effects'][11]['state']=='CLAIMED'and journal.get('originalSemanticGetSucceeded')is False,
            'EXACT_UNCOMPLETED_STAGE_ELEVEN_PREFIX_REQUIRED')
    require(owner['state']=='CANCELLED'and owner['reason']=='CANCELLED_BY_OWNER'
            and owner['controlledPredecessorGrantAttempts']==320 and owner['attempts']==1
            and owner['controlledCumulativeGrantAttempts']==321 and owner['workerSessionHash']==digest(scope)
            and records['owner-session.json']==scope and records['owner-admission.json']['state']=='BLOCKED'
            and owner['firstGrantReceiptHash']==scope['firstGrantReceiptHash']==digest(records['owner-first-grant.json'])
            and owner['bootId']==scope['currentSessionBootId']==journal['bootId']
            and owner['gateGeneration']==journal['newGeneration']
            and all(owner[k]==scope[k]==records['owner-admission.json'][k]for k in('contextRef','generationRef')),
            'EXACT_CANCELLED321_OWNER_RECORDS_REQUIRED')
    require(reads['authorityHash']==AUTHORITY_HASH
            and reads['counts']=={'databaseSessions':18,'gatewayAdminGets':18,'semanticGets':0}
            and all(type(v)is int for v in reads['counts'].values()),
            'EXACT_RETAINED_NATIVE18_18_0_COUNTERS_REQUIRED')

def retain_repair_inputs(reader,prepared,registry,caller,observation):
    review=reader.json(PREPARATION_ROOT+'/review.json',REVIEW_HASH)
    scope=review['scopes']['semanticRegistryPostbootOwner'];ownerroot=inside(scope['journalPath'])
    lock=os.open(ownerroot/'invocation.lock',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        records={name:reader.json(str(ownerroot/name),maximum=131072)
                 for name in('recovery.json','owner-session.json','owner-admission.json','owner-first-grant.json','installation.json')}
        context=prepared['nativeContext'];execution=inside(context['executionRoot'])
        journal=reader.json(str(execution/'recovery.json'),maximum=2097152)
        reads=reader.json(str(execution/'native-reads.json'),maximum=8192)
        validate_repair_prefix(journal,records['recovery.json'],scope,records,reads)
        require(reads['scopeHash']==digest(review['scopes']['semanticRegistryRecoveryReads']),'SAME_SIGNED_NATIVE_READ_SCOPE_REQUIRED')
        fence=reader.json(scope['fenceBinding']['path'],maximum=131072)
        require(fence==scope['fenceBinding']['value'],'UNCHANGED_CURRENT_OWNER_FENCE_REQUIRED')
        first=reader.json(PREPARATION_ROOT+'/current-caller-get-v1/result.json',maximum=131072)
        correlated=reader.json(PREPARATION_ROOT+'/current-caller-403-attribution-v1/result.json',maximum=131072)
        require(first.get('httpStatus')==correlated.get('httpStatus')==403 and first.get('httpRequests')==correlated.get('httpRequests')==1
                and correlated.get('combinedDiagnosticHttpGetAttempts')==2
                and correlated['diagnosticResponseOrigin']['problemClass']=='SEM_CAPABILITY_REQUIRED'
                and correlated['diagnosticResponseOrigin']['registryProblemShape']is True
                and correlated['diagnosticResponseOrigin']['problemCorrelationMatchesRequest']is True
                and correlated['diagnosticResponseOrigin']['responseCorrelationHeaderMatchesRequest']is True,
                'EXACT_TWO_COMPLETED_REGISTRY403_DIAGNOSTICS_REQUIRED')
        files=sys.modules['tools.semantic_registry_recovery_execution.postboot_prepare'].Files()
        old=context['originalRequest']['tokenSource'];current,_=files.seal(old['path'],16384)
        require(current['ancestors']==old['ancestors']and all(current['metadata'][i]==old['metadata'][i]for i in(0,2,3,4,5,6))
                and current['sha256']!=old['sha256']and mounted_metadata(caller['State']['Pid'],context['originalRequest']['tokenTarget'])==current['metadata'],
                'EXACT_CURRENT_ROTATED_CONFIGURED_CALLER_TOKEN_REQUIRED')
        identity_value={'purpose':'RUNNING_REGISTRY_POLICY_REFRESH_REPAIR_INPUTS_V1','priorAuthorityHash':AUTHORITY_HASH,
                        'nativeJournalHash':digest(journal),'ownerJournalHash':digest(records['recovery.json']),
                        'retainedControlledGrantAttempts':321}
        root=Path(PARENT)/('semantic-registry-running-policy-inputs-'+digest(identity_value))
        value={'schema':'ouf.semantic-registry-running-policy-repair-inputs.v1','identity':identity_value,
               'preparationBinding':{'path':PREPARATION_ROOT+'/prepared.json','sha256':PREPARATION_HASH},
               'reviewBinding':{'path':PREPARATION_ROOT+'/review.json','sha256':REVIEW_HASH},
               'prepared':prepared,'review':review,'retainedNativeJournal':journal,'retainedNativeReads':reads,
               'retainedOwnerRecords':records,'retainedFence':scope['fenceBinding'],
               'currentRegistryObservation':registry,'currentCallerObservation':caller,
               'retainedCallerTokenBinding':old,'proposedCallerTokenBinding':current,
               'firstDiagnostic403':first,'correlatedDiagnostic403':correlated,
               'currentObservation':observation,'currentBindingIsNotSignedRuntimeAdoption':True,
               'runtimeAuthorityIssued':False,'newRuntimeBudgetGranted':False,'targetApplyAuthorized':False,
               'grantAttemptAllowance':0,'retainedControlledGrantAttempts':321,
               'oldClaimsRemainConsumed':True,'automaticReplayAllowed':False,'budgetReset':False}
        # Recheck all mutable protocol inputs while both invocation locks are held.
        require(reader.json(str(execution/'recovery.json'),maximum=2097152)==journal
                and reader.json(str(execution/'native-reads.json'),maximum=8192)==reads
                and reader.json(str(ownerroot/'recovery.json'),maximum=131072)==records['recovery.json']
                and reader.json(scope['fenceBinding']['path'],maximum=131072)==fence,
                'REPAIR_INPUT_JOURNALS_OR_FENCE_CHANGED')
        again,_=files.seal(old['path'],16384)
        require(again==current,'CURRENT_CALLER_TOKEN_CHANGED_BEFORE_INPUT_PUBLICATION')
        os.mkdir(root,0o700);publish_private(root/'inputs.json',value)
        return {'schema':SCHEMA,'status':'RUNNING_REGISTRY_POLICY_REPAIR_INPUTS_PREPARED','complete':True,
                'privateInputsPath':str(root/'inputs.json'),'privateInputsHash':digest(value),
                'retainedNativeCheckpoint':11,'retainedControlledGrantAttempts':321,
                'retainedDiagnosticHttpGetAttempts':2,'ownerCancelled':True,
                'sameRunningRegistryGenerationObserved':True,'rotatedCallerTokenCandidateCaptured':True,
                'signedCallerTokenRebindingPerformed':False,'permanentRenewalProven':False,
                'engineGets':4,'maximumEngineGets':4,'httpRequests':0,'oauthRequests':0,
                'databaseCalls':0,'adminGets':0,'credentialContentReads':files.reads,
                'credentialValuesPrinted':False,'addressesPrinted':False,
                'metadataReads':reader.reads,'metadataBytesRead':reader.bytes,
                'maximumMetadataReadOperations':48,'maximumMetadataBytes':33554432,
                'runtimeEffectsDispatched':0,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
                'newRuntimeBudgetGranted':False,'nativeEffectReplayAllowed':False,
                'automaticReplayAllowed':False,'budgetReset':False,'readOnlyRuntime':True,
                'serviceReadinessEstablished':False,'releaseAcceptance':False}
    finally:os.close(lock)

metadata_inspect=inspect

def inspect(reader):
    result=metadata_inspect(reader)
    prepared=reader.json(PREPARATION_ROOT+'/prepared.json',PREPARATION_HASH,maximum=16777216)
    context=prepared['nativeContext'];profile=context['originalRequest'];execution=inside(context['executionRoot'])
    journal=reader.json(str(execution/'recovery.json'),maximum=2097152)
    require(journal['authorityHash']==AUTHORITY_HASH and journal['nextStage']==11,'EXACT_STOPPED_CHECKPOINT_REQUIRED')
    # Existing invocation lock only; never create or rewrite protocol files.
    lock=os.open(execution/'invocation.lock',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        Engine,guard,configuration,transport=sealed_native_modules(reader.raw(CAPSULE,1048576,CAPSULE_HASH))
        binding=context['engineBinding'];engine=Engine(binding['socketPath'],tuple(binding['socketBinding']))
        caller_id=profile['caller']['binding']['containerId'];registry_id=context['plan']['stages'][0]['intent']['registryId']
        transport_only=DiagnosticEngine(engine,(caller_id,registry_id));get=transport_only.get
        caller=get(caller_id);registry=get(registry_id)
        guard.unchanged(caller,profile['caller']);configuration.verify(caller,profile)
        shape=mount_shape(caller,profile);require(shape['sourcePathMatchesReviewed'],'SAME_ORIGINAL_CALLER_TOKEN_SOURCE_REQUIRED')
        pid=caller['State']['Pid'];ticks=transport.process_ticks(pid)
        require(os.path.isfile('/proc/sys/kernel/random/boot_id'),'CURRENT_HOST_BOOT_REQUIRED')
        boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        require(boot==journal['bootId'],'SAME_RECOVERY_BOOT_REQUIRED')
        source=profile['tokenSource'];before=list(identity(Path(source['path']).lstat()))
        require(binding_metadata(source).get('status')in('METADATA_MATCHES','METADATA_CHANGED'),
                'PROTECTED_CALLER_TOKEN_SOURCE_REQUIRED')
        mounted=mounted_metadata(pid,profile['tokenTarget'])
        after=list(identity(Path(source['path']).lstat()))
        require(before==after and mounted==mounted_metadata(pid,profile['tokenTarget']),
                'HOST_OR_MOUNTED_TOKEN_METADATA_CHANGED')
        state=registry['State'];g=journal['newGeneration'];running=state['Running']is True
        same_generation=False
        if running and state['Pid']==g['pid']:
            ns=Path('/proc')/str(g['pid'])/'ns/net';info=ns.stat()
            same_generation=(transport.process_ticks(g['pid'])==g['startTicks']
                and info.st_dev==g['namespaceDevice']and info.st_ino==g['namespaceInode'])
        final_caller=get(caller_id);final_registry=get(registry_id)
        guard.unchanged(final_caller,profile['caller']);configuration.verify(final_caller,profile)
        def registry_pin(v):
            return {k:v[k]for k in('Id','Image','Config','HostConfig','Mounts','NetworkSettings','RestartCount')} | {'State':{k:v for k,v in v['State'].items()if k!='Health'}}
        require(registry_pin(final_registry)==registry_pin(registry)and transport.process_ticks(pid)==ticks,
                'CONTAINERS_CHANGED_DURING_METADATA_DIAGNOSIS')
        require(reader.json(str(execution/'recovery.json'),maximum=2097152)==journal,
                'NATIVE_JOURNAL_CHANGED_DURING_DIAGNOSIS')
        endpoints=registry['NetworkSettings']['Networks']
        require(type(endpoints)is dict and len(endpoints)<=32,'BOUNDED_REGISTRY_NETWORK_METADATA_REQUIRED')
        result.update(status='CURRENT_CALLER_AND_REGISTRY_METADATA_OBSERVED',engineGets=transport_only.attempts,
            maximumDiagnosticEngineGets=4,currentContainerStateObserved=True,
            callerConfigurationAndGenerationMatchReviewed=True,callerTokenMount=shape,
            mountedTokenMetadataMatchesCurrentHostSource=mounted==before,
            mountedTokenMetadataMatchesRetainedSource=mounted==source['metadata'],
            currentHostTokenMetadataMatchesRetainedSource=before==source['metadata'],
            callerMountedCredentialContentsRead=False,credentialContentReads=0,
            registryRunning=running,registryPaused=state['Paused']is True,
            registryRestarting=state['Restarting']is True,registryDead=state.get('Dead')is True,
            registryImageMatchesReviewed=registry['Image']==prepared['registryInputs']['creationRequest']['Image'],
            registrySameDurableProcessGeneration=same_generation,
            registryLiveNetworkEndpointCount=sum(bool(e.get('EndpointID'))for e in endpoints.values()),
            httpRequests=0,metadataReads=reader.reads,metadataBytesRead=reader.bytes,
            currentMetadataIsNotApplicationReadiness=True,nativeRecoveryCountersUnchanged=True,
            sealedSourcePreloaded=True,capsuleExecuted=False,applicationEntryInvoked=False)
        return retain_repair_inputs(reader,prepared,registry,caller,result)
    finally:os.close(lock)

def main():
    try:
        require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site
                and sys.dont_write_bytecode and len(sys.argv)==1,'ISOLATED_ROOT_METADATA_READER_REQUIRED')
        result=inspect(Reader())
    except Exception as error:
        reason=str(error)
        if re.fullmatch('[A-Z][A-Z0-9_]{0,127}',reason)is None:reason='FINAL_FILE_STOP_UNPROVEN_PRIVATE_DETAILS_REDACTED'
        result={'schema':SCHEMA,'status':'STOP_RECONCILE','reasonCode':reason,
                'runtimeEffectsDispatched':0,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False}
    print(json.dumps(result,sort_keys=True,separators=(',',':')),flush=True)
    return 0 if result['status']=='RUNNING_REGISTRY_POLICY_REPAIR_INPUTS_PREPARED'else 2

if __name__=='__main__':raise SystemExit(main())
