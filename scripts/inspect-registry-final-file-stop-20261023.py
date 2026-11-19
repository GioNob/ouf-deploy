#!/usr/bin/env python3
"""Read retained stop metadata only; never execute capsule or enter application."""
import ast
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
        require(time.monotonic() < self.until and self.reads < 20, 'BOUNDED_METADATA_READ_REQUIRED')
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
        require(self.bytes <= 16777216 and (sha is None or hashlib.sha256(raw).hexdigest() == sha), 'METADATA_HASH_OR_BYTE_BOUND')
        return raw

    def json(self, path, sha=None, maximum=8388608):
        raw = self.raw(path, maximum, sha); value = json.loads(raw)
        require(type(value) is dict and encoded(value) == raw, 'CANONICAL_METADATA_REQUIRED')
        return value


FIELDS=('device','inode','uid','gid','mode','links','size','mtimeNs','ctimeNs')
SCHEMA='ouf.semantic-registry-final-file-stop-observation.v1'

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
    return 0 if result['status']=='CHECKPOINT_ELEVEN_FILE_METADATA_OBSERVED'else 2

if __name__=='__main__':raise SystemExit(main())
