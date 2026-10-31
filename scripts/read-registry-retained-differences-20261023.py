#!/usr/bin/env python3
"""Read exact retained difference metadata, never live files or file contents."""
import hashlib,json,os,re,stat,sys,time
from pathlib import Path
REPORT='/etc/ouf/deploy-snapshots/semantic-registry-archive-comparison-4d8c3d00403c7ed0caeac97ed652bbd88a32d61bbeb6148bf1df23f5ece9b4c7/comparison.json'
REPORT_SHA='5d7e8b849cbee5aa944fa20cc4e657ce1c39bb19af427944d4d851beef998431'

def require(ok, reason):
    if not ok: raise ValueError(reason)

def encoded(v): return json.dumps(v, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()

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

def path_label(value):
    require(type(value) is str and len(value)<=4096 and not value.startswith('/') and '..' not in value.split('/'),
        'BOUNDED_RELATIVE_IMAGE_PATH_REQUIRED')
    # Print image paths needed for diagnosis, never symlink targets or content.
    # IPv4-looking components and names outside a small image-path alphabet are
    # represented by hashes. No deployment addresses are substituted into code.
    parts=value.split('/');result=[]
    for part in parts:
        if re.fullmatch('[A-Za-z0-9_+.-]{1,255}',part) is None or re.search(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}',part):
            part='[redacted-'+hashlib.sha256(part.encode()).hexdigest()[:12]+']'
        result.append(part)
    return '/'.join(result)


def fields(value):
    require(type(value) is dict,'EXACT_ENTRY_METADATA_REQUIRED')
    result={}
    for k in ('kind','mode','uid','gid','links','size','sha256'):
        if k not in value:continue
        v=value[k]
        if k=='kind':require(v in ('file','directory','symlink'),'CLOSED_ENTRY_KIND_REQUIRED')
        elif k=='sha256':require(type(v) is str and re.fullmatch('[0-9a-f]{64}',v),'EXACT_CONTENT_HASH_REQUIRED')
        else:require(v is None or type(v) is int and 0<=v<=8589934592,'BOUNDED_ENTRY_NUMBER_REQUIRED')
        result[k]=v
    return result


def inspect():
    r=Reader();v=r.json(REPORT,REPORT_SHA)
    require(v.get('schema')=='ouf.archived-image-rootfs-comparison.v1' and v.get('diagnosticOnly') is True
        and v.get('manifestHash')=='92ce6633088609b68d10cb3f8310ea1a083596ed93a177b8bc634be947b71294'
        and type(v.get('extraEntries')) is list and len(v['extraEntries'])==17 and v.get('missingEntries')==[]
        and type(v.get('differences')) is list and len(v['differences'])<=4,'EXACT_RETAINED_COMPARISON_SHAPE_REQUIRED')
    differences=[]
    for row in v['differences']:
        changed=row['fields'];require(type(changed) is list and set(changed)<={'kind','size','sha256','target','mode','uid','gid'},'CLOSED_DIFFERENCE_FIELDS_REQUIRED')
        differences.append({'relativeImagePath':path_label(row['path']),'pathHash':hashlib.sha256(row['path'].encode()).hexdigest(),
            'changedFields':changed,'archived':fields(row['archive']),'observed':fields(row['observed'])})
    require(sum(bool(set(x['changedFields'])&{'size','sha256'}) for x in differences)==1
        and sum(bool(set(x['changedFields'])&{'mode','uid','gid'}) for x in differences)==3,'EXACT_OBSERVED_DIFFERENCE_COUNTS_REQUIRED')
    extra=[{'relativeImagePath':path_label(row['path']),'pathHash':hashlib.sha256(row['path'].encode()).hexdigest(),**fields(row)} for row in v['extraEntries']]
    return {'schema':'ouf.semantic-registry-retained-difference-details.v1','status':'RETAINED_DIFFERENCES_REPORTED',
        'complete':True,'extraEntries':extra,'differences':differences,'metadataReads':r.reads,'metadataBytesRead':r.bytes,
        'imageRelativePathsPrinted':True,'fileContentsPrinted':False,'symlinkTargetsPrinted':False,'xattrsPrinted':False,
        'currentContainerStateObserved':False,'liveRootfsContentsRead':False,'engineGets':0,'priorDiagnosticEngineGets':4,
        'retainedControlledGrantAttempts':320,'oauthRequests':0,'databaseCalls':0,'adminGets':0,'credentialFilesOpened':0,
        'runtimeAuthorityIssued':False,'runtimeEffectsDispatched':0,'automaticReplayAllowed':False,'budgetReset':False,
        'readOnly':True,'serviceReadinessEstablished':False,'releaseAcceptance':False}


def main():
    try:
        require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and len(sys.argv)==1,
            'ISOLATED_ROOT_METADATA_READER_REQUIRED')
        value=inspect()
    except Exception as error:
        reason=str(error)
        if re.fullmatch('[A-Z][A-Z0-9_]{0,127}',reason) is None:reason='RETAINED_DIFFERENCES_UNPROVEN_PRIVATE_DETAILS_REDACTED'
        value={'schema':'ouf.semantic-registry-retained-difference-details.v1','status':'STOP_RECONCILE','reasonCode':reason,
            'automaticReplayAllowed':False,'budgetReset':False,'runtimeEffectsDispatched':0,'runtimeAuthorityIssued':False}
    print(json.dumps(value,sort_keys=True,separators=(',',':')),flush=True)
    return 0 if value['status']=='RETAINED_DIFFERENCES_REPORTED' else 2


if __name__=='__main__':raise SystemExit(main())
