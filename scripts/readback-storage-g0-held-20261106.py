#!/usr/bin/env python3
"""Read-only reconciliation of the consumed G0 HOST_BEFORE attempt.

No socket, HTTP, SQL, credential-file read, write, scope creation or retry.
File guards copied unchanged from capacity helper9bfb77f3.
"""
import hashlib,json,os,re,stat,sys
from pathlib import Path

STAGING=Path('/var/lib/ouf-g0-network-preparation-20261106')
METADATA=Path('/var/lib/docker/containers')
OPERATION='seaweedfs-g0-20261106-v1'
DECISION='OUF-G0-COLLECT-20261106-01'
INPUT_SHA='6b5a2ba087cd5bfbc956f3bb240cf103b0bbf8d0aeaebb14d6a10f9aaaa22af1'
MANIFEST_SHA='1e542f786ac1606cf72f273bc079eaa5b06b6bd22a210d615c10d13a9d9f8adf'
EXPECTED_LIMITS={'attempts':1,'seconds':900,'engineGets':130,'engineBytes':33554432,
    's3Requests':3000,'s3WireBytes':134217728,'s3Bodies':256,'s3BodyBytes':67108864,
    'databaseExports':3,'databaseBytesEach':33554432,'databaseRowsPerSection':10000,
    'priorControls':17,'priorEngineGets':52,'automaticReplayAllowed':False}
EXPECTED_RESULT={'acceptanceCreditAdded': 0, 'automaticReplayAllowed': False, 'childScopes': {}, 'cumulativeEngineGets': 53, 'databaseExportsAttempted': 0, 'engineBytes': 285226, 'engineGets': 1, 'g0Complete': False, 'phase': 'HOST_BEFORE', 'priorControls': 17, 'priorEngineGets': 52, 'reason': 'G0_HOST_CONTAINER_LIMIT', 'runtimeAuthorityIssued': False, 's3Requests': None, 'schema': 'ouf.storage-g0-package-result.v1', 'scopeConsumed': True, 'sections': {'ACCESS': {'status': 'NOT_COLLECTED'}, 'CAPACITY': {'status': 'NOT_COLLECTED'}, 'CUSTODY': {'status': 'NOT_COLLECTED'}, 'DB': {'status': 'NOT_COLLECTED'}, 'OBJECTS': {'status': 'NOT_COLLECTED'}, 'RUNTIME': {'status': 'NOT_COLLECTED'}, 'WINDOW': {'status': 'NOT_COLLECTED'}, 'WRITERS': {'status': 'NOT_COLLECTED'}}, 'status': 'HELD', 'targetWrites': 0, 'technicalCaptureComplete': False}

class Held(ValueError):
    pass


def require(ok, code):
    if not ok:
        raise Held(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def identity(info):
    return tuple(getattr(info, k) for k in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid',
                 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def directory(path):
    path = Path(path)
    require(path.is_absolute() and str(path) == os.path.normpath(path), 'CAPACITY_CANONICAL_PATH')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in ('', *path.parts[1:]):
            if part:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            info = os.fstat(fd)
            require(info.st_uid == 0 and not info.st_mode & 0o022, 'CAPACITY_ROOT_PROTECTED_ANCESTRY')
        return fd
    except BaseException:
        os.close(fd)
        raise


def read(path, limit, private=True):
    path = Path(path)
    parent = directory(path.parent)
    fd = None
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
                and 0 < before.st_size <= limit and not before.st_mode & 0o022,
                'CAPACITY_BOUNDED_ROOT_FILE')
        if private:
            require(stat.S_IMODE(before.st_mode) == 0o600, 'CAPACITY_PRIVATE_FILE_MODE')
        raw = os.read(fd, limit + 1)
        require(len(raw) == before.st_size and identity(before) == identity(os.fstat(fd))
                == identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)), 'CAPACITY_FILE_CHANGED')
        return raw
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def metadata_count(path, expected_ids):
    result={'path':str(path),'liveEngineContainerCountProven':False,
            'containerConfigurationFilesRead':0,'providerRequests':0}
    if not os.path.lexists(path):
        return result | {'status':'ABSENT_NOT_PROOF_OF_DOCKER_ROOT'}
    fd=directory(path)
    try:
        before=identity(os.fstat(fd));identifiers=set();other=0;links=0;entries=0
        with os.scandir(fd) as scan:
            for item in scan:
                entries+=1
                require(entries<=10000,'HELD_READBACK_METADATA_ENTRY_LIMIT')
                if item.is_symlink():links+=1
                elif re.fullmatch('[a-f0-9]{64}',item.name) and item.is_dir(follow_symlinks=False):
                    identifiers.add(item.name)
                else:other+=1
        require(identity(os.fstat(fd))==before,'HELD_READBACK_METADATA_CHANGED')
        return result | {'status':'LOCAL_DIRECTORY_NAMES_OBSERVED',
            'directoryNamesMatchingContainerIds':len(identifiers),
            'boundRoleDirectoryNamesPresent':len(expected_ids & identifiers),
            'allBoundRoleDirectoryNamesPresent':expected_ids <= identifiers,
            'otherEntries':other,'symlinkEntries':links,'scanComplete':True}
    finally:os.close(fd)


def inspect(staging, metadata, *, input_sha=INPUT_SHA, expected_result=EXPECTED_RESULT):
    require(os.geteuid()==os.getegid()==0,'HELD_READBACK_ROOT_ONLY')
    source=staging/'inputs/capacity-directory-preparation-20261106'
    scope=staging/'evidence'/OPERATION
    original=read(source/'package-input.review.json',65536)
    require(sha(original)==input_sha,'HELD_READBACK_ORIGINAL_INPUT_CHANGED')
    config=json.loads(original)
    copied=read(source/'package-input.collection.json',65536)
    execution=json.loads(copied)
    require(config.get('collectionDecisionRef') is None,'HELD_READBACK_ORIGINAL_DECISION')
    require(execution==config|{'collectionDecisionRef':DECISION},'HELD_READBACK_ONLY_DECISION_DELTA')
    require(config['operationId']==OPERATION and config['outputParent']==str(staging/'evidence'),
            'HELD_READBACK_SCOPE_BINDING')
    claim_raw=read(scope/'claim.private.json',65536);claim=json.loads(claim_raw)
    result_raw=read(scope/'result.json',65536);result=json.loads(result_raw)
    decision_raw=read(source/'collection-decision.private.json',65536);decision=json.loads(decision_raw)
    require(encode(result)==encode(expected_result),'HELD_READBACK_RESULT_MISMATCH')
    require(claim['limits']==EXPECTED_LIMITS,'HELD_READBACK_APPROVED_LIMITS_CHANGED')
    require(claim['collectionDecisionRef']==DECISION and claim['operationId']==OPERATION
            and claim['installationRef']==config['installationRef']
            and claim['inputSha256']==sha(copied) and claim['packageManifestSha256']==MANIFEST_SHA,
            'HELD_READBACK_CLAIM_BINDING')
    require(decision['decisionRef']==DECISION and decision['baseInputSha256']==input_sha
            and decision['executionInputSha256']==sha(copied)
            and decision['boundInputSha256']==claim['boundInputSha256']
            and decision['limits']==claim['limits'] and decision['scope']==str(scope)
            and decision['runtimeAuthorityIssued'] is False
            and decision['authenticatedHumanApproval'] is False,'HELD_READBACK_DECISION_BINDING')
    expected_files={'claim.private.json','result.json','phase-HOST_BEFORE.json','engine-request-1.json',
                    'network-binding.private.json'}|{'input-'+k+'.private.json' for k in config['connectionFiles']}
    fd=directory(scope)
    try:require(set(os.listdir(fd))==expected_files,'HELD_READBACK_UNEXPECTED_SCOPE_MEMBERS')
    finally:os.close(fd)
    phase=json.loads(read(scope/'phase-HOST_BEFORE.json',4096))
    request=json.loads(read(scope/'engine-request-1.json',4096))
    require(phase=={'phase':'HOST_BEFORE','reserved':True},'HELD_READBACK_PHASE')
    require(request=={'sequence':1,'method':'GET','pathSha256':sha(b'/containers/json?all=1')},
            'HELD_READBACK_SINGLE_LIST_REQUEST')
    bound=claim['boundInputSha256']
    for key,path in config['connectionFiles'].items():
        require(sha(read(Path(path),16384))==bound['connection:'+key]
                ==sha(read(scope/('input-'+key+'.private.json'),16384)),
                'HELD_READBACK_CONNECTION_DRIFT')
    require(sha(read(Path(config['networkBindingFile']),65536))==bound['network']
            ==sha(read(scope/'network-binding.private.json',65536)),'HELD_READBACK_NETWORK_DRIFT')
    for key,path in config['operatorEvidenceFiles'].items():
        if path is not None:
            require(sha(read(Path(path),1<<20))==bound['operator:'+key],'HELD_READBACK_OPERATOR_DRIFT')
    require(len(config['priorReceiptFiles'])==17,'HELD_READBACK_HISTORY_DOMAIN')
    for item in config['priorReceiptFiles']:
        require(sha(read(Path(item['path']),2<<20))==item['sha256']==bound['history:'+str(item['control'])],
                'HELD_READBACK_HISTORY_DRIFT')
    observed=metadata_count(metadata,{x['containerId'] for x in config['roles'].values()})
    require(read(scope/'result.json',65536)==result_raw and read(scope/'claim.private.json',65536)==claim_raw
            and read(source/'package-input.collection.json',65536)==copied,
            'HELD_READBACK_RECEIPTS_CHANGED')
    return {'schema':'ouf.storage-g0-held-readback.v1','status':'HELD_ATTEMPT_BOUND_NO_REPLAY_AUTHORITY',
        'operationId':OPERATION,'resultMatchesReported':True,'expectedScopeMembersOnly':True,
        'resultSha256':sha(result_raw),'claimSha256':sha(claim_raw),'decisionSha256':sha(decision_raw),
        'executionInputSha256':sha(copied),'historyReceiptsPreserved':17,'priorControls':17,
        'priorEngineGets':52,'consumedEngineGets':1,'cumulativeEngineGets':53,
        's3AndDbPhasesNotReachedAccordingToLocalReceipts':True,
        'providerRequests':0,'credentialFilesRead':0,'filesModified':0,
        'metadataObservation':observed,'automaticReplayAllowed':False,'scopeConsumed':True,
        'runtimeAuthorityIssued':False,'g0Complete':False,'acceptanceCreditAdded':0}


def main():
    try:
        require(len(sys.argv)==1 and sys.flags.isolated and sys.flags.no_site
                and sys.dont_write_bytecode,'HELD_READBACK_ISOLATED_ENTRY')
        print(json.dumps(inspect(STAGING,METADATA),sort_keys=True));return 0
    except Exception as error:
        reason=str(error) if isinstance(error,Held) else 'HELD_READBACK_INCOMPLETE_PRESERVE_SCOPE'
        print(json.dumps({'status':'HELD','reason':reason,'providerRequests':0,'filesModified':0,
                          'automaticReplayAllowed':False,'runtimeAuthorityIssued':False},sort_keys=True))
        return 1


if __name__=='__main__':raise SystemExit(main())
