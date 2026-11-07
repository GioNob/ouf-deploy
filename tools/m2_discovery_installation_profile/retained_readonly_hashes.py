"""One new private input: hash only exact captured readonly regular files.

No content or per-file hash is printed/spooled. Existing credential/key files
may be read transiently for hashing: this is explicitly not metadata-only.
Mutable/ephemeral/special contents are never opened. No runtime authority,
policy inference, copy/install, signing, OAuth, SQL or lifecycle operation.
"""
import copy, hashlib, json, os, re, stat
from pathlib import Path
from .custody_capture import attrs, decode, digest, encoded, process_pin, require, Stop
from .retained_mount_capture import RetainedCapture, RetainedEngine, RETAINED, SEED, identity
from .retained_mount_role_correction import OUTPUT as METADATA_SCOPE, PREDECESSOR, PREDECESSOR_HASH, ROSTER
from .retained_mount_intake import CANDIDATE, CANDIDATE_HASH, RESULT_HASH, SEED_HASH, validate_capture

OUTPUT=Path('/etc/ouf/deploy-snapshots/m2-retained-readonly-hashes-46f6e635-20261101-v1')
BOOT_PATH=Path('/proc/sys/kernel/random/boot_id')
CASE={'candidatePath':str(CANDIDATE),'resultPath':str(METADATA_SCOPE/'result.json'),
    'seedPath':str(SEED),'candidateHash':CANDIDATE_HASH,'resultHash':RESULT_HASH,'seedHash':SEED_HASH,
    'failedScope':str(PREDECESSOR)}
PROFILE={'schema':'ouf.retained-readonly-file-hash-preparation-profile.v1',
    'purpose':'NEW_READONLY_REGULAR_FILE_CONTENT_HASH_INPUT_FROM_EXACT_METADATA_ALLOWLIST',
    'maximumPreparationAttempts':1,'maximumSeconds':90,'maximumDirectEngineGets':20,
    'maximumFileBytes':8388608,'maximumTotalHashedBytes':67108864,'maximumUniqueFiles':2048,
    'priorMetadataScopesRemainConsumed':True,'priorCaptureControlAttempts':2,
    'priorCaptureDirectEngineGets':20,'maximumCumulativeDirectEngineGets':40,
    'oldCaptureReplayed':False,'automaticReplayAllowed':False,'runtimeBudgetResetOrGrant':False,
    'credentialOrKeyFilesMayBeReadForHashingOnly':True,'rawValuesOrIndividualHashesPrinted':False}
PUBLIC_COUNTS=('metadataReads','bytes','engineGets','engineBytes','staticEntries','readonlyMounts',
    'mutableMounts','ephemeralMounts','specialSources','readonlyRegularFilesHashed','readonlyFileBytesHashed')


class ReadonlyHashPreparation(RetainedCapture):
    def __init__(self,scope):
        super().__init__(scope);self.hashes={};self.mutable_sources=[]
        self.counts.update(readonlyRegularFilesHashed=0,readonlyFileBytesHashed=0)
        self.put('readonly-hash-preparation.claim.json',{'schema':'ouf.retained-readonly-hash-claim.v1',
            'caseHash':digest(CASE),'profile':PROFILE,'automaticReplayAllowed':False})

    def reject_mutable_overlap(self,path,expected):
        path=Path(path);self.guarded()
        canonical=lambda p:Path('/run/'+str(p)[len('/var/run/'):] if str(p).startswith('/var/run/') else p)
        selected=canonical(path)
        for source,metadata in self.mutable_sources:
            require(not selected.is_relative_to(canonical(source)) and expected[:2]!=metadata[:2],
                'READONLY_HASH_FILE_OVERLAPS_CAPTURED_MUTABLE_SOURCE')
        # Host bind aliases can have different names but the same inode. Check
        # every actual ancestor against the captured RW roots before content.
        inodes={tuple(v[:2]) for _,v in self.mutable_sources}
        for parent in path.parents:
            if parent==Path('/'):break
            self.guarded();fd=self.node(parent)
            try:require(tuple(attrs(os.fstat(fd))[:2]) not in inodes,
                'READONLY_HASH_FILE_OVERLAPS_CAPTURED_MUTABLE_SOURCE')
            finally:os.close(fd)

    def hash_file(self,path,expected):
        self.guarded();path=Path(path);self.reject_mutable_overlap(path,expected)
        held=self.node(path);parent=None;reader=None
        try:
            require(attrs(os.fstat(held))==expected and stat.S_ISREG(expected[2]) and expected[5]==1
                and 0<=expected[6]<=PROFILE['maximumFileBytes'], 'EXACT_BOUNDED_CAPTURED_READONLY_REGULAR_FILE_REQUIRED')
            if str(path) in self.hashes:
                require(self.hashes[str(path)]['metadata']==expected,'SHARED_READONLY_FILE_METADATA_DISAGREES');return
            require(len(self.hashes)<PROFILE['maximumUniqueFiles'],'BOUNDED_READONLY_HASH_FILE_SET_REQUIRED')
            require(self.counts['readonlyFileBytesHashed']+expected[6]<=PROFILE['maximumTotalHashedBytes'],
                'BOUNDED_READONLY_CONTENT_HASH_BYTES_REQUIRED')
            parent=(os.open('/',os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW) if path.parent==Path('/') else self.node(path.parent))
            reader=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
            require(attrs(os.fstat(reader))==expected,'READONLY_HASH_FILE_REBOUND_BEFORE_READ')
            h=hashlib.sha256();size=0
            while size<expected[6]:
                self.guarded();block=os.read(reader,min(65536,expected[6]-size))
                require(bool(block),'COMPLETE_READONLY_FILE_HASH_READ_REQUIRED')
                size+=len(block);self.counts['readonlyFileBytesHashed']+=len(block);h.update(block)
            again=self.node(path)
            try:
                require(size==expected[6] and attrs(os.fstat(reader))==attrs(os.fstat(held))==attrs(os.fstat(again))==expected,
                    'READONLY_FILE_CHANGED_DURING_HASH_READ')
            finally:os.close(again)
            self.hashes[str(path)]={'sha256':h.hexdigest(),'bytes':size,'metadata':expected,
                'rawValueExported':False,'permissionPolicyEstablished':False}
            self.counts['readonlyRegularFilesHashed']+=1
        finally:
            if reader is not None:os.close(reader)
            if parent is not None:os.close(parent)
            os.close(held)


def history_frames(root,expected_names):
    root=Path(root);RetainedCapture.ancestors(root/'placeholder');info=root.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid==info.st_gid==0
        and stat.S_IMODE(info.st_mode)==0o700 and {p.name for p in root.iterdir()}==set(expected_names),
        'EXACT_PRESERVED_METADATA_SCOPE_REQUIRED')
    frames={str(root):attrs(info)}
    for name in expected_names:
        path=root/name;s=path.lstat()
        require(stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and s.st_nlink==1
            and stat.S_IMODE(s.st_mode)==0o600,'PRESERVED_METADATA_SCOPE_FILE_CUSTODY_REQUIRED')
        frames[str(path)]=attrs(s)
    return frames


def metadata_binding(rows):
    value=copy.deepcopy(rows)
    for row in value:
        if row['kind']=='MUTABLE_CONTENT_NOT_OBSERVED':row['metadata']=row['metadata'][:5]
    return value


def collect(c):
    case_hash=digest(CASE)
    frames=history_frames(CASE['failedScope'],('capture.claim.json','result.json'))
    frames.update(history_frames(Path(CASE['candidatePath']).parent,
        ('capture.claim.json','predecessor-reconciliation.json','retained-mounts.private.json','result.json')))
    def read(path,maximum):return decode(c.read(Path(path),0,0,0o600,maximum,'metadataReads'))
    failed=read(Path(CASE['failedScope'])/'result.json',4096)
    require(digest(failed)==PREDECESSOR_HASH,'EXACT_PRESERVED_FAILED_PREDECESSOR_REQUIRED')
    candidate=read(CASE['candidatePath'],8388608);result=read(CASE['resultPath'],16384)
    seed=read(CASE['seedPath'],2097152)
    validate_capture(candidate,result,seed,candidate_hash=CASE['candidateHash'],result_hash=CASE['resultHash'],
        seed_hash=CASE['seedHash'],roster=ROSTER)
    peers=candidate['peers']
    def roots():
        c.guarded();require(digest(CASE)==case_hash and BOOT_PATH.read_text().strip()==seed['bootId']
            and all(process_pin(v['pid'])==v for v in seed['rootProcessPins'].values())
            and all(process_pin(p['processPin']['pid'])==p['processPin'] for p in peers.values()),
            'READONLY_HASH_BOOT_PROCESS_OR_CASE_CHANGED')
    roots();engine=RetainedEngine(c,seed['engineBinding'],[peers[r]['containerId'] for r in sorted(RETAINED)])
    for role in sorted(RETAINED):
        prior=peers[role];actual=engine.get(prior['containerId']);roots()
        require(digest(identity(actual))==prior['runtimeIdentityHash'], 'READONLY_HASH_RETAINED_CONFIGURATION_CHANGED')
        require(metadata_binding(c.mounts(actual))==metadata_binding(prior['mounts']),
            'READONLY_HASH_MOUNT_METADATA_DIFFERS_FROM_CAPTURE')
    c.mutable_sources=[(Path(mount['source']),mount['metadata']) for peer in peers.values()
        for mount in peer['mounts'] if mount['kind']=='MUTABLE_CONTENT_NOT_OBSERVED']
    files={}
    def select_tree(path,tree):
        c.guarded()
        if tree['kind']=='REGULAR_FILE':
            require(str(path) not in files or files[str(path)]==tree['metadata'],
                'SHARED_READONLY_FILE_METADATA_DISAGREES')
            files[str(path)]=tree['metadata']
        elif tree['kind']=='DIRECTORY':
            for name,child in sorted(tree['children'].items()):select_tree(path/name,child)
        # Special source contents are never opened, even if the mount is ro.
    for role in sorted(RETAINED):
        for mount in peers[role]['mounts']:
            if mount['kind']=='READONLY_METADATA_CANDIDATE':select_tree(Path(mount['source']),mount['metadataTree'])
    # Preflight the WHOLE set before opening its first file for content. This
    # also rejects a readonly alias of an explicitly RW mounted source.
    for path,metadata in files.items():c.reject_mutable_overlap(Path(path),metadata)
    for path,metadata in sorted(files.items()):c.hash_file(Path(path),metadata)
    for role in sorted(RETAINED):
        actual=engine.get(peers[role]['containerId']);roots()
        require(digest(identity(actual))==peers[role]['runtimeIdentityHash'], 'READONLY_HASH_RETAINED_CONFIGURATION_CHANGED_DURING_READ')
    for path,(before,static) in c.observed.items():
        fd=c.node(path)
        try:
            after=attrs(os.fstat(fd));require(after==before if static else after[:5]==before[:5],
                'READONLY_HASH_SOURCE_METADATA_CHANGED_DURING_READ')
        finally:os.close(fd)
    roots();require(all(attrs(Path(p).lstat())==v for p,v in {**frames,**c.seals}.items())
        and c.counts['engineGets']==20 and 0<len(c.hashes)<=PROFILE['maximumUniqueFiles'],
        'READONLY_HASH_HISTORY_INPUT_OR_CLOSED_READ_SET_CHANGED')
    private={'schema':'ouf.retained-readonly-content-hash-candidates.v1','caseHash':case_hash,
        'metadataCandidateHash':CASE['candidateHash'],'metadataResultHash':CASE['resultHash'],
        'seedHash':CASE['seedHash'],'bootId':seed['bootId'],'files':c.hashes,'profile':PROFILE,
        'regularReadonlyContentsReadForHashingOnly':True,'rawValuesSpilledOrExported':False,
        'expectedPermissionOrContentPolicyEstablished':False,'mutableContentsObserved':False,
        'specialProtocolRightsProven':False,'completePrivateCustodyProven':False,
        'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'releaseAcceptance':False}
    require(len(encoded(private))<=8388608,'BOUNDED_PRIVATE_READONLY_HASH_CANDIDATES_REQUIRED')
    c.put('readonly-content-hashes.private.json',private)
    return {'schema':'ouf.retained-readonly-hash-preparation-result.v1',
        'status':'PRIVATE_READONLY_HASH_CANDIDATES_PREPARED_NOT_ADMITTED','scope':str(c.scope),
        'candidateHash':digest(private),'metadataCandidateHash':CASE['candidateHash'],
        'counts':{k:c.counts[k] for k in PUBLIC_COUNTS},'priorMetadataScopesPreserved':True,
        'priorCaptureDirectEngineGets':20,'preparationDirectEngineGets':20,'cumulativeDirectEngineGets':40,
        'priorCaptureControlAttempts':2,'preparationAttempts':1,'cumulativeControlAttempts':3,
        'regularReadonlyContentsReadForHashingOnly':True,'credentialOrKeyFilesMayHaveBeenHashed':True,
        'rawValuesOrIndividualFileHashesPrinted':False,'mutableContentsObserved':False,
        'expectedPermissionOrContentPolicyEstablished':False,'completePrivateCustodyProven':False,
        'automaticReplayAllowed':False,'runtimeBudgetResetOrGrant':False,
        'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'releaseAcceptance':False}


def main():
    c=None
    try:
        c=ReadonlyHashPreparation(OUTPUT);result=collect(c);c.put('result.json',result);code=0
    except Exception as error:
        reason=str(error) if type(error) is Stop and re.fullmatch('[A-Z0-9_]{1,128}',str(error)) else 'RETAINED_READONLY_HASH_PREPARATION_UNPROVEN'
        result={'schema':'ouf.retained-readonly-hash-preparation-result.v1','status':'STOP_RECONCILE',
            'reasonCode':reason,'scopeConsumed':os.path.lexists(OUTPUT),
            'counts':{k:c.counts[k] for k in PUBLIC_COUNTS} if c is not None else {},
            'automaticReplayAllowed':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False}
        if c is not None:
            try:c.put('result.json',result)
            except Exception:pass
        code=1
    print(json.dumps(result,sort_keys=True));return code

if __name__=='__main__':raise SystemExit(main())
