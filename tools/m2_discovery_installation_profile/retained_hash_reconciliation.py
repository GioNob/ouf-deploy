"""Reconcile one exact gateway-owner metadata mismatch, never retry hashing.

Zero Engine calls and mounted-file contents. Current drift is new diagnostic
evidence, not a reconstruction of the failed observation or permission policy.
Names/paths/exact metadata remain private; public output has structural deltas.
"""
import copy, json, os, re, stat, time
from pathlib import Path
from .custody_capture import attrs, decode, digest, encoded, process_pin, require, Stop
from .retained_mount_capture import RetainedCapture
from .retained_mount_intake import validate_capture
from . import retained_readonly_hashes as previous

FAILED_HASH='a7a7601c5f78dd55ad43839c588cddaded3a61471517dbf6b7917ffbfd9f4319'
FAILED_SCOPE=previous.OUTPUT
OUTPUT=Path('/etc/ouf/deploy-snapshots/m2-retained-hash-reconciliation-a7a7601c-20261101-v1')
CASE=copy.deepcopy(previous.CASE)
ROSTER=copy.deepcopy(previous.ROSTER)
BOOT_PATH=Path('/proc/sys/kernel/random/boot_id')
ROLE='gateway-owner'
FIELDS=('device','inode','typeAndMode','uid','gid','linkCount','size','mtimeNs','ctimeNs')
PROFILE={'schema':'ouf.retained-hash-metadata-reconciliation-profile.v1','maximumAttempts':1,
    'maximumSeconds':30,'maximumNodes':2048,'maximumDepth':32,'maximumEngineGets':0,
    'maximumMountedFileContentBytes':0,'maximumPrivateOutputBytes':8388608,'maximumPublicDifferences':128,
    'priorMetadataControlAttempts':2,'failedHashControlAttempts':1,'reconciliationControlAttempts':1,
    'cumulativeControlAttempts':4,'priorMetadataEngineGets':20,'failedHashEngineGets':2,
    'maximumCumulativeDirectEngineGets':22,'hashAttemptRearmed':False,
    'oldScopesReopenedOrReset':False,'automaticReplayAllowed':False,'runtimeBudgetResetOrGrant':False}


def kind(mode):
    if stat.S_ISDIR(mode):return 'DIRECTORY'
    if stat.S_ISREG(mode):return 'REGULAR_FILE'
    if stat.S_ISLNK(mode):return 'SYMLINK'
    return 'SPECIAL_FILE'


class Reconciliation(RetainedCapture):
    def __init__(self,scope):
        super().__init__(scope);self.until=time.monotonic()+PROFILE['maximumSeconds']
        self.counts.update(reconciliationNodes=0,mountedFileContentBytesRead=0)
        self.put('reconciliation.claim.json',{'schema':'ouf.retained-hash-reconciliation-claim.v1',
            'failedHashResultHash':FAILED_HASH,'profile':PROFILE,'automaticReplayAllowed':False})

    def current_node(self,path,depth=0,*,walk=True):
        """Only O_PATH nodes and directory listings; never follow a drifted link."""
        self.guarded();path=Path(path);original=str(path)
        if original.startswith('/var/run/'):
            alias=Path('/var/run').lstat()
            require(stat.S_ISLNK(alias.st_mode) and alias.st_uid==0 and os.readlink('/var/run')=='/run',
                'EXACT_SYSTEM_RUN_ALIAS_REQUIRED')
            path=Path('/run/'+original[len('/var/run/'):])
        require(path.is_absolute() and '..' not in path.parts and str(path)==str(Path(path))
            and path!=Path('/') and len(path.parts)<=64,'EXACT_RECONCILIATION_METADATA_PATH_REQUIRED')
        require(depth<=PROFILE['maximumDepth'] and self.counts['reconciliationNodes']<PROFILE['maximumNodes'],
            'BOUNDED_RECONCILIATION_METADATA_TREE_REQUIRED')
        self.counts['reconciliationNodes']+=1
        fds=[];fd=os.open('/',os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW);fds.append(fd)
        chain=[]
        try:
            for index,name in enumerate(path.parts[1:]):
                self.guarded()
                try:child=os.open(name,os.O_PATH|os.O_NOFOLLOW,dir_fd=fd)
                except FileNotFoundError:return {'kind':'MISSING','changedDuringRead':False}
                except NotADirectoryError:return {'kind':'ANCESTOR_NOT_DIRECTORY','changedDuringRead':False}
                except PermissionError:return {'kind':'ACCESS_DENIED','ancestorDepth':index+1,
                    'childrenObserved':False,'changedDuringRead':False}
                fds.append(child);info=os.fstat(child)
                if index<len(path.parts)-2 and not stat.S_ISDIR(info.st_mode):
                    return {'kind':'BLOCKED_BY_'+kind(info.st_mode),'metadata':attrs(info),
                        'ancestorDepth':index+1,'changedDuringRead':False}
                chain.append((fd,name,child,attrs(info)));fd=child
            before=attrs(os.fstat(fd));row={'kind':kind(before[2]),'metadata':before,'changedDuringRead':False}
            if row['kind']=='DIRECTORY' and walk:
                try:reader=os.open('.',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                except PermissionError:
                    row.update(childrenObserved=False,observationError='DIRECTORY_LIST_PERMISSION_DENIED');return row
                row['childrenObserved']=True
                try:
                    row['children']={}
                    with os.scandir(reader) as entries:
                        for entry in entries:
                            self.guarded();require(entry.name not in ('','.','..') and '/' not in entry.name
                                and len(entry.name)<=255,'BOUNDED_RECONCILIATION_MEMBER_NAME_REQUIRED')
                            row['children'][entry.name]=self.current_node(path/entry.name,depth+1)
                finally:os.close(reader)
            after=attrs(os.fstat(fd))
            if before!=after:row.update(changedDuringRead=True,metadataAfter=after)
            for parent,name,child,frame in chain:
                try:stable=attrs(os.fstat(child))==attrs(os.stat(name,dir_fd=parent,follow_symlinks=False))==frame
                except FileNotFoundError:stable=False
                if not stable:row['changedDuringRead']=True
            return row
        finally:
            for fd in reversed(fds):os.close(fd)


def flatten(tree,prefix=''):
    rows={prefix:{k:copy.deepcopy(v) for k,v in tree.items() if k!='children'}}
    for name,child in tree.get('children',{}).items():
        rows.update(flatten(child,prefix+'/'+name if prefix else name))
    return rows


def token_reference(row,mount,node):
    # Classification comes only from explicit path-valued environment references
    # in the hash-bound old config. It never reads a token/config file.
    destination=Path(mount['destination']);selected=destination/node if node else destination
    for item in row['Config'].get('Env') or []:
        key,_,value=item.partition('=')
        if re.search(r'(?:^|_)TOKEN_(?:FILE|PATH|DIRECTORY|DIR)$',key) and value.startswith('/'):
            target=Path(value)
            if target==selected:return 'EXPLICIT_TOKEN_PATH_REFERENCE'
            if target.is_relative_to(selected):return 'CONTAINS_EXPLICIT_TOKEN_PATH_REFERENCE'
    return 'UNCLASSIFIED_DECLARED_MOUNT_NODE'


def differences(prior,current,mount,index,container):
    before=flatten(prior);after=flatten(current);private=[];public=[]
    for name in sorted(set(before)|set(after)):
        old,new=before.get(name),after.get(name)
        changed=[]
        if old is None:membership='ADDED'
        elif new is None:membership='REMOVED'
        else:
            membership='PRESENT'
            a,b=old.get('metadata'),new.get('metadata')
            if a is not None and b is not None:changed=[k for k,x,y in zip(FIELDS,a,b) if x!=y]
        kind_changed=old is None or new is None or old['kind']!=new['kind']
        unstable=bool(new and new.get('changedDuringRead'))
        incomplete=bool(new and new.get('childrenObserved') is False)
        blocked=any((v.get('childrenObserved') is False or v['kind']=='SYMLINK' or v['kind'].startswith('BLOCKED_BY_'))
            and ((name.startswith(parent+'/')) or (parent=='' and name!='')) for parent,v in after.items())
        if new is None and blocked:membership='UNOBSERVED_BELOW_UNREADABLE_DIRECTORY'
        if membership=='PRESENT' and not kind_changed and not changed and not unstable and not incomplete:continue
        category=('MEMBERSHIP_CHANGED' if membership!='PRESENT' else
            'KIND_OR_CUSTODY_CHANGED' if kind_changed or set(changed)&set(FIELDS[:6]) else
            'SIZE_OR_TIME_CHANGED' if changed else 'CHANGED_DURING_OBSERVATION')
        row={'mountOrdinal':index,'mountBindingHash':mount['mountHash'],'relativeNodeHash':digest(name),
            'depth':len(Path(name).parts) if name else 0,'membership':membership,
            'capturedKind':old['kind'] if old else None,'currentKind':new['kind'] if new else None,
            'changedMetadataFields':changed,'changedDuringRead':unstable,'observationIncomplete':incomplete or blocked,
            'category':category,
            'configuredReferenceClass':token_reference(container,mount,name)}
        public.append(row);private.append({**row,'relativePath':name,'captured':old,'current':new})
    return private,public,len(set(before)|set(after))


def collect(c):
    # Read only the exact terminal failed hash preparation, never replay it.
    frames=previous.history_frames(FAILED_SCOPE,('capture.claim.json','readonly-hash-preparation.claim.json','result.json'))
    def read(path,maximum):return decode(c.read(Path(path),0,0,0o600,maximum,'metadataReads'))
    failed=read(FAILED_SCOPE/'result.json',16384)
    require(digest(failed)==FAILED_HASH,'EXACT_TERMINAL_TWO_GET_ZERO_HASH_PREDECESSOR_REQUIRED')
    claim=read(FAILED_SCOPE/'readonly-hash-preparation.claim.json',16384)
    require(claim=={'schema':'ouf.retained-readonly-hash-claim.v1','caseHash':digest(CASE),
        'profile':previous.PROFILE,'automaticReplayAllowed':False},'EXACT_FAILED_HASH_SOURCE_PROFILE_REQUIRED')
    frames.update(previous.history_frames(CASE['failedScope'],('capture.claim.json','result.json')))
    frames.update(previous.history_frames(Path(CASE['candidatePath']).parent,
        ('capture.claim.json','predecessor-reconciliation.json','retained-mounts.private.json','result.json')))
    candidate=read(CASE['candidatePath'],8388608);receipt=read(CASE['resultPath'],16384);seed=read(CASE['seedPath'],2097152)
    mapping=validate_capture(candidate,receipt,seed,candidate_hash=CASE['candidateHash'],
        result_hash=CASE['resultHash'],seed_hash=CASE['seedHash'],roster=ROSTER)
    require(sorted(candidate['peers'])[failed['counts']['engineGets']-1]==ROLE
        and failed['counts']['readonlyRegularFilesHashed']==failed['counts']['readonlyFileBytesHashed']==0,
        'PINNED_FAILED_ROLE_AND_ZERO_HASH_EFFECT_REQUIRED')
    container=seed['observations'][mapping[ROLE]];proof=candidate['peers'][ROLE]
    def roots():
        c.guarded();require(BOOT_PATH.read_text().strip()==seed['bootId']
            and all(process_pin(v['pid'])==v for v in seed['rootProcessPins'].values())
            and process_pin(proof['processPin']['pid'])==proof['processPin'],
            'RECONCILIATION_BOOT_ROOT_OR_GATEWAY_PROCESS_CHANGED')
    roots();public=[];private=[];compared=0
    for index,mount in enumerate(proof['mounts']):
        c.guarded()
        if mount['kind']=='READONLY_METADATA_CANDIDATE':
            current=c.current_node(Path(mount['source']));prior=mount['metadataTree']
        elif mount['kind']=='MUTABLE_CONTENT_NOT_OBSERVED':
            # A writable root is metadata only and is never enumerated.
            current=c.current_node(Path(mount['source']),walk=False)
            prior={'kind':kind(mount['metadata'][2]),'metadata':mount['metadata'][:5]}
            if 'metadata' in current:current['metadata']=current['metadata'][:5]
            if 'metadataAfter' in current:current['metadataAfter']=current['metadataAfter'][:5]
        else:continue
        secret,redacted,count=differences(prior,current,mount,index,container)
        compared+=count;private.append({'mount':mount,'currentTree':current,'differences':secret});public+=redacted
    roots();require(c.counts['engineGets']==c.counts['mountFileContentBytesRead']==0
        and all(attrs(Path(p).lstat())==v for p,v in {**frames,**c.seals}.items()),
        'RECONCILIATION_HISTORY_INPUT_OR_ZERO_EFFECT_CHANGED')
    record={'schema':'ouf.retained-hash-metadata-reconciliation-private.v1','failedResultHash':FAILED_HASH,
        'metadataCandidateHash':CASE['candidateHash'],'role':ROLE,'mounts':private,'profile':PROFILE,
        'currentDiffIsNotHistoricalFailureTrace':True,'permissionOrContentPolicyEstablished':False,
        'hashPreparationRearmed':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False}
    require(len(encoded(record))<=PROFILE['maximumPrivateOutputBytes'],'BOUNDED_PRIVATE_RECONCILIATION_OUTPUT_REQUIRED')
    c.put('reconciliation.private.json',record)
    return {'schema':'ouf.retained-hash-metadata-reconciliation-result.v1',
        'status':'METADATA_DIFFERENCES_RECORDED_NOT_ADMITTED','role':ROLE,'scope':str(c.scope),
        'candidateHash':digest(record),'failedResultHash':FAILED_HASH,'comparedNodes':compared,
        'changedNodes':len(public),'differences':public[:PROFILE['maximumPublicDifferences']],
        'differencesTruncated':len(public)>PROFILE['maximumPublicDifferences'],'counts':{'metadataReads':c.counts['metadataReads'],
            'metadataBytes':c.counts['bytes'],'metadataNodes':c.counts['reconciliationNodes'],
            'engineGets':0,'mountedFileContentBytesRead':0},'cumulativeDirectEngineGets':22,
        'currentContainerConfigurationFreshlyObserved':False,'currentDiffIsNotHistoricalFailureTrace':True,
        'allPriorScopesPreserved':True,'hashPreparationRearmed':False,'privatePathsNamesOrValuesPrinted':False,
        'permissionOrContentPolicyEstablished':False,'automaticReplayAllowed':False,
        'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'releaseAcceptance':False}


def main():
    c=None
    try:
        c=Reconciliation(OUTPUT);result=collect(c);c.put('result.json',result);code=0
    except Exception as error:
        reason=str(error) if type(error) is Stop and re.fullmatch('[A-Z0-9_]{1,128}',str(error)) else 'HASH_METADATA_RECONCILIATION_UNPROVEN'
        result={'schema':'ouf.retained-hash-metadata-reconciliation-result.v1','status':'STOP_RECONCILE',
            'reasonCode':reason,'scopeConsumed':os.path.lexists(OUTPUT),'automaticReplayAllowed':False,
            'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'hashPreparationRearmed':False}
        if c is not None:
            try:c.put('result.json',result)
            except Exception:pass
        code=1
    print(json.dumps(result,sort_keys=True));return code

if __name__=='__main__':raise SystemExit(main())
