"""One private effective-view/live-metadata input after static success.

Zero Engine, mounted-file content, SQL, IAM, commands or lifecycle. All five
predecessor scopes remain consumed. Current metadata are candidates, never
expected policy or authenticated live owner credentials.
"""
import copy,hashlib,json,os,re,stat
from pathlib import Path
from .custody_capture import attrs,decode,digest,encoded,process_pin,require,Stop
from .retained_mount_capture import RetainedCapture
from .retained_mount_intake import validate_capture
from .retained_static_intake import validate_static,CANDIDATE,CANDIDATE_HASH,RESULT_HASH
from . import retained_static_custody as previous
from . import retained_readonly_hashes as original_hash
from . import retained_view_primitives as kernel
from . import retained_mount_lifecycle as lifecycle

OUTPUT=Path('/etc/ouf/deploy-snapshots/m2-retained-kernel-views-de4546d0-20261101-v1')
CASE={**copy.deepcopy(previous.CASE),'staticCandidatePath':str(CANDIDATE),
    'staticCandidateHash':CANDIDATE_HASH,'staticResultHash':RESULT_HASH}
ROSTER=copy.deepcopy(previous.ROSTER)
BOOT_PATH=Path('/proc/sys/kernel/random/boot_id')
PROFILE={'schema':'ouf.retained-effective-view-capture-profile.v1','maximumAttempts':1,'maximumSeconds':90,
    'maximumKernelMetadataBytes':16777216,'maximumKernelReads':128,'maximumPrivateOutputBytes':8388608,
    'maximumEngineGets':0,'maximumMountedFileContentBytesRead':0,'priorControlAttempts':5,
    'cumulativeControlAttempts':6,'cumulativeDirectEngineGets':22,'automaticReplayAllowed':False,
    'oldScopesRearmedOrReset':False,'runtimeBudgetResetOrGrant':False}


class ViewCapture(RetainedCapture):
    def __init__(self,scope):
        super().__init__(scope);self.counts.update(kernelReads=0,kernelMetadataBytes=0,effectiveReadonlyMounts=0,
            effectiveWritableMounts=0,liveLeafMetadataNodes=0,liveCustodyContinuityDifferences=0)
        self.put('effective-view.claim.json',{'schema':'ouf.retained-effective-view-capture-claim.v1',
            'caseHash':digest(CASE),'profile':PROFILE,'automaticReplayAllowed':False})

    def kernel_read(self,path,maximum):
        self.guarded();require(self.counts['kernelReads']<PROFILE['maximumKernelReads'],'BOUNDED_KERNEL_METADATA_READ_SET_REQUIRED')
        self.counts['kernelReads']+=1;raw=kernel.kernel_read(path,maximum,self)
        self.counts['kernelMetadataBytes']+=len(raw)
        require(self.counts['kernelMetadataBytes']<=PROFILE['maximumKernelMetadataBytes'],'BOUNDED_KERNEL_METADATA_BYTES_REQUIRED')
        return raw

    def mount_id(self,fd):
        raw=self.kernel_read('/proc/self/fdinfo/'+str(fd),kernel.LIMITS['maximumFdinfoBytes'])
        rows=[r.split(':',1)[1].strip() for r in raw.decode('ascii').splitlines() if r.startswith('mnt_id:')]
        require(len(rows)==1 and rows[0].isdigit() and int(rows[0])>0,'EXACT_CAPTURED_EFFECTIVE_DESCRIPTOR_MOUNT_ID_REQUIRED')
        return int(rows[0])


def collect(c):
    case_hash=digest(CASE);static_root=Path(CASE['staticCandidatePath']).parent
    scopes={CASE['failedScope']:('capture.claim.json','result.json'),
        str(Path(CASE['candidatePath']).parent):('capture.claim.json','predecessor-reconciliation.json','retained-mounts.private.json','result.json'),
        CASE['failedHashScope']:('capture.claim.json','readonly-hash-preparation.claim.json','result.json'),
        CASE['reconciliationScope']:('capture.claim.json','reconciliation.claim.json','reconciliation.private.json','result.json'),
        str(static_root):('capture.claim.json','static-custody.claim.json','static-custody.private.json','result.json')}
    seals={}
    for root,names in scopes.items():seals.update(original_hash.history_frames(root,names))
    def read(path,maximum):return decode(c.read(Path(path),0,0,0o600,maximum,'metadataReads'))
    capture=read(CASE['candidatePath'],8388608);receipt=read(CASE['resultPath'],16384);seed=read(CASE['seedPath'],2097152)
    validate_capture(capture,receipt,seed,candidate_hash=CASE['candidateHash'],result_hash=CASE['resultHash'],
        seed_hash=CASE['seedHash'],roster=ROSTER)
    record=read(CASE['staticCandidatePath'],8388608);result=read(static_root/'result.json',16384)
    prior_case={k:v for k,v in CASE.items() if k not in ('staticCandidatePath','staticCandidateHash','staticResultHash')}
    claim=read(static_root/'static-custody.claim.json',16384)
    require(claim=={'schema':'ouf.retained-static-custody-claim.v1','caseHash':digest(prior_case),
        'lifecycleContractHash':lifecycle.CONTRACT_HASH,'profile':previous.PROFILE,'automaticReplayAllowed':False},
        'EXACT_CONSUMED_STATIC_PREPARATION_CLAIM_REQUIRED')
    classes,_=validate_static(record,result,capture,candidate_hash=CASE['staticCandidateHash'],
        result_hash=CASE['staticResultHash'],case=prior_case)
    peers=capture['peers'];tables={};sources={};proofs={}
    def roots():
        c.guarded();require(digest(CASE)==case_hash and BOOT_PATH.read_text().strip()==seed['bootId']
            and all(process_pin(p['pid'])==p for p in seed['rootProcessPins'].values())
            and all(process_pin(p['processPin']['pid'])==p['processPin'] for p in peers.values()),
            'EFFECTIVE_CAPTURE_BOOT_ROOT_RETAINED_PROCESS_OR_CASE_CHANGED')
    roots()
    for role,peer in sorted(peers.items()):
        roots();pid=peer['processPin']['pid'];proc_root='/proc/'+str(pid)+'/root';info='/proc/'+str(pid)+'/mountinfo'
        before=c.kernel_read(info,kernel.LIMITS['maximumMountinfoBytes']);tables[info]=before
        rows=kernel.parse_mountinfo(before);root=os.open(proc_root,os.O_PATH|os.O_DIRECTORY);members=[]
        try:
            root_frame=attrs(os.fstat(root))[:5]
            for mount,kind in zip(peer['mounts'],classes[role]):
                roots();selected=kernel.select_mount(rows,mount['destination'],mount['readOnly'])
                expected=(mount['metadataTree']['metadata'] if kind in lifecycle.LIVE|{'STATIC_CAPTURE_CANDIDATE'} else mount['metadata'])
                static=kind=='STATIC_CAPTURE_CANDIDATE';frame=expected if static else expected[:5]
                host=c.node(Path(mount['source']));view=None;again=None
                try:
                    view=kernel.view_node(root,mount['destination']);a=attrs(os.fstat(host));b=attrs(os.fstat(view))
                    require((a==b==frame if static else a[:5]==b[:5]==frame)
                        and c.mount_id(view)==selected['mountId'],'EFFECTIVE_CAPTURE_SOURCE_VIEW_OR_ACCESS_DIFFERS')
                    member={'mount':mount,'lifecycleClass':kind,'effectiveMountId':selected['mountId'],
                        'readOnly':selected['readOnly'],'sourceAndViewMetadata':frame,'liveLeafMetadata':None}
                    if kind in lifecycle.LIVE:
                        name='token' if kind=='RENEWABLE_TOKEN_OWNER_INPUT' else 'gateway-operations.sqlite'
                        old=mount['metadataTree']['children'][name]['metadata']
                        source=c.node(Path(mount['source'])/name);target=None;current=None
                        try:
                            target=kernel.view_node(view,'/'+name);a=attrs(os.fstat(source));b=attrs(os.fstat(target))
                            require(stat.S_ISREG(a[2]) and a[5]==1 and stat.S_ISREG(b[2]) and b[5]==1,
                                'SINGLE_LINK_REGULAR_LIVE_LEAF_METADATA_REQUIRED')
                            token=kind=='RENEWABLE_TOKEN_OWNER_INPUT'
                            require((a==b and 0<a[6]<=16384 if token else a[:6]==b[:6]),
                                'LIVE_LEAF_SOURCE_AND_EFFECTIVE_VIEW_NOT_STABLE')
                            current=kernel.view_node(view,'/'+name);after=attrs(os.fstat(current))
                            require((after==attrs(os.fstat(source))==a if token else after[:6]==attrs(os.fstat(source))[:6]==a[:6])
                                and c.mount_id(target)==c.mount_id(current)==selected['mountId'],
                                'LIVE_LEAF_ROTATED_OR_REBOUND_DURING_METADATA_READ')
                            fields=(0,2,3,4,5) if token else tuple(range(6))
                            same=all(a[i]==old[i] for i in fields)
                            member['liveLeafMetadata']={'name':name,'captured':old,'currentSource':a,
                                'currentEffectiveView':b,'custodyFieldsMatchCapture':same,'contentObserved':False,
                                'expectedPolicyEstablished':False,'ownerAuthenticated':False}
                            c.counts['liveLeafMetadataNodes']+=1
                            c.counts['liveCustodyContinuityDifferences']+=int(not same)
                        finally:
                            if current is not None:os.close(current)
                            if target is not None:os.close(target)
                            os.close(source)
                    again=kernel.view_node(root,mount['destination']);final=attrs(os.fstat(again))
                    require((final==frame if static else final[:5]==frame) and c.mount_id(again)==selected['mountId'],
                        'EFFECTIVE_CAPTURE_NAMED_MOUNT_CHANGED_DURING_READ')
                    members.append(member);sources[mount['source']]=(frame,static)
                    c.counts['effectiveReadonlyMounts' if mount['readOnly'] else 'effectiveWritableMounts']+=1
                finally:
                    if again is not None:os.close(again)
                    if view is not None:os.close(view)
                    os.close(host)
            fresh=os.open(proc_root,os.O_PATH|os.O_DIRECTORY)
            try:require(attrs(os.fstat(root))[:5]==attrs(os.fstat(fresh))[:5]==root_frame,'EFFECTIVE_CAPTURE_PROCESS_ROOT_CHANGED')
            finally:os.close(fresh)
            require(c.kernel_read(info,kernel.LIMITS['maximumMountinfoBytes'])==before,'EFFECTIVE_CAPTURE_KERNEL_TABLE_CHANGED')
            proofs[role]={'processPin':peer['processPin'],'rootMetadata':root_frame,
                'mountinfoSha256':hashlib.sha256(before).hexdigest(),'mounts':members}
        finally:os.close(root)
    for path,(frame,static) in sources.items():
        fd=c.node(Path(path))
        try:require((attrs(os.fstat(fd))==frame if static else attrs(os.fstat(fd))[:5]==frame),
            'EFFECTIVE_CAPTURE_SOURCE_CHANGED_DURING_INTERVAL')
        finally:os.close(fd)
    require(all(c.kernel_read(path,kernel.LIMITS['maximumMountinfoBytes'])==raw for path,raw in tables.items()),
        'EFFECTIVE_CAPTURE_KERNEL_TABLE_CHANGED_DURING_INTERVAL')
    roots();require(c.counts['engineGets']==c.counts['mountFileContentBytesRead']==0
        and c.counts['effectiveReadonlyMounts']==25 and c.counts['effectiveWritableMounts']==4
        and c.counts['liveLeafMetadataNodes']==8
        and all(attrs(Path(path).lstat())==v for path,v in {**seals,**c.seals}.items()),
        'EXACT_EFFECTIVE_CAPTURE_SET_ZERO_CONTENT_AND_PRESERVED_HISTORY_REQUIRED')
    private={'schema':'ouf.retained-effective-view-candidates.v1','caseHash':case_hash,'profile':PROFILE,
        'staticCandidateHash':CASE['staticCandidateHash'],'metadataCandidateHash':CASE['candidateHash'],
        'lifecycleContractHash':lifecycle.CONTRACT_HASH,'bootId':seed['bootId'],'peers':proofs,
        'currentContainerConfigurationFreshlyObserved':False,'mountedFileContentsObserved':False,
        'liveOwnerAuthenticated':False,'expectedPermissionOrContentPolicyEstablished':False,
        'completePrivateCustodyProven':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'releaseAcceptance':False}
    require(len(encoded(private))<=PROFILE['maximumPrivateOutputBytes'],'BOUNDED_PRIVATE_EFFECTIVE_VIEW_CANDIDATE_REQUIRED')
    c.put('effective-views.private.json',private)
    return {'schema':'ouf.retained-effective-view-capture-result.v1','status':'EFFECTIVE_VIEWS_AND_LIVE_METADATA_CAPTURED_NOT_ADMITTED',
        'scope':str(c.scope),'candidateHash':digest(private),'staticCandidateHash':CASE['staticCandidateHash'],
        'counts':{k:c.counts[k] for k in ('metadataReads','bytes','engineGets','kernelReads','kernelMetadataBytes',
            'effectiveReadonlyMounts','effectiveWritableMounts','liveLeafMetadataNodes','liveCustodyContinuityDifferences','mountFileContentBytesRead')},
        'retainedProcesses':10,'allFivePriorScopesPreserved':True,'cumulativeControlAttempts':6,'cumulativeDirectEngineGets':22,
        'currentContainerConfigurationFreshlyObserved':False,'staticContentsRehashed':False,
        'liveOwnerAuthenticated':False,'expectedPermissionOrContentPolicyEstablished':False,'completePrivateCustodyProven':False,
        'privatePathsNamesValuesOrIndividualHashesPrinted':False,'automaticReplayAllowed':False,'runtimeBudgetResetOrGrant':False,
        'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'releaseAcceptance':False}


def main():
    c=None
    try:
        c=ViewCapture(OUTPUT);result=collect(c);c.put('result.json',result);code=0
    except Exception as error:
        reason=str(error) if type(error) is Stop and re.fullmatch('[A-Z0-9_]{1,128}',str(error)) else 'RETAINED_EFFECTIVE_VIEW_CAPTURE_UNPROVEN'
        result={'schema':'ouf.retained-effective-view-capture-result.v1','status':'STOP_RECONCILE','reasonCode':reason,
            'scopeConsumed':os.path.lexists(OUTPUT),'counts':dict(c.counts) if c is not None else {},
            'automaticReplayAllowed':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False}
        if c is not None:
            try:c.put('result.json',result)
            except Exception:pass
        code=1
    print(json.dumps(result,sort_keys=True));return code

if __name__=='__main__':raise SystemExit(main())
