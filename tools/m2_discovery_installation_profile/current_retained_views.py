"""Effective per-process mount views for the accepted retained declarations.

Kernel mountinfo/fdinfo and O_PATH only. No setns, command, mount syscall,
Engine, directory enumeration or mounted-file content in this observer. Host
file continuity and live-owner/token admission remain separate typed owners.
"""
import copy,hashlib,os,re,stat
from pathlib import Path
from .custody_capture import attrs,decode,digest,process_pin,require
from .current_retained_static import CurrentRetainedStaticBytes,StaticObservation,BOOT_PATH
from .retained_mount_lifecycle import LIVE,CONTRACT_HASH
from .node_owner import ObservationBudget
from .retained_view_intake import (validate_views,CANDIDATE as VIEW_CANDIDATE,
    CANDIDATE_HASH as VIEW_CANDIDATE_HASH,RESULT_HASH as VIEW_RESULT_HASH,CASE as VIEW_CASE)
from .retained_view_capture import PROFILE as VIEW_PROFILE
from .retained_live_metadata import observe_live_leaf
from .retained_readonly_hashes import history_frames
from tools.semantic_registry_operational_owner.guard import protected_file

from .retained_view_primitives import (KERNEL_CONTRACT,LIMITS,canonical,unescape,
    parse_mountinfo,select_mount,kernel_read,fd_mount_id,view_node)


class CurrentRetainedMountViews:
    def __init__(self,static_bytes):
        require(type(static_bytes) is CurrentRetainedStaticBytes,'ACTUAL_STATIC_BYTES_OWNER_FOR_EFFECTIVE_VIEWS_REQUIRED')
        self.static_bytes=static_bytes;self.runtime=static_bytes.runtime
        self.view_path=Path(VIEW_CANDIDATE);self.view_case=copy.deepcopy(VIEW_CASE)
        self.view_bindings={'candidateHash':VIEW_CANDIDATE_HASH,'resultHash':VIEW_RESULT_HASH}
        self.reference_hash=digest({'path':str(self.view_path),'case':self.view_case,**self.view_bindings})
        self.ids=(id(static_bytes),id(self.runtime));self.guard()

    def guard(self):
        require(type(self.static_bytes) is CurrentRetainedStaticBytes
            and self.ids==(id(self.static_bytes),id(self.runtime)) and self.static_bytes.runtime is self.runtime
            and self.reference_hash==digest({'path':str(self.view_path),'case':self.view_case,**self.view_bindings})
            and self.view_case['staticCandidatePath']==str(self.static_bytes.path)
            and self.view_case['staticCandidateHash']==self.static_bytes.bindings['candidateHash']
            and self.view_case['staticResultHash']==self.static_bytes.bindings['resultHash'],
            'SAME_CURRENT_STATIC_BYTES_AND_EFFECTIVE_VIEW_RUNTIME_REQUIRED')
        return self.static_bytes.guard()

    def material(self,budget):
        capture,seed,classes,files,seals=self.static_bytes.material(budget)
        seals.update(history_frames(self.view_path.parent,('capture.claim.json','effective-view.claim.json','effective-views.private.json','result.json')))
        def read(path,maximum):
            budget.check();before=attrs(path.lstat());value=decode(protected_file(path,maximum,modes=(0o600,)))
            require(before[3:6]==[0,0,1] and stat.S_IMODE(before[2])==0o600 and attrs(path.lstat())==before,
                'ROOT_PRIVATE_STABLE_EFFECTIVE_VIEW_INPUT_REQUIRED')
            seals[str(path)]=before;return value
        record=read(self.view_path,8388608);result=read(self.view_path.parent/'result.json',16384)
        claim=read(self.view_path.parent/'effective-view.claim.json',16384)
        require(claim=={'schema':'ouf.retained-effective-view-capture-claim.v1','caseHash':digest(self.view_case),
            'profile':VIEW_PROFILE,'automaticReplayAllowed':False},'EXACT_ACCEPTED_KERNEL_VIEW_CAPTURE_CLAIM_REQUIRED')
        accepted,baseline=validate_views(record,result,capture,candidate_hash=self.view_bindings['candidateHash'],
            result_hash=self.view_bindings['resultHash'],case=self.view_case)
        require(classes==accepted,'SAME_STATIC_AND_KERNEL_VIEW_LIFECYCLE_PLAN_REQUIRED')
        return capture,seed,classes,files,seals,baseline

    def observe(self):
        budget=ObservationBudget(LIMITS['maximumSeconds']);held=self.guard()
        capture,seed,classes,_,seals,baseline=self.material(budget);c=StaticObservation(budget)
        peers=capture['peers'];proofs={};readonly=0;writable=0;live=0;tables={};sources={}
        def roots():
            self.guard();budget.check()
            require(BOOT_PATH.read_text().strip()==seed['bootId']
                and all(process_pin(p['pid'])==p for p in seed['rootProcessPins'].values())
                and all(process_pin(p['processPin']['pid'])==p['processPin'] for p in peers.values()),
                'EFFECTIVE_VIEW_BOOT_ROOT_OR_RETAINED_GENERATION_CHANGED')
        roots()
        for role,peer in sorted(peers.items()):
            roots();pid=peer['processPin']['pid'];proc_root='/proc/'+str(pid)+'/root'
            mountinfo='/proc/'+str(pid)+'/mountinfo';before=kernel_read(mountinfo,LIMITS['maximumMountinfoBytes'],budget)
            tables[mountinfo]=before
            rows=parse_mountinfo(before);root=os.open(proc_root,os.O_PATH|os.O_DIRECTORY)
            root_frame=attrs(os.fstat(root))[:5];members=[]
            try:
                require(root_frame==baseline[role]['rootMetadata'],'SAME_CAPTURED_EFFECTIVE_PROCESS_ROOT_REQUIRED')
                for mount,kind,prior in zip(peer['mounts'],classes[role],baseline[role]['mounts']):
                    roots();selected=select_mount(rows,mount['destination'],mount['readOnly'])
                    require(kind in LIVE|{'STATIC_CAPTURE_CANDIDATE','MUTABLE_CONTENT_NOT_OBSERVED'},
                        'EXACT_CAPTURED_STATIC_LIVE_OR_WRITABLE_VIEW_REQUIRED')
                    expected=(mount['metadataTree']['metadata'] if kind in LIVE|{'STATIC_CAPTURE_CANDIDATE'} else mount['metadata'])
                    static=kind=='STATIC_CAPTURE_CANDIDATE';frame=expected if static else expected[:5]
                    source=c.node(Path(mount['source']));view=None;again=None
                    try:
                        view=view_node(root,mount['destination'])
                        host=attrs(os.fstat(source));inside=attrs(os.fstat(view))
                        require((host==inside==frame if static else host[:5]==inside[:5]==frame)
                            and fd_mount_id(view,budget)==selected['mountId']==prior['effectiveMountId'],
                            'EFFECTIVE_MOUNT_VIEW_SOURCE_IDENTITY_OR_ACCESS_CHANGED')
                        leaf=None
                        if kind in LIVE:
                            leaf=observe_live_leaf(c,view,mount,kind,prior['liveLeafMetadata'],selected['mountId'],budget);live+=1
                        again=view_node(root,mount['destination'])
                        final=attrs(os.fstat(again))
                        require((final==inside if static else final[:5]==inside[:5])
                            and fd_mount_id(again,budget)==selected['mountId'],
                            'EFFECTIVE_MOUNT_NAMED_VIEW_CHANGED_DURING_READ')
                        members.append({'mountHash':mount['mountHash'],'lifecycleClass':kind,
                            'mountId':selected['mountId'],'readOnly':selected['readOnly'],'sourceAndViewMetadata':frame,
                            'liveLeafCustodyMetadata':leaf})
                        sources[mount['source']]=(frame,static)
                        readonly+=int(mount['readOnly']);writable+=int(not mount['readOnly'])
                    finally:
                        if again is not None:os.close(again)
                        if view is not None:os.close(view)
                        os.close(source)
                require(kernel_read(mountinfo,LIMITS['maximumMountinfoBytes'],budget)==before,
                    'EFFECTIVE_KERNEL_MOUNT_TABLE_CHANGED_DURING_READ')
                fresh=os.open(proc_root,os.O_PATH|os.O_DIRECTORY)
                try:require(attrs(os.fstat(fresh))[:5]==attrs(os.fstat(root))[:5]==root_frame,
                    'EFFECTIVE_PROCESS_ROOT_CHANGED_DURING_READ')
                finally:os.close(fresh)
                proofs[role]=digest({'processPin':peer['processPin'],'root':root_frame,
                    'mountinfoHash':hashlib.sha256(before).hexdigest(),'members':members})
            finally:os.close(root)
        for path,(before,static) in sources.items():
            fd=c.node(Path(path))
            try:require((attrs(os.fstat(fd))==before if static else attrs(os.fstat(fd))[:5]==before),
                'EFFECTIVE_VIEW_HOST_SOURCE_CHANGED_DURING_INTERVAL')
            finally:os.close(fd)
        require(all(kernel_read(path,LIMITS['maximumMountinfoBytes'],budget)==raw for path,raw in tables.items()),
            'EFFECTIVE_KERNEL_MOUNT_TABLE_CHANGED_DURING_INTERVAL')
        roots();require(readonly==25 and writable==4 and live==8 and c.counts['engineGets']==0
            and all(attrs(Path(p).lstat())==v for p,v in seals.items()),
            'EXACT_EFFECTIVE_VIEW_SET_AND_UNCHANGED_PRIVATE_INPUTS_REQUIRED')
        self.runtime.selected.held(held);budget.check()
        return {'schema':'ouf.discovery-current-retained-mount-views.v2',
            'nativeRuntimeInputsHash':self.runtime.input_hash,'heldHistoryHash':digest(held),
            'staticCandidateHash':self.static_bytes.bindings['candidateHash'],'lifecycleContractHash':CONTRACT_HASH,
            'viewCandidateHash':self.view_bindings['candidateHash'],'viewResultHash':self.view_bindings['resultHash'],
            'effectiveViewsHash':digest(proofs),'currentMountDeclarationsMatchEffectiveViews':True,
            'currentLiveLeafCustodyMatchesCapturedMetadata':True,'liveLeafMetadataNodes':live,
            'readonlyMounts':readonly,'writableMounts':writable,'retainedProcessCount':10,
            'directEngineGets':0,'mountedFileContentBytesRead':0,'liveOwnerAuthenticated':False,
            'liveDirectoryMembershipObserved':False,
            'newCaptureScopeCreated':False,'privatePathsOrValuesPrinted':False,
            'expectedPermissionOrContentPolicyEstablished':False,'completePrivateCustodyProven':False,
            'fullCohortProven':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'releaseAcceptance':False}
