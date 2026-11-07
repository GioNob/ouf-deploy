"""Current host-file byte continuity for one accepted static candidate.

No output scope or Engine call. The same typed metadata/runtime owners bind
process and declaration provenance. Live members and expected permission/content
policy remain independent, unproven obligations; no positive callback accepted.
"""
import copy, os, stat
from pathlib import Path
from .custody_capture import attrs, decode, digest, process_pin, require
from .current_retained_mounts import CurrentRetainedMountMetadata,MetadataObservation,BOOT_PATH
from .retained_readonly_hashes import ReadonlyHashPreparation,history_frames
from .retained_static_custody import CASE,PROFILE
from .retained_static_intake import CANDIDATE,CANDIDATE_HASH,RESULT_HASH,validate_static
from . import retained_mount_lifecycle as lifecycle
from .node_owner import ObservationBudget
from tools.semantic_registry_operational_owner.guard import protected_file


class StaticObservation(MetadataObservation):
    hash_file=ReadonlyHashPreparation.hash_file
    reject_mutable_overlap=ReadonlyHashPreparation.reject_mutable_overlap
    def __init__(self,budget):
        super().__init__(budget);self.hashes={};self.mutable_sources=[]
        self.counts.update(readonlyRegularFilesHashed=0,readonlyFileBytesHashed=0)


class CurrentRetainedStaticBytes:
    def __init__(self,mounts):
        require(type(mounts) is CurrentRetainedMountMetadata,'ACTUAL_RETAINED_METADATA_OWNER_FOR_STATIC_BYTES_REQUIRED')
        self.mounts=mounts;self.runtime=mounts.runtime;self.ids=(id(mounts),id(self.runtime))
        self.path=Path(CANDIDATE);self.case=copy.deepcopy(CASE)
        self.bindings={'candidateHash':CANDIDATE_HASH,'resultHash':RESULT_HASH}
        self.reference_hash=digest({'path':str(self.path),'case':self.case,**self.bindings})
        self.guard()

    def guard(self):
        require(type(self.mounts) is CurrentRetainedMountMetadata
            and self.ids==(id(self.mounts),id(self.runtime)) and self.mounts.runtime is self.runtime
            and self.reference_hash==digest({'path':str(self.path),'case':self.case,**self.bindings}),
            'SAME_RETAINED_METADATA_RUNTIME_AND_STATIC_CANDIDATE_REFERENCE_REQUIRED')
        return self.mounts.guard()

    def material(self,budget):
        capture,seed,pins=self.mounts.material(budget)
        frames=history_frames(self.path.parent,('capture.claim.json','static-custody.claim.json','static-custody.private.json','result.json'))
        def read(path,maximum):
            budget.check();before=attrs(path.lstat())
            require(before[3:6]==[0,0,1] and stat.S_IMODE(before[2])==0o600,
                'ROOT_PRIVATE_SINGLE_LINK_STATIC_INPUT_REQUIRED')
            value=decode(protected_file(path,maximum,modes=(0o600,)))
            require(attrs(path.lstat())==before,'STATIC_INPUT_CHANGED_DURING_READ')
            pins[str(path)]=before;return value
        record=read(self.path,8388608);result=read(self.path.parent/'result.json',16384)
        claim=read(self.path.parent/'static-custody.claim.json',16384)
        require(claim=={'schema':'ouf.retained-static-custody-claim.v1','caseHash':digest(self.case),
            'lifecycleContractHash':lifecycle.CONTRACT_HASH,'profile':PROFILE,'automaticReplayAllowed':False},
            'EXACT_ACCEPTED_STATIC_INPUT_SOURCE_CLAIM_REQUIRED')
        classes,files=validate_static(record,result,capture,candidate_hash=self.bindings['candidateHash'],
            result_hash=self.bindings['resultHash'],case=self.case)
        return capture,seed,classes,files,{**frames,**pins}

    def observe(self):
        budget=ObservationBudget(90);held=self.guard();capture,seed,classes,files,seals=self.material(budget)
        c=StaticObservation(budget);peers=capture['peers']
        def roots():
            budget.check();self.guard()
            require(BOOT_PATH.read_text().strip()==seed['bootId']
                and all(process_pin(v['pid'])==v for v in seed['rootProcessPins'].values())
                and all(process_pin(v['processPin']['pid'])==v['processPin'] for v in peers.values()),
                'CURRENT_STATIC_BYTES_BOOT_ROOT_OR_RETAINED_PROCESS_CHANGED')
        roots();c.mutable_sources=lifecycle.excluded_sources(peers,classes)
        for path,row in sorted(files.items()):c.reject_mutable_overlap(Path(path),row['metadata'])
        for role,peer in sorted(peers.items()):lifecycle.observe_mounts(c,role,peer['mounts'])
        for path,row in sorted(files.items()):
            roots();c.hash_file(Path(path),row['metadata'])
            require(c.hashes[path]==row,'CURRENT_STATIC_FILE_BYTES_DIFFER_FROM_ACCEPTED_CANDIDATE')
        for path,(before,static) in c.observed.items():
            fd=c.node(path)
            try:require((attrs(os.fstat(fd))==before if static else attrs(os.fstat(fd))[:5]==before[:5]),
                'CURRENT_STATIC_FILE_OR_LIVE_ROOT_CUSTODY_CHANGED_DURING_READ')
            finally:os.close(fd)
        roots();require(c.counts['engineGets']==0 and c.hashes==files
            and all(attrs(Path(p).lstat())==v for p,v in seals.items()),
            'CURRENT_STATIC_INPUT_OR_CLOSED_FILE_SET_CHANGED_DURING_READ')
        self.runtime.selected.held(held);budget.check()
        return {'schema':'ouf.discovery-current-retained-static-bytes.v1',
            'nativeRuntimeInputsHash':self.runtime.input_hash,'heldHistoryHash':digest(held),
            'candidateHash':self.bindings['candidateHash'],'captureResultHash':self.bindings['resultHash'],
            'metadataCandidateHash':self.case['candidateHash'],'lifecycleContractHash':lifecycle.CONTRACT_HASH,
            'lifecyclePlanHash':digest(classes),'staticInputPinsHash':digest(seals),
            'currentStaticFileBytesMatchCapturedCandidate':True,'staticFileCount':len(files),
            'staticFileBytesRead':c.counts['readonlyFileBytesHashed'],'directEngineGets':0,
            'liveTokenAndOperationalStoreContentBytesRead':0,'liveMembersObservedOrAdmitted':False,
            'rawValuesOrIndividualFileHashesPrinted':False,'newCaptureScopeCreated':False,
            'underlyingOwnerGuardReadsCountedHere':False,'expectedPermissionOrContentPolicyEstablished':False,
            'completePrivateCustodyProven':False,'fullCohortProven':False,
            'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'releaseAcceptance':False}
