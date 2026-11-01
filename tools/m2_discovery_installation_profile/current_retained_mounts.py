"""Current metadata equality against the one successful retained capture.

Read-only witness: no new scope/claim/output, mounted-file contents, policy
inference or runtime authority. The complete parent-bound runtime remains the
actual owner. An accepted capture is input provenance, never independent policy.
"""
import copy, os, stat
from pathlib import Path
from .custody_capture import Capture, attrs, decode, digest, process_pin, require
from .retained_mount_capture import RetainedCapture, RetainedEngine, SEED, RETAINED, identity
from .retained_mount_role_correction import ROSTER
from .retained_mount_intake import CANDIDATE, CANDIDATE_HASH, RESULT_HASH, SEED_HASH, validate_capture
from .current_cohort import CurrentCohortRuntime
from .node_owner import ObservationBudget
from tools.semantic_registry_operational_owner.guard import protected_file
from engine_creation import Engine

BOOT_PATH=Path('/proc/sys/kernel/random/boot_id')


class MetadataObservation:
    # Reuse the qualified no-follow/O_PATH scanner without the create-only
    # Capture constructor or its put method. Observation never creates files.
    node=RetainedCapture.node
    metadata_tree=RetainedCapture.metadata_tree
    mounts=RetainedCapture.mounts
    ancestors=staticmethod(Capture.ancestors)
    def __init__(self,budget):
        self.budget=budget;self.until=budget.until;self.observed={}
        self.counts=dict.fromkeys(('engineGets','engineBytes','staticEntries','mountFileContentBytesRead',
            'readonlyMounts','mutableMounts','ephemeralMounts','specialSources'),0)
    def guarded(self):self.budget.check()


def metadata_binding(rows):
    result=copy.deepcopy(rows)
    for row in result:
        # Mutable content/size/times/link count are not immutable custody policy.
        # Keep device/inode/type+mode/uid/gid exactly as the original scanner.
        if row['kind']=='MUTABLE_CONTENT_NOT_OBSERVED':row['metadata']=row['metadata'][:5]
    return result


class CurrentRetainedMountMetadata:
    def __init__(self,runtime):
        require(type(runtime) is CurrentCohortRuntime,'ACTUAL_CURRENT_RUNTIME_FOR_RETAINED_MOUNT_METADATA_REQUIRED')
        self.runtime=runtime;self.runtime_id=id(runtime);self.runtime_hash=runtime.input_hash
        self.candidate_path=Path(CANDIDATE);self.seed_path=Path(SEED)
        self.bindings={'candidate_hash':CANDIDATE_HASH,'result_hash':RESULT_HASH,
            'seed_hash':SEED_HASH,'roster':copy.deepcopy(ROSTER)}
        self.reference_hash=digest({'candidatePath':str(self.candidate_path),'seedPath':str(self.seed_path),**self.bindings})
        self.guard()

    def guard(self):
        r=self.runtime
        require(type(r) is CurrentCohortRuntime and id(r)==self.runtime_id and r.input_hash==self.runtime_hash
            and self.reference_hash==digest({'candidatePath':str(self.candidate_path),
                'seedPath':str(self.seed_path),**self.bindings}),
            'SAME_CURRENT_RUNTIME_AND_EXACT_RETAINED_CAPTURE_REFERENCE_REQUIRED')
        r.guard();return r.selected.held()

    def material(self,budget):
        pins={}
        def read(path,maximum):
            budget.check();before=attrs(path.lstat())
            require(before[3:6]==[0,0,1] and stat.S_IMODE(before[2])==0o600,
                'ROOT_PRIVATE_SINGLE_LINK_RETAINED_INPUT_REQUIRED')
            value=decode(protected_file(path,maximum,modes=(0o600,)))
            require(attrs(path.lstat())==before,'RETAINED_METADATA_INPUT_CHANGED_DURING_READ')
            pins[str(path)]=before;return value
        candidate=read(self.candidate_path,8388608)
        result=read(self.candidate_path.parent/'result.json',16384)
        seed=read(self.seed_path,2097152)
        mapping=validate_capture(candidate,result,seed,**self.bindings)
        r=self.runtime.inputs
        require(r['bootId']==seed['bootId'] and r['rootProcessPins']==seed['rootProcessPins']
            and r['engineBinding']=={**seed['engineBinding'],'startTicks':seed['rootProcessPins']['engine']['startTicks']}
            and all(r['peers'][role]=={'name':seed['observations'][mapping[role]]['Name'],
                'runtimeBinding':Engine.runtime_binding(seed['observations'][mapping[role]]),
                'processPin':seed['processPins'][mapping[role]]} for role in RETAINED),
            'EXACT_PARENT_RUNTIME_AND_RETAINED_CAPTURE_GENERATIONS_REQUIRED')
        return candidate,seed,pins

    def observe(self):
        budget=ObservationBudget(90);held=self.guard();candidate,seed,seals=self.material(budget)
        c=MetadataObservation(budget);peers=candidate['peers']
        def roots():
            budget.check();self.guard()
            require(BOOT_PATH.read_text().strip()==seed['bootId']
                and all(process_pin(v['pid'])==v for v in seed['rootProcessPins'].values())
                and all(process_pin(v['processPin']['pid'])==v['processPin'] for v in peers.values()),
                'CURRENT_RETAINED_METADATA_BOOT_OR_PROCESS_CHANGED')
        roots();engine=RetainedEngine(c,seed['engineBinding'],[peers[r]['containerId'] for r in sorted(RETAINED)])
        proofs={}
        for role in sorted(RETAINED):
            expected=peers[role];actual=engine.get(expected['containerId']);roots()
            require(digest(identity(actual))==expected['runtimeIdentityHash'],
                'CURRENT_RETAINED_METADATA_CONTAINER_CONFIGURATION_CHANGED')
            mounts=c.mounts(actual)
            require(metadata_binding(mounts)==metadata_binding(expected['mounts']),
                'CURRENT_RETAINED_MOUNT_METADATA_DIFFERS_FROM_CAPTURE')
            proofs[role]=digest({'identityHash':expected['runtimeIdentityHash'],
                'mountMetadata':metadata_binding(mounts),'processPin':expected['processPin']})
        for role in sorted(RETAINED):
            actual=engine.get(peers[role]['containerId']);roots()
            require(digest(identity(actual))==peers[role]['runtimeIdentityHash'],
                'CURRENT_RETAINED_METADATA_CONFIGURATION_CHANGED_DURING_READ')
        for path,(before,static) in c.observed.items():
            fd=c.node(path)
            try:
                after=attrs(os.fstat(fd))
                require(after==before if static else after[:5]==before[:5],
                    'CURRENT_RETAINED_MOUNT_METADATA_CHANGED_DURING_READ')
            finally:os.close(fd)
        roots();require(c.counts['engineGets']==20 and all(attrs(Path(p).lstat())==v for p,v in seals.items()),
            'RETAINED_METADATA_INPUT_OR_CLOSED_READ_COUNT_CHANGED')
        self.runtime.selected.held(held);budget.check()
        return {'schema':'ouf.discovery-current-retained-mount-metadata.v1',
            'nativeRuntimeInputsHash':self.runtime_hash,'heldHistoryHash':digest(held),
            'candidateHash':self.bindings['candidate_hash'],'captureResultHash':self.bindings['result_hash'],
            'peerMetadataHash':digest(proofs),'captureInputPinsHash':digest(seals),
            'currentRetainedMetadataMatchesCapturedCandidate':True,'retainedPeerCount':10,
            'directRetainedEngineGets':20,
            'counts':{k:v for k,v in c.counts.items() if k!='engineBytes'},
            'underlyingOwnerGuardReadsCountedHere':False,'mountedFileContentBytesRead':0,
            'newCaptureScopeCreated':False,'expectedMountPolicyEstablished':False,
            'mutableContentsObserved':False,'specialProtocolRightsProven':False,
            'completePrivateCustodyProven':False,'fullCohortProven':False,
            'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'releaseAcceptance':False}
