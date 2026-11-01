"""Read the exact consumed archive set with no Engine, host mount or writes.

The private result contains only image byte evidence. Publisher/source trust,
scan admission, expected execution policy and live authority remain separate.
"""
import copy,os,stat
from pathlib import Path
from .custody_capture import Capture,attrs,decode,digest,process_pin,require
from .retained_mount_intake import validate_capture
from .retained_view_intake import validate_views
from .retained_readonly_hashes import history_frames
from .retained_image_intake import (CANDIDATE,CANDIDATE_HASH,RESULT_HASH,CASE,PROFILE,ROSTER,validate_archives)
from .retained_image_identity import VerificationBudget,verified_image,LIMITS

BOOT_PATH=Path('/proc/sys/kernel/random/boot_id')


class RetainedArchiveReader:
    ancestors=staticmethod(Capture.ancestors)
    read=Capture.read
    def __init__(self):
        self.budget=VerificationBudget();self.case=copy.deepcopy(CASE);self.path=Path(CANDIDATE)
        self.bindings={'candidateHash':CANDIDATE_HASH,'resultHash':RESULT_HASH}
        self.reference_hash=digest({'case':self.case,'path':str(self.path),**self.bindings})
        self.counts={'metadataReads':0,'bytes':0};self.seals={}

    def check(self):
        self.budget.check()
        require(self.reference_hash==digest({'case':self.case,'path':str(self.path),**self.bindings}),
            'EXACT_RETAINED_PRIVATE_ARCHIVE_READER_BINDINGS_REQUIRED')

    def metadata(self,path,maximum):
        return decode(self.read(Path(path),0,0,0o600,maximum,'metadataReads'))

    def material(self):
        self.check();case=self.case;root=self.path.parent
        scopes={case['failedScope']:('capture.claim.json','result.json'),
            str(Path(case['candidatePath']).parent):('capture.claim.json','predecessor-reconciliation.json','retained-mounts.private.json','result.json'),
            case['failedHashScope']:('capture.claim.json','readonly-hash-preparation.claim.json','result.json'),
            case['reconciliationScope']:('capture.claim.json','reconciliation.claim.json','reconciliation.private.json','result.json'),
            str(Path(case['staticCandidatePath']).parent):('capture.claim.json','static-custody.claim.json','static-custody.private.json','result.json'),
            str(Path(case['viewCandidatePath']).parent):('capture.claim.json','effective-view.claim.json','effective-views.private.json','result.json')}
        for path,names in scopes.items():self.seals.update(history_frames(path,names))
        capture=self.metadata(case['candidatePath'],8388608)
        receipt=self.metadata(case['resultPath'],16384);seed=self.metadata(case['seedPath'],2097152)
        validate_capture(capture,receipt,seed,candidate_hash=case['candidateHash'],
            result_hash=case['resultHash'],seed_hash=case['seedHash'],roster=ROSTER)
        views=self.metadata(case['viewCandidatePath'],8388608)
        view_receipt=self.metadata(Path(case['viewCandidatePath']).parent/'result.json',16384)
        view_case={k:v for k,v in case.items() if k not in ('viewCandidatePath','viewCandidateHash','viewResultHash')}
        validate_views(views,view_receipt,capture,candidate_hash=case['viewCandidateHash'],
            result_hash=case['viewResultHash'],case=view_case)
        self.ancestors(root/'placeholder');info=root.lstat()
        names={'capture.claim.json','native-image-archive.claim.json','native-image-archives.private.json','result.json'}
        names.update('image-'+role+'.docker.tar' for role in ROSTER)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o700
            and {p.name for p in root.iterdir()}==names,'EXACT_CONSUMED_PRIVATE_ARCHIVE_SCOPE_REQUIRED')
        self.seals[str(root)]=attrs(info)
        require(self.metadata(root/'capture.claim.json',4096)==
            {'schema':'ouf.m2-discovery-custody-capture-claim.v1','automaticReplayAllowed':False},
            'ORIGINAL_PRIVATE_IMAGE_CAPTURE_CLAIM_REQUIRED')
        require(self.metadata(root/'native-image-archive.claim.json',16384)==
            {'schema':'ouf.retained-native-image-archive-claim.v1','caseHash':digest(case),
                'profile':PROFILE,'automaticReplayAllowed':False},'EXACT_CONSUMED_PRIVATE_IMAGE_PROFILE_REQUIRED')
        record=self.metadata(self.path,131072);result=self.metadata(root/'result.json',16384)
        rows=validate_archives(record,result,seed,candidate_hash=self.bindings['candidateHash'],
            result_hash=self.bindings['resultHash'],case=case,roster=ROSTER)
        for row in rows.values():
            path=root/row['filename'];self.ancestors(path)
            require(attrs(path.lstat())==row['metadata'],'CAPTURED_PRIVATE_ARCHIVE_METADATA_CHANGED')
            self.seals[str(path)]=row['metadata']
        return seed,rows

    def roots(self,seed):
        self.check()
        require(BOOT_PATH.read_text().strip()==seed['bootId']
            and set(seed['rootProcessPins'])=={'pid1','engine'} and seed['rootProcessPins']['pid1']['pid']==1
            and seed['rootProcessPins']['engine']['pid']==seed['engineBinding']['peerCredentials'][0]
            and all(process_pin(row['pid'])==row for row in seed['rootProcessPins'].values()),
            'PRIVATE_ARCHIVE_READER_BOOT_OR_ROOT_ENGINE_GENERATION_CHANGED')
        require(all(attrs(Path(path).lstat())==frame for path,frame in self.seals.items()),
            'PRIVATE_ARCHIVE_READER_INPUT_OR_HISTORY_CHANGED')

    def read_set(self):
        seed,rows=self.material();self.roots(seed);proofs={};root=self.path.parent
        for role,row in sorted(rows.items()):
            self.roots(seed);path=root/row['filename']
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            with os.fdopen(fd,'rb') as stream:
                require(attrs(os.fstat(stream.fileno()))==row['metadata'],'SAME_CAPTURED_PRIVATE_ARCHIVE_FD_REQUIRED')
                proofs[role]=verified_image(stream,row['sha256'],row['imageIdRequested'],row['bytes'],self.budget)
                require(attrs(os.fstat(stream.fileno()))==attrs(path.lstat())==row['metadata'],
                    'PRIVATE_ARCHIVE_CHANGED_DURING_BYTE_VERIFICATION')
            self.roots(seed)
        self.check()
        private={'schema':'ouf.retained-image-byte-set.v1','candidateHash':self.bindings['candidateHash'],
            'captureResultHash':self.bindings['resultHash'],'verificationProfile':LIMITS,'images':proofs,
            'sourcePublisherAuthenticated':False,'allRuntimeArtifactMembershipProven':False,
            'expectedPermissionOrContentPolicyEstablished':False,'completePrivateCustodyProven':False,
            'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'releaseAcceptance':False}
        public={'schema':'ouf.retained-image-byte-set-witness.v1','candidateHash':self.bindings['candidateHash'],
            'captureResultHash':self.bindings['resultHash'],'privateByteEvidenceHash':digest(private),
            'imageCount':len(proofs),'archiveBytesVerified':sum(v['bytes'] for v in rows.values()),
            'expandedBytesVerified':self.budget.expanded,'allSevenInputScopesPreserved':True,
            'directEngineGets':0,'mountedHostFileContentBytesRead':0,'sourcePublisherAuthenticated':False,
            'nativeOrClassicImageByteIdentityProven':True,'allRuntimeArtifactMembershipProven':False,
            'currentApplicationConfigurationOrLivenessProven':False,'completePrivateCustodyProven':False,
            'newCaptureScopeCreated':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'releaseAcceptance':False}
        return private,public

    def observe(self):return self.read_set()[1]
