"""Reconcile the exact consumed empty-config STOP using the corrected verifier.

Never repeats the capture, calls Engine or changes any application state.
The new finite scope keeps its claim, private byte proofs and public result.
"""
import json,os,re,sys,time
from pathlib import Path
from .custody_capture import Capture,Stop,attrs,decode,digest,require
from .retained_readonly_hashes import history_frames
from .retained_image_identity import LIMITS
from .retained_image_reader import RetainedArchiveReader
from .retained_image_intake import CANDIDATE_HASH,RESULT_HASH

FAILED_SCOPE=Path('/etc/ouf/deploy-snapshots/m2-image-byte-verification-fa95a719-20261101-v1')
FAILED_RESULT_HASH='d1e98ad391ccc5d339ce853a8b88afc12bcb1eb8737887d5c807321fd68e0955'
OUTPUT=Path('/etc/ouf/deploy-snapshots/m2-image-byte-reconciliation-fa95a719-20261101-v1')
PREDECESSOR_PROFILE={'schema':'ouf.retained-image-byte-verification-control.v1','maximumAttempts':1,
    'maximumSeconds':600,'maximumEngineGets':0,'priorControlAttempts':7,'maximumCumulativeControlAttempts':8,
    'cumulativeDirectEngineGets':35,'automaticReplayAllowed':False,'runtimeBudgetResetOrGrant':False,
    'verificationLimits':LIMITS,'candidateHash':CANDIDATE_HASH,'captureResultHash':RESULT_HASH}
PROFILE={**PREDECESSOR_PROFILE,'schema':'ouf.retained-image-byte-reconciliation-control.v1',
    'priorControlAttempts':8,'maximumCumulativeControlAttempts':9,'failedResultHash':FAILED_RESULT_HASH,
    'oldVerificationScopeRearmed':False,'captureReplayed':False,
    'purpose':'RECONCILE_EXACT_EMPTY_CONFIG_STOP_WITH_CORRECTED_OCI_VERIFIER'}


def predecessor(control):
    names=('capture.claim.json','image-byte-verification.claim.json','result.json')
    frames=history_frames(FAILED_SCOPE,names)
    def read(name,maximum):return decode(control.read(FAILED_SCOPE/name,0,0,0o600,maximum,'metadataReads'))
    require(read('capture.claim.json',4096)==
        {'schema':'ouf.m2-discovery-custody-capture-claim.v1','automaticReplayAllowed':False},
        'EXACT_CONSUMED_IMAGE_VERIFICATION_CAPTURE_CLAIM_REQUIRED')
    failed=read('result.json',16384)
    require(digest(failed)==FAILED_RESULT_HASH,'EXACT_CONSUMED_EMPTY_CONFIG_STOP_REQUIRED')
    require(read('image-byte-verification.claim.json',16384)==
        {'schema':'ouf.image-byte-verification-claim.v1','profile':PREDECESSOR_PROFILE,'automaticReplayAllowed':False},
        'EXACT_CONSUMED_IMAGE_VERIFICATION_PROFILE_REQUIRED')
    require(all(attrs(Path(path).lstat())==frame for path,frame in frames.items()),
        'CONSUMED_IMAGE_VERIFICATION_CHANGED_DURING_RECONCILIATION')
    return frames


def main():
    control=None
    try:
        require(sys.argv[1:]==[],'PRIVATE_IMAGE_VERIFICATION_ACCEPTS_NO_ARGUMENTS')
        require(os.geteuid()==os.getegid()==0,'ROOT_PRIVATE_IMAGE_VERIFICATION_REQUIRED')
        os.umask(0o077);started=time.monotonic();control=Capture(OUTPUT)
        control.until=started+PROFILE['maximumSeconds']
        control.put('image-byte-verification.claim.json',{'schema':'ouf.image-byte-verification-claim.v1',
            'profile':PROFILE,'automaticReplayAllowed':False})
        frames=predecessor(control)
        reader=RetainedArchiveReader();reader.budget.until=min(reader.budget.until,control.until)
        private,witness=reader.read_set();control.check()
        require(all(attrs(Path(path).lstat())==frame for path,frame in frames.items()),
            'CONSUMED_IMAGE_VERIFICATION_CHANGED_DURING_RECONCILIATION')
        require(private['candidateHash']==witness['candidateHash']==PROFILE['candidateHash']
            and private['captureResultHash']==witness['captureResultHash']==PROFILE['captureResultHash']
            and witness['privateByteEvidenceHash']==digest(private),
            'SAME_CONSUMED_INPUT_AND_COMPLETE_PRIVATE_BYTE_WITNESS_REQUIRED')
        control.put('image-byte-evidence.private.json',private)
        result={'schema':'ouf.retained-image-byte-verification-result.v1',
            'status':'PRIVATE_IMAGE_BYTES_VERIFIED_SOURCE_AND_RUNTIME_NOT_ADMITTED',
            'witness':witness,'privateEvidenceHash':digest(private),'verificationProfileHash':digest(PROFILE),
            'verificationControlAttempts':1,'newVerificationControlScopeCreated':True,
            'cumulativeControlAttempts':9,'cumulativeDirectEngineGets':35,
            'failedVerificationResultHash':FAILED_RESULT_HASH,'failedVerificationScopePreserved':True,
            'allEightPriorScopesPreserved':True,'oldVerificationScopeRearmed':False,
            'automaticReplayAllowed':False,'runtimeBudgetResetOrGrant':False,'runtimeAuthorityIssued':False,
            'targetApplyAuthorized':False,'releaseAcceptance':False}
        control.put('result.json',result);code=0
    except Exception as error:
        reason=str(error) if type(error) is Stop and re.fullmatch('[A-Z0-9_]{1,128}',str(error)) else 'PRIVATE_IMAGE_BYTE_VERIFICATION_UNPROVEN'
        result={'schema':'ouf.retained-image-byte-verification-result.v1','status':'STOP_RECONCILE',
            'reasonCode':reason,'scopeConsumed':os.path.lexists(OUTPUT),'automaticReplayAllowed':False,
            'newVerificationControlScopeCreated':control is not None,
            'cumulativeControlAttempts':9 if control is not None else None,'cumulativeDirectEngineGets':35,
            'runtimeBudgetResetOrGrant':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
            'releaseAcceptance':False}
        if control is not None:
            try:control.put('result.json',result)
            except Exception:pass
        code=1
    print(json.dumps(result,sort_keys=True));return code


if __name__=='__main__':raise SystemExit(main())
