"""One structural diagnosis bound to both exact consumed verifier STOPs.

No identity-verifier retry, capture, external blob fetch, Engine or runtime effect.
The original archive hashes authenticate the input; missing content is not admitted.
"""
import json,os,re,sys,time
from pathlib import Path
from .custody_capture import Capture,Stop,attrs,decode,digest,encoded,require
from .retained_readonly_hashes import history_frames
from .retained_image_reader import RetainedArchiveReader
from .retained_image_graph import GRAPH_LIMITS,inspect_graph
from . import retained_image_verification as previous

FAILED_SCOPE=previous.OUTPUT
FAILED_RESULT_HASH='8bec830155b26ee665298b6e35f8bb53d41e1ee8ba0333e4e2209829dfea1380'
OUTPUT=Path('/etc/ouf/deploy-snapshots/m2-image-graph-diagnostic-fa95a719-20261101-v1')
PROFILE={'schema':'ouf.retained-image-graph-diagnostic-control.v1','maximumAttempts':1,
    'maximumSeconds':600,'maximumEngineGets':0,'maximumArchiveSetBytes':8589934592,
    'priorControlAttempts':9,'maximumCumulativeControlAttempts':10,'cumulativeDirectEngineGets':35,
    'candidateHash':previous.PROFILE['candidateHash'],'captureResultHash':previous.PROFILE['captureResultHash'],
    'failedResultHash':FAILED_RESULT_HASH,'limits':GRAPH_LIMITS,'maximumPublicResultBytes':65536,
    'maximumPrivateEvidenceBytes':16777216,
    'purpose':'CLASSIFY_PRESENT_AND_MISSING_ARCHIVE_REFERENCES_WITHOUT_IMAGE_ADMISSION',
    'verificationReplayed':False,'captureReplayed':False,'automaticReplayAllowed':False,
    'oldScopesRearmed':False,'runtimeBudgetResetOrGrant':False}


def terminal_history(control):
    frames=previous.predecessor(control)
    frames.update(history_frames(FAILED_SCOPE,('capture.claim.json','image-byte-verification.claim.json','result.json')))
    def read(name,maximum):return decode(control.read(FAILED_SCOPE/name,0,0,0o600,maximum,'metadataReads'))
    require(read('capture.claim.json',4096)==
        {'schema':'ouf.m2-discovery-custody-capture-claim.v1','automaticReplayAllowed':False},
        'EXACT_FAILED_GRAPH_PREDECESSOR_CAPTURE_CLAIM_REQUIRED')
    require(digest(read('result.json',16384))==FAILED_RESULT_HASH,
        'EXACT_CONSUMED_NINTH_IMAGE_CONTROL_STOP_REQUIRED')
    require(read('image-byte-verification.claim.json',16384)==
        {'schema':'ouf.image-byte-verification-claim.v1','profile':previous.PROFILE,'automaticReplayAllowed':False},
        'EXACT_CONSUMED_NINTH_IMAGE_CONTROL_PROFILE_REQUIRED')
    return frames


def diagnose(control):
    frames=terminal_history(control);reader=RetainedArchiveReader()
    reader.budget.until=min(reader.budget.until,control.until)
    seed,rows=reader.material();reader.roots(seed)
    require(sum(row['bytes'] for row in rows.values())<=PROFILE['maximumArchiveSetBytes'],
        'BOUNDED_RETAINED_GRAPH_ARCHIVE_SET_REQUIRED')
    private=[];summaries=[]
    def stable():
        control.check();reader.roots(seed)
        require(all(attrs(Path(path).lstat())==frame for path,frame in frames.items()),
            'CONSUMED_GRAPH_PREDECESSOR_CHANGED_DURING_DIAGNOSIS')
    for ordinal,(role,row) in enumerate(sorted(rows.items())):
        stable();path=reader.path.parent/row['filename']
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as stream:
            require(attrs(os.fstat(stream.fileno()))==row['metadata'],'SAME_RETAINED_GRAPH_ARCHIVE_FD_REQUIRED')
            record,summary=inspect_graph(stream,row['sha256'],row['imageIdRequested'],row['bytes'],reader.budget)
            require(attrs(os.fstat(stream.fileno()))==attrs(path.lstat())==row['metadata'],
                'RETAINED_GRAPH_ARCHIVE_CHANGED_DURING_DIAGNOSIS')
        private.append({'archiveOrdinal':ordinal,'role':role,'record':record})
        summaries.append({'archiveOrdinal':ordinal,**summary});stable()
    proof={'schema':'ouf.retained-image-graph-set-private.v1','profile':PROFILE,
        'priorFailedVerificationResultHash':previous.FAILED_RESULT_HASH,'priorFailedReconciliationResultHash':FAILED_RESULT_HASH,
        'images':private,'nativeImageByteIdentityProven':False,'runtimeAuthorityIssued':False,
        'targetApplyAuthorized':False,'releaseAcceptance':False}
    result={'schema':'ouf.retained-image-graph-diagnostic-result.v1',
        'status':'PRIVATE_IMAGE_GRAPH_STRUCTURE_DIAGNOSED_NOT_ADMITTED','completeDiagnostic':True,
        'imageCount':len(rows),'archiveBytesHashed':sum(r['archiveBytesHashed'] for r in summaries),
        'missingReferences':sum(r['missingReferences'] for r in summaries),
        'metadataBytesRead':sum(r['metadataBytesRead'] for r in summaries),
        'archives':[{k:r[k] for k in ('archiveOrdinal','layoutKind','requestedDigestDocumentPresent',
            'descriptorReferencesObserved','missingReferences','missingReferenceGroups',
            'classicMissingMembers','classicMatchesPresentRuntimeManifests','unobservedManifestSubgraphs')}
            for r in summaries],
        'allNinePriorScopesPreserved':True,'failedResultHash':FAILED_RESULT_HASH,'privateEvidenceHash':digest(proof),
        'newDiagnosticControlScopeCreated':True,'cumulativeControlAttempts':10,'cumulativeDirectEngineGets':35,
        'directEngineGets':0,'mountedHostFileContentBytesRead':0,'credentialFileReads':0,'externalBlobFetches':0,
        'configurationMembersOpened':0,'layerMembersOpened':0,'expandedLayerBytesRead':0,
        'captureReplayed':False,'verificationReplayed':False,'missingBlobAdmitted':False,
        'nativeImageByteIdentityProven':False,'publisherTrustAccepted':False,'sourcePublisherAuthenticated':False,
        'automaticReplayAllowed':False,'runtimeBudgetResetOrGrant':False,'runtimeAuthorityIssued':False,
        'targetApplyAuthorized':False,'releaseAcceptance':False}
    require(len(encoded(result))<=PROFILE['maximumPublicResultBytes'],'BOUNDED_PRIVATE_GRAPH_PUBLIC_RESULT_REQUIRED')
    require(len(encoded(proof))<=PROFILE['maximumPrivateEvidenceBytes'],'BOUNDED_PRIVATE_GRAPH_EVIDENCE_REQUIRED')
    stable();return proof,result


def main():
    control=None
    try:
        require(sys.argv[1:]==[],'PRIVATE_IMAGE_GRAPH_DIAGNOSTIC_ACCEPTS_NO_ARGUMENTS')
        require(os.geteuid()==os.getegid()==0,'ROOT_PRIVATE_IMAGE_GRAPH_DIAGNOSTIC_REQUIRED')
        os.umask(0o077);started=time.monotonic();control=Capture(OUTPUT)
        control.until=started+PROFILE['maximumSeconds']
        control.put('image-graph-diagnostic.claim.json',{'schema':'ouf.retained-image-graph-diagnostic-claim.v1',
            'profile':PROFILE,'automaticReplayAllowed':False})
        proof,result=diagnose(control)
        control.put('image-graph-diagnostic.private.json',proof);control.put('result.json',result);code=0
    except Exception as error:
        reason=str(error) if type(error) is Stop and re.fullmatch('[A-Z0-9_]{1,128}',str(error)) else 'PRIVATE_IMAGE_GRAPH_DIAGNOSTIC_UNPROVEN'
        result={'schema':'ouf.retained-image-graph-diagnostic-result.v1','status':'STOP_RECONCILE',
            'reasonCode':reason,'scopeConsumed':os.path.lexists(OUTPUT),'automaticReplayAllowed':False,
            'newDiagnosticControlScopeCreated':control is not None,
            'cumulativeControlAttempts':10 if control is not None else None,'cumulativeDirectEngineGets':35,
            'runtimeBudgetResetOrGrant':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
            'releaseAcceptance':False}
        if control is not None:
            try:control.put('result.json',result)
            except Exception:pass
        code=1
    print(json.dumps(result,sort_keys=True));return code


if __name__=='__main__':raise SystemExit(main())
