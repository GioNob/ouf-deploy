"""One selected-runtime byte proof bound to the exact successful graph diagnosis.

Installation-specific linux/amd64 recovery binding, not a reusable installer
default. The original native digest and complete classic/config/layer identity
remain mandatory. Unavailable nonselected branches are never admitted.
"""
import json,os,re,sys,time
from pathlib import Path
from .custody_capture import Capture,Stop,attrs,decode,digest,require
from .retained_readonly_hashes import history_frames
from .retained_image_reader import RetainedArchiveReader
from .retained_selected_image_identity import verified_selected_image
from . import retained_image_graph_diagnostic as previous

GRAPH_SCOPE=previous.OUTPUT
GRAPH_RESULT_HASH='95e66e217be370477f7bece3a3ac7313857c92d73dd7d6fabd41c2200f67cea7'
GRAPH_PROOF_HASH='f54c14e334545054a4c6d3f56d51c3ad9d8c4038653dd2c813b4408dabc295ea'
OUTPUT=Path('/etc/ouf/deploy-snapshots/m2-selected-runtime-bytes-fa95a719-20261101-v1')
PROFILE={'schema':'ouf.retained-selected-runtime-verification-control.v1','maximumAttempts':1,
    'maximumSeconds':600,'maximumEngineGets':0,'priorControlAttempts':10,
    'maximumCumulativeControlAttempts':11,'cumulativeDirectEngineGets':35,
    'candidateHash':previous.PROFILE['candidateHash'],'captureResultHash':previous.PROFILE['captureResultHash'],
    'graphResultHash':GRAPH_RESULT_HASH,'graphPrivateEvidenceHash':GRAPH_PROOF_HASH,
    'selectedPlatform':{'os':'linux','architecture':'amd64'},'maximumGraphProofBytes':2097152,
    'maximumPrivateEvidenceBytes':2097152,'maximumArchiveSetBytes':8589934592,
    'purpose':'VERIFY_EXACT_NATIVE_TO_CLASSIC_SELECTED_RUNTIME_CONFIG_LAYERS_AND_DIFF_IDS',
    'completeIndexAdmissionAllowed':False,'nonselectedBranchAdmissionAllowed':False,
    'oldScopesRearmed':False,'captureReplayed':False,'graphDiagnosticReplayed':False,
    'automaticReplayAllowed':False,'runtimeBudgetResetOrGrant':False}


def graph_history(control):
    frames=previous.terminal_history(control)
    frames.update(history_frames(GRAPH_SCOPE,('capture.claim.json','image-graph-diagnostic.claim.json',
        'image-graph-diagnostic.private.json','result.json')))
    def read(name,maximum):return decode(control.read(GRAPH_SCOPE/name,0,0,0o600,maximum,'metadataReads'))
    require(read('capture.claim.json',4096)==
        {'schema':'ouf.m2-discovery-custody-capture-claim.v1','automaticReplayAllowed':False},
        'EXACT_SUCCESSFUL_GRAPH_CAPTURE_CLAIM_REQUIRED')
    require(read('image-graph-diagnostic.claim.json',16384)==
        {'schema':'ouf.retained-image-graph-diagnostic-claim.v1','profile':previous.PROFILE,'automaticReplayAllowed':False},
        'EXACT_SUCCESSFUL_GRAPH_PROFILE_REQUIRED')
    result=read('result.json',65536);proof=read('image-graph-diagnostic.private.json',PROFILE['maximumGraphProofBytes'])
    require(digest(result)==GRAPH_RESULT_HASH and result.get('privateEvidenceHash')==GRAPH_PROOF_HASH
        and digest(proof)==GRAPH_PROOF_HASH and proof.get('profile')==previous.PROFILE
        and proof.get('schema')=='ouf.retained-image-graph-set-private.v1',
        'EXACT_SUCCESSFUL_GRAPH_RESULT_AND_PRIVATE_PROOF_REQUIRED')
    return frames,result,proof


def verify(control):
    frames,graph_result,graph_proof=graph_history(control);reader=RetainedArchiveReader()
    reader.budget.until=min(reader.budget.until,control.until)
    seed,rows=reader.material();reader.roots(seed)
    require(len(graph_proof['images'])==graph_result['imageCount']==len(rows)
        and sum(row['bytes'] for row in rows.values())==graph_result['archiveBytesHashed']
        and graph_result['archiveBytesHashed']<=PROFILE['maximumArchiveSetBytes'],
        'SAME_COMPLETE_DIAGNOSED_ARCHIVE_SET_REQUIRED')
    def stable():
        control.check();reader.roots(seed)
        require(all(attrs(Path(path).lstat())==frame for path,frame in frames.items()),
            'SUCCESSFUL_GRAPH_INPUT_CHANGED_DURING_RUNTIME_VERIFICATION')
    selected={};other=auxiliary=0
    for ordinal,(role,row) in enumerate(sorted(rows.items())):
        stable();graph=graph_proof['images'][ordinal];public=graph_result['archives'][ordinal]
        record=graph['record'];summary=record['summary']
        require(graph['archiveOrdinal']==public['archiveOrdinal']==ordinal and graph['role']==role
            and record['archiveSha256']==row['sha256'] and record['requestedImageId']==row['imageIdRequested']
            and summary['classicManifestRows']==summary['classicMatchesPresentRuntimeManifests']==1
            and summary['classicMissingMembers']==0 and summary['layoutKind']=='OCI'
            and summary['requestedDigestDocumentPresent'] is True
            and {k:summary[k] for k in public if k!='archiveOrdinal'}==
                {k:v for k,v in public.items() if k!='archiveOrdinal'},
            'EXACT_DIAGNOSED_NATIVE_CLASSIC_RUNTIME_BINDING_REQUIRED')
        groups=summary['missingReferenceGroups'];counts={'EXPLICIT_OTHER_PLATFORM':0,'UNKNOWN_NONRUNTIME':0}
        for group in groups:
            require(group['context']=='INDEX_MEMBER' and group['mediaClass']=='IMAGE_MANIFEST'
                and group['presenceClass']=='ABSENT' and group['inlineDataPresent'] is False
                and group['platformClass'] in counts and type(group['count']) is int and group['count']>0,
                'ONLY_DIAGNOSED_UNAVAILABLE_MANIFEST_BRANCHES_MAY_REMAIN_OUTSIDE_SCOPE')
            counts[group['platformClass']]+=group['count']
        path=reader.path.parent/row['filename'];fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as stream:
            require(attrs(os.fstat(stream.fileno()))==row['metadata'],'SAME_SELECTED_RUNTIME_ARCHIVE_FD_REQUIRED')
            proof=verified_selected_image(stream,row['sha256'],row['imageIdRequested'],row['bytes'],
                PROFILE['selectedPlatform'],reader.budget)
            require(attrs(os.fstat(stream.fileno()))==attrs(path.lstat())==row['metadata'],
                'SELECTED_RUNTIME_ARCHIVE_CHANGED_DURING_VERIFICATION')
        require(proof['unavailableOtherPlatformManifests']==counts['EXPLICIT_OTHER_PLATFORM']
            and proof['unavailableAuxiliaryManifests']==counts['UNKNOWN_NONRUNTIME'],
            'SELECTED_SCOPE_MUST_RECONCILE_EVERY_DIAGNOSED_UNAVAILABLE_BRANCH')
        selected[role]=proof;other+=counts['EXPLICIT_OTHER_PLATFORM'];auxiliary+=counts['UNKNOWN_NONRUNTIME'];stable()
    require(other+auxiliary==graph_result['missingReferences'],'ALL_DIAGNOSED_UNAVAILABLE_BRANCHES_ACCOUNTED_FOR')
    private={'schema':'ouf.retained-selected-runtime-byte-set.v1','profile':PROFILE,
        'graphResultHash':GRAPH_RESULT_HASH,'graphPrivateEvidenceHash':GRAPH_PROOF_HASH,'images':selected,
        'completeIndexAccepted':False,'nonselectedBranchesAdmitted':False,'sourcePublisherAuthenticated':False,
        'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'releaseAcceptance':False}
    from .custody_capture import encoded
    require(len(encoded(private))<=PROFILE['maximumPrivateEvidenceBytes'],'BOUNDED_SELECTED_RUNTIME_PRIVATE_PROOF_REQUIRED')
    result={'schema':'ouf.retained-selected-runtime-byte-verification-result.v1',
        'status':'SELECTED_RUNTIME_BYTES_VERIFIED_COMPLETE_INDEX_NOT_ADMITTED','imageCount':len(selected),
        'archiveBytesVerified':sum(row['bytes'] for row in rows.values()),'expandedRuntimeBytesVerified':reader.budget.expanded,
        'selectedRuntimeBytesProven':True,'selectedRuntimeContentComplete':True,
        'unavailableOtherPlatformManifests':other,'unavailableAuxiliaryManifests':auxiliary,
        'allUnavailableBranchesAccountedFor':True,'allTenPriorScopesPreserved':True,
        'privateEvidenceHash':digest(private),'graphResultHash':GRAPH_RESULT_HASH,
        'newSelectedRuntimeControlScopeCreated':True,'cumulativeControlAttempts':11,'cumulativeDirectEngineGets':35,
        'directEngineGets':0,'credentialFileReads':0,'mountedHostFileContentBytesRead':0,'externalBlobFetches':0,
        'completeIndexAccepted':False,'nonselectedBranchesAdmitted':False,'auxiliaryTrustAccepted':False,
        'sourcePublisherAuthenticated':False,'allRuntimeArtifactMembershipProven':False,
        'currentApplicationConfigurationOrLivenessProven':False,'completePrivateCustodyProven':False,
        'automaticReplayAllowed':False,'runtimeBudgetResetOrGrant':False,'runtimeAuthorityIssued':False,
        'targetApplyAuthorized':False,'releaseAcceptance':False}
    stable();return private,result


def main():
    control=None
    try:
        require(sys.argv[1:]==[],'SELECTED_RUNTIME_VERIFICATION_ACCEPTS_NO_ARGUMENTS')
        require(os.geteuid()==os.getegid()==0,'ROOT_SELECTED_RUNTIME_VERIFICATION_REQUIRED')
        os.umask(0o077);started=time.monotonic();control=Capture(OUTPUT);control.until=started+PROFILE['maximumSeconds']
        control.put('selected-runtime-verification.claim.json',{'schema':'ouf.selected-runtime-verification-claim.v1',
            'profile':PROFILE,'automaticReplayAllowed':False})
        private,result=verify(control);control.put('selected-runtime-byte-evidence.private.json',private)
        control.put('result.json',result);code=0
    except Exception as error:
        reason=str(error) if type(error) is Stop and re.fullmatch('[A-Z0-9_]{1,128}',str(error)) else 'SELECTED_RUNTIME_BYTE_VERIFICATION_UNPROVEN'
        result={'schema':'ouf.retained-selected-runtime-byte-verification-result.v1','status':'STOP_RECONCILE',
            'reasonCode':reason,'scopeConsumed':os.path.lexists(OUTPUT),
            'newSelectedRuntimeControlScopeCreated':control is not None,
            'cumulativeControlAttempts':11 if control is not None else None,'cumulativeDirectEngineGets':35,
            'automaticReplayAllowed':False,'runtimeBudgetResetOrGrant':False,'runtimeAuthorityIssued':False,
            'targetApplyAuthorized':False,'releaseAcceptance':False}
        if control is not None:
            try:control.put('result.json',result)
            except Exception:pass
        code=1
    print(json.dumps(result,sort_keys=True));return code


if __name__=='__main__':raise SystemExit(main())
