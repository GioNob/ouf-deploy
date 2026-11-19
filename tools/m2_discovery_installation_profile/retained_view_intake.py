"""Exact successful kernel/live-metadata input, without policy or owner admission.

Pure validation. Token inode/time and database size/time are not immutable
permission policy; the original source and actual capture define provenance.
"""
import copy,re,stat
from .custody_capture import digest,require
from .retained_view_capture import CASE,PROFILE,OUTPUT
from . import retained_mount_lifecycle as lifecycle

CANDIDATE=OUTPUT/'effective-views.private.json'
CANDIDATE_HASH='9f1d571b1f38ace9ec5b5f52b157ed0c4de20c2e1a4553ccc6ae19f9ae04344a'
RESULT_HASH='ac206493fa3e9e4d7af098fe8d3a8aec9325162c3167858cff37a0dd57cc6a7b'
FALSE=('currentContainerConfigurationFreshlyObserved','mountedFileContentsObserved',
    'liveOwnerAuthenticated','expectedPermissionOrContentPolicyEstablished','completePrivateCustodyProven',
    'runtimeAuthorityIssued','targetApplyAuthorized','releaseAcceptance')


def live_fields(kind):
    return (0,2,3,4,5) if kind=='RENEWABLE_TOKEN_OWNER_INPUT' else tuple(range(6))


def frame(value,length):
    require(type(value) is list and len(value)==length and all(type(v) is int and v>=0 for v in value),
        'EXACT_EFFECTIVE_VIEW_METADATA_FRAME_REQUIRED')


def validate_views(record,result,capture,*,candidate_hash=CANDIDATE_HASH,result_hash=RESULT_HASH,case=CASE):
    require(digest(record)==candidate_hash and digest(result)==result_hash and digest(capture)==case['candidateHash'],
        'EXACT_SUCCESSFUL_KERNEL_VIEW_CAPTURE_AND_ORIGINAL_METADATA_REQUIRED')
    require(type(record) is dict and set(record)=={'schema','caseHash','profile','staticCandidateHash',
        'metadataCandidateHash','lifecycleContractHash','bootId','peers',*FALSE}
        and record['schema']=='ouf.retained-effective-view-candidates.v1'
        and record['caseHash']==digest(case) and record['profile']==PROFILE
        and record['staticCandidateHash']==case['staticCandidateHash']
        and record['metadataCandidateHash']==case['candidateHash']
        and record['lifecycleContractHash']==lifecycle.CONTRACT_HASH
        and record['bootId']==capture['bootId'] and all(record[k] is False for k in FALSE)
        and type(record['peers']) is dict and set(record['peers'])==set(capture['peers']),
        'EXACT_NONAUTHORITATIVE_EFFECTIVE_VIEW_RECORD_REQUIRED')
    classes,_=lifecycle.plan(capture['peers'],exact_static_input=True)
    readonly=writable=live=differences=0
    for role,peer in record['peers'].items():
        old=capture['peers'][role]
        require(set(peer)=={'processPin','rootMetadata','mountinfoSha256','mounts'}
            and peer['processPin']==old['processPin'] and type(peer['mountinfoSha256']) is str
            and re.fullmatch('[a-f0-9]{64}',peer['mountinfoSha256']) and type(peer['mounts']) is list
            and len(peer['mounts'])==len(old['mounts']), 'EXACT_CAPTURED_PROCESS_ROOT_AND_MOUNT_VIEWS_REQUIRED')
        frame(peer['rootMetadata'],5)
        require(stat.S_ISDIR(peer['rootMetadata'][2]),'EFFECTIVE_PROCESS_ROOT_DIRECTORY_REQUIRED')
        ids=set()
        for row,mount,kind in zip(peer['mounts'],old['mounts'],classes[role]):
            expected=mount['metadataTree']['metadata'] if kind in lifecycle.LIVE|{'STATIC_CAPTURE_CANDIDATE'} else mount['metadata']
            static=kind=='STATIC_CAPTURE_CANDIDATE'
            require(type(row) is dict and set(row)=={'mount','lifecycleClass','effectiveMountId',
                'readOnly','sourceAndViewMetadata','liveLeafMetadata'} and row['mount']==mount
                and row['lifecycleClass']==kind and row['readOnly'] is mount['readOnly']
                and row['sourceAndViewMetadata']==(expected if static else expected[:5])
                and type(row['effectiveMountId']) is int and row['effectiveMountId']>0
                and row['effectiveMountId'] not in ids,'EXACT_SOURCE_CAPTURE_AND_EFFECTIVE_MOUNT_VIEW_REQUIRED')
            ids.add(row['effectiveMountId']);readonly+=int(mount['readOnly']);writable+=int(not mount['readOnly'])
            if kind not in lifecycle.LIVE:
                require(row['liveLeafMetadata'] is None,'NO_LIVE_LEAF_CLAIM_FOR_STATIC_OR_MUTABLE_MOUNT')
                continue
            node=row['liveLeafMetadata'];name='token' if kind=='RENEWABLE_TOKEN_OWNER_INPUT' else 'gateway-operations.sqlite'
            prior=mount['metadataTree']['children'][name]['metadata']
            require(type(node) is dict and set(node)=={'name','captured','currentSource','currentEffectiveView',
                'custodyFieldsMatchCapture','contentObserved','expectedPolicyEstablished','ownerAuthenticated'}
                and node['name']==name and node['captured']==prior
                and all(node[k] is False for k in ('contentObserved','expectedPolicyEstablished','ownerAuthenticated')),
                'EXACT_UNAUTHENTICATED_LIVE_METADATA_NODE_REQUIRED')
            a,b=node['currentSource'],node['currentEffectiveView'];frame(a,9);frame(b,9)
            require(stat.S_ISREG(a[2]) and stat.S_ISREG(b[2]) and a[5]==b[5]==1
                and (a==b and 0<a[6]<=16384 if kind=='RENEWABLE_TOKEN_OWNER_INPUT' else a[:6]==b[:6]),
                'SAME_REGULAR_SINGLE_LINK_CAPTURED_LIVE_SOURCE_AND_VIEW_REQUIRED')
            same=all(a[i]==prior[i] for i in live_fields(kind))
            require(type(node['custodyFieldsMatchCapture']) is bool and node['custodyFieldsMatchCapture'] is same,
                'LIVE_CUSTODY_CONTINUITY_FLAG_MUST_MATCH_ACTUAL_FIELDS')
            live+=1;differences+=int(not same)
    require(result['schema']=='ouf.retained-effective-view-capture-result.v1'
        and result['status']=='EFFECTIVE_VIEWS_AND_LIVE_METADATA_CAPTURED_NOT_ADMITTED'
        and result['candidateHash']==candidate_hash and result['staticCandidateHash']==case['staticCandidateHash']
        and result['allFivePriorScopesPreserved'] is True and result['retainedProcesses']==10
        and result['cumulativeControlAttempts']==6 and result['cumulativeDirectEngineGets']==22
        and all(result[k] is False for k in ('automaticReplayAllowed','completePrivateCustodyProven',
            'currentContainerConfigurationFreshlyObserved','expectedPermissionOrContentPolicyEstablished',
            'liveOwnerAuthenticated','privatePathsNamesValuesOrIndividualHashesPrinted','releaseAcceptance',
            'runtimeAuthorityIssued','runtimeBudgetResetOrGrant','staticContentsRehashed','targetApplyAuthorized')),
        'EXACT_SUCCESSFUL_UNADMITTED_VIEW_RECEIPT_REQUIRED')
    counts=result['counts']
    require(readonly==counts['effectiveReadonlyMounts']==25 and writable==counts['effectiveWritableMounts']==4
        and live==counts['liveLeafMetadataNodes']==8 and differences==counts['liveCustodyContinuityDifferences']==0
        and counts['engineGets']==counts['mountFileContentBytesRead']==0 and counts['metadataReads']==6
        and counts['kernelReads']==104 and 0<counts['kernelMetadataBytes']<=PROFILE['maximumKernelMetadataBytes'],
        'CLOSED_VIEW_COUNTS_AND_ZERO_CUSTODY_DIFFERENCE_TARGET_REQUIRED')
    return classes,copy.deepcopy(record['peers'])
