"""Pure intake of the consumed thirteen-image capture; no file or Engine I/O.

The operator's public result pins the private index, not publisher provenance,
current runtime policy or authority. The archive byte reader is a separate step.
"""
import copy,re,stat
from .custody_capture import digest,require
from .retained_image_capture import OUTPUT,CASE,PROFILE,ROSTER
from .retained_mount_role_correction import select_roles

CANDIDATE=OUTPUT/'native-image-archives.private.json'
CANDIDATE_HASH='fa95a7196e67dee8b0f94f5df223bb51bcf17feeb31bf2022626d0a7be81008e'
RESULT_HASH='9733fa7c6168a5073f06ea02b89cd015da505ce8bc0bbbbe4f95e614b2b5a4de'
RECORD_FALSE=('nativeIdentityAndSourceAdmissionEstablished','completePrivateCustodyProven',
    'runtimeAuthorityIssued','targetApplyAuthorized','releaseAcceptance')
RESULT_FALSE=(*RECORD_FALSE,'currentContainerConfigurationFreshlyObserved',
    'mountedHostFileContentsObserved','liveOwnerAuthenticated','expectedPermissionOrContentPolicyEstablished',
    'privatePathsNamesValuesOrIndividualArchiveHashesPrinted','automaticReplayAllowed','runtimeBudgetResetOrGrant')
ZERO_COUNTS=('applicationMacKeyReads','credentialFileReads','ephemeralMounts',
    'mountFileContentBytesRead','mutableMounts','publicCertificateReads','readonlyMounts','specialSources','staticEntries')


def validate_archives(record,result,seed,*,candidate_hash=CANDIDATE_HASH,result_hash=RESULT_HASH,case=CASE,roster=ROSTER):
    require(digest(record)==candidate_hash and digest(result)==result_hash and digest(seed)==case['seedHash'],
        'EXACT_PRIVATE_ARCHIVE_INDEX_PUBLIC_RECEIPT_AND_ORIGINAL_SEED_REQUIRED')
    require(type(record) is dict and set(record)=={'schema','caseHash','profile','viewCandidateHash',
        'seedHash','bootId','archives',*RECORD_FALSE}
        and record['schema']=='ouf.retained-native-image-archive-candidates.v1'
        and record['caseHash']==digest(case) and record['profile']==PROFILE
        and record['viewCandidateHash']==case['viewCandidateHash'] and record['seedHash']==case['seedHash']
        and record['bootId']==seed['bootId'] and all(record[k] is False for k in RECORD_FALSE),
        'EXACT_UNADMITTED_PRIVATE_IMAGE_ARCHIVE_INDEX_REQUIRED')
    mapping=select_roles(seed,roster)
    require(type(record['archives']) is dict and set(record['archives'])==set(mapping)
        and len(mapping)==13,'THIRTEEN_ID_BOUND_ARCHIVE_ROLES_REQUIRED')
    identities=set();total=0
    for role,row in record['archives'].items():
        require(type(row) is dict and set(row)=={'imageIdRequested','filename','bytes','sha256','metadata',
            'nativeIdentityAndSourceAdmissionEstablished'}
            and row['imageIdRequested']==seed['observations'][mapping[role]]['Image']
            and type(row['imageIdRequested']) is str and re.fullmatch('sha256:[a-f0-9]{64}',row['imageIdRequested'])
            and row['filename']=='image-'+role+'.docker.tar'
            and type(row['bytes']) is int and 0<row['bytes']<=PROFILE['maximumImageBytes'] and row['bytes']%512==0
            and type(row['sha256']) is str and re.fullmatch('[a-f0-9]{64}',row['sha256'])
            and row['nativeIdentityAndSourceAdmissionEstablished'] is False,
            'EXACT_PRIVATE_ARCHIVE_ROLE_NAME_SIZE_HASH_AND_ORIGINAL_IMAGE_REQUIRED')
        frame=row['metadata']
        require(type(frame) is list and len(frame)==9 and all(type(v) is int and v>=0 for v in frame)
            and stat.S_ISREG(frame[2]) and stat.S_IMODE(frame[2])==0o400 and frame[3:6]==[0,0,1]
            and frame[6]==row['bytes'],'ROOT_PRIVATE_SINGLE_LINK_IMAGE_ARCHIVE_METADATA_REQUIRED')
        identities.add(row['imageIdRequested']);total+=row['bytes']
    require(len(identities)==13 and total<=PROFILE['maximumTotalImageBytes'],
        'THIRTEEN_DISTINCT_BOUNDED_ORIGINAL_IMAGE_ARCHIVES_REQUIRED')
    require(type(result) is dict and set(result)=={'schema','status','candidateHash','viewCandidateHash','counts',
        'allSixPriorScopesPreserved','cumulativeControlAttempts','cumulativeDirectEngineGets',
        'imageBytesRetainedPrivately',*RESULT_FALSE}
        and result['schema']=='ouf.retained-native-image-archive-result.v1'
        and result['status']=='NATIVE_IMAGE_ARCHIVE_CANDIDATES_CAPTURED_NOT_ADMITTED'
        and result['candidateHash']==candidate_hash and result['viewCandidateHash']==case['viewCandidateHash']
        and result['allSixPriorScopesPreserved'] is result['imageBytesRetainedPrivately'] is True
        and type(result['cumulativeControlAttempts']) is int and result['cumulativeControlAttempts']==7
        and type(result['cumulativeDirectEngineGets']) is int and result['cumulativeDirectEngineGets']==35
        and all(result[k] is False for k in RESULT_FALSE),'EXACT_CONSUMED_UNADMITTED_ARCHIVE_RECEIPT_REQUIRED')
    counts=result['counts']
    require(type(counts) is dict and set(counts)=={*ZERO_COUNTS,'bytes','engineBytes','engineGets',
        'imageArchiveBytes','imageArchivesCaptured','metadataReads'}
        and all(type(v) is int and v>=0 for v in counts.values())
        and all(counts[k]==0 for k in ZERO_COUNTS) and counts['engineGets']==counts['imageArchivesCaptured']==13
        and counts['engineBytes']==counts['imageArchiveBytes']==total and counts['metadataReads']==5
        and 0<counts['bytes']<=4194304,'PRIVATE_ARCHIVE_BYTES_AND_CLOSED_CAPTURE_COUNTS_MUST_AGREE')
    return copy.deepcopy(record['archives'])
