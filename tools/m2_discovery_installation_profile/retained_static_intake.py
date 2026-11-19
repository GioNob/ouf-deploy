"""Intake the actual static host-file candidate, never learn expected policy.

Pure validation. The exact successful capture remains the declaration source;
neither this receipt nor copied hashes authenticate live owner credentials.
"""
import copy, re, stat
from .custody_capture import digest, require
from .retained_static_custody import CASE, PROFILE, OUTPUT
from . import retained_mount_lifecycle as lifecycle

CANDIDATE=OUTPUT/'static-custody.private.json'
CANDIDATE_HASH='de4546d0ee39be6b3c3cca2e5d5307167564a953ca8428762840b0b205768023'
RESULT_HASH='39426368418d74a71e894d82f88fed3f7fba40734d25269a18438a63adf14881'
FALSE=('currentContainerConfigurationFreshlyObserved','liveMembersObservedOrAdmitted',
    'expectedPermissionOrContentPolicyEstablished','completePrivateCustodyProven',
    'runtimeAuthorityIssued','targetApplyAuthorized','releaseAcceptance')


def validate_static(record,result,capture,*,candidate_hash=CANDIDATE_HASH,result_hash=RESULT_HASH,case=CASE):
    require(digest(record)==candidate_hash and digest(result)==result_hash and digest(capture)==case['candidateHash'],
        'EXACT_STATIC_CANDIDATE_RECEIPT_AND_METADATA_CAPTURE_REQUIRED')
    require(type(record) is dict and set(record)=={'schema','caseHash','metadataCandidateHash',
        'reconciliationCandidateHash','lifecycleContractHash','lifecyclePlanHash','rootAndStaticMetadataHash',
        'files','profile','bootId',*FALSE}
        and record['schema']=='ouf.retained-static-host-file-candidates.v1'
        and record['caseHash']==digest(case) and record['profile']==PROFILE
        and record['metadataCandidateHash']==case['candidateHash']
        and record['reconciliationCandidateHash']==case['reconciliationCandidateHash']
        and record['bootId']==capture['bootId'] and all(record[k] is False for k in FALSE),
        'EXACT_NONAUTHORITATIVE_STATIC_HOST_FILE_RECORD_REQUIRED')
    classes,totals=lifecycle.plan(capture['peers'],exact_static_input=True)
    expected={};proofs={}
    for role,peer in sorted(capture['peers'].items()):
        proofs[role]=[]
        for mount,kind in zip(peer['mounts'],classes[role]):
            proof={k:copy.deepcopy(v) for k,v in mount.items() if k not in ('metadataTree','metadata')}
            proof['lifecycleClass']=kind
            if kind=='STATIC_CAPTURE_CANDIDATE':
                proof['metadataTree']=copy.deepcopy(mount['metadataTree'])
                path=mount['source'];metadata=mount['metadataTree']['metadata']
                require(path not in expected or expected[path]==metadata,'SHARED_STATIC_INTAKE_FILE_METADATA_DISAGREES')
                expected[path]=metadata
            else:
                proof['rootCustodyMetadata']=(mount['metadataTree']['metadata'] if kind in lifecycle.LIVE else mount['metadata'])[:5]
            proofs[role].append(proof)
    require(record['lifecycleContractHash']==lifecycle.CONTRACT_HASH and record['lifecyclePlanHash']==digest(classes)
        and record['rootAndStaticMetadataHash']==digest(proofs)
        and type(record['files']) is dict and set(record['files'])==set(expected)
        and 0<len(expected)<=PROFILE['maximumUniqueFiles'],
        'EXACT_CAPTURE_ALLOWLIST_AND_LIFECYCLE_STATIC_INPUT_REQUIRED')
    total=0
    for path,row in record['files'].items():
        require(type(row) is dict and set(row)=={'sha256','bytes','metadata','rawValueExported','permissionPolicyEstablished'}
            and type(row['sha256']) is str and re.fullmatch('[a-f0-9]{64}',row['sha256'])
            and row['metadata']==expected[path] and stat.S_ISREG(row['metadata'][2]) and row['metadata'][5]==1
            and type(row['bytes']) is int and 0<=row['bytes']==row['metadata'][6]<=PROFILE['maximumFileBytes']
            and row['rawValueExported'] is False and row['permissionPolicyEstablished'] is False,
            'EXACT_BOUNDED_STATIC_FILE_HASH_WITHOUT_POLICY_REQUIRED')
        total+=row['bytes']
    require(total<=PROFILE['maximumTotalHashedBytes'],'BOUNDED_STATIC_INTAKE_TOTAL_REQUIRED')
    require(result['schema']=='ouf.retained-static-host-file-custody-result.v1'
        and result['status']=='STATIC_HOST_FILE_CANDIDATES_PREPARED_LIVE_INPUTS_NOT_ADMITTED'
        and result['candidateHash']==candidate_hash and result['lifecycleContractHash']==lifecycle.CONTRACT_HASH
        and result['classifiedMounts']==totals and result['allFourPriorScopesPreserved'] is True
        and result['cumulativeControlAttempts']==5 and result['cumulativeDirectEngineGets']==22
        and result['liveTokenAndOperationalStoreContentBytesRead']==0
        and result['staticCredentialOrKeyFilesMayHaveBeenHashed'] is True
        and all(result[k] is False for k in (*FALSE,'automaticReplayAllowed','runtimeBudgetResetOrGrant',
            'oldHashAttemptRearmed','rawValuesOrIndividualFileHashesPrinted')),
        'EXACT_SUCCESSFUL_STATIC_HOST_FILE_RECEIPT_REQUIRED')
    counts=result['counts']
    require(counts['readonlyRegularFilesHashed']==len(expected) and counts['readonlyFileBytesHashed']==total
        and counts['metadataReads']==8 and counts['readonlyMounts']==25 and counts['mutableMounts']==4
        and counts['staticEntries']==17 and all(counts[k]==0 for k in
            ('engineGets','engineBytes','ephemeralMounts','specialSources')),
        'STATIC_RECEIPT_FILE_BYTES_AND_CLOSED_EFFECT_COUNTS_DISAGREE')
    return classes,copy.deepcopy(record['files'])
