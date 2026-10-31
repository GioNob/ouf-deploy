"""Private preparation plan from exact verified candidates; no copying or IO.

Copies are proposed with the new profile's custody. Historical source files are
preserved. Credential validity, authority and current native admission remain
separate; the public operator result cannot substitute for the private record.
"""
import copy,re,stat
from pathlib import PurePosixPath
from tools.m2_discovery_installation_profile.audit import digest,require,path

def hash_value(value):return type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None

ROLES={'providerCredential','registryDiscoveryKey','gatewayDiscoveryKey','publicProviderCa'}

def compile_projections(candidates,binding,output_directory,discovery_key_environment):
    require(type(binding) is dict and set(binding)=={'path','sha256'} and hash_value(binding['sha256'])
        and type(candidates) is dict and digest(candidates)==binding['sha256'], 'EXACT_PRIVATE_CUSTODY_CANDIDATE_BINDING_REQUIRED')
    path(binding['path']);path(output_directory)
    require(candidates.get('schema')=='ouf.m2-discovery-current-material-candidates.v1'
        and hash_value(candidates.get('installationInputsHash')) and hash_value(candidates.get('materialManifestHash'))
        and all(candidates.get(k) is False for k in ('runtimeAuthorityIssued','targetApplyAuthorized','historicalAuthorityReused'))
        and set(candidates.get('candidates',{}))==ROLES,'PRIVATE_UNADMITTED_CUSTODY_CANDIDATES_REQUIRED')
    require(type(discovery_key_environment) is str and re.fullmatch('[A-Z][A-Z0-9_]{0,112}_OWNER_KEY',discovery_key_environment)
        and discovery_key_environment not in {'OUF_SEMANTIC_READ_OWNER_KEY','OUF_SEMANTIC_PROPOSAL_OWNER_KEY',
        'OUF_AUTHORIZATION_OWNER_KEY','OUF_INGESTION_READ_OWNER_KEY','OUF_UDP_SEARCH_OWNER_KEY'},
        'DISTINCT_DISCOVERY_GATEWAY_KEY_REFERENCE_REQUIRED')
    rows=candidates['candidates'];sources=[]
    for role,row in rows.items():
        require(type(row) is dict and set(row)=={'path','sha256','uid','gid','mode','metadata','historicalAuthorityReused','runtimeAdmissionProven'}
            and hash_value(row['sha256']) and row['historicalAuthorityReused'] is False and row['runtimeAdmissionProven'] is False,
            'EXACT_UNADMITTED_SOURCE_CUSTODY_REQUIRED')
        source=path(row['path']);sources.append(source)
        expected=(0,0,0o600) if role=='publicProviderCa' else (636,636,0o400) if role=='gatewayDiscoveryKey' else (10001,10001,0o400)
        require((row['uid'],row['gid'],row['mode'])==expected
            and type(row['metadata']) is list and len(row['metadata'])==9
            and all(type(v) is int and v>=0 for v in row['metadata'])
            and row['metadata'][3:6]==[row['uid'],row['gid'],1]
            and stat.S_ISREG(row['metadata'][2]) and row['metadata'][2]&0o777==row['mode']
            and 0<row['metadata'][6]<=(1048576 if role=='publicProviderCa' else 4096 if role=='providerCredential' else 64),
            'SOURCE_CUSTODY_IDENTITY_METADATA_DRIFT')
    require(len(set(sources))==4 and all(not (source==output_directory or source.startswith(output_directory+'/')
        or output_directory.startswith(str(PurePosixPath(source).parent)+'/') or output_directory==str(PurePosixPath(source).parent))
        for source in sources),'PREPARATION_OUTPUT_MUST_BE_SEPARATE_FROM_ALL_SOURCE_DIRECTORIES')
    key=rows['registryDiscoveryKey']['sha256']
    require(key==rows['gatewayDiscoveryKey']['sha256'] and key!=rows['providerCredential']['sha256'],
        'DISTINCT_MATCHED_DISCOVERY_KEY_PAIR_REQUIRED')
    projections=[]
    for role,name in [('providerCredential','schema-gov-client-secret'),('registryDiscoveryKey','semantic-discovery-owner.key')]:
        projections.append({'role':role,'source':copy.deepcopy(rows[role]),'destination':output_directory+'/'+name,
            'uid':0,'gid':10001,'mode':0o440,'expectedSha256':rows[role]['sha256'],'regenerationAllowed':False})
    return {'schema':'ouf.m2-discovery-private-custody-projection-plan.v1','candidateBinding':copy.deepcopy(binding),
        'installationInputsHash':candidates['installationInputsHash'],'materialManifestHash':candidates['materialManifestHash'],
        'outputDirectory':output_directory,'projections':projections,
        'gatewayKey':{'environmentName':discovery_key_environment,'source':copy.deepcopy(rows['gatewayDiscoveryKey']),
            'sameKeyAsRegistryRequired':True,'secretValueExported':False},
        'publicTrustInput':copy.deepcopy(rows['publicProviderCa']),
        'trustStoreCreationRequiresPublicCaOnlyVerification':True,'sourceFilesMustRemainUnchanged':True,
        'currentProcessRevalidationRequired':True,'currentIamCredentialScopeAndProviderTlsAdmissionRequired':True,
        'gatewayRuntimeMustProveSelectedKeySlotIsDistinct':True,
        'existingReadProposalAndDelegationKeysMustBeComparedForDistinctness':True,
        'executionAllowed':False,'newKeysGenerated':0,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
        'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}
