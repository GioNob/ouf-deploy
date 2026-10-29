"""Pure preparation from a hash-bound private capture; never a native execution plan.

Declared mounts do not prove file existence, directory type, custody or reachability.
All deployment-specific references come from the selected capture and selection.
"""
import copy,hashlib,json,re
from pathlib import PurePosixPath
from urllib.parse import urlsplit

SCHEMA='ouf.m2-discovery-private-installation-inputs.v1'
ROLES={'mcp','semantic','gateway-owner','apisix'}
KEY_REFERENCE_NAMES=('OUF_GATEWAY_DELEGATION_KEY','OUF_SEMANTIC_READ_OWNER_KEY',
                     'OUF_SEMANTIC_PROPOSAL_OWNER_KEY','OUF_AUTHORIZATION_OWNER_KEY',
                     'GATEWAY_SUMMARY_RECEIPT_KEY','INGESTION_SUMMARY_RECEIPT_KEY',
                     'OUF_INGESTION_READ_OWNER_KEY','OUF_UDP_SEARCH_OWNER_KEY')


def require(condition,code):
    if not condition:raise ValueError(code)


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()


def path(value):
    require(type(value) is str and value.startswith('/') and value!='/' and len(value)<=4096
            and str(PurePosixPath(value))==value and '..' not in PurePosixPath(value).parts
            and not any(ord(c)<32 or ord(c)==127 for c in value),'CANONICAL_INSTALLATION_PATH_REQUIRED')
    return value


def env(actual):
    rows=actual['Config'].get('Env')
    if rows is None:rows=[]
    require(type(rows) is list and len(rows)<=512,'TYPED_INSTALLATION_ENV_REQUIRED')
    values={}
    for row in rows:
        require(type(row) is str and '=' in row and len(row)<=1048576,'TYPED_INSTALLATION_ENV_REQUIRED')
        key,value=row.split('=',1)
        require(re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,127}',key) and key not in values,
                'UNIQUE_INSTALLATION_ENV_REQUIRED')
        values[key]=value
    return values


def https(value):
    require(type(value) is str and 0<len(value)<=2048,'CONFIGURED_HTTPS_REFERENCE_REQUIRED')
    u=urlsplit(value)
    require(u.scheme=='https' and u.hostname and u.username is None and u.password is None
            and not u.query and not u.fragment and not any(c in value for c in ('\\',' ','%','\n','\r')),
            'CONFIGURED_HTTPS_REFERENCE_REQUIRED')
    return value


def coverage(file_path,mounts):
    wanted=path(file_path)
    require(type(mounts) is list and len(mounts)<=64,'BOUNDED_INSTALLATION_MOUNTS_REQUIRED')
    exact=[];parents=[]
    for row in mounts:
        destination=path(row['Destination'])
        require(type(row.get('RW')) is bool and row.get('Type') in ('bind','volume','tmpfs'),
                'TYPED_INSTALLATION_MOUNT_REQUIRED')
        if wanted==destination:exact.append(row)
        elif wanted.startswith(destination+'/'):parents.append(row)
    require(len(exact)<=1,'AMBIGUOUS_INSTALLATION_MOUNT_TARGET')
    if exact:
        state='EXACT_READONLY_TARGET_DECLARED' if exact[0]['RW'] is False else 'READWRITE_TARGET_DECLARED'
    elif parents:
        state='ANCESTOR_TARGET_DECLARED_DIRECTORY_TYPE_AND_FILE_CUSTODY_UNPROVEN'
    else:state='NO_COVERING_MOUNT_DECLARED'
    return {'path':wanted,'state':state,'fileExistenceProven':False,'credentialCustodyProven':False}


def compile_audit(inputs,binding,selection):
    require(type(inputs) is dict and inputs.get('schema')==SCHEMA
        and type(binding) is dict and set(binding)=={'path','sha256'}
        and re.fullmatch('[0-9a-f]{64}',binding['sha256']) and digest(inputs)==binding['sha256'],
        'HASH_BOUND_PRIVATE_INSTALLATION_INPUTS_REQUIRED')
    path(binding['path'])
    require(all(inputs.get(k) is False for k in ('historicalAuthorityReused','runtimeAuthorityIssued','automaticReplayAllowed','budgetReset')),
            'CAPTURE_IS_PROVENANCE_NOT_AUTHORITY')
    observations=inputs['observations'];pins=inputs['processPins']
    require(set(observations)==set(pins)==ROLES and len({r['Id'] for r in observations.values()})==4,
            'EXACT_FOUR_INSTALLATION_ROLES_REQUIRED')
    require(type(selection) is dict and set(selection)=={'discoveryOwnerKeyEnvironmentName'},
            'EXACT_DISCOVERY_KEY_REFERENCE_SELECTION_REQUIRED')
    key_name=selection['discoveryOwnerKeyEnvironmentName']
    require(type(key_name) is str and re.fullmatch('[A-Z][A-Z0-9_]{0,112}_OWNER_KEY',key_name)
        and key_name not in KEY_REFERENCE_NAMES,'DISTINCT_DISCOVERY_OWNER_KEY_REFERENCE_REQUIRED')
    values={role:env(actual) for role,actual in observations.items()}
    for role,actual in observations.items():
        require(re.fullmatch('[0-9a-f]{64}',actual['Id']) and re.fullmatch('sha256:[0-9a-f]{64}',actual['Image'])
            and actual['State']['Running'] is True and actual['State']['Paused'] is False
            and actual['State']['Pid']==pins[role]['pid'],'CURRENT_CAPTURE_GENERATION_REQUIRED')
    semantic=values['semantic'];mcp=values['mcp']
    secret=coverage(semantic['OUF_SCHEMA_GOV_CLIENT_SECRET_FILE'],observations['semantic']['Mounts'])
    receipt_key=coverage(semantic['OUF_SEMANTIC_DISCOVERY_DELEGATION_KEY_FILE'],observations['semantic']['Mounts'])
    require(secret['path']!=receipt_key['path'],'DISTINCT_PROVIDER_CREDENTIAL_AND_RECEIPT_KEY_REQUIRED')
    mcp_secret=coverage(mcp['MCP_OIDC_CLIENT_SECRET_FILE'],observations['mcp']['Mounts'])
    provider={name:https(semantic[name]) for name in ('OUF_IAM_ISSUER','OUF_SCHEMA_GOV_GATEWAY_BASE_URL','OUF_SCHEMA_GOV_TOKEN_ENDPOINT')}
    for name in ('OUF_SCHEMA_GOV_CLIENT_ID','OUF_IAM_AUDIENCE','OUF_SCHEMA_GOV_WORKLOAD_SCOPE','OUF_SEMANTIC_DISCOVERY_DELEGATION_WORKLOAD'):
        value=semantic[name]
        require(type(value) is str and re.fullmatch('[A-Za-z0-9._:/@-]+( [A-Za-z0-9._:/@-]+)*',value),
                'CONFIGURED_IDENTITY_AND_SCOPE_REQUIRED')
        provider[name]=value
    provider['OUF_SCHEMA_GOV_SEARCH_PATH']=path(semantic['OUF_SCHEMA_GOV_SEARCH_PATH'])
    provider['OUF_SCHEMA_GOV_FETCH_PATH']=path(semantic['OUF_SCHEMA_GOV_FETCH_PATH'])
    require(semantic['OUF_SEMANTIC_DISCOVERY_DELEGATION_WORKLOAD']==mcp['MCP_OIDC_CLIENT_ID'],
            'DISCOVERY_OWNER_AND_MCP_WORKLOAD_MUST_AGREE')
    mcp_references={k:https(mcp[k]) for k in ('MCP_GATEWAY_ENDPOINT','MCP_GATEWAY_RECOVERY_ENDPOINT',
        'MCP_AUTHORIZATION_BUNDLE_ENDPOINT','MCP_OIDC_TOKEN_ENDPOINT')}
    # State is a declaration only; the actual replacement needs a separately qualified
    # full-frame/credential/DB/provider admission and fresh current native authority.
    blocking=['CURRENT_FULL_COHORT_AND_NATIVE_FRAME_ADMISSION_REQUIRED','CURRENT_PROVIDER_GATEWAY_TLS_AND_ADMISSION_REQUIRED',
        'CURRENT_CREDENTIAL_OWNER_AND_RENEWAL_REVIEW_REQUIRED','REGISTRY_V11_V12_BACKUP_AND_DATABASE_ADMISSION_REQUIRED',
        'GOVERNED_DESCRIPTOR_SCOPE_ROLE_PUBLICATION_REQUIRED','RESTART_REBOOT_ROTATION_AND_TWO_CLIENT_EVIDENCE_REQUIRED']
    if secret['state']!='EXACT_READONLY_TARGET_DECLARED':blocking.append('PROVIDER_CLIENT_SECRET_MOUNT_BINDING_REQUIRED')
    if receipt_key['state']!='EXACT_READONLY_TARGET_DECLARED':blocking.append('REGISTRY_DISCOVERY_RECEIPT_KEY_MOUNT_BINDING_REQUIRED')
    key_state='EXISTING_REFERENCE_REQUIRES_CUSTODY_AND_PURPOSE_REVIEW' if key_name in values['apisix'] else 'NEW_REFERENCE_REQUIRED'
    blocking.append('APISIX_DISTINCT_DISCOVERY_RECEIPT_KEY_CUSTODY_REQUIRED')
    return {'schema':'ouf.m2-discovery-installation-audit.v1',
        'status':'PERSISTENT_INSTALLATION_REVIEW_REQUIRED','inputBinding':copy.deepcopy(binding),
        'generationHashes':{role:digest(pins[role]) for role in sorted(pins)},
        'providerDeclaredReferences':provider,'mcpDeclaredReferences':mcp_references,
        'providerCredential':secret,'registryReceiptKey':receipt_key,'mcpCredential':mcp_secret,
        'gatewayReceiptKey':{'environmentName':key_name,'state':key_state,'valueRead':False},
        'featureDeclarations':{k:semantic.get(k) if semantic.get(k) in ('true','false') else 'UNRECOGNIZED_OR_ABSENT'
            for k in ('OUF_SCHEMA_GOV_ENABLED','OUF_DISCOVERY_WORKER_ENABLED','OUF_IAM_ENABLED','OUF_SCHEMA_GOV_GATEWAY_AUTH_ENABLED')},
        'blockingRequirements':blocking,'otherNinePeersProvenCurrent':False,
        'effectiveConfigurationProven':False,'credentialCustodyProven':False,'providerReadinessProven':False,
        'databaseAdmissionProven':False,'fileOnlyProfileCanAuthorizeDiscovery':False,
        'nativeExecutionAllowed':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
        'automaticReplayAllowed':False,'budgetReset':False,'stableCapabilitiesOperationalProven':False,
        'applicationE2EProven':False,'releaseAcceptance':False}
