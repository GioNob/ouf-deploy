"""Independent discovery launch proposal; no custody, admission or execution.

The file-only profile remains unchanged and cannot accept this profile. Explicit
owner selections add provider credentials, TLS and a separate discovery MAC key.
This code reads no secret bytes and never turns a captured generation into an
authority. Runtime adapters must still obtain current native acceptance.
"""
import copy
import hashlib
import re
from pathlib import PurePosixPath
from urllib.parse import urlsplit

from tools.semantic_frame_compiler.compile_creation_frame_policy import canonical, environment, require
from tools.semantic_application_cutover.gated_creation_plan import ENTRY
from tools.semantic_application_cutover.transition_journal import PHASES

PROFILE = 'ouf.semantic-discovery-native-proposal.v1'
JAVA = ['java', '-XX:MaxRAMPercentage=75', '-jar', '/app/application.jar']
FILE_ROLES = ('consultationKey', 'proposalReceiptKey', 'providerCredential', 'discoveryReceiptKey', 'tlsTrustStore')
IDENTITY_KEYS = ('OUF_IAM_ISSUER', 'OUF_IAM_AUDIENCE', 'OUF_SCHEMA_GOV_CLIENT_ID',
                 'OUF_SCHEMA_GOV_TOKEN_ENDPOINT', 'OUF_SCHEMA_GOV_WORKLOAD_SCOPE',
                 'OUF_SCHEMA_GOV_GATEWAY_BASE_URL', 'OUF_SCHEMA_GOV_SEARCH_PATH',
                 'OUF_SCHEMA_GOV_FETCH_PATH', 'OUF_SEMANTIC_DISCOVERY_DELEGATION_WORKLOAD')
FLAGS = {'OUF_SCHEMA_GOV_ENABLED': 'true', 'OUF_DISCOVERY_WORKER_ENABLED': 'true',
         'OUF_IAM_ENABLED': 'true', 'OUF_SCHEMA_GOV_GATEWAY_AUTH_ENABLED': 'true'}
FILE_ENV = {'consultationKey': 'OUF_SEMANTIC_DELEGATION_KEY_FILE',
            'proposalReceiptKey': 'OUF_SEMANTIC_PROPOSAL_RECEIPT_KEY_FILE',
            'providerCredential': 'OUF_SCHEMA_GOV_CLIENT_SECRET_FILE',
            'discoveryReceiptKey': 'OUF_SEMANTIC_DISCOVERY_DELEGATION_KEY_FILE'}
FORBIDDEN_ENV = {'JDK_JAVA_OPTIONS', '_JAVA_OPTIONS', 'JAVA_OPTS', 'SPRING_APPLICATION_JSON',
                 'OUF_AUTHORIZATION_REGISTRY_TOKEN', 'OUF_SCHEMA_GOV_CLIENT_SECRET', 'OUF_SEM_DB_PASSWORD',
                 'OUF_SEMANTIC_DELEGATION_KEY', 'OUF_SEMANTIC_PROPOSAL_RECEIPT_KEY',
                 'OUF_SEMANTIC_DISCOVERY_DELEGATION_KEY'}
RUNTIME_ENV = {'PATH', 'JAVA_HOME', 'JAVA_VERSION', 'LANG', 'LANGUAGE', 'LC_ALL', 'TZ', 'PORT'}


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def hash_value(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def path(value):
    require(type(value) is str and value.startswith('/') and value != '/' and len(value) <= 4096
            and str(PurePosixPath(value)) == value and '..' not in value.split('/')
            and not any(ord(c) < 33 or ord(c) == 127 or c in ':,$\\' for c in value),
            'DISCOVERY_CANONICAL_PRIVATE_PATH_REQUIRED')
    return value


def https(value):
    require(type(value) is str and 0 < len(value) <= 2048, 'DISCOVERY_HTTPS_REFERENCE_REQUIRED')
    u = urlsplit(value)
    require(u.scheme == 'https' and u.hostname and u.username is None and u.password is None
            and not u.query and not u.fragment and not any(ord(c) < 33 or ord(c) == 127 or c in '\\%' for c in value),
            'DISCOVERY_HTTPS_REFERENCE_REQUIRED')
    return value


def identity_references(value):
    require(type(value) is dict and set(value) == set(IDENTITY_KEYS), 'EXACT_DISCOVERY_IDENTITY_REFERENCES_REQUIRED')
    result = copy.deepcopy(value)
    for k in IDENTITY_KEYS:
        if k in ('OUF_IAM_ISSUER', 'OUF_SCHEMA_GOV_TOKEN_ENDPOINT', 'OUF_SCHEMA_GOV_GATEWAY_BASE_URL'):
            https(value[k])
        elif k.endswith('_PATH'):
            path(value[k])
        else:
            require(type(value[k]) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}', value[k]),
                    'EXACT_DISCOVERY_IDENTITY_OR_SINGLE_SCOPE_REQUIRED')
    require(value['OUF_SCHEMA_GOV_SEARCH_PATH'] != value['OUF_SCHEMA_GOV_FETCH_PATH'],
            'DISTINCT_PROVIDER_SEARCH_AND_FETCH_PATHS_REQUIRED')
    return result


def file_bindings(value):
    require(type(value) is dict and set(value) == set(FILE_ROLES), 'EXACT_DISCOVERY_FILE_ROLES_REQUIRED')
    fields = {'source', 'target', 'readOnly', 'uid', 'gid', 'mode', 'maxBytes', 'sha256', 'metadataHash'}
    for role, f in value.items():
        require(type(f) is dict and set(f) == fields, 'EXACT_DISCOVERY_FILE_BINDING_REQUIRED')
        path(f['source']); path(f['target'])
        consultation = role == 'consultationKey'
        maximum = 1048576 if role == 'tlsTrustStore' else 4096 if role == 'providerCredential' else 65
        require(f['readOnly'] is True and type(f['uid']) is int and f['uid'] == (10001 if consultation else 0)
                and type(f['gid']) is int and f['gid'] == 10001
                and type(f['mode']) is int and f['mode'] == (0o400 if consultation else 0o440)
                and type(f['maxBytes']) is int and 1 <= f['maxBytes'] <= maximum
                and hash_value(f['sha256']) and hash_value(f['metadataHash']),
                'DISCOVERY_PRIVATE_FILE_CUSTODY_DECLARATION_REQUIRED')
    # Different paths alone would permit accidental reuse of the same MAC key.
    key_hashes = [value[k]['sha256'] for k in ('consultationKey', 'proposalReceiptKey', 'discoveryReceiptKey')]
    require(len(set(key_hashes)) == 3 and value['providerCredential']['sha256'] not in key_hashes,
            'DISTINCT_DISCOVERY_PROVIDER_AND_MAC_KEY_CONTENT_IDENTITIES_REQUIRED')
    return copy.deepcopy(value)


def directories(tree, token):
    fields = {'source', 'target', 'readOnly', 'uid', 'gid', 'directoryMode', 'fileName', 'fileMode', 'maxBytes', 'sha256'}
    require(type(tree) is dict and set(tree) == fields and tree['fileName'] == 'OUF_SEM_DB_PASSWORD'
            and tree['readOnly'] is True and type(tree['uid']) is int and type(tree['gid']) is int
            and tree['uid'] == tree['gid'] == 10001 and tree['directoryMode'] == 0o500 and tree['fileMode'] == 0o400
            and type(tree['maxBytes']) is int and 1 <= tree['maxBytes'] <= 1048576 and hash_value(tree['sha256']),
            'DISCOVERY_DATABASE_ONLY_CONFIGTREE_REQUIRED')
    fields = {'source', 'target', 'fileName', 'gid', 'directoryDevice', 'directoryInode',
              'ownerBindingHash', 'maxBytes', 'minimumRemainingSeconds'}
    require(type(token) is dict and set(token) == fields and type(token['gid']) is int and token['gid'] == 10001
            and type(token['fileName']) is str and re.fullmatch('[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}', token['fileName'])
            and type(token['directoryDevice']) is int and token['directoryDevice'] >= 0
            and type(token['directoryInode']) is int and token['directoryInode'] > 0
            and type(token['maxBytes']) is int and 1 <= token['maxBytes'] <= 16384
            and type(token['minimumRemainingSeconds']) is int and 1 <= token['minimumRemainingSeconds'] <= 3600
            and hash_value(token['ownerBindingHash']), 'DISCOVERY_CURRENT_RENEWABLE_TOKEN_CUSTODY_DECLARATION_REQUIRED')
    for d in (tree, token):
        path(d['source']); path(d['target'])


def manifest_bindings(files, tree, token):
    return [{k: files[role][k] for k in ('source', 'target', 'readOnly')} for role in FILE_ROLES] + [
        {k: tree[k] for k in ('source', 'target', 'readOnly')},
        {'source': token['source'], 'target': token['target'], 'readOnly': True}]


def compile_profile(request, *, preserved_environment, references, files, configtree, renewable_token, mcp_workload):
    require(type(request) is dict and len(canonical(request)) <= 131072, 'BOUNDED_DISCOVERY_CREATION_REQUEST_REQUIRED')
    require(set(request) <= {'Image', 'User', 'Entrypoint', 'Cmd', 'Env', 'WorkingDir', 'HostConfig',
            'NetworkingConfig', 'Tty', 'Hostname', 'Domainname', 'Volumes', 'Labels', 'ExposedPorts'},
            'UNKNOWN_DISCOVERY_CREATION_FIELD_DENIED')
    require(type(request.get('Image')) is str and re.fullmatch('sha256:[0-9a-f]{64}', request['Image'])
            and request.get('User') == '10001:10001', 'PINNED_DISCOVERY_IMAGE_AND_NONROOT_USER_REQUIRED')
    require(request.get('Entrypoint') == ENTRY and request.get('Cmd') == JAVA,
            'DISCOVERY_REQUIRES_EXACT_PREAPPLICATION_GATE')
    refs = identity_references(references); fs = file_bindings(files)
    directories(configtree, renewable_token)
    require(type(mcp_workload) is str and mcp_workload == refs['OUF_SEMANTIC_DISCOVERY_DELEGATION_WORKLOAD'],
            'DISCOVERY_AND_SELECTED_MCP_WORKLOAD_MUST_AGREE')
    before = environment(preserved_environment); env = environment(request.get('Env'))
    expected = {**before, **refs, **FLAGS,
                **{key: fs[role]['target'] for role, key in FILE_ENV.items()},
                'SPRING_CONFIG_IMPORT': 'configtree:' + configtree['target'] + '/',
                'OUF_AUTHORIZATION_REGISTRY_TOKEN_FILE': renewable_token['target'] + '/' + renewable_token['fileName'],
                'JAVA_TOOL_OPTIONS': '-Djavax.net.ssl.trustStore=' + fs['tlsTrustStore']['target']
                    + ' -Djavax.net.ssl.trustStoreType=PKCS12 -Djavax.net.ssl.trustStorePassword=changeit'}
    require(env == expected, 'DISCOVERY_ENVIRONMENT_MUST_PRESERVE_UNRELATED_SETTINGS_EXACTLY')
    require(bool(env.get('PATH')) and 'HOSTNAME' not in env
            and all(k in RUNTIME_ENV or k == 'JAVA_TOOL_OPTIONS' or k.startswith(('OUF_', 'SPRING_', 'MANAGEMENT_')) for k in env),
            'DISCOVERY_REVIEWED_RUNTIME_ENVIRONMENT_REQUIRED')
    require(not set(env) & FORBIDDEN_ENV
            and not any(k.startswith('SPRING_') and k != 'SPRING_CONFIG_IMPORT' for k in env),
            'DISCOVERY_CONFIGURATION_OVERRIDE_CHANNEL_DENIED')
    aliases = ('oufsemanticprovidersschemagov', 'oufsemanticdiscoveryworker')
    require(not any(k.lower().replace('_', '').startswith(aliases) for k in env), 'DISCOVERY_FEATURE_ALIAS_OVERRIDE_DENIED')
    require(env.get('OUF_SEMANTIC_DELEGATION_WORKLOAD') == mcp_workload
            and env.get('OUF_SEMANTIC_PROPOSAL_RECEIPT_WORKLOAD') == mcp_workload,
            'PRESERVED_READ_AND_PROPOSAL_WORKLOADS_MUST_AGREE')
    https(env.get('OUF_AUTHORIZATION_REGISTRY_URL'))
    host = request.get('HostConfig'); network = request.get('NetworkingConfig')
    require(type(host) is dict and type(network) is dict and type(network.get('EndpointsConfig')) is dict
            and len(network['EndpointsConfig']) == 1, 'ONE_EXPLICIT_DISCOVERY_PRIVATE_BRIDGE_REQUIRED')
    name, endpoint = next(iter(network['EndpointsConfig'].items()))
    mode = host.get('NetworkMode')
    require(type(name) is str and bool(name) and type(endpoint) is dict and type(mode) is str
            and mode in (name, endpoint.get('NetworkID')) and mode not in ('host', 'none', 'default', 'bridge')
            and not mode.startswith('container:'), 'ONE_EXPLICIT_DISCOVERY_PRIVATE_BRIDGE_REQUIRED')
    require(host.get('RestartPolicy') == {'Name': 'no', 'MaximumRetryCount': 0}
            and host.get('Privileged', False) is False and host.get('CapDrop') == ['ALL'] and not host.get('CapAdd')
            and host.get('SecurityOpt') == ['no-new-privileges:true'] and host.get('Runtime', 'runc') == 'runc'
            and all(host.get(k) in (None, '') for k in ('PidMode', 'IpcMode', 'UTSMode', 'CgroupnsMode'))
            and not any(host.get(k) for k in ('Devices', 'DeviceRequests', 'GroupAdd', 'VolumesFrom', 'Links',
                'PortBindings', 'ExtraHosts', 'Sysctls', 'Ulimits', 'Binds', 'Tmpfs')),
            'DISCOVERY_NONPRIVILEGED_FENCED_HOST_REQUIRED')
    require(set(host) <= {'NetworkMode', 'RestartPolicy', 'Privileged', 'CapDrop', 'CapAdd', 'SecurityOpt', 'Runtime',
            'PidMode', 'IpcMode', 'UTSMode', 'CgroupnsMode', 'Devices', 'DeviceRequests', 'GroupAdd', 'VolumesFrom',
            'Links', 'PortBindings', 'ExtraHosts', 'Sysctls', 'Ulimits', 'Binds', 'Tmpfs', 'ReadonlyRootfs',
            'Memory', 'MemorySwap', 'PidsLimit', 'NanoCpus', 'Mounts'}, 'UNKNOWN_DISCOVERY_HOST_FIELD_DENIED')
    require(request.get('Tty', False) is False and request.get('Hostname') in (None, '')
            and request.get('Domainname') in (None, '') and not request.get('Volumes')
            and request.get('WorkingDir') == '/app', 'DISCOVERY_EXACT_PROCESS_CONFIGURATION_REQUIRED')
    require(type(host.get('Memory')) is int and 0 < host['Memory'] == host.get('MemorySwap') <= 8589934592
            and type(host.get('PidsLimit')) is int and 1 <= host['PidsLimit'] <= 4096
            and type(host.get('NanoCpus')) is int and 0 < host['NanoCpus'] <= 8000000000
            and host['NanoCpus'] % 10000 == 0, 'FINITE_DISCOVERY_RESOURCE_BOUNDS_REQUIRED')
    bindings = manifest_bindings(fs, configtree, renewable_token)
    require(len({b['source'] for b in bindings}) == len({b['target'] for b in bindings}) == 7
            and not any(a[k].startswith(b[k] + '/') for a in bindings for b in bindings if a is not b for k in ('source', 'target')),
            'DISTINCT_NONSHADOWING_DISCOVERY_MOUNTS_REQUIRED')
    wanted = [{'Type': 'bind', 'Source': b['source'], 'Target': b['target'], 'ReadOnly': True} for b in bindings]
    require(host.get('Mounts') == wanted, 'EXACT_DISCOVERY_READONLY_MOUNT_SET_REQUIRED')
    return {'schema': 'ouf.semantic-discovery-execution-proposal.v1', 'deploymentProfile': PROFILE,
            'creationRequestHash': digest(request), 'preservedEnvironmentHash': digest(preserved_environment),
            'identityReferencesHash': digest(refs), 'fileBindingsHash': digest(fs),
            'databaseConfigtreeHash': digest(configtree), 'renewableTokenHash': digest(renewable_token),
            'enabledFeatures': copy.deepcopy(FLAGS), 'phaseOrder': list(PHASES),
            'requiredNativeAdmissions': ['FULL_CURRENT_COHORT', 'COMPLETE_OCI_AND_MOUNT_CUSTODY',
                'DATABASE_V11_V12_BACKUP_FENCE', 'PROVIDER_TLS_NETWORK_AND_WORKLOAD',
                'DISTINCT_GATEWAY_REGISTRY_DISCOVERY_KEY', 'GOVERNED_CAPABILITY_SCOPE_ROLE_PUBLICATION'],
            'bootReentry': 'FRESH_CURRENT_AUTHORITY_AND_GENERATION_ADMISSION',
            'credentialRotation': 'FENCED_COORDINATED_NATIVE_REPLACEMENT_PRESERVING_INCIDENT_HISTORY',
            'newDistinctLeaseWorkerRequired': True,
            'nativeExecutorIntegrated': False, 'externalProviderCallsAllowed': False,
            'runtimeAuthorityIssued': False, 'targetApplyAuthorized': False,
            'automaticReplayAllowed': False, 'budgetReset': False, 'releaseAcceptance': False}


class DiscoveryProfile:
    """Typed proposal, deliberately rejected by the existing file-only executor."""
    def __init__(self, request, **selection):
        self.request = copy.deepcopy(request)
        self.selection = copy.deepcopy(selection)
        self.compiled = compile_profile(self.request, **self.selection)
        self.sha256 = digest(self.compiled)

    def verify(self, request):
        require(type(request) is dict and digest(request) == self.compiled['creationRequestHash']
                and compile_profile(request, **self.selection) == self.compiled
                and digest(self.compiled) == self.sha256, 'DISCOVERY_REVIEWED_PROFILE_OR_REQUEST_DRIFT')
        return self.sha256
