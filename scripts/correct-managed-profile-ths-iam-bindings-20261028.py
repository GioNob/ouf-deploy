#!/usr/bin/env python3
"""One exact reviewed additive IAM correction, with same-effect reconciliation.
No old authentication/authority reuse and no runtime configuration APPLY.
"""
import base64,copy,hashlib,http.client,ipaddress,json,os,pwd,random,re,resource,select,signal,socket,stat,struct,subprocess,sys,termios,time,types,uuid
from pathlib import Path
from urllib.parse import urlsplit
MAXIMUMS={'engineGets':7,'privateMetadataReads':3,'responseBytes':2097152,'totalBytes':25165824,'seconds':600}
CASE={'adminEndpoint': {'adminClientId': 'admin-cli',
                   'adminRealm': 'master',
                   'connectHost': '127.0.0.1',
                   'connectPort': 8080,
                   'expectedAdminUser': 'oufadmin',
                   'storedServerUrl': 'http://localhost:8080'},
 'adminEndpointProvenance': '3b205c44e983184e90baf31230b7f5ec1affb6b7:releases/iam-explicit-api-case-20261021.json; '
                            'retained installation transport, not a portable default',
 'clientId': 'ouf-authorization-ths',
 'expectedEngineVersion': '29.8.1',
 'expectedObservation': {'bindingAndUnrestrictedEligibilityProven': False,
                         'bindingSnapshotHash': 'ba556e9fce5fb31de5f53af0bf6d3fe7a77e8e09d9048529d8283eaaa6afabc2',
                         'blockedScopes': ['ouf.managed-source.preview',
                                           'ouf.managed-source.file.profile',
                                           'ouf.onboarding.quarantine.release'],
                         'clientId': 'ouf-authorization-ths',
                         'clientUuid': 'a53bc77e-1b21-4a54-8f1a-b236fadb759a',
                         'defaultScopeCount': 14,
                         'definitionCount': 69,
                         'effectiveBrowserTokenScopesProven': False,
                         'iamMutations': 0,
                         'newGrantsGranted': 0,
                         'optionalScopeCount': 6,
                         'requiredScopes': [{'binding': 'NONE',
                                             'defined': True,
                                             'eligibleForExplicitRequest': False,
                                             'id': 'e369f8fd-fe4d-4fa2-8ff2-4cd806398417',
                                             'includeInTokenScope': True,
                                             'includeInTokenScopeAttribute': 'true',
                                             'name': 'ouf.managed-source.preview',
                                             'roleMappingsObserved': True,
                                             'unrestrictedByScopeRoleMappings': True},
                                            {'binding': 'NONE',
                                             'defined': True,
                                             'eligibleForExplicitRequest': False,
                                             'id': '226b20cd-7798-4da9-af03-eb2bca3d2c5a',
                                             'includeInTokenScope': True,
                                             'includeInTokenScopeAttribute': 'true',
                                             'name': 'ouf.managed-source.file.profile',
                                             'roleMappingsObserved': True,
                                             'unrestrictedByScopeRoleMappings': True},
                                            {'binding': 'NONE',
                                             'defined': False,
                                             'eligibleForExplicitRequest': False,
                                             'id': None,
                                             'includeInTokenScope': None,
                                             'includeInTokenScopeAttribute': None,
                                             'name': 'ouf.onboarding.quarantine.release',
                                             'roleMappingsObserved': False,
                                             'unrestrictedByScopeRoleMappings': False}],
                         'schema': 'ouf.ths-oidc-client-binding-observation.v1'},
 'iamContainerName': '/ouf-keycloak',
 'inputsHash': '5dfd7b7a903c07f546c42ba1915bf6f8fd1430ab91addc4879988cd4c1727892',
 'installationRef': 'ouf-lab-validated-ths-recovery-20261028',
 'issuer': 'https://auth.ouf-lab.it/realms/ouf',
 'outputRoot': '/etc/ouf/deploy-snapshots/managed-profile-ths-iam-binding-correction-ba556e9f-20261028-v1',
 'overlaySha256': '6d546047448495746d7eaad6d83e7942fa2950f137d4a240a3aef9309f7f39be',
 'parentResultHash': 'bfbff1b10039bcca43ad587167bb0fe4314055866c214926daaf4c2570f3fa7b',
 'parentRoot': '/etc/ouf/deploy-snapshots/managed-profile-ths-iam-binding-read-5dfd7b7a-20261028-v1',
 'priorCounts': {'bytes': 695761, 'configurationFileContentReads': 1, 'engineGets': 5, 'privateMetadataReads': 3},
 'priorInputsHash': 'fdc618841f14eeb0c99ee3f61f0971affefff5f13d740d406db376d3daaa7bec',
 'priorRoot': '/etc/ouf/deploy-snapshots/managed-profile-ths-client-selection-fdc61884-20261028-v1',
 'realm': 'ouf'}

class Stop(Exception):
    pass

def require(value, code):
    if not value:
        raise Stop(code)

def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()

def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()

def decode(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, 'DUPLICATE_PRIVATE_KEY')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(Stop('NONFINITE_PRIVATE_JSON')))

def frame(info):
    return tuple(getattr(info, k) for k in ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))

def ancestry(path):
    require(path.is_absolute() and path.resolve() == path and '..' not in path.parts, 'CANONICAL_ROOT_PATH_REQUIRED')
    for parent in (path, *path.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022, 'PROTECTED_ROOT_ANCESTRY_REQUIRED')

class Capture:
    def __init__(self, root, cohort_size, reconcile=False):
        require(type(cohort_size) is int and 1 <= cohort_size <= 32, 'BOUNDED_CAPTURE_COHORT_REQUIRED')
        require(type(reconcile) is bool, 'EXPLICIT_RECONCILIATION_MODE_REQUIRED')
        self.maximums = {**MAXIMUMS, 'engineGets': 1 + 2*cohort_size,
                         'privateMetadataReads': 5 if reconcile else 3}
        self.root = Path(root)
        ancestry(self.root.parent)
        require(not os.path.lexists(self.root), 'CSV_RECOVERY_CAPTURE_CONSUMED_NO_REPLAY')
        os.mkdir(self.root, 0o700)
        os.chmod(self.root, 0o700)
        self.counts = {'engineGets': 0, 'privateMetadataReads': 0, 'bytes': 0}
        self.seals = {}
        self.sync(self.root.parent)
        self.put('claim.json', {'schema': 'ouf.managed-csv-recovery-input-capture-claim.v1', 'maximums': self.maximums,
                               'containerWrites': 0, 'automaticReplayAllowed': False, 'budgetReset': False})

    def sync(self, path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def put(self, name, value):
        require(re.fullmatch(r'[a-z0-9-]+\.json', name) is not None, 'CLOSED_CAPTURE_FILENAME_REQUIRED')
        fd = os.open(self.root/name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as out:
            os.fchmod(out.fileno(), 0o600)
            out.write(encoded(value)); out.flush(); os.fsync(out.fileno())
        self.sync(self.root)

    def private(self, path, expected=None):
        require(self.counts['privateMetadataReads'] < self.maximums['privateMetadataReads'], 'PRIVATE_CAPTURE_READ_LIMIT')
        self.counts['privateMetadataReads'] += 1
        path = Path(path)
        self.put('private-read-'+str(self.counts['privateMetadataReads'])+'-claim.json', {'path': str(path), 'attemptNotCompletion': True})
        ancestry(path.parent)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0 and before.st_nlink == 1
                    and stat.S_IMODE(before.st_mode) in (0o400, 0o600) and 0 < before.st_size <= 6*1024*1024, 'SEALED_PRIVATE_CAPTURE_INPUT_REQUIRED')
            raw = b''
            while len(raw) <= before.st_size:
                part = os.read(fd, min(65536, before.st_size+1-len(raw)))
                if not part:
                    break
                raw += part
            require(len(raw) == before.st_size and frame(before) == frame(os.fstat(fd)) == frame(path.lstat()), 'CAPTURE_HISTORY_CHANGED')
            require(expected is None or hashlib.sha256(raw).hexdigest() == expected, 'EXACT_INSTALLED_CAPTURE_HASH_REQUIRED')
            self.counts['bytes'] += len(raw)
            require(self.counts['bytes'] <= MAXIMUMS['totalBytes'], 'PRIVATE_CAPTURE_BYTE_LIMIT')
            value = decode(raw)
            self.seals[str(path)] = {'metadata': list(frame(before)), 'sha256': hashlib.sha256(raw).hexdigest()}
            return value
        finally:
            os.close(fd)

def process_pin(pid):
    require(type(pid) is int and pid >= 1, 'POSITIVE_CAPTURE_PID_REQUIRED')
    raw = Path('/proc/'+str(pid)+'/stat').read_bytes()
    require(0 < len(raw) < 16384 and b') ' in raw, 'BOUNDED_CAPTURE_PROCESS_REQUIRED')
    namespaces = {}
    for name in ('net', 'mnt'):
        info = Path('/proc/'+str(pid)+'/ns/'+name).stat()
        namespaces[name] = [info.st_dev, info.st_ino]
    return {'pid': pid, 'startTicks': int(raw.rsplit(b') ', 1)[1].split()[19]), 'namespaces': namespaces}

def stable_binding(actual):
    return {'containerId': actual['Id'], 'imageId': actual['Image'], 'name': actual['Name'], 'pid': actual['State']['Pid'], 'startedAt': actual['State']['StartedAt'],
            'configHash': digest(actual['Config']), 'hostConfigHash': digest(actual['HostConfig']),
            'mountsHash': digest(sorted(actual['Mounts'], key=lambda v: v['Destination'])), 'networkSettingsHash': digest(actual['NetworkSettings']),
            'profile': 'ouf.acquisition-read.mount-set-binding.v1'}

class Engine:
    def __init__(self, capture, binding, ids):
        self.capture, self.binding = capture, binding
        require(0 < len(ids) <= 32 and len(set(ids)) == len(ids) and all(re.fullmatch('[a-f0-9]{64}', cid) for cid in ids), 'EXACT_DISTINCT_COHORT_IDS_REQUIRED')
        self.allowed = {'/v1.44/info'} | {'/v1.44/containers/'+cid+'/json' for cid in ids}

    def get(self, path):
        c = self.capture
        require(path in self.allowed and c.counts['engineGets'] < c.maximums['engineGets'], 'CLOSED_READ_ONLY_ENGINE_CAPTURE_REQUIRED')
        selected = Path(self.binding['socketPath']); ancestry(selected.parent)
        info = selected.lstat()
        require(stat.S_ISSOCK(info.st_mode) and [info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)] == self.binding['socketBinding'], 'EXACT_CAPTURE_ENGINE_SOCKET_REQUIRED')
        c.counts['engineGets'] += 1
        c.put('engine-get-'+str(c.counts['engineGets'])+'-claim.json', {'method': 'GET', 'path': path, 'attemptNotCompletion': True})
        binding = self.binding
        class Local(http.client.HTTPConnection):
            def connect(conn):
                conn.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); conn.sock.settimeout(4); conn.sock.connect(str(selected))
                peer = list(struct.unpack('3i', conn.sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)))
                require(peer == binding['peerCredentials'] and peer[1] == 0, 'EXACT_CAPTURE_ROOT_ENGINE_PEER_REQUIRED')
        conn = Local('root-local-engine', timeout=4)
        try:
            conn.request('GET', path, headers={'Connection': 'close'})
            response = conn.getresponse(); raw = response.read(MAXIMUMS['responseBytes']+1)
            c.counts['bytes'] += len(raw)
            require(response.status == 200 and 0 < len(raw) <= MAXIMUMS['responseBytes'] and c.counts['bytes'] <= MAXIMUMS['totalBytes'], 'BOUNDED_SUCCESSFUL_ENGINE_CAPTURE_REQUIRED')
            value = decode(raw)
            c.put('engine-get-'+str(c.counts['engineGets'])+'-response.json', value)
            return value
        finally:
            conn.close()

class Logger:
    def __init__(self, path):
        self.original = sys.stdout
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.fchmod(fd, 0o600)
        self.file = os.fdopen(fd, "w", buffering=1)

    def write(self, value):
        self.file.write(value); self.file.flush(); os.fsync(self.file.fileno())
        return self.original.write(value)

    def flush(self):
        self.file.flush(); os.fsync(self.file.fileno()); self.original.flush()

    def isatty(self):
        return self.original.isatty()

    def fileno(self):
        return self.original.fileno()

"""Additive THS OAuth request contract, reused from the retained Teatri/Resolution patch.

Local transformation only: no IAM binding, token, grant, lifecycle or job action.
Caller must obtain current owner configuration and separate deployment authority.
"""
REQUIRED=('ouf.managed-source.preview','ouf.managed-source.file.profile','ouf.onboarding.quarantine.release')
REGISTRATION='ouf-ths'
SCOPE_PROPERTY='spring.security.oauth2.client.registration.ouf-ths.scope'
CLIENT_PROPERTY='spring.security.oauth2.client.registration.ouf-ths.client-id'

def normalized(key):return re.sub('[^a-z0-9]','',key.lower())

def spring_properties(obj):
    result={};nodes=[0]
    def walk(value,path=()):
        require(type(value)is dict and len(path)<=24,'BOUNDED_SPRING_JSON_OBJECT_REQUIRED')
        for key,item in value.items():
            nodes[0]+=1;require(nodes[0]<=16384 and type(key)is str and 0<len(key)<=512,'BOUNDED_SPRING_PROPERTY_REQUIRED')
            selected=path+(key,)
            if type(item)is dict:walk(item,selected)
            else:
                canonical=normalized('.'.join(selected))
                require(canonical not in result,'AMBIGUOUS_SPRING_JSON_PROPERTY')
                result[canonical]=(selected,item)
    walk(obj);return result

def scope_list(value):
    if type(value)is str:value=[s for s in re.split(r'[\s,]+',value)if s]
    require(type(value)is list and 0<len(value)<=128
            and all(type(s)is str and re.fullmatch('[A-Za-z0-9_.:-]{1,160}',s)for s in value) and len(value)==len(set(value)),
            'EXACT_EXISTING_THS_SCOPE_LIST_REQUIRED')
    return list(value)

def scope_patch(actual):
    require(type(actual)is dict and type(actual.get('Config'))is dict,'OWNER_CONFIG_REQUIRED')
    config=actual['Config'];values=config.get('Env');require(type(values)is list,'RETAINED_ENVIRONMENT_REQUIRED')
    env={}
    for row in values:
        require(type(row)is str and '='in row,'TYPED_ENVIRONMENT_REQUIRED')
        key,value=row.split('=',1)
        require(re.fullmatch('[A-Za-z_][A-Za-z0-9_]*',key)and key not in env,'UNIQUE_ENVIRONMENT_REQUIRED');env[key]=value
    require(not any(env.get(k)for k in('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','JAVA_OPTS'))
            and not any(type(a)is not str or a.startswith(('-D','--'))for a in(config.get('Entrypoint')or[])+(config.get('Cmd')or[])),
            'UNREVIEWED_OAUTH_REQUEST_ARGUMENT_OVERRIDE')
    require(not any(k.startswith('SPRING_SECURITY_OAUTH2_CLIENT_')for k in env),'DIRECT_OAUTH_ENV_OVERRIDE_REQUIRES_REVIEW')
    require(0<len(env.get('SPRING_APPLICATION_JSON',''))<=1048576,'BOUNDED_EXISTING_SPRING_JSON_REQUIRED')
    original=decode(env['SPRING_APPLICATION_JSON']);properties=spring_properties(original)
    require(normalized(SCOPE_PROPERTY)in properties,'EXPLICIT_SPRING_JSON_SCOPE_OVERRIDE_REQUIRED')
    path,raw_scopes=properties[normalized(SCOPE_PROPERTY)];scopes=scope_list(raw_scopes)
    client=properties.get(normalized(CLIENT_PROPERTY),(None,None))[1]
    require(client is None or type(client)is str and re.fullmatch('[A-Za-z0-9_.:-]{1,128}',client),'LITERAL_CLIENT_ID_REQUIRED')
    missing=[s for s in REQUIRED if s not in scopes]
    proposal=copy.deepcopy(original);cursor=proposal
    for key in path[:-1]:cursor=cursor[key]
    cursor[path[-1]]=scopes+missing if type(raw_scopes)is list else ' '.join(scopes+missing)
    following=spring_properties(proposal)
    require({k:v for k,v in following.items()if k!=normalized(SCOPE_PROPERTY)}=={k:v for k,v in properties.items()if k!=normalized(SCOPE_PROPERTY)},'UNRELATED_SPRING_PROPERTY_CHANGED')
    require(scope_list(following[normalized(SCOPE_PROPERTY)][1])==scopes+missing,'EXACT_ADDITIVE_THS_SCOPE_REQUEST_REQUIRED')
    replacement=json.dumps(proposal,sort_keys=True,separators=(',',':'),allow_nan=False)
    patched=[('SPRING_APPLICATION_JSON='+replacement)if row.startswith('SPRING_APPLICATION_JSON=')else row for row in values] if missing else copy.deepcopy(values)
    require([row for row in patched if not row.startswith('SPRING_APPLICATION_JSON=')]==[row for row in values if not row.startswith('SPRING_APPLICATION_JSON=')],'UNRELATED_ENVIRONMENT_CHANGED')
    summary={'registrationId':REGISTRATION,'clientIdObservedFromJson':client,'clientIdFromLowerPriorityFileRead':False,
             'requestedScopes':scopes,'requiredRecoveryScopes':list(REQUIRED),'missingRequestScopes':missing,
             'retainedScopeCount':len(scopes),'scopeRequestProperty':SCOPE_PROPERTY,
             'requestBeforeHash':digest(original),'conditionalRequestAfterHash':digest(proposal)if missing else digest(original),
             'conditionalConfigurationPatchPrepared':bool(missing),'allOtherEnvironmentAndJsonPropertiesPreserved':True,
             'iamBindingObserved':False,'browserTokenInspected':False,'scopePatchApplied':False,
             'newGrantsGranted':0,'humanBudgetsGranted':0,'resumes':0}
    return summary,patched

def scope_rows(rows):
    require(type(rows)is list and len(rows)<=1024,'BOUNDED_COMPLETE_CLIENT_SCOPE_ROWS_REQUIRED')
    by_name={};ids=set()
    for row in rows:
        require(type(row)is dict and type(row.get('id'))is str and re.fullmatch('[A-Za-z0-9_-]{1,128}',row['id'])
                and type(row.get('name'))is str and re.fullmatch('[A-Za-z0-9_.:-]{1,160}',row['name'])
                and row['id']not in ids and row['name']not in by_name,'DISTINCT_LITERAL_CLIENT_SCOPE_IDENTITIES_REQUIRED')
        attrs=row.get('attributes')or{}
        require(type(attrs)is dict,'CLIENT_SCOPE_ATTRIBUTES_REQUIRED')
        flag=attrs.get('include.in.token.scope')
        require(flag in (None,'true','false'),'TYPED_INCLUDE_IN_TOKEN_SCOPE_REQUIRED')
        # Keycloak ClientScopeModel's documented default is true when absent.
        require(attrs.get('is.dynamic.scope')in(None,'true','false')and attrs.get('is.parameterized.scope')in(None,'true','false'),'TYPED_SCOPE_PARAMETERIZATION_REQUIRED')
        ids.add(row['id']);by_name[row['name']]={'id':row['id'],'name':row['name'],'protocol':row.get('protocol'),
                'includeInTokenScope':flag!='false','includeInTokenScopeAttribute':flag,
                'dynamic':attrs.get('is.dynamic.scope')=='true'or attrs.get('is.parameterized.scope')=='true'}
    return by_name

def binding_report(client,defaults,optionals,definitions,role_mappings,*,expected_client,required=REQUIRED):
    require(type(client)is dict and client.get('clientId')==expected_client and client.get('enabled')is True
            and client.get('protocol')=='openid-connect'and client.get('standardFlowEnabled')is True
            and type(client.get('id'))is str and re.fullmatch('[A-Za-z0-9_-]{1,128}',client['id']),'EXACT_ENABLED_BROWSER_OIDC_CLIENT_REQUIRED')
    d,o,all_scopes=scope_rows(defaults),scope_rows(optionals),scope_rows(definitions)
    require(not(set(d)&set(o))and not({v['id']for v in d.values()}&{v['id']for v in o.values()}),'DISJOINT_DEFAULT_OPTIONAL_CLIENT_BINDINGS_REQUIRED')
    for name,row in {**d,**o}.items():
        require(name in all_scopes and row['id']==all_scopes[name]['id']
                and row['protocol']in(None,all_scopes[name]['protocol']),'ASSIGNED_SCOPE_DEFINITION_IDENTITY_DRIFT')
        # Assignment endpoints return lightweight representations on Keycloak26.
        # An omitted attribute there is not a definition default: eligibility
        # must come from the separately read realm definition of the same UUID.
        if row['includeInTokenScopeAttribute']is not None:
            require(row['includeInTokenScopeAttribute']==all_scopes[name]['includeInTokenScopeAttribute'],'EXPLICIT_ASSIGNED_SCOPE_ATTRIBUTE_DRIFT')
        require(not row['dynamic']or all_scopes[name]['dynamic'],'EXPLICIT_ASSIGNED_SCOPE_PARAMETERIZATION_DRIFT')
    require(type(required)in(tuple,list)and 0<len(required)<=128 and len(set(required))==len(required),'DISTINCT_REQUIRED_SCOPES_REQUIRED')
    rows=[]
    for name in required:
        definition=all_scopes.get(name);mapping=role_mappings.get(name)
        require(mapping is None or type(mapping)is dict and set(mapping)<={'realmMappings','clientMappings'},'CLOSED_SCOPE_ROLE_MAPPING_METADATA_REQUIRED')
        unrestricted=mapping is not None and not mapping.get('realmMappings')and not mapping.get('clientMappings')
        bound=name in d or name in o
        eligible=bool(definition and definition['protocol']=='openid-connect'and definition['includeInTokenScope']and not definition['dynamic']and bound and unrestricted)
        rows.append({'name':name,'id':definition['id']if definition else None,'defined':definition is not None,
                     'binding':'DEFAULT'if name in d else'OPTIONAL'if name in o else'NONE',
                     'includeInTokenScope':definition['includeInTokenScope']if definition else None,
                     'includeInTokenScopeAttribute':definition['includeInTokenScopeAttribute']if definition else None,
                     'roleMappingsObserved':mapping is not None,'unrestrictedByScopeRoleMappings':unrestricted,
                     'eligibleForExplicitRequest':eligible})
    return {'schema':'ouf.ths-oidc-client-binding-observation.v1','clientId':expected_client,'clientUuid':client['id'],
            'defaultScopeCount':len(d),'optionalScopeCount':len(o),'definitionCount':len(all_scopes),
            'bindingSnapshotHash':digest({'client':client,'defaults':d,'optionals':o,'definitions':all_scopes,'roleMappings':role_mappings}),
            'requiredScopes':rows,'bindingAndUnrestrictedEligibilityProven':all(r['eligibleForExplicitRequest']for r in rows),
            'blockedScopes':[r['name']for r in rows if not r['eligibleForExplicitRequest']],
            'effectiveBrowserTokenScopesProven':False,'iamMutations':0,'newGrantsGranted':0}

def configuration_profile(actual,observation,identity,*,installation_ref):
    require(type(installation_ref)is str and re.fullmatch('[A-Za-z0-9_.:-]{1,160}',installation_ref),'EXPLICIT_INSTALLATION_REFERENCE_REQUIRED')
    require(observation.get('schema')=='ouf.ths-oidc-client-binding-observation.v1'
            and observation.get('clientId')==identity['clientId']and observation.get('bindingAndUnrestrictedEligibilityProven')is True
            and observation.get('blockedScopes')==[]and observation.get('iamMutations')==0
            and [r['name']for r in observation['requiredScopes']]==list(REQUIRED)
            and all(r['eligibleForExplicitRequest']is True for r in observation['requiredScopes'])
            and identity.get('registrationId')=='ouf-ths'and identity.get('fileSelectionAndPrecedenceVerified')is True,'CURRENT_EXACT_CLIENT_BINDING_PROOF_REQUIRED')
    summary,environment=scope_patch(actual)
    require(summary['missingRequestScopes'],'ALREADY_COMPLETE_REQUEST_RECONCILE_WITHOUT_NOOP_PATCH')
    original=copy.deepcopy(actual);candidate=copy.deepcopy(actual);candidate['Config']['Env']=environment
    unchanged=lambda value:{**value,'Config':{k:v for k,v in value['Config'].items()if k!='Env'}}
    require(unchanged(original)==unchanged(candidate),'ONLY_OWNER_ENVIRONMENT_MAY_CHANGE')
    profile={'schema':'ouf.ths-additive-owner-configuration-profile.v1','installationRef':installation_ref,
             'registrationId':'ouf-ths','clientId':identity['clientId'],'issuer':identity['issuer'],
             'ownerImageId':actual['Image'],'ownerContainerId':actual['Id'],'currentConfigurationHash':digest(actual['Config']),
             'proposedConfigurationHash':digest(candidate['Config']),'iamBindingSnapshotHash':observation['bindingSnapshotHash'],
             'requiredScopes':list(REQUIRED),'preservedRequestedScopes':summary['requestedScopes'],'addedRequestScopes':summary['missingRequestScopes'],
             'requestBeforeHash':summary['requestBeforeHash'],'requestAfterHash':summary['conditionalRequestAfterHash'],
             'replacementEnvironment':environment,'sameNativeImageRequired':True,'allOtherPropertiesPreserved':True,
             'iamConfigurationMutationAuthorized':False,'executionEntryQualified':False,'currentJobOrBudgetStateObserved':False,
             'freshRuntimeAndJobFencesRequired':True,'newHumanExecutionReviewRequired':True,'runtimeAuthorityIssued':False,
             'targetApplyAuthorized':False,'effectiveBrowserTokenScopesProven':False,'automaticReplayAllowed':False,'budgetReset':False}
    return profile

CLIENT_FIELDS=('id','clientId','enabled','protocol','standardFlowEnabled','publicClient','consentRequired','fullScopeAllowed','directAccessGrantsEnabled','serviceAccountsEnabled')

CHILD=r'''import http.client,ipaddress,json,os,re,signal,sys,urllib.parse
signal.alarm(8)
def require(ok):
 if not ok:raise ValueError()
def unique(rows):
 value={}
 for k,v in rows:require(k not in value);value[k]=v
 return value
def client(value):
 require(type(value)is dict)
 return {k:value[k]for k in ('id','clientId','enabled','protocol','standardFlowEnabled','publicClient','consentRequired','fullScopeAllowed','directAccessGrantsEnabled','serviceAccountsEnabled')if k in value}
def scopes(value):
 require(type(value)is list and len(value)<=1024)
 result=[]
 for row in value:
  require(type(row)is dict and type(row.get('attributes',{}))is dict)
  result.append({**{k:row[k]for k in ('id','name','protocol')if k in row},'attributes':{k:v for k,v in row.get('attributes',{}).items()if k in ('include.in.token.scope','is.dynamic.scope','is.parameterized.scope')}})
 return result
def roles(value):
 require(type(value)is list and len(value)<=2048 and all(type(row)is dict for row in value))
 return [{k:row[k]for k in ('id','name')if k in row}for row in value]
try:
 raw=sys.stdin.buffer.read(32769);require(0<len(raw)<=32768)
 v=json.loads(raw,object_pairs_hook=unique);require(set(v)=={'host','port','adminRealm','clientId','expectedUser','targetRealm','targetClient','operation','credential','subject','clientUuid','scopeUuid'})
 require(ipaddress.ip_address(v['host']).is_loopback and type(v['port'])is int and 1<=v['port']<=65535)
 for k in ('adminRealm','clientId','expectedUser','targetRealm','targetClient'):require(type(v[k])is str and re.fullmatch('[A-Za-z0-9._-]{1,128}',v[k]))
 op=v['operation'];cred=v['credential'];require(type(cred)is str and 0<len(cred)<=16384 and not any(c in cred for c in '\r\n\x00'))
 headers={'Accept':'application/json','Connection':'close'};body=None;method='GET';base='/admin/realms/'+v['targetRealm']
 if op=='PASSWORD_GRANT':
  method='POST';path='/realms/'+v['adminRealm']+'/protocol/openid-connect/token';headers['Content-Type']='application/x-www-form-urlencoded'
  body=urllib.parse.urlencode({'client_id':v['clientId'],'grant_type':'password','username':v['expectedUser'],'password':cred,'scope':'openid'})
 elif op=='IDENTITY':
  require(re.fullmatch('[A-Za-z0-9_-]{1,128}',v['subject']));path='/admin/realms/'+v['adminRealm']+'/users/'+v['subject'];headers['Authorization']='Bearer '+cred
 elif op=='CLIENT_LIST':path=base+'/clients?'+urllib.parse.urlencode({'clientId':v['targetClient'],'exact':'true','first':0,'max':2});headers['Authorization']='Bearer '+cred
 elif op in ('CLIENT','DEFAULTS','OPTIONALS'):
  require(re.fullmatch('[A-Za-z0-9_-]{1,128}',v['clientUuid']));path=base+'/clients/'+v['clientUuid']+{'CLIENT':'','DEFAULTS':'/default-client-scopes','OPTIONALS':'/optional-client-scopes'}[op];headers['Authorization']='Bearer '+cred
 elif op=='DEFINITIONS':path=base+'/client-scopes';headers['Authorization']='Bearer '+cred
 elif op=='SCOPE_ROLES':
  require(re.fullmatch('[A-Za-z0-9_-]{1,128}',v['scopeUuid']));path=base+'/client-scopes/'+v['scopeUuid']+'/scope-mappings';headers['Authorization']='Bearer '+cred
 else:raise ValueError()
 fd=int(sys.argv[1]);os.setns(fd,0);os.close(fd)
 c=http.client.HTTPConnection(v['host'],v['port'],timeout=6)
 try:
  c.request(method,path,body=body,headers=headers);r=c.getresponse();raw=r.read(1048577);require(len(raw)<=1048576)
  status=r.status;retry=r.getheader('Retry-After','');require(len(retry)<=128 and all(32<=ord(x)<127 for x in retry))
  value=None
  if status==200:
   data=json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in()).throw(ValueError()))
   if op=='PASSWORD_GRANT':require(type(data)is dict);value={k:data[k]for k in ('access_token','id_token','token_type','expires_in')if k in data}
   elif op=='IDENTITY':require(type(data)is dict);value={k:data[k]for k in ('id','username','enabled')if k in data}
   elif op=='CLIENT_LIST':require(type(data)is list and len(data)<=2);value=[client(x)for x in data]
   elif op=='CLIENT':value=client(data)
   elif op in ('DEFAULTS','OPTIONALS','DEFINITIONS'):value=scopes(data)
   elif op=='SCOPE_ROLES':
    require(type(data)is dict and set(data)<={'realmMappings','clientMappings'});value={}
    if 'realmMappings'in data:value['realmMappings']=roles(data['realmMappings'])
    if 'clientMappings'in data:
     cm=data['clientMappings'];require(type(cm)is dict and len(cm)<=256);value['clientMappings']={}
     for key,row in cm.items():
      require(type(row)is dict);value['clientMappings'][key]={**{k:row[k]for k in ('id','client')if k in row},'mappings':roles(row.get('mappings',[]))}
  result={'status':status,'body':value,'retryAfter':retry,'bytes':len(raw)}
 except (OSError,TimeoutError,http.client.RemoteDisconnected):
  # Authentication dispatch is never replayed, including unknown completion.
  result={'status':0,'body':None,'retryAfter':'','bytes':0}
 finally:c.close()
 out=json.dumps(result,sort_keys=True,separators=(',',':'),allow_nan=False).encode();require(len(out)<=1048576)
 sys.stdout.buffer.write(out);sys.stdout.buffer.flush()
except BaseException:os._exit(2)
os._exit(0)
'''

def executable(binding):
    path=Path(binding['path']);require(path.is_absolute()and path.resolve()==path,'EXACT_IAM_PROGRAM_PATH_REQUIRED')
    for parent in path.parents:
        s=parent.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and not s.st_mode&0o022,'ROOT_IAM_PROGRAM_ANCESTRY_REQUIRED')
    s=path.lstat();require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and s.st_nlink==1 and s.st_mode&0o111 and not s.st_mode&0o022
            and 0<s.st_size<=64000000 and __import__('hashlib').sha256(path.read_bytes()).hexdigest()==binding['sha256'],'EXACT_IAM_PROGRAM_BYTES_REQUIRED')
    return str(path)

def dispatch(program,namespace,payload):
    try:
        result=subprocess.run([executable(program),'-I','-S','-B','-c',CHILD,str(namespace)],input=encoded(payload),
                stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10,pass_fds=(namespace,),env={'LC_ALL':'C','PATH':'/usr/bin:/bin'})
    except subprocess.TimeoutExpired:
        return {'status':0,'body':None,'retryAfter':'','bytes':0}
    require(result.returncode==0 and 0<len(result.stdout)<=1048576,'IAM_READ_CHILD_OUTCOME_UNPROVEN_NO_REPLAY')
    value=decode(result.stdout)
    require(type(value)is dict and set(value)=={'status','body','retryAfter','bytes'}and type(value['status'])is int
            and type(value['bytes'])is int and 0<=value['bytes']<=1048576,'CLOSED_IAM_READ_RESPONSE_REQUIRED')
    return value

class ReadLedger:
    def __init__(self,capture,*,clock=time.time,sleep=time.sleep):
        self.c,self.clock,self.sleep=capture,clock,sleep;self.serial=0;self.authenticated=False;self.identityVerified=False;self.deadline=None
        require(not any(k in self.c.counts for k in ('oauthRequestsReserved','adminGetsReserved','adminGetRetryReservations')),'IAM_LEDGER_ALREADY_INITIALIZED_NO_COUNTER_RESET')
        self.c.counts.update(oauthRequestsReserved=0,adminGetsReserved=0,adminGetRetryReservations=0)
    def event(self,stage,**metadata):
        require(re.fullmatch('[a-z0-9-]{1,160}',stage),'CLOSED_IAM_STAGE_REQUIRED')
        self.serial+=1;self.c.put('iam-step-'+str(self.serial)+'.json',{'stage':stage,'counts':dict(self.c.counts),'at':self.clock(),**metadata})
    def request(self,stage,operation,payload,send,guard,*,expiry=None):
        require(operation in ('PASSWORD_GRANT','IDENTITY','CLIENT_LIST','CLIENT','DEFAULTS','OPTIONALS','DEFINITIONS','SCOPE_ROLES')and payload.get('operation')==operation,'EXACT_COUNTED_IAM_OPERATION_REQUIRED')
        for attempt in range(3):
            guard()
            require(self.deadline is not None and self.clock()<self.deadline,'FINITE_ORIGINAL_IAM_OPERATION_WINDOW_REQUIRED')
            if operation=='PASSWORD_GRANT':
                require(attempt==0 and self.c.counts['oauthRequestsReserved']==0,'ONE_EXPLICIT_ADMIN_AUTHENTICATION_NO_REPLAY')
                self.c.counts['oauthRequestsReserved']=1
            else:
                require(self.authenticated and self.c.counts['adminGetsReserved']<20 and expiry is not None and expiry>self.clock()+8,'CURRENT_ADMIN_IDENTITY_TOKEN_AND_READ_BUDGET_REQUIRED')
                require(operation=='IDENTITY'or self.identityVerified,'PROTECTED_EFFECTIVE_IAM_IDENTITY_REQUIRED_BEFORE_CLIENT_READ')
                self.c.counts['adminGetsReserved']+=1
                if attempt:
                    require(self.c.counts['adminGetRetryReservations']<4,'FINITE_IAM_RETRY_BUDGET_EXHAUSTED');self.c.counts['adminGetRetryReservations']+=1
            self.event(stage,operation=operation,attempt=attempt+1,dispatchReserved=True)
            value=send(payload);self.c.counts['bytes']+=value['bytes'];require(self.c.counts['bytes']<=25165824,'FINITE_IAM_BYTE_BUDGET_REQUIRED')
            self.event(stage,operation=operation,status=value['status'],responseReceived=True)
            guard()
            if value['status']==200:return value['body']
            require(operation!='PASSWORD_GRANT','ADMIN_AUTHENTICATION_OUTCOME_STOP_NO_RETRY')
            require(value['status']in(0,429,502,503,504)and attempt<2,'IAM_DENIED_OR_UNKNOWN_RESPONSE_NO_RETRY')
            # Explicit transient GET only. Preserve the same stage/session and
            # finite token/deadline, never refresh or reserve another login.
            delay=(5,15)[attempt]*random.SystemRandom().uniform(.8,1.2)
            header=value['retryAfter']
            if header:
                if header.isdigit():retry=float(header)
                else:
                    from email.utils import parsedate_to_datetime
                    try:retry=parsedate_to_datetime(header).timestamp()-self.clock()
                    except (ValueError,TypeError,OverflowError):raise Stop('INVALID_RETRY_AFTER_STOP')from None
                delay=max(delay,max(0,retry))
            require(delay<=20 and self.clock()+delay+8<expiry,'IAM_TRANSIENT_WAIT_EXCEEDS_ORIGINAL_TOKEN_WINDOW')
            until=self.clock()+delay;self.event(stage,transient=True,nextAttemptAt=until)
            while self.clock()<until:guard();self.sleep(min(1,until-self.clock()))
        raise Stop('FINITE_IAM_STAGE_EXHAUSTED')

def terminal(summary, phrase=None):
    """Controlling tty only; password echo restored even on timeout/interrupt."""
    fd = os.open('/dev/tty', os.O_RDWR | os.O_NOCTTY | os.O_NOFOLLOW)
    old = None
    try:
        require(stat.S_ISCHR(os.fstat(fd).st_mode) and os.isatty(fd), 'CONTROLLING_ADMIN_TERMINAL_REQUIRED')
        termios.tcflush(fd, termios.TCIFLUSH)
        if phrase is None:
            old = termios.tcgetattr(fd)
            hidden = termios.tcgetattr(fd)
            hidden[3] &= ~(termios.ECHO | termios.ECHONL)
            termios.tcsetattr(fd, termios.TCSAFLUSH, hidden)
            os.write(fd, ('\n' + summary + '\n> ').encode())
        else:
            os.write(fd, ('\n' + summary + '\nScrivi esattamente: ' + phrase + '\n> ').encode())
        require(bool(select.select([fd], [], [], 90)[0]), 'ADMIN_TERMINAL_INPUT_TIMEOUT_NO_REPLAY')
        raw = os.read(fd, 4097)
        require(0 < len(raw) <= 4096 and raw.endswith(b'\n') and b'\x00' not in raw,
            'BOUNDED_ADMIN_TERMINAL_LINE_REQUIRED')
        value = raw[:-1].decode('utf-8')
        if phrase is not None:
            require(value == phrase, 'EXACT_ADMIN_API_TERMINAL_CONSENT_REQUIRED')
            return True
        require(value and not any(c in value for c in '\r\n'), 'NONEMPTY_SINGLE_ADMIN_PASSWORD_REQUIRED')
        return value
    finally:
        if old is not None:
            termios.tcsetattr(fd, termios.TCSANOW, old)
            os.write(fd, b'\n')
        os.close(fd)

def access(api, response, endpoint, issuer, requested_at):
    require(type(response) is dict and response.get('token_type', '').lower() == 'bearer'
        and type(response.get('expires_in')) is int and 0 < response['expires_in'] <= 3600,
        'EXACT_FRESH_ADMIN_TOKEN_RESPONSE_REQUIRED')
    token = response.get('access_token')
    require(type(token) is str and len(token) <= 16384 and len(token.split('.')) == 3,
        'BOUNDED_FRESH_ADMIN_ACCESS_TOKEN_REQUIRED')
    part = token.split('.')[1]
    require(re.fullmatch('[A-Za-z0-9_-]+', part) is not None, 'FRESH_ADMIN_JWT_PAYLOAD_REQUIRED')
    claims = api.decode(base64.b64decode(part + '=' * (-len(part) % 4), altchars=b'-_', validate=True))
    allowed = {issuer.rsplit('/realms/', 1)[0] + '/realms/' + endpoint['adminRealm'],
        endpoint['storedServerUrl'] + '/realms/' + endpoint['adminRealm']}
    require(type(claims) is dict and claims.get('iss') in allowed,
        'FRESH_ADMIN_ACCESS_ISSUER_MUST_MATCH_SELECTED_PROVIDER')
    require(claims.get('azp') == endpoint['adminClientId'], 'FRESH_ADMIN_ACCESS_CLIENT_MUST_MATCH')
    require(type(claims.get('exp')) is type(claims.get('iat')) is int
        and requested_at - 10 <= claims['iat'] <= time.time() + 5,
        'FRESH_ADMIN_ACCESS_TIMESTAMPS_REQUIRED')
    # A lightweight access token can omit BOTH preferred_username and sub.
    # Resolve the routing subject from the ID token returned in this same
    # fresh, directly received password-grant response (scope=openid). This is
    # provider-channel provenance, not independent JWT signature validation.
    # A protected Admin user lookup must then prove username/id/enabled state.
    id_token = response.get('id_token')
    require(type(id_token) is str and len(id_token) <= 16384 and len(id_token.split('.')) == 3,
        'FRESH_ADMIN_OIDC_ID_TOKEN_REQUIRED_FOR_SUBJECT')
    part = id_token.split('.')[1]
    require(re.fullmatch('[A-Za-z0-9_-]+', part) is not None, 'BOUNDED_ADMIN_ID_TOKEN_PAYLOAD_REQUIRED')
    identity = api.decode(base64.b64decode(part + '=' * (-len(part) % 4), altchars=b'-_', validate=True))
    require(type(identity) is dict and identity.get('iss') == claims['iss'], 'SAME_PROVIDER_ADMIN_ID_TOKEN_ISSUER_REQUIRED')
    audience = identity.get('aud')
    require(audience == endpoint['adminClientId'] or type(audience) is list
        and endpoint['adminClientId'] in audience and all(type(v) is str for v in audience),
        'ADMIN_ID_TOKEN_AUDIENCE_MUST_INCLUDE_SELECTED_CLIENT')
    require(identity.get('azp', endpoint['adminClientId']) == endpoint['adminClientId'],
        'ADMIN_ID_TOKEN_AUTHORIZED_PARTY_MUST_MATCH')
    require(type(identity.get('exp')) is type(identity.get('iat')) is int
        and requested_at - 10 <= identity['iat'] <= time.time() + 5 and identity['exp'] > time.time(),
        'FRESH_ADMIN_ID_TOKEN_TIMESTAMPS_REQUIRED')
    require(re.fullmatch('[A-Za-z0-9_-]{1,128}', identity.get('sub', '')),
        'BOUNDED_ADMIN_ID_TOKEN_SUBJECT_REQUIRED')
    require(claims.get('sub') is None or claims['sub'] == identity['sub'],
        'ADMIN_ACCESS_AND_ID_TOKEN_SUBJECTS_MUST_AGREE_WHEN_PRESENT')
    expiry = min(claims['exp'], requested_at + response['expires_in'])
    require(expiry > time.time() + 45, 'FRESH_ADMIN_TOKEN_TOO_SHORT_FOR_FOUR_BOUNDED_GETS')
    # This is routing metadata, never independent JWT signature verification.
    # The provider's protected user endpoint must establish subject identity.
    return token, expiry, identity['sub']

MARKER='ouf.provisioning.operation-ref'

def compile_correction(observation,expected,*,installation_ref,parent_result_hash,realm):
    require(observation==expected and observation.get('schema')=='ouf.ths-oidc-client-binding-observation.v1'
            and observation['bindingAndUnrestrictedEligibilityProven']is False and observation['iamMutations']==0
            and observation['blockedScopes']==list(REQUIRED),'EXACT_RETAINED_BINDING_BASELINE_REQUIRED')
    rows=observation['requiredScopes']
    require([r['name']for r in rows]==list(REQUIRED)and all(r['binding']=='NONE'for r in rows),'THREE_ABSENT_LINKS_REQUIRED')
    require(all(r['defined']is True and r['includeInTokenScope']is True and r['unrestrictedByScopeRoleMappings']is True
                and re.fullmatch('[A-Za-z0-9_-]{1,128}',r['id'])for r in rows[:2])
            and rows[2]['defined']is False and rows[2]['id']is None,'EXACT_TWO_DEFINITIONS_AND_ONE_ABSENT_REQUIRED')
    require(re.fullmatch('[a-f0-9]{64}',parent_result_hash)and re.fullmatch('[A-Za-z0-9_.:-]{1,160}',installation_ref)
            and re.fullmatch('[A-Za-z0-9_.-]{1,128}',realm),'EXPLICIT_INSTALLATION_LINEAGE_REQUIRED')
    operation=digest({'schema':'ouf.ths-iam-correction-intent.v1','installationRef':installation_ref,'realm':realm,
                      'parentResultHash':parent_result_hash,'bindingSnapshotHash':observation['bindingSnapshotHash'],
                      'clientUuid':observation['clientUuid'],'scopes':list(REQUIRED)})
    new_id=str(uuid.uuid5(uuid.NAMESPACE_URL,'ouf:ths-iam-correction:'+operation+':'+REQUIRED[2]))
    definition={'id':new_id,'name':REQUIRED[2],'protocol':'openid-connect',
                'attributes':{'include.in.token.scope':'true',MARKER:operation},'protocolMappers':[]}
    assignments=[{'name':r['name'],'id':r['id']if r['defined']else new_id,'type':'OPTIONAL'}for r in rows]
    return {'schema':'ouf.ths-additive-iam-correction-plan.v1','installationRef':installation_ref,'realm':realm,
            'parentResultHash':parent_result_hash,'operationRef':operation,'clientId':observation['clientId'],
            'clientUuid':observation['clientUuid'],'baselineBindingHash':observation['bindingSnapshotHash'],
            'definitionToCreate':definition,'assignmentsToAdd':assignments,
            'preservedDefaultScopeCount':observation['defaultScopeCount'],'preservedOptionalScopeCount':observation['optionalScopeCount'],
            'previousDefinitionCount':observation['definitionCount'],'newDefinitionCount':observation['definitionCount']+1,
            'newOptionalScopeCount':observation['optionalScopeCount']+3,'maximumDefinitionCreates':1,'maximumOptionalAssignments':3,
            'realmDefaultMutationAuthorized':False,'clientSettingsMutationAuthorized':False,'existingDefinitionMutationAuthorized':False,
            'roleOrMapperMutationAuthorized':False,'newApplicationGrantsAuthorized':False,'humanProfilingBudgetAuthorized':False,
            'resumeAuthorized':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
            'automaticReplayAllowed':False,'budgetReset':False}

def link_map(rows):
    require(type(rows)is list and len(rows)<=1024,'BOUNDED_BINDING_LIST_REQUIRED');result={}
    for row in rows:
        require(type(row)is dict and re.fullmatch('[A-Za-z0-9_-]{1,128}',row.get('id',''))
                and type(row.get('name'))is str and row['id']not in result,'UNIQUE_BINDING_ID_REQUIRED')
        result[row['id']]=row['name']
    require(len(set(result.values()))==len(result),'UNIQUE_BINDING_NAME_REQUIRED');return result

def validate_created_scope(detail,plan):
    wanted=plan['definitionToCreate']
    require(type(detail)is dict and all(detail.get(k)==wanted[k]for k in ('id','name','protocol','attributes'))
            and detail.get('protocolMappers',[])==[] and detail.get('otherAttributeCount',0)==0,'EXACT_CREATED_DEFINITION_ID_MARKER_AND_EMPTY_MAPPERS_REQUIRED')
    return wanted['id']

def validate_location(location,plan,endpoint,issuer):
    require(type(location)is str and 0<len(location)<=2048 and all(32<=ord(c)<127 for c in location),'BOUNDED_CREATE_LOCATION_REQUIRED')
    u=urlsplit(location);expected='/admin/realms/'+plan['realm']+'/client-scopes/'+plan['definitionToCreate']['id']
    require(u.path==expected and not u.query and not u.fragment and not u.username and not u.password,'EXACT_PREAPPROVED_SCOPE_LOCATION_REQUIRED')
    if u.scheme or u.netloc:
        origin=u.scheme+'://'+u.netloc
        allowed={issuer.rsplit('/realms/',1)[0],endpoint['storedServerUrl'],
                 'http://'+endpoint['connectHost']+':'+str(endpoint['connectPort'])}
        require(origin in allowed,'SELECTED_PROVIDER_CREATE_LOCATION_REQUIRED')

def verify_postcondition(before,after,plan):
    require(after['report']['bindingAndUnrestrictedEligibilityProven']is True
            and after['report']['clientUuid']==plan['clientUuid']and after['report']['clientId']==plan['clientId'],
            'CORRECTED_CLIENT_BINDING_ELIGIBILITY_REQUIRED')
    require(link_map(before['defaults'])==link_map(after['defaults']),'ALL_PREEXISTING_DEFAULT_BINDINGS_MUST_REMAIN_EXACT')
    wanted={**link_map(before['optionals']),**{r['id']:r['name']for r in plan['assignmentsToAdd']}}
    require(link_map(after['optionals'])==wanted,'ONLY_THREE_REVIEWED_OPTIONAL_LINKS_MAY_BE_ADDED')
    require(before['clientIntegrity']==after['clientIntegrity'],'UNRELATED_CLIENT_CONFIGURATION_CHANGED')
    require(before['realmDefaults']==after['realmDefaults'],'REALM_DEFAULT_SCOPE_ASSIGNMENTS_CHANGED')
    old,new=before['definitionIntegrity'],after['definitionIntegrity'];scope=plan['definitionToCreate']
    require(len(old)==plan['previousDefinitionCount']and len(new)==len(old)+1 and scope['id']not in old
            and set(new)==set(old)|{scope['id']}and all(new[k]==v for k,v in old.items()),'ONLY_ONE_REVIEWED_DEFINITION_MAY_BE_CREATED')
    return True

class CorrectionCapture(Capture):
    def put(self,name,value):
        if name=='claim.json':self.maximums.update(privateMetadataReads=3,engineGets=7)
        if re.fullmatch('engine-get-[0-9]+-response.json',name):
            value={'schema':'ouf.ths-iam-engine-observation.v1','rawEnvironmentPersisted':False,'binding':stable_binding(value)}if 'Id'in value else{'schema':'ouf.ths-iam-engine-info.v1','serverVersion':value.get('ServerVersion')}
        return super().put(name,value)

class CorrectionLedger(ReadLedger):
    def __init__(self,capture,*,clock=time.time,sleep=time.sleep):
        super().__init__(capture,clock=clock,sleep=sleep)
        require('iamWritesReserved'not in self.c.counts,'CORRECTION_LEDGER_CANNOT_RESET_COUNTERS')
        self.c.counts.update(iamWritesReserved=0,iamWritesObserved=0);self.approvedReviewHash=None
        self.claimedWrites=set();self.claimedStages=set();self.observedStages=set()
    def request(self,stage,operation,payload,send,guard,*,expiry=None):
        require(operation in ('PASSWORD_GRANT','IDENTITY','CLIENT_LIST','CLIENT','DEFAULTS','OPTIONALS','DEFINITIONS','SCOPE_ROLES','SCOPE_DETAIL','CLIENT_INTEGRITY','DEFINITIONS_INTEGRITY','REALM_DEFAULTS','REALM_OPTIONALS')
                and payload.get('operation')==operation,'EXACT_COUNTED_CORRECTION_READ_REQUIRED')
        # Reuse the established read-only state machine with this operation's
        # explicit40GET profile. Authentication remains exactly one dispatch.
        for attempt in range(3):
            guard();require(self.approvedReviewHash is not None and self.deadline is not None and self.clock()<self.deadline,'CURRENT_CORRECTION_REVIEW_AND_WINDOW_REQUIRED')
            if operation=='PASSWORD_GRANT':
                require(attempt==0 and self.c.counts['oauthRequestsReserved']==0,'ONE_CORRECTION_AUTHENTICATION_NO_REPLAY');self.c.counts['oauthRequestsReserved']=1
            else:
                require(self.authenticated and expiry is not None and expiry>self.clock()+8 and self.c.counts['adminGetsReserved']<40,'FINITE_CURRENT_CORRECTION_GET_PROFILE_REQUIRED')
                require(operation=='IDENTITY'or self.identityVerified,'PROTECTED_IDENTITY_REQUIRED_BEFORE_IAM_CORRECTION_READ')
                if attempt:require(self.c.counts['adminGetRetryReservations']<4,'CORRECTION_GET_RETRY_BUDGET_EXHAUSTED');self.c.counts['adminGetRetryReservations']+=1
                self.c.counts['adminGetsReserved']+=1
            self.event(stage,operation=operation,attempt=attempt+1,dispatchReserved=True)
            value=send(payload);self.c.counts['bytes']+=value['bytes'];require(self.c.counts['bytes']<=25165824,'CORRECTION_BYTE_LIMIT')
            self.event(stage,operation=operation,status=value['status'],responseReceived=True);guard()
            if value['status']==200:return value['body']
            require(operation!='PASSWORD_GRANT','CORRECTION_AUTHENTICATION_AMBIGUOUS_OR_DENIED_NO_RETRY')
            require(value['status']in(0,429,502,503,504)and attempt<2,'CORRECTION_GET_DENIED_OR_UNKNOWN_NO_RETRY')
            import random
            delay=(5,15)[attempt]*random.SystemRandom().uniform(.8,1.2);header=value.get('retryAfter','')
            if header:
                if header.isdigit():retry=float(header)
                else:
                    from email.utils import parsedate_to_datetime
                    try:retry=parsedate_to_datetime(header).timestamp()-self.clock()
                    except (ValueError,TypeError,OverflowError):raise Stop('INVALID_CORRECTION_RETRY_AFTER')from None
                delay=max(delay,max(0,retry))
            require(delay<=20 and self.clock()+delay+8<min(expiry,self.deadline),'CORRECTION_RETRY_CANNOT_EXTEND_CURRENT_WINDOW')
            until=self.clock()+delay;self.event(stage,transient=True,nextAttemptAt=until)
            while self.clock()<until:guard();self.sleep(min(1,until-self.clock()))
        raise Stop('FINITE_CORRECTION_GET_STAGE_EXHAUSTED')
    def write(self,stage,operation,payload,send,guard,*,expiry):
        require(operation in ('CREATE_SCOPE','ASSIGN_OPTIONAL')and payload.get('operation')==operation,'CLOSED_CORRECTION_WRITE_REQUIRED')
        signature=(operation,payload['clientUuid'],payload['scopeUuid'])
        require(signature not in self.claimedWrites and stage not in self.claimedStages,'CORRECTION_EFFECT_ALREADY_CLAIMED_NO_REPLAY')
        guard();require(self.approvedReviewHash is not None and self.authenticated and self.identityVerified and expiry>self.clock()+8
                        and self.clock()<self.deadline and self.c.counts['iamWritesReserved']<4,'LIVE_REVIEW_IDENTITY_AND_FOUR_WRITE_LIMIT_REQUIRED')
        self.claimedWrites.add(signature);self.claimedStages.add(stage)
        self.c.counts['iamWritesReserved']+=1
        self.event(stage,operation=operation,dispatchReserved=True,reviewHash=self.approvedReviewHash,
                   scopeId=payload['scopeUuid'],scopeName=payload['scopeName'],clientUuid=payload['clientUuid'])
        try:value=send(payload)
        except BaseException:
            self.event(stage,operation=operation,responseNotObserved=True,reconciliationRequired=True)
            raise
        self.c.counts['bytes']+=value['bytes']
        # Persist the whitelisted HTTP receipt BEFORE any parser, process,
        # expiry or state guard. A subsequent STOP cannot erase this evidence.
        self.event(stage,operation=operation,status=value['status'],location=value.get('location',''),responseReceived=True)
        guard();require(self.c.counts['bytes']<=25165824,'CORRECTION_BYTE_LIMIT')
        require(value['status']in(0,200,201,204,429,500,502,503,504),'CORRECTION_WRITE_DENIED_OR_UNKNOWN_PRESERVED_NO_REPLAY')
        return value
    def observed(self,stage,*,ambiguous):
        require(stage in self.claimedStages and stage not in self.observedStages
                and self.c.counts['iamWritesObserved']<self.c.counts['iamWritesReserved'],'ONE_PROOF_PER_CLAIMED_CORRECTION_EFFECT_REQUIRED')
        self.observedStages.add(stage)
        self.c.counts['iamWritesObserved']+=1
        self.event(stage,effectStateObserved=True,httpOutcomeAmbiguous=ambiguous,writeWillNotBeRepeated=True)

EXTRA_CHILD=r'''import hashlib,http.client,ipaddress,json,os,re,signal,sys
signal.alarm(8)
def require(ok):
 if not ok:raise ValueError()
def unique(rows):
 result={}
 for k,v in rows:require(k not in result);result[k]=v
 return result
def sha(v):return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
required=('ouf.managed-source.preview','ouf.managed-source.file.profile','ouf.onboarding.quarantine.release')
marker='ouf.provisioning.operation-ref'
try:
 raw=sys.stdin.buffer.read(32769);require(0<len(raw)<=32768);v=json.loads(raw,object_pairs_hook=unique)
 require(set(v)=={'host','port','adminRealm','clientId','expectedUser','targetRealm','targetClient','operation','credential','subject','clientUuid','scopeUuid','scopeName','operationRef'})
 require(ipaddress.ip_address(v['host']).is_loopback and type(v['port'])is int and 1<=v['port']<=65535)
 require(re.fullmatch('[A-Za-z0-9_.-]{1,128}',v['targetRealm'])and re.fullmatch('[a-f0-9]{64}',v['operationRef']))
 require(type(v['credential'])is str and 0<len(v['credential'])<=16384 and not any(c.isspace()for c in v['credential']))
 base='/admin/realms/'+v['targetRealm'];op=v['operation'];method='GET';body=None
 headers={'Accept':'application/json','Connection':'close','Authorization':'Bearer '+v['credential']}
 if op in ('ASSIGN_OPTIONAL','CLIENT_INTEGRITY'):require(re.fullmatch('[A-Za-z0-9_-]{1,128}',v['clientUuid']))
 if op in ('CREATE_SCOPE','ASSIGN_OPTIONAL','SCOPE_DETAIL'):require(re.fullmatch('[A-Za-z0-9_-]{1,128}',v['scopeUuid']))
 if op=='CREATE_SCOPE':
  require(v['scopeName']==required[2]);method='POST';path=base+'/client-scopes';headers['Content-Type']='application/json'
  body=json.dumps({'id':v['scopeUuid'],'name':v['scopeName'],'protocol':'openid-connect','attributes':{'include.in.token.scope':'true',marker:v['operationRef']},'protocolMappers':[]},sort_keys=True,separators=(',',':')).encode()
 elif op=='ASSIGN_OPTIONAL':require(v['scopeName']in required);method='PUT';path=base+'/clients/'+v['clientUuid']+'/optional-client-scopes/'+v['scopeUuid']
 elif op=='SCOPE_DETAIL':path=base+'/client-scopes/'+v['scopeUuid']
 elif op=='CLIENT_INTEGRITY':path=base+'/clients/'+v['clientUuid']
 elif op=='DEFINITIONS_INTEGRITY':path=base+'/client-scopes'
 elif op=='REALM_DEFAULTS':path=base+'/default-default-client-scopes'
 elif op=='REALM_OPTIONALS':path=base+'/default-optional-client-scopes'
 else:raise ValueError()
 fd=int(sys.argv[1]);os.setns(fd,0);os.close(fd);c=http.client.HTTPConnection(v['host'],v['port'],timeout=6)
 try:
  c.request(method,path,body=body,headers=headers);r=c.getresponse();raw=r.read(1048577);require(len(raw)<=1048576)
  status=r.status;location=r.getheader('Location','');retry=r.getheader('Retry-After','')
  require(len(location)<=2048 and len(retry)<=128 and all(32<=ord(x)<127 for x in location+retry));value=None
  if status==200 and method=='GET':
   data=json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in()).throw(ValueError()))
   if op=='CLIENT_INTEGRITY':
    require(type(data)is dict)
    selected={k:item for k,item in data.items()if k not in ('secret','registrationAccessToken','defaultClientScopes','optionalClientScopes')}
    value={'id':data.get('id'),'clientId':data.get('clientId'),'nonCredentialNonBindingMetadataHash':sha(selected)}
   elif op=='DEFINITIONS_INTEGRITY':
    require(type(data)is list and len(data)<=1024);value={}
    for row in data:
     require(type(row)is dict and type(row.get('id'))is str and row['id']not in value);value[row['id']]={'name':row.get('name'),'metadataHash':sha(row)}
   elif op=='SCOPE_DETAIL':
    require(type(data)is dict and type(data.get('attributes',{}))is dict);attrs=data.get('attributes',{});mappers=data.get('protocolMappers')or[];require(type(mappers)is list)
    value={**{k:data.get(k)for k in ('id','name','protocol')},'attributes':{k:item for k,item in attrs.items()if k in ('include.in.token.scope',marker)},
           'otherAttributeCount':len(set(attrs)-{'include.in.token.scope',marker}),'protocolMappers':[]if not mappers else[{'unreviewed':True}]}
   elif op in ('REALM_DEFAULTS','REALM_OPTIONALS'):
    require(type(data)is list and len(data)<=1024);value=[{k:row[k]for k in ('id','name','protocol')if k in row}for row in data]
  result={'status':status,'body':value,'retryAfter':retry,'bytes':len(raw),'location':location}
 except (OSError,TimeoutError,http.client.RemoteDisconnected):result={'status':0,'body':None,'retryAfter':'','bytes':0,'location':''}
 finally:c.close()
 out=json.dumps(result,sort_keys=True,separators=(',',':'),allow_nan=False).encode();require(len(out)<=1048576);sys.stdout.buffer.write(out);sys.stdout.buffer.flush()
except BaseException:os._exit(2)
os._exit(0)
'''

BASE_OPERATIONS=('PASSWORD_GRANT','IDENTITY','CLIENT_LIST','CLIENT','DEFAULTS','OPTIONALS','DEFINITIONS','SCOPE_ROLES')

def dispatch_correction(program,namespace,payload):
    operation=payload.get('operation')
    if operation in BASE_OPERATIONS:
        body={k:v for k,v in payload.items()if k not in ('scopeName','operationRef')}
        result=dispatch(program,namespace,body);return {**result,'location':''}
    require(operation in ('CREATE_SCOPE','ASSIGN_OPTIONAL','SCOPE_DETAIL','CLIENT_INTEGRITY','DEFINITIONS_INTEGRITY','REALM_DEFAULTS','REALM_OPTIONALS'),'CLOSED_SUPPLEMENTAL_IAM_OPERATION_REQUIRED')
    try:
        child=subprocess.run([executable(program),'-I','-S','-B','-c',EXTRA_CHILD,str(namespace)],input=encoded(payload),stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                             timeout=10,pass_fds=(namespace,),env={'LC_ALL':'C','PATH':'/usr/bin:/bin'})
    except subprocess.TimeoutExpired:return {'status':0,'body':None,'retryAfter':'','bytes':0,'location':''}
    if child.returncode!=0:
        require(operation in ('CREATE_SCOPE','ASSIGN_OPTIONAL'),'CORRECTION_READ_CHILD_OUTCOME_UNPROVEN')
        # The durable write claim already exists. Reconcile this exact fixed ID
        # using GET in the same session; never infer nondispatch or repeat it.
        return {'status':0,'body':None,'retryAfter':'','bytes':0,'location':''}
    require(0<len(child.stdout)<=1048576,'BOUNDED_CORRECTION_RESPONSE_REQUIRED')
    value=decode(child.stdout)
    require(type(value)is dict and set(value)=={'status','body','retryAfter','bytes','location'}and type(value['status'])is int
            and type(value['bytes'])is int and 0<=value['bytes']<=1048576,'CLOSED_CORRECTION_HTTP_RECEIPT_REQUIRED')
    return value

def correction_snapshot(request,client_uuid,stage):
    client=request('client-'+stage,'CLIENT',uuid=client_uuid)
    require(client.get('id')==client_uuid,'SAME_APPROVED_CLIENT_UUID_REQUIRED')
    defaults=request('defaults-'+stage,'DEFAULTS',uuid=client_uuid)
    optionals=request('optionals-'+stage,'OPTIONALS',uuid=client_uuid)
    definitions=request('definitions-'+stage,'DEFINITIONS');named=scope_rows(definitions);mappings={}
    for i,name in enumerate(REQUIRED):
        if name in named:mappings[name]=request('roles-'+str(i)+'-'+stage,'SCOPE_ROLES',scope=named[name]['id'])
    observation=binding_report(client,defaults,optionals,definitions,mappings,expected_client=client['clientId'])
    integrity=request('client-integrity-'+stage,'CLIENT_INTEGRITY',uuid=client_uuid)
    require(integrity.get('id')==client_uuid and integrity.get('clientId')==client['clientId'],'CLIENT_INTEGRITY_IDENTITY_REQUIRED')
    return {'report':observation,'defaults':defaults,'optionals':optionals,'clientIntegrity':integrity,
            'definitionIntegrity':request('definition-integrity-'+stage,'DEFINITIONS_INTEGRITY'),
            'realmDefaults':{'DEFAULT':link_map(request('realm-defaults-'+stage,'REALM_DEFAULTS')),
                             'OPTIONAL':link_map(request('realm-optionals-'+stage,'REALM_OPTIONALS'))}}

def execute_correction(c,prepared,case,*,prompt=terminal,sender=dispatch_correction,wall=time.time):
    inputs,parent,plan,review,namespace,program,guard,containers=prepared
    ledger=CorrectionLedger(c,clock=wall);password=token=response=None
    try:
        print(json.dumps({'review':review,'reviewHash':digest(review),'runtimeAuthorityIssued':False},sort_keys=True),flush=True)
        prompt('Nuova correzione IAM condizionata alla baseline osservata.\n'
               'UNA definizione OAuth con UUID fissato,nessun mapper/ruolo/RealmDefault;TRE link OPTIONAL SOLO al client '+plan['clientId']+'.\n'
               'Tutti i '+str(plan['preservedDefaultScopeCount'])+' DEFAULT/'+str(plan['preservedOptionalScopeCount'])+' OPTIONAL esistenti sono preservati;massimo1auth amministrativa e4write.\n'
               'Prima degli effetti identita e snapshot correnti devono coincidere con la review;nessuna richiesta di scrivere in chat password/token.\n'
               'Nessun APPLY runtime,grant applicativo,budgetprofiling,resume,upload/job/acquisizione. STOP:non rilanciare.',
               'APPROVO CORREZIONE IAM '+digest(review))
        guard();ledger.approvedReviewHash=digest(review);ledger.deadline=wall()+210
        ledger.event('approval',reviewHash=ledger.approvedReviewHash,expiresAt=ledger.deadline,retainedAdministrativeAuthenticationReservations=1,
                     maximumNewAdministrativeAuthenticationRequests=1,oldBudgetsModified=False)
        endpoint=case['adminEndpoint'];password=prompt('Password IAM per '+endpoint['expectedAdminUser']+' (input nascosto):')
        ledger.deadline=min(ledger.deadline,wall()+120);deadline=ledger.deadline
        def live():guard();require(wall()<deadline,'FINITE_CORRECTION_WINDOW_EXPIRED')
        def payload(operation,credential,*,subject='',uuid='',scope='',name=''):
            return {'host':endpoint['connectHost'],'port':endpoint['connectPort'],'adminRealm':endpoint['adminRealm'],'clientId':endpoint['adminClientId'],
                    'expectedUser':endpoint['expectedAdminUser'],'targetRealm':case['realm'],'targetClient':case['clientId'],'operation':operation,
                    'credential':credential,'subject':subject,'clientUuid':uuid,'scopeUuid':scope,'scopeName':name,'operationRef':plan['operationRef']}
        def send(value):return sender(program,namespace,value)
        at=wall();response=ledger.request('authenticate','PASSWORD_GRANT',payload('PASSWORD_GRANT',password),send,live);password=None
        token,expiry,subject=access(types.SimpleNamespace(decode=decode),response,endpoint,case['issuer'],at);response=None;ledger.authenticated=True
        who=ledger.request('identity','IDENTITY',payload('IDENTITY',token,subject=subject),send,live,expiry=expiry)
        require(who.get('id')==subject and who.get('username')==endpoint['expectedAdminUser']and who.get('enabled')is True,'CURRENT_PROTECTED_IAM_ADMIN_IDENTITY_REQUIRED')
        ledger.identityVerified=True;del who
        def request(stage,operation,*,uuid='',scope='',name=''):
            return ledger.request(stage,operation,payload(operation,token,uuid=uuid,scope=scope,name=name),send,live,expiry=expiry)
        listing=request('client-list','CLIENT_LIST')
        require(type(listing)is list and len(listing)==1 and listing[0].get('id')==plan['clientUuid']and listing[0].get('clientId')==plan['clientId'],'SAME_RETAINED_CLIENT_NOT_A_NEW_CLIENT_REQUIRED')
        before=correction_snapshot(request,plan['clientUuid'],'before')
        require(before['report']==parent['bindingObservation'],'CURRENT_IAM_BASELINE_DRIFT_NO_WRITES')
        require(len(before['definitionIntegrity'])==plan['previousDefinitionCount']and plan['definitionToCreate']['id']not in before['definitionIntegrity'],'PREAPPROVED_NEW_SCOPE_ID_MUST_NOT_EXIST')
        c.put('before-invariants.json',before)
        containers();live();require(expiry>wall()+30,'INSUFFICIENT_CURRENT_TOKEN_WINDOW_BEFORE_FIRST_IAM_WRITE')
        definition=plan['definitionToCreate'];create_payload=payload('CREATE_SCOPE',token,uuid=plan['clientUuid'],scope=definition['id'],name=definition['name'])
        receipt=ledger.write('create-scope','CREATE_SCOPE',create_payload,send,live,expiry=expiry)
        require(receipt['status']in(0,201,429,500,502,503,504),'UNEXPECTED_SCOPE_CREATION_STATUS_NO_REPLAY')
        if receipt['status']==201:validate_location(receipt.get('location',''),plan,endpoint,case['issuer'])
        detail=request('created-scope-read','SCOPE_DETAIL',scope=definition['id'])
        validate_created_scope(detail,plan)
        roles=request('created-scope-roles','SCOPE_ROLES',scope=definition['id'])
        require(type(roles)is dict and not roles.get('realmMappings')and not roles.get('clientMappings'),'NEW_SCOPE_MUST_HAVE_NO_ROLE_RESTRICTIONS')
        ledger.observed('create-scope',ambiguous=receipt['status']!=201)
        initial_optionals=request('preassignment-optionals','OPTIONALS',uuid=plan['clientUuid'])
        require(link_map(initial_optionals)==link_map(before['optionals']),'OPTIONAL_BINDING_DRIFT_BEFORE_ASSIGNMENTS')
        expected=link_map(before['optionals'])
        for i,row in enumerate(plan['assignmentsToAdd']):
            stage='assign-'+str(i)
            value=payload('ASSIGN_OPTIONAL',token,uuid=plan['clientUuid'],scope=row['id'],name=row['name'])
            receipt=ledger.write(stage,'ASSIGN_OPTIONAL',value,send,live,expiry=expiry)
            require(receipt['status']in(0,204,429,500,502,503,504),'UNEXPECTED_OPTIONAL_ASSIGNMENT_STATUS_NO_REPLAY')
            expected={**expected,row['id']:row['name']}
            observed=request('optionals-after-'+str(i),'OPTIONALS',uuid=plan['clientUuid'])
            require(link_map(observed)==expected,'SAME_ASSIGNMENT_OUTCOME_NOT_PROVEN_NO_REPLAY')
            ledger.observed(stage,ambiguous=receipt['status']!=204)
        after=correction_snapshot(request,plan['clientUuid'],'after')
        verify_postcondition(before,after,plan);c.put('after-invariants.json',after)
        token=None;containers();guard()
        profile=configuration_profile(inputs['currentObservations']['onboarding'],after['report'],inputs['clientMetadata'],installation_ref=case['installationRef'])
        c.put('configuration-profile.json',profile)
        ledger.event('complete',configurationProfileHash=digest(profile),iamWritesObserved=4)
        result={'schema':'ouf.managed-profile-ths-iam-binding-correction-result.v1','status':'THS_IAM_BINDINGS_CORRECTED_CONFIGURATION_PROFILE_PREPARED_NOT_AUTHORIZED',
                'complete':True,'contextPath':str(c.root),'operationRef':plan['operationRef'],'reviewHash':digest(review),'parentResultHash':case['parentResultHash'],
                'counts':dict(c.counts),'bindingObservation':after['report'],'createdScopeId':definition['id'],'createdScopeName':definition['name'],
                'newScopeDefinitions':1,'newOptionalClientBindings':3,'preservedDefaultBindings':len(before['defaults']),'preservedOptionalBindings':len(before['optionals']),
                'nonCredentialClientPropertiesPreserved':True,'preexistingDefinitionsPreserved':True,'realmDefaultsPreserved':True,
                'configurationProfilePrepared':True,'configurationProfileHash':digest(profile),'addedRequestScopes':profile['addedRequestScopes'],
                'adminIdentityApiVerified':True,'adminSubjectFromSameFreshProviderIdToken':True,'jwtSignatureIndependentlyVerified':False,
                'humanIamCorrectionReviewApproved':True,'retainedAdministrativeAuthenticationReservations':parent['counts']['oauthRequestsReserved'],
                'cumulativeAdministrativeAuthenticationReservationsInThisLineage':parent['counts']['oauthRequestsReserved']+c.counts['oauthRequestsReserved'],
                'oldScopesAndFilesModified':False,'oldAuthenticationWindowsOrBudgetsReopened':False,'newAdministrativeCredentialValuesPersisted':False,
                'retainedEnvironmentMayContainCredentials':True,'credentialFilesRead':0,'configurationFileContentReads':0,'credentialValuesPrinted':False,
                'iamMutations':c.counts['iamWritesObserved'],'scopePatchApplied':False,'engineWrites':0,'sqlSessions':0,'imageImports':0,
                'newGrantsGranted':0,'humanBudgetsGranted':0,'resumes':0,'newJobs':0,'uploads':0,'sourceActivations':0,'acquisitionsExecuted':0,
                'historicalAuthorityReused':False,'currentJobOrBudgetStateObserved':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
                'automaticReplayAllowed':False,'budgetReset':False,'effectiveBrowserTokenScopesProven':False,'applicationE2EProven':False,'releaseAcceptance':False}
        c.put('result.json',result);return result
    finally:
        password=token=response=None;os.close(namespace)

def validate_parent_read(parent,case):
 require(parent.get('schema')=='ouf.managed-profile-ths-iam-binding-read-result.v1'and digest(parent)==case['parentResultHash']
         and parent['status']=='THS_IAM_BINDINGS_OBSERVED_CONFIGURATION_PROFILE_BLOCKED'and parent['complete']is True
         and parent['contextPath']==case['parentRoot']and parent['retainedClientInputsHash']==case['inputsHash']
         and parent['bindingObservation']==case['expectedObservation']and parent['configurationProfilePrepared']is False
         and parent['configurationProfileHash']is None and parent['adminIdentityApiVerified']is True
         and parent['counts']['oauthRequestsReserved']==1 and parent['counts']['adminGetsReserved']==14
         and parent['counts']['engineGets']==5 and parent['counts']['privateMetadataReads']==2
         and parent['iamMutations']==parent['engineWrites']==parent['humanBudgetsGranted']==parent['resumes']==0
         and all(parent[k]is False for k in ('runtimeAuthorityIssued','targetApplyAuthorized','automaticReplayAllowed','budgetReset','scopePatchApplied')),
         'EXACT_COMPLETED_CONSUMED_IAM_READ_REQUIRED')

def prepare_correction(c,case=CASE,*,engine_factory=Engine,pin=process_pin,boot_path=Path('/proc/sys/kernel/random/boot_id')):
 parent=c.private(Path(case['parentRoot'])/'result.json',case['parentResultHash']);validate_parent_read(parent,case)
 plan=compile_correction(parent['bindingObservation'],case['expectedObservation'],installation_ref=case['installationRef'],parent_result_hash=case['parentResultHash'],realm=case['realm'])
 old=Path(case['priorRoot']);inputs=c.private(old/'inputs.json',case['inputsHash']);receipt=c.private(old/'result.json')
 require(inputs.get('schema')=='ouf.managed-profile-ths-client-selection-inputs.v1'and digest(inputs)==case['inputsHash']
         and receipt.get('schema')=='ouf.managed-profile-ths-client-selection-result.v1'and receipt['complete']is True
         and receipt['status']=='MANAGED_PROFILE_THS_CLIENT_SELECTED_IAM_BINDING_NOT_OBSERVED'
         and receipt['contextPath']==str(old)and receipt['inputsHash']==case['inputsHash']and receipt['priorInputsHash']==inputs['priorInputsHash']==case['priorInputsHash']
         and receipt['counts']==case['priorCounts']and receipt['clientMetadata']==inputs['clientMetadata']
         and receipt['mountedFileContentIdentityProven']is True and receipt['sameImageAndGeneration']is True
         and receipt['iamRequests']==receipt['oauthRequests']==receipt['engineWrites']==receipt['humanBudgetsGranted']==receipt['resumes']==0,
         'EXACT_SUCCESSFUL_CONSUMED_CLIENT_SELECTION_REQUIRED')
 identity=inputs['clientMetadata'];require(identity['clientId']==case['clientId']and identity['issuer']==case['issuer']and identity['realm']==case['realm']
         and identity['registrationId']=='ouf-ths'and identity['providerIdExplicit']is True and identity['authorizationGrantTypeConfigured']=='authorization_code'
         and identity['fileSelectionAndPrecedenceVerified']is True and inputs['overlayBinding']['sha256']==case['overlaySha256']
         and all(inputs[k]is False for k in ('executionEntryQualified','runtimeAuthorityIssued','targetApplyAuthorized','automaticReplayAllowed','budgetReset')),'EXACT_OBSERVED_THS_CLIENT_AND_NO_OLD_AUTHORITY_REQUIRED')
 observed=inputs['currentObservations'];iam=inputs['iamRole'];require(len(observed)==2 and set(observed)=={'onboarding',iam}and observed[iam]['Name']==case['iamContainerName'],'EXACT_RETAINED_THS_AND_IAM_SELECTION_REQUIRED')
 binding=inputs['engineBinding'];engine=engine_factory(c,binding,[v['Id']for v in observed.values()]);rootpins=inputs['currentRootProcessPins']
 require(engine.get('/v1.44/info').get('ServerVersion')==case['expectedEngineVersion'],'QUALIFIED_CURRENT_ENGINE_VERSION_REQUIRED')
 def guard():
  require(boot_path.read_text().strip()==inputs['bootId']and rootpins=={'pid1':pin(1),'engine':pin(binding['peerCredentials'][0])},'SAME_CAPTURED_BOOT_AND_ROOT_PROCESSES_REQUIRED')
  for role,value in observed.items():require(pin(value['State']['Pid'])==inputs['currentProcessPins'][role],'CURRENT_THS_AND_IAM_PROCESS_GENERATIONS_REQUIRED')
  overlay=inputs['overlayBinding'];require(list(frame(Path(overlay['path']).lstat()))==overlay['metadata'],'PREVIOUSLY_READ_OWNER_OVERLAY_METADATA_CHANGED')
  mounted=Path('/proc')/str(observed['onboarding']['State']['Pid'])/'root'/identity['selectedMountTarget'].lstrip('/')
  require(list(frame(mounted.stat()))==overlay['metadata'],'CURRENT_MOUNTED_OWNER_FILE_IDENTITY_REQUIRED')
  for path,seal in c.seals.items():require(list(frame(Path(path).lstat()))==seal['metadata'],'CONSUMED_CLIENT_SELECTION_METADATA_DRIFT')
 def containers():
  guard()
  for role,expected in observed.items():
   actual=engine.get('/v1.44/containers/'+expected['Id']+'/json')
   require(stable_binding(actual)==stable_binding(expected)and actual['State']['Running']is True and actual['State']['Paused']is False and actual['State']['Restarting']is False,'EXACT_CURRENT_THS_AND_IAM_CONFIGURATIONS_REQUIRED')
 containers()
 program_path=Path(sys.executable).resolve();program={'path':str(program_path),'sha256':hashlib.sha256(program_path.read_bytes()).hexdigest()};executable(program)
 ns_path=Path('/proc')/str(observed[iam]['State']['Pid'])/'ns/net';ns=os.open(ns_path,os.O_RDONLY|os.O_CLOEXEC);ns_pin=[os.fstat(ns).st_dev,os.fstat(ns).st_ino]
 try:
  require(ns_pin==inputs['currentProcessPins'][iam]['namespaces']['net'],'EXACT_CAPTURED_IAM_NETWORK_NAMESPACE_REQUIRED')
 except BaseException:os.close(ns);raise
 def active_guard():
  guard();executable(program)
  require(ns_pin==[os.fstat(ns).st_dev,os.fstat(ns).st_ino]==[ns_path.stat().st_dev,ns_path.stat().st_ino],'CURRENT_IAM_NAMESPACE_REQUIRED')
 review={'schema':'ouf.ths-iam-binding-correction-review.v1','plan':plan,'retainedInputsHash':case['inputsHash'],
         'currentBindingsHash':digest({r:stable_binding(v)for r,v in observed.items()}),'currentProcessPins':inputs['currentProcessPins'],
         'adminEndpoint':case['adminEndpoint'],'maximumNewAdministrativeAuthenticationRequests':1,'maximumAdminGetAttempts':40,
         'maximumGetRetryReservations':4,'maximumIamWriteDispatches':4,'maximumEngineGets':7,'maximumSecondsAfterConsent':210,
         'maximumSecondsAfterPassword':120,'oldScopesAndBudgetsRemainConsumed':True,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False}
 c.put('review.json',review);review_path=c.root/'review.json'
 c.seals[str(review_path)]={'metadata':list(frame(review_path.lstat())),'sha256':hashlib.sha256(encoded(review)).hexdigest()}
 return inputs,parent,plan,review,ns,program,active_guard,containers

def main():
 c=None
 try:
  resource.setrlimit(resource.RLIMIT_CORE,(0,0))
  require(len(sys.argv)==1 and os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
          and os.environ.get('SUDO_UID')==str(pwd.getpwnam('oufadmin').pw_uid),'ISOLATED_OUFADMIN_ROOT_CORRECTION_REQUIRED')
  require(sys.stdin.isatty()and sys.stdout.isatty(),'INTERACTIVE_OPERATOR_TERMINAL_REQUIRED')
  code=Path(__file__).resolve();ancestry(code.parent);st=code.lstat()
  require(stat.S_ISREG(st.st_mode)and st.st_uid==st.st_gid==0 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o400,'PROTECTED_CORRECTION_ROOT400_REQUIRED')
  require(not os.path.lexists(CASE['outputRoot']),'THS_IAM_CORRECTION_SCOPE_CONSUMED_NO_REPLAY')
  sys.stdout=Logger(code.parent/'operator.log');signal.signal(signal.SIGALRM,lambda *_:require(False,'FINITE_IAM_CORRECTION_TOTAL_WINDOW_EXPIRED'));signal.alarm(600)
  c=CorrectionCapture(CASE['outputRoot'],2)
  result=execute_correction(c,prepare_correction(c),CASE)
 except BaseException as error:
  reason=str(error)if isinstance(error,Stop)and re.fullmatch('[A-Z0-9_]{1,120}',str(error))else'PRIVATE_IAM_CORRECTION_FAILURE_RECONCILE'
  counts=dict(c.counts)if c else{}
  result={'schema':'ouf.managed-profile-ths-iam-binding-correction-result.v1','status':'STOP_RECONCILE','complete':False,'reasonCode':reason,'counts':counts,
          'iamMutationsObserved':counts.get('iamWritesObserved',0),'iamMutationsMayHaveOccurred':counts.get('iamWritesReserved',0)>0,
          'automaticRollbackPerformed':False,'engineWrites':0,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
          'automaticReplayAllowed':False,'budgetReset':False,'applicationE2EProven':False,'releaseAcceptance':False}
  if c is not None and not(c.root/'result.json').exists():c.put('result.json',result)
 finally:signal.alarm(0)
 print(json.dumps(result,sort_keys=True,separators=(',',':')),flush=True)
 return 0 if result['complete']else 2
if __name__=='__main__':raise SystemExit(main())
