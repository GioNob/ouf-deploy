#!/usr/bin/env python3
"""Fresh read-only cohort plus private conditional same-image Onboarding plan.
No old main/authority, SQL, IAM/OAuth, imports, credentials or lifecycle ports.
"""
import copy,hashlib,http.client,ipaddress,json,os,pwd,re,signal,socket,stat,struct,sys,types
from pathlib import Path
MAXIMUMS={'engineGets':27,'privateMetadataReads':5,'responseBytes':2097152,'totalBytes':25165824,'seconds':120}
CASE={'authorityHash': '9ae7b608a7836e83d93df74d07612b121040854608bdf47cdd820a9d676f5bd1',
 'clientId': 'ouf-authorization-ths',
 'cohortSize': 13,
 'configurationProfileHash': 'd0dbbd61b5a6486124e229e646ce63a96165dfc2433ae200f7fec92383d5140c',
 'executionInputsHash': '900b09c6d29a20fda5dfff1f1333df167363c96e865cc2c13a7b58791f4e0c51',
 'frozenPlanHash': '06054f1cb3fe0045c3fdc3ca1cfa595444b90fd20d3ee589cae71e9ad3225dc5',
 'iamResultHash': 'c82b1b1025086faf4acf0899485643209f8929c4fa8ce6ca045fc2bfbdd7d027',
 'iamRoot': '/etc/ouf/deploy-snapshots/managed-profile-ths-iam-binding-correction-ba556e9f-20261028-v1',
 'installedRoot': '/etc/ouf/deploy-snapshots/managed-csv-control-update-900b09c6d29a20fd-v1',
 'nativeBindingHashes': {'mcp': 'd5750f01ee879ba43c28d97385ffd835c3e2836a48e6346d6bce5293a4831c19',
                         'onboarding': '1765524aacf85c6d47cb78e0a4cadcec7db0180c6506793102db188f80d65de8'},
 'nativeImageIds': {'mcp': 'sha256:a52180123104ac97e4979ad1b9b291654b076692da51708bb2a377301fef1220',
                    'onboarding': 'sha256:c512c24787304dc0ee40d2b5b1559d458ddf1d5a65a068775ef173c47ba849a3'},
 'outputRoot': '/etc/ouf/deploy-snapshots/managed-profile-ths-native-plan-d0dbbd61-20261028-v1',
 'reviewHash': '42db62a1d9d8f0423b88c86b4d56c50f39d9b0cd96ae6a2c11797583df3f830e',
 'sourceCommits': {'mcp': 'd2454f3cb8cd410d284b9dc78349a170187aea1c',
                   'onboarding': '9890b31868641e5be43c949a56f4ef69dd23bdfd'}}

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

def completed_history(review,result,journal,case):
    require(review.get('schema')=='ouf.managed-csv-control-update-review.v1' and digest(review)==case['reviewHash']
            and review['executionRoot']==case['installedRoot'] and review['frozenPlanHash']==case['frozenPlanHash']
            and digest(review['nativePlan']['proposal'])==case['frozenPlanHash'],'EXACT_SUCCESSFUL_CONTROL_REVIEW_REQUIRED')
    require(result.get('schema')=='ouf.managed-csv-control-update-result.v1'
            and result.get('status')=='MANAGED_CSV_CONTROL_UPDATE_INSTALLED_E2E_NOT_ACCEPTED'
            and result.get('complete')is True and result.get('componentReadinessProven')is True
            and result['reviewHash']==case['reviewHash'] and result['authorityHash']==case['authorityHash']
            and result['executionInputsHash']==case['executionInputsHash'] and result['frozenPlanHash']==case['frozenPlanHash']
            and result['candidateSourceCommits']==case['sourceCommits'] and result['nativeImageIds']==case['nativeImageIds']
            and result['humanBudgetsGranted']==result['resumes']==result['acquisitionsExecuted']==result['sourceActivations']==0
            and result['registryWorkerTouched']is False,'EXACT_SUCCESSFUL_CONSUMED_CONTROL_RESULT_REQUIRED')
    require(journal.get('schema')=='ouf.managed-csv-control-update-journal.v1' and journal['state']=='COMPLETE'
            and journal['reviewHash']==case['reviewHash'] and journal['authorityHash']==case['authorityHash']
            and journal['quarantine']is None and journal['automaticReplayAllowed']is False and journal['budgetReset']is False
            and journal['nextStage']==len(review['stages'])==len(journal['effects']) and set(journal['candidates'])=={'onboarding','mcp'},
            'COMPLETED_TWO_OWNER_HISTORY_REQUIRED')
    for stage,effect in zip(review['stages'],journal['effects']):
        require(effect['stage']==stage and effect['state']=='APPLIED'and effect['intentHash']==digest({'reviewHash':case['reviewHash'],'stage':stage}),'NO_AMBIGUOUS_RETAINED_CONTROL_EFFECT_REQUIRED')
    final=[e['proof']['ownerProofs']for e in journal['effects']if e['stage']=='VERIFY_FINAL']
    require(len(final)==1 and final[0]==result['ownerProofs'],'ONE_EXACT_RETAINED_FINAL_OWNER_PROOF_REQUIRED')
    cohort=copy.deepcopy(review['nativePlan']['proposal']['existingApplications'])
    require(len(cohort)==case['cohortSize'] and {'onboarding','mcp'}<=set(cohort),'EXACT_RETAINED_COHORT13_REQUIRED')
    for role in ('onboarding','mcp'):
        candidate=journal['candidates'][role];proof=result['ownerProofs'][role]
        require(candidate['configurationVerified']is True and candidate['readinessProven']is True
                and candidate['generation']==proof['generation'] and proof['nativeBindingHash']==case['nativeBindingHashes'][role],
                'EXACT_COMPLETED_OWNER_BINDING_REQUIRED')
        cohort[role]['containerId']=candidate['id']
    require(len({v['containerId']for v in cohort.values()})==case['cohortSize'],'DISTINCT_RETAINED_COHORT_REQUIRED')
    return cohort

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

CREATE_FIELDS=set('Hostname Domainname User AttachStdin AttachStdout AttachStderr ExposedPorts Tty OpenStdin StdinOnce Env Cmd Healthcheck Image Volumes WorkingDir Entrypoint Labels StopSignal StopTimeout MacAddress'.split())

def config_copy(actual):
    config=actual['Config'];ignored=set(config)-CREATE_FIELDS
    require(all(config[k]in(None,False,0,'',[],{})for k in ignored),'NONDEFAULT_UNSUPPORTED_CONTAINER_CONFIG')
    mac=config.get('MacAddress')
    require(mac in(None,'')or valid_mac(mac),'TYPED_RETAINED_CONFIG_MAC_REQUIRED')
    return {k:copy.deepcopy(v)for k,v in config.items()if k in CREATE_FIELDS and k!='MacAddress'}

def valid_mac(value):
    return type(value)is str and re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}',value)is not None and not(int(value[:2],16)&1)and value.lower()!='00:00:00:00:00:00'

def network(actual,aliases,preserve_mac=False):
    nets=actual['NetworkSettings']['Networks'];require(len(nets)==1,'ONE_RETAINED_ROLE_NETWORK_REQUIRED')
    name,value=next(iter(nets.items()));nid=value['NetworkID']
    require(re.fullmatch('[a-f0-9]{64}',nid)is not None and type(name)is str and name not in('host','none','bridge')and actual['HostConfig'].get('NetworkMode')in(name,nid),'BOUND_USER_DEFINED_ROLE_NETWORK_REQUIRED')
    require(all(type(v)is str and len(v)<=253 for v in aliases),'BOUNDED_NETWORK_ALIASES_REQUIRED')
    mac=value.get('MacAddress');declared=actual['Config'].get('MacAddress')
    require(valid_mac(mac),'RETAINED_ENDPOINT_MAC_REQUIRED')
    require(declared in(None,'')or declared.lower()==mac.lower(),'RETAINED_CONFIG_ENDPOINT_MAC_MISMATCH')
    endpoint={'NetworkID':nid,'Aliases':list(dict.fromkeys(aliases))}
    if preserve_mac:endpoint['MacAddress']=mac
    return {'name':name,'id':nid,'request':{'EndpointsConfig':{name:endpoint}}}

plan_helpers=types.SimpleNamespace(config_copy=config_copy,network=network,stable_binding=stable_binding)

def retain_allocations(actual, request, p):
    """Same V36 IP/port preservation, shared by the two replacement requests."""
    name = actual['Name'].removeprefix('/')
    require(re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,160}', name), 'BOUNDED_RETAINED_OWNER_NAME_REQUIRED')
    endpoint = next(iter(actual['NetworkSettings']['Networks'].values()))
    network = p.network(actual, [name, *(endpoint.get('Aliases') or [])], preserve_mac=True)
    ipam = copy.deepcopy(endpoint.get('IPAMConfig') or {})
    require(type(ipam) is dict and set(ipam) <= {'IPv4Address', 'IPv6Address', 'LinkLocalIPs'}, 'CLOSED_RETAINED_ENDPOINT_ALLOCATION')
    for source, target, version in [('IPAddress', 'IPv4Address', 4), ('GlobalIPv6Address', 'IPv6Address', 6)]:
        address = endpoint.get(source)
        if address:
            parsed = ipaddress.ip_address(address)
            require(parsed.version == version and not parsed.is_unspecified and not parsed.is_multicast
                    and ipam.get(target) in (None, '', address), 'RETAINED_STATIC_ENDPOINT_MISMATCH')
            ipam[target] = address
    network['request']['EndpointsConfig'][network['name']]['IPAMConfig'] = ipam
    for port, bindings in (request['HostConfig'].get('PortBindings') or {}).items():
        if any(row.get('HostPort') in (None, '', '0') for row in bindings):
            allocated = (actual['NetworkSettings'].get('Ports') or {}).get(port)
            require(type(allocated) is list and len(allocated) == len(bindings)
                    and all(type(row) is dict and str(row.get('HostPort', '')).isdigit()
                            and 1 <= int(row['HostPort']) <= 65535 for row in allocated), 'ALREADY_ALLOCATED_PUBLISHED_PORT_REQUIRED')
            request['HostConfig']['PortBindings'][port] = copy.deepcopy(allocated)
    request['NetworkingConfig'] = network['request']
    return {'name': network['name'], 'id': network['id']}

def valid(value):return type(value)is str and re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}',value)is not None and value.lower()!='00:00:00:00:00:00'and not(int(value[:2],16)&1)

def detached_config(original):
    config=original['Config'];mac=config.get('MacAddress');networks=original['NetworkSettings']['Networks']
    require('MacAddress'in config and valid(mac)and type(networks)is dict and len(networks)==1,'ONE_PROVEN_LEGACY_CONFIG_AND_ENDPOINT_MAC_REQUIRED')
    endpoint=next(iter(networks.values()));require(valid(endpoint.get('MacAddress'))and endpoint['MacAddress'].lower()==mac.lower(),'EXACT_LEGACY_ENDPOINT_MAC_EQUALITY_REQUIRED')
    result=copy.deepcopy(config);del result['MacAddress'];return result

def policy(original):
    expected=detached_config(original)
    return {'profile':'LEGACY_CONFIG_MAC_ABSENT_ONLY_AFTER_PROVEN_STOP_AND_DETACH_V1','originalConfigHash':digest(original['Config']),'detachedConfigHash':digest(expected),'originalEndpointSetHash':digest(original['NetworkSettings']['Networks']),'originalHashesRewritten':False}

retained_mac_policy=policy

def validate_profile(result, profile, actual, case):
    require(digest(result) == case['iamResultHash']
            and result['schema'] == 'ouf.managed-profile-ths-iam-binding-correction-result.v1'
            and result['status'] == 'THS_IAM_BINDINGS_CORRECTED_CONFIGURATION_PROFILE_PREPARED_NOT_AUTHORIZED'
            and result['complete'] is True and result['contextPath'] == case['iamRoot']
            and result['configurationProfileHash'] == case['configurationProfileHash']
            and result['configurationProfilePrepared'] is True
            and result['iamMutations'] == 4 and result['newScopeDefinitions'] == 1
            and result['newOptionalClientBindings'] == 3
            and result['preexistingDefinitionsPreserved'] is True
            and result['realmDefaultsPreserved'] is True
            and result['nonCredentialClientPropertiesPreserved'] is True
            and result['humanIamCorrectionReviewApproved'] is True
            and result['adminIdentityApiVerified'] is True
            and all(result[k] is False for k in ('scopePatchApplied','runtimeAuthorityIssued',
                'targetApplyAuthorized','automaticReplayAllowed','budgetReset')),
            'EXACT_SUCCESSFUL_CONSUMED_IAM_CORRECTION_REQUIRED')
    observed = result['bindingObservation']
    require(observed['bindingAndUnrestrictedEligibilityProven'] is True
            and observed['blockedScopes'] == [] and observed['defaultScopeCount'] == 14
            and observed['optionalScopeCount'] == 9 and observed['definitionCount'] == 70
            and [r['name'] for r in observed['requiredScopes']] == list(REQUIRED)
            and all(r['eligibleForExplicitRequest'] is True and r['binding'] == 'OPTIONAL'
                    for r in observed['requiredScopes']), 'PROVED_RETAINED_IAM_OPTIONAL_BINDINGS_REQUIRED')
    require(digest(profile) == case['configurationProfileHash']
            and profile['schema'] == 'ouf.ths-additive-owner-configuration-profile.v1'
            and profile['ownerContainerId'] == actual['Id']
            and profile['ownerImageId'] == actual['Image'] == case['nativeImageIds']['onboarding']
            and profile['currentConfigurationHash'] == digest(actual['Config'])
            and profile['clientId'] == observed['clientId'] == case['clientId']
            and profile['iamBindingSnapshotHash'] == observed['bindingSnapshotHash']
            and profile['requiredScopes'] == list(REQUIRED)
            and profile['sameNativeImageRequired'] is True
            and profile['allOtherPropertiesPreserved'] is True
            and profile['freshRuntimeAndJobFencesRequired'] is True
            and profile['newHumanExecutionReviewRequired'] is True
            and all(profile[k] is False for k in ('executionEntryQualified','runtimeAuthorityIssued',
                'targetApplyAuthorized','effectiveBrowserTokenScopesProven','automaticReplayAllowed','budgetReset')),
            'EXACT_PRIVATE_CONDITIONAL_SAME_OWNER_PROFILE_REQUIRED')
    summary, environment = scope_patch(actual)
    candidate = copy.deepcopy(actual['Config']); candidate['Env'] = environment
    require(environment == profile['replacementEnvironment']
            and summary['requestedScopes'] == profile['preservedRequestedScopes']
            and summary['missingRequestScopes'] == profile['addedRequestScopes'] == list(REQUIRED)
            and summary['requestBeforeHash'] == profile['requestBeforeHash']
            and summary['conditionalRequestAfterHash'] == profile['requestAfterHash']
            and digest(candidate) == profile['proposedConfigurationHash'],
            'EXACT_ADDITIVE_REQUEST_PROFILE_REQUIRED')
    return summary, environment

def compile_native_plan(capture, review, iam_result, profile, case):
    require(capture['engineInfo'].get('ServerVersion') == '29.8.1'
            and ['driver-type','io.containerd.snapshotter.v1'] in (capture['engineInfo'].get('DriverStatus') or []),
            'QUALIFIED_NATIVE_ENGINE_PROFILE_REQUIRED')
    actual = capture['currentObservations']['onboarding']
    summary, environment = validate_profile(iam_result, profile, actual, case)
    retained = review['nativePlan']['proposal']
    facts = retained['candidateApplicationFacts']
    require(len(facts['migrations']) == 36 and facts['applicationYamlSha256']
            and retained['databaseMigration'] == {'from':36,'to':36,'newMigrations':0},
            'RETAINED_SCHEMA36_FACTS_REQUIRED_NOT_DATABASE_ADMISSION')
    request = plan_helpers.config_copy(actual)
    request['Env'] = copy.deepcopy(environment)
    host = copy.deepcopy(actual['HostConfig']); restore = copy.deepcopy(host['RestartPolicy'])
    require(host.get('AutoRemove') is False and type(host.get('Memory')) is int
            and host['Memory'] >= 0
            and (host.get('OomKillDisable') is None or type(host['OomKillDisable']) is bool),
            'EXACT_RETAINED_OWNER_RESOURCE_POLICY_REQUIRED')
    host['RestartPolicy'] = {'Name':'no','MaximumRetryCount':0}
    request.update(Image=actual['Image'], HostConfig=host)
    network = retain_allocations(actual, request, plan_helpers)
    old = plan_helpers.stable_binding(actual)
    image = retained['readReplacements']['onboarding']['imageAudit']
    require(image['nativeIdentity']['nativeImageId'] == actual['Image'],
            'RETAINED_SAME_NATIVE_IMAGE_AUDIT_REQUIRED')
    defaults = image['imageConfig'].get('Labels') or {}
    labels = actual['Config'].get('Labels') or {}
    require(all(k.startswith('org.opencontainers.image.') for k in set(defaults)-set(labels)),
            'NO_UNREVIEWED_IMAGE_DEFAULT_LABEL_ADDITIONS')
    replacement = {'name':actual['Name'].removeprefix('/'),
        'retiredName':actual['Name'].removeprefix('/')+'-retained-ths-request-'+case['configurationProfileHash'][:12],
        'request':request, 'restoreRestartPolicy':restore, 'oldBinding':old,
        'oldNativeHostConfig':copy.deepcopy(actual['HostConfig']), 'network':network,
        'imageAudit':copy.deepcopy(image),
        'readiness':copy.deepcopy(retained['readReplacements']['onboarding']['readiness']),
        'runtimeLabelProjection':{'expectedLabels':{**defaults, **labels}},
        'oldRetainedStopped':True, 'oldMustBeStoppedAndDetachedBeforeNewStarts':True,
        'sameNativeImageRequired':True, 'nativeImageImportAuthorized':False}
    replacement['legacyConfigMacDetachPolicy'] = retained_mac_policy(actual) if actual['Config'].get('MacAddress') else {
        'profile':'NO_LEGACY_CONFIG_MAC_CHANGE_RETAIN_EXACT_V1',
        'originalConfigHash':digest(actual['Config']),
        'originalEndpointSetHash':digest(actual['NetworkSettings']['Networks']), 'originalHashesRewritten':False}
    if host.get('OomKillDisable') is None:
        replacement['runtimeHostProjection'] = {'profile':'DOCKER_ENABLED_OOM_DEFAULT_NULL_FALSE_V1',
            'requestedOomKillDisable':None,'materializedOomKillDisable':False,'retainedMemoryBytes':host['Memory']}
    require(len(capture['currentObservations']) == 13
            and set(capture['currentObservations']) == set(capture['currentProcessPins']),
            'EXACT_FRESH_COHORT13_REQUIRED')
    plan = {'schema':'ouf.ths-owner-request-conditional-native-plan.v1',
        'kind':'FROZEN_CONDITIONAL_PROPOSAL_NOT_EXECUTABLE',
        'configurationProfileHash':case['configurationProfileHash'], 'iamResultHash':case['iamResultHash'],
        'iamBindingSnapshotHash':iam_result['bindingObservation']['bindingSnapshotHash'],
        'bootId':capture['bootId'], 'engineBinding':copy.deepcopy(capture['engineBinding']),
        'engineInfoHash':digest(capture['engineInfo']),
        'currentRootProcessPins':copy.deepcopy(capture['currentRootProcessPins']),
        'currentProcessPins':copy.deepcopy(capture['currentProcessPins']),
        'existingApplications':{r:plan_helpers.stable_binding(v) for r,v in capture['currentObservations'].items()},
        'unchangedApplications':{r:plan_helpers.stable_binding(v) for r,v in capture['currentObservations'].items() if r != 'onboarding'},
        'replacements':{'onboarding':replacement}, 'targetRoles':['onboarding'],
        'boundDatabaseProfile':copy.deepcopy(retained['boundDatabaseProfile']),
        'nativeFlywayConfiguration':copy.deepcopy(retained['nativeFlywayConfiguration']),
        'candidateApplicationFacts':copy.deepcopy(facts), 'databaseMigration':{'from':36,'to':36,'newMigrations':0},
        'scopeRequestDelta':{k:summary[k] for k in ('requestedScopes','missingRequestScopes','requestBeforeHash','conditionalRequestAfterHash')},
        'futureRequirements':['NEW_CONCRETE_HUMAN_EXECUTION_REVIEW_AND_SIGNED_AUTHORITY',
            'FRESH_SCHEMA36_AND_EXACT_FAILED5_OPERATIONAL_STATE_ADMISSION',
            'CURRENT_NETWORK_MEMBERSHIP_AND_RETIRED_NAME_AVAILABILITY',
            'CURRENT_OWNER_OVERLAY_AND_PROCESS_ROOT_PRECEDENCE',
            'VERIFIED_QUIESCED_BACKUP', 'SEPARATE_HUMAN_JOB_BUDGET_AND_RESUME'],
        'executionEntryQualified':False, 'databaseAdmissionProven':False,
        'currentJobOrBudgetStateObserved':False, 'runtimeAuthorityIssued':False, 'targetApplyAuthorized':False,
        'iamConfigurationMutationAuthorized':False, 'imageImportAuthorized':False,
        'humanBudgetsOrResumeAuthorized':False, 'sourceActivationAuthorized':False,
        'automaticRollbackAllowed':False,'automaticReplayAllowed':False,'budgetReset':False,
        'applicationE2EProven':False,'releaseAcceptance':False}
    return plan

def capture_current(capture,case=CASE,*,engine_factory=Engine,pin=process_pin,boot_path=Path('/proc/sys/kernel/random/boot_id')):
    c=capture;root=Path(case['installedRoot'])
    review=c.private(root/'review.json',case['reviewHash']);result=c.private(root/'result.json');journal=c.private(root/'recovery.json')
    cohort=completed_history(review,result,journal,case)
    require(boot_path.read_text().strip()==review['bootId'],'SAME_RETAINED_HOST_BOOT_REQUIRED')
    binding=review['nativePlan']['proposal']['engineBinding'];engine=engine_factory(c,binding,[v['containerId']for v in cohort.values()])
    root_pins={'pid1':pin(1),'engine':pin(binding['peerCredentials'][0])}
    info=engine.get('/v1.44/info');require(info.get('ServerVersion')=='29.8.1','QUALIFIED_ENGINE_VERSION_REQUIRED');observations={};generations={}
    for role,expected in sorted(cohort.items()):
        actual=engine.get('/v1.44/containers/'+expected['containerId']+'/json');current=stable_binding(actual)
        require(actual['State']['Running']is True and actual['State']['Paused']is False and actual['State']['Restarting']is False,'CURRENT_COHORT_RUNNING_REQUIRED')
        generation=pin(actual['State']['Pid'])
        if role in ('onboarding','mcp'):
            require(digest(current)==case['nativeBindingHashes'][role] and actual['Image']==case['nativeImageIds'][role]
                    and generation==journal['candidates'][role]['generation'],'EXACT_INSTALLED_OWNER_GENERATION_REQUIRED')
        else:require(current==expected,'UNCHANGED_RETAINED_PEER_GENERATION_REQUIRED')
        observations[role]=actual;generations[role]=generation
    for role,first in sorted(observations.items()):
        again=engine.get('/v1.44/containers/'+first['Id']+'/json')
        require(stable_binding(first)==stable_binding(again)and generations[role]==pin(again['State']['Pid']),'CURRENT_CAPTURE_GENERATION_DRIFT')
    require(root_pins=={'pid1':pin(1),'engine':pin(binding['peerCredentials'][0])}and boot_path.read_text().strip()==review['bootId'],'ENGINE_ROOT_OR_BOOT_DRIFT')
    for path,seal in c.seals.items():require(list(frame(Path(path).lstat()))==seal['metadata'],'RETAINED_CONTROL_METADATA_DRIFT')
    summary,patched=scope_patch(observations['onboarding'])
    payload={'schema':'ouf.managed-profile-ths-scope-current-inputs.v1','bootId':review['bootId'],'engineBinding':binding,'engineInfo':info,
             'currentObservations':observations,'currentProcessPins':generations,'currentRootProcessPins':root_pins,
             'historySeals':c.seals,'retainedReviewHash':case['reviewHash'],'retainedAuthorityHash':case['authorityHash'],
             'retainedScopeConsumed':True,'historicalAuthorityReused':False,'scopeInspection':summary,
             'conditionalOnboardingEnvironment':patched,'conditionalPatchOnly':True,'executionEntryQualified':False,
             'targetApplyAuthorized':False,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False}
    return payload,review

class PlanCapture(Capture):
    def __init__(self,root,cohort_size):
        # Reuse the existing protected five-read custody mode; no old STOP is
        # reopened and no previous counters or operation windows are reset.
        super().__init__(root,cohort_size,reconcile=True)

def prepare(c,case=CASE,*,engine_factory=Engine,pin=process_pin,boot_path=Path('/proc/sys/kernel/random/boot_id')):
    captured,review=capture_current(c,case,engine_factory=engine_factory,pin=pin,boot_path=boot_path)
    iam=c.private(Path(case['iamRoot'])/'result.json',case['iamResultHash'])
    profile=c.private(Path(case['iamRoot'])/'configuration-profile.json',case['configurationProfileHash'])
    plan=compile_native_plan(captured,review,iam,profile,case)
    require(all(list(frame(Path(path).lstat()))==seal['metadata'] for path,seal in c.seals.items()),'PLAN_INPUT_SEAL_CHANGED')
    require(captured['currentRootProcessPins']=={'pid1':pin(1),'engine':pin(captured['engineBinding']['peerCredentials'][0])}
        and boot_path.read_text().strip()==captured['bootId']
        and all(pin(v['pid'])==v for v in captured['currentProcessPins'].values()),'PLAN_PROCESS_OR_BOOT_DRIFT')
    c.put('execution-plan.json',plan)
    private={'schema':'ouf.ths-owner-request-private-native-inputs.v1','currentCapture':captured,
        'conditionalNativePlanHash':digest(plan),'configurationProfileHash':case['configurationProfileHash'],
        'retainedSuccessfulControlReview':review,'retainedIamResult':iam,'historySeals':c.seals,
        'executionEntryQualified':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
        'automaticReplayAllowed':False,'budgetReset':False}
    c.put('execution-inputs.json',private)
    output={'schema':'ouf.ths-owner-request-native-plan-result.v1',
        'status':'THS_OWNER_REQUEST_CONDITIONAL_NATIVE_PLAN_PREPARED_NOT_AUTHORIZED',
        'complete':True,'contextPath':str(c.root),'executionInputsHash':digest(private),
        'conditionalNativePlanHash':digest(plan),'configurationProfileHash':case['configurationProfileHash'],
        'iamResultHash':case['iamResultHash'],'retainedIamBindingSnapshotHash':iam['bindingObservation']['bindingSnapshotHash'],
        'targetRoles':['onboarding'],'cohortSize':13,'unchangedPeers':12,'sameNativeImageRequired':True,
        'nativeImageId':case['nativeImageIds']['onboarding'],'sourceCommit':case['sourceCommits']['onboarding'],
        'addedRequestScopes':list(REQUIRED),'preservedRequestedScopeCount':len(profile['preservedRequestedScopes']),
        'counts':dict(c.counts),'databaseMigration':{'from':36,'to':36,'newMigrations':0},
        'databaseAdmissionProven':False,'currentJobOrBudgetStateObserved':False,
        'executionEntryQualified':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
        'iamRequests':0,'oauthRequests':0,'credentialFileReads':0,'configurationFileContentReads':0,'signingKeyReads':0,
        'engineWrites':0,'sqlSessions':0,'imageImports':0,'newGrantsGranted':0,'humanBudgetsGranted':0,'resumes':0,
        'newJobs':0,'uploads':0,'sourceActivations':0,'acquisitionsExecuted':0,'registryWorkerTouched':False,
        'scopePatchApplied':False,'effectiveBrowserTokenScopesProven':False,'historicalAuthorityReused':False,
        'automaticReplayAllowed':False,'budgetReset':False,'applicationE2EProven':False,'releaseAcceptance':False}
    c.put('result.json',output);return output

def main():
    c=None
    try:
        require(len(sys.argv)==1 and os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site
            and sys.dont_write_bytecode and os.environ.get('SUDO_UID')==str(pwd.getpwnam('oufadmin').pw_uid),
            'ISOLATED_OUFADMIN_ROOT_NATIVE_PLAN_REQUIRED')
        require(sys.stdin.isatty()and sys.stdout.isatty(),'INTERACTIVE_OPERATOR_TERMINAL_REQUIRED')
        code=Path(__file__).resolve();ancestry(code.parent);st=code.lstat()
        require(stat.S_ISREG(st.st_mode)and st.st_uid==st.st_gid==0 and st.st_nlink==1
            and stat.S_IMODE(st.st_mode)==0o400,'PROTECTED_NATIVE_PLANNER_ROOT400_REQUIRED')
        require(not os.path.lexists(CASE['outputRoot']),'THS_NATIVE_PLAN_SCOPE_CONSUMED_NO_REPLAY')
        sys.stdout=Logger(code.parent/'operator.log')
        signal.signal(signal.SIGALRM,lambda *_:require(False,'FINITE_NATIVE_PLAN_WINDOW_EXPIRED'));signal.alarm(120)
        c=PlanCapture(CASE['outputRoot'],13)
        print('NUOVO piano privato condizionale:5metadata conservati,27GET Engine coorte13. Solo Onboarding stessa immagine;12peer invariati. Zero SQL/IAM/OAuth/config/credenziali/chiavi/import/lifecycle/grant/budget/resume. Nessun login o APPROVO. Max120s;STOP conservare senza rilancio.',flush=True)
        result=prepare(c)
    except BaseException as error:
        reason=str(error)if isinstance(error,Stop)and re.fullmatch('[A-Z0-9_]{1,120}',str(error))else'PRIVATE_NATIVE_PLAN_FAILURE_RECONCILE'
        result={'schema':'ouf.ths-owner-request-native-plan-result.v1','status':'STOP_RECONCILE','complete':False,'reasonCode':reason,
            'contextPath':str(c.root)if c else None,'counts':dict(c.counts)if c else{},'engineWrites':0,
            'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False,
            'applicationE2EProven':False,'releaseAcceptance':False}
        if c is not None and not(c.root/'result.json').exists():c.put('result.json',result)
    finally:signal.alarm(0)
    print(json.dumps(result,sort_keys=True,separators=(',',':')),flush=True)
    return 0 if result['complete']else 2
if __name__=='__main__':raise SystemExit(main())
