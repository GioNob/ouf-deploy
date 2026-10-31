#!/usr/bin/env python3
"""One-use selected THS client observation. Not an IAM login, binding or runtime update."""
import copy,hashlib,http.client,json,os,pwd,re,signal,socket,stat,struct,sys,time
from pathlib import Path
from urllib.parse import urlsplit
MAXIMUMS={'engineGets':5,'privateMetadataReads':3,'responseBytes':2097152,'totalBytes':25165824,'seconds':60}
CASE={'priorRoot':'/etc/ouf/deploy-snapshots/managed-profile-ths-scope-capture-policy58-20261028-v1',
      'inputsHash':'fdc618841f14eeb0c99ee3f61f0971affefff5f13d740d406db376d3daaa7bec',
      'installedRoot':'/etc/ouf/deploy-snapshots/managed-csv-control-update-900b09c6d29a20fd-v1',
      'reviewHash':'42db62a1d9d8f0423b88c86b4d56c50f39d9b0cd96ae6a2c11797583df3f830e',
      'frozenPlanHash':'06054f1cb3fe0045c3fdc3ca1cfa595444b90fd20d3ee589cae71e9ad3225dc5',
      'ownerOverlayPath':'/opt/ouf/secrets/onboarding-ths.yaml',
      'onboardingBindingHash':'1765524aacf85c6d47cb78e0a4cadcec7db0180c6506793102db188f80d65de8',
      'outputRoot':'/etc/ouf/deploy-snapshots/managed-profile-ths-client-selection-fdc61884-20261028-v1'}
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

def owner_json_overlay(raw):
    """Closed JSON owner/OAuth configuration; no Spring loading/migration channels."""
    def unique(rows):
        value={}
        for key,item in rows:
            require(key not in value,'DUPLICATE_OWNER_OVERLAY_KEY');value[key]=item
        return value
    try:
        value=json.loads(raw,object_pairs_hook=unique,
            parse_constant=lambda _:require(False,'NONFINITE_OWNER_OVERLAY'))
    except (ValueError,TypeError,RecursionError):require(False,'STRICT_OWNER_JSON_REQUIRED')
    require(type(value)is dict and bool(value),'OWNER_JSON_OBJECT_REQUIRED')
    found=set();nodes=0;session={}
    session_fields={'server.servlet.session.cookie.httponly':bool,'server.servlet.session.cookie.secure':bool,
        'server.servlet.session.cookie.samesite':str,'server.servlet.session.timeout':str}
    def visit(obj,prefix=(),depth=0):
        nonlocal nodes
        require(type(obj)is dict and bool(obj) and depth<=16,'BOUNDED_OWNER_JSON_OBJECT')
        for key,item in obj.items():
            nodes+=1;require(nodes<=512 and type(key)is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_.-]{0,127}',key),'OWNER_JSON_KEY_SCHEMA')
            parts=prefix+tuple(key.split('.'))
            require(all(parts),'OWNER_JSON_EMPTY_SEGMENT')
            canonical=tuple(re.sub('[^a-z0-9]','',part.lower()) for part in parts)
            require(all(canonical),'OWNER_JSON_EMPTY_CANONICAL_SEGMENT')
            if type(item)is dict:visit(item,parts,depth+1);continue
            name='.'.join(canonical)
            require(not any(name==old or name.startswith(old+'.') or old.startswith(name+'.') for old in found),'AMBIGUOUS_OWNER_JSON_PROPERTY');found.add(name)
            owner=canonical[:1]==('ouf',) and not ''.join(canonical).startswith('oufonbdb')
            oauth=canonical[:5]==('spring','security','oauth2','client','registration') or canonical[:5]==('spring','security','oauth2','client','provider')
            require(owner or oauth or name in session_fields,'UNREVIEWED_OWNER_JSON_NAMESPACE')
            if name in session_fields:
                require(type(item)is session_fields[name],'SESSION_PROPERTY_TYPE_CHANGED')
                session[name]=item
            if oauth:
                require(len(parts)==7 and (parts[5]=='ouf-ths' if canonical[4]=='registration' else re.fullmatch('[A-Za-z0-9_-]{1,128}',parts[5])),'EXACT_THS_OAUTH_MAP_KEY_REQUIRED')
                fields={'clientid','clientsecret','clientauthenticationmethod','authorizationgranttype','redirecturi','scope','provider'} if canonical[4]=='registration' else {'issueruri','authorizationuri','tokenuri','userinfouri','usernameattribute','jwkseturi'}
                require(canonical[-1] in fields,'UNREVIEWED_THS_OAUTH_PROPERTY')
            require(type(item) in (str,bool,int,list),'OWNER_JSON_SCALAR_TYPE')
            values=item if type(item)is list else [item]
            require(len(values)<=256 and all(type(v)in(str,bool,int) for v in values),'OWNER_JSON_SCALAR_LIST')
            if oauth:
                require(type(item)is str or canonical[-1]=='scope' and type(item)is list and all(type(v)is str for v in item),'THS_OAUTH_PROPERTY_TYPE')
            for v in values:
                require(type(v)is not str or len(v)<=65536 and not any(c in v for c in ('${','#{','\x00')),'LITERAL_OWNER_JSON_VALUES_REQUIRED')
    visit(value)
    if session:
        require(set(session)==set(session_fields),'COMPLETE_RETAINED_SESSION_PROPERTIES_REQUIRED')
        require(session['server.servlet.session.cookie.httponly'] is True and session['server.servlet.session.cookie.secure'] is True,'SECURE_HTTPONLY_SESSION_REQUIRED')
        require(session['server.servlet.session.cookie.samesite'].lower() in ('strict','lax','none'),'EXPLICIT_SESSION_SAMESITE_REQUIRED')
        timeout=session['server.servlet.session.timeout']
        simple=re.fullmatch(r'[1-9][0-9]{0,8}(?i:ns|us|ms|s|m|h|d)?',timeout)
        iso=re.fullmatch(r'P(?:[0-9]{1,8}D)?(?:T(?:[0-9]{1,8}H)?(?:[0-9]{1,8}M)?(?:[0-9]{1,8}(?:\.[0-9]{1,9})?S)?)?',timeout)
        require(simple or iso and not timeout.endswith('T') and any(c in '123456789' for c in timeout),'FINITE_POSITIVE_SESSION_TIMEOUT_REQUIRED')
    return {'format':'STRICT_JSON','ownerThsOAuthAndSessionOnly':True,'retainedSessionSecurityValidated':bool(session),'migrationOverridePresent':False,
            'propertyCount':len(found),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
            'configurationValuesPrinted':False}

def additional_location(value):
    require(type(value) is str and 0 < len(value) <= 4096, 'EXACT_ADDITIONAL_LOCATION_REQUIRED')
    if value.startswith('optional:'):
        value = value[len('optional:'):]
    require(value.startswith('file:'), 'ONLY_RETAINED_FILE_OVERLAY_SUPPORTED')
    path = value[len('file:'):]
    require(path.startswith('/') and str(Path(path)) == path and '..' not in Path(path).parts
            and re.fullmatch(r'/[A-Za-z0-9_./-]+\.(?:yml|yaml)',path), 'EXACT_SINGLE_OWNER_OVERLAY_REQUIRED')
    return path

REGISTRATION_PREFIX='spring.security.oauth2.client.registration.ouf-ths.'

def oauth_properties(obj):
    result={}
    def walk(value,prefix=()):
        require(type(value)is dict,'OAUTH_PROPERTY_OBJECT_REQUIRED')
        for key,item in value.items():
            require(type(key)is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_.-]{0,127}',key),'OAUTH_PROPERTY_KEY_REQUIRED')
            parts=prefix+tuple(key.split('.'))
            require(all(parts),'OAUTH_EMPTY_PROPERTY_SEGMENT')
            canonical=[re.sub('[^a-z0-9]','',s.lower())for s in parts]
            # Registration/provider map keys are case-sensitive literal keys.
            if canonical[:5]in (['spring','security','oauth2','client','registration'],['spring','security','oauth2','client','provider'])and len(parts)>5:canonical[5]=parts[5]
            name='.'.join(canonical)
            if type(item)is dict:walk(item,parts);continue
            require(not any(name==old or name.startswith(old+'.')or old.startswith(name+'.')for old in result),'AMBIGUOUS_OAUTH_PROPERTY')
            result[name]=item
    walk(obj);return result

def selected_overlay(actual,retained):
    # The successful native update already classified the lower-priority loader
    # and pinned this one overlay. This helper neither discovers nor adopts files.
    scope_patch(actual)
    env=dict(row.split('=',1)for row in actual['Config']['Env'])
    require(not env.get('_JAVA_OPTIONS')and not any(a.startswith('@')for a in(actual['Config'].get('Entrypoint')or[])+(actual['Config'].get('Cmd')or[])),'UNREVIEWED_ADDITIONAL_JVM_OVERRIDE')
    require(not any(re.sub('[^a-z0-9]','',k.lower())in ('springconfigimport','springconfiglocation')for k in env),'UNREVIEWED_CONFIG_LOADER_OVERRIDE')
    target=additional_location(env.get('SPRING_CONFIG_ADDITIONAL_LOCATION'))
    require(type(retained)is dict and set(retained)>={'binding','target'}and retained['target']==target,'EXACT_RETAINED_OWNER_OVERLAY_TARGET_REQUIRED')
    mounts=[v for v in actual['Mounts']if v.get('Destination')==target]
    require(len(mounts)==1 and mounts[0].get('Type')=='bind'and mounts[0].get('RW')is False and mounts[0].get('Source')==retained['binding']['path'],'EXACT_SELECTED_READ_ONLY_OWNER_OVERLAY_REQUIRED')
    high=oauth_properties(decode(env['SPRING_APPLICATION_JSON']))
    require(not any(k.startswith(('spring.config.','spring.profiles.','loader.'))for k in high),'UNREVIEWED_JSON_LOADER_OVERRIDE')
    return target,high

def client_metadata(actual,raw,retained):
    target,high=selected_overlay(actual,retained)
    owner_json_overlay(raw)  # Reuse the qualified closed literal JSON verifier.
    low=oauth_properties(decode(raw));effective={**low,**high}
    prefix=REGISTRATION_PREFIX
    def key(s):
        parts=s.split('.');return '.'.join(re.sub('[^a-z0-9]','',p.lower())if i!=5 else p for i,p in enumerate(parts))
    client=effective.get(key(prefix+'client-id'))
    require(type(client)is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}',client),'LITERAL_EFFECTIVE_THS_CLIENT_ID_REQUIRED')
    provider=effective.get(key(prefix+'provider'),'ouf-ths')
    require(type(provider)is str and re.fullmatch('[A-Za-z0-9_-]{1,128}',provider),'LITERAL_THS_PROVIDER_REQUIRED')
    provider_prefix='spring.security.oauth2.client.provider.'+provider+'.'
    issuer=effective.get(key(provider_prefix+'issuer-uri'))
    require(type(issuer)is str and len(issuer)<=2048,'EXPLICIT_LITERAL_THS_ISSUER_REQUIRED')
    url=urlsplit(issuer)
    require(url.scheme=='https'and bool(url.hostname)and not url.username and not url.password and not url.query and not url.fragment
            and re.fullmatch('/realms/[A-Za-z0-9_.-]{1,128}',url.path)and issuer==url.geturl(),'EXACT_HTTPS_REALM_ISSUER_REQUIRED')
    require(not any(key(provider_prefix+suffix)in effective for suffix in ('authorization-uri','token-uri','userinfo-uri','jwk-set-uri')),'EXPLICIT_PROVIDER_ENDPOINT_OVERRIDE_REQUIRES_REVIEW')
    grant=effective.get(key(prefix+'authorization-grant-type'))
    require(grant in (None,'authorization_code'),'THS_BROWSER_AUTHORIZATION_CODE_REQUIRED')
    return {'registrationId':'ouf-ths','clientId':client,'clientIdOrigin':'SPRING_APPLICATION_JSON'if key(prefix+'client-id')in high else 'RETAINED_MOUNTED_OWNER_OVERLAY',
            'providerId':provider,'providerIdExplicit':key(prefix+'provider')in effective,'issuer':issuer,'realm':url.path.split('/')[-1],
            'authorizationGrantTypeConfigured':grant,'selectedMountTarget':target,'fileSelectionAndPrecedenceVerified':True,
            'rawOverlayPersisted':False,'credentialValuesPrinted':False,'iamBindingObserved':False,'browserTokenInspected':False}

EXTERNAL_ADMIN_KEY = '/opt/ouf/secrets/apisix-admin-key'

_EXISTING_CONFIG_CUSTODY = {
    # These are the observed, already-running selections on this host. Do not
    # change ownership of /opt/ouf or the files mounted into live containers.
    '/opt/ouf/installation/active-projection.json': {
        'parents': {'/opt/ouf': (1000, 1000, 0o750),
                    '/opt/ouf/installation': (0, 0, 0o700)},
        'file': (0, 0, 0o600)},
    '/opt/ouf/secrets/onboarding-ths.yaml': {
        'parents': {'/opt/ouf': (1000, 1000, 0o750),
                    '/opt/ouf/secrets': (1000, 1000, 0o700)},
        'file': (10003, 10003, 0o400)},
    EXTERNAL_ADMIN_KEY: {
        'parents': {'/opt/ouf': (1000, 1000, 0o750),
                    '/opt/ouf/secrets': (1000, 1000, 0o700)},
        # 0600 does not grant group access. The observed uid/mode are fixed;
        # the actual gid is pinned by the returned file metadata.
        'file': (1000, None, 0o600)},
    '/etc/ouf/deploy-snapshots/consultation-human-read-20261002-1153/prepared/apisix-config.yaml': {
        'parents': {}, 'file': (636, 636, 0o400)},
}

def selected_directory_custody(info, path, exception):
    selected = exception['parents'].get(path) if exception else None
    if selected is not None:
        return (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == selected
    return info.st_uid == 0 and not info.st_mode & 0o022

def selected_file_custody(info, exception):
    selected = exception['file'] if exception else None
    if selected is not None:
        uid,gid,mode=selected
        return info.st_uid==uid and (gid is None or info.st_gid==gid) and stat.S_IMODE(info.st_mode)==mode
    return info.st_uid == 0 and stat.S_IMODE(info.st_mode) in (0o400,0o440,0o444,0o600,0o640,0o644)

def private_config(path, expected=None):
    """Read an exact selected file with pinned, no-follow path custody.

    The three existing selections above have different named owners. All
    other paths, including newly staged APISIX config, retain root custody.
    """
    target = Path(path)
    require(target.is_absolute() and '..' not in target.parts, 'EXACT_APISIX_CONFIG_PATH_REQUIRED')
    exception = _EXISTING_CONFIG_CUSTODY.get(str(target))
    fds = []; ancestors = []
    try:
        parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW); fds.append(parent)
        current = '/'
        for name in target.parts[1:-1]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            fds.append(child); info = os.fstat(child)
            current = os.path.join(current, name)
            require(selected_directory_custody(info,current,exception),'APISIX_CONFIG_ANCESTRY_NOT_CUSTODIED')
            ancestors.append((parent,name,child,(info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode)))
            parent = child
        fd = os.open(target.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent); fds.append(fd)
        s = os.fstat(fd)
        pin = lambda v: (v.st_dev,v.st_ino,v.st_uid,v.st_gid,v.st_mode,v.st_nlink,v.st_size,v.st_mtime_ns,v.st_ctime_ns)
        require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and 0 < s.st_size <= 1048576
                and selected_file_custody(s,exception),
                'ROOT_CONTROLLED_SELECTED_APISIX_CONFIG_REQUIRED')
        raw = b''
        while len(raw) <= 1048576:
            part = os.read(fd,65536)
            if not part: break
            raw += part
        require(len(raw) == s.st_size and pin(s) == pin(os.fstat(fd))
                == pin(os.stat(target.name, dir_fd=parent, follow_symlinks=False)), 'APISIX_CONFIG_READ_DRIFT')
        binding = {'path': str(target), 'sha256': hashlib.sha256(raw).hexdigest(), 'metadata': list(pin(s))}
        require(expected is None or binding == expected, 'APISIX_SELECTED_CONFIG_CHANGED')
        identity=lambda v:(v.st_dev,v.st_ino,v.st_uid,v.st_gid,v.st_mode)
        for parent,name,child,seal in ancestors:
            require(seal == identity(os.fstat(child)) == identity(os.stat(name,dir_fd=parent,follow_symlinks=False)),
                    'APISIX_CONFIG_ANCESTRY_CHANGED')
        return raw, binding
    finally:
        for fd in reversed(fds): os.close(fd)

def inspect_client(c,case=CASE,*,engine_factory=Engine,pin=process_pin,boot_path=Path('/proc/sys/kernel/random/boot_id'),read_overlay=private_config,mounted_stat=None):
    old=Path(case['priorRoot']);inputs=c.private(old/'inputs.json',case['inputsHash']);receipt=c.private(old/'result.json')
    review=c.private(Path(case['installedRoot'])/'review.json',case['reviewHash'])
    require(inputs.get('schema')=='ouf.managed-profile-ths-scope-current-inputs.v1'and digest(inputs)==case['inputsHash']
            and receipt.get('schema')=='ouf.managed-profile-ths-scope-capture-result.v1'
            and receipt.get('status')=='MANAGED_PROFILE_THS_SCOPE_REQUEST_OBSERVED_NOT_AUTHORIZED'
            and receipt.get('complete')is True and receipt['inputsHash']==case['inputsHash']and receipt['contextPath']==str(old)
            and receipt['counts']=={'bytes':743005,'engineGets':27,'privateMetadataReads':3}
            and receipt['scopeInspection']==inputs['scopeInspection']and inputs['retainedReviewHash']==case['reviewHash']
            and all(inputs[k]is False for k in ('historicalAuthorityReused','executionEntryQualified','targetApplyAuthorized','runtimeAuthorityIssued','automaticReplayAllowed','budgetReset')),
            'EXACT_SUCCESSFUL_CONSUMED_SCOPE_INPUTS_REQUIRED')
    require(review.get('schema')=='ouf.managed-csv-control-update-review.v1'and review['executionRoot']==case['installedRoot']
            and review['frozenPlanHash']==case['frozenPlanHash']and digest(review['nativePlan']['proposal'])==case['frozenPlanHash']
            and review['bootId']==inputs['bootId']and review['nativePlan']['proposal']['engineBinding']==inputs['engineBinding'],
            'EXACT_SUCCESSFUL_REVIEW_PROVENANCE_REQUIRED')
    require(boot_path.read_text().strip()==inputs['bootId'],'SAME_CAPTURED_BOOT_REQUIRED')
    observed=inputs['currentObservations'];require(len(observed)==len(inputs['currentProcessPins'])==13 and set(observed)==set(inputs['currentProcessPins']),'EXACT_CAPTURED_COHORT13_REQUIRED')
    require(len({v['Id']for v in observed.values()})==13,'DISTINCT_CAPTURED_COHORT13_REQUIRED')
    owners=[r for r,v in observed.items()if v.get('Name')=='/ouf-keycloak'];require(len(owners)==1 and owners[0]!='onboarding','ONE_RETAINED_IAM_CONTAINER_REQUIRED')
    roles=('onboarding',owners[0]);binding=inputs['engineBinding'];engine=engine_factory(c,binding,[observed[r]['Id']for r in roles])
    rootpins={'pid1':pin(1),'engine':pin(binding['peerCredentials'][0])}
    require(rootpins==inputs['currentRootProcessPins'],'CAPTURED_ROOT_GENERATIONS_REQUIRED')
    require(engine.get('/v1.44/info').get('ServerVersion')=='29.8.1','QUALIFIED_ENGINE_VERSION_REQUIRED')
    current={}
    def guard(r):
        value=engine.get('/v1.44/containers/'+observed[r]['Id']+'/json')
        require(stable_binding(value)==stable_binding(observed[r])and pin(value['State']['Pid'])==inputs['currentProcessPins'][r]
                and value['State']['Running']is True and value['State']['Paused']is False and value['State']['Restarting']is False,'EXACT_CAPTURED_THS_AND_IAM_GENERATIONS_REQUIRED')
        return value
    for role in roles:current[role]=guard(role)
    require(digest(stable_binding(current['onboarding']))==case['onboardingBindingHash'],'EXACT_INSTALLED_ONBOARDING_BINDING_REQUIRED')
    overlays=review['nativePlan']['proposal']['nativeFlywayConfiguration']['ownerOverlays']
    require(len(overlays)==1 and overlays[0]['binding']['path']==case['ownerOverlayPath'],'ONE_EXACT_INSTALLED_OWNER_OVERLAY_REQUIRED')
    selected=overlays[0];target,_=selected_overlay(current['onboarding'],selected)
    c.counts['configurationFileContentReads']=1
    c.put('configuration-read-claim.json',{'path':case['ownerOverlayPath'],'expectedBinding':selected['binding'],'attemptNotCompletion':True,'rawContentWillNotBePersisted':True})
    raw,file_binding=read_overlay(case['ownerOverlayPath'],selected['binding'])
    c.counts['bytes']+=len(raw);require(len(raw)<=1048576 and c.counts['bytes']<=MAXIMUMS['totalBytes'],'BOUNDED_SELECTED_OWNER_CONFIGURATION_REQUIRED')
    metadata=client_metadata(current['onboarding'],raw,selected);del raw
    root=Path('/proc')/str(current['onboarding']['State']['Pid'])/'root'
    actual_file=(mounted_stat or(lambda p:p.stat()))(root/target.lstrip('/'))
    require(list(frame(actual_file))==file_binding['metadata'],'MOUNTED_OWNER_FILE_CONTENT_IDENTITY_REQUIRED')
    for role in roles:guard(role)
    require(rootpins=={'pid1':pin(1),'engine':pin(binding['peerCredentials'][0])}and boot_path.read_text().strip()==inputs['bootId'],'CAPTURED_ROOT_OR_BOOT_DRIFT')
    require(list(frame(Path(file_binding['path']).lstat()))==file_binding['metadata'],'SELECTED_OWNER_CONFIGURATION_CHANGED')
    for path,seal in c.seals.items():require(list(frame(Path(path).lstat()))==seal['metadata'],'RETAINED_PRIVATE_METADATA_DRIFT')
    iam_role=roles[1]
    prepared={'schema':'ouf.managed-profile-ths-client-selection-inputs.v1','priorInputsHash':case['inputsHash'],'bootId':inputs['bootId'],
              'engineBinding':binding,'currentRootProcessPins':rootpins,'currentObservations':current,
              'currentProcessPins':{r:inputs['currentProcessPins'][r]for r in roles},'iamRole':iam_role,
              'clientMetadata':metadata,'overlayBinding':file_binding,'historySeals':c.seals,
              'conditionalOnboardingEnvironment':inputs['conditionalOnboardingEnvironment'],
              'requiredScopes':list(REQUIRED),'iamBindingObserved':False,'browserTokenInspected':False,
              'executionEntryQualified':False,'targetApplyAuthorized':False,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False}
    c.put('inputs.json',prepared)
    output={'schema':'ouf.managed-profile-ths-client-selection-result.v1','status':'MANAGED_PROFILE_THS_CLIENT_SELECTED_IAM_BINDING_NOT_OBSERVED',
            'complete':True,'contextPath':str(c.root),'inputsHash':digest(prepared),'priorInputsHash':case['inputsHash'],'counts':dict(c.counts),
            'clientMetadata':metadata,'overlaySha256':file_binding['sha256'],'mountedFileContentIdentityProven':True,
            'sameImageAndGeneration':True,'iamContainerGenerationPinned':True,'rawOverlayPersisted':False,
            'iamRequests':0,'oauthRequests':0,'credentialTokenOrSigningKeyFileReads':0,'credentialFieldsMayExistInConfiguration':True,
            'engineWrites':0,'sqlSessions':0,'imageImports':0,'historicalAuthorityReused':False,'scopePatchApplied':False,
            'newGrantsGranted':0,'humanBudgetsGranted':0,'resumes':0,'newJobs':0,'uploads':0,'sourceActivations':0,'acquisitionsExecuted':0,
            'currentJobOrBudgetStateObserved':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
            'automaticReplayAllowed':False,'budgetReset':False,'applicationE2EProven':False,'releaseAcceptance':False}
    c.put('result.json',output);return output

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

def main():
    capture=None
    try:
        require(len(sys.argv)==1 and os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
                and os.environ.get('SUDO_UID')==str(pwd.getpwnam('oufadmin').pw_uid),'ISOLATED_OUFADMIN_ROOT_CLIENT_READER_REQUIRED')
        require(sys.stdin.isatty()and sys.stdout.isatty(),'INTERACTIVE_OPERATOR_TERMINAL_REQUIRED')
        code=Path(__file__).resolve();ancestry(code.parent);st=code.lstat()
        require(stat.S_ISREG(st.st_mode)and st.st_uid==st.st_gid==0 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o400,'PROTECTED_CLIENT_READER_ROOT400_REQUIRED')
        require(not os.path.lexists(CASE['outputRoot']),'THS_CLIENT_SELECTION_CONSUMED_NO_REPLAY')
        sys.stdout=Logger(code.parent/'operator.log')
        signal.signal(signal.SIGALRM,lambda *_:require(False,'FINITE_CLIENT_SELECTION_WINDOW_EXPIRED'));signal.alarm(60)
        capture=Capture(CASE['outputRoot'],2)
        print('Nuova lettura:3metadata conservati,5GET Engine solo Onboarding/IAM e1overlayTHS esatto gia classificato;solo client/provider/issuer/hash pubblici. Il file puo contenere segreti,le altre proprieta non sono stampate o salvate. Zero IAM/OAuth/SQL/write/lifecycle/grant/budget/resume;60s;STOP consuma scope,nonrilanciare.',flush=True)
        result=inspect_client(capture)
    except BaseException as error:
        reason=str(error)if isinstance(error,Stop)and re.fullmatch('[A-Z0-9_]{1,120}',str(error))else'PRIVATE_CLIENT_SELECTION_FAILURE_RECONCILE'
        result={'schema':'ouf.managed-profile-ths-client-selection-result.v1','status':'STOP_RECONCILE','complete':False,'reasonCode':reason,
                'counts':dict(capture.counts)if capture else{},'engineWrites':0,'iamRequests':0,'oauthRequests':0,
                'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False,'applicationE2EProven':False,'releaseAcceptance':False}
        if capture is not None and not(capture.root/'result.json').exists():capture.put('result.json',result)
    finally:signal.alarm(0)
    print(json.dumps(result,sort_keys=True,separators=(',',':')),flush=True)
    return 0 if result['complete']else 2
if __name__=='__main__':raise SystemExit(main())
