#!/usr/bin/env python3
"""Fresh read-only exact retained owner/peer capture and THS OAuth request inspection.
Reuses consumed-success metadata as provenance only; never invokes old entrypoints.
No credential/configuration file, IAM request, key, SQL, import or lifecycle write.
"""
import copy,hashlib,http.client,json,os,pwd,re,signal,socket,stat,struct,sys,time
from pathlib import Path
MAXIMUMS={'engineGets':27,'privateMetadataReads':3,'responseBytes':2*1024*1024,'totalBytes':24*1024*1024,'seconds':90}
CASE={'installedRoot':'/etc/ouf/deploy-snapshots/managed-csv-control-update-900b09c6d29a20fd-v1',
      'reviewHash':'42db62a1d9d8f0423b88c86b4d56c50f39d9b0cd96ae6a2c11797583df3f830e',
      'authorityHash':'9ae7b608a7836e83d93df74d07612b121040854608bdf47cdd820a9d676f5bd1',
      'frozenPlanHash':'06054f1cb3fe0045c3fdc3ca1cfa595444b90fd20d3ee589cae71e9ad3225dc5',
      'executionInputsHash':'900b09c6d29a20fda5dfff1f1333df167363c96e865cc2c13a7b58791f4e0c51',
      'sourceCommits':{'onboarding':'9890b31868641e5be43c949a56f4ef69dd23bdfd','mcp':'d2454f3cb8cd410d284b9dc78349a170187aea1c'},
      'nativeImageIds':{'onboarding':'sha256:c512c24787304dc0ee40d2b5b1559d458ddf1d5a65a068775ef173c47ba849a3','mcp':'sha256:a52180123104ac97e4979ad1b9b291654b076692da51708bb2a377301fef1220'},
      'nativeBindingHashes':{'onboarding':'1765524aacf85c6d47cb78e0a4cadcec7db0180c6506793102db188f80d65de8','mcp':'d5750f01ee879ba43c28d97385ffd835c3e2836a48e6346d6bce5293a4831c19'},
      'outputRoot':'/etc/ouf/deploy-snapshots/managed-profile-ths-scope-capture-policy58-20261028-v1','cohortSize':13}
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

def inspect_current(capture,case=CASE,*,engine_factory=Engine,pin=process_pin,boot_path=Path('/proc/sys/kernel/random/boot_id')):
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
    c.put('inputs.json',payload)
    output={'schema':'ouf.managed-profile-ths-scope-capture-result.v1','status':'MANAGED_PROFILE_THS_SCOPE_REQUEST_OBSERVED_NOT_AUTHORIZED',
            'complete':True,'contextPath':str(c.root),'inputsHash':digest(payload),'cohortSize':len(cohort),'counts':dict(c.counts),
            'scopeInspection':summary,'currentOnboardingNativeImageId':observations['onboarding']['Image'],
            'currentMcpNativeImageId':observations['mcp']['Image'],'historicalAuthorityReused':False,
            'configurationFileContentReads':0,'credentialFileReads':0,'signingKeyReads':0,'iamRequests':0,'oauthRequests':0,
            'engineWrites':0,'sqlSessions':0,'imageImports':0,'newGrantsGranted':0,'humanBudgetsGranted':0,'resumes':0,
            'newJobs':0,'uploads':0,'sourceActivations':0,'acquisitionsExecuted':0,
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
                and os.environ.get('SUDO_UID')==str(pwd.getpwnam('oufadmin').pw_uid),'ISOLATED_OUFADMIN_ROOT_SCOPE_CAPTURE_REQUIRED')
        require(sys.stdin.isatty() and sys.stdout.isatty(),'INTERACTIVE_OPERATOR_TERMINAL_REQUIRED')
        code=Path(__file__).resolve();ancestry(code.parent);st=code.lstat()
        require(stat.S_ISREG(st.st_mode)and st.st_uid==st.st_gid==0 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o400,'PROTECTED_SCOPE_READER_ROOT400_REQUIRED')
        require(not os.path.lexists(CASE['outputRoot']),'THS_SCOPE_CAPTURE_CONSUMED_NO_REPLAY')
        sys.stdout=Logger(code.parent/'operator.log')
        signal.signal(signal.SIGALRM,lambda *_:require(False,'FINITE_SCOPE_CAPTURE_WINDOW_EXPIRED'));signal.alarm(90)
        capture=Capture(CASE['outputRoot'],CASE['cohortSize'])
        print('Nuova sola lettura:3 metadata update riuscito,27GET Engine coorte13 e scope richiesti del browser da metadataEnv privati. Zero fileconfig/credenziali/chiavi/IAM/OAuth/SQL/import/lifecycle/grant/budget/resume. Max90s;scope consumato ancheSTOP,nonrilanciare.',flush=True)
        result=inspect_current(capture)
    except BaseException as error:
        reason=str(error)if isinstance(error,Stop)and re.fullmatch('[A-Z0-9_]{1,120}',str(error))else'PRIVATE_SCOPE_CAPTURE_FAILURE_RECONCILE'
        result={'schema':'ouf.managed-profile-ths-scope-capture-result.v1','status':'STOP_RECONCILE','complete':False,'reasonCode':reason,
                'counts':dict(capture.counts)if capture else{},'engineWrites':0,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
                'automaticReplayAllowed':False,'budgetReset':False,'applicationE2EProven':False,'releaseAcceptance':False}
        if capture is not None and not(capture.root/'result.json').exists():capture.put('result.json',result)
    finally:signal.alarm(0)
    print(json.dumps(result,sort_keys=True,separators=(',',':')),flush=True)
    return 0 if result['complete']else 2
if __name__=='__main__':raise SystemExit(main())
