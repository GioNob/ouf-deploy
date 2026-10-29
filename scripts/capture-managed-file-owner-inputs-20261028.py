#!/usr/bin/env python3
"""New finite current-owner capture. No SQL, original file, authentication or runtime action."""
import copy,hashlib,http.client,json,os,pwd,re,signal,socket,stat,struct,sys,time
from pathlib import Path
MAXIMUMS={'engineGets':27,'privateMetadataReads':4,'responseBytes':2097152,'totalBytes':25165824,'seconds':90}
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
                         'privateMetadataReads': 5 if reconcile else 4}
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

ASSET='9c502da5-b5d8-405e-b3f5-60eb31ecb513'

JOB='677480c8-3d10-44fd-9dad-f72ddeed20a4'

TEATRI='6609b245-86ed-4315-8ce0-73f2a8555bf3'

SUBJECT='b93d8cf6-cd14-4ee6-91d7-84cd76c4f500'

TENANT='ouf-lab'

CASE={'installedRoot':'/etc/ouf/deploy-snapshots/managed-profile-ths-request-update-e22a443d-20261028-v1',
 'outputRoot':'/etc/ouf/deploy-snapshots/managed-file-ownership-read-0990401f-20261028-v1',
 'reviewHash':'0990401fb938c73c13bd6be090c04a5291bfe52aa06d9546cdaf7e13659a10b8',
 'resultHash':'1c452fa61251395b18c800ee0aceefa9cce09e068807b85729d0857ff9b547bf',
 'authorityHash':'ce93c610fee96883a11fb806d283565340ffe6d1e6e629acf883eaabae0956ba',
 'frozenPlanHash':'040d5a43b8050007666e993886d575dcf95259d6d8d1ef712aba44f3422aced5',
 'executionInputsHash':'e22a443d2617bf4db06b90ca272fd80e87fe3a05a9b4b6386b15cce51fea11e4',
 'nativeBindingHash':'2c5295203d6f190e04f2add429a617be69b2a72dd264b45f241a80d1aac09d0b',
 'nativeImageId':'sha256:c512c24787304dc0ee40d2b5b1559d458ddf1d5a65a068775ef173c47ba849a3',
 'assetId':ASSET,'jobId':JOB,'teatriAssetId':TEATRI,'subjectId':SUBJECT,'tenantId':TENANT,
 'contentHash':'sha256:f670059bb524832aa9cd78fbe5e907be053244248ff1ef4d7962b14fcd72c311'}

def history(review,result,journal,case):
    require(digest(review)==case['reviewHash']and digest(result)==case['resultHash']
        and review['schema']=='ouf.ths-owner-request-update-review.v1'
        and review['executionRoot']==case['installedRoot']and review['frozenPlanHash']==case['frozenPlanHash']
        and digest(review['nativePlan']['proposal'])==case['frozenPlanHash'],'EXACT_CONSUMED_SUCCESS_REVIEW_REQUIRED')
    require(result['schema']=='ouf.ths-owner-request-update-result.v1'
        and result['status']=='THS_OWNER_REQUEST_UPDATE_INSTALLED_E2E_NOT_ACCEPTED'
        and result['complete']is True and result['scopePatchApplied']is True and result['componentReadinessProven']is True
        and result['reviewHash']==case['reviewHash']and result['authorityHash']==case['authorityHash']
        and result['executionInputsHash']==case['executionInputsHash']and result['nativeBindingHash']==case['nativeBindingHash']
        and result['nativeImageId']==case['nativeImageId']and result['humanBudgetsGranted']==result['resumes']==0,
        'EXACT_INSTALLED_SINGLE_OWNER_RESULT_REQUIRED')
    require(journal['schema']=='ouf.managed-csv-control-update-journal.v1'and journal['state']=='COMPLETE'
        and journal['reviewHash']==case['reviewHash']and journal['authorityHash']==case['authorityHash']
        and journal['quarantine']is None and journal['automaticReplayAllowed']is False and journal['budgetReset']is False
        and journal['nextStage']==len(review['stages'])==len(journal['effects'])==15 and set(journal['candidates'])=={'onboarding'},
        'COMPLETE_CONSUMED_SINGLE_OWNER_JOURNAL_REQUIRED')
    for stage,effect in zip(review['stages'],journal['effects']):
        require(effect['stage']==stage and effect['state']=='APPLIED'
            and effect['intentHash']==digest({'reviewHash':case['reviewHash'],'stage':stage}),'NO_AMBIGUOUS_PREDECESSOR_EFFECT_REQUIRED')
    candidate=journal['candidates']['onboarding']
    require(candidate['configurationVerified']is True and candidate['readinessProven']is True and candidate['generation']==result['generation'],
        'EXACT_COMPLETED_OWNER_PROCESS_REQUIRED')
    proposal=review['nativePlan']['proposal'];profile=proposal['boundDatabaseProfile']
    peers=proposal['existingApplications'];pg=profile['postgresRuntimeBinding']['containerId']
    matches=[v for v in peers.values()if v['containerId']==pg]
    require(len(peers)==13 and len(matches)==1 and candidate['id']!=pg,'EXACT_RETAINED_POSTGRES_AND_ONBOARDING_REQUIRED')
    return candidate,profile,matches[0]

"""Exact current Onboarding/12 peers; the successful ownership read is consumed provenance."""
OWNER_READ_ROOT='/etc/ouf/deploy-snapshots/managed-file-ownership-read-0990401f-20261028-v1'
OWNER_READ_HASH='1c0cff56d38d831bb0b0ea90674d754f2331601b771b7b347f2249977c7f7ad1'
OUTPUT_ROOT='/etc/ouf/deploy-snapshots/managed-file-owner-recovery-inputs-1c0cff56-20261028-v1'

def validated_owner_read(read,case):
    require(digest(read)==case['ownerReadHash']and read['schema']=='ouf.managed-file-ownership-read-result.v1'
        and read['status']=='MANAGED_FILE_OWNERSHIP_OBSERVED_NO_AUTHORITY'and read['complete']is True
        and read['contextPath']==case['ownerReadRoot']and read['sourceDatabaseSchema']==36
        and read['counts']=={'bytes':573839,'engineGets':5,'privateMetadataReads':3,'sqlSessions':1}
        and all(read[k]==0 for k in('databaseWrites','engineWrites','humanBudgetsGranted','resumes','newJobs','uploads','acquisitionsExecuted','newGrantsGranted','sourceActivations','oauthRequests','iamRequests'))
        and all(read[k]is False for k in('browserIdentityVerified','historicalAuthorityReused','runtimeAuthorityIssued','automaticReplayAllowed','budgetReset','applicationE2EProven','releaseAcceptance')),
        'EXACT_SUCCESSFUL_CONSUMED_OWNERSHIP_READ_REQUIRED')
    s=read['summary'];require(s['classification']=='RETAINED_UPLOADER_MATCHES_TENANT_PROOF_MISSING'
        and s['expectedSubjectId']==case['subjectId']and s['expectedTenantId']==case['tenantId']and s['browserSubjectOrTenantObserved']is False
        and s['job']=={'assetId':case['assetId'],'jobId':case['jobId'],'status':'FAILED','cumulativeAttempts':5,'expectedVersion':0,'generation':0,'hasRecoverySession':False}
        and s['sameAssetJobCount']==1 and s['recoverySessionCount']==s['recoveryEventCount']==0,'EXACT_RETAINED_FAILED5_WITHOUT_TENANT_PROOF_REQUIRED')
    require(len(s['assets'])==2 and {row['kind']for row in s['assets']}=={'FARMACIE','TEATRI'},'TWO_RETAINED_ASSET_OBSERVATIONS_REQUIRED')
    for a in s['assets']:
        require(a['present']is True and a['uploadedByMatchesExpectedSubject']is True and a['exactUploadTenantSubjectProof']is False
            and a['uploadReceiptCount']==0 and a['otherReviewIdentityObserved']is False and a['otherUploadIdentityObserved']is False,
            'NO_RETAINED_CONTRADICTORY_PROVENANCE_REQUIRED')
        if a['kind']=='FARMACIE':require(a['assetId']==case['assetId']and a['contentHash']==case['contentHash']and a['sizeBytes']==13903
            and a['expectedPrincipalOwnerPredicate']is False and a['exactReviewTenantSubjectProof']is False,'EXACT_RETAINED_FARMACIE_PROOF_GAP_REQUIRED')
        else:require(a['assetId']==case['teatriAssetId']and a['contentHash']=='sha256:08b20658b2b4eadf34d25cd93eead2945096b353ae33b797cf3c41df5319c9e9'
            and a['sizeBytes']==4404 and a['expectedPrincipalOwnerPredicate']is True and a['exactReviewTenantSubjectProof']is True,'EXACT_RETAINED_TEATRI_REVIEW_PROOF_REQUIRED')
    return s

def capture_inputs(c,case=None,*,engine_factory=Engine,pin=process_pin,boot_path=Path('/proc/sys/kernel/random/boot_id')):
    case=CASE if case is None else case
    old=Path(case['installedRoot']);review=c.private(old/'review.json',case['reviewHash'])
    result=c.private(old/'result.json');journal=c.private(old/'recovery.json')
    candidate,profile,_=history(review,result,journal,case)
    consumed=c.private(Path(case['ownerReadRoot'])/'result.json',case['ownerReadHash']);retained=validated_owner_read(consumed,case)
    cohort=copy.deepcopy(review['nativePlan']['proposal']['existingApplications']);cohort['onboarding']['containerId']=candidate['id']
    require(len(cohort)==13 and len({v['containerId']for v in cohort.values()})==13,'EXACT_LATEST_COHORT13_REQUIRED')
    binding=review['nativePlan']['proposal']['engineBinding'];engine=engine_factory(c,binding,[v['containerId']for v in cohort.values()])
    require(boot_path.read_text().strip()==review['bootId'],'SAME_RETAINED_HOST_BOOT_REQUIRED')
    roots={'pid1':pin(1),'engine':pin(binding['peerCredentials'][0])}
    require(engine.get('/v1.44/info').get('ServerVersion')=='29.8.1','QUALIFIED_CURRENT_ENGINE_REQUIRED')
    observed={};pins={}
    for role,expected in sorted(cohort.items()):
        actual=engine.get('/v1.44/containers/'+expected['containerId']+'/json');current=stable_binding(actual);generation=pin(actual['State']['Pid'])
        require(actual['State']['Running']is True and actual['State']['Paused']is False and actual['State']['Restarting']is False,'CURRENT_COHORT_RUNNING_REQUIRED')
        if role=='onboarding':require(digest(current)==case['nativeBindingHash']and actual['Image']==case['nativeImageId']and generation==candidate['generation'],'EXACT_INSTALLED_ONBOARDING_REQUIRED')
        else:require(current==expected,'ALL_12_RETAINED_PEERS_MUST_MATCH')
        observed[role]=actual;pins[role]=generation
    for role,actual in sorted(observed.items()):
        again=engine.get('/v1.44/containers/'+actual['Id']+'/json')
        require(stable_binding(again)==stable_binding(actual)and pin(again['State']['Pid'])==pins[role],'CURRENT_COHORT_GENERATION_DRIFT')
    require(roots=={'pid1':pin(1),'engine':pin(binding['peerCredentials'][0])}and boot_path.read_text().strip()==review['bootId'],'HOST_ROOT_OR_BOOT_DRIFT')
    for path,seal in c.seals.items():require(list(frame(Path(path).lstat()))==seal['metadata'],'CONSUMED_PRIVATE_METADATA_DRIFT')
    prepared={'schema':'ouf.managed-file-owner-recovery-current-inputs.v1','bootId':review['bootId'],'engineBinding':binding,
        'currentObservations':observed,'currentProcessPins':pins,'currentRootProcessPins':roots,'boundDatabaseProfile':profile,
        'retainedReviewHash':case['reviewHash'],'retainedSuccessfulReview':review,'retainedSuccessfulResult':result,
        'retainedOwnershipReadResult':consumed,'retainedOwnershipReadHash':case['ownerReadHash'],'historySeals':c.seals,
        'targetRoles':['onboarding'],'unchangedPeers':12,'currentDatabaseSchema':36,'databaseSchemaObservedByThisCapture':False,
        'currentJobOrBudgetStateObserved':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'nativePlanPrepared':False,
        'automaticReplayAllowed':False,'budgetReset':False}
    c.put('inputs.json',prepared)
    accounting={'lineageStart':case['ownerReadRoot'],'retainedConsumedScopeCounts':dict(consumed['counts']),
        'currentScopeCounts':{**c.counts,'sqlSessions':0},
        'cumulativeCounts':{k:consumed['counts'][k]+c.counts.get(k,0)for k in('bytes','engineGets','privateMetadataReads','sqlSessions')}}
    output={'schema':'ouf.managed-file-owner-recovery-input-capture-result.v1','status':'MANAGED_FILE_OWNER_RECOVERY_INPUTS_CAPTURED_NOT_AUTHORIZED',
        'complete':True,'contextPath':str(c.root),'inputsHash':digest(prepared),'counts':dict(c.counts),'captureAccounting':accounting,
        'retainedOwnershipReadHash':case['ownerReadHash'],'cohortSize':13,'targetRoles':['onboarding'],'unchangedPeers':12,
        'retainedJobObservation':retained['job'],'currentJobOrBudgetStateObserved':False,'databaseSchemaObservedByThisCapture':False,
        'sqlSessions':0,'configurationFileContentReads':0,'credentialFileReads':0,'signingKeyReads':0,'iamRequests':0,'oauthRequests':0,
        'engineWrites':0,'imageImports':0,'newGrantsGranted':0,'humanBudgetsGranted':0,'resumes':0,'newJobs':0,'uploads':0,
        'acquisitionsExecuted':0,'sourceActivations':0,'nativePlanPrepared':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
        'automaticReplayAllowed':False,'budgetReset':False,'applicationE2EProven':False,'releaseAcceptance':False}
    c.put('result.json',output);return output

CASE={**CASE,'ownerReadRoot':OWNER_READ_ROOT,'ownerReadHash':OWNER_READ_HASH,'outputRoot':OUTPUT_ROOT}
def main():
    c=None
    try:
        require(len(sys.argv)==1 and os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
            and os.environ.get('SUDO_UID')==str(pwd.getpwnam('oufadmin').pw_uid),'ISOLATED_OUFADMIN_CAPTURE_REQUIRED')
        require(sys.stdin.isatty()and sys.stdout.isatty(),'INTERACTIVE_OPERATOR_TERMINAL_REQUIRED')
        code=Path(__file__).resolve();ancestry(code.parent);s=code.lstat()
        require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o400,'ROOT400_OWNER_CAPTURE_REQUIRED')
        require(not os.path.lexists(CASE['outputRoot']),'OWNER_INPUT_CAPTURE_CONSUMED_NO_REPLAY')
        sys.stdout=Logger(code.parent/'operator.log')
        signal.signal(signal.SIGALRM,lambda *_:require(False,'FINITE_OWNER_CAPTURE_WINDOW_EXPIRED'));signal.alarm(90)
        c=Capture(CASE['outputRoot'],13)
        print('NUOVA sola lettura4metadata conservati:3successoTHS e1letturaownership riuscita;27GET Engine sulla stessa coorte13,solo Onboarding candidato futuro/12peer invariati.90s/24MiB. Zero SQL/fileconfig/credenziali/chiavi/IAM/OAuth/import/lifecycle/grant/budget/resume/acquisizioni. Nessuna authority o piano eseguibile;STOP conserva e consuma,nonrilanciare.',flush=True)
        result=capture_inputs(c)
    except BaseException as error:
        reason=str(error)if isinstance(error,Stop)and re.fullmatch('[A-Z0-9_]{1,120}',str(error))else'PRIVATE_OWNER_CAPTURE_FAILURE_RECONCILE'
        result={'schema':'ouf.managed-file-owner-recovery-input-capture-result.v1','status':'STOP_RECONCILE','complete':False,'reasonCode':reason,
            'counts':dict(c.counts)if c else{},'engineWrites':0,'sqlSessions':0,'humanBudgetsGranted':0,'resumes':0,
            'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False,'applicationE2EProven':False,'releaseAcceptance':False}
        if c is not None and not(c.root/'result.json').exists():c.put('result.json',result)
    finally:signal.alarm(0)
    print(json.dumps(result,sort_keys=True,separators=(',',':')),flush=True)
    return 0 if result['complete']else 2
if __name__=='__main__':raise SystemExit(main())
