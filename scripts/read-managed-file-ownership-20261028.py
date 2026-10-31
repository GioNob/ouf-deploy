#!/usr/bin/env python3
"""New one-use exact Farmacie/Teatri ownership observation. No domain writes or authority."""
import copy,hashlib,http.client,json,os,pwd,re,signal,socket,stat,struct,subprocess,sys,time,uuid
from pathlib import Path
MAXIMUMS={'engineGets':5,'privateMetadataReads':3,'responseBytes':2097152,'totalBytes':25165824,'seconds':90}
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

"""Closed read-only comparison; never infer or write a legacy tenant binding."""

ASSET='9c502da5-b5d8-405e-b3f5-60eb31ecb513'
JOB='677480c8-3d10-44fd-9dad-f72ddeed20a4'
TEATRI='6609b245-86ed-4315-8ce0-73f2a8555bf3'
SUBJECT='b93d8cf6-cd14-4ee6-91d7-84cd76c4f500'
TENANT='ouf-lab'

def query(case):
    for key in ('assetId','jobId','teatriAssetId','subjectId'):
        if str(uuid.UUID(case[key]))!=case[key]:raise ValueError('CANONICAL_OWNERSHIP_ID_REQUIRED')
    if not re.fullmatch('[a-z0-9][a-z0-9_-]{0,63}',case['tenantId']):raise ValueError('LITERAL_BOUNDED_TENANT_REQUIRED')
    asset,job,teatri,subject,tenant=(case[k]for k in('assetId','jobId','teatriAssetId','subjectId','tenantId'))
    return """BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
WITH requested(kind,asset_id) AS (VALUES ('FARMACIE','%s'::uuid),('TEATRI','%s'::uuid)),
proof AS (
 SELECT q.kind,q.asset_id,a.asset_id IS NOT NULL AS present,
   coalesce(a.uploaded_by='%s',false) AS subject_matches,
   (SELECT count(*) FROM ouf_onboarding.managed_file_upload_attempt u WHERE u.asset_id=q.asset_id) AS upload_receipts,
   EXISTS(SELECT 1 FROM ouf_onboarding.managed_file_upload_attempt u WHERE u.asset_id=q.asset_id AND u.tenant_id='%s' AND u.subject_id='%s') AS upload_proven,
   EXISTS(SELECT 1 FROM ouf_onboarding.source s JOIN ouf_onboarding.managed_onboarding_review r ON r.source_id=s.source_id
     WHERE s.metadata->>'managedFileAssetId'=q.asset_id::text AND r.tenant_id='%s' AND r.subject_id='%s'
       AND (NOT(jsonb_exists(s.metadata,'managedTenantId')) OR s.metadata->>'managedTenantId'='%s')) AS review_proven,
   EXISTS(SELECT 1 FROM ouf_onboarding.managed_file_upload_attempt u WHERE u.asset_id=q.asset_id AND (u.tenant_id<>'%s' OR u.subject_id<>'%s')) AS other_upload_identity,
   EXISTS(SELECT 1 FROM ouf_onboarding.source s JOIN ouf_onboarding.managed_onboarding_review r ON r.source_id=s.source_id
     WHERE s.metadata->>'managedFileAssetId'=q.asset_id::text AND (r.tenant_id<>'%s' OR r.subject_id<>'%s')) AS other_review_identity,
   a.content_hash,a.size_bytes
 FROM requested q LEFT JOIN ouf_onboarding.managed_file_asset a ON a.asset_id=q.asset_id)
SELECT jsonb_build_object('schema','ouf.managed-file-ownership-sql-observation.v1',
 'readOnly',current_setting('transaction_read_only'),'database',current_database(),
 'databaseOid',(SELECT oid::bigint FROM pg_database WHERE datname=current_database()),
 'user',current_user,'serverVersionNum',current_setting('server_version_num')::int,
 'standby',pg_is_in_recovery(),
 'installedSchemaVersion',(SELECT max(version::int) FROM ouf_onboarding.flyway_schema_history WHERE type='SQL' AND success),
 'assets',(SELECT jsonb_agg(jsonb_build_object('kind',kind,'assetId',asset_id::text,'present',present,
   'uploadedByMatchesExpectedSubject',subject_matches,'uploadReceiptCount',upload_receipts,
   'exactUploadTenantSubjectProof',upload_proven,'exactReviewTenantSubjectProof',review_proven,
   'otherUploadIdentityObserved',other_upload_identity,'otherReviewIdentityObserved',other_review_identity,
   'expectedPrincipalOwnerPredicate',subject_matches AND (upload_proven OR review_proven),
   'contentHash',content_hash,'sizeBytes',size_bytes) ORDER BY kind) FROM proof),
 'job',(SELECT jsonb_build_object('jobId',job_id::text,'assetId',asset_id::text,'status',state,
   'cumulativeAttempts',attempts,'generation',generation,'expectedVersion',lock_version,
   'hasRecoverySession',recovery_session_id IS NOT NULL) FROM ouf_onboarding.file_profile_job
   WHERE job_id='%s'::uuid AND asset_id='%s'::uuid),
 'sameAssetJobCount',(SELECT count(*) FROM ouf_onboarding.file_profile_job WHERE asset_id='%s'::uuid),
 'recoverySessionCount',(SELECT count(*) FROM ouf_onboarding.managed_profile_budget_session WHERE job_id='%s'::uuid),
 'recoveryEventCount',(SELECT count(*) FROM ouf_onboarding.managed_profile_event WHERE job_id='%s'::uuid));
ROLLBACK;"""%(asset,teatri,subject,tenant,subject,tenant,subject,tenant,tenant,subject,tenant,subject,job,asset,asset,job,job)

def validate(facts,identity,case,require):
    require(type(facts)is dict and facts.get('schema')=='ouf.managed-file-ownership-sql-observation.v1'
        and facts.get('readOnly')=='on' and facts.get('standby')is False
        and facts.get('database')==identity['database'] and facts.get('databaseOid')==identity['databaseOid']
        and facts.get('user')==identity['adminRole'] and type(facts.get('serverVersionNum'))is int
        and facts['serverVersionNum']//10000==17 and facts.get('installedSchemaVersion')==36,
        'EXACT_READ_ONLY_OWNER_DATABASE_V36_REQUIRED')
    require(type(facts.get('assets'))is list and len(facts['assets'])==2,'TWO_EXACT_ASSET_PROOFS_REQUIRED')
    expected={'FARMACIE':case['assetId'],'TEATRI':case['teatriAssetId']};seen=set()
    fields={'kind','assetId','present','uploadedByMatchesExpectedSubject','uploadReceiptCount',
        'exactUploadTenantSubjectProof','exactReviewTenantSubjectProof','otherUploadIdentityObserved',
        'otherReviewIdentityObserved','expectedPrincipalOwnerPredicate','contentHash','sizeBytes'}
    for row in facts['assets']:
        require(type(row)is dict and set(row)==fields and row['kind']in expected and row['kind']not in seen
            and row['assetId']==expected[row['kind']],'ONLY_EXACT_REDACTED_ASSET_FACTS_REQUIRED');seen.add(row['kind'])
        for name in ('present','uploadedByMatchesExpectedSubject','exactUploadTenantSubjectProof','exactReviewTenantSubjectProof',
                     'otherUploadIdentityObserved','otherReviewIdentityObserved','expectedPrincipalOwnerPredicate'):
            require(type(row[name])is bool,'TYPED_OWNERSHIP_BOOLEAN_REQUIRED')
        require(type(row['uploadReceiptCount'])is int and 0<=row['uploadReceiptCount']<=10000,'BOUNDED_UPLOAD_PROOF_COUNT_REQUIRED')
        require(row['expectedPrincipalOwnerPredicate']==(row['uploadedByMatchesExpectedSubject']and(row['exactUploadTenantSubjectProof']or row['exactReviewTenantSubjectProof'])),
            'EXACT_INSTALLED_OWNER_PREDICATE_REQUIRED')
        if row['present']:
            require(type(row['contentHash'])is str and re.fullmatch('sha256:[0-9a-f]{64}',row['contentHash'])
                and type(row['sizeBytes'])is int and 1<=row['sizeBytes']<=10485760,'EXACT_INTAKE_CONTENT_METADATA_REQUIRED')
        else:require(row['contentHash']is None and row['sizeBytes']is None,'ABSENT_ASSET_HAS_NO_CONTENT_METADATA')
    for name in ('sameAssetJobCount','recoverySessionCount','recoveryEventCount'):
        require(type(facts.get(name))is int and 0<=facts[name]<=10000,'BOUNDED_JOB_HISTORY_COUNT_REQUIRED')
    j=facts.get('job')
    require(type(j)is dict and set(j)=={'jobId','assetId','status','cumulativeAttempts','generation','expectedVersion','hasRecoverySession'}
        and j['jobId']==case['jobId']and j['assetId']==case['assetId'] and type(j['hasRecoverySession'])is bool,
        'EXACT_RETAINED_JOB_FACTS_REQUIRED')
    require(j['status']in('READY','RUNNING','RETRY_WAIT','FAILED','SUCCEEDED','CANCELLED')
        and all(type(j[k])is int and j[k]>=0 for k in('cumulativeAttempts','generation','expectedVersion')),'TYPED_JOB_STATE_REQUIRED')
    farm=next(row for row in facts['assets']if row['kind']=='FARMACIE')
    require(farm['present']and farm['contentHash']==case['contentHash']and farm['sizeBytes']==13903,'SAME_RETAINED_FARMACIE_INPUT_REQUIRED')
    if not farm['uploadedByMatchesExpectedSubject']:classification='EXPECTED_SUBJECT_DIFFERS_FROM_RETAINED_UPLOADER'
    elif not farm['expectedPrincipalOwnerPredicate']:classification='RETAINED_UPLOADER_MATCHES_TENANT_PROOF_MISSING'
    else:classification='EXPECTED_PRINCIPAL_DURABLE_OWNERSHIP_PROVEN_BROWSER_IDENTITY_STILL_UNOBSERVED'
    return {'classification':classification,'expectedSubjectId':case['subjectId'],'expectedTenantId':case['tenantId'],
        'browserSubjectOrTenantObserved':False,'assets':facts['assets'],'job':j,
        **{name:facts[name]for name in('sameAssetJobCount','recoverySessionCount','recoveryEventCount')}}

"""New finite maintenance read. Retained reviews are provenance, never authority."""

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

def sql_arguments(profile,empty,sql,case):
    require(sql==query(case),'ONLY_CLOSED_OWNERSHIP_READ_QUERY_REQUIRED')
    require(profile['schema']=='ouf.current-onboarding-database-snapshot-profile.v1','RETAINED_DATABASE_IDENTITY_REQUIRED')
    identity=profile['identity'];program=profile['containerPrograms']
    for key in ('database','adminRole'):
        require(type(identity[key])is str and re.fullmatch('[a-z_][a-z0-9_]{0,62}',identity[key]),'CLOSED_DATABASE_IDENTIFIER_REQUIRED')
    require(type(identity['postgresPort'])is int and 1<=identity['postgresPort']<=65535,'EXACT_POSTGRES_PORT_REQUIRED')
    require(set(program)=={'env','timeout','psql','pgDump','pgRestore'}or {'env','timeout','psql'}<=set(program),'RETAINED_CONTAINER_PROGRAMS_REQUIRED')
    for path in (profile['dockerExecutable']['path'],profile['engineBinding']['socketPath'],profile['unixSocketDirectory'],str(empty),program['env'],program['timeout'],program['psql']):
        require(type(path)is str and path.startswith('/')and'..'not in path.split('/')and'\x00'not in path,'CLOSED_NATIVE_TRANSPORT_PATH_REQUIRED')
    return [profile['dockerExecutable']['path'],'--host','unix://'+profile['engineBinding']['socketPath'],'--config',str(empty),
        'exec',profile['postgresRuntimeBinding']['containerId'],program['env'],'-i','LC_ALL=C','PGPASSFILE=/dev/null',
        'PGSERVICEFILE=/dev/null','PGSYSCONFDIR=/nonexistent',
        'PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=5000 -c lock_timeout=1000 -c idle_in_transaction_session_timeout=5000',
        program['timeout'],'-s','KILL','15',program['psql'],'-X','-w','-q','-A','-t','-v','ON_ERROR_STOP=1','-v','VERBOSITY=sqlstate',
        '-h',profile['unixSocketDirectory'],'-p',str(identity['postgresPort']),'-U',identity['adminRole'],'-d',identity['database'],'-c',sql]

def read_sql(c,profile,case,guard,*,popen=None):
    guard();binding=profile['dockerExecutable'];path=Path(binding['path']);ancestry(path.parent);s=path.lstat()
    require(path.resolve()==path and stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and s.st_mode&0o111
        and not s.st_mode&0o022 and 0<s.st_size<=134217728 and hashlib.sha256(path.read_bytes()).hexdigest()==binding['sha256'],
        'EXACT_EXISTING_ROOT_DOCKER_CLI_REQUIRED')
    empty=c.root/'empty-docker-config';empty.mkdir(mode=0o700);c.sync(c.root)
    sql=query(case);argv=sql_arguments(profile,empty,sql,case)
    require(c.counts.get('sqlSessions',0)==0,'ONE_NEW_READ_ONLY_SQL_ATTEMPT_ONLY');c.counts['sqlSessions']=1
    c.put('sql-dispatch-claim.json',{'schema':'ouf.managed-file-ownership-read-dispatch.v1','querySha256':hashlib.sha256(sql.encode()).hexdigest(),
        'attemptNotCompletion':True,'historicalAuthorityReused':False,'databaseWritesAuthorized':False,'maximumSeconds':20})
    paths=[c.root/'sql-stdout.log',c.root/'sql-stderr.log'];streams=[];proc=None;started=time.monotonic()
    try:
        for file in paths:
            fd=os.open(file,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.fchmod(fd,0o600);streams.append(os.fdopen(fd,'wb'))
        proc=(popen or subprocess.Popen)(argv,stdin=subprocess.DEVNULL,stdout=streams[0],stderr=streams[1],cwd='/',
            env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},start_new_session=True)
        while proc.poll()is None:
            require(time.monotonic()-started<20,'FINITE_OWNERSHIP_SQL_ATTEMPT_REQUIRED')
            require(all(file.stat().st_size<=65536 for file in paths),'BOUNDED_OWNERSHIP_SQL_RECEIPT_REQUIRED');time.sleep(.05)
    finally:
        if proc is not None and proc.poll()is None:os.killpg(proc.pid,signal.SIGKILL);proc.wait(timeout=3)
        for stream in streams:stream.flush();os.fsync(stream.fileno());stream.close()
        c.sync(c.root)
    raw=[]
    for file in paths:
        fd=os.open(file,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW)
        try:
            before=os.fstat(fd);require(stat.S_ISREG(before.st_mode)and before.st_uid==before.st_gid==0 and before.st_nlink==1
                and stat.S_IMODE(before.st_mode)==0o600 and before.st_size<=65536,'PRIVATE_SQL_RECEIPT_CUSTODY_REQUIRED')
            payload=os.read(fd,65537);require(len(payload)==before.st_size and frame(before)==frame(os.fstat(fd))==frame(file.lstat()),'SQL_RECEIPT_CHANGED')
            raw.append(payload);c.counts['bytes']+=len(payload)
        finally:os.close(fd)
    c.put('sql-receipt.json',{'returnCode':proc.returncode,'stdoutSha256':hashlib.sha256(raw[0]).hexdigest(),
        'stderrSha256':hashlib.sha256(raw[1]).hexdigest(),'bytes':[len(v)for v in raw]})
    require(c.counts['bytes']<=MAXIMUMS['totalBytes']and proc.returncode==0 and 0<len(raw[0])<=65536,'SUCCESSFUL_BOUNDED_READ_ONLY_SQL_REQUIRED')
    return decode(raw[0])

def inspect_ownership(c,case=CASE,*,engine_factory=Engine,pin=process_pin,boot_path=Path('/proc/sys/kernel/random/boot_id'),sql_reader=read_sql):
    root=Path(case['installedRoot']);review=c.private(root/'review.json',case['reviewHash'])
    result=c.private(root/'result.json');journal=c.private(root/'recovery.json')
    candidate,profile,expected_pg=history(review,result,journal,case)
    require(boot_path.read_text().strip()==review['bootId'],'SAME_RETAINED_BOOT_REQUIRED')
    binding=review['nativePlan']['proposal']['engineBinding'];retained=profile['engineBinding']
    require('peerCredentials'not in retained and set(binding)==set(retained)|{'peerCredentials'}
        and all(binding[k]==v for k,v in retained.items()),'SAME_RETAINED_SQL_AND_CURRENT_ENGINE_TRANSPORT_REQUIRED')
    ids={'onboarding':candidate['id'],'postgres':expected_pg['containerId']};engine=engine_factory(c,binding,list(ids.values()))
    roots={'pid1':pin(1),'engine':pin(binding['peerCredentials'][0])};observed={};pins={}
    require(engine.get('/v1.44/info').get('ServerVersion')=='29.8.1','QUALIFIED_ENGINE_VERSION_REQUIRED')
    def check(role):
        actual=engine.get('/v1.44/containers/'+ids[role]+'/json');native=stable_binding(actual);generation=pin(actual['State']['Pid'])
        require(actual['State']['Running']is True and actual['State']['Paused']is False and actual['State']['Restarting']is False,'EXACT_RUNNING_READ_OWNER_REQUIRED')
        if role=='onboarding':require(digest(native)==case['nativeBindingHash']and actual['Image']==case['nativeImageId']and generation==candidate['generation'],'SAME_INSTALLED_ONBOARDING_REQUIRED')
        else:require(native==expected_pg,'SAME_RETAINED_POSTGRES_REQUIRED')
        if role in observed:require(native==stable_binding(observed[role])and generation==pins[role],'CURRENT_READ_OWNER_GENERATION_DRIFT')
        return actual,generation
    for role in ids:observed[role],pins[role]=check(role)
    def local_guard():
        require(boot_path.read_text().strip()==review['bootId']and roots=={'pid1':pin(1),'engine':pin(binding['peerCredentials'][0])}
            and all(pin(value['State']['Pid'])==pins[role]for role,value in observed.items()),'READ_BOOT_OR_PROCESS_GENERATION_DRIFT')
        for path,seal in c.seals.items():require(list(frame(Path(path).lstat()))==seal['metadata'],'CONSUMED_PRIVATE_METADATA_DRIFT')
    local_guard();facts=sql_reader(c,profile,case,local_guard)
    # The SQL receipt is durable before validation or post-read generation checks.
    summary=validate(facts,profile['identity'],case,require)
    for role in ids:check(role)
    local_guard()
    c.put('ownership-facts.json',facts)
    output={'schema':'ouf.managed-file-ownership-read-result.v1','status':'MANAGED_FILE_OWNERSHIP_OBSERVED_NO_AUTHORITY',
        'complete':True,'contextPath':str(c.root),'counts':dict(c.counts),'summary':summary,'sourceDatabaseSchema':36,
        'browserIdentityVerified':False,'currentJobOrBudgetStateObserved':True,'historicalAuthorityReused':False,
        'configurationFileContentReads':0,'credentialFileReads':0,'signingKeyReads':0,'iamRequests':0,'oauthRequests':0,
        'databaseWrites':0,'engineWrites':0,'imageImports':0,'humanBudgetsGranted':0,'resumes':0,'newGrantsGranted':0,
        'uploads':0,'newJobs':0,'acquisitionsExecuted':0,'sourceActivations':0,'runtimeAuthorityIssued':False,
        'automaticReplayAllowed':False,'budgetReset':False,'applicationE2EProven':False,'releaseAcceptance':False}
    c.put('result.json',output);return output

def main():
    c=None
    try:
        require(len(sys.argv)==1 and os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
            and os.environ.get('SUDO_UID')==str(pwd.getpwnam('oufadmin').pw_uid),'ISOLATED_OUFADMIN_READ_SCOPE_REQUIRED')
        require(sys.stdin.isatty()and sys.stdout.isatty(),'INTERACTIVE_OPERATOR_TERMINAL_REQUIRED')
        code=Path(__file__).resolve();ancestry(code.parent);s=code.lstat()
        require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o400,'ROOT400_OWNERSHIP_READER_REQUIRED')
        require(not os.path.lexists(CASE['outputRoot']),'OWNERSHIP_READ_SCOPE_CONSUMED_NO_REPLAY')
        sys.stdout=Logger(code.parent/'operator.log')
        signal.signal(signal.SIGALRM,lambda *_:require(False,'FINITE_OWNERSHIP_READ_WINDOW_EXPIRED'));signal.alarm(90)
        c=Capture(CASE['outputRoot'],2)
        print('NUOVA lettura3metadata del successo conservato,5GET Engine solo Onboarding/Postgres e UNA SQL REPEATABLE READ READ ONLY,2asset esatti Farmacie/Teatri. Solo metadati/prove booleane ownership e stato stesso job. Zero letture fileconfig/credenziali/chiavi/OAuth/IAM/import/lifecycle/grant/budget/resume/acquisizioni. 90s/24MiB;STOP conserva e consuma,nonrilanciare.',flush=True)
        result=inspect_ownership(c)
    except BaseException as error:
        reason=str(error)if isinstance(error,Stop)and re.fullmatch('[A-Z0-9_]{1,120}',str(error))else'PRIVATE_OWNERSHIP_READ_FAILURE_RECONCILE'
        result={'schema':'ouf.managed-file-ownership-read-result.v1','status':'STOP_RECONCILE','complete':False,'reasonCode':reason,
            'counts':dict(c.counts)if c else{},'databaseWrites':0,'engineWrites':0,'humanBudgetsGranted':0,'resumes':0,
            'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False,'applicationE2EProven':False,'releaseAcceptance':False}
        if c is not None and not(c.root/'result.json').exists():c.put('result.json',result)
    finally:signal.alarm(0)
    print(json.dumps(result,sort_keys=True,separators=(',',':')),flush=True)
    return 0 if result['complete']else 2
if __name__=='__main__':raise SystemExit(main())
