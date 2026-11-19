"""CI only: actual Docker/Unix root peer/PG17 and synthetic retained ownership data."""
import copy,hashlib,importlib.util,json,os,shutil,socket,stat,struct,subprocess,time,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('ownership_native',ROOT/'scripts/read-managed-file-ownership-20261028.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
assert os.geteuid()==os.getegid()==0
root=Path('/var/lib/ouf-ownership-native-ci');root.mkdir(mode=0o700);root.chmod(0o700)
docker=str(Path(shutil.which('docker')).resolve());ids=[]
def cli(*args):return subprocess.check_output([docker,*args],text=True).strip()
def inspect(cid):return json.loads(cli('inspect',cid))[0]
def sql(query):return cli('exec',pg,'psql','-X','-w','-q','-A','-t','-v','ON_ERROR_STOP=1','-U','owner','-d','ouf_ownership_fixture','-c',query)
def save(folder,name,value):p=folder/name;p.write_bytes(m.encoded(value));p.chmod(0o400)

try:
    assert json.loads(cli('version','--format','{{json .Server.Version}}'))=='29.8.1'
    pg=cli('run','-d','--name','ouf-ownership-fixture-pg','-e','POSTGRES_USER=owner','-e','POSTGRES_DB=ouf_ownership_fixture','-e','POSTGRES_HOST_AUTH_METHOD=trust','postgres:17-alpine');ids.append(pg)
    for _ in range(60):
        probe=subprocess.run([docker,'exec',pg,'pg_isready','-U','owner','-d','ouf_ownership_fixture'],capture_output=True)
        if probe.returncode==0:break
        time.sleep(.5)
    assert probe.returncode==0
    onb=cli('run','-d','--name','ouf-ownership-fixture-onboarding','--user','10003:10003','alpine:3.21','sleep','300');ids.append(onb)
    a,b=inspect(onb),inspect(pg);socket_path=Path('/var/run/docker.sock').resolve();st=socket_path.lstat()
    sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);sock.connect(str(socket_path));peer=list(struct.unpack('3i',sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)));sock.close()
    binding={'socketPath':str(socket_path),'socketBinding':[st.st_dev,st.st_ino,st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode)],'peerCredentials':peer}
    retained={k:v for k,v in binding.items()if k!='peerCredentials'}
    identity={'database':'ouf_ownership_fixture','databaseOid':int(sql("select oid from pg_database where datname=current_database()")),'adminRole':'owner','postgresPort':5432}
    programs={'env':cli('exec',pg,'which','env'),'timeout':cli('exec',pg,'which','timeout'),'psql':cli('exec',pg,'which','psql')}
    profile={'schema':'ouf.current-onboarding-database-snapshot-profile.v1','identity':identity,'engineBinding':retained,
        'dockerExecutable':{'path':docker,'sha256':hashlib.sha256(Path(docker).read_bytes()).hexdigest()},
        'postgresRuntimeBinding':{'containerId':pg},'containerPrograms':programs,'unixSocketDirectory':'/var/run/postgresql'}
    case={**m.CASE,'assetId':str(uuid.uuid4()),'teatriAssetId':str(uuid.uuid4()),'jobId':str(uuid.uuid4()),'subjectId':str(uuid.uuid4()),'tenantId':'ci-tenant',
        'contentHash':'sha256:'+'a'*64,'installedRoot':str(root/'retained-success'),'nativeImageId':a['Image'],'nativeBindingHash':m.digest(m.stable_binding(a)),
        'authorityHash':'b'*64,'executionInputsHash':'c'*64}
    stages=['fixture-stage-'+str(i)for i in range(15)];generation=m.process_pin(a['State']['Pid'])
    peers={'onboarding':m.stable_binding(a),'postgres':m.stable_binding(b)}
    peers.update({'synthetic-unused-peer-'+str(i):{'containerId':str(i+1)*64}for i in range(9)})
    peers['synthetic-unused-peer-9']={'containerId':'e'*64};peers['synthetic-unused-peer-10']={'containerId':'f'*64}
    assert len(peers)==13
    proposal={'boundDatabaseProfile':profile,'existingApplications':peers,'engineBinding':binding}
    case['frozenPlanHash']=m.digest(proposal)
    review={'schema':'ouf.ths-owner-request-update-review.v1','executionRoot':case['installedRoot'],'frozenPlanHash':case['frozenPlanHash'],
        'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'stages':stages,'nativePlan':{'proposal':proposal}}
    case['reviewHash']=m.digest(review)
    result={'schema':'ouf.ths-owner-request-update-result.v1','status':'THS_OWNER_REQUEST_UPDATE_INSTALLED_E2E_NOT_ACCEPTED','complete':True,
        'scopePatchApplied':True,'componentReadinessProven':True,'reviewHash':case['reviewHash'],'authorityHash':case['authorityHash'],
        'executionInputsHash':case['executionInputsHash'],'nativeBindingHash':case['nativeBindingHash'],'nativeImageId':case['nativeImageId'],
        'generation':generation,'humanBudgetsGranted':0,'resumes':0}
    case['resultHash']=m.digest(result)
    journal={'schema':'ouf.managed-csv-control-update-journal.v1','state':'COMPLETE','reviewHash':case['reviewHash'],'authorityHash':case['authorityHash'],
        'quarantine':None,'automaticReplayAllowed':False,'budgetReset':False,'nextStage':15,
        'effects':[{'stage':stage,'state':'APPLIED','intentHash':m.digest({'reviewHash':case['reviewHash'],'stage':stage})}for stage in stages],
        'candidates':{'onboarding':{'id':onb,'configurationVerified':True,'readinessProven':True,'generation':generation}}}
    folder=Path(case['installedRoot']);folder.mkdir(mode=0o700)
    for name,v in [('review.json',review),('result.json',result),('recovery.json',journal)]:save(folder,name,v)
    before_files={p.name:p.read_bytes()for p in folder.iterdir()}
    # Purpose-minimal synthetic tables, not an application or migration E2E fixture.
    sql("""create schema ouf_onboarding;
create table ouf_onboarding.flyway_schema_history(version text,type text,success boolean);
insert into ouf_onboarding.flyway_schema_history values('36','SQL',true);
create table ouf_onboarding.managed_file_asset(asset_id uuid primary key,uploaded_by text,content_hash text,size_bytes bigint);
create table ouf_onboarding.managed_file_upload_attempt(asset_id uuid,tenant_id text,subject_id text);
create table ouf_onboarding.source(source_id text primary key,metadata jsonb);
create table ouf_onboarding.managed_onboarding_review(source_id text,tenant_id text,subject_id text);
create table ouf_onboarding.file_profile_job(job_id uuid primary key,asset_id uuid,state text,attempts integer,generation bigint,lock_version bigint,recovery_session_id uuid);
create table ouf_onboarding.managed_profile_budget_session(job_id uuid);
create table ouf_onboarding.managed_profile_event(job_id uuid);
""")
    sql("insert into ouf_onboarding.managed_file_asset values('%s','%s','%s',13903),('%s','%s','%s',1600);"%(case['assetId'],case['subjectId'],case['contentHash'],case['teatriAssetId'],case['subjectId'],case['contentHash']))
    sql("insert into ouf_onboarding.file_profile_job values('%s','%s','FAILED',5,0,0,null);"%(case['jobId'],case['assetId']))
    sql("insert into ouf_onboarding.source values('ci-teatri',jsonb_build_object('managedFileAssetId','%s'));insert into ouf_onboarding.managed_onboarding_review values('ci-teatri','%s','%s');"%(case['teatriAssetId'],case['tenantId'],case['subjectId']))
    def state():
        return {table:sql("select coalesce(jsonb_agg(to_jsonb(x) order by to_jsonb(x)::text),'[]'::jsonb) from ouf_onboarding."+table+' x')for table in('managed_file_asset','managed_file_upload_attempt','source','managed_onboarding_review','file_profile_job','managed_profile_budget_session','managed_profile_event')}
    def run(label,selected=None):
        cap=m.Capture(root/label,2);out=m.inspect_ownership(cap,selected or case);assert cap.counts['engineGets']==5 and cap.counts['privateMetadataReads']==3 and cap.counts['sqlSessions']==1
        assert stat.S_IMODE((cap.root/'sql-stdout.log').stat().st_mode)==0o600
        assert (cap.root/'sql-dispatch-claim.json').exists()and(cap.root/'sql-receipt.json').exists()
        return cap,out
    original=state();cap,out=run('legacy-gap')
    assert out['summary']['classification']=='RETAINED_UPLOADER_MATCHES_TENANT_PROOF_MISSING'and state()==original
    assert out['summary']['job']['cumulativeAttempts']==5 and out['summary']['recoverySessionCount']==out['summary']['recoveryEventCount']==0
    assert next(r for r in out['summary']['assets']if r['kind']=='TEATRI')['exactReviewTenantSubjectProof']
    saved=(cap.root/'result.json').read_bytes()
    try:m.Capture(cap.root,2);raise AssertionError('replayed read scope')
    except m.Stop as error:assert 'NO_REPLAY'in str(error)
    assert (cap.root/'result.json').read_bytes()==saved
    # A distinct CI fixture case with a real preexisting upload proof.
    sql("insert into ouf_onboarding.managed_file_upload_attempt values('%s','%s','%s')"%(case['assetId'],case['tenantId'],case['subjectId']))
    original=state();_,out=run('durable-proof');assert 'BROWSER_IDENTITY_STILL_UNOBSERVED'in out['summary']['classification']and state()==original
    # Wrong expected identity is separate from the browser, never an invitation to transfer ownership.
    wrong={**case,'subjectId':str(uuid.uuid4())};original=state();_,out=run('different-subject',wrong)
    assert out['summary']['classification']=='EXPECTED_SUBJECT_DIFFERS_FROM_RETAINED_UPLOADER'and state()==original
    # Lost/incomplete predecessor is denied before any Engine or SQL attempt.
    broken=copy.deepcopy(journal);broken['effects'][-1]['state']='CLAIMED'
    try:m.history(review,result,broken,case);raise AssertionError('ambiguous predecessor accepted')
    except m.Stop:pass
    # Root private metadata is sealed and byte-identical after all new scopes.
    assert all(p.read_bytes()==before_files[p.name]for p in folder.iterdir())
    assert m.stable_binding(inspect(onb))==m.stable_binding(a)and m.stable_binding(inspect(pg))==m.stable_binding(b)
    print(json.dumps({'status':'OWNERSHIP_READER_NATIVE_PG17_PASS','positiveCases':3,'engineGetsPerCase':5,'metadataReadsPerCase':3,'sqlSessionsPerCase':1,
        'realUnixRootPeer':True,'actualPostgres17Queries':True,'sourceDataUnchanged':True,'retainedSuccessFilesUnchanged':True,
        'sameReadScopeReplayDenied':True,'ambiguousPredecessorDenied':True,'browserIdentityProven':False,'targetExecuted':False,'applicationE2EProven':False},sort_keys=True))
finally:
    for cid in ids:subprocess.run([docker,'rm','-f',cid],capture_output=True)
