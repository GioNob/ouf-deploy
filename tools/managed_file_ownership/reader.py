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
