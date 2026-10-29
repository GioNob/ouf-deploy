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
