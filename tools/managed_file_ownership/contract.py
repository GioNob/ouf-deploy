"""Closed read-only comparison; never infer or write a legacy tenant binding."""
import json,re,uuid

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
