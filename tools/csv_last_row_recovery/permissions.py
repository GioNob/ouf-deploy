"""Exact native permission and retry intent for one already reviewed durable job."""
import copy,re,time,uuid
from datetime import datetime,timezone
from tools.teatri_materialization_apply.owner import require,digest
from tools.teatri_materialization_apply.preparation import publish_json
from tools.chatbot_file_cohort.authorization import ADMIN
CAP='udp.materialization.retry'
def stamp(value):return datetime.fromtimestamp(value,timezone.utc).isoformat().replace('+00:00','Z')
def job(row,issue):
 return {**row,'jobId':row['job_id'],'issueId':issue,'handoffId':row['handoff_id'],'sourceId':row['source_id'],
  'ingestionRunId':row['ingestion_run_id'],'integrityAttempts':row['integrity_attempts'],'safeFailureCode':row['safe_failure_code'],
  'jobVersion':row['state_version'],'baselineHash':row['integrity_baseline_hash'],'typeCode':row['type_code']}
def job_query(expected,tenant):
 from tools.teatri_materialization_apply.preflight import literal
 t=literal(tenant);identifier=literal(expected['jobId']);issue=literal(expected['issueId'])
 return """BEGIN READ ONLY;SET LOCAL statement_timeout='10s';SET LOCAL lock_timeout='3s';
 WITH selected AS(
 SELECT h.handoff_id,h.ingestion_run_id,h.source_id,h.type_code,h.state intake_state,
 j.job_id,j.state,j.state_version,j.attempts,j.integrity_attempts,j.safe_failure_code,j.missing_ref_hashes,
 j.integrity_baseline_hash,(j.claimed_by IS NOT NULL OR j.lease_until IS NOT NULL)lease_present,
 l.state lake_state,l.access_label raw_access_label,q.state issue_state,d.action latest_action,
 (SELECT count(*)FROM ouf_udp.source_binding b WHERE b.first_handoff_id=h.handoff_id OR(b.source_id=h.source_id AND b.type_code=h.type_code AND b.source_object_id=h.source_object_id))binding_count,
 (SELECT count(*)FROM ouf_udp.materialization_observation o WHERE o.handoff_id=h.handoff_id)observation_count,
 (SELECT count(*)FROM ouf_udp.property_contribution c WHERE c.handoff_id=h.handoff_id)contribution_count
 FROM ouf_udp.materialization_job j JOIN ouf_udp.handoff_intake h USING(handoff_id)
 JOIN ouf_udp.resolution_issue q ON q.handoff_id=h.handoff_id AND q.issue_id="""+issue+"""::uuid AND q.tenant_id="""+t+"""
 JOIN ouf_udp.lake_object l ON l.lake_object_id=h.raw_lake_object_id AND l.tenant_id=q.tenant_id
 LEFT JOIN LATERAL(SELECT action FROM ouf_udp.human_resolution_decision WHERE issue_id=q.issue_id ORDER BY decided_at DESC LIMIT 1)d ON true
 WHERE j.job_id="""+identifier+"""::uuid)
 SELECT jsonb_build_object('database',current_database(),'databaseOid',(SELECT oid::bigint FROM pg_database WHERE datname=current_database()),
 'role',current_user,'transactionReadOnly',current_setting('transaction_read_only')='on',
 'jobs',coalesce((SELECT jsonb_agg(to_jsonb(x))FROM selected x),'[]'::jsonb));ROLLBACK;"""
def verify_job(rows,expected):
 keys=('handoff_id','ingestion_run_id','source_id','type_code','intake_state','job_id','state','state_version','attempts','integrity_attempts',
  'safe_failure_code','missing_ref_hashes','integrity_baseline_hash','lease_present','lake_state','raw_access_label',
  'issue_state','latest_action','binding_count','observation_count','contribution_count')
 require(type(rows)is list and len(rows)==1 and {k:rows[0].get(k)for k in keys}=={k:expected.get(k)for k in keys},
  'SINGLE_PREPARED_JOB_SNAPSHOT_CHANGED')
 require(expected['state']=='QUARANTINED'and expected['latest_action']=='CREATE_NEW'and expected['issue_state']=='RESOLVED'
  and expected['binding_count']==expected['observation_count']==expected['contribution_count']==0,'APPROVED_UNMATERIALIZED_JOB_REQUIRED')
def compile_review(active,one,selection,hb,now,context,closure_hash):
 p=active['policy'];version=p['version']
 require(type(version)is int and version==41 and active['policyRef']==p['bundleId']+':'+str(version),'REVIEWED_POLICY41_REQUIRED')
 descriptor={'capabilityId':CAP,'operation':'COMMAND','requiredScope':CAP,'allowedActors':['HUMAN']}
 require([c for c in p['capabilities']if c['capabilityId']==CAP]==[descriptor],'EXISTING_NATIVE_RECOVERY_DESCRIPTOR_REQUIRED')
 require(all(hb[k]==selection[k]for k in('tenant','subject','issuer'))and CAP in hb['scopes'],'ISSUER_VERIFIED_RECOVERY_OPERATOR_REQUIRED')
 end=min(int(now)+3600,hb['expiresAt']-5);require(end>=now+900,'HUMAN_WINDOW_TOO_SHORT_FOR_SINGLE_JOB')
 constraints={'effect':'ALLOW','externalRoleRef':None,'resourceType':'materialization-job','resourceId':one['jobId'],
  'resourceAttributes':{'module':'UDP','sourceRef':one['sourceId'],'jobRef':one['ingestionRunId'],'typeRef':one['typeCode']},
  'allowedDataLabels':[one['raw_access_label']],'allowedDetailLevels':[],'requiredAcr':None,'requiredAmr':[],'maxAuthenticationAgeSeconds':None}
 addition={'grantId':'csv-materialization:'+digest({'jobId':one['jobId'],'context':str(context)})[:40],
  'capabilityId':CAP,'tenantId':selection['tenant'],'subjectId':selection['subject'],'servicePrincipalId':None,'organizationId':None,
  'validFrom':stamp(int(now)-30),'validUntil':stamp(end),'constraints':constraints}
 ids={g['grantId']for g in p['grants']};require(len(ids)==len(p['grants'])and addition['grantId']not in ids,'PRESERVED_GRANT_IDENTIFIERS_REQUIRED')
 candidate=copy.deepcopy(p);candidate.update(version=version+1,publishedAt=stamp(int(now)),grants=copy.deepcopy(p['grants'])+[addition])
 return {'schema':'ouf.csv-single-job-permission-review.v1','baseline':copy.deepcopy(active),'candidatePolicy':candidate,'addedGrants':[addition],
  'authenticatedHuman':copy.deepcopy(hb),'sourceClosureHash':closure_hash,'absoluteExpiresAt':end,'maximumOwnerMutations':2,
  'existingGrantsPreserved':True,'capabilitiesPreserved':True,'rolesUnchanged':True,'iamChangesAllowed':False,
  'identityDecisionsAllowed':False,'budgetReset':False}
def composed_valid(approved,decision,now):
 require(decision.get('decision')=='APPROVE_EXACT_FINITE_SCOPED_ACTION'and decision.get('reviewHash')==digest(approved)
  and decision.get('sourceClosureHash')==approved['sourceClosureHash']
  and decision.get('humanSessionHash')==digest(approved['authenticatedHuman'])
  and decision['approvedAt']<=now<decision['expiresAt']<=approved['absoluteExpiresAt'],
  'CURRENT_COMPOSED_HUMAN_APPROVAL_REQUIRED')
def retry_intent(one,binding):
 return {'jobId':one['jobId'],'handoffId':one['handoffId'],'sourceId':one['sourceId'],'ingestionRunId':one['ingestionRunId'],
  'stateVersion':one['jobVersion'],'integrityAttempts':one['integrityAttempts'],'safeFailureCode':one['safeFailureCode'],
  'verifiedBaselineHash':one['baselineHash'],'operationId':str(uuid.uuid5(uuid.NAMESPACE_URL,'ouf:csv-native-recovery:'+binding+':'+one['jobId'])),
  'maximumPosts':1,'ownerReviewRequired':True,'identityDecisionsAllowed':False,'budgetReset':False}
def authorize_fresh_retry(review,approved,decision,now):
 composed_valid(approved,decision,now)
 require(now<review['expiresAt']<=decision['expiresAt'],'FRESH_NATIVE_REVIEW_WINDOW_REQUIRED')
 require(len(review['jobs'])==1 and review['authenticatedHuman']==approved['authenticatedHuman']
  and review['sourceClosureHash']==approved['sourceClosureHash'],'SAME_OPERATOR_AND_CODE_FOR_SINGLE_RETRY_REQUIRED')
 row=review['jobs'][0];intent=approved['nativeRetryIntent'];native=row['review'];body=row['request']
 require({k:native.get(k)for k in('jobId','handoffId','sourceId','ingestionRunId','stateVersion','integrityAttempts','safeFailureCode','verifiedBaselineHash')}
  =={k:intent[k]for k in('jobId','handoffId','sourceId','ingestionRunId','stateVersion','integrityAttempts','safeFailureCode','verifiedBaselineHash')}
  and native.get('retryEligible')is True and native.get('contractReady')is True and native.get('contractCheck')=='READY'
  and body['operationId']==intent['operationId']and body['expectedVersion']==intent['stateVersion']
  and body['expectedSnapshotHash']==native.get('snapshotHash')and type(native.get('snapshotHash'))is str
  and re.fullmatch('sha256:[0-9a-f]{64}',native['snapshotHash'])and set(body)=={'operationId','expectedVersion','expectedSnapshotHash','reason'}
  and intent['maximumPosts']==1,
  'FRESH_OWNER_REVIEW_MUST_MATCH_APPROVED_RETRY_INTENT')
def publish(transport,human,review,approved,decision,context,guard):
 composed_valid(approved,decision,time.time())
 require(approved['permissionReview']==review and review['authenticatedHuman']==approved['authenticatedHuman'],'EXACT_APPROVED_PERMISSION_CANDIDATE_REQUIRED')
 def check():
  composed_valid(approved,decision,time.time());require(decision['expiresAt']-time.time()>35,'CURRENT_MUTATION_WINDOW_REQUIRED');require(human.current()==approved['authenticatedHuman'],'SAME_AUTHENTICATED_HUMAN_REQUIRED');guard()
 check();require(transport.active()==review['baseline'],'ACTIVE_POLICY_CHANGED_BEFORE_DRAFT')
 publish_json(context,'permission-draft-claim.json',{'reviewHash':digest(review),'composedReviewHash':digest(approved),'decisionHash':digest(decision),'automaticRetry':False})
 _,draft,_=transport.request(ADMIN+'/policies','POST',review['candidatePolicy'])
 require(draft.get('state')=='DRAFT'and draft.get('policy')==review['candidatePolicy']and draft.get('baseActiveRef')==review['baseline']['policyRef']
  and type(draft.get('revision'))is int and str(uuid.UUID(draft['id']))==draft['id'],'EXACT_OWNER_POLICY_DRAFT_REQUIRED')
 publish_json(context,'permission-draft-receipt.json',draft)
 check();_,preview,_=transport.request(ADMIN+'/policies/'+draft['id']+':preview','POST',etag=draft['revision'])
 changes=preview.get('grantChanges',[])
 require(preview.get('draftId')==draft['id']and preview.get('revision')==draft['revision']and preview.get('baseActiveRef')==review['baseline']['policyRef']
  and preview.get('addedCapabilities')==[]and preview.get('removedCapabilities')==[]and len(changes)==1
  and changes[0].get('before')is None and changes[0].get('after')==review['addedGrants'][0]
  and changes[0].get('grantId')==review['addedGrants'][0]['grantId'],'ONLY_EXACT_SINGLE_ADDITIVE_GRANT_ALLOWED')
 require(transport.active()==review['baseline'],'ACTIVE_POLICY_CHANGED_BEFORE_PUBLICATION')
 check();publish_json(context,'permission-publish-claim.json',{'reviewHash':digest(review),'composedReviewHash':digest(approved),'draftId':draft['id'],'revision':draft['revision'],'automaticRetry':False})
 _,receipt,_=transport.request(ADMIN+'/policies/'+draft['id']+':publish','POST',etag=draft['revision'])
 require(receipt.get('id')==draft['id']and receipt.get('state')=='PUBLISHED','OWNER_POLICY_PUBLICATION_UNPROVEN')
 current=transport.active();expected=review['candidatePolicy']
 require(current['policyRef']==expected['bundleId']+':'+str(expected['version'])
  and {k:v for k,v in current['policy'].items()if k!='publishedAt'}=={k:v for k,v in expected.items()if k!='publishedAt'},'EXACT_PRESERVED_POLICY_AND_SINGLE_GRANT_REQUIRED')
 result={'complete':True,'policyRef':current['policyRef'],'policyHash':current['contentHash'],'addedGrants':1,
  'composedReviewHash':digest(approved),'existingGrantsPreserved':True,'capabilitiesPreserved':True,'jobsRetried':0}
 publish_json(context,'permission-publication.json',result);return result
