"""Native job recovery API, exact snapshots, one durable dispatch claim per job."""
import copy,json,os,re,time,urllib.error,urllib.request,uuid
from pathlib import Path
from iam_owner_action import publish
from tools.semantic_policy_token_owner.producer import protected_directory
from tools.teatri_materialization_apply.owner import require,digest,encoded
from tools.teatri_materialization_apply.preparation import write_new

PREFIX='/api/udp/v1/governance/materialization/jobs/'

def document(context,name,value):
 require(re.fullmatch(r'[a-z0-9-]{1,96}\.json',name),'EXACT_RECOVERY_DOCUMENT_NAME_REQUIRED')
 raw=encoded(value);require(0<len(raw)<=8388608,'RECOVERY_DOCUMENT_BOUND')
 with protected_directory(context)as directory:
  fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
  try:
   with os.fdopen(os.dup(fd),'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
   os.fsync(directory)
  finally:os.close(fd)

class Client:
 def __init__(self,transport):self.transport=transport
 def request(self,job,method='GET',body=None):
  require(str(uuid.UUID(job))==job and method in('GET','POST')and (method=='GET')==(body is None),'EXACT_NATIVE_JOB_REQUEST_REQUIRED')
  raw=None if body is None else encoded(body)
  headers={'Authorization':'Bearer '+self.transport.token('admin'),'Accept':'application/json'}
  if raw is not None:headers['Content-Type']='application/json'
  req=urllib.request.Request(self.transport.selection['origin'].rstrip('/')+PREFIX+job+('/retry'if method=='POST'else''),
   data=raw,method=method,headers=headers)
  try:
   with self.transport.opener.open(req,timeout=30)as reply:
    data=reply.read(131073);require(reply.status==200 and len(data)<=131072,'BOUNDED_NATIVE_RECOVERY_RESPONSE_REQUIRED');return json.loads(data)
  except urllib.error.HTTPError as error:
   raise ValueError('NATIVE_RECOVERY_HTTP_'+str(error.code))from None
  except (urllib.error.URLError,TimeoutError,OSError):raise ValueError('NATIVE_RECOVERY_OUTCOME_UNPROVEN')from None

def qualify(value,job):
 require(value.get('jobId')==job['jobId']and value.get('handoffId')==job['handoffId']
  and value.get('sourceId')==job['sourceId']and value.get('ingestionRunId')==job['ingestionRunId']
  and value.get('state')=='QUARANTINED'and value.get('stateVersion')==job['jobVersion']
  and value.get('intakeState')=='DURABLE'and value.get('integrityAttempts')==job['integrityAttempts']
  and value.get('safeFailureCode')==job['safeFailureCode']and value.get('retryEligible')is True
  and value.get('contractReady')is True and value.get('contractCheck')=='READY'
  and value.get('verifiedBaselineHash')==job['baselineHash']
  and re.fullmatch('sha256:[0-9a-f]{64}',str(value.get('snapshotHash',''))),'EXACT_ELIGIBLE_NATIVE_JOB_AND_BASELINE_REQUIRED')

def prepare(client,jobs,binding,expires_at):
 rows=[];require(len({j['jobId']for j in jobs})==len(jobs)>0,'EXACT_DISTINCT_JOB_SET_REQUIRED')
 for job in jobs:
  value=client.request(job['jobId']);qualify(value,job)
  operation=str(uuid.uuid5(uuid.NAMESPACE_URL,'ouf:csv-native-recovery:'+binding+':'+job['jobId']))
  body={'operationId':operation,'expectedVersion':value['stateVersion'],'expectedSnapshotHash':value['snapshotHash'],
   'reason':'Ripresa tecnica dopo il ripristino dei riferimenti, conservando la decisione umana CREATE_NEW gia registrata.'}
  rows.append({'job':copy.deepcopy(job),'review':value,'request':body})
 return {'schema':'ouf.csv-native-materialization-retry-review.v1','jobs':rows,'maximumNewJobCalls':len(rows),
  'expiresAt':expires_at,'absoluteExpiresAt':expires_at,'maximumElapsedSeconds':900,'automaticReplayAllowed':False,'budgetReset':False,
  'identityDecisionsAllowed':False,'firstGrantReplayAllowed':False,'deferredJobsIncluded':False}

def dispatch(client,review,decision,context,guard,emit):
 require(decision.get('reviewHash')==digest(review)and decision.get('decision')=='APPROVE_EXACT_FINITE_SCOPED_ACTION'
  and decision['approvedAt']<=time.time()<decision['expiresAt']<=review['expiresAt'],'EXACT_NATIVE_RETRY_SET_APPROVAL_REQUIRED')
 accepted=[]
 for row in review['jobs']:
  require(time.time()<decision['expiresAt'],'NATIVE_JOB_RETRY_AUTHORITY_EXPIRED');guard()
  current=client.request(row['job']['jobId']);qualify(current,row['job'])
  require(current==row['review'],'NATIVE_JOB_REVIEW_CHANGED')
  name='retry-'+row['job']['jobId']
  document(context,name+'-claim.json',{'reviewHash':digest(review),'decisionHash':digest(decision),'requestHash':digest(row['request']),
   'jobId':row['job']['jobId'],'operationId':row['request']['operationId'],'automaticReplayAllowed':False})
  guard();receipt=client.request(row['job']['jobId'],'POST',row['request'])
  require(receipt.get('jobId')==row['job']['jobId']and receipt.get('handoffId')==row['job']['handoffId']
   and receipt.get('operationId')==row['request']['operationId']and receipt.get('acceptedVersion')==row['job']['jobVersion']+1
   and receipt.get('state')=='READY'and receipt.get('repeated')is False,'NATIVE_RETRY_RECEIPT_UNPROVEN')
  document(context,name+'-receipt.json',receipt);accepted.append(receipt)
  emit('OUF_CSV_NATIVE_JOB_RETRY_ACCEPTED='+encoded({'jobId':receipt['jobId'],'acceptedJobs':len(accepted),'maximumJobs':len(review['jobs']),'identityDecisionRepeated':False}).decode())
 return accepted

def proof_query(jobs,tenant):
 require(re.fullmatch('[A-Za-z0-9_.:-]{1,128}',tenant),'CLOSED_TENANT_REQUIRED')
 values=[]
 for j in jobs:
  for key in('jobId','issueId'):require(str(uuid.UUID(j[key]))==j[key],'CLOSED_JOB_IDENTIFIER_REQUIRED')
  values.append("('"+j['jobId']+"'::uuid,'"+j['issueId']+"'::uuid)")
 require(0<len(values)<=128,'BOUNDED_EXACT_JOB_SET_REQUIRED')
 return """BEGIN READ ONLY;SET LOCAL statement_timeout='10s';SET LOCAL lock_timeout='3s';
 WITH selected(job_id,issue_id)AS(VALUES """+','.join(values)+"""),facts AS(
 SELECT j.job_id,j.state job_state,j.safe_failure_code,h.state intake_state,q.state issue_state,
 b.urban_object_id,b.state binding_state,o.status object_state,o.current_revision_id,
 obs.revision_id observation_revision,rv.revision_id verified_revision,
 (SELECT count(*)FROM ouf_udp.property_contribution c WHERE c.handoff_id=h.handoff_id AND c.urban_object_id=b.urban_object_id) contributions
 FROM selected s JOIN ouf_udp.materialization_job j USING(job_id) JOIN ouf_udp.handoff_intake h USING(handoff_id)
 JOIN ouf_udp.resolution_issue q ON q.issue_id=s.issue_id AND q.handoff_id=h.handoff_id AND q.tenant_id='"""+tenant+"""'
 LEFT JOIN ouf_udp.source_binding b ON b.source_id=h.source_id AND b.type_code=h.type_code AND b.source_object_id=h.source_object_id
 LEFT JOIN ouf_udp.urban_object o ON o.urban_object_id=b.urban_object_id AND o.tenant_id='"""+tenant+"""'
 LEFT JOIN ouf_udp.materialization_observation obs ON obs.handoff_id=h.handoff_id AND obs.urban_object_id=b.urban_object_id
 LEFT JOIN ouf_udp.object_revision rv ON rv.revision_id=obs.revision_id AND rv.urban_object_id=b.urban_object_id)
 SELECT jsonb_build_object('database',current_database(),'databaseOid',(SELECT oid::bigint FROM pg_database WHERE datname=current_database()),
 'role',current_user,'transactionReadOnly',current_setting('transaction_read_only')='on','jobCount',(SELECT count(*)FROM facts),
 'distinctObjects',(SELECT count(DISTINCT urban_object_id)FROM facts),
 'materializedRows',(SELECT count(*)FROM facts WHERE job_state='SUCCEEDED'AND intake_state='PROCESSED'AND issue_state='RESOLVED'
 AND binding_state='ACTIVE'AND object_state='ACTIVE'AND current_revision_id IS NOT NULL AND observation_revision=verified_revision AND contributions>0),
 'jobs',coalesce((SELECT jsonb_agg(x)FROM(SELECT job_id,job_state,safe_failure_code,intake_state,issue_state,urban_object_id,contributions FROM facts ORDER BY job_id)x),'[]'::jsonb));ROLLBACK;"""
