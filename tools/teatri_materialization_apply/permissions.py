"""Exact additive temporary grants through the authenticated native owner API.

Never edits the database, existing grants, roles, descriptors or IAM. Each owner
mutation is durably claimed once. An uncertain response requires reconciliation.
"""
import copy,time,uuid
from datetime import datetime,timezone
from tools.teatri_materialization_apply.owner import require,digest
from tools.teatri_materialization_apply.preparation import publish_json
from tools.chatbot_file_cohort.authorization import ADMIN

CAP='udp.materialization.retry'
FIELDS=('grantId','capabilityId','tenantId','subjectId','servicePrincipalId','organizationId','validFrom','validUntil','constraints')

def verify_jobs(jobs,expected):
 require(type(jobs)is list and len(jobs)==len(expected)==11 and len({j['jobId']for j in jobs})==11,'EXACT_ELEVEN_RECOVERY_JOBS_REQUIRED')
 require(sorted(jobs,key=lambda j:j['jobId'])==sorted(expected,key=lambda j:j['jobId']),'CONFIRMED_JOB_SNAPSHOT_CHANGED')
 for row in jobs:
  require(row['action']=='CREATE_NEW'and row['state']=='QUARANTINED'
   and row['safeFailureCode']=='UDP_REFERENCE_INTEGRITY_MISSING'and row['integrityAttempts']==5
   and row['jobVersion']==11 and row['baselinePresent']is True and row['leasePresent']is False
   and row['canonicalEffectsPresent']is False and row['rawAccessLabel']=='RESTRICTED'
   and row['rawLakeState']=='VERIFIED'and row['issueState']=='RESOLVED'
   and all(row[k]is True for k in('governedDecisionMatches','humanReceiptMatchesResolvedIssue','latestHumanDecisionMatches','rawLakeBindingMatches','rawLakePresent')),
   'ONLY_APPROVED_UNMATERIALIZED_TEATRI_JOBS_ALLOWED')
  for key in('jobId','issueId','handoffId','ingestionRunId'):require(str(uuid.UUID(row[key]))==row[key],'CANONICAL_JOB_IDENTIFIER_REQUIRED')
  require(row['sourceId']=='teatri-csv-6609b245'and row['ingestionRunId']=='a3208f2f-ebfd-415d-bddc-79ab05dea78f'and row['typeCode']=='FILE','EXACT_TEATRI_SOURCE_REQUIRED')

def stamp(value):return datetime.fromtimestamp(value,timezone.utc).isoformat().replace('+00:00','Z')

def compile_review(active,jobs,selection,hb,now,context,closure_hash):
 verify_jobs(jobs,jobs);p=active['policy']
 require(p['version']==40 and active['policyRef']==p['bundleId']+':40','EXACT_CURRENT_POLICY40_REQUIRED')
 descriptor={'capabilityId':CAP,'operation':'COMMAND','requiredScope':CAP,'allowedActors':['HUMAN']}
 require([c for c in p['capabilities']if c['capabilityId']==CAP]==[descriptor],'EXISTING_NATIVE_RECOVERY_DESCRIPTOR_REQUIRED')
 require(selection['tenant']=='ouf-lab'and selection['subject']=='b93d8cf6-cd14-4ee6-91d7-84cd76c4f500'
  and all(hb[k]==selection[k]for k in('tenant','subject','issuer')),'EXACT_AUTHENTICATED_OPERATOR_REQUIRED')
 end=min(int(now)+3600,hb['expiresAt']-5);require(end>=now+900,'HUMAN_WINDOW_TOO_SHORT_FOR_RECOVERY_GRANTS')
 additions=[]
 for j in sorted(jobs,key=lambda j:j['jobId']):
  constraints={'effect':'ALLOW','externalRoleRef':None,'resourceType':'materialization-job','resourceId':j['jobId'],
   'resourceAttributes':{'module':'UDP','sourceRef':j['sourceId'],'jobRef':j['ingestionRunId'],'typeRef':j['typeCode']},
   'allowedDataLabels':['RESTRICTED'],'allowedDetailLevels':[],'requiredAcr':None,'requiredAmr':[],'maxAuthenticationAgeSeconds':None}
  additions.append({'grantId':'teatri-materialization:'+digest({'jobId':j['jobId'],'context':str(context)})[:40],
   'capabilityId':CAP,'tenantId':selection['tenant'],'subjectId':selection['subject'],
   'servicePrincipalId':None,'organizationId':None,'validFrom':stamp(int(now)-30),'validUntil':stamp(end),'constraints':constraints})
 ids={g['grantId']for g in p['grants']};require(len(ids)==len(p['grants'])and not ids.intersection(g['grantId']for g in additions),'EXISTING_GRANT_ID_COLLISION')
 candidate=copy.deepcopy(p);candidate.update(version=41,publishedAt=stamp(int(now)),grants=copy.deepcopy(p['grants'])+additions)
 return {'schema':'ouf.teatri-exact-recovery-permission-review.v1','baseline':copy.deepcopy(active),'candidatePolicy':candidate,
  'addedGrants':additions,'jobSnapshotHash':digest(sorted(jobs,key=lambda j:j['jobId'])),'authenticatedHuman':copy.deepcopy(hb),
  'sourceClosureHash':closure_hash,'maximumExecutionSeconds':900,'maximumElapsedSeconds':900,'absoluteExpiresAt':min(end,hb['expiresAt']-5),
  'maximumOwnerMutations':2,'existingGrantsPreserved':True,'capabilitiesPreserved':True,'rolesUnchanged':True,
  'iamChangesAllowed':False,'identityDecisionsAllowed':False,'newPolicyWorkerStarted':False,'budgetReset':False}

def verify_preview(value,review,draft):
 require(value.get('draftId')==draft['id']and value.get('revision')==draft['revision']
  and value.get('baseActiveRef')==review['baseline']['policyRef']
  and value.get('addedCapabilities')==[]and value.get('removedCapabilities')==[], 'OWNER_POLICY_PREVIEW_BASELINE_MISMATCH')
 changes=value.get('grantChanges',[])
 require(len(changes)==11 and all(r.get('before')is None for r in changes)
  and {r['grantId']:r['after']for r in changes}=={g['grantId']:g for g in review['addedGrants']},'ONLY_ELEVEN_EXACT_ADDITIVE_GRANTS_ALLOWED')

def verify_active(value,review):
 expected=review['candidatePolicy'];actual=value['policy']
 require(value['policyRef']==expected['bundleId']+':41'
  and {k:v for k,v in actual.items()if k!='publishedAt'}=={k:v for k,v in expected.items()if k!='publishedAt'},'ACTIVE_POLICY41_EXACT_GRANTS_NOT_PROVEN')

def publish(transport,human,review,decision,context,guard):
 require(decision.get('schema')=='ouf.semantic-scoped-terminal-decision.v1'
  and decision.get('sourceClosureHash')==review['sourceClosureHash']
  and decision.get('reviewHash')==digest(review)and decision.get('decision')=='APPROVE_EXACT_FINITE_SCOPED_ACTION'
  and decision.get('humanSessionHash')==digest(review['authenticatedHuman'])
  and decision['expiresAt']==min(decision['approvedAt']+900,review['absoluteExpiresAt']), 'EXACT_PERMISSION_PUBLICATION_CONSENT_REQUIRED')
 def check():
  require(decision['approvedAt']<=time.time()<decision['expiresAt'],'PERMISSION_PUBLICATION_WINDOW_EXPIRED')
  require(human.current()==review['authenticatedHuman'],'SAME_CURRENT_AUTHENTICATED_OPERATOR_REQUIRED');guard()
 check();require(transport.active()==review['baseline'],'ACTIVE_POLICY_CHANGED_BEFORE_DRAFT')
 publish_json(context,'permission-draft-claim.json',{'reviewHash':digest(review),'decisionHash':digest(decision),'automaticRetry':False})
 _,draft,_=transport.request(ADMIN+'/policies','POST',review['candidatePolicy'])
 require(draft.get('state')=='DRAFT'and draft.get('policy')==review['candidatePolicy']
  and draft.get('baseActiveRef')==review['baseline']['policyRef']and type(draft.get('revision'))is int
  and str(uuid.UUID(draft['id']))==draft['id'],'EXACT_OWNER_POLICY_DRAFT_REQUIRED')
 publish_json(context,'permission-draft-receipt.json',draft)
 check();_,preview,_=transport.request(ADMIN+'/policies/'+draft['id']+':preview','POST',etag=draft['revision']);verify_preview(preview,review,draft)
 require(transport.active()==review['baseline'],'ACTIVE_POLICY_CHANGED_BEFORE_PUBLICATION')
 check();publish_json(context,'permission-publish-claim.json',{'reviewHash':digest(review),'decisionHash':digest(decision),'draftId':draft['id'],'revision':draft['revision'],'automaticRetry':False})
 _,receipt,_=transport.request(ADMIN+'/policies/'+draft['id']+':publish','POST',etag=draft['revision'])
 require(receipt.get('id')==draft['id']and receipt.get('state')=='PUBLISHED','OWNER_POLICY_PUBLICATION_UNPROVEN')
 current=transport.active();verify_active(current,review)
 result={'schema':'ouf.teatri-exact-recovery-permission-publication.v1','complete':True,'policyRef':current['policyRef'],
  'policyHash':current['contentHash'],'reviewHash':digest(review),'decisionHash':digest(decision),'addedGrants':11,
  'existingGrantsPreserved':True,'capabilitiesPreserved':True,'maximumGrantExpiry':review['addedGrants'][0]['validUntil'],
  'jobMutations':0,'identityDecisionsPerformed':False,'newPolicyWorkerStarted':False,'budgetReset':False}
 publish_json(context,'permission-publication.json',result);return result
