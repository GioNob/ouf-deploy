"""Existing successful HUMAN, then one distinct owner7 projection publication gate."""
import copy,hashlib,os,re,signal,time
from pathlib import Path
from tools.ingestion_profile_publication import authority,history,session
from tools.ingestion_profile_publication.owner import require,digest,encoded,scope,scope_key,KIND,FORBIDDEN,FiniteUpdate,OWNER_RESULT,EXPORT
from tools.ingestion_profile_publication.native import OwnerHttp,Ports
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.chatbot_file_cohort.gateway import private_config
from tools.installation_binding_plan.plan import canonical_owner
SCHEMAS={'session-review.json':'ouf.ingestion-projection-existing-session-review.v1','session-decision.json':'ouf.ingestion-projection-existing-session-decision.v1',
 'session-receipt.json':'ouf.ingestion-projection-existing-session-receipt.v1','execution-plan.json':'ouf.ingestion-active-projection-plan.v1',
 'review.json':'ouf.semantic-scoped-infrastructure-review.v1','update-result.json':'ouf.ingestion-active-projection-result.v1'}
def publish_json(context,name,value):
 context=Path(context);require(context.parent==authority.evidence.PARENT and re.fullmatch('ingestion-profile-publication-execution-[A-Za-z0-9_-]{8,64}',context.name)
  and name in SCHEMAS and value.get('schema')==SCHEMAS[name],'EXACT_PRIVATE_PROJECTION_DOCUMENT_REQUIRED')
 history.write_new(context/name,encoded(value));require(history.read(context/name)==encoded(value),'PRIVATE_PROJECTION_DOCUMENT_READBACK_REQUIRED')
def alarm(seconds):
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('FINITE_PROJECTION_PHASE_DEADLINE')));signal.alarm(seconds)
def compile_plan(completed,first,revision,last,human,context):
 old=completed['plan'];result=completed['result'];expected=result['active']
 require(first==last==expected and revision.get('payload')==old['bindingPlan']['candidatePayload']
  and canonical_owner(revision['payload'])==expected['checksum']and revision.get('validationState')=='VALIDATED'
  and revision.get('validationFindings')==[]and revision.get('revision')==7,'CURRENT_OWNER7_FULL_PAYLOAD_AND_ETAG_REQUIRED')
 before,binding=private_config(old['projectionBinding']['path'],old['projectionBinding'])
 require(hashlib.sha256(before).hexdigest()==old['projectionBinding']['sha256'],'ORIGINAL_ACTIVE6_CAS_BINDING_REQUIRED')
 history.write_new(Path(context)/'previous-active-projection.json',before)
 plan={'schema':'ouf.ingestion-active-projection-plan.v1','kind':KIND,'authorityDirectory':str(context),
  'ownerResultBinding':{'path':str(history.CONTEXT/'update-result.json'),'sha256':OWNER_RESULT},
  'exportedProjectionBinding':result['projectionBinding'],'projectionHash':EXPORT,'projectionBinding':binding,
  'previousProjectionBackupBinding':{'path':str(Path(context)/'previous-active-projection.json'),'sha256':hashlib.sha256(before).hexdigest()},
  'expectedActive':copy.deepcopy(expected),'humanBinding':human.current(),'engine':copy.deepcopy(old['engine']),
  'gateway':copy.deepcopy(old['gateway']),'currentApplications':copy.deepcopy(old['currentApplications']),
  'retainedMcpMetadata':copy.deepcopy(old['retainedMcpMetadata']),'installationId':expected['installationId'],
  'maximumExecutionSeconds':120,'maximumEffectAttemptsPerStage':1,**{k:False for k in FORBIDDEN}}
 plan['logicalRef']=digest({'ownerResultHash':OWNER_RESULT,'oldProjectionHash':binding['sha256'],'newProjectionHash':EXPORT})
 scope(plan);return plan

def main(original,sources,closure,case,context,read,emit):
 context=Path(context);authority.closure_valid(closure);completed=history.verified()
 claim=read(case['preparationClaimBinding']['path'],expected=case['preparationClaimBinding']['sha256'])
 require(claim['context']==str(context)and claim['ownerResultHash']==OWNER_RESULT and claim['automaticReplayAllowed']is False,'EXACT_PROJECTION_PREPARATION_CLAIM_REQUIRED')
 require(case['humanBinding']==completed['plan']['humanBinding']and case['originalBinding']==completed['case']['originalBinding'],'EXACT_COMPLETED_OWNER_HUMAN_AND_SELECTION_REQUIRED')
 authority.current_authorities(int(time.time())+600)
 emit('OUF_OWNER_REFERENCE_PHASE=EXISTING_SUCCESSFUL_HUMAN_MAX_ONE_VERIFIED_REFRESH');alarm(180)
 human=session.authenticate(original['authorization']['plan']['selection'],case['humanBinding'],context,publish_json,emit)
 emit('OUF_OWNER_REFERENCE_PHASE=THREE_OWNER7_READS_AND_EXACT_PROJECTION_PLAN');alarm(45)
 http=OwnerHttp(human.selection,human,completed['result']['active']['installationId'],'ouf-projection-plan-'+case['logicalRef'][:24])
 first=http.active();revision,_=http.call('GET','/revisions/7');last=http.active()
 plan=compile_plan(completed,first,revision,last,human,context);publish_json(context,'execution-plan.json',plan)
 review=authority.compile_action_review(KIND,closure,{scope_key(KIND):scope(plan)},human.current(),context,
  {'predecessorHistoryHash':OWNER_RESULT,'predecessorIncidentRef':plan['logicalRef']},120)
 review['absoluteExpiresAt']=human.expires_at-5;publish_json(context,'review.json',review)
 emit('OUF_OWNER_REFERENCE_PHASE=NATIVE_OWNER7_PROJECTION_APPROVO_REQUIRED');alarm(90)
 decision=authority.terminal_consent(review,
  'Pubblico SOLO la proiezione autorevole owner7 gia esportata e verificata; nessun nuovo POST o export owner.\n'
  'CAS sul file attivo6 precedente, backup privato conservato, lock locale senza rete, rename atomico e readback con custodia approvata.\n'
  'Nuova autorita120s firmata dai due ruoli. Massimo UNA pubblicazione, un tentativo per effetto.\n'
  'Le82rotte e tutti i container rimangono invariati. Zero DB/migrazioni, chiavi generate, IAM/grant, fonte/job o metadati MCP.\n'
  'Il rollout Ingestion/Gateway e la sua ammissione DB restano azioni successive distinte.\n'
  'STOP/esito ambiguo: conservare tutto, nessun rollback o replay automatico. Tecniche8/8;funzionali4/6.\nPiano privato: '+str(context/'execution-plan.json'))
 require(human._read()['accessExpiresAt']>time.time()+150,'CURRENT_VERIFIED_HUMAN_MARGIN150_REQUIRED')
 action=authority.issue_action(review,decision,human);alarm(120)
 http=OwnerHttp(human.selection,human,plan['installationId'],'ouf-projection-'+plan['logicalRef'][:32])
 ports=Ports(action,plan,human,http,context);update=FiniteUpdate(action,plan,ports,Journal(context));update.initialize();row=update.run()
 binding=ports.evidence(row,'PUBLISH_ACTIVE_PROJECTION')['publishedBinding']
 result={'schema':'ouf.ingestion-active-projection-result.v1','status':'OWNER7_ACTIVE_PROJECTION_PUBLISHED','complete':True,
  'contextPath':str(context),'ownerRevision':7,'ownerGeneration':7,'ownerResultHash':OWNER_RESULT,'projectionHash':EXPORT,'publishedBinding':binding,
  'activeProjectionWrites':1,'activeProjectionPublicationPending':False,'installationProfilePublished':True,'nativeProfilePublished':False,
  'ownerPosts':0,'projectionExports':0,'gatewayWrites':0,'retainedGatewayRoutes':82,'containerLifecycleOperations':0,'databaseCalls':0,
  'databaseMigrationsPerformed':0,'secretValuesGenerated':0,'grantChanges':0,'sourceActivated':False,'jobsRetried':0,
  'oauthAttemptsAfter':human._read()['attempts'],'maximumCumulativeOAuthAttempts':288,'humanWindowExpiresAt':human.expires_at,
  'newLoginPerformed':False,'runtimeAuthorityIssued':True,'runtimeRolloutExecutorQualified':False,'databaseAdmissionProven':False,
  'completedOwnerActionReplayed':False,'automaticReplayAllowed':False,'budgetReset':False,
  'completedTechnicalPhases':8,'functionalMilestonesProven':4,'notReleaseAcceptance':True}
 publish_json(context,'update-result.json',result);signal.alarm(0);emit('OUF_INGESTION_PROFILE_PUBLICATION_RESULT='+encoded(result).decode())
