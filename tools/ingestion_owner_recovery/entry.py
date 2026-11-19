"""Two native gates: fresh HUMAN288, then only the owner secret-reference lifecycle."""
import copy,os,re,signal,time
from pathlib import Path
from tools.ingestion_read_owner_reference import baseline
from tools.ingestion_owner_recovery import authority,login,reconcile
from tools.ingestion_owner_recovery.owner import require,digest,encoded,scope,scope_key,KIND,FORBIDDEN,FiniteUpdate,DRAFT_HASH
from tools.ingestion_owner_recovery.native import OwnerHttp,Ports
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.chatbot_file_cohort.gateway import private_config
from tools.installation_binding_plan.plan import canonical_owner
SCHEMAS={'login-review.json':'ouf.human-ingestion-owner-recovery-budget-review.v7','login-decision.json':'ouf.human-ingestion-owner-recovery-budget-decision.v7',
 'login-window-receipt.json':'ouf.ingestion-owner-recovery-budget288-receipt.v1','execution-plan.json':'ouf.ingestion-owner-reference-plan.v1',
 'review.json':'ouf.semantic-scoped-infrastructure-review.v1','update-result.json':'ouf.ingestion-owner-reference-result.v1'}
def publish_json(context,name,value):
 context=Path(context);require(context.parent==authority.evidence.PARENT and re.fullmatch('ingestion-owner-recovery-execution-[A-Za-z0-9_-]{8,64}',context.name)
  and name in SCHEMAS and value.get('schema')==SCHEMAS[name],'EXACT_PRIVATE_OWNER_REFERENCE_DOCUMENT_REQUIRED')
 raw=encoded(value);require(0<len(raw)<=8388608,'BOUNDED_OWNER_REFERENCE_DOCUMENT_REQUIRED');baseline.write_new(context/name,raw)
 require(baseline.read(context/name)==raw,'OWNER_REFERENCE_PRIVATE_READBACK_REQUIRED')
def alarm(seconds):
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('FINITE_OWNER_REFERENCE_PHASE_DEADLINE')));signal.alarm(seconds)
def compile_plan(draft,inputs,prior,first,revision,last,human,context):
 require(first==last=={**draft['owner']['expectedActiveSnapshot'],'etag':'"6:'+draft['owner']['expectedActiveSnapshot']['checksum']+':6"'},'CURRENT_OWNER_ACTIVE_ETAG_MUST_MATCH_REVIEWED6')
 require(all(revision.get(k)==first[k]for k in('installationId','revision','checksum'))
  and revision.get('validationState')=='VALIDATED'and revision.get('validationFindings')==[]
  and revision.get('payload')==inputs['retainedOwnerPayload']and canonical_owner(revision['payload'])==first['checksum'],'EXACT_CURRENT_VALIDATED_OWNER_PAYLOAD_REQUIRED')
 binding={'expectedActive':{k:first[k]for k in('installationId','revision','checksum','generation')},'expectedActiveETag':first['etag'],
  'sourcePayload':copy.deepcopy(revision['payload']),'candidatePayload':copy.deepcopy(draft['owner']['candidatePayload']),
  'candidatePayloadChecksum':draft['owner']['candidatePayloadChecksum'],'onlyChange':'/secrets/references/ingestionReadOwnerKey','addedBindings':{}}
 gateway={**copy.deepcopy(prior['gateway']),'beforeRoutes':copy.deepcopy(prior['gateway']['afterRoutes']),'afterRoutes':copy.deepcopy(prior['gateway']['afterRoutes'])}
 plan={'schema':'ouf.ingestion-owner-reference-plan.v1','kind':KIND,'bindingPlan':binding,'humanBinding':human.current(),
  'authorityDirectory':str(context),'engine':copy.deepcopy(prior['engine']),'gateway':gateway,
  'currentApplications':copy.deepcopy(prior['currentApplications']),'retainedMcpMetadata':copy.deepcopy(prior['retainedMcpMetadata']),
  'projectionBinding':copy.deepcopy(inputs['publishedProjectionBinding']),'sourceProjection':copy.deepcopy(inputs['retainedProjection']),
  'draftBinding':{'path':str(baseline.DRAFT/'draft-plan.json'),'sha256':DRAFT_HASH},
  'maximumExecutionSeconds':210,'maximumEffectAttemptsPerStage':1,**{k:False for k in FORBIDDEN}}
 plan['logicalRef']=digest({'kind':KIND,'expectedActive':binding['expectedActive'],'candidatePayloadChecksum':binding['candidatePayloadChecksum'],'draftPlanHash':DRAFT_HASH})
 scope(plan);return plan

def main(original,sources,closure,case,context,read,emit):
 context=Path(context);authority.closure_valid(closure)
 claim=read(case['preparationClaimBinding']['path'],expected=case['preparationClaimBinding']['sha256'])
 require(claim['context']==str(context)and claim['draftPlanHash']==DRAFT_HASH and claim['priorOAuthAttempts']==272
  and claim['automaticReplayAllowed']is False and claim['budgetReset']is False,'EXACT_OWNER_REFERENCE_PREPARATION_CLAIM_REQUIRED')
 draft,inputs,prior,package,raw,retained,binding=baseline.history()
 require(digest(package)==baseline.PACKAGE_HASH,'EXACT_RETAINED_HUMAN264_BINDING_REQUIRED')
 reconcile.inspect()
 require(case['humanBinding']==reconcile.predecessor_binding(),'EXACT_STOPPED272_BINDING_REQUIRED')
 require(read(case['originalBinding']['path'],expected=case['originalBinding']['sha256'])==original,'EXACT_RETAINED_SELECTION_REQUIRED')
 authority.current_authorities(int(time.time())+1200)
 emit('OUF_OWNER_REFERENCE_PHASE=FRESH_HUMAN288_PROTECTED_CONFIRMATION');alarm(1200)
 human=login.authenticate(original['authorization']['plan']['selection'],case['humanBinding'],context,closure,publish_json,emit,case)
 emit('OUF_OWNER_REFERENCE_PHASE=CURRENT_OWNER_ETAG_AND_EXACT_SECRET_REFERENCE');alarm(90)
 private_config(inputs['publishedProjectionBinding']['path'],inputs['publishedProjectionBinding'])
 http=OwnerHttp(human.selection,human,inputs['installationId'],'ouf-owner-reference-plan-'+case['logicalRef'][:24])
 first=http.active();revision,_=http.call('GET','/revisions/'+str(first['revision']));last=http.active()
 plan=compile_plan(draft,inputs,prior,first,revision,last,human,context)
 publish_json(context,'execution-plan.json',plan)
 selected=scope(plan);review=authority.compile_action_review(KIND,closure,{scope_key(KIND):selected},human.current(),context,
  {'predecessorHistoryHash':DRAFT_HASH,'predecessorIncidentRef':plan['logicalRef']},210)
 review['absoluteExpiresAt']=human.expires_at-5;publish_json(context,'review.json',review)
 emit('OUF_OWNER_REFERENCE_PHASE=NATIVE_OWNER_REFERENCE_APPROVO_REQUIRED');alarm(90)
 decision=authority.terminal_consent(review,
  'Azione owner distinta: aggiungo SOLO secrets.references.ingestionReadOwnerKey dal DRAFT verificato.\n'
  'Creo UNA revisione immutabile, valido ambiente e attivo con If-Match revisione/checksum/generazione.\n'
  'Massimo3POST e1export autorevole privato,210secondi,un tentativo per effetto e readback del payload.\n'
  'Nuova autorita firmata dai due ruoli nativi, limitata al solo scope owner.\n'
  'NON genero chiavi e NON pubblico la proiezione attiva; resta quella precedente fino ad APPROVO distinto.\n'
  'Zero scritture Gateway, container, DB diretto, IAM/grant, fonte/job o metadati MCP. Il runtime non legge ancora la nuova chiave.\n'
  'Questo non e un rollout: DB e aggiornamenti runtime richiedono ammissione ed esecutore qualificato separati.\n'
  'Tecniche8/8;funzionali4/6. Dopo STOP/interruzione nessun replay.\nPiano privato: '+str(context/'execution-plan.json'))
 require(human._read()['accessExpiresAt']>time.time()+240,'FRESH_TOKEN_MARGIN240_REQUIRED_NO_REFRESH')
 action=authority.issue_action(review,decision,human);alarm(210)
 http=OwnerHttp(human.selection,human,inputs['installationId'],'ouf-owner-reference-'+plan['logicalRef'][:32])
 ports=Ports(action,plan,human,http,context);update=FiniteUpdate(action,plan,ports,Journal(context));update.initialize();row=update.run()
 active=ports.evidence(row,'ACTIVATE_EXPECTED')['active'];export=ports.evidence(row,'EXPORT_ACTIVE')['projectionBinding']
 result={'schema':'ouf.ingestion-owner-reference-result.v1','status':'OWNER_REFERENCE_ACTIVATED_AND_EXPORTED','complete':True,
  'contextPath':str(context),'active':active,'ownerPosts':http.posts,'projectionExports':http.exports,'projectionBinding':export,
  'ownerPayloadReadbackProven':True,'activeProjectionPublicationPending':True,'activeProjectionWrites':0,'secretValuesGenerated':0,
  'gatewayWrites':0,'containerLifecycleOperations':0,'directDatabaseCalls':0,'grantChanges':0,'sourceActivated':False,'jobsRetried':0,
  'nativeProfilePublished':False,'freshChatClientReadProven':False,'databaseAdmissionProven':False,'runtimeRolloutExecutorQualified':False,
  'draftPlanHash':DRAFT_HASH,'planHash':digest(plan),'oauthAttemptsAfter':human._read()['attempts'],'maximumCumulativeOAuthAttempts':288,
  'humanWindowExpiresAt':human.expires_at,'runtimeAuthorityIssued':True,'automaticReplayAllowed':False,'budgetReset':False,
  'completedTechnicalPhases':8,'functionalMilestonesProven':4,'notReleaseAcceptance':True}
 publish_json(context,'update-result.json',result);signal.alarm(0);emit('OUF_INGESTION_OWNER_REFERENCE_RESULT='+encoded(result).decode())
