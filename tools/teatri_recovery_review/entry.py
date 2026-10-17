"""Prepare native retry prerequisites and a new test budget without starting it."""
import base64,copy,json,os,re,stat,time
from pathlib import Path
from engine_creation import Engine
from tools.chatbot_file_cohort.gateway import NamespaceAdmin
from tools.chatbot_file_cohort.authorization import OwnerTransport
from tools.chatbot_file_cohort.human_session import HumanSession
from tools.semantic_policy_token_owner.installed_owner import compile_governed_session
from tools.teatri_materialization_apply import preflight,permissions
from tools.teatri_materialization_apply.native import runtime
from tools.teatri_materialization_apply.preparation import publish_json
from tools.teatri_materialization_apply.owner import require,digest,encoded

CAP='udp.materialization.retry'

def token_metadata(human,selection):
 row=human._read();human._check_identity_and_budget(row)
 require(row['binding']['sessionDirectory']==str(human.directory),'EXACT_HUMAN_DIRECTORY_REQUIRED')
 fd=os.open(human.token_path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  before=os.fstat(fd);require(stat.S_ISREG(before.st_mode)and before.st_uid==before.st_gid==0
   and stat.S_IMODE(before.st_mode)==0o600 and before.st_nlink==1 and 0<before.st_size<=16384,'PRIVATE_HUMAN_TOKEN_METADATA_REQUIRED')
  raw=os.read(fd,16385);pin=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  require(pin(before)==pin(os.fstat(fd))==pin(human.token_path.lstat())and len(raw)==before.st_size,'HUMAN_METADATA_CHANGED')
 finally:os.close(fd)
 parts=raw.strip().split(b'.');require(len(parts)==3,'JWT_METADATA_REQUIRED')
 claims=json.loads(base64.urlsafe_b64decode(parts[1]+b'='*(-len(parts[1])%4)))
 require(claims.get('sub')==selection['subject']and claims.get('iss')==selection['issuer']
  and claims.get('tenant_id')==selection['tenant']and claims.get('ouf_actor_type')=='HUMAN'
  and claims.get('azp')=='ouf-human-admin','SAME_HUMAN_TOKEN_METADATA_REQUIRED')
 scope=claims.get('scope','');require(type(scope)is str and len(scope)<=16384,'BOUNDED_TOKEN_SCOPE_METADATA_REQUIRED')
 return {'recoveryScopePresent':CAP in scope.split(),'actorHuman':True,'subjectMatchesReviewedHuman':True,
  'expiredAtRead':time.time()>=claims['exp'],'expiryEpoch':claims['exp'],'claimsAreMetadataOnly':True,
  'signatureVerifiedLocally':False,'credentialValuesPrinted':False,'oauthRequests':0,
  'attempts':row['attempts'],'maximumCumulativeOAuthAttempts':256,'remainingOAuthAttempts':256-row['attempts']}

def route_metadata(routes):
 rows=[]
 for route in routes.values():
  patterns=route.get('uris')or[route.get('uri','')]
  if not any('/api/udp/'in u and ('materialization'in u or 'governance'in u or u.endswith('/*'))for u in patterns):continue
  plugins=route.get('plugins')or{};oidc=plugins.get('openid-connect')or{};actors=[]
  for fn in (plugins.get('serverless-post-function')or{}).get('functions')or[]:
   for table in re.findall(r'local allowed_actors=\{([^}]+)\}',fn):actors+=re.findall(r'\["([A-Z_]+)"\]=true',table)
  rows.append({'routeId':route['id'],'uris':patterns,'methods':route.get('methods',[]),
   'requiredScopes':oidc.get('required_scopes')or[],'bearerOnly':oidc.get('bearer_only')is True,
   'allowedActorsMetadata':sorted(set(actors))})
 require(len(rows)<=64,'BOUNDED_RECOVERY_ROUTE_METADATA_REQUIRED');return rows

def iam_metadata(transport):
 rows=transport.kc('get','clients','-q','clientId=ouf-human-admin','--fields','id,clientId,enabled,protocol')
 require(type(rows)is list and len(rows)==1 and rows[0]['clientId']=='ouf-human-admin'and rows[0]['enabled']is True,'EXACT_HUMAN_ADMIN_CLIENT_REQUIRED')
 client=rows[0];require(re.fullmatch('[A-Za-z0-9_-]{1,128}',client['id']),'CANONICAL_OAUTH_CLIENT_ID_REQUIRED')
 scopes=transport.kc('get','client-scopes','--fields','id,name')
 defaults=transport.kc('get','clients/'+client['id']+'/default-client-scopes','--fields','id,name')
 optional=transport.kc('get','clients/'+client['id']+'/optional-client-scopes','--fields','id,name')
 require(all(type(x)is list and len(x)<=10000 for x in(scopes,defaults,optional)),'BOUNDED_OAUTH_CATALOGUE_REQUIRED')
 selected=[r for r in scopes if r['name']==CAP];require(len(selected)<=1,'UNIQUE_RECOVERY_SCOPE_REQUIRED')
 return {'clientEnabled':True,'scopeExists':len(selected)==1,'boundDefault':any(r['name']==CAP for r in defaults),
  'boundOptional':any(r['name']==CAP for r in optional),'iamCalls':4,'iamMutations':0}, {'client':client,'scope':selected,'defaults':defaults,'optional':optional}

def worker_review(base,records,journal):
 old=records['recovery.json'];previous=records['owner-session.json']
 require(old['state']=='CANCELLED'and old['reason']=='CANCELLED_BY_OWNER'and old['attempts']==old['publicationCount']==8
  and old['controlledPredecessorGrantAttempts']==308 and old['controlledCumulativeGrantAttempts']==316
  and old['workerSessionHash']==digest(previous)and previous['predecessorGrantAttempts']==308
  and previous['maximumCumulativeGrantAttempts']==316,'EXACT_CANCELLED316_HISTORY_REQUIRED')
 review=copy.deepcopy(base);review.update(schema='ouf.chatbot-semantic-functional-session-review.v3',preparedAt=int(time.time()),
  predecessorRecordHashes={k:digest(v)for k,v in records.items()},predecessorJournalDirectory=str(journal),
  predecessorFenceBinding=copy.deepcopy(previous['fenceBinding']),finiteTestProfile={
   'schema':'ouf.policy-token-test-session-profile.v1','maximumNewTokenGrantAttempts':128,'maximumSeconds':3600,
   'renewalIntervalSeconds':60,'automaticRenewalAllowed':False,'purpose':'CONFIGURATION_AND_VALIDATION','preserveCumulativeHistory':True})
 review['proposedFiniteBudget'].update(priorControlledGrantAttempts=316,predecessorWorkerAttempts=8,
  maximumNewTokenGrantAttempts=128,maximumCumulativeGrantAttempts=444,maximumSeconds=3600,renewalIntervalSeconds=60,automaticRenewalAllowed=False)
 review['requiredOwnerDecision'].update(explicitNewTestBudgetRequired=True,newCumulativeCeilingRequiresFreshHumanDecision=True)
 review.update(runtimeAuthorityIssued=False,humanApprovalGranted=False,readyForExecution=False);return review

def main(prepared,sources,closure,case,context,read,ns,emit):
 context=Path(context);root=Path(case['updateContext']);review=read(root/'review.json',8388608,case['updateReviewSha256'])
 plan=read(root/'execution-plan.json',8388608);record=read(root/'recovery.json',131072);issued=read(root/'authority.json',131072)
 selected=review['scopes']['udpResolutionUpdate']
 require(review['kind']=='UDP_RESOLUTION_UPDATE'and review['authorityDirectory']==str(root)
  and review['sourceClosure']['declaration']['sourceCommit']==case['updateSourceCommit']and digest(plan)==selected['planHash']
  and record['scopeHash']==digest(selected)and record['authorityHash']==digest(issued)and issued['udpResolutionUpdate']==selected
  and issued['scopedExecution']['reviewHash']==digest(review)and record['version']==31
  and record['incidentState']=='RECOVERED'and record['nextStage']==len(record['effects'])==len(selected['stages'])==11
  and [r['stage']for r in record['effects']]==selected['stages']
  and all(r['state']=='APPLIED'and r['intentHash']==digest({'planHash':selected['planHash'],'stage':r['stage']})for r in record['effects']),
  'EXACT_COMPLETED_UDP_UPDATE_REQUIRED')
 permission=review['permissionPublicationBinding'];publication=read(permission['path'],8388608,permission['sha256'])
 require(publication['policyRef']==case['expectedPolicyRef']and publication['policyHash']==case['expectedPolicyHash']
  and publication['addedGrants']==11 and publication['maximumGrantExpiry']==case['maximumGrantExpiry'],'EXACT_ELEVEN_NATIVE_RECOVERY_GRANTS_REQUIRED')
 engine=Engine(prepared['engine']['socketPath'],tuple(prepared['engine']['socketBinding']))
 pin=record['effects'][-1]['evidence']['applications']['udp']['runtimeBinding']
 for retained in {**plan['unchangedApplications'],'udp':pin}.values():
  status,actual=engine.request('GET','/v1.44/containers/'+retained['containerId']+'/json')
  require(status==200 and actual['State']['Running']is True and runtime(actual)==retained,'CURRENT_APPLICATION_GENERATION_CHANGED')
 admin=NamespaceAdmin(engine,plan['gateway']['transport']);routes=admin.routes()
 require(routes==plan['gateway']['beforeRoutes']and digest(routes)==record['effects'][-1]['evidence']['routeMapHash'],'CURRENT_ROUTE_MAP_CHANGED')
 selection=prepared['authorization']['plan']['selection'];hb=review['authenticatedHuman']
 human=HumanSession(selection,Path(hb['sessionDirectory']),Path(hb['tokenPath']),hb['expiresAt'])
 require(human._read()['binding']==hb,'EXACT_CURRENT_AUTHENTICATED_HUMAN_REQUIRED')
 token=token_metadata(human,selection);transport=OwnerTransport(selection,human.token_path,human.token_path)
 if token['recoveryScopePresent']:
  iam={'recoveryScopeAlreadyInObservedToken':True,'iamCalls':0,'iamMutations':0};iam_private={}
 else:
  try:iam,iam_private=iam_metadata(transport)
  except Exception as error:
   reason=str(error)if type(error).__name__ in('AuthorizationPaused','UpdateDenied')and re.fullmatch('[A-Z_]{1,160}',str(error))else type(error).__name__
   iam={'metadataAvailable':False,'reason':reason,'iamMutations':0};iam_private={}
 private=read(case['preparedReview']['path'],8388608,case['preparedReview']['sha256'])
 jobs=preflight.sql_fact(prepared,ns,closure['executables']['docker'],'udp',preflight.jobs_query(selection['tenant']))
 permissions.verify_jobs(jobs['jobs'],private['recoveryPreflight']['jobs']['jobs'])
 policy=preflight.sql_fact(prepared,ns,closure['executables']['docker'],'onboarding',preflight.policy_query(selection['tenant'],selection['subject']))
 require(policy['bundleVersion']==41,'PUBLISHED_RECOVERY_POLICY41_REQUIRED')
 owner=read(case['currentWorkerReview']['path'],8388608,case['currentWorkerReview']['sha256']);worker=owner['scopes']['policyTokenFiniteWorkerSession']
 journal=Path(worker['fenceBinding']['value']['journalPath']);history=private['recoveryPreflight']['workerHistory']
 records={n:read(journal/n,131072,h)for n,h in history['recordHashes'].items()};require(records['owner-session.json']==worker,'SAME_CANCELLED_POLICY_WORKER_REQUIRED')
 base=read(journal/'owner-session-review.json',131072,worker['reviewHash']);first=read(journal/'owner-first-grant.json',16384)
 future=worker_review(base,records,journal);policy128={'delays':[5,15,60,300,900],'max_attempts':128,'max_elapsed':3600,'attempt_timeout':30,'jitter':.2}
 compiled=compile_governed_session(future,records,first,policy128,digest({'operation':future['logicalOperation'],'reviewHash':digest(future)}),digest(future['registryGeneration']),60)
 require(compiled['predecessorGrantAttempts']==316 and compiled['maximumCumulativeGrantAttempts']==444,'EXACT_PRESERVED316_PLUS128_REQUIRED')
 publish_json(context,'prepared-plan.json',{'schema':'ouf.teatri-native-retry-preparation.v1','updateReviewBinding':{'path':str(root/'review.json'),'sha256':digest(review)},
  'udpRuntimeBinding':pin,'gatewayRoutesHash':digest(routes),'authenticatedHuman':hb,'jobs':jobs['jobs'],'publishedRecoveryPolicy':policy,
  'permissionPublicationBinding':permission,'iam':iam_private,'workerReview':future,'workerScope':compiled,
  'runtimeAuthorityIssued':False,'newPolicyWorkerStarted':False,'jobsRetried':0,'readyForExecution':False})
 safe={'complete':True,'contextPath':str(context),'preparedPlanPath':str(context/'prepared-plan.json'),
  'preparedPlanSha256':digest(read(context/'prepared-plan.json',8388608)),'tokenMetadata':token,'recoveryRoutes':route_metadata(routes),
  'iamMetadata':iam,'confirmedJobs':11,'controlledCumulativeGrantAttempts':316,'proposedNewWorkerAttempts':128,
  'proposedMaximumCumulativeGrantAttempts':444,'runtimeAuthorityIssued':False,'newPolicyWorkerStarted':False,'jobsRetried':0,
  'oauthRequests':0,'databaseMutations':0,'gatewayWrites':0,'grantRequests':0,'budgetReset':False,'serviceMutations':0,'functionalMilestonesProven':2}
 require(admin.routes()==routes,'ROUTES_CHANGED_DURING_PRIVATE_REVIEW')
 emit('OUF_TEATRI_NATIVE_RECOVERY_PREPARATION='+encoded(safe).decode())
