"""Retained-installation draft compiler. No authority, credentials, network or runtime effects."""
import copy,hashlib,json,os,re,signal,stat,sys,tempfile
from pathlib import Path
INPUT_CONTEXT=Path('/etc/ouf/deploy-snapshots/ingestion-read-owner-inputs-z048j_zr')
INPUT_HASH='7b5d811ba31ab5899f969759eb5140c586785b1a17bdfe9287b6666ba788b314'
LOGICAL='e9de2899283ddec4c8bd2612b6e5d4f8e7d4fef4831d8ec99584c3b9a818220a'
BASE_SHA='b98be85bec46db9e929bfc0a46d773d1e3805154f99a3b2eca0b062536a6ac08'
OWNER_CHECKSUM='ded675196fa5b7f9c398b249f737ff19df26d66e81afa65ddcf9a5ecfb034a98'
KEY_REF='ingestionReadOwnerKey'
KEY_ENV='OUF_INGESTION_READ_OWNER_KEY'
CONTAINER_KEY='/run/secrets/ouf-ingestion-read-owner.key'

def require(ok,code):
 if not ok:raise ValueError(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def digest(v):return sha(encoded(v))
def canonical_owner(value):
 def check(v):
  require(type(v)in(dict,list,str,int,bool,type(None)),'OWNER_CANONICAL_JSON_DOMAIN_REQUIRED')
  if type(v)is str:require(all(0x20<=ord(c)<=0xffff and not 0xd800<=ord(c)<=0xdfff for c in v),'OWNER_CANONICAL_STRING_DOMAIN_REQUIRED')
  if type(v)is int:require(-(2**63)<=v<2**63,'OWNER_CANONICAL_INTEGER_DOMAIN_REQUIRED')
  if type(v)is list:
   for item in v:check(item)
  if type(v)is dict:
   for key,item in v.items():require(type(key)is str,'OWNER_STRING_KEYS_REQUIRED');check(key);check(item)
 check(value)
 return sha(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode())

def owner_candidate(inputs,context):
 source=inputs['retainedOwnerPayload'];projection=inputs['retainedProjection'];iam=source['iam']
 require(inputs['retainedOwnerRevision']==inputs['retainedOwnerGeneration']==projection['revision']==6
  and projection['checksum']==canonical_owner(source)==OWNER_CHECKSUM
  and source['installationId']==projection['installationId']==inputs['installationId']
  and source['secrets']['provider']=='FILES'and KEY_REF not in source['secrets']['references'],
  'EXACT_OWNER6_PAYLOAD_AND_MISSING_DEDICATED_REFERENCE_REQUIRED')
 require(iam['issuerUrl']==projection['gateway']['issuerUrl']and iam['gatewayAudience']==projection['gateway']['requiredAudience']
  and iam['workloadClients']['mcpServer']==projection['iam']['workloadClients']['mcpServer'], 'EXACT_OWNER_PROFILE_TRUST_BINDINGS_REQUIRED')
 candidate=copy.deepcopy(source);candidate['secrets']['references'][KEY_REF]=str(context/'ingestion-read-owner.key')
 restored=copy.deepcopy(candidate);del restored['secrets']['references'][KEY_REF]
 require(restored==source,'ONE_OWNER_SECRET_REFERENCE_DELTA_REQUIRED')
 return candidate

def render_function(lua,installation,capability):
 values={'DELEGATION_KEY_ENV':'OUF_GATEWAY_DELEGATION_KEY','ISSUER':installation['issuerUrl'].rstrip('/'),
  'AUDIENCE':installation['gatewayAudience'],'MCP_WORKLOAD':installation['mcpServiceIdentity'],
  'OWNER_KEY_ENV':KEY_ENV,'CAPABILITY':capability,'OWNER':'ingestion','REQUIRED_SCOPE':'ingestion.operations.read'}
 require(all(type(v)is str and v.strip()==v and v and not v.startswith('installation://')for v in values.values()),'RESOLVED_OWNER_TRUST_BINDINGS_REQUIRED')
 return 'return function(conf, ctx)\n'+'\n'.join(f'local {k} = {json.dumps(v)}'for k,v in values.items())+'\n'+lua['delegation.lua']+'\n'+lua['execute_ingestion_read.lua']+'\nend'

def route_delta(inputs,before,lua):
 require(type(before)is dict and len(before)==82 and digest(before)==inputs['retainedGatewayRouteMapHash'],'EXACT_RETAINED82_ROUTE_MAP_REQUIRED')
 iam=inputs['retainedOwnerPayload']['iam'];installation={'issuerUrl':iam['issuerUrl'],'gatewayAudience':iam['gatewayAudience'],'mcpServiceIdentity':iam['workloadClients']['mcpServer']}
 after=copy.deepcopy(before);changes=[]
 for mode in('status','history'):
  rid='mcp-ingestion-'+mode;cap='ouf.ingestion.'+mode;route=before[rid]
  require(route['uri']=='/internal/capabilities/v1/execute/'+cap and route['methods']==['POST']
   and route['plugins']['openid-connect']['bearer_only']is True and route['plugins']['openid-connect']['ssl_verify']is True
   and route['plugins']['proxy-rewrite']['uri']=='/api/internal/v1/ingestion/operations/'+mode,
   'EXACT_RETAINED_AUTHENTICATED_READ_ROUTE_REQUIRED')
  post=route['plugins']['serverless-post-function'];require(post['phase']=='access'and len(post['functions'])==1,'EXACT_SINGLE_ACCESS_FUNCTION_REQUIRED')
  for constant,expected in {'DELEGATION_KEY_ENV':'OUF_GATEWAY_DELEGATION_KEY','ISSUER':installation['issuerUrl'].rstrip('/'),
    'AUDIENCE':installation['gatewayAudience'],'MCP_WORKLOAD':installation['mcpServiceIdentity'],'CAPABILITY':cap,'OWNER':'ingestion','REQUIRED_SCOPE':'ingestion.operations.read'}.items():
   matches=re.findall(r'^local '+constant+r' = ("[^\n]*")$',post['functions'][0],re.MULTILINE)
   require(len(matches)==1 and json.loads(matches[0])==expected,'EXACT_RETAINED_LUA_TRUST_CONSTANTS_REQUIRED')
  require('OWNER_KEY_ENV'not in post['functions'][0],'OWNER_RECEIPT_ROUTE_ALREADY_PRESENT_NO_REPLAY')
  updated=after[rid];updated['plugins']['serverless-post-function']={'phase':'access','functions':[render_function(lua,installation,cap)]}
  updated.setdefault('labels',{})['ouf-mediation']='ingestion-read-owner-receipt-v1'
  restored=copy.deepcopy(updated);restored['plugins']['serverless-post-function']=copy.deepcopy(post)
  if 'labels'in route:restored['labels']=copy.deepcopy(route['labels'])
  else:restored.pop('labels',None)
  require(restored==route,'ONLY_TWO_RECEIPT_FUNCTIONS_AND_MEDIATION_LABELS_MAY_CHANGE')
  changes.append({'routeId':rid,'beforeHash':digest(route),'afterHash':digest(updated)})
 require({k:v for k,v in before.items()if k not in{c['routeId']for c in changes}}=={k:v for k,v in after.items()if k not in{c['routeId']for c in changes}},'EXACT80_OTHER_ROUTES_PRESERVED')
 return {'beforeRoutes':copy.deepcopy(before),'afterRoutes':after,'changes':changes,'retainedOtherRoutes':80,'maximumPutRequests':2}

def compile_plan(inputs,before,lua,context):
 require(inputs['schema']=='ouf.ingestion-read-owner-installation-inputs.private.v1'
  and inputs['gatewaySourceCommit']=='6bcb28906eee08e0ebe3507b8b58dd987012c8e6'
  and inputs['ingestionCandidateSourceCommit']=='663faa03288f9ad7775382b9757e44eaba4f51ca'
  and inputs['lastReportedOAuthAttempts']==259 and inputs['maximumCumulativeOAuthAttempts']==264
  and inputs['runtimeAuthorityIssued']is False and inputs['automaticReplayAllowed']is False and inputs['budgetReset']is False,
  'EXACT_AUTHENTICATED_INPUTS259_NO_AUTHORITY_REQUIRED')
 require(KEY_ENV not in inputs['gatewayEnvironmentNames']and inputs['gatewayEnvironmentAdditionRequired']is True
  and inputs['secretReferenceAlreadyPresent']is False and 'OUF_GATEWAY_DELEGATION_KEY'in inputs['gatewayEnvironmentNames'],
  'EXACT_NEW_GATEWAY_ENVIRONMENT_BINDING_REQUIRED')
 names=('OUF_ING_GATEWAY_READ_ENABLED','OUF_ING_GATEWAY_READ_ISSUER','OUF_ING_GATEWAY_READ_AUDIENCE','OUF_ING_GATEWAY_READ_WORKLOAD','OUF_ING_GATEWAY_READ_KEY_FILE')
 require(not set(names)&set(inputs['ingestionEnvironmentNames'])and all(v['Destination']!=CONTAINER_KEY for v in inputs['ingestionMountReferences']), 'NO_EXISTING_INGESTION_READ_CONFIG_OR_MOUNT_COLLISION')
 candidate=owner_candidate(inputs,context);iam=candidate['iam'];gateway=route_delta(inputs,before,lua)
 environment=dict(zip(names,('true',iam['issuerUrl'],iam['gatewayAudience'],iam['workloadClients']['mcpServer'],CONTAINER_KEY)))
 keypath=candidate['secrets']['references'][KEY_REF]
 return {'schema':'ouf.ingestion-read-owner-rollout-draft.v1','kind':'DRAFT_ONLY_NO_RUNTIME_EXECUTOR',
  'inputBinding':{'path':str(INPUT_CONTEXT/'inputs.json'),'sha256':digest(inputs)},'installationId':inputs['installationId'],
  'owner':{'expectedActiveSnapshot':{'installationId':inputs['installationId'],'revision':6,'generation':6,'checksum':OWNER_CHECKSUM},
   'ownerActiveRequeried':False,'candidatePayload':candidate,'candidatePayloadChecksum':canonical_owner(candidate),
   'onlyPayloadChange':'/secrets/references/'+KEY_REF,'maximumPosts':3,'maximumProjectionExports':1,
   'requireFreshActiveAndRevisionAndActiveBeforeReview':True,'strongIfMatchRequired':True,'revisionNumberAllocatedByOwner':True},
  'secret':{'referenceName':KEY_REF,'proposedPath':keypath,'randomBytes':32,'encoding':'hex-ascii','fileBytes':64,
   'uid':10002,'gid':10002,'mode':256,'createExclusive':True,'valuesGenerated':False,'independentOfExistingKeysRequired':True},
  'runtime':{'expectedBindings':copy.deepcopy(inputs['runtimeBindings']),
   'ingestion':{'candidateMetadata':copy.deepcopy(inputs['candidateMetadata']),'candidateImageBinding':copy.deepcopy(inputs['candidateImageBinding']),
    'environmentAdditions':environment,'readOnlyBindAddition':{'Type':'bind','Source':keypath,'Destination':CONTAINER_KEY,'RW':False,'Propagation':'rprivate'},
    'retainedMountReferences':copy.deepcopy(inputs['ingestionMountReferences']),'allOtherConfigurationPreserved':True},
   'gateway':{'imageUnchanged':True,'environmentAddition':{KEY_ENV:{'secretReference':KEY_REF}},
    'mountsUnchanged':True,'allOtherConfigurationPreserved':True},
   'maximumReplacementContainers':2,'gatewayRecreationAffectsAllRoutesDuringReadiness':True,'automaticRollbackAllowed':False},
  'gateway':gateway,'projection':{'maximumActivePublications':1,'authoritativeExportOnly':True,'casAndApprovedCustodyRequired':True,
   'expectedBinding':copy.deepcopy(inputs['publishedProjectionBinding']),
   'ingestionSecretRefNotInStandardExport':True,'serviceBootstrapFromValidatedFullOwnerPayloadRequired':True},
  'human':{'lastObservedAttempts':259,'predecessorMaximumCumulativeOAuthAttempts':264,'predecessorExpiresAt':1792436155,
   'proposedMaximumCumulativeOAuthAttempts':272,'proposedWindowSeconds':7200,'budgetReset':False,'newBudgetAuthorized':False,
   'freshNativeBudgetAndWindowConsentRequired':True,'loginCompletedBeforeFirstTokenRequest':True,'oldCredentialsReusable':False,
   'scopesUnchangedRequired':True,'automaticRenewalAllowed':False,'liveCounterReconciliationRequired':True},
  'gates':['EXACT_IMAGE_AND_INSTALLED_MIGRATION_AUDIT','NATIVE_FRESH_HUMAN_BUDGET_AND_WINDOW_CONSENT',
   'CURRENT_OWNER_CAS_AND_SECRET_REFERENCE_APPROVO','AUTHORITATIVE_PROJECTION_AND_RUNTIME_APPROVO','TWO_GATEWAY_FUNCTIONS_APPROVO','FRESH_CLIENT_READBACK'],
  'unprovenAdmissions':['exactCandidateRootfsAudit','installedJarMigrationEquality','currentDatabaseAdmission',
   'currentOwnerActiveETag','currentRuntimeGenerations','currentGatewayRouteMap','newHumanAuthority','runtimeExecutorQualification'],
  'noEffectBudget':{'databaseMigrations':0,'iamMutations':0,'grantChanges':0,'sourceActivations':0,'jobsRetried':0,'mcpMetadataChanges':0},
  'runtimeAuthorityIssued':False,'ownerApplyAuthorized':False,'newHumanLoginAllowed':False,'automaticReplayAllowed':False,'budgetReset':False,
  'completedTechnicalPhases':8,'functionalMilestonesProven':4,'notReleaseAcceptance':True}

def check_image_file(path,binding):
 path=Path(path);require(str(path)==binding['path'],'EXACT_SEALED_IMAGE_PATH_REQUIRED')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  st=os.fstat(fd);require(stat.S_ISREG(st.st_mode)and st.st_uid==st.st_gid==0 and stat.S_IMODE(st.st_mode)==0o600
   and st.st_nlink==1 and st.st_size==binding['bytes']and 0<st.st_size<=536870912,'EXACT_PRIVATE_IMAGE_CUSTODY_REQUIRED')
  h=hashlib.sha256()
  with os.fdopen(os.dup(fd),'rb')as f:
   for part in iter(lambda:f.read(1048576),b''):h.update(part)
  pin=lambda v:tuple(getattr(v,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  require(h.hexdigest()==binding['sha256']and pin(st)==pin(os.fstat(fd))==pin(path.lstat()),'SEALED_IMAGE_BYTES_DRIFT')
 finally:os.close(fd)

def main(base,lua,auditor):
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_REQUIRED')
 os.umask(0o077);signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('FINITE_DRAFT_COMPILATION_DEADLINE')));signal.alarm(300)
 inputs=base.parsed(INPUT_CONTEXT/'inputs.json',INPUT_HASH);receipt=base.parsed(INPUT_CONTEXT/'preparation-result.json')
 require(receipt['complete']is True and receipt['contextPath']==str(INPUT_CONTEXT)and receipt['inputsHash']==INPUT_HASH
  and receipt['logicalRef']==LOGICAL and receipt['candidateImageImported']is False and inputs['candidateMetadata']==base.CANDIDATE,
  'EXACT_COMPLETED_INPUT_PREPARATION_REQUIRED')
 require(inputs['candidateImageBinding']=={'path':str(INPUT_CONTEXT/'candidate-image.tar.gz'),'sha256':base.CANDIDATE['imageArchiveSha256'],'bytes':base.CANDIDATE['imageArchiveBytes']},'EXACT_SEALED_CANDIDATE_BINDING_REQUIRED')
 check_image_file(INPUT_CONTEXT/'candidate-image.tar.gz',inputs['candidateImageBinding'])
 base.private_config(base.ACTIVE_PATH,inputs['publishedProjectionBinding'])
 routes=base.parsed(base.NEW_CONTEXT/'execution-plan.json')['gateway']['afterRoutes']
 claim=INPUT_CONTEXT.parent/('ingestion-read-owner-draft-'+LOGICAL+'.claim.json');require(not os.path.lexists(claim),'DRAFT_ALREADY_CLAIMED_NO_REPLAY')
 context=Path(tempfile.mkdtemp(prefix='ingestion-read-owner-draft-',dir=INPUT_CONTEXT.parent));os.chmod(context,0o700)
 print('OUF_INGESTION_OWNER_DRAFT_CONTEXT='+str(context),flush=True)
 plan=compile_plan(inputs,routes,lua,context)
 base.write_new(claim,encoded({'contextPath':str(context),'inputHash':INPUT_HASH,'automaticReplayAllowed':False}))
 audit=auditor(inputs,context)
 require(audit['candidateImageImported']is False and audit['currentRuntimeGenerationsVerified']is True
  and audit['candidateJar']['migrationFilesUnchanged']is True and audit['installedJar']['migrationFilesUnchanged']is True
  and audit['databaseAdmissionProven']is False and audit['runtimeAuthorityIssued']is False,'EXACT_IMAGE_AND_INSTALLED_SQL_AUDIT_REQUIRED')
 base.write_new(context/'image-and-migration-audit.json',encoded(audit))
 plan['imageAndMigrationAuditBinding']={'path':str(context/'image-and-migration-audit.json'),'sha256':digest(audit)}
 plan['unprovenAdmissions']=[v for v in plan['unprovenAdmissions']if v not in('exactCandidateRootfsAudit','installedJarMigrationEquality','currentRuntimeGenerations')]
 base.write_new(context/'draft-plan.json',encoded(plan))
 require(base.parsed(context/'draft-plan.json')==plan,'SEALED_DRAFT_READBACK_REQUIRED')
 report={'schema':'ouf.ingestion-read-owner-rollout-draft-result.v1','complete':True,'status':'DRAFT_COMPILED_NO_AUTHORITY',
  'contextPath':str(context),'inputContextPath':str(INPUT_CONTEXT),'inputHash':INPUT_HASH,'draftPlanHash':digest(plan),
  'candidatePayloadChecksum':plan['owner']['candidatePayloadChecksum'],'candidateRouteMapHash':digest(plan['gateway']['afterRoutes']),
  'ownerSecretReferenceAdditions':1,'proposedRuntimeReplacements':2,'proposedGatewayPuts':2,'retainedOtherRoutes':80,
  'unprovenAdmissionCount':len(plan['unprovenAdmissions']),'runtimeExecutorQualified':False,'currentOwnerActiveRequeried':False,
  'privatePreparationWrites':4,'candidateRootfsByteCustodyProven':True,'installedSqlResourceEqualityProven':True,'databaseAdmissionProven':False,'credentialFilesOpened':0,'humanCredentialJournalsRead':0,'oauthRequests':0,'ownerRequests':0,'engineGetRequests':audit['engineGetRequests'],'engineArchiveGetRequests':audit['engineArchiveGetRequests'],
  'secretValuesGenerated':0,'gatewayWrites':0,'activeProjectionWrites':0,'containerLifecycleOperations':0,'databaseCalls':0,
  'newHumanLoginAllowed':False,'newBudgetAuthorized':False,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False,
  'completedTechnicalPhases':8,'functionalMilestonesProven':4,'notReleaseAcceptance':True}
 base.write_new(context/'preparation-result.json',encoded(report));signal.alarm(0);return report
