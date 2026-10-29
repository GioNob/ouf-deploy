"""Exact finite HUMAN decisions and existing two-role issuance for MCP update.

Private preparation has no runtime authority. The permit decision and the
infrastructure decision are distinct, hash-bound and one-use; neither performs
semantic dispatch or semantic approval. Only existing installer keys are read.
"""
import base64,copy,hashlib,json,os,re,stat,termios,time
from pathlib import Path
import iam_binding_candidate as evidence
import iam_governance_intake as governance
from iam_owner_action import publish,stdlib_binding
from cutover_authority import CutoverAuthority
from tools.chatbot_file_cohort.human_session import HumanSession
from tools.chatbot_file_cohort.review import command_matches,terminal_line,terminal_answer
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator
from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_policy_token_owner.producer import protected_directory
from tools.teatri_materialization_update.owner import require,digest,encoded,STAGES,PROFILE

KINDS={'UDP_RESOLUTION_UPDATE'}

def closure_valid(closure):
 require(type(closure)is dict and set(closure)=={'declaration','executables','stdlibHash','stdlibFileCount'}
  and closure['declaration'].get('entryModule')=='tools.teatri_materialization_update.entry'
  and closure['declaration'].get('requiredPythonFlags')==['-I','-B','-S']
  and re.fullmatch('[0-9a-f]{64}',closure.get('stdlibHash','')),'EXACT_SCOPED_EXECUTABLE_CLOSURE_REQUIRED')
 for program in closure['executables'].values():command_matches(program)
 library=stdlib_binding()
 require(digest(library)==closure['stdlibHash']and len(library['fileHashes'])==closure['stdlibFileCount'],
  'APPROVED_PYTHON_STDLIB_CHANGED')


def scopes_valid(kind,scopes,closure_hash):
 require(kind=='UDP_RESOLUTION_UPDATE'and type(scopes)is dict and set(scopes)=={'udpResolutionUpdate'},'ONLY_SINGLE_UDP_UPDATE_SCOPE_ALLOWED')
 value=scopes['udpResolutionUpdate']
 require(value.get('profile')==PROFILE and value.get('stages')==list(STAGES)
  and value.get('maximumExecutionSeconds')==900 and value.get('maximumEffectAttemptsPerStage')==1
  and value.get('maximumGatewayWrites')==0
  and all(value.get(k)is False for k in('automaticReplayAllowed','databaseMigrationsAllowed','grantChangesAllowed','semanticDispatchAllowed','automaticRollbackAllowed','identityDecisionsAllowed')),
  'EXACT_SINGLE_UDP_NO_DOMAIN_DECISION_SCOPE_REQUIRED')


def compile_action_review(kind,closure,scopes,human_binding,context,lineage,maximum_seconds):
 require(type(maximum_seconds)is int and maximum_seconds==(3600 if kind=='POLICY_TEST_SESSION'else maximum_seconds)
  and 210<=maximum_seconds<=(3600 if kind=='POLICY_TEST_SESSION'else 900),'FINITE_ACTION_WINDOW_REQUIRED')
 scopes_valid(kind,scopes,digest(closure))
 require(type(lineage)is dict and set(lineage)=={'predecessorHistoryHash','predecessorIncidentRef'}
  and all(re.fullmatch('[0-9a-f]{64}',str(v))for v in lineage.values()),'EXACT_PREDECESSOR_LINEAGE_REQUIRED')
 require(Path(context).parent==evidence.PARENT and re.fullmatch('udp-resolution-execution-[A-Za-z0-9_-]{8,64}',Path(context).name),
  'EXACT_PRIVATE_SCOPED_ACTION_CONTEXT_REQUIRED')
 require(type(human_binding)is dict and type(human_binding.get('sessionId'))is str
  and all(type(human_binding.get(k))is str and human_binding[k]for k in('issuer','tenant','subject')),
  'FRESH_AUTHENTICATED_HUMAN_BINDING_REQUIRED')
 return {'schema':'ouf.semantic-scoped-infrastructure-review.v1','kind':kind,'authorityDirectory':str(context),
  'sourceClosure':copy.deepcopy(closure),'sourceClosureHash':digest(closure),'scopes':copy.deepcopy(scopes),
  'authenticatedHuman':copy.deepcopy(human_binding),'creationRequestHash':digest(scopes),**lineage,
  'maximumElapsedSeconds':maximum_seconds,'automaticReplayAllowed':False,'budgetReset':False,
  'semanticDispatchAllowed':False,'semanticApprovalAllowed':False,'completedTechnicalPhases':8,
  'functionalMilestonesProven':2,'acceptanceGranted':False}


def terminal_consent(review,summary,*,login=False):
 require(type(summary)is str and len(summary)<8192,'BOUNDED_TERMINAL_SUMMARY_REQUIRED')
 review_hash=digest(review);phrase=('RIAPRO LOGIN 'if login else'APPROVO ')+review_hash
 fd=os.open('/dev/tty',os.O_RDWR|os.O_NOCTTY|os.O_NOFOLLOW)
 try:
  require(stat.S_ISCHR(os.fstat(fd).st_mode)and os.isatty(fd),'CONTROLLING_HUMAN_TERMINAL_REQUIRED')
  termios.tcflush(fd,termios.TCIFLUSH)
  os.write(fd,('\n'+summary+'\nRevisione SHA256: '+review_hash+'\nScrivi: '+phrase+'\n> ').encode())
  accepted=False
  for attempt in range(1,4):
   raw,count=terminal_line(fd);accepted,detail=terminal_answer(raw,phrase.encode('ascii'),count)
   if accepted:break
   os.write(fd,b'\n'+encoded({'status':'NOT_ACCEPTED','attempt':attempt,**detail})+b'\n> ')
  require(accepted,'EXACT_CURRENT_TERMINAL_CONSENT_NOT_GIVEN')
 finally:os.close(fd)
 now=int(time.time())
 if login:return {'schema':'ouf.human-login-window-terminal-consent.v1','reviewHash':review_hash,
  'decision':'OPEN_ONE_LOGIN_WINDOW_NO_RUNTIME_AUTHORITY','approvedAt':now,'expiresAt':now+7200}
 return {'schema':'ouf.semantic-scoped-terminal-decision.v1','reviewHash':review_hash,
  'approvalRef':'mcp-scoped-'+review_hash[:24]+'-'+str(now),'sourceClosureHash':review['sourceClosureHash'],
  'humanSessionHash':digest(review['authenticatedHuman']),'approvedAt':now,
  'expiresAt':min(now+review['maximumElapsedSeconds'],review.get('absoluteExpiresAt',now+review['maximumElapsedSeconds'])),'decision':'APPROVE_EXACT_FINITE_SCOPED_ACTION','state':'ACTIVE'}


def decision_valid(review,decision,human,now):
 require(type(human)is HumanSession and human.current()==review['authenticatedHuman'],
  'CURRENT_SAME_AUTHENTICATED_HUMAN_REQUIRED')
 require(type(decision)is dict and set(decision)=={'schema','reviewHash','approvalRef','sourceClosureHash',
  'humanSessionHash','approvedAt','expiresAt','decision','state'}
  and decision['schema']=='ouf.semantic-scoped-terminal-decision.v1'and decision['state']=='ACTIVE'
  and decision['decision']=='APPROVE_EXACT_FINITE_SCOPED_ACTION'
  and decision['reviewHash']==digest(review)and decision['sourceClosureHash']==review['sourceClosureHash']
  and decision['humanSessionHash']==digest(review['authenticatedHuman'])
  and re.fullmatch('mcp-scoped-[0-9a-f]{24}-[0-9]+',decision['approvalRef'])
  and type(decision['approvedAt'])is int and type(decision['expiresAt'])is int
  and decision['approvedAt']<=now<decision['expiresAt']
  and decision['expiresAt']==min(decision['approvedAt']+review['maximumElapsedSeconds'],
   review.get('absoluteExpiresAt',decision['approvedAt']+review['maximumElapsedSeconds']))
  and decision['expiresAt']<=human.expires_at,'EXACT_CURRENT_SCOPED_DECISION_REQUIRED')


def current_authorities(expiry):
 profile=evidence.decode(governance.public_input(governance.PROFILE))
 policy=evidence.decode(governance.public_input(governance.POLICY))
 windows=governance.authority_metadata(profile,policy,int(time.time()))
 require(all(expiry<=row['expiresAt']for row in windows),'ACTION_WINDOW_EXCEEDS_EXISTING_ROLE_AUTHORITY')
 return profile,policy


def issue_action(review,decision,human):
 require(review.get('schema')=='ouf.semantic-scoped-infrastructure-review.v1','EXACT_SCOPED_REVIEW_REQUIRED')
 scopes_valid(review['kind'],review['scopes'],review['sourceClosureHash'])
 decision_valid(review,decision,human,time.time());closure_valid(review['sourceClosure'])
 profile,policy=current_authorities(decision['expiresAt'])
 context=Path(review['authorityDirectory'])
 require(context.parent==evidence.PARENT and context.name.startswith('udp-resolution-execution-'),
  'SCOPED_CONTEXT_REQUIRED')
 expected={key:review[key]for key in('sourceClosureHash','creationRequestHash','predecessorHistoryHash','predecessorIncidentRef')}
 expected['intakeHash']=digest(review)
 raw=encoded({'schema':'ouf.semantic-cutover-execution-authority.v1',
  **{k:v for k,v in expected.items()if k!='intakeHash'},'issuedAt':int(time.time()),'expiresAt':decision['expiresAt'],
  **review['scopes'],'scopedExecution':{'reviewHash':digest(review),'approvalRef':decision['approvalRef'],
   'humanSessionHash':decision['humanSessionHash']},'automaticReplayAllowed':False,'databaseRestoreAuthorized':False,'r12ReplayAuthorized':False})
 mandate=encoded({'schema':'ouf.semantic-cutover-human-mandate.v1','approvalRef':decision['approvalRef'],
  'decision':'APPROVE_FINITE_INFRASTRUCTURE_CUTOVER_ONLY','state':'ACTIVE','issuedAt':decision['approvedAt'],
  'expiresAt':decision['expiresAt'],'executionAuthorityHash':hashlib.sha256(raw).hexdigest(),**expected})
 from tools.chatbot_file_cohort.action_process import private_file
 require(private_file({'path':str(context/'review.json'),'sha256':digest(review)},8388608)==encoded(review),
  'PUBLISHED_EXACT_SCOPED_REVIEW_REQUIRED')
 with protected_directory(context)as directory:
  require(publish(directory,'issuance.claim.json',encoded({'reviewHash':digest(review),'decisionHash':digest(decision),
   'automaticReplayAllowed':False})),'SCOPED_ISSUANCE_ALREADY_CONSUMED')
  for name,body in(('decision.json',encoded(decision)),('human.json',mandate),('authority.json',raw)):
   require(publish(directory,name,body),'SCOPED_AUTHORITY_ARTIFACT_ALREADY_EXISTS')
  verifier=DetachedAuthenticator(governance.POLICY,str(context),review['sourceClosure']['executables']['openssl'])
  mandate_hash=hashlib.sha256(mandate).hexdigest()
  gate=CutoverAuthority(verifier,{'path':str(context/'human.json'),'sha256':mandate_hash},mandate_hash,governance.CONTEXT,expected)
  for role,key in(('DEPLOYMENT_INTENT','intentIssuerRef'),('FINAL_DEPLOYMENT_APPROVAL','approvalIssuerRef')):
   gate.mandate(raw);decision_valid(review,decision,human,time.time())
   require(current_authorities(decision['expiresAt'])==(profile,policy),'CURRENT_SCOPED_ROLE_POLICY_CHANGED')
   signer=ExistingEd25519Signer(profile['keyBindings']['installer'],profile['keyRefs']['installer'],verifier,
    {'role':role,'issuerRef':governance.CONTEXT[key],'installationRef':governance.CONTEXT['installationRef'],
     'entityRef':governance.CONTEXT['entityRef']})
   require(publish(directory,hashlib.sha256(raw).hexdigest()+'.'+role+'.json',signer.sign(raw)),
    'SCOPED_SIGNATURE_ALREADY_EXISTS')
  gate(raw)
 return AggregateAction(gate,raw,review['sourceClosureHash'])
