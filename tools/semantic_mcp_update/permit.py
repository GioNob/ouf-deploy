"""Private one-call permit issuance after a separate current HUMAN decision.

The closed delivery supplies a fresh independently observed owner read from the
selected MCP connection; an operator assertion or a 403 is never owner absence.
The permit keeps the original command key and cannot approve semantic content.
"""
import base64,copy,hashlib,json,time,uuid
from pathlib import Path
from tools.semantic_mcp_update import authority
from tools.semantic_mcp_update.owner import require,digest,encoded
from tools.semantic_policy_token_owner.producer import protected_directory
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator
from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
from iam_owner_action import publish
import iam_governance_intake as governance


def owner_absence_valid(proof,private_review,now,connection_ref):
 require(type(proof)is dict and set(proof)=={'schema','provenance','connectionRef','subject','tenant',
  'commandKey','httpStatus','observedAt','responseHash','predecessorAttemptId','predecessorRequestHash'}
  and proof['schema']=='ouf.semantic-owner-receipt-absence.v1'
  and proof['provenance']=='LIVE_MCP_OWNER_RECEIPT_READ'
  and proof['connectionRef']==connection_ref and type(connection_ref)is str and connection_ref.startswith('link_')
  and proof['httpStatus']==404 and type(proof['observedAt'])is int
  and proof['observedAt']<=now<proof['observedAt']+300
  and type(proof['responseHash'])is str and len(proof['responseHash'])==64
  and all(c in '0123456789abcdef'for c in proof['responseHash'])
  and proof['commandKey']==private_review['history']['semanticCommandKey']
  and proof['subject']==private_review['history']['humanSubject']and proof['tenant']==private_review['history']['tenant']
  and proof['predecessorAttemptId']==private_review['retainedClaim']['attemptId']
  and proof['predecessorRequestHash']==private_review['retainedClaim']['requestHash'],
  'FRESH_SELECTED_OWNER_RECEIPT_ABSENCE_REQUIRED')


def compile_review(private_review,private_binding,closure,human_binding,context,proof,now,connection_ref):
 require(digest(private_review)==private_binding['sha256']and private_review.get('readyForExecution')is False,
  'EXACT_UNEXECUTED_ATOMIC_REVIEW_REQUIRED')
 owner_absence_valid(proof,private_review,now,connection_ref)
 profile,policy=authority.current_authorities(now+900)
 policy_raw=governance.public_input(governance.POLICY)
 configured={'schema':'ouf.mcp-reprocessing-key-profile.v1','maxSessionsPerTenant':64,
  'installationRef':profile['authorities']['installationRef'],'entityRef':profile['authorities']['entityRef'],
  'installerKeyRef':profile['keyRefs']['installer'],'intentIssuerRef':profile['authorities']['intentIssuerRef'],
  'approvalIssuerRef':profile['authorities']['approvalIssuerRef'],'trustPolicyHash':hashlib.sha256(policy_raw).hexdigest()}
 profile_raw=encoded(configured);claim=private_review['retainedClaim'];history=private_review['history']
 require(human_binding['subject']==history['humanSubject']and human_binding['tenant']==history['tenant'],
  'SAME_SELECTED_HUMAN_FOR_REPROCESSING_REQUIRED')
 payload={'schema':'ouf.mcp-semantic-reprocessing-session.v1','sessionId':str(uuid.uuid4()),
  'decisionRef':'mcp-reprocessing-'+str(uuid.uuid4()),'reason':'EXPLICIT_REPROCESSING_AFTER_VERIFIED_SCOPE_RECOVERY',
  'installationRef':configured['installationRef'],'keyProfileHash':hashlib.sha256(profile_raw).hexdigest(),
  'manifestChecksum':claim['manifestChecksum'],'servicePrincipalId':claim['servicePrincipalId'],
  'humanSubject':history['humanSubject'],'tenantId':history['tenant'],'owner':'semantic',
  'capabilityId':'ouf.semantic.propose','operationClass':'COMMAND','commandKey':history['semanticCommandKey'],
  'requestHash':claim['requestHash'],'predecessorAttemptId':claim['attemptId'],'predecessorLockVersion':claim['lockVersion'],
  'predecessorOutcomeCode':'SEM_CAPABILITY_REQUIRED:ouf.semantic.propose','priorToolCalls':1,'maximumNewToolCalls':1,
  'maximumCumulativeToolCalls':2,'ownerReceiptAbsentAt':proof['observedAt'],'issuedAt':now,'expiresAt':now+900}
 require(payload['expiresAt']<=human_binding['expiresAt'],'PERMIT_WINDOW_EXCEEDS_HUMAN_WINDOW')
 return {'schema':'ouf.mcp-reprocessing-private-permit-review.v1','authorityDirectory':str(context),
  'privateReviewBinding':copy.deepcopy(private_binding),'sourceClosure':copy.deepcopy(closure),'sourceClosureHash':digest(closure),
  'authenticatedHuman':copy.deepcopy(human_binding),'ownerReceiptAbsence':copy.deepcopy(proof),'selectedOwnerConnectionRef':connection_ref,
  'profileRaw':profile_raw.decode(),'policyRaw':policy_raw.decode(),'payload':payload,
  'maximumElapsedSeconds':900,'absoluteExpiresAt':payload['expiresAt'],'semanticApprovalAuthorized':False,
  'installerDispatchAuthorized':False,'budgetReset':False,'acceptanceGranted':False}


def issue(review,decision,human,private_review):
 require(review.get('schema')=='ouf.mcp-reprocessing-private-permit-review.v1'
  and digest(private_review)==review['privateReviewBinding']['sha256'],'EXACT_PRIVATE_PERMIT_REVIEW_REQUIRED')
 authority.decision_valid(review,decision,human,time.time());authority.closure_valid(review['sourceClosure'])
 owner_absence_valid(review['ownerReceiptAbsence'],private_review,time.time(),review['selectedOwnerConnectionRef'])
 payload=encoded(review['payload']);profile=json.loads(review['profileRaw']);expiry=review['payload']['expiresAt']
 require(review['payload']['issuedAt']<=decision['approvedAt']and expiry-time.time()>=210,
  'CURRENT_PERMIT_WINDOW_REQUIRED_BEFORE_ISSUANCE')
 installation,policy=authority.current_authorities(expiry)
 require(governance.public_input(governance.POLICY).decode()==review['policyRaw']
  and profile['installerKeyRef']==installation['keyRefs']['installer'],'CURRENT_EXISTING_PERMIT_ROLE_BINDINGS_REQUIRED')
 context=Path(review['authorityDirectory']);require(context.parent==authority.evidence.PARENT,'PRIVATE_PERMIT_CONTEXT_REQUIRED')
 from tools.chatbot_file_cohort.action_process import private_file
 require(private_file({'path':str(context/'permit-review.json'),'sha256':digest(review)},8388608)==encoded(review),
  'PUBLISHED_EXACT_PRIVATE_PERMIT_REQUIRED')
 verifier=DetachedAuthenticator(governance.POLICY,str(context),review['sourceClosure']['executables']['openssl'])
 with protected_directory(context)as directory:
  require(publish(directory,'permit-issuance.claim.json',encoded({'reviewHash':digest(review),'decisionHash':digest(decision),
   'payloadHash':hashlib.sha256(payload).hexdigest(),'automaticReplayAllowed':False})),'PERMIT_ISSUANCE_ALREADY_CONSUMED')
  require(publish(directory,'permit-decision.json',encoded(decision)),'PERMIT_DECISION_ALREADY_EXISTS')
  signatures={}
  for field,role,key in(('intent','DEPLOYMENT_INTENT','intentIssuerRef'),('approval','FINAL_DEPLOYMENT_APPROVAL','approvalIssuerRef')):
   authority.decision_valid(review,decision,human,time.time());owner_absence_valid(review['ownerReceiptAbsence'],private_review,time.time(),review['selectedOwnerConnectionRef'])
   require(authority.current_authorities(expiry)==(installation,policy),'PERMIT_ROLE_POLICY_CHANGED')
   signer=ExistingEd25519Signer(installation['keyBindings']['installer'],installation['keyRefs']['installer'],verifier,
    {'role':role,'issuerRef':governance.CONTEXT[key],'installationRef':governance.CONTEXT['installationRef'],
     'entityRef':governance.CONTEXT['entityRef']})
   signatures[field]=json.loads(signer.sign(payload))
  envelope=encoded({'payload':base64.b64encode(payload).decode(),**signatures})
  require(publish(directory,'permit-envelope.json',envelope),'PERMIT_ENVELOPE_ALREADY_EXISTS')
 return {'profile.json':review['profileRaw'],'policy.json':review['policyRaw'],'permit.json':envelope.decode()}
