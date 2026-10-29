"""Authenticate finite cutover authority against explicit approved HUMAN bytes.

No issuance/signing, private key access, grant, budget reset or target mutation.
Reuse the existing root-custody Ed25519 verifier and its role/scoped policy.
A sealed root installer supplies the independently reviewed mandate hash, exact
intake/source/request/history bindings and installed authority context.
"""
import hashlib,time
from pathlib import Path
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator,decode,private_bytes,policy
from tools.semantic_provider_deployment_protocol import identity,hashed

class AuthorityDenied(RuntimeError):pass

def require(ok,reason):
 if not ok:raise AuthorityDenied(reason)

class CutoverAuthority:
 def __init__(self,verifier,mandate_binding,explicitly_approved_hash,context,expected,clock=time.time,*,execution_profile=None):
  require(isinstance(verifier,DetachedAuthenticator),'EXISTING_ED25519_ROLE_VERIFIER_REQUIRED')
  require(type(mandate_binding) is dict and set(mandate_binding)=={'path','sha256'} and hashed(explicitly_approved_hash) and mandate_binding['sha256']==explicitly_approved_hash,'EXPLICIT_APPROVED_HUMAN_MANDATE_HASH_REQUIRED')
  require(type(context) is dict and set(context)=={'installationRef','entityRef','intentIssuerRef','approvalIssuerRef','attestorRef'} and all(identity(v) for v in context.values()),'EXACT_INSTALLED_CUTOVER_AUTHORITY_CONTEXT_REQUIRED')
  require(type(expected) is dict and set(expected)=={'intakeHash','sourceClosureHash','creationRequestHash','predecessorHistoryHash','predecessorIncidentRef'} and all(hashed(v) for v in expected.values()),'INDEPENDENT_REVIEWED_CUTOVER_BINDINGS_REQUIRED')
  if execution_profile is not None:
   from file_only_profile import FileOnlyProfile
   require(type(execution_profile) is FileOnlyProfile,'TYPED_FILE_ONLY_EXECUTION_PROFILE_REQUIRED')
  self.execution_profile=execution_profile
  self.profile_hash=None if execution_profile is None else execution_profile.verify(execution_profile.request)
  if execution_profile is not None:require(expected['creationRequestHash']==execution_profile.compiled['creationRequestHash'],'FILE_ONLY_AUTHORITY_REQUEST_DRIFT')
  self.verifier,self.binding,self.approved,self.context,self.expected,self.clock=verifier,dict(mandate_binding),explicitly_approved_hash,dict(context),dict(expected),clock
 def mandate(self,raw):
  approval_raw=private_bytes(Path(self.binding['path']))
  require(hashlib.sha256(approval_raw).hexdigest()==self.approved,'APPROVED_HUMAN_MANDATE_CHANGED')
  approval=decode(approval_raw,131072);authority=decode(raw,131072);now=self.clock()
  profile_fields=set()
  if self.profile_hash is None:require(self.execution_profile is None,'CUTOVER_AUTHORITY_PROFILE_DRIFT')
  else:
   from file_only_profile import FileOnlyProfile,PROFILE,PHASES
   require(type(self.execution_profile) is FileOnlyProfile and self.execution_profile.verify(self.execution_profile.request)==self.profile_hash
     and authority.get('deploymentProfile')==approval.get('deploymentProfile')==PROFILE
     and authority.get('executionProfileHash')==approval.get('executionProfileHash')==self.profile_hash
     and authority.get('newDistinctLeaseWorkerRequired') is False
     and set(authority.get('phaseIntentHashes',{}))==set(PHASES),'FILE_ONLY_HUMAN_AUTHORITY_PROFILE_DRIFT')
   profile_fields={'deploymentProfile','executionProfileHash'}
  fields={'schema','approvalRef' ,'decision','state','issuedAt','expiresAt','executionAuthorityHash',*self.expected}|profile_fields
  require(set(approval)==fields and approval['schema']==('ouf.semantic-cutover-human-mandate.v1' if self.profile_hash is None else 'ouf.semantic-cutover-human-mandate.v2') and identity(approval['approvalRef']) and approval['decision']=='APPROVE_FINITE_INFRASTRUCTURE_CUTOVER_ONLY' and approval['state']=='ACTIVE','EXACT_HUMAN_INFRASTRUCTURE_DECISION_REQUIRED')
  require(approval['executionAuthorityHash']==hashlib.sha256(raw).hexdigest() and all(approval[k]==v for k,v in self.expected.items()),'HUMAN_REVIEWED_AUTHORITY_OR_INTAKE_DRIFT')
  require(type(approval['issuedAt']) is int and type(approval['expiresAt']) is int and approval['issuedAt']<=now<approval['expiresAt'] and 0<approval['expiresAt']-approval['issuedAt']<=3600,'FINITE_CURRENT_HUMAN_CUTOVER_DECISION_REQUIRED')
  require(authority.get('schema')==('ouf.semantic-cutover-execution-authority.v1' if self.profile_hash is None else 'ouf.semantic-cutover-execution-authority.v2') and all(authority.get(k)==v for k,v in self.expected.items() if k!='intakeHash'),'SIGNED_AUTHORITY_REVIEW_SCOPE_DRIFT')
  require(type(authority.get('issuedAt')) is int and type(authority.get('expiresAt')) is int and approval['issuedAt']<=authority['issuedAt']<=now<authority['expiresAt']<=approval['expiresAt'],'SIGNED_AUTHORITY_WITHIN_HUMAN_WINDOW_REQUIRED')
  ctx=self.context;configured=policy(self.verifier.read_policy(),ctx['installationRef'],ctx['entityRef'],now)
  for role,issuer in (('DEPLOYMENT_INTENT',ctx['intentIssuerRef']),('FINAL_DEPLOYMENT_APPROVAL',ctx['approvalIssuerRef']),('CREATION_ATTESTATION',ctx['attestorRef'])):
   keys=[k for k in configured['keys'] if k['issuerRef']==issuer and role in k['roles'] and k['state']=='ACTIVE' and k['notBefore']<=now<k['expiresAt']]
   require(len(keys)==1 and authority['expiresAt']<=keys[0]['expiresAt'],'CUTOVER_WINDOW_EXCEEDS_SCOPED_KEY_AUTHORITY')
  return approval_raw
 def __call__(self,raw):
  require(type(raw) is bytes and 0<len(raw)<=131072,'BOUNDED_CUTOVER_AUTHORITY_BYTES_REQUIRED')
  started=self.clock();before=self.mandate(raw);ctx=self.context
  # BOTH separately role-framed signatures are required; a hash, an ordinary
  # provenance signature or a no-op callback cannot grant execution authority.
  for role,issuer in (('DEPLOYMENT_INTENT',ctx['intentIssuerRef']),('FINAL_DEPLOYMENT_APPROVAL',ctx['approvalIssuerRef'])):
   require(self.verifier(raw,role,issuer,ctx['installationRef'],ctx['entityRef']) is True,'CURRENT_SCOPED_CUTOVER_SIGNATURE_REQUIRED')
  require(self.mandate(raw)==before,'HUMAN_DECISION_CHANGED_DURING_VERIFICATION')
  require(self.clock()>=started,'CUTOVER_AUTHORITY_CLOCK_REGRESSED')
  return True

