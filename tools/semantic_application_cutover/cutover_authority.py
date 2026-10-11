"""Authenticate finite cutover authority against explicit approved HUMAN bytes.

No issuance/signing, private key access, grant, budget reset or target mutation.
Reuse the existing root-custody Ed25519 verifier and its role/scoped policy.
A sealed root installer supplies the independently reviewed mandate hash, exact
intake/source/request/history bindings and installed authority context.
"""
import hashlib,time
from pathlib import Path
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator,decode,private_bytes
from tools.semantic_provider_deployment_protocol import identity,hashed

class AuthorityDenied(RuntimeError):pass

def require(ok,reason):
 if not ok:raise AuthorityDenied(reason)

class CutoverAuthority:
 def __init__(self,verifier,mandate_binding,explicitly_approved_hash,context,expected,clock=time.time):
  require(isinstance(verifier,DetachedAuthenticator),'EXISTING_ED25519_ROLE_VERIFIER_REQUIRED')
  require(type(mandate_binding) is dict and set(mandate_binding)=={'path','sha256'} and hashed(explicitly_approved_hash) and mandate_binding['sha256']==explicitly_approved_hash,'EXPLICIT_APPROVED_HUMAN_MANDATE_HASH_REQUIRED')
  require(type(context) is dict and set(context)=={'installationRef','entityRef','intentIssuerRef','approvalIssuerRef','attestorRef'} and all(identity(v) for v in context.values()),'EXACT_INSTALLED_CUTOVER_AUTHORITY_CONTEXT_REQUIRED')
  require(type(expected) is dict and set(expected)=={'intakeHash','sourceClosureHash','creationRequestHash','predecessorHistoryHash','predecessorIncidentRef'} and all(hashed(v) for v in expected.values()),'INDEPENDENT_REVIEWED_CUTOVER_BINDINGS_REQUIRED')
  self.verifier,self.binding,self.approved,self.context,self.expected,self.clock=verifier,dict(mandate_binding),explicitly_approved_hash,dict(context),dict(expected),clock
 def mandate(self,raw):
  approval_raw=private_bytes(Path(self.binding['path']))
  require(hashlib.sha256(approval_raw).hexdigest()==self.approved,'APPROVED_HUMAN_MANDATE_CHANGED')
  approval=decode(approval_raw,131072);authority=decode(raw,131072);now=self.clock()
  fields={'schema','approvalRef','decision','state','issuedAt','expiresAt','executionAuthorityHash',*self.expected}
  require(set(approval)==fields and approval['schema']=='ouf.semantic-cutover-human-mandate.v1' and identity(approval['approvalRef']) and approval['decision']=='APPROVE_FINITE_INFRASTRUCTURE_CUTOVER_ONLY' and approval['state']=='ACTIVE','EXACT_HUMAN_INFRASTRUCTURE_DECISION_REQUIRED')
  require(approval['executionAuthorityHash']==hashlib.sha256(raw).hexdigest() and all(approval[k]==v for k,v in self.expected.items()),'HUMAN_REVIEWED_AUTHORITY_OR_INTAKE_DRIFT')
  require(type(approval['issuedAt']) is int and type(approval['expiresAt']) is int and approval['issuedAt']<=now<approval['expiresAt'] and 0<approval['expiresAt']-approval['issuedAt']<=3600,'FINITE_CURRENT_HUMAN_CUTOVER_DECISION_REQUIRED')
  require(authority.get('schema')=='ouf.semantic-cutover-execution-authority.v1' and all(authority.get(k)==v for k,v in self.expected.items() if k!='intakeHash'),'SIGNED_AUTHORITY_REVIEW_SCOPE_DRIFT')
  require(type(authority.get('issuedAt')) is int and type(authority.get('expiresAt')) is int and approval['issuedAt']<=authority['issuedAt']<=now<authority['expiresAt']<=approval['expiresAt'],'SIGNED_AUTHORITY_WITHIN_HUMAN_WINDOW_REQUIRED')
  return approval_raw
 def __call__(self,raw):
  require(type(raw) is bytes and 0<len(raw)<=131072,'BOUNDED_CUTOVER_AUTHORITY_BYTES_REQUIRED')
  before=self.mandate(raw);ctx=self.context
  # BOTH separately role-framed signatures are required; a hash, an ordinary
  # provenance signature or a no-op callback cannot grant execution authority.
  for role,issuer in (('DEPLOYMENT_INTENT',ctx['intentIssuerRef']),('FINAL_DEPLOYMENT_APPROVAL',ctx['approvalIssuerRef'])):
   require(self.verifier(raw,role,issuer,ctx['installationRef'],ctx['entityRef']) is True,'CURRENT_SCOPED_CUTOVER_SIGNATURE_REQUIRED')
  require(self.mandate(raw)==before,'HUMAN_DECISION_CHANGED_DURING_VERIFICATION')
  return True
