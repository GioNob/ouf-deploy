"""Project selected installed public policy windows, never signature authority."""
import hashlib,re
ROLES={'DEPLOYMENT_INTENT','FINAL_DEPLOYMENT_APPROVAL','CREATION_ATTESTATION'}
def require(ok,why):
 if not ok:raise ValueError(why)
def identity(v):return type(v) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}',v)
def project(profile,policy,now,expected_context,policy_binding):
 require(type(now) is int and now>=0,'EXACT_POLICY_OBSERVATION_TIME_REQUIRED')
 require(type(profile) is dict and profile.get('schema')=='ouf.semantic-existing-installation-authority-bindings.v1' and profile.get('authorities')==expected_context and profile.get('policyBinding')==policy_binding,'EXACT_INSTALLED_AUTHORITY_PROFILE_REQUIRED')
 require(type(profile.get('keyRefs')) is dict and type(profile.get('keyBindings')) is dict and set(profile['keyRefs'])==set(profile['keyBindings'])=={'installer','attestor'} and all(identity(v) for v in profile['keyRefs'].values()) and len(set(profile['keyRefs'].values()))==2,'EXISTING_DISTINCT_ROLE_KEY_REFERENCES_REQUIRED')
 for b in profile['keyBindings'].values():require(type(b) is dict and set(b)=={'path','sha256'} and type(b['path']) is str and b['path'].startswith('/') and '..' not in b['path'].split('/') and type(b['sha256']) is str and re.fullmatch('[0-9a-f]{64}',b['sha256']),'EXACT_EXISTING_ROLE_KEY_BINDING_REQUIRED')
 require(type(policy) is dict and set(policy)=={'schema','installationRef','entityRef','keys'} and policy['schema']=='ouf.semantic-deployment-trust-policy.v1' and policy['installationRef']==expected_context['installationRef'] and policy['entityRef']==expected_context['entityRef'] and type(policy['keys']) is list and 1<=len(policy['keys'])<=32,'EXACT_INSTALLED_PUBLIC_TRUST_POLICY_REQUIRED')
 seen=set()
 for k in policy['keys']:
  require(type(k) is dict and set(k)=={'keyRef','issuerRef','roles','publicKey','notBefore','expiresAt','state'} and identity(k['keyRef']) and identity(k['issuerRef']) and k['keyRef'] not in seen and type(k['roles']) is list and 1<=len(k['roles'])<=3 and all(type(r) is str and r in ROLES for r in k['roles']) and len(set(k['roles']))==len(k['roles']) and type(k['publicKey']) is str and re.fullmatch('[0-9a-f]{64}',k['publicKey']) and type(k['notBefore']) is int and type(k['expiresAt']) is int and 0<=k['notBefore']<k['expiresAt'] and k['state'] in ('ACTIVE','REVOKED'),'EXACT_PUBLIC_ROLE_POLICY_ENTRY_REQUIRED')
  seen.add(k['keyRef'])
 result={}
 for role,issuer,needed in (('installer',expected_context['intentIssuerRef'],('DEPLOYMENT_INTENT','FINAL_DEPLOYMENT_APPROVAL')),('attestor',expected_context['attestorRef'],('CREATION_ATTESTATION',))):
  selected=[k for k in policy['keys'] if k['keyRef']==profile['keyRefs'][role] and k['issuerRef']==issuer]
  require(len(selected)<=1,'ONE_INSTALLED_ROLE_POLICY_ENTRY_REQUIRED')
  if not selected:result[role]={'keyRef':profile['keyRefs'][role],'entryPresent':False,'requiredRoleWindowsEligible':False};continue
  k=selected[0];current=k['state']=='ACTIVE' and k['notBefore']<=now<k['expiresAt']
  result[role]={'keyRef':k['keyRef'],'issuerRef':k['issuerRef'],'entryPresent':True,'state':k['state'],'notBefore':k['notBefore'],'expiresAt':k['expiresAt'],'secondsUntilExpiry':max(0,k['expiresAt']-now),'policyWindowCurrent':current,'declaredRoles':k['roles'],'requiredRoleWindowsEligible':current and all(r in k['roles'] for r in needed),'publicKeyHash':hashlib.sha256(bytes.fromhex(k['publicKey'])).hexdigest()}
 return {'installationRef':expected_context['installationRef'],'entityRef':expected_context['entityRef'],'roles':result,'metadataOnlyNotSignatureVerification':True,'runtimeAuthorityIssued':False}
