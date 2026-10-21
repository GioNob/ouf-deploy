"""Read complete selected intake and installed authority policy; no issuance."""
import hashlib,json,os,re,stat,sys,time,types
from pathlib import Path
HASHES={'review':'6ec32cdd81af7fd8e70b4dc2f876ecfabfd2772c1cd6fba70b8e9e4bafe9f666','custody':'cb9ff64684243d563da79d327eb7d7e325dbea6a3922c91a0b7791a3ceec9baf','scope':'ca86883d4756c57ebc0657929e67e4de98920ad5572ec725e25802f55165f80c'}
INTAKE_HASH='9ec18cf053e5925e42df93b75990343cc1d09696975fc2a224d76b4b28becdae'
INTAKE=Path('/etc/ouf/deploy-snapshots')/('semantic-native-v11-intake-'+INTAKE_HASH)
AUTHORITY={'path':'/etc/ouf/deploy-snapshots/semantic-creation-issuer-install-USjonf22/installation-authority-profile.json','sha256':'7fb7880d58e43ab40f9f53dac07a5dbad462d12e3a96f3b1287c6763b1d7ce18'}
POLICY={'path':'/etc/ouf/deploy-snapshots/semantic-trust-policy-preparation-20261004-172336/trust-policy.json','sha256':'21122630e52cb63c3744fee89f5c81ed926dad55231190243ca11be6d481bd42'}
CONTEXT={'installationRef':'ouf-lab-netcup-01','entityRef':'ouf-lab','intentIssuerRef':'ouf-lab-infrastructure-installer','approvalIssuerRef':'ouf-lab-infrastructure-installer','attestorRef':'ouf-lab-node-attestor'}
def require(ok,why):
 if not ok:raise ValueError(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def parse(raw):
 def unique(pairs):
  result={}
  for k,v in pairs:require(k not in result,'DUPLICATE_PREFLIGHT_JSON_KEY');result[k]=v
  return result
 v=json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('NONFINITE_PREFLIGHT_VALUE')))
 require(type(v) is dict,'EXACT_PREFLIGHT_OBJECT_REQUIRED');return v

def modules(sources):
 require(type(sources) is dict and set(sources)==set(HASHES),'EXACT_TRANSITION_PREFLIGHT_SOURCE_SET_REQUIRED')
 for n,h in HASHES.items():require(type(sources[n]) is bytes and len(sources[n])<=131072 and sha(sources[n])==h,'TRANSITION_PREFLIGHT_SOURCE_HASH_MISMATCH')
 out={}
 for n in HASHES:
  m=types.ModuleType('sealed_transition_preflight_'+n);exec(compile(sources[n],'sealed-transition-preflight-'+n,'exec'),m.__dict__);out[n]=m
 return out

def key_metadata(path):
 # Only lstat. Never open/read/sign/export a private authority key.
 p=Path(path)
 try:
  for parent in p.parents:
   s=parent.lstat()
   if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022:return {'present':os.path.lexists(p),'metadataCustodyMatches':False,'privateKeyBytesRead':False}
  s=p.lstat();return {'present':True,'metadataCustodyMatches':stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1 and 0<s.st_size<=4096,'privateKeyBytesRead':False}
 except FileNotFoundError:return {'present':False,'metadataCustodyMatches':False,'privateKeyBytesRead':False}

def main():
 report={'schema':'ouf.native-v11-transition-preflight-read.v1','protectedFileWrites':0,'privateKeysRead':0,'signaturesIssued':0,'runtimeAuthorityIssued':False,'executionAuthorityVerified':False,'applicationCutoverAuthorized':False,'productionApplyReady':False,'newApplicationTransitionClaimCreated':False,'containerLifecycleOperations':0,'databaseQueries':0,'databaseWrites':0,'providerCalls':0,'dnsQueries':0,'firewallWrites':0,'imageImports':0,'importJournalWrites':0,'r12Touched':False,'commonLeaseLockAcquired':False,'budgetReset':False,'privateValuesPrinted':False,'notReleaseAcceptance':True,'readConsistencyMode':'STABLE_REREADS_NOT_RUNTIME_TRANSITION_AUTHORITY'}
 phase='VERIFY_EXACT_COMPLETE_PRIVATE_INTAKE'
 try:
  require(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode and len(sys.argv)==1,'ISOLATED_ROOT_TRANSITION_PREFLIGHT_REQUIRED')
  m=modules(globals().get('__transition_preflight_sources__'));review,custody,scope=(m[k] for k in ('review','custody','scope'))
  info=INTAKE.lstat();require(stat.S_ISDIR(info.st_mode) and info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o700,'EXACT_PRIVATE_INTAKE_DIRECTORY_REQUIRED')
  require(set(os.listdir(INTAKE))==set(review.NAMES)|{'intake.json'},'EXACT_COMPLETE_PRIVATE_INTAKE_REQUIRED')
  manifest_raw=custody.file_bytes(INTAKE/'intake.json',0,{0o600},expected=INTAKE_HASH);manifest=parse(manifest_raw)
  require(manifest.get('schema')=='ouf.native-v11-atomic-review-intake.v1' and manifest.get('preparedBindings')==review.EXPECTED and manifest.get('sourceHashes')=={'program':HASHES['review'],'atomic':'c113f578b027c39573b4562cd3ac324abb8108a393b82dde19f8eb53d98e0ea6','custody':HASHES['custody']} and all(manifest.get(k) is False for k in ('applicationCutoverAuthorized','productionApplyReady','runtimeAuthorityIssued')) and manifest.get('observationsAreHistorical') is True,'EXACT_UNAUTHORIZED_REVIEW_MANIFEST_REQUIRED')
  files={n:custody.file_bytes(INTAKE/n,0,{0o600}) for n in review.NAMES};review.validate(files)
  require(manifest.get('fileHashes')=={n:sha(raw) for n,raw in files.items()},'COMPLETE_PRIVATE_INTAKE_FILE_HASHES_REQUIRED')
  phase='READ_EXISTING_AUTHORITY_PROFILE_AND_PUBLIC_POLICY_NO_KEY_BYTES'
  authority_raw=custody.file_bytes(AUTHORITY['path'],0,{0o600},expected=AUTHORITY['sha256']);profile=parse(authority_raw)
  policy_raw=custody.file_bytes(POLICY['path'],0,{0o600},expected=POLICY['sha256']);policy=parse(policy_raw)
  now=int(time.time());projection=scope.project(profile,policy,now,CONTEXT,POLICY)
  metadata={role:key_metadata(b['path']) for role,b in profile['keyBindings'].items()}
  phase='FINAL_STABLE_RECHECK_OF_SELECTED_READ_INPUTS'
  require(custody.file_bytes(INTAKE/'intake.json',0,{0o600},expected=INTAKE_HASH)==manifest_raw and all(custody.file_bytes(INTAKE/n,0,{0o600})==raw for n,raw in files.items()),'PRIVATE_INTAKE_CHANGED_DURING_PREFLIGHT')
  require(custody.file_bytes(AUTHORITY['path'],0,{0o600},expected=AUTHORITY['sha256'])==authority_raw and custody.file_bytes(POLICY['path'],0,{0o600},expected=POLICY['sha256'])==policy_raw,'INSTALLED_AUTHORITY_POLICY_CHANGED_DURING_PREFLIGHT')
  require(metadata=={role:key_metadata(b['path']) for role,b in profile['keyBindings'].items()},'PRIVATE_KEY_METADATA_CHANGED_DURING_PREFLIGHT')
  report.update(status='COMPLETE_INTAKE_AND_EXISTING_ROLE_POLICY_CAPTURED_NOT_RUNTIME_AUTHORITY',intakeHash=INTAKE_HASH,intakeFilesReverified=5,authorityProfileHash=AUTHORITY['sha256'],trustPolicyHash=POLICY['sha256'],policyObservationAt=now,policyScope=projection,privateKeyMetadata=metadata,privateKeyContentCustodyReverified=False,sourceClosurePreparedForTargetApply=False)
  code=0
 except Exception as e:
  reason=str(e);report.update(status='NATIVE_V11_TRANSITION_PREFLIGHT_READ_BLOCKED',phase=phase,reason=reason if re.fullmatch('[A-Z][A-Z0-9_]{0,120}',reason) else 'TRANSITION_PREFLIGHT_UNPROVEN');code=1
 print('OUF_NATIVE_V11_TRANSITION_PREFLIGHT='+json.dumps(report,sort_keys=True));return code
if __name__=='__main__':raise SystemExit(main())
