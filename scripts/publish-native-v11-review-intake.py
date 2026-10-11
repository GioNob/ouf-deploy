"""Publish complete prepared V11 review bytes atomically; no runtime authority."""
import hashlib,json,os,re,sys,types
from pathlib import Path
HASHES={'atomic':'c113f578b027c39573b4562cd3ac324abb8108a393b82dde19f8eb53d98e0ea6','custody':'cb9ff64684243d563da79d327eb7d7e325dbea6a3922c91a0b7791a3ceec9baf'}
SOURCE=Path('/etc/ouf/deploy-snapshots/semantic-native-v11-plan-vj30camx')
BASE=SOURCE.parent
NAMES=('private-runtime-declaration.json','creation-request.private.json','observation.private.json','receipt.json')
EXPECTED={'declarationHash':'fc94b491d05e267b49da6e2e2fe50cc7e02e7986783bad7ebf1289b0914a0a68','requestHash':'59181588fd8bbc0836f892789156532ebcc1cce304197560ca1274f05267d552','planHash':'8f2b687846d936b91b9651e95371b5e009f3d555edb3f3cce12cf7c7823f506c','imageId':'sha256:bd48ab35db0441b1f4f48422e7190adaff176a61cddde5f981d93e496ad4b24a','configImageId':'sha256:83635be46d1fe61dea08597ea4488980b4349e5f6e0ed8bbd3ab6f5e2686370e','sourceCommit':'8a2e84b32d4ce2bdc3bc529b56afb5663ab133e3','zipSha256':'b6ae1051cee4ec9fb1b28f532622ecd39e038ec2e6a384d50565cbf92f2a0def'}
def require(ok,reason):
 if not ok:raise ValueError(reason)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def digest(value):return sha(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode())
def modules(sources):
 require(type(sources) is dict and set(sources)==set(HASHES),'EXACT_ATOMIC_INTAKE_SOURCE_SET_REQUIRED')
 for name,h in HASHES.items():require(type(sources[name]) is bytes and len(sources[name])<=131072 and sha(sources[name])==h,'ATOMIC_INTAKE_SOURCE_HASH_MISMATCH')
 out={}
 for name in HASHES:
  m=types.ModuleType('sealed_native_intake_'+name);exec(compile(sources[name],'sealed-native-intake-'+name,'exec'),m.__dict__);out[name]=m
 return out

def validate(files,expected=EXPECTED):
 require(set(files)==set(NAMES),'EXACT_PREPARED_REVIEW_FILE_SET_REQUIRED')
 values={n:json.loads(raw) for n,raw in files.items()}
 require(all(type(v) is dict for v in values.values()),'PREPARED_REVIEW_OBJECT_REQUIRED')
 decl,request,observation,receipt=(values[n] for n in NAMES)
 require(sha(files[NAMES[0]])==digest(decl)==expected['declarationHash'] and sha(files[NAMES[1]])==digest(request)==expected['requestHash'] and digest(observation.get('creationPlan'))==expected['planHash'],'EXACT_PREPARED_NATIVE_PLAN_HASHES_REQUIRED')
 require(decl.get('schema')=='ouf.discovery.private-file-secret-runtime-declaration.v1' and decl.get('candidateImageId')==request.get('Image')==expected['imageId'],'EXACT_NATIVE_REVIEW_IMAGE_REQUIRED')
 require(all(decl.get(k) is False for k in ('productionApplyReady','applicationCutoverAuthorized','completeReplacementOciProven')),'UNAPPLIED_NATIVE_DECLARATION_REQUIRED')
 package=decl.get('qualifiedPackageBinding',{})
 require(package.get('sourceCommit')==expected['sourceCommit'] and package.get('zipSha256')==expected['zipSha256'] and package.get('imageId')==expected['configImageId'],'ORIGINAL_REVIEW_PUBLISHER_BINDING_REQUIRED')
 require(receipt.get('schema')=='ouf.native-v11-current-private-plan.v1' and receipt.get('status')=='CURRENT_NATIVE_V11_DECLARATION_AND_PLAN_PREPARED_NOT_APPLY_READY' and receipt.get('privateDeclarationHash')==expected['declarationHash'] and receipt.get('creationRequestHash')==expected['requestHash'] and receipt.get('creationPlanHash')==expected['planHash'],'EXACT_PREPARED_REVIEW_RECEIPT_REQUIRED')
 require(all(receipt.get(k) is False for k in ('applicationCutoverAuthorized','productionApplyReady','budgetReset','r12Touched','newApplicationTransitionClaimCreated','newTransportClosureProven','completeRealizedOciProven')),'REVIEW_RECEIPT_MUST_NOT_GRANT_AUTHORITY')
 binding=decl.get('nativeImageBinding',{});proof=observation.get('imageProof',{});journal=observation.get('importJournal',{})
 require(binding.get('nativeEngineImageId')==proof.get('nativeEngineImageId')==expected['imageId'] and binding.get('configImageId')==proof.get('configImageId')==expected['configImageId'] and binding.get('nativeEvidenceHash')==journal.get('nativeEvidenceHash')==digest(proof) and binding.get('importJournalContextHash')==journal.get('contextHash'),'EXACT_BOUND_RECONCILED_REVIEW_PROOF_REQUIRED')
 require(journal.get('state')=='VERIFIED' and journal.get('version')==2 and journal.get('effectAttemptCount')==1 and journal.get('automaticReplayAllowed') is False and proof.get('imageByteCustodyProven') is True and proof.get('completeContainerOciProven') is False and proof.get('transportClosureProven') is False and proof.get('targetApplyAuthorized') is False,'EXACT_RETAINED_REVIEW_IMPORT_HISTORY_REQUIRED')
 return values

def main():
 report={'schema':'ouf.native-v11-atomic-review-publication.v1','protectedFileWrites':0,'applicationCutoverAuthorized':False,'productionApplyReady':False,'runtimeAuthorityIssued':False,'budgetReset':False,'r12Touched':False,'newApplicationTransitionClaimCreated':False,'privateKeysRead':0,'signaturesIssued':0,'imageImports':0,'importJournalWrites':0,'databaseQueries':0,'databaseWrites':0,'containerLifecycleOperations':0,'providerCalls':0,'dnsQueries':0,'firewallWrites':0,'privateValuesPrinted':False,'observationsAreHistorical':True,'notReleaseAcceptance':True}
 phase='VERIFY_PREPARED_SOURCE_AND_COMPLETE_REVIEW_BYTES'
 try:
  require(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode and len(sys.argv)==1,'ISOLATED_ROOT_ATOMIC_REVIEW_REQUIRED')
  m=modules(globals().get('__intake_sources__'));atomic,custody=m['atomic'],m['custody']
  files={n:custody.file_bytes(SOURCE/n,0,{0o600}) for n in NAMES};validate(files)
  source_hash=globals().get('__sealed_program_sha__')
  require(type(source_hash) is str and re.fullmatch('[0-9a-f]{64}',source_hash),'SEALED_REVIEW_PROGRAM_HASH_REQUIRED')
  manifest={'schema':'ouf.native-v11-atomic-review-intake.v1','sourceDirectory':str(SOURCE),'fileHashes':{n:sha(raw) for n,raw in files.items()},'sourceHashes':{'program':source_hash,**HASHES},'preparedBindings':EXPECTED,'applicationCutoverAuthorized':False,'productionApplyReady':False,'runtimeAuthorityIssued':False,'observationsAreHistorical':True,'notReleaseAcceptance':True}
  require(all(custody.file_bytes(SOURCE/n,0,{0o600})==raw for n,raw in files.items()),'SOURCE_REVIEW_CHANGED_BEFORE_PUBLICATION')
  phase='ATOMIC_COMPLETE_REVIEW_PUBLICATION_NO_APPLICATION_APPLY'
  def checkpoint(point):
   if point.startswith('AFTER_FILE_'):report['protectedFileWrites']+=1
  result=atomic.publish(BASE,files,manifest,0,checkpoint);report.update(result)
  require(all(custody.file_bytes(SOURCE/n,0,{0o600})==raw for n,raw in files.items()),'SOURCE_REVIEW_CHANGED_DURING_PUBLICATION')
  report['status']='COMPLETE_NATIVE_V11_REVIEW_INTAKE_PUBLISHED_NOT_RUNTIME_AUTHORITY';code=0
 except Exception as e:
  reason=str(e);report.update(status='NATIVE_V11_REVIEW_INTAKE_BLOCKED',phase=phase,reason=reason if re.fullmatch('[A-Z][A-Z0-9_]{0,120}',reason) else 'NATIVE_REVIEW_INTAKE_UNPROVEN');code=1
 print('OUF_NATIVE_V11_REVIEW_INTAKE='+json.dumps(report,sort_keys=True));return code
if __name__=='__main__':raise SystemExit(main())
