"""New private review plan using the already reconciled native manifest.

No application authority, image import, journal rewrite or R12 effect. Complete
source closure is sealed before exec; old source/provenance and plans retained.
"""
import hashlib,json,os,re,stat,sys,tempfile,types
from pathlib import Path
HASHES={
 'reader':'4d4da44d8ef27f77e00982d978ad8400eb7a0b79997bd468535fc49654b2ac3f',
 'planner':'38bb934fedfcdd38d11fc29ff4d60e75170854686273b7592edcae92fa0d1d28',
 'prepare':'693ec0196a60d3a9f6adee96571947306df4a0cffb449905c3dcf8c09a34da1b',
 'custody':'cb9ff64684243d563da79d327eb7d7e325dbea6a3922c91a0b7791a3ceec9baf',
 'creation':'e018567bbd67504ec00d5cbd830c65adbb2670dd7a627b63b9ae20ffa420d665',
 'original_program':'34e96bdd52bca79f25a4ef75d34b667f0f6693c5607e4a9b9551769dcaf4d3ed',
 'audit':'d118924b52618f00871ccd4ae9ade379ccb818ce517e34e31d815fe5abdfdd23',
 'importer':'f893be75b8b9ca3eececdc60244d7a5963ba5ee95e9f8c3516db4d3608ad1272',
 'journal':'43a293ab9b4075401cfc139a6531f30fdae7277cbe096f10c0d460cd26ed291d',
 'engine':'b60db967a0f921b798617c6e1d5ed713b61d0384d5993b2302751315ee6f8392',
 'rebase':'0f1e559b14a481d6b24ee454ff5f6209c08e959579e5fe4a53697395755b6cdf'}
def require(ok,why):
 if not ok:raise ValueError(why)
def modules(sources):
 require(type(sources) is dict and set(sources)==set(HASHES),'EXACT_NATIVE_PLAN_SOURCE_SET_REQUIRED')
 for name,h in HASHES.items():
  require(type(sources[name]) is bytes and len(sources[name])<=131072 and hashlib.sha256(sources[name]).hexdigest()==h,'NATIVE_PLAN_SOURCE_HASH_MISMATCH')
 out={}
 for name in ('reader','original_program','rebase'):
  value=types.ModuleType('sealed_native_plan_'+name)
  exec(compile(sources[name],'sealed-native-plan-'+name,'exec'),value.__dict__);out[name]=value
 planner,prepare,custody,creation=out['reader'].modules({k:sources[k] for k in ('planner','prepare','custody','creation')})
 out.update(planner=planner,prepare=prepare,custody=custody,creation=creation)
 out.update(out['original_program'].modules({k:sources[k] for k in out['original_program'].SOURCE_HASHES}))
 return out

def stable(before,after):
 require(all(before[k]==after[k] for k in ('workerGenerationHash','authorizationHash','currentSemanticFrameHash','declarationHash'))
  and after['refreshCount']>=before['refreshCount'],'CURRENT_GENERATION_CHANGED_DURING_NATIVE_PLAN')

def main():
 os.umask(0o077)
 report={'schema':'ouf.native-v11-current-private-plan.v1','imageImports':0,'containerLifecycleOperations':0,
  'databaseQueries':0,'databaseWrites':0,'dnsQueries':0,'firewallWrites':0,'providerCalls':0,'signaturesIssued':0,
  'budgetReset':False,'r12Touched':False,'commonLeaseLockAcquired':False,'importJournalWrites':0,
  'newApplicationTransitionClaimCreated':False,'privateValuesPrinted':False,'protectedFileWrites':0,
  'productionApplyReady':False,'applicationCutoverAuthorized':False,'completeRealizedOciProven':False,
  'newTransportClosureProven':False,'notReleaseAcceptance':True,'privateSnapshotPublicationIsAtomic':False}
 phase='VERIFY_COMPLETE_NATIVE_PLAN_SOURCE_CLOSURE'
 try:
  require(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode and len(sys.argv)==1,'ISOLATED_ROOT_NATIVE_PLAN_REQUIRED')
  m=modules(globals().get('__native_plan_sources__'))
  reader,planner,prepare,custody,creation,old,audit,importer,journal,engine,rebase=(m[k] for k in
   ('reader','planner','prepare','custody','creation','original_program','audit','importer','journal','engine','rebase'))
  phase='VERIFY_ORIGINAL_V11_PLAN_AND_RECONCILED_IMPORT_HISTORY'
  old.plan(custody)
  raw_decl=custody.file_bytes(old.PLAN/'private-runtime-declaration.json',0,{0o600},expected=old.DECL)
  raw_request=custody.file_bytes(old.PLAN/'creation-request.private.json',0,{0o600},expected=old.REQUEST)
  declaration,request=json.loads(raw_decl),json.loads(raw_request)
  # A fresh hash of the original ZIP accompanies the shell's eight publisher
  # checks. No re-envelope, load or signature is performed on target.
  with os.fdopen(os.open(old.ZIP,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as stream:
   s=os.fstat(stream.fileno());require(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size<=audit.LIMIT,'BOUNDED_ORIGINAL_ZIP_REQUIRED')
   require(audit.hashed(stream,audit.LIMIT)[0]==old.ZIP_SHA,'EXACT_ORIGINAL_SIGNED_ZIP_REQUIRED')
   end=os.fstat(stream.fileno());require((s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)==(end.st_dev,end.st_ino,end.st_size,end.st_mtime_ns,end.st_ctime_ns),'ORIGINAL_ZIP_CHANGED_DURING_READ')
  authority=audit.digest({'scope':'OPERATOR_ROOT_OFFLINE_IMAGE_IMPORT_ONLY','declarationHash':old.DECL,
   'requestHash':old.REQUEST,'originalZipSha256':old.ZIP_SHA,'originalArchiveSha256':old.TAR_SHA,
   'derivedArchiveSha256':old.TAGLESS_SHA,'sourceHashes':old.SOURCE_HASHES})
  intent={'imageId':old.IMAGE,'sourceCommit':old.SOURCE,'archiveSha256':old.TAGLESS_SHA}
  initial=importer.Import.initial(intent,authority)
  custody.file_bytes(old.DIRECTORY/'recovery.json',0,{0o600})
  session=importer.Import(journal.Journal(old.DIRECTORY),initial['contextHash'])
  imported=session.read(intent)
  sock=Path('/var/run/docker.sock');s=sock.stat(follow_symlinks=False)
  client=engine.Engine(str(sock),(s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)))
  def image_read():
   status,native=client.request('GET','/v1.56/images/'+rebase.NATIVE+'/json?manifests=true')
   require(status==200,'RECONCILED_NATIVE_IMAGE_ABSENT_OR_UNPROVEN')
   proof=rebase.native_proof(native);rebase.verified_record(session.read(intent),proof,initial['contextHash'])
   return native,proof
  observed,proof=image_read();require(image_read()[0]==observed,'NATIVE_IMAGE_CHANGED_DURING_PLAN')
  proposed,new_request=rebase.rebase(declaration,request,imported,proof,initial['contextHash'])
  phase='CURRENT_R12_APPLICATION_AND_INPUT_CUSTODY'
  before=reader.observe(planner,prepare,custody,creation)
  native_raw=custody.file_bytes(prepare.R10/'reader.py',0,{0o600},expected=prepare.PROGRAMS['reader.py'])
  retained=types.ModuleType('sealed_native_plan_retained_reader');retained.__file__=str(prepare.R10/'reader.py')
  exec(compile(native_raw,'sealed-native-plan-retained-reader','exec'),retained.__dict__)
  human=retained.parse(retained.private(retained.CONTEXT/'human-approval-binding.json'))
  cfg=retained.parse(retained.private(retained.CONTEXT/'execution-configuration.json',human['configurationHash']))
  args=['inspect','--type','container',retained.SEMANTIC_ID]
  current=retained.parse(prepare.native(retained,cfg['commandBindings']['docker'],args,True))[0]
  require(creation.digest(prepare.frame(current))==before['currentSemanticFrameHash'],'CURRENT_NATIVE_PLAN_FRAME_DRIFT')
  planner.verify_secret_custody(custody,declaration,current)
  # Recompile both plans with current native host facts, preserving all previously
  # qualified resource/network/mount/config fields. Only Image may change.
  host=planner.current_host(creation,current)
  require(creation.compile_creation(declaration,old.DECL,host)[0]==request,'PREDECESSOR_CREATION_REQUEST_DRIFT')
  new_hash=creation.digest(proposed)
  compiled,public=creation.compile_creation(proposed,new_hash,host)
  require(compiled==new_request,'NATIVE_PLAN_HAS_UNREVIEWED_CREATION_DELTA')
  phase='FINAL_STABLE_NATIVE_IMAGE_JOURNAL_AND_R12_RECHECK'
  after=reader.observe(planner,prepare,custody,creation);stable(before,after)
  require(custody.file_bytes(old.PLAN/'private-runtime-declaration.json',0,{0o600},expected=old.DECL)==raw_decl
   and custody.file_bytes(old.PLAN/'creation-request.private.json',0,{0o600},expected=old.REQUEST)==raw_request,'ORIGINAL_V11_PLAN_CHANGED')
  require(session.read(intent)==imported and image_read()[0]==observed,'RECONCILED_IMAGE_OR_HISTORY_CHANGED')
  final=retained.parse(prepare.native(retained,cfg['commandBindings']['docker'],args,True))[0]
  require(creation.digest(prepare.frame(final))==after['currentSemanticFrameHash'],'FINAL_NATIVE_PLAN_FRAME_DRIFT')
  planner.verify_secret_custody(custody,declaration,final)
  require(creation.compile_creation(proposed,new_hash,planner.current_host(creation,final))[0]==new_request,'FINAL_NATIVE_CREATION_INTENT_DRIFT')
  phase='PUBLISH_NEW_PRIVATE_NATIVE_PLAN_NO_APPLY'
  directory=Path(tempfile.mkdtemp(prefix='semantic-native-v11-plan-',dir=prepare.BASE));directory.chmod(0o700)
  for name,value in (('private-runtime-declaration.json',proposed),('creation-request.private.json',new_request),
   ('observation.private.json',{'custodyBefore':before,'custodyAfter':after,'imageProof':proof,'importJournal':imported,'creationPlan':public})):
   custody.create(directory/name,creation.encoded(value));report['protectedFileWrites']+=1
  report.update(status='CURRENT_NATIVE_V11_DECLARATION_AND_PLAN_PREPARED_NOT_APPLY_READY',
   evidenceDirectory=str(directory),privateDeclarationHash=new_hash,creationRequestHash=creation.digest(new_request),
   creationPlanHash=creation.digest(public),predecessorDeclarationHash=old.DECL,predecessorCreationRequestHash=old.REQUEST,
   candidateImageId=rebase.NATIVE,configImageId=rebase.CONFIG,sourceCommit=rebase.SOURCE,zipSha256=old.ZIP_SHA,
   importJournalState=imported['state'],importJournalVersion=imported['version'],cumulativeImportEffectAttemptCount=1,
   newCandidateImageCustodyProven=True,originalPublisherBindingPreserved=True,onlyCreationImageIdentityChanged=True,
   existingInputFilesReverified=4,workerPid=after['workerPid'],refreshCount=after['refreshCount'],flows=after['flows'],
   currentSemanticFrameHash=after['currentSemanticFrameHash'],workerGenerationHash=after['workerGenerationHash'])
  receipt={**report,'protectedFileWrites':report['protectedFileWrites']+1}
  custody.create(directory/'receipt.json',creation.encoded(receipt));report['protectedFileWrites']+=1;code=0
 except Exception as e:
  reason=str(e);report.update(status='CURRENT_NATIVE_V11_PLAN_BLOCKED',phase=phase,
   reason=reason if re.fullmatch('[A-Z][A-Z0-9_]{0,120}',reason) else 'CURRENT_NATIVE_V11_PLAN_UNPROVEN');code=1
 print('OUF_CURRENT_NATIVE_V11_PLAN='+json.dumps(report,sort_keys=True));return code
if __name__=='__main__':raise SystemExit(main())
