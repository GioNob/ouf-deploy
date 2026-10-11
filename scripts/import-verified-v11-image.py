"""Operator root offline image custody only. No application/container transition.

New private import journal; prior R12 authority is NOT used. The operator invokes
this exact image-only effect; source/config/layer authenticity binds fixed
original publisher bytes and the independently qualified tagless envelope.
"""
import hashlib,json,os,re,shutil,stat,subprocess,sys,tempfile,types,zipfile
from pathlib import Path
SOURCE_HASHES={
 'custody':'cb9ff64684243d563da79d327eb7d7e325dbea6a3922c91a0b7791a3ceec9baf',
 'audit':'d118924b52618f00871ccd4ae9ade379ccb818ce517e34e31d815fe5abdfdd23',
 'importer':'f893be75b8b9ca3eececdc60244d7a5963ba5ee95e9f8c3516db4d3608ad1272',
 'journal':'43a293ab9b4075401cfc139a6531f30fdae7277cbe096f10c0d460cd26ed291d',
 'engine':'b60db967a0f921b798617c6e1d5ed713b61d0384d5993b2302751315ee6f8392'}
BASE=Path('/etc/ouf/deploy-snapshots')
PLAN=BASE/'semantic-durable-v11-plan-2yliy8_t'
DECL='ffc02da66a08fb1f1b06c143ef0f2aa18d68a6fb7b2bfaa616a812aa37eabe0f'
REQUEST='798de748a4fcc0d8c2b6eb70f3577430d690729a4a03bc00ebbf3adcae765836'
ZIP=Path('/home/oufadmin/ouf-durable-v11-stage.drTnFl4m/semantic.zip')
ZIP_SHA='b6ae1051cee4ec9fb1b28f532622ecd39e038ec2e6a384d50565cbf92f2a0def'
TAR_SHA='e0e51617f847494f3bf8a746277da02761aeb81b37d1483ec26dc8e4e35fbd00'
TAGLESS_SHA='52baabdfd39189c598a9ded3aeec08367d20ae2fccbf14330481c98f1ad7783f'
IMAGE='sha256:83635be46d1fe61dea08597ea4488980b4349e5f6e0ed8bbd3ab6f5e2686370e'
SOURCE='8a2e84b32d4ce2bdc3bc529b56afb5663ab133e3'
DIRECTORY=BASE/'semantic-v11-image-import-ffc02da66a08'

def require(ok,why):
 if not ok:raise ValueError(why)

def modules(sources):
 require(type(sources) is dict and set(sources)==set(SOURCE_HASHES),'EXACT_IMAGE_IMPORT_SOURCE_CLOSURE_REQUIRED')
 for k,h in SOURCE_HASHES.items():
  require(type(sources[k]) is bytes and len(sources[k])<=131072 and hashlib.sha256(sources[k]).hexdigest()==h,'IMAGE_IMPORT_SOURCE_HASH_MISMATCH')
 result={}
 for name in ('custody','audit','importer','journal','engine'):
  m=types.ModuleType('sealed_image_'+name)
  if name=='audit':sys.modules['image_custody']=m
  exec(compile(sources[name],'sealed-image-'+name,'exec'),m.__dict__);result[name]=m
 return result

def plan(custody):
 declaration=json.loads(custody.file_bytes(PLAN/'private-runtime-declaration.json',0,{0o600},expected=DECL))
 request=json.loads(custody.file_bytes(PLAN/'creation-request.private.json',0,{0o600},expected=REQUEST))
 require(declaration['candidateImageId']==IMAGE and request['Image']==IMAGE
         and all(declaration[k] is False for k in ('productionApplyReady','applicationCutoverAuthorized','completeReplacementOciProven')),'EXACT_UNAPPLIED_V11_PLAN_REQUIRED')

def bounded_copy(source,destination,limit):
 total=0
 while True:
  raw=source.read(min(1048576,limit-total+1))
  if not raw:return total
  total+=len(raw);require(total<=limit,'BOUNDED_ORIGINAL_COPY_REQUIRED');destination.write(raw)

def main():
 os.umask(0o077)
 report={'schema':'ouf.operator-v11-offline-image-import.v1','productionApplyReady':False,
  'applicationCutoverAuthorized':False,'completeRealizedOciProven':False,'newTransportClosureProven':False,
  'newApplicationTransitionClaimCreated':False,'budgetReset':False,'r12Touched':False,
  'commonLeaseLockAcquired':False,'containerLifecycleOperations':0,'databaseQueries':0,'databaseWrites':0,
  'firewallWrites':0,'providerCalls':0,'dnsQueries':0,'signaturesIssued':0,'privateValuesPrinted':False,
  'imageImportAttemptsThisInvocation':0,'newCandidateImageCustodyProven':False,'notReleaseAcceptance':True}
 phase='VERIFY_SEALED_SOURCE_AND_PRIVATE_PLAN'
 try:
  require(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode and len(sys.argv)==1,'ISOLATED_ROOT_IMAGE_IMPORT_ENTRY_REQUIRED')
  m=modules(globals().get('__image_import_sources__'));custody,audit,importer,journal,engine=(m[k] for k in ('custody','audit','importer','journal','engine'))
  plan(custody)
  # Reuse ONLY the retained hash-bound Docker executable metadata. Its old
  # activation approval is not permission for any new application transition.
  r10=BASE/'semantic-finite-lease-recovery-r10-nw9ue4d5'
  raw=custody.file_bytes(r10/'reader.py',0,{0o600},expected='4ddfda694150771fc8059ce22080a44c1d42db80c4f85b6b42f85c46442536d2')
  retained=types.ModuleType('sealed_import_command_custody');retained.__file__=str(r10/'reader.py')
  exec(compile(raw,'sealed-import-command-custody','exec'),retained.__dict__)
  old=retained.parse(retained.private(retained.CONTEXT/'human-approval-binding.json'))
  cfg=retained.parse(retained.private(retained.CONTEXT/'execution-configuration.json',old['configurationHash']))
  binding=cfg['commandBindings']['docker'];retained.private(binding['path'],binding['sha256'],executable=True)
  phase='VERIFY_ORIGINAL_ARCHIVE_AND_TAGLESS_LAYER_CUSTODY'
  capacity=os.statvfs(BASE);require(capacity.f_bavail*capacity.f_frsize>=10*1024**3,'IMAGE_IMPORT_CONTROL_DISK_RESERVE_REQUIRED')
  # Anonymous immutable-to-other-users copy avoids a pathname race at import.
  with tempfile.TemporaryFile() as copied,tempfile.TemporaryFile() as original,tempfile.TemporaryFile() as tagless:
   fd=os.open(ZIP,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
   with os.fdopen(fd,'rb') as stream:
    info=os.fstat(stream.fileno());require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size<=2147483648,'BOUNDED_ORIGINAL_ZIP_REQUIRED')
    bounded_copy(stream,copied,2147483648)
    end=os.fstat(stream.fileno())
    require((info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)==(end.st_dev,end.st_ino,end.st_size,end.st_mtime_ns,end.st_ctime_ns),'ORIGINAL_ZIP_CHANGED_DURING_COPY')
   copied.seek(0);require(audit.hashed(copied,audit.LIMIT)[0]==ZIP_SHA,'EXACT_ORIGINAL_SIGNED_ZIP_REQUIRED');copied.seek(0)
   with zipfile.ZipFile(copied) as package:
    names=package.namelist();require(len(names)==len(set(names)) and len(names)<=256,'UNIQUE_BOUNDED_PACKAGE_REQUIRED')
    rows=[x for x in package.infolist() if Path(x.filename).name=='image.docker.tar']
    require(len(rows)==1 and 0<rows[0].file_size<=audit.LIMIT,'EXACT_ORIGINAL_IMAGE_TAR_REQUIRED')
    with package.open(rows[0]) as source:shutil.copyfileobj(source,original,1048576)
   original.seek(0);original_audit=audit.archive(original,TAR_SHA,IMAGE,SOURCE)
   envelope=audit.tagless_archive(original,tagless,original_audit)
   require(envelope['derivedArchiveSha256']==TAGLESS_SHA,'EXACT_QUALIFIED_TAGLESS_ENVELOPE_REQUIRED')
   current_audit=audit.archive(tagless,TAGLESS_SHA,IMAGE,SOURCE)
   require(current_audit['repositoryTags']==[],'TAGLESS_IMAGE_IMPORT_REQUIRED')
   socket=Path('/var/run/docker.sock');s=socket.stat(follow_symlinks=False)
   client=engine.Engine(str(socket),(s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)))
   def inspect(image):
    status,value=client.request('GET','/v1.44/images/'+image+'/json')
    require(status in (200,404),'IMAGE_INSPECTION_OUTCOME_UNPROVEN')
    return value if status==200 else None
   authority=audit.digest({'scope':'OPERATOR_ROOT_OFFLINE_IMAGE_IMPORT_ONLY','declarationHash':DECL,
    'requestHash':REQUEST,'originalZipSha256':ZIP_SHA,'originalArchiveSha256':TAR_SHA,
    'derivedArchiveSha256':TAGLESS_SHA,'sourceHashes':SOURCE_HASHES})
   phase='OPEN_DISTINCT_PRIVATE_IMPORT_JOURNAL'
   fresh=not os.path.lexists(DIRECTORY)
   if fresh:DIRECTORY.mkdir(mode=0o700)
   record=journal.Journal(DIRECTORY);initial=importer.Import.initial(current_audit,authority)
   if fresh:record.initialize(initial)
   session=importer.Import(record,initial['contextHash'])
   def checkpoint(name):
    plan(custody);retained.private(binding['path'],binding['sha256'],executable=True);client.check_socket()
    return authority
   def load():
    report['imageImportAttemptsThisInvocation']+=1;tagless.seek(0)
    with tempfile.TemporaryDirectory(dir=DIRECTORY,prefix='empty-docker-cli-') as empty:
     completed=subprocess.run([binding['path'],'--config',empty,'image','load'],stdin=tagless,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
      timeout=120,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','DOCKER_HOST':'unix:///var/run/docker.sock'})
     require(completed.returncode==0 and len(completed.stdout)<=2097152,'IMAGE_IMPORT_OUTCOME_REQUIRES_RECONCILIATION')
   phase='IMPORT_OR_RECONCILE_EXACT_IMAGE_NO_CONTAINER_EFFECT'
   with session.invocation():
    row=session.read(current_audit)
    if row['state']=='READY':proof=session.import_once(current_audit,load,inspect,checkpoint)
    elif row['state']=='IN_FLIGHT':proof=session.reconcile(current_audit,inspect,checkpoint)
    else:
     checkpoint('VERIFY_ALREADY_RECONCILED_IMAGE');observed=inspect(IMAGE);proof=audit.loaded(current_audit,observed)
     require(inspect(IMAGE)==observed,'VERIFIED_IMAGE_CHANGED_DURING_READ');checkpoint('AFTER_VERIFIED_IMAGE_READ')
    final=session.read(current_audit)
   report.update(status='EXACT_V11_IMAGE_CUSTODY_VERIFIED_NO_APPLICATION_APPLY',newCandidateImageCustodyProven=True,
    imageId=IMAGE,sourceCommit=SOURCE,originalZipSha256=ZIP_SHA,originalArchiveSha256=TAR_SHA,
    derivedArchiveSha256=TAGLESS_SHA,repositoryTagCount=0,rootfsLayerCount=len(current_audit['layers']),
    nativeRootfsHash=proof['nativeRootfsHash'],nativeConfigProjectionHash=proof['nativeConfigProjectionHash'],
    journalDirectory=str(DIRECTORY),journalState=final['state'],cumulativeImportEffectAttemptCount=final['effectAttemptCount'],
    imageRebuilt=False,originalPublisherDigestBindingVerified=True,privateDeclarationHash=DECL,creationRequestHash=REQUEST)
   code=0
 except Exception as error:
  reason=str(error);report.update(status='V11_IMAGE_IMPORT_BLOCKED_OR_RECONCILE_REQUIRED',phase=phase,
   reason=reason if re.fullmatch('[A-Z][A-Z0-9_]{0,120}',reason) else 'V11_IMAGE_IMPORT_UNPROVEN')
  code=1
 print('OUF_V11_IMAGE_IMPORT='+json.dumps(report,sort_keys=True));return code
if __name__=='__main__':raise SystemExit(main())
