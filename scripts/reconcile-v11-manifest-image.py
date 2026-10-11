"""Operator reconciliation of the existing V11 import, never an import entry.

Original config digest and native manifest digest stay distinct. Authenticate
original intent; close existing consumed journal only with exact byte-derived
manifest plus two stable native reads. No new plan or application authority.
"""
import hashlib,json,os,re,shutil,stat,sys,tempfile,types,zipfile
from pathlib import Path
HASHES={
 'original_program':'34e96bdd52bca79f25a4ef75d34b667f0f6693c5607e4a9b9551769dcaf4d3ed',
 'custody':'cb9ff64684243d563da79d327eb7d7e325dbea6a3922c91a0b7791a3ceec9baf',
 'audit':'d118924b52618f00871ccd4ae9ade379ccb818ce517e34e31d815fe5abdfdd23',
 'importer':'f893be75b8b9ca3eececdc60244d7a5963ba5ee95e9f8c3516db4d3608ad1272',
 'journal':'43a293ab9b4075401cfc139a6531f30fdae7277cbe096f10c0d460cd26ed291d',
 'engine':'b60db967a0f921b798617c6e1d5ed713b61d0384d5993b2302751315ee6f8392',
 'manifest':'b8fad73953aaf44209b3a1b50209fde6198d39926d2aa46cb3995313f9c05f7a'}
EXPECTED={'mediaType':'application/vnd.docker.distribution.manifest.v2+json',
 'digest':'sha256:bd48ab35db0441b1f4f48422e7190adaff176a61cddde5f981d93e496ad4b24a','size':1845}
def require(ok,why):
 if not ok:raise ValueError(why)
def modules(sources):
 require(type(sources) is dict and set(sources)==set(HASHES),'EXACT_MANIFEST_RECONCILIATION_SOURCE_SET_REQUIRED')
 for name,h in HASHES.items():
  require(type(sources[name]) is bytes and len(sources[name])<=131072 and hashlib.sha256(sources[name]).hexdigest()==h,'MANIFEST_RECONCILIATION_SOURCE_HASH_MISMATCH')
 old=types.ModuleType('sealed_original_import')
 exec(compile(sources['original_program'],'sealed-original-import','exec'),old.__dict__)
 original=old.modules({k:sources[k] for k in old.SOURCE_HASHES})
 manifest=types.ModuleType('sealed_manifest_identity')
 exec(compile(sources['manifest'],'sealed-manifest-identity','exec'),manifest.__dict__)
 return old,original,manifest

def main():
 os.umask(0o077)
 report={'schema':'ouf.operator-v11-manifest-image-reconciliation.v1','imageImports':0,
  'containerLifecycleOperations':0,'databaseQueries':0,'databaseWrites':0,'dnsQueries':0,'providerCalls':0,
  'firewallWrites':0,'budgetReset':False,'journalInitialized':False,'r12Touched':False,'signaturesIssued':0,
  'privateValuesPrinted':False,'commonLeaseLockAcquired':False,'productionApplyReady':False,
  'applicationCutoverAuthorized':False,'completeRealizedOciProven':False,'newTransportClosureProven':False,
  'newApplicationTransitionClaimCreated':False,'newCandidateImageCustodyProven':False,'notReleaseAcceptance':True}
 phase='VERIFY_ORIGINAL_CONTEXT_AND_NEW_SEALED_RECONCILER'
 try:
  require(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode and len(sys.argv)==1,'ISOLATED_ROOT_RECONCILIATION_REQUIRED')
  old,m,manifest=modules(globals().get('__manifest_reconciliation_sources__'))
  custody,audit,importer,journal,engine=(m[k] for k in ('custody','audit','importer','journal','engine'))
  old.plan(custody)
  require(os.path.lexists(old.DIRECTORY),'EXISTING_IMPORT_JOURNAL_REQUIRED_NO_INITIALIZATION')
  raw=custody.file_bytes(old.BASE/'semantic-finite-lease-recovery-r10-nw9ue4d5'/'reader.py',0,{0o600},expected='4ddfda694150771fc8059ce22080a44c1d42db80c4f85b6b42f85c46442536d2')
  retained=types.ModuleType('sealed_retained_binding');retained.__file__=str(old.BASE/'semantic-finite-lease-recovery-r10-nw9ue4d5'/'reader.py')
  exec(compile(raw,'sealed-retained-binding','exec'),retained.__dict__)
  binding_context=retained.parse(retained.private(retained.CONTEXT/'human-approval-binding.json'))
  cfg=retained.parse(retained.private(retained.CONTEXT/'execution-configuration.json',binding_context['configurationHash']))
  binding=cfg['commandBindings']['docker'];retained.private(binding['path'],binding['sha256'],executable=True)
  # Only command custody is reused; old activation approval grants no transition.
  phase='DERIVE_NATIVE_MANIFEST_FROM_ORIGINAL_SIGNED_BYTES'
  capacity=os.statvfs(old.BASE);require(capacity.f_bavail*capacity.f_frsize>=10*1024**3,'IMAGE_IMPORT_CONTROL_DISK_RESERVE_REQUIRED')
  with tempfile.TemporaryFile() as copied,tempfile.TemporaryFile() as original,tempfile.TemporaryFile() as tagless:
   with os.fdopen(os.open(old.ZIP,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as stream:
    info=os.fstat(stream.fileno());require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size<=audit.LIMIT,'BOUNDED_ORIGINAL_ZIP_REQUIRED')
    old.bounded_copy(stream,copied,audit.LIMIT);end=os.fstat(stream.fileno())
    require((info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)==(end.st_dev,end.st_ino,end.st_size,end.st_mtime_ns,end.st_ctime_ns),'ORIGINAL_ZIP_CHANGED_DURING_COPY')
   copied.seek(0);require(audit.hashed(copied,audit.LIMIT)[0]==old.ZIP_SHA,'EXACT_ORIGINAL_SIGNED_ZIP_REQUIRED');copied.seek(0)
   with zipfile.ZipFile(copied) as package:
    names=package.namelist();require(len(names)==len(set(names)) and len(names)<=256,'UNIQUE_BOUNDED_PACKAGE_REQUIRED')
    rows=[x for x in package.infolist() if Path(x.filename).name=='image.docker.tar']
    require(len(rows)==1 and 0<rows[0].file_size<=audit.LIMIT,'EXACT_ORIGINAL_IMAGE_TAR_REQUIRED')
    with package.open(rows[0]) as source:old.bounded_copy(source,original,audit.LIMIT)
   original_audit=audit.archive(original,old.TAR_SHA,old.IMAGE,old.SOURCE)
   envelope=audit.tagless_archive(original,tagless,original_audit)
   require(envelope['derivedArchiveSha256']==old.TAGLESS_SHA,'EXACT_QUALIFIED_TAGLESS_ENVELOPE_REQUIRED')
   current=audit.archive(tagless,old.TAGLESS_SHA,old.IMAGE,old.SOURCE)
   require(current['repositoryTags']==[],'TAGLESS_IMAGE_IMPORT_REQUIRED')
   descriptor=manifest.descriptor(tagless,current);require(descriptor==EXPECTED,'EXACT_NATIVE_MANIFEST_DERIVATION_REQUIRED')
   sock=Path('/var/run/docker.sock');s=sock.stat(follow_symlinks=False)
   client=engine.Engine(str(sock),(s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)))
   def inspect(image):
    require(image==EXPECTED['digest'],'EXACT_NATIVE_MANIFEST_QUERY_REQUIRED')
    status,value=client.request('GET','/v1.56/images/'+image+'/json?manifests=true')
    require(status in (200,404),'IMAGE_INSPECTION_OUTCOME_UNPROVEN')
    return value if status==200 else None
   # Reconstruct the ORIGINAL consumed context, never a new import authority.
   original_authority=audit.digest({'scope':'OPERATOR_ROOT_OFFLINE_IMAGE_IMPORT_ONLY','declarationHash':old.DECL,
    'requestHash':old.REQUEST,'originalZipSha256':old.ZIP_SHA,'originalArchiveSha256':old.TAR_SHA,
    'derivedArchiveSha256':old.TAGLESS_SHA,'sourceHashes':old.SOURCE_HASHES})
   initial=importer.Import.initial(current,original_authority)
   record=journal.Journal(old.DIRECTORY);session=importer.Import(record,initial['contextHash'])
   def checkpoint(name):
    old.plan(custody);retained.private(binding['path'],binding['sha256'],executable=True);client.check_socket()
    return original_authority
   phase='RECONCILE_EXISTING_CONSUMED_IMPORT_NO_LOAD_CALLBACK'
   with session.invocation():
    before=session.read(current)
    proof=manifest.reconcile_existing(session,current,descriptor,inspect,checkpoint)
    final=session.read(current)
   report.update(status='EXACT_V11_NATIVE_MANIFEST_IMAGE_CUSTODY_RECONCILED_NO_APPLY',newCandidateImageCustodyProven=True,
    configImageId=old.IMAGE,nativeEngineImageId=EXPECTED['digest'],manifestDescriptor=descriptor,
    originalZipSha256=old.ZIP_SHA,originalArchiveSha256=old.TAR_SHA,derivedArchiveSha256=old.TAGLESS_SHA,
    sourceCommit=old.SOURCE,journalDirectory=str(old.DIRECTORY),journalState=final['state'],
    journalVersion=final['version'],protectedJournalWrites=final['version']-before['version'],
    cumulativeImportEffectAttemptCount=final['effectAttemptCount'],originalContextPreserved=True,
    nativeConfigProjectionHash=proof['nativeConfigProjectionHash'],nativeRootfsHash=proof['nativeRootfsHash'],
    rootfsLayerCount=proof['rootfsLayerCount'],imageRebuilt=False,creationRequestNeedsNativeIdentityRebase=True)
   code=0
 except Exception as e:
  reason=str(e);report.update(status='V11_NATIVE_MANIFEST_RECONCILIATION_BLOCKED',phase=phase,
   reason=reason if re.fullmatch('[A-Z][A-Z0-9_]{0,120}',reason) else 'V11_NATIVE_MANIFEST_RECONCILIATION_UNPROVEN');code=1
 print('OUF_V11_MANIFEST_IMAGE_RECONCILIATION='+json.dumps(report,sort_keys=True));return code
if __name__=='__main__':raise SystemExit(main())
