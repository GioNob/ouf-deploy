"""Exact candidate bytes and installed SQL resources; no image import or database calls."""
import gzip,hashlib,io,os,tarfile,tempfile,zipfile
from pathlib import Path,PurePosixPath
MAX=268435456

def require(ok,code):
 if not ok:raise ValueError(code)
def sha(v):return hashlib.sha256(v).hexdigest()
def jar_inventory(raw,metadata,candidate):
 require(0<len(raw)<=MAX,'BOUNDED_COMPLETE_APPLICATION_JAR_REQUIRED')
 with zipfile.ZipFile(io.BytesIO(raw))as z:
  infos=z.infolist();require(len(infos)<=20000 and len({i.filename for i in infos})==len(infos),'UNIQUE_BOUNDED_JAR_INDEX_REQUIRED')
  selected={i.filename:i for i in infos if i.filename.startswith('BOOT-INF/classes/db/migration/')and not i.is_dir()}
  expected={'BOOT-INF/classes/db/migration/'+n:h for n,h in metadata['migrationInventory'].items()}
  require(set(selected)==set(expected),'EXACT_INSTALLED_AND_CANDIDATE_MIGRATION_SETS_REQUIRED')
  for name,item in selected.items():
   require(not item.flag_bits&1 and 0<item.file_size<=1048576,'BOUNDED_SQL_RESOURCE_REQUIRED')
   require(sha(z.read(item))==expected[name],'EXACT_UNCHANGED_INSTALLED_SQL_BYTES_REQUIRED')
  for name,wanted in metadata['applicationClasses'].items():
   if not candidate and name not in('IngestionIamSecurityConfiguration','IngestionIamDisabledConfiguration'):continue
   item=z.getinfo('BOOT-INF/classes/it/comune/trieste/ouf/ingestion/'+name+'.class')
   require(not item.flag_bits&1 and 0<item.file_size<=2097152 and sha(z.read(item))==wanted,'EXACT_QUALIFIED_APPLICATION_CLASS_BYTES_REQUIRED')
 return {'jarSha256':sha(raw),'migrationFileCount':len(expected),'migrationFilesUnchanged':True,'candidateClassesVerified':candidate}

def rootfs_jar(stream,audit):
 stream.seek(0);found=None;count=0
 with tarfile.open(fileobj=stream,mode='r:')as outer:
  for layer in audit['layerMembers']:
   with outer.extractfile(outer.getmember(layer))as content,tarfile.open(fileobj=content,mode='r|*')as inner:
    for item in inner:
     count+=1;require(count<=250000,'BOUNDED_LAYER_ENTRY_SET_REQUIRED');name=item.name.removeprefix('./').rstrip('/')
     require(not name.startswith('/')and '..'not in PurePosixPath(name).parts,'SAFE_ROOTFS_MEMBER_REQUIRED')
     if name in('.wh.app','.wh..wh..opq','app/.wh.app.jar','app/.wh..wh..opq'):found=None
     if name=='app':require(item.isdir(),'APP_DIRECTORY_LINK_OR_SPECIAL_DENIED')
     if name=='app/app.jar':
      require(item.isfile()and not item.islnk()and not item.issym()and 0<item.size<=MAX,'REGULAR_BOUNDED_FINAL_APP_JAR_REQUIRED')
      with inner.extractfile(item)as f:found=f.read(MAX+1)
      require(len(found)==item.size,'COMPLETE_IMAGE_APP_JAR_REQUIRED')
 require(found is not None,'FINAL_IMAGE_APP_JAR_REQUIRED');return found

def candidate_audit(path,context,metadata,image_custody):
 # Input gzip SHA/custody is already sealed by the draft compiler. Recheck the
 # compressed stream's digest via the same open file before decompressing it.
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  before=os.fstat(fd);pin=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  require(before.st_size==metadata['imageArchiveBytes'],'EXACT_COMPRESSED_IMAGE_SIZE_REQUIRED')
  with os.fdopen(os.dup(fd),'rb')as source:
   require(image_custody.hashed(source,536870912)[0]==metadata['imageArchiveSha256'],'EXACT_COMPRESSED_IMAGE_DIGEST_REQUIRED')
   source.seek(0)
   with tempfile.TemporaryFile(dir=context)as expanded,gzip.GzipFile(fileobj=source)as compressed:
    size=0;h=hashlib.sha256()
    for raw in iter(lambda:compressed.read(1048576),b''):
     size+=len(raw);require(size<=image_custody.LIMIT,'BOUNDED_EXPANDED_CANDIDATE_REQUIRED');h.update(raw);expanded.write(raw)
    expanded.flush();expanded.seek(0)
    audit=image_custody.archive(expanded,h.hexdigest(),metadata['imageId'],metadata['sourceCommit'])
    require(audit['imageConfig'].get('User')==metadata['imageUser']and audit['imageConfig'].get('Entrypoint')==metadata['imageEntrypoint'],'EXACT_CANDIDATE_EXECUTION_IDENTITY_REQUIRED')
    raw=rootfs_jar(expanded,audit);require(sha(raw)==metadata['applicationJarSha256'],'EXACT_CI_AND_ROOTFS_APPLICATION_JAR_REQUIRED')
    proof=jar_inventory(raw,metadata,True)
  require(pin(before)==pin(os.fstat(fd))==pin(Path(path).lstat()),'CANDIDATE_READ_DRIFT')
 finally:os.close(fd)
 return {'imageAudit':audit,'candidateJar':proof,'candidateImageImported':False}

def run(base,jar_reader,image_custody,inputs,context):
 old,completed,_=base.history();expected={**inputs['runtimeBindings'],'mcp':completed['finalEvidence']['mcp']['runtimeBinding']}
 reader=base.Reader(old['engine'],[v['containerId']for v in expected.values()]);actual={}
 def inspect(name):
  row=reader.get('/v1.44/containers/'+expected[name]['containerId']+'/json')
  ordered=name!='gateway'or old['gateway']['transport'].get('runtimeBindingProfile')=='ouf.apisix-runtime-binding.mount-set.v1'
  require(base.runtime(row,ordered)==expected[name],'CURRENT_INSTALLATION_GENERATION_DRIFT');return row
 for name in expected:actual[name]=inspect(name)
 archive=jar_reader.ArchiveRead(reader,actual['ingestion']);installed=archive.get()
 require(sha(installed)=='58199f4be91c4e99ac4b5fd2ac863303f4154257b88750d095c62409ab8f7630','EXACT_PREVIOUSLY_QUALIFIED_INSTALLED_JAR_REQUIRED')
 installed_proof=jar_inventory(installed,inputs['candidateMetadata'],False)
 candidate=candidate_audit(inputs['candidateImageBinding']['path'],context,inputs['candidateMetadata'],image_custody)
 for name in expected:inspect(name)
 base.private_config(base.ACTIVE_PATH,inputs['publishedProjectionBinding'])
 return {**candidate,'installedJar':installed_proof,'currentRuntimeGenerationsVerified':True,
  'engineGetRequests':reader.calls,'engineArchiveGetRequests':archive.calls,
  'databaseAdmissionProven':False,'databaseCalls':0,'runtimeAuthorityIssued':False}
