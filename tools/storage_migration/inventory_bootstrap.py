"""Template for a hash-bound, single-attempt private inventory delivery.

No service lifecycle, object bodies, S3 writes or credential handling here.
The publisher replaces DELIVERY and PUBLICATION with verified immutable data.
"""
import gzip,hashlib,json,os,re,shutil,signal,stat,struct,subprocess,sys,tempfile,time,urllib.request
from pathlib import Path
DELIVERY=None
PUBLICATION=None
INSTALL=Path('/usr/local/lib/ouf-storage-inventory-20261102')
SCOPE=Path('/etc/ouf/deploy-snapshots/seaweedfs-inventory-20261102-v1')

def require(ok,code):
 if not ok:raise ValueError(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def ancestry(path):
 for p in [path,*path.parents]:
  s=p.lstat();require(stat.S_ISDIR(s.st_mode) and s.st_uid==s.st_gid==0 and not s.st_mode&0o022,'ROOT_PROTECTED_ANCESTRY_REQUIRED')
def checked(raw,size,digest):
 require(len(raw)==size and sha(raw)==digest,'EXACT_DELIVERY_BYTES_REQUIRED');return raw
def executable(raw):
 require(len(raw)>=64 and raw[:7]==b'\x7fELF\x02\x01\x01' and struct.unpack_from('<H',raw,18)[0]==62,'LINUX_AMD64_ELF_REQUIRED')
 offset=struct.unpack_from('<Q',raw,32)[0];size,count=struct.unpack_from('<HH',raw,54)
 require(size>=56 and count<=256 and offset+size*count<=len(raw),'BOUNDED_ELF_HEADERS_REQUIRED')
 require(all(struct.unpack_from('<I',raw,offset+i*size)[0]!=3 for i in range(count)),'STATIC_NO_INTERPRETER_BACKEND_REQUIRED')
def validate_delivery():
 require(type(DELIVERY) is dict and re.fullmatch('[a-f0-9]{40}',str(PUBLICATION)),'PINNED_DELIVERY_REQUIRED')
 require(DELIVERY['backendInstallPath']==str(INSTALL/'inventory') and DELIVERY['scopePath']==str(SCOPE),'EXACT_INSTALL_AND_SCOPE_REQUIRED')
 require(DELIVERY['closedSourceCount']==24 and DELIVERY['original23SourcesUnchanged'] is True and DELIVERY['runtimeAuthorityIssued'] is False and DELIVERY['targetApplyAuthorized'] is False,'CLOSED_READ_ONLY_DELIVERY_REQUIRED')
 parts=DELIVERY['parts'];require(0<len(parts)<=64 and 0<DELIVERY['backendBytes']<=33554432 and 0<DELIVERY['compressedBackendBytes']<=16777216,'BOUNDED_DELIVERY_REQUIRED')
 require([p['name'] for p in parts]==['inventory.part%03d'%i for i in range(len(parts))] and all(0<p['bytes']<=196608 and re.fullmatch('[a-f0-9]{64}',p['sha256']) for p in parts),'CLOSED_ORDERED_PARTS_REQUIRED')
 require(sum(p['bytes'] for p in parts)==DELIVERY['compressedBackendBytes'],'COMPLETE_DELIVERY_PARTS_REQUIRED')
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):raise ValueError('DELIVERY_REDIRECT_DENIED')
def fetch(name,limit,until):
 require(re.fullmatch(r'inventory\.part[0-9]{3}|prepare-storage-inventory\.py',name),'CLOSED_DOWNLOAD_NAME_REQUIRED')
 remaining=until-time.monotonic();require(remaining>0,'DELIVERY_TIME_BUDGET')
 url='https://raw.githubusercontent.com/GioNob/ouf-deploy/'+PUBLICATION+'/releases/seaweedfs-inventory-delivery-20261102/'+name
 # Public immutable assets: no proxies, tokens, cookies or cross-host redirects.
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
 with opener.open(url,timeout=min(20,remaining)) as response:
  require(response.status==200,'SUCCESSFUL_DELIVERY_DOWNLOAD_REQUIRED');raw=response.read(limit+1)
 require(0<len(raw)<=limit,'DELIVERY_DOWNLOAD_SIZE_BUDGET');return raw
def assemble(reader):
 packed=b''.join(checked(reader(p['name'],p['bytes']),p['bytes'],p['sha256']) for p in DELIVERY['parts'])
 checked(packed,DELIVERY['compressedBackendBytes'],DELIVERY['compressedBackendSha256'])
 # Limit decompression even if a malformed manifest were accidentally published.
 import io
 with gzip.GzipFile(fileobj=io.BytesIO(packed)) as f:
  binary=f.read(DELIVERY['backendBytes']+1);require(not f.read(1),'BOUNDED_DECOMPRESSION_REQUIRED')
 checked(binary,DELIVERY['backendBytes'],DELIVERY['backendSha256']);executable(binary)
 capsule=reader('prepare-storage-inventory.py',1048576);require(sha(capsule)==DELIVERY['capsuleSha256'],'EXACT_CAPSULE_BYTES_REQUIRED')
 return binary,capsule
def install(binary,capsule):
 ancestry(INSTALL.parent);require(not os.path.lexists(INSTALL),'NEW_READER_INSTALL_REQUIRED')
 temporary=Path(tempfile.mkdtemp(prefix='.ouf-storage-inventory-',dir=INSTALL.parent))
 try:
  for name,raw,mode in [('inventory',binary,0o500),('prepare-storage-inventory.py',capsule,0o400),('delivery.json',(json.dumps(DELIVERY,sort_keys=True)+'\n').encode(),0o400)]:
   fd=os.open(temporary/name,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
   with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fchmod(f.fileno(),mode);os.fsync(f.fileno())
  fd=os.open(temporary,os.O_RDONLY|os.O_DIRECTORY)
  try:os.fsync(fd)
  finally:os.close(fd)
  # Parent is root protected and this destination was checked absent. No resume
  # or merge with an existing installation is supported.
  temporary.chmod(0o500);os.rename(temporary,INSTALL)
  fd=os.open(INSTALL.parent,os.O_RDONLY|os.O_DIRECTORY)
  try:os.fsync(fd)
  finally:os.close(fd)
 finally:
  if temporary.exists():temporary.chmod(0o700);shutil.rmtree(temporary)
def launch():
 child=subprocess.Popen(['/usr/bin/python3','-I','-B','-S',str(INSTALL/'prepare-storage-inventory.py')],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin'},start_new_session=True)
 try:stdout,stderr=child.communicate(timeout=630)
 except subprocess.TimeoutExpired:
  os.killpg(child.pid,signal.SIGKILL);child.communicate();raise ValueError('CONTROL_TIMEOUT_SCOPE_MUST_NOT_BE_REPLAYED')
 require(len(stdout)<=16384 and len(stderr)<=4096,'MINIMIZED_CONTROL_OUTPUT_REQUIRED')
 report=json.loads(stdout);require(type(report) is dict and type(report.get('status')) is str,'TYPED_CONTROL_RECEIPT_REQUIRED')
 return child.returncode,report
def main():
 try:
  validate_delivery()
  if sys.argv[1:]==['--inspect-delivery']:
   print(json.dumps({'status':'PINNED_DELIVERY_INSPECTED','producerSource':DELIVERY['producerSource'],'publication':PUBLICATION,'closedSources':24,'parts':len(DELIVERY['parts']),'targetOperations':0}));return 0
  require(not sys.argv[1:] and os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ROOT_ISOLATED_NO_ARGUMENT_ENTRY_REQUIRED')
  require(os.uname().sysname=='Linux' and os.uname().machine=='x86_64' and hasattr(os,'memfd_create') and Path('/usr/bin/nsenter').is_file(),'LINUX_AMD64_NAMESPACE_AND_MEMFD_REQUIRED')
  os.umask(0o077);ancestry(INSTALL.parent);ancestry(SCOPE.parent)
  require(not os.path.lexists(SCOPE) and not os.path.lexists(INSTALL),'FRESH_MONOUSE_CONTROL_AND_INSTALL_REQUIRED')
  until=time.monotonic()+240;binary,capsule=assemble(lambda n,limit:fetch(n,limit,until));install(binary,capsule)
  code,report=launch();report['inventoryDeliveryProducer']=DELIVERY['producerSource'];report['inventoryDeliveryPublication']=PUBLICATION;print(json.dumps(report,sort_keys=True));return code
 except Exception as error:
  code=str(error) if type(error) is ValueError and re.fullmatch('[A-Z0-9_]{1,128}',str(error)) else 'DELIVERY_STOP_PRIVATE_DETAILS_NOT_PRINTED'
  print(json.dumps({'status':'STORAGE_INVENTORY_DELIVERY_STOP','reasonCode':code,'scopeConsumed':os.path.lexists(SCOPE),'readerInstallPresent':os.path.lexists(INSTALL),'automaticReplayAllowed':False,'targetApplyAuthorized':False}));return 1
if __name__=='__main__':raise SystemExit(main())
