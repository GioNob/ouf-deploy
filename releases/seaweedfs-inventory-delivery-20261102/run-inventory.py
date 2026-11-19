#!/usr/bin/env python3
"""Template for a hash-bound, single-attempt private inventory delivery.

No service lifecycle, object bodies, S3 writes or credential handling here.
The publisher replaces DELIVERY and PUBLICATION with verified immutable data.
"""
import gzip,hashlib,json,os,re,shutil,signal,stat,struct,subprocess,sys,tempfile,time,urllib.request
from pathlib import Path
DELIVERY={'schema': 'ouf.storage-inventory-delivery.v1', 'controlProfile': {'schema': 'ouf.storage-baseline-read-control.v1', 'maximumAttempts': 1, 'maximumSeconds': 600, 'maximumEngineGets': 65, 'maximumContainers': 64, 'maximumEngineResponseBytes': 2097152, 'maximumCredentialSources': 2, 'maximumCredentialBytesEach': 4096, 'maximumS3Requests': 10000, 'maximumPrivateInventoryBytes': 67108864, 'maximumS3Records': 25000, 'maximumS3Seconds': 300, 'backendGoMemoryLimit': '256MiB', 'backendGoMaxProcs': 1, 'objectBodiesRead': 0, 'sqlRequests': 0, 'containerLifecycleOperations': 0, 'runtimeAuthorityIssued': False, 'automaticReplayAllowed': False, 'previousControlAttempts': 12, 'previousEngineGets': 35, 'migrationAuthorized': False}, 'scopePath': '/etc/ouf/deploy-snapshots/seaweedfs-inventory-20261102-v1', 'backendInstallPath': '/usr/local/lib/ouf-storage-inventory-20261102/inventory', 'producerSource': '6cddeee707b67bd27568aa7a3890e28ebecf274f', 'capsuleSha256': '13d0cb759e5b46c4f71fc496cce08ffde9e69d5d6d77a1d83d0ebe18f34e0d78', 'backendSha256': '430631fe4dfd1b844229637373ea176c2e84e81e1491919f4a25cc36c68359a8', 'backendBytes': 9314464, 'compressedBackendSha256': '25a80b05040d1cddb590e834bce321e6f0e592f5e272c986696d1bda4613df7e', 'compressedBackendBytes': 3595172, 'parts': [{'name': 'inventory.part000', 'bytes': 196608, 'sha256': '02da0525d9b6095b143e4f11f382959cdda6779e8118823348b2dd43e7074f93'}, {'name': 'inventory.part001', 'bytes': 196608, 'sha256': '1e3c58a1a955bceff1bdf83843a7c38ede3c74178aa9b9f60675721cec4aceaf'}, {'name': 'inventory.part002', 'bytes': 196608, 'sha256': '6b6070fdf57ebfdea27647ffbd787f547684f94b75814d6fc0d78bbaaae074ae'}, {'name': 'inventory.part003', 'bytes': 196608, 'sha256': 'ab452506463726f080d67de9499b0c63046439346e8f5651c12d92f722d8869b'}, {'name': 'inventory.part004', 'bytes': 196608, 'sha256': 'ae1e50d457bb57043ee11de89c581bc65d1c67c114a4dfb37fad6e611e06927a'}, {'name': 'inventory.part005', 'bytes': 196608, 'sha256': '6b4be5080142ce8da56d9c1b5fa33fe1d0a184bb47a81216854de28c7bb22ee8'}, {'name': 'inventory.part006', 'bytes': 196608, 'sha256': 'fe16f9939cf1731e4a15f72d7a1dd3c75546c4cc0fe1cc2eff29ecf767d06ce1'}, {'name': 'inventory.part007', 'bytes': 196608, 'sha256': 'a814e3bdf0a287cc988dd630705fb0cda8f90e5b154f77ac3aa637f238ecf79a'}, {'name': 'inventory.part008', 'bytes': 196608, 'sha256': '16f2378c9d4fc793e0327f94f195bed9f508b637fca12d4917f81ae32f864f37'}, {'name': 'inventory.part009', 'bytes': 196608, 'sha256': 'cb6258902c5719b0ecc9b0d3750af3810fa5999983391d92deb44ccb94ccbcc5'}, {'name': 'inventory.part010', 'bytes': 196608, 'sha256': '13259d88bf552f70a2e0841aac90bc5f2ff4f8ce12ea77e6aee95afc38d3a88e'}, {'name': 'inventory.part011', 'bytes': 196608, 'sha256': '4399f6dec5955d6137876a37344e73cd88a99830c68570c79edbdbfaecca9869'}, {'name': 'inventory.part012', 'bytes': 196608, 'sha256': '626f95a9db2b70dcaae949a289b7dbf2f0f4c62ee01d8d16dda1796ff83caa43'}, {'name': 'inventory.part013', 'bytes': 196608, 'sha256': '347d62ecefc9a8a6753dd81536e2ad62c86277f2463def0adfb237e3b33ff866'}, {'name': 'inventory.part014', 'bytes': 196608, 'sha256': '5d982262215ddf4ad362997d43933b5b77d5b1cdbc00edb9601c79afc2743eb8'}, {'name': 'inventory.part015', 'bytes': 196608, 'sha256': 'deb13ccaa7d06e7346e1d1d579642e31849a82c40ec7cb5687db7316c6110588'}, {'name': 'inventory.part016', 'bytes': 196608, 'sha256': '533b3f98ba2c119b0ae394fb346925ea9549b498ec9a684d9d2514ab177ed1f6'}, {'name': 'inventory.part017', 'bytes': 196608, 'sha256': '2e93f79dba3531b6bf8a711b603c11ba7c682e5609992fa13016e337a44548d7'}, {'name': 'inventory.part018', 'bytes': 56228, 'sha256': '82343ca45ce9d4536474ded9b75d00c4b1f584fdbb9462d7445dafd59502448d'}], 'closedSourceCount': 24, 'original23SourcesUnchanged': True, 'capsuleTamperDenied': True, 'targetApplyAuthorized': False, 'runtimeAuthorityIssued': False, 'targetExecutionPreparedNotPerformed': True, 'rootCredentialValuesSpooled': False}
PUBLICATION='0f446ddb4a1ed19b2c139bb496d06f84edb6062a'
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
