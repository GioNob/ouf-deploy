"""Hash-bound corrective delivery; reuse the installed SDK and preserve old scopes."""
import hashlib,json,os,re,shutil,signal,stat,subprocess,sys,tempfile,urllib.request
from pathlib import Path
DELIVERY=None
PUBLICATION=None
INSTALL=Path('/usr/local/lib/ouf-storage-inventory-credentials-20261102')
SCOPE=Path('/etc/ouf/deploy-snapshots/seaweedfs-inventory-credentials-20261102-v1')
PREDECESSOR=Path('/etc/ouf/deploy-snapshots/seaweedfs-inventory-reconciliation-20261102-v1')
BACKEND=Path('/usr/local/lib/ouf-storage-inventory-20261102/inventory')
BACKEND_SHA='430631fe4dfd1b844229637373ea176c2e84e81e1491919f4a25cc36c68359a8'
def require(ok,code):
 if not ok:raise ValueError(code)
def ancestry(path):
 for p in [path,*path.parents]:
  s=p.lstat();require(stat.S_ISDIR(s.st_mode) and s.st_uid==s.st_gid==0 and not s.st_mode&0o022,'ROOT_PROTECTED_ANCESTRY_REQUIRED')
def validate():
 require(type(DELIVERY) is dict and re.fullmatch('[a-f0-9]{40}',str(PUBLICATION)),'PINNED_CORRECTIVE_DELIVERY_REQUIRED')
 require(DELIVERY['backendPath']==str(BACKEND) and DELIVERY['backendSha256']==BACKEND_SHA and DELIVERY['installPath']==str(INSTALL) and DELIVERY['scopePath']==str(SCOPE),'EXACT_READER_AND_CORRECTIVE_PATHS_REQUIRED')
 require(DELIVERY['closedSourceCount']==26 and DELIVERY['original23SourcesUnchanged'] and DELIVERY['oldScopeRearmed'] is False and DELIVERY['oldReaderReinstalled'] is False and 0<DELIVERY['capsuleBytes']<=1048576,'CLOSED_NO_REPLAY_CORRECTIVE_DELIVERY_REQUIRED')
def existing_reader():
 ancestry(BACKEND.parent);s=BACKEND.lstat()
 require(stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o500 and s.st_nlink==1 and 0<s.st_size<=33554432,'ORIGINAL_ROOT_READER_CUSTODY_REQUIRED')
 fd=os.open(BACKEND,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as f:
  require(os.fstat(f.fileno())==s,'ORIGINAL_READER_REBOUND');h=hashlib.sha256()
  while raw:=f.read(1048576):h.update(raw)
  require(h.hexdigest()==BACKEND_SHA and os.fstat(f.fileno())==BACKEND.lstat(),'EXACT_ORIGINAL_INSTALLED_READER_REQUIRED')
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**kw):raise ValueError('CORRECTIVE_DELIVERY_REDIRECT_DENIED')
def fetch():
 url='https://raw.githubusercontent.com/GioNob/ouf-deploy/'+PUBLICATION+'/releases/seaweedfs-inventory-credentials-20261102/prepare-credentials.py'
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
 with opener.open(url,timeout=20) as response:
  require(response.status==200,'SUCCESSFUL_CORRECTIVE_DOWNLOAD_REQUIRED');return response.read(DELIVERY['capsuleBytes']+1)
def install(raw):
 require(len(raw)==DELIVERY['capsuleBytes'] and hashlib.sha256(raw).hexdigest()==DELIVERY['capsuleSha256'],'EXACT_CORRECTIVE_CAPSULE_REQUIRED')
 ancestry(INSTALL.parent);require(not os.path.lexists(INSTALL),'NEW_CORRECTIVE_INSTALL_REQUIRED')
 temporary=Path(tempfile.mkdtemp(prefix='.ouf-inventory-correction-',dir=INSTALL.parent))
 try:
  for name,data in [('prepare-credentials.py',raw),('delivery.json',(json.dumps(DELIVERY,sort_keys=True)+'\n').encode())]:
   fd=os.open(temporary/name,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
   with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fchmod(f.fileno(),0o400);os.fsync(f.fileno())
  fd=os.open(temporary,os.O_RDONLY|os.O_DIRECTORY)
  try:os.fsync(fd)
  finally:os.close(fd)
  temporary.chmod(0o500);require(not os.path.lexists(INSTALL),'NEW_CORRECTIVE_INSTALL_REQUIRED');os.rename(temporary,INSTALL)
  fd=os.open(INSTALL.parent,os.O_RDONLY|os.O_DIRECTORY)
  try:os.fsync(fd)
  finally:os.close(fd)
 finally:
  if temporary.exists():temporary.chmod(0o700);shutil.rmtree(temporary)
def launch():
 child=subprocess.Popen(['/usr/bin/python3','-I','-B','-S',str(INSTALL/'prepare-credentials.py')],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin'},start_new_session=True)
 try:stdout,stderr=child.communicate(timeout=630)
 except BaseException:
  if child.poll() is None:os.killpg(child.pid,signal.SIGKILL)
  child.communicate();raise
 require(len(stdout)<=16384 and len(stderr)<=4096,'MINIMIZED_CORRECTIVE_OUTPUT_REQUIRED')
 report=json.loads(stdout);require(type(report) is dict and type(report.get('status')) is str,'TYPED_CORRECTIVE_RECEIPT_REQUIRED');return child.returncode,report
def main():
 try:
  validate()
  if sys.argv[1:]==['--inspect-delivery']:
   print(json.dumps({'status':'PINNED_CORRECTIVE_DELIVERY_INSPECTED','producerSource':DELIVERY['producerSource'],'publication':PUBLICATION,'closedSources':26,'targetOperations':0,'oldScopeRearmed':False}));return 0
  require(not sys.argv[1:] and os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ROOT_ISOLATED_NO_ARGUMENT_ENTRY_REQUIRED')
  require(os.uname().sysname=='Linux' and os.uname().machine=='x86_64' and hasattr(os,'memfd_create') and Path('/usr/bin/nsenter').is_file(),'LINUX_AMD64_NAMESPACE_AND_MEMFD_REQUIRED')
  os.umask(0o077);ancestry(SCOPE.parent);ancestry(INSTALL.parent);existing_reader()
  require(PREDECESSOR.is_dir() and not os.path.lexists(SCOPE) and not os.path.lexists(INSTALL),'PRESERVED_PREDECESSOR_AND_FRESH_CORRECTION_REQUIRED')
  install(fetch());code,report=launch();report['inventoryReconciliationProducer']=DELIVERY['producerSource'];report['inventoryReconciliationPublication']=PUBLICATION;print(json.dumps(report,sort_keys=True));return code
 except Exception as error:
  code=str(error) if type(error) is ValueError and re.fullmatch('[A-Z0-9_]{1,128}',str(error)) else 'CORRECTIVE_DELIVERY_STOP_PRIVATE_DETAILS_NOT_PRINTED'
  print(json.dumps({'status':'STORAGE_INVENTORY_RECONCILIATION_DELIVERY_STOP','reasonCode':code,'scopeConsumed':os.path.lexists(SCOPE),'automaticReplayAllowed':False,'oldScopeRearmed':False,'targetApplyAuthorized':False}));return 1
if __name__=='__main__':raise SystemExit(main())
