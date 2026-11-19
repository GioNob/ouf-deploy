"""Pinned download/install of the offline-only compiler; no target network calls."""
import hashlib,json,os,re,shutil,signal,stat,subprocess,sys,tempfile,urllib.request
from pathlib import Path
DELIVERY=None
PUBLICATION=None
INSTALL=Path('/usr/local/lib/ouf-storage-offline-plan-20261102')
SCOPE=Path('/etc/ouf/deploy-snapshots/seaweedfs-offline-plan-20261102-v1')
INPUT=Path('/etc/ouf/deploy-snapshots/seaweedfs-inventory-inputs-20261102-v1')
def require(ok,reason):
 if not ok:raise ValueError(reason)
def ancestry(path):
 for p in [path,*path.parents]:
  info=p.lstat();require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022,'ROOT_PROTECTED_ANCESTRY_REQUIRED')
def validate():
 require(type(DELIVERY) is dict and re.fullmatch('[a-f0-9]{40}',str(PUBLICATION)),'PINNED_OFFLINE_DELIVERY_REQUIRED')
 require(DELIVERY['sourceCount']==2 and DELIVERY['controlAttempt']==17 and DELIVERY['previousControlAttempts']==16 and DELIVERY['previousEngineGets']==52 and DELIVERY['newEngineGets']==DELIVERY['newS3Requests']==DELIVERY['credentialFileReads']==DELIVERY['objectBodiesRead']==0 and DELIVERY['oldScopeRearmed'] is DELIVERY['runtimeAuthorityIssued'] is DELIVERY['targetApplyAuthorized'] is False,'EXACT_OFFLINE_ONLY_PROFILE_REQUIRED')
 require(DELIVERY['scopePath']==str(SCOPE) and DELIVERY['installPath']==str(INSTALL) and 0<DELIVERY['capsuleBytes']<=131072 and re.fullmatch('[a-f0-9]{64}',DELIVERY['capsuleSha256']),'EXACT_OFFLINE_PATHS_AND_HASH_REQUIRED')
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**kw):raise ValueError('DELIVERY_REDIRECT_DENIED')
def fetch():
 url='https://raw.githubusercontent.com/GioNob/ouf-deploy/'+PUBLICATION+'/releases/seaweedfs-offline-plan-20261102/prepare-plan.py'
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
 with opener.open(url,timeout=20) as response:
  require(response.status==200,'SUCCESSFUL_PINNED_DOWNLOAD_REQUIRED');raw=response.read(DELIVERY['capsuleBytes']+1)
 require(len(raw)==DELIVERY['capsuleBytes'] and hashlib.sha256(raw).hexdigest()==DELIVERY['capsuleSha256'],'EXACT_OFFLINE_COMPILER_BYTES_REQUIRED');return raw
def install(raw):
 require(len(raw)==DELIVERY['capsuleBytes'] and hashlib.sha256(raw).hexdigest()==DELIVERY['capsuleSha256'],'EXACT_OFFLINE_COMPILER_BYTES_REQUIRED')
 ancestry(INSTALL.parent);require(not os.path.lexists(INSTALL),'FRESH_OFFLINE_INSTALL_REQUIRED')
 temporary=Path(tempfile.mkdtemp(prefix='.ouf-offline-plan-',dir=INSTALL.parent))
 try:
  for name,data in [('prepare-plan.py',raw),('delivery.json',(json.dumps(DELIVERY,sort_keys=True)+'\n').encode())]:
   fd=os.open(temporary/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
   with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
  fd=os.open(temporary,os.O_RDONLY|os.O_DIRECTORY)
  try:os.fsync(fd)
  finally:os.close(fd)
  temporary.chmod(0o500);require(not os.path.lexists(INSTALL),'FRESH_OFFLINE_INSTALL_REQUIRED');os.rename(temporary,INSTALL)
  fd=os.open(INSTALL.parent,os.O_RDONLY|os.O_DIRECTORY)
  try:os.fsync(fd)
  finally:os.close(fd)
 finally:
  if temporary.exists():temporary.chmod(0o700);shutil.rmtree(temporary)
def launch():
 child=subprocess.Popen(['/usr/bin/python3','-I','-B','-S',str(INSTALL/'prepare-plan.py')],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin'},start_new_session=True)
 try:stdout,stderr=child.communicate(timeout=60)
 except BaseException:
  if child.poll() is None:os.killpg(child.pid,signal.SIGKILL)
  child.communicate();raise
 require(len(stdout)<=16384 and len(stderr)<=4096,'MINIMIZED_OFFLINE_RECEIPT_REQUIRED');result=json.loads(stdout);require(type(result) is dict and type(result.get('status')) is str,'TYPED_OFFLINE_RECEIPT_REQUIRED');return child.returncode,result
def main():
 try:
  validate()
  if sys.argv[1:]==['--inspect-delivery']:
   print(json.dumps({'status':'OFFLINE_DELIVERY_INSPECTED','producerSource':DELIVERY['producerSource'],'publication':PUBLICATION,'targetOperations':0,'runtimeAuthorityIssued':False}));return 0
  require(not sys.argv[1:] and os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ROOT_ISOLATED_NO_ARGUMENT_ENTRY_REQUIRED');os.umask(0o077)
  ancestry(INPUT);ancestry(SCOPE.parent);ancestry(INSTALL.parent)
  require(not os.path.lexists(SCOPE) and not os.path.lexists(INSTALL),'FRESH_OFFLINE_CONTROL_AND_INSTALL_REQUIRED')
  install(fetch());code,result=launch();result.update(offlinePlanProducer=DELIVERY['producerSource'],offlinePlanPublication=PUBLICATION);print(json.dumps(result,sort_keys=True));return code
 except Exception as error:
  reason=str(error) if type(error) is ValueError and re.fullmatch('[A-Z0-9_]{1,128}',str(error)) else 'OFFLINE_DELIVERY_UNPROVEN_PRIVATE_DETAILS_NOT_PRINTED'
  print(json.dumps({'status':'OFFLINE_DELIVERY_STOP','reasonCode':reason,'scopeConsumed':os.path.lexists(SCOPE),'automaticReplayAllowed':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False}));return 1
if __name__=='__main__':raise SystemExit(main())
