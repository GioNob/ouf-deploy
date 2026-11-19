"""Pinned network-only children for G0. No process discovery or re-admission."""
import argparse,ipaddress,json,os,re,select,selectors,signal,subprocess,sys,time
from pathlib import Path
from urllib.parse import urlsplit
from . import g0_database as db
from .inventory_manifest import canonical,decode,require,sha

def bounded(path,limit):
 with open(path,'rb') as f:b=f.read(limit+1)
 require(0<len(b)<=limit,'G0_NETWORK_METADATA_LIMIT');return b
def boot_id():return bounded('/proc/sys/kernel/random/boot_id',128).decode().strip()
def namespace(pid,name):
 s=Path('/proc/'+str(pid)+'/ns/'+name).stat();return [s.st_dev,s.st_ino]
def process_pin(pid):
 raw=bounded('/proc/'+str(pid)+'/stat',16384);require(b') ' in raw,'G0_NETWORK_PROCESS_STAT')
 return {'pid':pid,'startTicks':int(raw.rsplit(b') ',1)[1].split()[19]),'namespaces':{k:namespace(pid,k) for k in ('net','mnt')}}
def validate(binding,operation,installation,roles):
 require(type(binding) is dict and set(binding)=={'schema','operationId','installationRef','bootId','targets'} and binding['schema']=='ouf.storage-g0-network-binding.v1' and binding['operationId']==operation and binding['installationRef']==installation,'G0_NETWORK_EXACT_BINDING')
 require(type(binding['bootId']) is str and re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',binding['bootId']) and type(binding['targets']) is dict and set(binding['targets'])=={'minio','postgres'},'G0_NETWORK_BOOT_AND_TARGETS')
 for role,b in binding['targets'].items():
  require(type(b) is dict and set(b)=={'containerId','nativeImage','process'} and {k:b[k] for k in ('containerId','nativeImage')}==roles[role],'G0_NETWORK_ROLE_BINDING')
  p=b['process'];require(type(p) is dict and set(p)=={'pid','startTicks','namespaces'} and type(p['pid']) is int and p['pid']>1 and type(p['startTicks']) is int and p['startTicks']>0 and type(p['namespaces']) is dict and set(p['namespaces'])=={'net','mnt'},'G0_NETWORK_PROCESS_BINDING')
  for v in p['namespaces'].values():require(type(v) is list and len(v)==2 and all(type(n) is int and n>0 for n in v),'G0_NETWORK_NAMESPACE_BINDING')
 require(binding['targets']['minio']['process']['pid']!=binding['targets']['postgres']['process']['pid'],'G0_NETWORK_DISTINCT_OWNERS')
 return binding
def loopback_config(kind,c):
 if kind=='s3':
  u=urlsplit(c['connection']['endpoint']);require(u.scheme in ('http','https') and u.hostname and not u.username and not u.password and not u.query and not u.fragment and not u.path,'G0_NETWORK_S3_ENDPOINT');address=ipaddress.ip_address(u.hostname)
 else:
  address=ipaddress.ip_address(c['hostaddr']);require(c['host']==c['hostaddr'],'G0_NETWORK_DB_LITERAL_HOST')
 require(address.version==4 and address.is_loopback,'G0_NETWORK_ONLY_IPV4_LOOPBACK')
def identity_check(binding,role):
 require(boot_id()==binding['bootId'],'G0_NETWORK_BOOT_CHANGED')
 require(process_pin(binding['targets'][role]['process']['pid'])==binding['targets'][role]['process'],'G0_NETWORK_OWNER_CHANGED')
def fd_check(binding,role,netfd,pidfd):
 identity_check(binding,role);p=binding['targets'][role]['process'];s=os.fstat(netfd)
 require([s.st_dev,s.st_ino]==p['namespaces']['net'],'G0_NETWORK_FD_BINDING')
 info=bounded('/proc/self/fdinfo/'+str(pidfd),4096).decode();match=re.search(r'^Pid:\s+(\d+)$',info,re.M)
 require(match is not None and int(match[1])==p['pid'] and not select.select([pidfd],[],[],0)[0],'G0_NETWORK_OWNER_EXITED')

class PinnedNetwork:
 def __init__(self,binding,role):self.binding=binding;self.role=role;self.netfd=None;self.pidfd=None
 def __enter__(self):
  require(os.geteuid()==0 and hasattr(os,'setns') and hasattr(os,'pidfd_open'),'G0_NETWORK_ROOT_LINUX_PYTHON_REQUIRED')
  try:
   identity_check(self.binding,self.role);pid=self.binding['targets'][self.role]['process']['pid'];self.pidfd=os.pidfd_open(pid,0);self.netfd=os.open('/proc/'+str(pid)+'/ns/net',os.O_RDONLY);self.check();return self
  except BaseException:self.close();raise
 def check(self):fd_check(self.binding,self.role,self.netfd,self.pidfd)
 def close(self):
  for key in ('netfd','pidfd'):
   fd=getattr(self,key)
   if fd is not None:os.close(fd);setattr(self,key,None)
 def __exit__(self,*unused):self.close()

def run_child(args,env,pass_fds,seconds,guard):
 """One child session; bounded output/deadline, kill child group on failure."""
 guard();until=time.monotonic()+seconds;proc=subprocess.Popen(args,env=env,pass_fds=pass_fds,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
 sel=selectors.DefaultSelector();sel.register(proc.stdout,selectors.EVENT_READ,'out');sel.register(proc.stderr,selectors.EVENT_READ,'err');buffers={'out':bytearray(),'err':bytearray()}
 try:
  while sel.get_map():
   require(time.monotonic()<until,'G0_NETWORK_CHILD_DEADLINE');guard()
   for key,_ in sel.select(min(.2,max(0,until-time.monotonic()))):
    b=os.read(key.fileobj.fileno(),8193)
    if not b:sel.unregister(key.fileobj);continue
    require(len(buffers[key.data])+len(b)<=8192,'G0_NETWORK_CHILD_OUTPUT_LIMIT');buffers[key.data].extend(b)
  code=proc.wait(timeout=max(.01,until-time.monotonic()));guard()
  return subprocess.CompletedProcess(args,code,bytes(buffers['out']),bytes(buffers['err']))
 finally:
  # If the leader is unreaped/alive its process-group identity cannot be reused.
  if proc.poll() is None:
   try:os.killpg(proc.pid,signal.SIGKILL)
   except ProcessLookupError:pass
  proc.wait(timeout=5);sel.close();proc.stdout.close();proc.stderr.close()

class NetworkChildren:
 def __init__(self,root,binding_path,binding,expected_sha):self.root=root;self.path=binding_path;self.binding=binding;self.sha=expected_sha
 def runtime(self,host):
  for role,b in self.binding['targets'].items():
   v=host['roles'].get(role,{})
   require(v.get('id')==b['containerId'] and v.get('nativeImage')==b['nativeImage'] and v.get('pid')==b['process']['pid'] and v.get('running') is True and v.get('paused') is False,'G0_NETWORK_RUNTIME_ROLE_DRIFT')
   identity_check(self.binding,role)
 def run(self,kind,config,scope,seconds):
  require(kind in ('s3','db'),'G0_NETWORK_CHILD_KIND');loopback_config(kind,decode(db.private_read(config,16384)))
  role='minio' if kind=='s3' else 'postgres';host_net=namespace('self','net');host_mnt=namespace('self','mnt')
  def stable():require(sha(db.private_read(self.path,65536))==self.sha,'G0_NETWORK_INPUT_CHANGED')
  stable()
  with PinnedNetwork(self.binding,role) as pin:
   def guard():stable();pin.check()
   args=[sys.executable,'-I','-B','-S',str(self.root/'network-worker.py'),kind,str(self.path),self.sha,str(config),str(scope),str(pin.netfd),str(pin.pidfd)]
   result=run_child(args,{'PATH':'/usr/bin:/bin','GOMEMLIMIT':'256MiB','GOMAXPROCS':'1'},(pin.netfd,pin.pidfd),seconds,guard)
  require(namespace('self','net')==host_net and namespace('self','mnt')==host_mnt,'G0_NETWORK_PARENT_CONTEXT_CHANGED');return result

def worker_main(root):
 try:
  p=argparse.ArgumentParser();p.add_argument('kind',choices=['s3','db']);p.add_argument('binding',type=Path);p.add_argument('binding_sha');p.add_argument('config',type=Path);p.add_argument('scope',type=Path);p.add_argument('netfd',type=int);p.add_argument('pidfd',type=int);a=p.parse_args()
  require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'G0_NETWORK_ISOLATED_ROOT_WORKER')
  raw=db.private_read(a.binding,65536);require(sha(raw)==a.binding_sha,'G0_NETWORK_WORKER_BINDING');b=decode(raw);roles={k:{f:v[f] for f in ('containerId','nativeImage')} for k,v in b['targets'].items()};validate(b,b['operationId'],b['installationRef'],roles)
  c=decode(db.private_read(a.config,16384));kind='s3' if a.kind=='s3' else c['profile'].split('-')[0]
  require(kind in ('s3','onboarding','udp','ingestion') and c['installationRef']==b['installationRef'] and c['operationId']==b['operationId']+'-'+kind and a.scope.name==c['operationId'] and a.scope.is_absolute(),'G0_NETWORK_WORKER_OPERATION_BINDING');loopback_config(a.kind,c)
  role='minio' if a.kind=='s3' else 'postgres';fd_check(b,role,a.netfd,a.pidfd);mnt=namespace('self','mnt');before=namespace('self','net')
  os.setns(a.netfd,os.CLONE_NEWNET)
  require(namespace('self','net')==b['targets'][role]['process']['namespaces']['net'] and namespace('self','mnt')==mnt,'G0_NETWORK_ENTRY_BINDING');fd_check(b,role,a.netfd,a.pidfd)
  db.put_new(a.scope.parent,'network-entry-'+a.scope.name+'.json',canonical({'schema':'ouf.storage-g0-network-entry.v1','kind':a.kind,'role':role,'bindingSha256':a.binding_sha,'enteredNet':namespace('self','net'),'previousNet':before,'mountNamespaceUnchanged':True,'ownerProcess':b['targets'][role]['process'],'runtimeAuthorityIssued':False}))
  os.close(a.netfd);os.close(a.pidfd)
  if a.kind=='s3':os.execve(str(root/'bin/inventory'),[str(root/'bin/inventory'),'g0-collect',str(a.config),str(a.scope)],dict(os.environ))
  result=db.export(a.config,a.scope);print(json.dumps(result,sort_keys=True));return 0 if result['complete'] else 1
 except Exception as e:
  reason=str(e);print(json.dumps({'complete':False,'reason':reason if re.fullmatch('G0_[A-Z0-9_]+',reason) else 'G0_NETWORK_WORKER_HELD'}));return 1
