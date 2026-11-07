"""Bounded current host observations. No credentials, container exec or mutation.

Uses the allowlist/representation approach of the historical target_inventory
reader, without importing its consumed scope, authority or launchers.
"""
import http.client,os,re,socket,stat,time
from urllib.parse import urlsplit
from pathlib import Path
from .g0_database import ancestors,put_new
from .inventory_manifest import canonical,decode,require,sha

ROLES=('apisix','caddy','gateway-owner','ingestion','ingestion-evidence-read','keycloak','mcp','minio','onboarding','postgres','semantic','udp','udp-evidence-read')
BINDINGS={'OUF_ONBOARDING_STAGING_ENDPOINT','OUF_ONBOARDING_STAGING_BUCKET','OUF_UDP_S3_ENDPOINT','OUF_UDP_S3_BUCKET','OUF_UDP_LAKE_S3_ENDPOINT','OUF_UDP_LAKE_S3_BUCKET','OUF_ONBOARDING_OBJECT_STORE_GATEWAY_BASE_URL','OUF_ONBOARDING_OBJECT_STORE_READ_PATH','AWS_REGION','AWS_DEFAULT_REGION'}
def frame(st):return (st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_gid,st.st_nlink)
class UnixConnection(http.client.HTTPConnection):
 def connect(self):
  self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(3);self.sock.connect('/run/docker.sock')
class Engine:
 def __init__(self,scope,max_requests=130):
  require(type(max_requests) is int and max_requests in (130,386),'G0_HOST_FIXED_REQUEST_PROFILE');self.max_requests=max_requests
  self.scope=scope;self.requests=0;self.bytes=0;self.until=time.monotonic()+120
  st=Path('/run/docker.sock').lstat();require(stat.S_ISSOCK(st.st_mode) and st.st_uid==0 and not st.st_mode&0o007 and st.st_nlink==1,'G0_HOST_PRIVATE_ENGINE_SOCKET');self.pin=frame(st)
 def get(self,path):
  require(time.monotonic()<self.until and self.requests<self.max_requests and self.bytes<32<<20,'G0_HOST_BUDGET')
  require(path=='/containers/json?all=1' or re.fullmatch('/containers/[a-f0-9]{64}/json',path),'G0_HOST_GET_ALLOWLIST')
  require(frame(Path('/run/docker.sock').lstat())==self.pin,'G0_HOST_SOCKET_CHANGED')
  self.requests+=1;put_new(self.scope,'engine-request-'+str(self.requests)+'.json',canonical({'sequence':self.requests,'method':'GET','pathSha256':sha(path.encode())}))
  c=UnixConnection('localhost',timeout=3)
  try:
   c.request('GET',path,headers={'Accept':'application/json'});r=c.getresponse();b=r.read((2<<20)+1);self.bytes+=len(b)
   require(r.status==200 and len(b)<=2<<20 and self.bytes<=32<<20 and time.monotonic()<self.until,'G0_HOST_BOUNDED_RESPONSE');return decode(b)
  finally:c.close();require(frame(Path('/run/docker.sock').lstat())==self.pin,'G0_HOST_SOCKET_CHANGED')
def selected(doc):
 require(type(doc) is dict and re.fullmatch('[a-f0-9]{64}',doc.get('Id','')) and re.fullmatch('sha256:[a-f0-9]{64}',doc.get('Image','')),'G0_HOST_TYPED_CONTAINER')
 env={}
 for entry in doc.get('Config',{}).get('Env') or []:
  require(type(entry) is str and '=' in entry,'G0_HOST_TYPED_ENV');k,v=entry.split('=',1);require(k not in env,'G0_HOST_DUPLICATE_ENV');env[k]=v
 state=doc.get('State') or {};labels=doc.get('Config',{}).get('Labels') or {}
 for k in BINDINGS&env.keys():
  if 'ENDPOINT' in k or 'URL' in k:
   u=urlsplit(env[k]);require(not u.username and not u.password,'G0_HOST_EMBEDDED_CREDENTIAL_BINDING')
 return {'id':doc['Id'],'name':doc.get('Name'),'nativeImage':doc['Image'],'running':state.get('Running'),'paused':state.get('Paused'),'pid':state.get('Pid'),'startedAt':state.get('StartedAt'),'finishedAt':state.get('FinishedAt'),'declaredRevision':labels.get('org.opencontainers.image.revision'),'storageBindings':{k:v for k,v in env.items() if k in BINDINGS},'environmentNames':sorted(env),'mounts':[{k:m.get(k) for k in ('Type','Name','Source','Destination','RW')} for m in doc.get('Mounts') or []],'networkMode':doc.get('HostConfig',{}).get('NetworkMode')}
def snapshot(engine,roles,max_containers=64):
 require(type(max_containers) is int and max_containers in (64,192),'G0_HOST_FIXED_CONTAINER_PROFILE')
 rows=engine.get('/containers/json?all=1')
 count=len(rows) if type(rows) is list else None
 engine.last_list_observation={'responseIsList':type(rows) is list,'containerCount':count,'maximumContainers':max_containers}
 put_new(engine.scope,'host-list-'+str(engine.requests)+'.json',canonical({'schema':'ouf.storage-g0-host-list-bound.v1','responseIsList':type(rows) is list,'containerCount':count,'maximumContainers':max_containers,'listIncludesStopped':True,'rawResponsePersisted':False}))
 require(type(rows) is list,'G0_HOST_CONTAINER_LIST_TYPE')
 require(0<len(rows)<=max_containers,'G0_HOST_CONTAINER_LIMIT')
 ids=[r.get('Id') for r in rows];require(all(type(x) is str and re.fullmatch('[a-f0-9]{64}',x) for x in ids) and len(ids)==len(set(ids)),'G0_HOST_UNIQUE_IDS')
 records=[]
 for identifier in sorted(ids):
  doc=engine.get('/containers/'+identifier+'/json');require(doc.get('Id')==identifier,'G0_HOST_RESPONSE_ID');records.append(selected(doc))
 index={x['id']:x for x in records};mapped={};issues=[]
 for role,binding in roles.items():
  r=index.get(binding['containerId'])
  if r is None:issues.append({'role':role,'code':'ROLE_CONTAINER_MISSING'});continue
  mapped[role]=r
  if r['nativeImage']!=binding['nativeImage']:issues.append({'role':role,'code':'ROLE_IMAGE_DRIFT'})
 return {'schema':'ouf.storage-g0-host-observation.v1','containers':records,'roles':mapped,'findings':issues,'unmappedContainerCount':len(set(ids)-{v['containerId'] for v in roles.values()}),'externalConsumersProvenAbsent':False,'installedSourceMembershipProven':False}
def capacity(paths):
 values={}
 for purpose,path in paths.items():
  p=Path(path);require(p.is_absolute() and str(p)==os.path.normpath(p),'G0_CAPACITY_CANONICAL_PATH');ancestors(p);st=p.stat();v=os.statvfs(p)
  values[purpose]={'path':str(p),'device':st.st_dev,'totalBytes':v.f_blocks*v.f_frsize,'availableBytes':v.f_bavail*v.f_frsize}
 with open('/proc/meminfo','rb') as f:raw=f.read(32769)
 require(len(raw)<=32768,'G0_MEMORY_LIMIT');m={l.split(':')[0]:l.split(':')[1].strip() for l in raw.decode().splitlines() if ':' in l}
 return {'schema':'ouf.storage-g0-capacity-observation.v1','filesystems':values,'memory':{k:m.get(k) for k in ['MemTotal','MemAvailable','SwapFree']},'independentFailureDomainsProven':False,'growthOrThroughputProven':False}
