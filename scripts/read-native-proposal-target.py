"""Bounded public Engine/service metadata for semantic proposal rollout; GET only."""
import http.client,json,pathlib,re,socket,subprocess,time

class Local(http.client.HTTPConnection):
 def connect(self):
  self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
  self.sock.settimeout(self.timeout);self.sock.connect('/var/run/docker.sock')
def get(path):
 c=Local('localhost',timeout=15)
 try:
  c.request('GET',path);r=c.getresponse();raw=r.read(2097153)
  if r.status!=200 or len(raw)>2097152:raise ValueError('ENGINE_BOUNDED_METADATA_UNAVAILABLE')
  return json.loads(raw)
 finally:c.close()
def main():
 out={'schema':'ouf.native-proposal-target-read.v1','observedAt':int(time.time()),'readOnly':True,
      'containerLifecycleOperations':0,'protectedFileReads':0,'databaseQueries':0,
      'privateValuesPrinted':False,'budgetReset':False,'r12Touched':False,'notReleaseAcceptance':True}
 try:
  version=get('/version');api=version['ApiVersion']
  if not re.fullmatch(r'1\.\d{1,3}',api):raise ValueError('ENGINE_API_VERSION_INVALID')
  rows=get('/v'+api+'/containers/json?all=true')
  if not isinstance(rows,list) or len(rows)>256:raise ValueError('CONTAINER_METADATA_BOUND_REQUIRED')
  selected=[]
  for row in rows:
   names=row.get('Names') or []
   if not any(re.search(r'(?:ouf[-_])?(?:semantic|mcp|apisix)',n,re.I) for n in names):continue
   cid=row.get('Id')
   if not isinstance(cid,str) or not re.fullmatch('[0-9a-f]{64}',cid):raise ValueError('EXACT_CONTAINER_ID_REQUIRED')
   v=get('/v'+api+'/containers/'+cid+'/json');labels=v.get('Config',{}).get('Labels') or {}
   source=labels.get('org.opencontainers.image.revision')
   if source is not None and not re.fullmatch('[0-9a-f]{40}',source):source=None
   state=v.get('State') or {}
   selected.append({'containerId':cid,'names':names,'imageId':v.get('Image'),
    'sourceRevision':source,'running':state.get('Running'),'status':state.get('Status'),
    'health':(state.get('Health') or {}).get('Status'),'restartCount':v.get('RestartCount')})
  out['containers']=selected
  fields=('LoadState','ActiveState','SubState','MainPID','NRestarts','Result','ExecMainStatus')
  p=subprocess.run(['/usr/bin/systemctl','show','ouf-semantic-provider-lease-resilient-r12.service','--no-pager','--property='+','.join(fields)],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
  if p.returncode or len(p.stdout)>8192:raise ValueError('PUBLIC_SERVICE_METADATA_UNAVAILABLE')
  service={}
  for line in p.stdout.decode().splitlines():
   k,sep,v=line.partition('=')
   if not sep or k not in fields or k in service or not re.fullmatch('[A-Za-z0-9_-]{0,64}',v):raise ValueError('PUBLIC_SERVICE_METADATA_INVALID')
   service[k]=v
  if set(service)!=set(fields):raise ValueError('PUBLIC_SERVICE_METADATA_INCOMPLETE')
  out.update(service=service,status='READ_COMPLETED')
 except Exception as e:
  reason=str(e);out.update(status='READ_BLOCKED',reason=reason if re.fullmatch('[A-Z][A-Z0-9_]{0,120}',reason) else 'TARGET_METADATA_UNAVAILABLE')
 print('OUF_NATIVE_PROPOSAL_TARGET_READ='+json.dumps(out,sort_keys=True))
 pathlib.Path('native-proposal-target-read.json').write_text(json.dumps(out,sort_keys=True,indent=2)+'\n')
 return 0 if out['status']=='READ_COMPLETED' else 1
if __name__=='__main__':raise SystemExit(main())
