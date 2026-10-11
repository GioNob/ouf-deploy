"""One bounded read-only CLI/API comparison. No import or protected reads."""
import hashlib,http.client,json,os,pathlib,re,socket,subprocess,tempfile
IMAGE='sha256:83635be46d1fe61dea08597ea4488980b4349e5f6e0ed8bbd3ab6f5e2686370e'
SOURCE='8a2e84b32d4ce2bdc3bc529b56afb5663ab133e3'
def hashed(v):return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':')).encode()).hexdigest()
class Local(http.client.HTTPConnection):
 def connect(self):
  self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(self.timeout);self.sock.connect('/var/run/docker.sock')
def request(path):
 c=Local('localhost',timeout=15)
 try:
  c.request('GET',path);r=c.getresponse();b=r.read(2097153)
  if len(b)>2097152:raise ValueError('BOUNDED_RESPONSE_REQUIRED')
  return r.status,json.loads(b) if b else None
 finally:c.close()
def projection(v):
 if not isinstance(v,dict):return {'shapeProven':False}
 return {'imageId':v.get('Id'),'os':v.get('Os'),'architecture':v.get('Architecture'),
  'rootfsHash':hashed(v.get('RootFS')),'configHash':hashed(v.get('Config')),
  'sourceMatches':v.get('Config',{}).get('Labels',{}).get('org.opencontainers.image.revision')==SOURCE,
  'repoTagCount':len(v.get('RepoTags') or [])}
def main():
 out={'schema':'ouf.v11-image-import-engine-read.v1','readOnly':True,'imageImports':0,'containerLifecycleOperations':0,
  'protectedFileReads':0,'protectedFileWrites':0,'budgetReset':False,'r12Touched':False,'privateValuesPrinted':False,'notReleaseAcceptance':True}
 try:
  status,v=request('/version');out['versionStatus']=status
  if status!=200:raise ValueError('ENGINE_VERSION_UNPROVEN')
  out['engineVersion']={k:v.get(k) for k in ('Version','ApiVersion','MinAPIVersion','Os','Arch')}
  versions=['1.44',v['ApiVersion']]
  if any(not re.fullmatch(r'1\.\d{1,3}',x) for x in versions):raise ValueError('ENGINE_API_SHAPE_UNPROVEN')
  out['nativeReads']=[]
  for version in dict.fromkeys(versions):
   for key in (IMAGE,IMAGE.removeprefix('sha256:')):
    status,v=request('/v'+version+'/images/'+key+'/json')
    out['nativeReads'].append({'apiVersion':version,'exactPrefixedId':key==IMAGE,'status':status,
     'projection':projection(v) if status==200 else None})
  status,rows=request('/v1.44/images/json?all=true');out['listStatus']=status
  if status==200:
   if not isinstance(rows,list) or len(rows)>256:raise ValueError('IMAGE_INVENTORY_BOUND_REQUIRED')
   out['imageCount']=len(rows)
   out['sourceMatches']=[{'imageId':r['Id'],'repoTagCount':len(r.get('RepoTags') or []),'size':r.get('Size')} for r in rows
    if (r.get('Labels') or {}).get('org.opencontainers.image.revision')==SOURCE or r['Id']==IMAGE]
  with tempfile.TemporaryDirectory(prefix='ouf-image-read-') as empty:
   p=subprocess.run(['docker','--config',empty,'image','inspect',IMAGE],stdin=subprocess.DEVNULL,
    stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,
    env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','DOCKER_HOST':'unix:///var/run/docker.sock'})
   out['cliExit']=p.returncode;out['cliStderrHash']=hashlib.sha256(p.stderr).hexdigest()
   if len(p.stdout)>2097152:raise ValueError('CLI_OUTPUT_BOUND_REQUIRED')
   if p.returncode==0:
    rows=json.loads(p.stdout)
    if not isinstance(rows,list) or len(rows)!=1:raise ValueError('EXACT_CLI_IMAGE_REQUIRED')
    out['cliProjection']=projection(rows[0])
  out['status']='READ_COMPLETED_NO_IMPORT_REPLAY'
 except Exception as e:
  reason=str(e);out['status']='READ_BLOCKED';out['reason']=reason if re.fullmatch('[A-Z][A-Z0-9_]{0,120}',reason) else 'ENGINE_DIAGNOSIS_UNPROVEN'
 print('OUF_V11_IMAGE_ENGINE_READ='+json.dumps(out,sort_keys=True))
 pathlib.Path('v11-image-engine-read.json').write_text(json.dumps(out,sort_keys=True,indent=2)+'\n')
 return 0 if out['status']=='READ_COMPLETED_NO_IMPORT_REPLAY' else 1
if __name__=='__main__':raise SystemExit(main())
