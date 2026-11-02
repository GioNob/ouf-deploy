#!/usr/bin/env python3
"""Independent exact-artifact and immutable-publication readback; no target calls."""
import hashlib,importlib.util,json,os,subprocess,sys,urllib.parse,urllib.request,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
ARTIFACT=13133996379
SIZE=166890
SHA='1025662beaad10843cf2d87f93f21c5edf93d93f2bc8d5074c8784b10bbbef40'
PRODUCER='6447b0f64616170cfa79e2d0e471c5f860fb6ec9'
PUBLICATION='28eb67064492c802ff96b884dbe42deefb5bec00'
assert os.environ.get('GITHUB_ACTIONS')=='true'
out=ROOT/'credential-readback';out.mkdir()
class Redirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,req,fp,code,msg,headers,newurl):
  u=urllib.parse.urlsplit(newurl);assert u.scheme=='https' and u.username is None and (u.hostname.endswith('.blob.core.windows.net') or u.hostname.endswith('.actions.githubusercontent.com') or u.hostname.endswith('.amazonaws.com') or u.hostname=='api.github.com')
  r=super().redirect_request(req,fp,code,msg,headers,newurl)
  if r is not None:r.remove_header('Authorization')
  return r
request=urllib.request.Request(f'https://api.github.com/repos/GioNob/ouf-deploy/actions/artifacts/{ARTIFACT}/zip');request.add_unredirected_header('Authorization','Bearer '+os.environ['GH_TOKEN']);request.add_header('Accept','application/vnd.github+json')
with urllib.request.build_opener(Redirect()).open(request,timeout=60) as response:raw=response.read(SIZE+1)
assert len(raw)==SIZE and hashlib.sha256(raw).hexdigest()==SHA
path=out/'original.zip';path.write_bytes(raw)
spec=importlib.util.spec_from_file_location('verify',ROOT/'scripts/verify-credential-continuation-evidence-20261102.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
result=m.verify(path,SHA,PRODUCER);(out/'byte-readback.json').write_text(json.dumps(result,indent=2)+'\n')
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**kw):raise ValueError('PUBLICATION_REDIRECT_DENIED')
public=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
with zipfile.ZipFile(path) as z:
 prefix='credential-evidence/'
 for name in ['SHA256SUMS','provenance.json','qualification.json','native-target-inventory-result.json','root-install-fixture.json']:(out/name).write_bytes(z.read(prefix+name))
 delivery=json.loads(z.read(prefix+'inventory-delivery/delivery.json'));total=0
 for name in ['delivery.json','prepare-credentials.py']:
  expected=z.read(prefix+'inventory-delivery/'+name)
  url='https://raw.githubusercontent.com/GioNob/ouf-deploy/'+PUBLICATION+'/releases/seaweedfs-inventory-credentials-20261102/'+name
  with public.open(url,timeout=20) as response:assert response.status==200;actual=response.read(len(expected)+1)
  assert actual==expected;total+=len(actual)
  (out/name).write_bytes(actual)
for source in ['tools/storage_migration/target_inventory_credentials.py','tools/storage_migration/minio_credential_binding.py','tools/storage_migration/inventory_credentials_bootstrap.py']:
 expected=(ROOT/source).read_bytes()
 with public.open('https://raw.githubusercontent.com/GioNob/ouf-deploy/'+PRODUCER+'/'+source,timeout=20) as response:assert response.status==200;actual=response.read(len(expected)+1)
 assert actual==expected,'REVIEWED_ENTRY_OR_BOOTSTRAP_DIFFERS_FROM_QUALIFIED_SOURCE'
spec=importlib.util.spec_from_file_location('builder',ROOT/'scripts/build-storage-credentials-launcher-20261102.py');b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
launcher=ROOT/'releases/seaweedfs-inventory-credentials-20261102/run-credentials.py';raw=launcher.read_bytes();assert raw==b.build(delivery,PUBLICATION).encode()
inspection=json.loads(subprocess.check_output([sys.executable,'-I','-B','-S',str(launcher),'--inspect-delivery'],timeout=30));assert inspection['targetOperations']==0 and not inspection['oldScopeRearmed']
report={'status':'PASS','publication':PUBLICATION,'producerSource':PRODUCER,'filesComparedByteForByte':2,'bytesCompared':total,'launcherSha256':hashlib.sha256(raw).hexdigest(),'entryAndBootstrapMatchQualifiedProducer':True,'sourceInspectionOnly':True,'oldScopeRearmed':False,'targetOperations':0}
(out/'published-readback.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
