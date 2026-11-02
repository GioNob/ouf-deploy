#!/usr/bin/env python3
"""Read back immutable public delivery and compare every byte to the attested ZIP."""
import hashlib,importlib.util,json,os,subprocess,sys,urllib.request,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
PUBLICATION='0f446ddb4a1ed19b2c139bb496d06f84edb6062a'
assert os.environ.get('GITHUB_ACTIONS')=='true','CI_ONLY'
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**kw):raise ValueError('IMMUTABLE_PUBLICATION_REDIRECT_DENIED')
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
with zipfile.ZipFile(ROOT/'sw-readback/original.zip') as z:
 delivery=json.loads(z.read('inventory-delivery/delivery.json'));count=0;total=0
 for name in [p['name'] for p in delivery['parts']]+['delivery.json','prepare-storage-inventory.py']:
  expected=z.read('inventory-delivery/'+name)
  url='https://raw.githubusercontent.com/GioNob/ouf-deploy/'+PUBLICATION+'/releases/seaweedfs-inventory-delivery-20261102/'+name
  with opener.open(url,timeout=20) as response:
   assert response.status==200;actual=response.read(len(expected)+1)
  assert actual==expected,'PUBLISHED_BYTES_DIFFER_FROM_ATTESTED_ARTIFACT';count+=1;total+=len(actual)
spec=importlib.util.spec_from_file_location('builder',ROOT/'scripts/build-storage-inventory-bootstrap-20261102.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
launcher=ROOT/'releases/seaweedfs-inventory-delivery-20261102/run-inventory.py';raw=launcher.read_bytes();assert raw==m.build(delivery,PUBLICATION).encode(),'EXACT_BOUND_LAUNCHER_REQUIRED'
inspected=json.loads(subprocess.check_output([sys.executable,'-I','-B','-S',str(launcher),'--inspect-delivery'],timeout=30));assert inspected['targetOperations']==0 and inspected['closedSources']==24
report={'status':'PASS','publication':PUBLICATION,'producerSource':delivery['producerSource'],'publishedFilesComparedByteForByte':count,'publishedBytes':total,'launcherSha256':hashlib.sha256(raw).hexdigest(),'launcherSourceExactlyBoundToTemplate':True,'sourceInspectionOnly':True,'targetOperations':0,'targetApplyAuthorized':False}
(ROOT/'sw-readback/published-delivery-readback.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
