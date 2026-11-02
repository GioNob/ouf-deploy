#!/usr/bin/env python3
"""Independent CI-only readback of one exact producer artifact; no rebuild."""
import hashlib,json,os,shutil,urllib.request,urllib.parse,zipfile
from pathlib import Path
import importlib.util
ROOT=Path(__file__).resolve().parents[1]
ARTIFACT=13114913760
SHA='5e14ecdc9ae38456cd2f851201c08ee0e2c21e90b1dff5670b13615f0354fe18'
SIZE=278488850
assert os.environ.get('GITHUB_ACTIONS')=='true','CI_ONLY'
out=ROOT/'sw-readback';out.mkdir()
class Redirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,req,fp,code,msg,headers,newurl):
  u=urllib.parse.urlsplit(newurl)
  assert u.scheme=='https' and u.username is None and (u.hostname.endswith('.blob.core.windows.net') or u.hostname.endswith('.actions.githubusercontent.com') or u.hostname.endswith('.amazonaws.com') or u.hostname=='api.github.com'),'ALLOWLISTED_HTTPS_ARTIFACT_REDIRECT_REQUIRED'
  r=super().redirect_request(req,fp,code,msg,headers,newurl)
  if r is not None:r.remove_header('Authorization')
  return r
request=urllib.request.Request(f'https://api.github.com/repos/GioNob/ouf-deploy/actions/artifacts/{ARTIFACT}/zip')
request.add_unredirected_header('Authorization','Bearer '+os.environ['GH_TOKEN'])
request.add_header('Accept','application/vnd.github+json')
path=out/'original.zip'
with urllib.request.build_opener(Redirect()).open(request,timeout=60) as response,path.open('xb') as f:
 total=0
 while block:=response.read(1048576):
  total+=len(block);assert total<=SIZE,'BOUNDED_EXACT_ARTIFACT_REQUIRED';f.write(block)
assert total==SIZE
spec=importlib.util.spec_from_file_location('verify',ROOT/'scripts/verify-seaweedfs-evidence-20261102.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
result=module.verify(path,SHA)
(out/'byte-readback.json').write_text(json.dumps(result,indent=2)+'\n')
with zipfile.ZipFile(path) as z:
 for name in ['SHA256SUMS','provenance.json','candidate.json','openpgp-applicability.json','adapter-source-inventory.json','compiled-packages.json','contract-result.json','inventory-live-result.json','trivy-binary.json']:
  (out/name).write_bytes(z.read(name))
print(json.dumps(result))
