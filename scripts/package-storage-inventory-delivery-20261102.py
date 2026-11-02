#!/usr/bin/env python3
"""Prepare a closed monouse inventory capsule; no target execution or grant."""
import ast,base64,gzip,hashlib,json,os,re,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def package(binary,output,revision):
 assert re.fullmatch('[a-f0-9]{40}',revision)
 backend=binary.read_bytes();assert 0<len(backend)<=33554432
 original=(ROOT/'scripts/prepare-m2-retained-runtime-origins-20261101.py').read_text();values={}
 for n in ast.parse(original).body:
  if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id in ['MANIFEST','PAYLOAD']:values[n.targets[0].id]=ast.literal_eval(n.value)
 old=values['MANIFEST'];sources=json.loads(base64.b64decode(values['PAYLOAD']));assert len(sources)==len(old['sources'])==23
 manifest_sources={}
 for name,record in old['sources'].items():
  assert sha(sources[name].encode())==record['sha256']==sha((ROOT/record['path']).read_bytes());manifest_sources[name]=dict(record)
 template=(ROOT/'tools/storage_migration/target_inventory.py').read_text();assert template.count('__QUALIFIED_BACKEND_SHA256__')==1
 body=template.replace('__QUALIFIED_BACKEND_SHA256__',sha(backend));name='tools.storage_migration.target_inventory';sources[name]=body
 manifest_sources[name]={'path':'tools/storage_migration/target_inventory.py','sha256':sha(body.encode()),'templateSha256':sha(template.encode()),'boundBackendSha256':sha(backend)}
 raw=canonical(sources);assert len(raw)<=262144
 tail=original[original.index('\ndef require(ok):'):].replace('RETAINED_RUNTIME_ORIGIN_JOIN','STORAGE_BASELINE_READ')
 manifest={'schema':'ouf.storage-baseline-capsule.v1','entryModule':name,'sources':manifest_sources,'sourceRevisionClaim':revision,'payloadSha256':sha(raw),'sourceMapSha256':sha(canonical(manifest_sources)),'loaderTemplateSha256':sha(tail.encode()),'original23SourcesUnchanged':True,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False}
 script='#!/usr/bin/env python3\nimport base64,hashlib,importlib.abc,importlib.util,json,os,sys\nMANIFEST='+repr(manifest)+'\nPAYLOAD='+repr(base64.b64encode(raw).decode())+tail
 output.mkdir();capsule=output/'prepare-storage-inventory.py';capsule.write_text(script)
 inspected=json.loads(subprocess.check_output([sys.executable,'-I','-B','-S',str(capsule),'--inspect-source'],timeout=60));assert inspected['sourceCount']==24 and inspected['runtimeAuthorityIssued'] is False
 # Deliberately corrupt the bound payload. Inspection must fail before any target code runs.
 altered=script.replace("PAYLOAD='", "PAYLOAD='A",1);corrupt=output/'tampered.py';corrupt.write_text(altered)
 test=subprocess.run([sys.executable,'-I','-B','-S',str(corrupt),'--inspect-source'],capture_output=True,timeout=60);assert test.returncode!=0;corrupt.unlink()
 compressed=gzip.compress(backend,compresslevel=9,mtime=0);parts=[]
 for i,offset in enumerate(range(0,len(compressed),196608)):
  name=f'inventory.part{i:03d}';raw_part=compressed[offset:offset+196608];(output/name).write_bytes(raw_part);parts.append({'name':name,'bytes':len(raw_part),'sha256':sha(raw_part)})
 delivery={'schema':'ouf.storage-inventory-delivery.v1','producerSource':revision,'capsuleSha256':sha(capsule.read_bytes()),'backendSha256':sha(backend),'backendBytes':len(backend),'compressedBackendSha256':sha(compressed),'compressedBackendBytes':len(compressed),'parts':parts,'closedSourceCount':24,'original23SourcesUnchanged':True,'capsuleTamperDenied':True,'targetApplyAuthorized':False,'runtimeAuthorityIssued':False,'targetExecutionPreparedNotPerformed':True,'rootCredentialValuesSpooled':False}
 (output/'delivery.json').write_text(json.dumps(delivery,indent=2)+'\n');print(json.dumps(delivery))
if __name__=='__main__':
 assert os.environ.get('GITHUB_ACTIONS')=='true','CI_PACKAGE_ONLY'
 package(Path(sys.argv[1]),Path(sys.argv[2]),os.environ['GITHUB_SHA'])
