#!/usr/bin/env python3
"""Package one corrective capsule; the original reader and all old scopes stay intact."""
import ast,base64,hashlib,json,os,re,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def package(output,revision):
 original=(ROOT/'releases/seaweedfs-inventory-reconciliation-20261102/prepare-reconciliation.py').read_text()
 assert sha(original.encode())=='16e98072a5a1eb0cba56a53de774cfb76dd32befd681a456ef669e244ae68285'
 values={n.targets[0].id:ast.literal_eval(n.value) for n in ast.parse(original).body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id in ['MANIFEST','PAYLOAD']}
 sources=json.loads(base64.b64decode(values['PAYLOAD']));manifest_sources={}
 for name,record in values['MANIFEST']['sources'].items():
  assert sha(sources[name].encode())==record['sha256']==sha((ROOT/record['path']).read_bytes());manifest_sources[name]=record
 for module in ['minio_credential_binding','target_inventory_credentials']:
  name='tools.storage_migration.'+module;body=(ROOT/('tools/storage_migration/'+module+'.py')).read_text();sources[name]=body
  manifest_sources[name]={'path':'tools/storage_migration/'+module+'.py','sha256':sha(body.encode())}
 raw=canonical(sources);assert len(raw)<=294912 and len(sources)==26
 tail=original[original.index('\ndef require(ok):'):].replace('0<len(raw)<=262144','0<len(raw)<=294912')
 manifest={'schema':'ouf.storage-credential-continuation-capsule.v1','entryModule':name,'sources':manifest_sources,'sourceRevisionClaim':revision,'payloadSha256':sha(raw),'sourceMapSha256':sha(canonical(manifest_sources)),'loaderTemplateSha256':sha(tail.encode()),'original23SourcesUnchanged':True,'allPrior24SourcesUnchanged':True,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False}
 script='#!/usr/bin/env python3\nimport base64,hashlib,importlib.abc,importlib.util,json,os,sys\nMANIFEST='+repr(manifest)+'\nPAYLOAD='+repr(base64.b64encode(raw).decode())+tail
 output.mkdir();capsule=output/'prepare-credentials.py';capsule.write_text(script)
 inspected=json.loads(subprocess.check_output([sys.executable,'-I','-B','-S',str(capsule),'--inspect-source'],timeout=30));assert inspected['sourceCount']==26 and not inspected['runtimeAuthorityIssued']
 bad=output/'tampered.py';bad.write_text(script.replace("PAYLOAD='","PAYLOAD='A",1));denied=subprocess.run([sys.executable,'-I','-B','-S',str(bad),'--inspect-source'],capture_output=True,timeout=30);assert denied.returncode!=0;bad.unlink()
 profile=next(ast.literal_eval(n.value) for n in ast.parse(body).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='PROFILE' for t in n.targets))
 delivery={'schema':'ouf.storage-credentials-delivery.v1','producerSource':revision,'capsuleSha256':sha(capsule.read_bytes()),'capsuleBytes':capsule.stat().st_size,'backendSha256':'430631fe4dfd1b844229637373ea176c2e84e81e1491919f4a25cc36c68359a8','backendPath':'/usr/local/lib/ouf-storage-inventory-20261102/inventory','installPath':'/usr/local/lib/ouf-storage-inventory-credentials-20261102','scopePath':'/etc/ouf/deploy-snapshots/seaweedfs-inventory-credentials-20261102-v1','controlProfile':profile,'closedSourceCount':26,'original23SourcesUnchanged':True,'allPrior24SourcesUnchanged':True,'payloadBytes':len(raw),'capsuleTamperDenied':True,'oldReaderReinstalled':False,'oldScopeRearmed':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False}
 (output/'delivery.json').write_text(json.dumps(delivery,indent=2)+'\n');print(json.dumps(delivery))
if __name__=='__main__':package(Path(sys.argv[1]),sys.argv[2])
