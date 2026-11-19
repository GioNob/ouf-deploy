#!/usr/bin/env python3
"""Independent artifact check. No target entry invocation except source inspection."""
import ast,hashlib,importlib.util,json,subprocess,sys,tempfile,zipfile
from pathlib import Path,PurePosixPath
ROOT=Path(__file__).resolve().parents[1]
def sha(raw):return hashlib.sha256(raw).hexdigest()
def verify(path,expected,producer):
 assert sha(path.read_bytes())==expected,'EXACT_QUALIFICATION_ZIP_REQUIRED'
 with zipfile.ZipFile(path) as z:
  names=z.namelist();assert len(names)==len(set(names)) and all(str(PurePosixPath(n))==n and not n.startswith('/') and '..' not in PurePosixPath(n).parts for n in names)
  assert sum(i.file_size for i in z.infolist())<=4194304
  prefix='offline-evidence/' if 'offline-evidence/SHA256SUMS' in names else ''
  read=lambda n:z.read(prefix+n)
  sums={}
  for line in read('SHA256SUMS').decode().splitlines():
   digest,name=line.split('  ',1);assert name not in sums;sums[name]=digest
  assert set(names)=={prefix+n for n in [*sums,'SHA256SUMS','provenance.json']}
  for name,digest in sums.items():assert sha(read(name))==digest
  assert set(sums)=={'inventory-delivery/delivery.json','inventory-delivery/prepare-plan.py','qualification.json','root-install-fixture.json','frozen-source-readback.json','unit-tests.txt'}
  q=json.loads(read('qualification.json'));d=json.loads(read('inventory-delivery/delivery.json'));installed=json.loads(read('root-install-fixture.json'))
  assert q['status']=='PASS' and q['producerSource']==d['producerSource']==producer
  assert q['pythonTests']==33 and q['skippedTests']==0 and q['networkNamespaceIsolated'] and q['rootFilesystemReal']
  assert q['fixtureInputHashesAndReceipt']=='MODELLED' and not q['productionTargetExecuted'] and q['targetOperations']==0 and q['allPrior28SourcesUnchanged']
  assert installed['status']=='PASS' and installed['exactProductionCompilerInstalled'] and installed['sourceInspectionOnly']
  assert d['controlAttempt']==17 and d['previousControlAttempts']==16 and d['previousEngineGets']==52
  assert d['newEngineGets']==d['newS3Requests']==d['credentialFileReads']==d['objectBodiesRead']==0
  assert d['oldScopeRearmed'] is d['runtimeAuthorityIssued'] is d['targetApplyAuthorized'] is False
  spec=importlib.util.spec_from_file_location('package',ROOT/'scripts/package-storage-offline-plan-20261102.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
  receipt=json.loads((ROOT/'evidence/seaweedfs-private-baseline-target-20261102.json').read_text());body,sources=m.build(receipt)
  raw=read('inventory-delivery/prepare-plan.py');assert raw==body.encode() and sha(raw)==d['capsuleSha256'] and len(raw)==d['capsuleBytes'] and d['sources']==sources and d['sourceCount']==2
  assert d['sourceInventorySha256']==receipt['privateInventorySha256']=='43571bb43921f74adfa5974a0903acb54ee1eadecbc9d5d0d70539ce5cadba55'
  frozen=json.loads(read('frozen-source-readback.json'));assert frozen['status']=='PASS' and frozen['allPrior28SourcesUnchanged'] and len(frozen['sourceRecords'])==28
  original=(ROOT/'releases/seaweedfs-inventory-inputs-20261102/prepare-inputs.py').read_bytes();assert sha(original)=='ec5c94e074ec2efb90b77ea383ac3047416f5472cd6813b42fd739b1f49fb14b'
  old=next(ast.literal_eval(n.value) for n in ast.parse(original).body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='MANIFEST')
  assert frozen['sourceRecords']==old['sources']
  for record in frozen['sourceRecords'].values():assert sha((ROOT/record['path']).read_bytes())==record['sha256']
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp)/'compiler.py';p.write_bytes(raw);info=json.loads(subprocess.check_output([sys.executable,'-I','-B','-S',str(p),'--inspect-source'],timeout=10));assert info['sources']==sources and info['targetOperations']==0
  return {'status':'PASS','producerSource':producer,'artifactSha256':expected,'checksumMembers':len(sums),'sourceCount':2,'allPrior28SourcesUnchanged':True,'pythonTests':33,'rootFilesystemReal':True,'networkNamespaceIsolated':True,'fixtureInputHashesAndReceipt':'MODELLED','sourceInspectionOnly':True,'targetOperations':0,'publisherVerified':False,'publisherVerificationRequiredFromSeparateStep':True}
if __name__=='__main__':print(json.dumps(verify(Path(sys.argv[1]),sys.argv[2],sys.argv[3]),indent=2))
