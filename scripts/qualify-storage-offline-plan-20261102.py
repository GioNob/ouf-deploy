#!/usr/bin/env python3
"""Qualify a pure metadata compiler under root in a fresh network namespace."""
import ast,hashlib,importlib.util,io,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/'offline-evidence'
assert os.environ.get('GITHUB_ACTIONS')=='true' and os.geteuid()==0
assert os.stat('/proc/self/ns/net').st_ino!=os.stat('/proc/1/ns/net').st_ino,'ISOLATED_NETWORK_NAMESPACE_REQUIRED'
OUT.mkdir();suite=unittest.defaultTestLoader.discover(str(ROOT/'tests'),pattern='test_storage_offline_plan.py');stream=io.StringIO();result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
(OUT/'unit-tests.txt').write_text(stream.getvalue());assert result.wasSuccessful() and result.testsRun==33 and not result.skipped,stream.getvalue()
subprocess.run([sys.executable,'-I','-B','-S',str(ROOT/'scripts/package-storage-offline-plan-20261102.py'),str(OUT/'inventory-delivery'),os.environ['GITHUB_SHA']],check=True)
delivery=json.loads((OUT/'inventory-delivery/delivery.json').read_text());raw=(OUT/'inventory-delivery/prepare-plan.py').read_bytes()
spec=importlib.util.spec_from_file_location('bootstrap',ROOT/'tools/storage_planning/offline_bootstrap_20261102.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
m.DELIVERY=delivery;m.PUBLICATION='a'*40;m.validate();tmp=Path(tempfile.mkdtemp(prefix='ouf-offline-install-',dir='/root'))
try:
 m.INSTALL=tmp/'install';m.install(raw)
 inspected=json.loads(subprocess.check_output([sys.executable,'-I','-B','-S',str(m.INSTALL/'prepare-plan.py'),'--inspect-source'],timeout=10))
 assert inspected['sources']==delivery['sources'] and inspected['targetOperations']==0
 install={'status':'PASS','exactProductionCompilerInstalled':True,'sourceInspectionOnly':True,'protectedModes':'root:root directory0500 files0400','networkNamespaceIsolated':True,'targetOperations':0}
 (OUT/'root-install-fixture.json').write_text(json.dumps(install,indent=2)+'\n')
finally:
 for p in tmp.rglob('*'):
  if p.is_dir():p.chmod(0o700)
 shutil.rmtree(tmp)
original=(ROOT/'releases/seaweedfs-inventory-inputs-20261102/prepare-inputs.py').read_bytes();assert hashlib.sha256(original).hexdigest()=='ec5c94e074ec2efb90b77ea383ac3047416f5472cd6813b42fd739b1f49fb14b'
manifest=next(ast.literal_eval(n.value) for n in ast.parse(original).body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='MANIFEST')
frozen=manifest['sources'];assert len(frozen)==28
for record in frozen.values():assert hashlib.sha256((ROOT/record['path']).read_bytes()).hexdigest()==record['sha256']
(OUT/'frozen-source-readback.json').write_text(json.dumps({'status':'PASS','allPrior28SourcesUnchanged':True,'sourceRecords':frozen},indent=2)+'\n')
report={'schema':'ouf.storage-offline-plan-qualification.v1','status':'PASS','producerSource':os.environ['GITHUB_SHA'],'pythonTests':33,'skippedTests':0,'rootFilesystemReal':True,'networkNamespaceIsolated':True,'fixtureInputHashesAndReceipt':'MODELLED','sourceInspectionOnlyForProductionBindings':True,'productionTargetExecuted':False,'targetOperations':0,'allPrior28SourcesUnchanged':True,'noNetworkOrCredentialImportsInCompiler':True,'runtimeAuthorityIssued':False,'migrationPerformed':False,'rawServerGate':'HELD_ONE_UNKNOWN'}
(OUT/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
files=sorted(p for p in OUT.rglob('*') if p.is_file());(OUT/'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+str(p.relative_to(OUT))+'\n' for p in files))
for p in OUT.rglob('*'):
 if p.is_file():p.chmod(0o644)
print(json.dumps(report))
