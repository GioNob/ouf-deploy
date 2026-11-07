#!/usr/bin/env python3
"""Root CI fixture of installation using the exact independently verified artifact.

No network, Docker, target scope creation or execution of the target reader.
"""
import hashlib,importlib.util,json,os,shutil,subprocess,sys,tempfile,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
assert os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true','ROOT_CI_FIXTURE_ONLY'
spec=importlib.util.spec_from_file_location('bootstrap',ROOT/'tools/storage_migration/inventory_bootstrap.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
temporary=Path(tempfile.mkdtemp(prefix='ouf-inventory-install-',dir='/root'))
try:
 with zipfile.ZipFile(sys.argv[1]) as z:
  m.DELIVERY=json.loads(z.read('inventory-delivery/delivery.json'));m.PUBLICATION='a'*40;m.validate_delivery()
  binary,capsule=m.assemble(lambda name,limit:z.read('inventory-delivery/'+name))
 m.INSTALL=temporary/'reader';m.install(binary,capsule)
 result=json.loads(subprocess.check_output(['/usr/bin/python3','-I','-B','-S',str(m.INSTALL/'prepare-storage-inventory.py'),'--inspect-source'],timeout=60))
 assert result['sourceCount']==24 and result['runtimeAuthorityIssued'] is False
 assert hashlib.sha256((m.INSTALL/'inventory').read_bytes()).hexdigest()==m.DELIVERY['backendSha256']
 m.INSTALL.chmod(0o700);unknown=m.INSTALL/'unknown';unknown.write_text('preserve')
 try:m.install(binary,capsule)
 except ValueError as e:assert str(e)=='NEW_READER_INSTALL_REQUIRED'
 else:raise AssertionError('EXISTING_INSTALL_OVERWRITE')
 assert unknown.read_text()=='preserve'
 report={'status':'PASS','exactArtifactExecutableInstalledInRootFixture':True,'sourceInspectionOnly':True,'sourceCount':24,'existingInstallDenied':True,'unknownFilePreserved':True,'targetScopeCreated':False,'targetOperations':0,'targetApplyAuthorized':False}
 Path(sys.argv[2]).write_text(json.dumps(report,indent=2)+'\n');Path(sys.argv[2]).chmod(0o644)
finally:
 for p in temporary.rglob('*'):
  if p.is_dir():p.chmod(0o700)
 shutil.rmtree(temporary)
