#!/usr/bin/env python3
"""Root CI installation of exact corrective capsule, reusing exact old SDK bytes."""
import importlib.util,json,os,shutil,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
assert os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'
spec=importlib.util.spec_from_file_location('bootstrap',ROOT/'tools/storage_migration/inventory_credentials_bootstrap.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
source=Path(sys.argv[1]);out=Path(sys.argv[2]);tmp=Path(tempfile.mkdtemp(prefix='ouf-correction-install-',dir='/root'))
try:
 m.DELIVERY=json.loads((source/'delivery.json').read_text());m.PUBLICATION='a'*40;m.validate()
 original=tmp/'original';original.mkdir(mode=0o500);original.chmod(0o700);backend=original/'inventory';shutil.copyfile(ROOT/'sw-evaluation/bin/storage-inventory',backend);backend.chmod(0o500);original.chmod(0o500)
 m.BACKEND=backend;m.existing_reader();before=backend.read_bytes()
 m.INSTALL=tmp/'correction';m.install((source/'prepare-credentials.py').read_bytes())
 inspected=json.loads(subprocess.check_output(['/usr/bin/python3','-I','-B','-S',str(m.INSTALL/'prepare-credentials.py'),'--inspect-source'],timeout=30));assert inspected['sourceCount']==26 and not inspected['runtimeAuthorityIssued'] and backend.read_bytes()==before
 out.write_text(json.dumps({'status':'PASS','sourceCount':26,'exactOriginalSdkReused':True,'originalReaderBytesPreserved':True,'newInstallContainsOnlyCapsuleAndManifest':True,'sourceInspectionOnly':True,'targetOperations':0,'oldScopeRearmed':False},indent=2)+'\n');out.chmod(0o644)
finally:
 for p in tmp.rglob('*'):
  if p.is_dir():p.chmod(0o700)
 shutil.rmtree(tmp)
