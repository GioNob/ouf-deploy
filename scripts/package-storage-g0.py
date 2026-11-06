#!/usr/bin/env python3
"""Build a reviewable operator package; qualify only the new host/assembly path."""
import argparse,hashlib,io,json,os,shutil,subprocess,sys,tarfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from tools.storage_planning.inventory_manifest import canonical,decode,require,sha
from tools.storage_planning.g0_host import Engine,ROLES,snapshot,capacity
from tools.storage_planning.g0_package import LIMITS,OPERATOR,verify_package
MINIO='ghcr.io/datalens-tech/minio@sha256:a1a8bd4ac40ad7881a245bab97323e18f971e4d4cba2c2007ec1bedd21cbaba2'
def cmd(args,cwd=None,timeout=180):
 r=subprocess.run(args,cwd=cwd,capture_output=True,text=True,timeout=timeout);require(r.returncode==0,'PACKAGE_COMMAND_FAILED:'+args[0]+':'+r.stderr[-1000:]);return r.stdout.strip()
def write(p,x):p.write_bytes(canonical(x))
def build(w):
 require(not w.exists(),'NEW_PACKAGE_WORK');w.mkdir(mode=0o700);out=w/'evidence';out.mkdir();bundle=w/'package';bundle.mkdir();(bundle/'bin').mkdir();(bundle/'tools/storage_planning').mkdir(parents=True)
 profile_path='releases/storage-g0-package-profile-20261105.json';profile=decode((ROOT/profile_path).read_bytes())
 write(out/'component-bindings.json',{p:{'expected':h,'observed':sha((ROOT/p).read_bytes())} for p,h in profile['qualifiedSourceSha256'].items()})
 require(all(sha((ROOT/p).read_bytes())==h for p,h in profile['qualifiedSourceSha256'].items()),'QUALIFIED_COMPONENT_BYTES_UNCHANGED')
 with (out/'network-tests.log').open('w') as log:subprocess.run(['sudo','-n','env','GITHUB_ACTIONS=true',sys.executable,'-m','unittest','discover','-s','tests','-p','test_storage_g0_network.py','-v'],cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=60)
 with (out/'tests.log').open('w') as log:subprocess.run([sys.executable,'-m','unittest','discover','-s','tests','-p','test_storage_g0_package.py','-v'],cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=60)
 sourcefiles=['tools/storage_planning/'+n for n in ['g0_host.py','g0_package.py','g0_network.py','g0_database.py','g0_reconciliation.py','inventory_manifest.py']]
 for f in sourcefiles:shutil.copyfile(ROOT/f,bundle/f)
 cmd(['go','build','-buildvcs=false','-trimpath','-o',str(bundle/'bin/inventory'),'.'],ROOT/'tools/storage_inventory',300)
 (bundle/'launch.py').write_text("import sys\nfrom pathlib import Path\nroot=Path(__file__).resolve().parent\nsys.path.insert(0,str(root))\nfrom tools.storage_planning.g0_package import main\nraise SystemExit(main(root))\n")
 (bundle/'network-worker.py').write_text("import sys\nfrom pathlib import Path\nroot=Path(__file__).resolve().parent\nsys.path.insert(0,str(root))\nfrom tools.storage_planning.g0_network import worker_main\nraise SystemExit(worker_main(root))\n")
 template={'schema':'ouf.storage-g0-package-input.v2','networkBindingFile':'/var/lib/ouf/g0/inputs/network.json','operationId':None,'installationRef':None,'outputParent':'/var/lib/ouf/g0/evidence','roles':{r:{'containerId':None,'nativeImage':None} for r in ROLES},'capacityPaths':dict.fromkeys(['source','destination','backup']),'connectionFiles':{r:'/var/lib/ouf/g0/inputs/'+r+'.json' for r in ['s3','onboarding','udp','ingestion']},'operatorEvidenceFiles':dict.fromkeys(OPERATOR),'priorReceiptFiles':[{'control':i,'path':None,'sha256':None} for i in range(1,18)],'collectionDecisionRef':None};write(bundle/'input-template.json',template)
 shutil.copyfile(ROOT/'docs/OUF_STORAGE_G0_NETWORK_20261106.md',bundle/'README.md')
 shutil.copyfile(ROOT/'docs/OUF_STORAGE_G0_OPERATOR_PACKAGE_20261105.md',bundle/'HOST_PROFILE.md')
 shutil.copyfile(ROOT/'docs/OUF_STORAGE_G0_COLLECTORS_20261105.md',bundle/'OUF_STORAGE_G0_COLLECTORS_20261105.md')
 shutil.copyfile(ROOT/profile_path,bundle/'component-profile.json')
 files={str(p.relative_to(bundle)):sha(p.read_bytes()) for p in sorted(bundle.rglob('*')) if p.is_file()}
 m={'schema':'ouf.storage-g0-package.v1','deployCommit':os.environ['GITHUB_SHA'],'files':files,'limits':LIMITS,'runtimeAuthorityIssued':False,'qualifiedComponents':{'bodyCommit':'f4b4152f78af7ca5a220714b517a458de5c494cc','bodyRunId':42111278483,'databaseCommit':'60a97c3a55da66e110953ba113b210c1d74dd1a2','databaseRunId':42114275442},'targetBindingsPresent':False,'targetCommandAuthorized':False};write(bundle/'package-manifest.json',m)
 md=sha((bundle/'package-manifest.json').read_bytes());verify_package(bundle,md)
 # Only executable entry/denial smoke; no repeated S3/PG provider laboratory.
 result=subprocess.run([str(bundle/'bin/inventory'),'g0-collect',str(w/'absent-config'),str(w/'must-not-exist')],capture_output=True,timeout=10)
 require(result.returncode!=0 and decode(result.stdout)['complete'] is False and not (w/'must-not-exist').exists(),'COMPILED_COLLECTOR_DENIAL_SMOKE')
 sourcefiles += [str(p.relative_to(ROOT)) for p in (ROOT/'tools/storage_inventory').iterdir() if p.suffix=='.go' or p.name in ['go.mod','go.sum']]
 module=w/'fixture-module';module.mkdir();scan=w/'scan';scan.mkdir();shutil.copyfile(bundle/'bin/inventory',scan/'inventory')
 for f in (ROOT/'tools/storage_inventory').iterdir():
  if f.suffix=='.go' or f.name in ('go.mod','go.sum'):shutil.copyfile(f,module/f.name)
 shutil.copyfile(ROOT/'tests/fixtures/storage-g0-network/seed_test.go',module/'network_seed_test.go');cmd(['go','test','-c','-o',str(scan/'seed.test')],module,300)
 write(out/'scan-executables.json',{p.name:sha(p.read_bytes()) for p in scan.iterdir()})
 sourcefiles += ['tools/storage_planning/g0_network.py','scripts/qualify-storage-g0-network-20261106.py','tests/test_storage_g0_network.py','tests/fixtures/storage-g0-network/seed_test.go','tests/fixtures/storage-g0-db/seed.sql','docs/OUF_STORAGE_G0_NETWORK_20261106.md']
 sourcefiles += ['scripts/package-storage-g0.py','tests/test_storage_g0_package.py','tests/test_storage_g0_database.py','.github/workflows/storage-g0-package.yml','docs/OUF_STORAGE_G0_OPERATOR_PACKAGE_20261105.md','docs/OUF_STORAGE_G0_COLLECTORS_20261105.md',profile_path]
 sources={p:ROOT/p for p in set(sourcefiles)};commits={'deploy':os.environ['GITHUB_SHA']}
 for repo,directory,expected in [('ouf-source-onboarding','onboarding-source','d5155899b09dda298494b68cefa7e1f281167652'),('ouf-udp-object-resolution','udp-source','0d40da05408a14db31d4d41af2372d6a71480291'),('ouf-ingestion-runtime','ingestion-source','4165b9e149be467d5d7c6bed35e4e1af4e249db1')]:
  require(cmd(['git','-C',str(ROOT/directory),'rev-parse','HEAD'])==expected,'EXACT_MIGRATION_SOURCE');commits[repo]=expected
  for f in (ROOT/directory/'src/main/resources/db/migration').glob('V*.sql'):sources[repo+'/'+str(f.relative_to(ROOT/directory))]=f
 write(out/'source-commits.json',commits);write(out/'source-sha256.json',{p:sha(f.read_bytes()) for p,f in sorted(sources.items())})
 with tarfile.open(out/'sources.tar.gz','w:gz') as t:
  for p,f in sorted(sources.items()):t.add(f,arcname=p,recursive=False)
 write(out/'build.json',{'schema':'ouf.storage-g0-package-build.v1','deployCommit':os.environ['GITHUB_SHA'],'goVersion':cmd(['go','version']),'manifestSha256':md,'inventorySha256':files['bin/inventory'],'files':len(files),'compiledWithBuildVcsFalse':True,'providerLaboratoriesRepeated':False,'newNamespaceCompositionQualificationRequired':True,'targetOperations':0})
def native(w):
 require(os.environ.get('GITHUB_ACTIONS')=='true','DISPOSABLE_CI_ONLY');out=w/'evidence';scan=decode((out/'trivy.json').read_bytes());require(any(Path(x['Target']).name=='inventory' and x.get('Type')=='gobinary' for x in scan.get('Results',[])),'PACKAGED_BINARY_SCAN_REQUIRED');require(not any(v.get('Severity','UNKNOWN') in ('HIGH','CRITICAL','UNKNOWN') for x in scan['Results'] for v in x.get('Vulnerabilities',[]) or []),'PACKAGED_TOOL_SECURITY_HELD')
 cmd(['docker','pull',MINIO],timeout=300);name='g0-package-'+os.environ['GITHUB_RUN_ID'];created=False
 try:
  identifier=cmd(['docker','create','--name',name,'--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--entrypoint','/not-executed','-e','PASSWORD=fixture-secret-must-not-export','-e','OUF_UDP_S3_BUCKET=fixture-bucket',MINIO]);created=True
  doc=json.loads(cmd(['docker','inspect',identifier]))[0];scope=w/'host-private';scope.mkdir(mode=0o700);e=Engine(scope);roles={'fixture':{'containerId':identifier,'nativeImage':doc['Image']}}
  first=snapshot(e,roles);second=snapshot(e,roles);require(first==second and not first['findings'] and first['roles']['fixture']['running'] is False,'CURRENT_STOPPED_HOST_OBSERVATIONS');require(b'fixture-secret-must-not-export' not in canonical(first),'HOST_SECRET_REDACTION')
  before=e.requests
  try:e.get('/containers/'+identifier+'/start');raise AssertionError('mutation path admitted')
  except ValueError:pass
  require(e.requests==before,'MUTATION_PATH_NO_RESERVATION')
  c=capacity({k:str(w) for k in ['source','destination','backup']});require(not c['independentFailureDomainsProven'] and not c['growthOrThroughputProven'],'CAPACITY_NOT_ADMISSION')
  write(out/'native-host.json',{'schema':'ouf.storage-g0-package-host-native.v1','status':'PASS_DISPOSABLE_HOST_OBSERVATION_ONLY','requestsReserved':e.requests,'engineBytes':e.bytes,'containersObserved':len(first['containers']),'beforeAfterEqual':True,'stoppedContainerObservedWithoutStarting':True,'secretValuesRedacted':True,'mutationPathDeniedBeforeNetwork':True,'capacityObservedWithoutIndependenceInference':True,'fixtureCreates':1,'fixtureStarts':0,'fullS3DbCompositionNativeRerun':False,'targetOperations':0,'runtimeAuthorityIssued':False})
 finally:
  if created:cmd(['docker','rm',identifier])
def seal(w):
 out=w/'evidence';bundle=w/'package'
 if not (out/'build.json').is_file():
  out.mkdir(parents=True,exist_ok=True);write(out/'delivery.json',{'status':'HELD_BUILD_INCOMPLETE_NO_OPERATOR_PACKAGE','deployCommit':os.environ['GITHUB_SHA'],'targetCommandAuthorized':False,'targetOperations':0});(out/'SHA256SUMS').write_text(''.join(sha(p.read_bytes())+'  '+p.name+'\n' for p in sorted(out.iterdir()) if p.name!='SHA256SUMS'));return
 build=decode((out/'build.json').read_bytes());verify_package(bundle,build['manifestSha256'])
 with tarfile.open(out/'operator-package.tar.gz','w:gz') as t:
  for p in sorted(bundle.rglob('*')):
   if p.is_file():t.add(p,arcname=str(p.relative_to(bundle)),recursive=False)
 raw=(out/'operator-package.tar.gz').read_bytes();write(out/'delivery.json',{'schema':'ouf.storage-g0-package-delivery.v1','packageSha256':sha(raw),'packageBytes':len(raw),'manifestSha256':build['manifestSha256'],'deployCommit':build['deployCommit'],'inputTemplateIsNotFilled':True,'targetOperations':0,'runtimeAuthorityIssued':False,'targetCommandAuthorized':False})
 (out/'SHA256SUMS').write_text(''.join(sha(p.read_bytes())+'  '+p.name+'\n' for p in sorted(out.iterdir()) if p.name!='SHA256SUMS'))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('action',choices=['build','native','seal']);p.add_argument('work',type=Path);a=p.parse_args();globals()[a.action](a.work.resolve())
