#!/usr/bin/env python3
"""Disposable MinIO -> exact OCI33 -> empty MinIO. No target/admission CLI."""
import argparse, hashlib, importlib.util, json, os, shutil, subprocess, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
MINIO='ghcr.io/datalens-tech/minio@sha256:a1a8bd4ac40ad7881a245bab97323e18f971e4d4cba2c2007ec1bedd21cbaba2'
MINIO_ID='sha256:69b2ec208575b69597784255eec6fa6a2985ee9e1a47f4411a51f7f5fdd193a9'
def load():
 spec=importlib.util.spec_from_file_location('rotation',ROOT/'scripts/run-storage-generation33-tls-rotation.py')
 module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def command(args,timeout=120):
 result=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
 if result.returncode:raise RuntimeError('COMMAND_FAILED '+args[0]+' '+result.stderr[-16000:])
 return result.stdout.strip()
def write(path,value):path.write_text(json.dumps(value,indent=2)+'\n')
def run(work,inputs):
 if os.environ.get('GITHUB_ACTIONS')!='true' or work.exists():raise ValueError('NEW_ISOLATED_CI_FIXTURE_REQUIRED')
 work.mkdir(mode=0o700);out=work/'evidence';out.mkdir()
 security=json.loads((inputs/'trivy-tools.json').read_text())
 if security.get('SchemaVersion')!=2 or len(security.get('Results',[]))<2:raise ValueError('TWO_TOOL_SCAN_RESULTS_REQUIRED')
 findings=[v for r in security['Results'] for v in r.get('Vulnerabilities',[]) or []]
 if any(v.get('Severity','UNKNOWN') in ['CRITICAL','HIGH','UNKNOWN'] for v in findings):raise ValueError('TOOL_SECURITY_GATE_HELD')
 shutil.copyfile(inputs/'trivy-tools.json',out/'trivy-tools.json')
 rotation=load();bound=rotation.binding(inputs/'bound-cohort/cohort-receipt.json')
 cold=rotation.labs.configured_harness('cold',bound)
 cold.prepare_image(inputs/'image.zip',work)
 command(['docker','pull',MINIO],300)
 if json.loads(command(['docker','image','inspect',MINIO]))[0]['Id']!=MINIO_ID:raise ValueError('EXACT_LEGACY_SOURCE_IMAGE_REQUIRED')
 config=work/'config';config.mkdir();tls=config/'tls';tls.mkdir()
 command(['openssl','req','-x509','-newkey','rsa:3072','-sha256','-nodes','-days','1','-subj','/CN=OUF synthetic migration','-addext','subjectAltName=IP:127.0.0.1','-keyout',str(tls/'private.key'),'-out',str(tls/'public.crt')])
 (tls/'private.key').chmod(0o600)
 (config/'filer.toml').write_text('[leveldb2]\nenabled = true\ndir = "/data/metadata"\n')
 write(config/'s3.json',{'identities':[{'name':'synthetic-destination-admin','credentials':[{'accessKey':'synthetic-destination-admin','secretKey':'synthetic-destination-secret-not-production'}],'actions':['Admin','Read','Write','List','Tagging']}]})
 bins=work/'bin';bins.mkdir()
 binary=bins/'copy.test';inventory=bins/'inventory';stage=work/'module'
 shutil.copytree(ROOT/'tools/storage_copy',stage)
 shutil.copyfile(ROOT/'tests/fixtures/storage-minio33/roundtrip_test.go',stage/'minio33_test.go')
 go=shutil.which('go');env=dict(os.environ,GOTOOLCHAIN='go1.27.3',GOMAXPROCS='2')
 subprocess.run([go,'test','-c','-o',str(binary)],cwd=stage,env=env,check=True,timeout=300)
 subprocess.run([go,'build','-trimpath','-o',str(inventory),'.'],cwd=ROOT/'tools/storage_inventory',env=env,check=True,timeout=300)
 command(['trivy','rootfs','--format','json','--output',str(out/'trivy-binaries.json'),'--list-all-pkgs','--scanners','vuln','--severity','UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL','--ignorefile',str(ROOT/'empty.trivyignore-minio33'),str(bins)],300)
 scan=json.loads((out/'trivy-binaries.json').read_text())
 if not scan.get('Results') or any(v.get('Severity','UNKNOWN') in ['CRITICAL','HIGH','UNKNOWN'] for r in scan['Results'] for v in r.get('Vulnerabilities',[]) or []):raise ValueError('BINARY_SECURITY_GATE_HELD')
 write(out/'executables.json',{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in bins.iterdir()})
 names=[];prefix='ouf-m33-'+os.environ['GITHUB_RUN_ID'];source=prefix+'-source';passed=[]
 try:
  for role,port,image in [('source',18441,MINIO_ID),('destination',18442,cold.IMAGE_ID),('return',18443,MINIO_ID)]:
   data=work/role;data.mkdir()
   if role=='destination':(data/'metadata').mkdir()
   name=prefix+'-'+role
   args=['docker','run','--detach','--name',name,'--network','none' if role=='source' else 'container:'+source,
         '--user',str(os.getuid())+':'+str(os.getgid()),'--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',
         '--pids-limit','256','--memory','1g','--cpus','2','--log-opt','max-size=8m',
         '--tmpfs','/tmp:rw,noexec,nosuid,size=67108864,mode=1777',
         '--mount','type=bind,src='+str(data)+',dst=/data','--mount','type=bind,src='+str(config)+',dst=/config,readonly']
   if role!='destination':
    args+=['--entrypoint','/usr/bin/minio','-e','MINIO_ROOT_USER=synthetic-source-admin','-e','MINIO_ROOT_PASSWORD=synthetic-source-secret-not-production','-e','MINIO_BROWSER=off']
    for key in ['MINIO_ROOT_USER_FILE','MINIO_ROOT_PASSWORD_FILE','MINIO_ACCESS_KEY_FILE','MINIO_SECRET_KEY_FILE']:
     args+=['-e',key+'=']
    args+=[image,'--certs-dir','/config/tls','server','--address','127.0.0.1:'+str(port),'--console-address','127.0.0.1:'+str(port+100),'/data']
   else:
    args+=['--workdir','/config',image,'-logtostderr=true','server','-ip=127.0.0.1','-ip.bind=127.0.0.1','-dir=/data',
           '-master.port=19332','-master.volumeSizeLimitMB=32','-volume.port=18082','-volume.max=128','-filer','-filer.port=18882',
           '-s3','-s3.port=9002','-s3.port.https=18442','-s3.cert.file=/config/tls/public.crt','-s3.key.file=/config/tls/private.key',
           '-s3.port.iceberg=0','-s3.port.lance=0','-s3.config=/config/s3.json']
   command(args);names.append(name)
  inspect=json.loads(command(['docker','inspect',*names]));pid=str(inspect[0]['State']['Pid'])
  for i,item in enumerate(inspect):
   host=item['HostConfig'];expected=MINIO_ID if i!=1 else cold.IMAGE_ID
   if item['Image']!=expected or not item['State']['Running'] or not host['ReadonlyRootfs'] or host['CapDrop']!=['ALL'] or host['PortBindings'] or host['Privileged']:raise ValueError('EXACT_ISOLATED_RUNNING_CONTAINERS_REQUIRED')
   if host['NetworkMode'] not in (['none'] if i==0 else ['container:'+source,'container:'+inspect[0]['Id']]):raise ValueError('CLOSED_SHARED_NETWORK_REQUIRED')
  net=['sudo','-n','nsenter','-t',pid,'-n']
  interfaces=json.loads(command(net+['ip','-j','link']));routes=json.loads(command(net+['ip','-j','route']))
  if [x['ifname'] for x in interfaces]!=['lo'] or routes:raise ValueError('NO_EXTERNAL_INTERFACE_OR_ROUTE_REQUIRED')
  write(out/'isolation.json',{'interfaces':interfaces,'routes':routes,'containers':[{'id':i['Id'],'image':i['Image'],'network':i['HostConfig']['NetworkMode'],'readOnly':i['HostConfig']['ReadonlyRootfs'],'capDrop':i['HostConfig']['CapDrop'],'portBindings':i['HostConfig']['PortBindings']} for i in inspect],'legacySourceProductionSecurityGate':'HELD_UNCHANGED','publisherAuthenticatedForLegacyMinio':False,'syntheticOnly':True})
  readiness='import socket,time\nend=time.monotonic()+90\nfor port in (18441,18442,18443):\n while True:\n  try:\n   s=socket.create_connection(("127.0.0.1",port),1);s.close();break\n  except OSError:\n   if time.monotonic()>end:raise\n   time.sleep(1)\n'
  command(net+['python3','-I','-B','-S','-c',readiness],100)
  tmp=work/'temporaries';tmp.mkdir(mode=0o700)
  settings={'GITHUB_ACTIONS':'true','OUF_COPY_LAB':'1','OUF_COPY_SOURCE':'https://127.0.0.1:18441','OUF_COPY_DESTINATION':'https://127.0.0.1:18442','OUF_COPY_RETURN':'https://127.0.0.1:18443','OUF_COPY_DEST_HTTP':'http://127.0.0.1:9002','OUF_COPY_CA':str(tls/'public.crt'),'OUF_COPY_INVENTORY_BINARY':str(inventory),'OUF_COPY_COMPILER':str(ROOT/'tools/storage_planning/inventory_manifest.py'),'OUF_COPY_RECEIPT':str(out/'roundtrip.json'),'TMPDIR':str(tmp),'GOMAXPROCS':'2'}
  cases=['TestRealFunctionalReadiness','TestMinio33RoundTrip','TestMinio33PostWriteReturn','TestRealProcessCrashResumeNoSecondPut','TestRealAmbiguous503RespectsRetryAfterAndReconciles','TestRealTagsAndEncodingPreserved','TestRealSourceIfMatchAndVersionedDestinationDenials']
  for case in cases:
   path=out/(case+'.jsonl')
   with path.open('w') as log:
    result=subprocess.run(net+['setpriv','--reuid',str(os.getuid()),'--regid',str(os.getgid()),'--clear-groups','env',*[k+'='+v for k,v in settings.items()],go,'tool','test2json','-t','-p','ouf/minio33',str(binary),'-test.v','-test.run=^'+case+'$','-test.timeout=5m'],stdout=log,stderr=subprocess.STDOUT,timeout=330)
   rows=[json.loads(line) for line in path.read_text().splitlines()]
   if result.returncode or any(r.get('Action') in ['fail','skip'] for r in rows) or not any(r.get('Action')=='pass' and r.get('Test')==case for r in rows):raise ValueError('NATIVE_CASE_FAILED:'+case)
   passed += [r['Test'] for r in rows if r.get('Action')=='pass' and 'Test' in r]
  command(['sudo','-n','chown',str(os.getuid())+':'+str(os.getgid()),str(out/'roundtrip.json')])
  write(out/'qualification.json',{'schema':'ouf.minio-oci33-rehearsal.v1','status':'PASS_SYNTHETIC_NOT_ACCEPTANCE','producerSource':os.environ['GITHUB_SHA'],'sourceImage':MINIO_ID,'destinationImage':cold.IMAGE_ID,'candidateLockSha256':rotation.LOCK_SHA,'passedTests':passed,'realProcessCrashPoints':['BEFORE_PUT','AFTER_PUT','BEFORE_CHECKPOINT'],'destinationPutsPerCrashCase':1,'ambiguous503AfterStoreReconciledWithoutSecondPut':True,'retryAfterQualifiedWithVirtualClock':True,'runtimeAuthorityIssued':False,'targetOperations':0,'gatesClosed':0,'realObjectsCopied':0})
 finally:
  stop_errors=[]
  for name in reversed(names):
   log=subprocess.run(['docker','logs',name],capture_output=True,timeout=30)
   (out/(name+'.log')).write_bytes((log.stdout+log.stderr)[-49152:])
   stopped=subprocess.run(['docker','stop','--time','30',name],capture_output=True,timeout=45)
   state=json.loads(command(['docker','inspect',name]))[0]['State'];write(out/(name+'-exit.json'),state)
   command(['docker','rm',name])
   if stopped.returncode or state['OOMKilled']:stop_errors.append(name)
  if stop_errors:raise ValueError('FIXTURE_STOP_FAILED:'+','.join(stop_errors))

def seal(work,inputs):
 out=work/'evidence';out.mkdir(parents=True,exist_ok=True)
 for name in ['cohort-publisher-verification.json','bound-cohort/cohort-receipt.json']:
  source=inputs/name
  if source.is_file():shutil.copyfile(source,out/Path(name).name)
 paths=subprocess.check_output(['git','ls-files'],cwd=ROOT,text=True).splitlines()
 sources={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in paths if p.startswith(('tools/storage_copy/','tools/storage_inventory/','tools/storage_security/','tools/storage_planning/')) or p.startswith('scripts/') and ('storage' in p or 'seaweedfs' in p) or p in ['tests/fixtures/storage-minio33/roundtrip_test.go','.github/workflows/storage-minio33-rehearsal.yml']}
 write(out/'source-sha256.json',sources)
 (out/'source-commit.txt').write_text(os.environ['GITHUB_SHA']+'\n')
 total=0
 for path in out.iterdir():
  if path.is_symlink() or not path.is_file():raise ValueError('REGULAR_EVIDENCE_REQUIRED')
  raw=path.read_bytes();total+=len(raw)
  if len(raw)>16*1024*1024 or total>64*1024*1024 or b'-----BEGIN PRIVATE KEY' in raw or b'-----BEGIN RSA PRIVATE KEY' in raw:raise ValueError('PUBLIC_BOUNDED_EVIDENCE_REQUIRED')
 (out/'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in sorted(out.iterdir()) if p.name!='SHA256SUMS'))
if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('action',choices=['run','seal']);parser.add_argument('work',type=Path);parser.add_argument('inputs',type=Path);args=parser.parse_args()
 globals()[args.action](args.work.resolve(),args.inputs.resolve())
