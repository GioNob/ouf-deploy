#!/usr/bin/env python3
"""Run original OUF adapters against a loopback-only disposable real server."""
import hashlib
import fcntl
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import time
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'sw-evaluation'
FIXTURE=ROOT/'tests/fixtures/seaweedfs-contract'
SOURCES={
 'onboarding-source':('73498c17596ae155a3ed9ab36acfd6bb69da9846',[
 'it/comune/trieste/ouf/onboarding/application/ManagedFileStagingStore.java',
 'it/comune/trieste/ouf/onboarding/application/MinioManagedFileStagingStore.java',
 'it/comune/trieste/ouf/onboarding/domain/DomainFailure.java']),
 'udp-source':('0d40da05408a14db31d4d41af2372d6a71480291',[
 'it/comune/trieste/ouf/udp/LakeObjectStoragePort.java',
 'it/comune/trieste/ouf/udp/S3LakeObjectStorageAdapter.java'])}
assert os.environ.get('GITHUB_ACTIONS')=='true','CI_ONLY'
candidate=json.loads((OUT/'candidate.json').read_text())
assert candidate['securityGate']=='PASS' or candidate.get('isolatedLabEligible') is True
assert hashlib.sha256((OUT/'bin/weed').read_bytes()).hexdigest()==candidate['binarySha256']
records=[]
for directory,(commit,files) in SOURCES.items():
 source=ROOT/directory
 assert subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip()==commit
 for file in files:
  origin=source/'src/main/java'/file;dest=FIXTURE/'src/main/java'/file
  dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(origin,dest)
  records.append({'repositoryDirectory':directory,'commit':commit,'path':file,'sha256':hashlib.sha256(origin.read_bytes()).hexdigest()})
(OUT/'adapter-source-inventory.json').write_text(json.dumps(records,indent=2)+'\n')
audit=[]
for directory,(commit,_) in SOURCES.items():
 source=ROOT/directory
 paths=subprocess.check_output(['git','-C',str(source),'ls-tree','-r','--name-only',commit],text=True).splitlines()
 for relative in paths:
  if not relative.startswith(('src/','scripts/','.github/','config/')) and relative!='pom.xml':continue
  path=source/relative
  if not path.is_file() or path.stat().st_size>262144:continue
  text=path.read_text(errors='replace')
  lines=[i for i,line in enumerate(text.splitlines(),1) if any(word in line.lower() for word in ['minio','s3client','lake.s3','onboarding.staging','presigned','objectstorage'])]
  if lines:audit.append({'repositoryDirectory':directory,'commit':commit,'path':relative,'matchingLines':lines,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
(OUT/'public-consumer-audit.json').write_text(json.dumps({'scope':'Onboarding and UDP exact selected public generations only','targetInventoryComplete':False,'files':audit},indent=2)+'\n')

lab=OUT/'lab';lab.mkdir();(lab/'data').mkdir();(lab/'metadata').mkdir()
(lab/'filer.toml').write_text('[leveldb2]\nenabled = true\ndir = "'+str(lab/'metadata')+'"\n')
# Synthetic self-signed certificate, explicitly trusted only for this loopback test.
subprocess.run(['openssl','req','-x509','-newkey','rsa:3072','-sha256','-nodes','-keyout',str(lab/'tls.key'),'-out',str(lab/'tls.crt'),'-days','1','-subj','/CN=ouf-sw-lab','-addext','subjectAltName=IP:127.0.0.1'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
subprocess.run(['keytool','-importcert','-noprompt','-alias','ouf-sw-lab','-file',str(lab/'tls.crt'),'-keystore',str(lab/'trust.p12'),'-storetype','PKCS12','-storepass','synthetic-lab-password'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
java_env=dict(os.environ,OUF_SW_ENDPOINT='https://127.0.0.1:18443',JAVA_TOOL_OPTIONS='-Djavax.net.ssl.trustStore='+str(lab/'trust.p12')+' -Djavax.net.ssl.trustStorePassword=synthetic-lab-password')
identities=[]
for name,actions in [('admin',['Admin','Read','Write','List','Tagging']),('staging',['Read:ouf-managed-files','Write:ouf-managed-files']),('udp',['Read:ouf-udp','Write:ouf-udp','List:ouf-udp'])]:
 identities.append({'name':'lab-'+name,'credentials':[{'accessKey':'lab-'+name,'secretKey':'lab-'+name+'-secret-not-production'}],'actions':actions})
(lab/'s3.json').write_text(json.dumps({'identities':identities}))
# No ports exposed outside loopback. Synthetic fixtures only; this is not the target TLS/IAM profile.
args=[str(OUT/'bin/weed'),'server','-ip=127.0.0.1','-ip.bind=127.0.0.1','-dir='+str(lab/'data'),'-master.port=19333','-master.volumeSizeLimitMB=32','-volume.port=18080','-volume.max=20','-filer','-filer.port=18888','-s3','-s3.port=9000','-s3.port.https=18443','-s3.cert.file='+str(lab/'tls.crt'),'-s3.key.file='+str(lab/'tls.key'),'-s3.port.iceberg=0','-s3.port.lance=0','-s3.config='+str(lab/'s3.json')]
with (OUT/'server.log').open('w') as log:
 proc=subprocess.Popen(args,cwd=lab,stdout=log,stderr=subprocess.STDOUT)
 try:
  for _ in range(90):
   if proc.poll() is not None:raise RuntimeError('SERVER_EXITED')
   try:
    with socket.create_connection(('127.0.0.1',9000),timeout=1):break
   except OSError:time.sleep(1)
  else:raise RuntimeError('SERVER_READINESS_TIMEOUT')
  subprocess.run(['mvn','-B','-ntp','-Dtest=SeaweedContractTest','test'],cwd=FIXTURE,env=java_env,check=True,timeout=600)
  reports=list((FIXTURE/'target/surefire-reports').glob('TEST-*.xml'));assert reports
  count=0
  for path in reports:
   r=ET.parse(path).getroot();assert all(int(r.attrib.get(k,-1))==0 for k in ['failures','errors','skipped']);count+=int(r.attrib['tests'])
  assert count==9
  # Exercise the read-only inventory component against the same real server.
  (lab/'inventory-access').write_text('lab-admin');(lab/'inventory-access').chmod(0o600)
  (lab/'inventory-secret').write_text('lab-admin-secret-not-production');(lab/'inventory-secret').chmod(0o600)
  config={'endpoint':'https://127.0.0.1:18443','region':'us-east-1','accessKeyFile':str(lab/'inventory-access'),'secretKeyFile':str(lab/'inventory-secret'),'allowLoopbackHttp':False,'caCertificateFile':str(lab/'tls.crt')}
  (lab/'inventory-config.json').write_text(json.dumps(config));(lab/'inventory-config.json').chmod(0o600)
  inventory_process=subprocess.run([str(OUT/'bin/storage-inventory'),str(lab/'inventory-config.json'),str(lab/'inventory-output')],timeout=320)
  inventory=json.loads((lab/'inventory-output/inventory.private.json').read_text())
  assert inventory_process.returncode==0 and inventory['complete'], 'SYNTHETIC_INVENTORY_FAILED '+json.dumps(inventory.get('failure',{}))
  assert len(inventory['records'])==1009 and inventory['targetWrites']==0 and inventory['objectBodiesRead']==0
  # Demonstrate no automatic replay of a consumed output scope.
  assert subprocess.run([str(OUT/'bin/storage-inventory'),str(lab/'inventory-config.json'),str(lab/'inventory-output')],timeout=30).returncode!=0
  (OUT/'inventory-live-result.json').write_text(json.dumps({'status':'PASS','syntheticRecords':len(inventory['records']),'requests':inventory['requests'],'automaticReplayDenied':True,'targetOperations':0,'bucketFeatureInventoryComplete':inventory['bucketFeaturesInventoried']},indent=2)+'\n')
  # Anonymous sealed credential descriptors: no credential file exists for this invocation.
  (lab/'inventory-access').unlink();(lab/'inventory-secret').unlink()
  descriptors=[]
  try:
   for value in ['lab-admin','lab-admin-secret-not-production']:
    fd=os.memfd_create('ouf-synthetic-credential',os.MFD_ALLOW_SEALING);os.fchmod(fd,0o600);os.write(fd,value.encode());os.lseek(fd,0,os.SEEK_SET)
    fcntl.fcntl(fd,fcntl.F_ADD_SEALS,fcntl.F_SEAL_SEAL|fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK);descriptors.append(fd)
   fd_config={k:v for k,v in config.items() if k not in ['accessKeyFile','secretKeyFile']};fd_config.update(accessKeyFd=descriptors[0],secretKeyFd=descriptors[1])
   fd_config_path=lab/'inventory-fd-config.json';fd_config_path.write_text(json.dumps(fd_config));fd_config_path.chmod(0o600)
   subprocess.run([str(OUT/'bin/storage-inventory'),str(fd_config_path),str(lab/'inventory-fd-output')],pass_fds=descriptors,check=True,timeout=320)
   fd_result=json.loads((lab/'inventory-fd-output/inventory.private.json').read_text());assert fd_result['complete'] and fd_result['records']==inventory['records']
   (OUT/'inventory-sealed-fd-result.json').write_text(json.dumps({'status':'PASS','syntheticRecords':len(fd_result['records']),'credentialFileReads':0,'anonymousSealedFds':2,'sameRecordsAsFileBinding':True,'targetOperations':0},indent=2)+'\n')
  finally:
   for fd in descriptors:os.close(fd)
  subprocess.run(['sudo','--preserve-env=GITHUB_ACTIONS','python3','-I','-B','-S',str(ROOT/'scripts/test-storage-target-native-20261102.py'),str(proc.pid),str(OUT/'bin/storage-inventory'),str(lab/'data'),str(OUT/'native-target-inventory-result.json')],check=True,timeout=360)
  # Coherent cold backup after all writers and the server have stopped.
  proc.terminate()
  try:proc.wait(timeout=120)
  except subprocess.TimeoutExpired:proc.kill();proc.wait()
  require_clean_exit = proc.returncode == 0
  assert require_clean_exit, 'COHERENT_COLD_BACKUP_REQUIRES_CLEAN_SHUTDOWN'
  restored=OUT/'restored-lab';shutil.copytree(lab,restored)
  (restored/'filer.toml').write_text('[leveldb2]\nenabled = true\ndir = "'+str(restored/'metadata')+'"\n')
  restore_args=[a.replace(str(lab),str(restored)) for a in args]
  java_env['JAVA_TOOL_OPTIONS']='-Djavax.net.ssl.trustStore='+str(restored/'trust.p12')+' -Djavax.net.ssl.trustStorePassword=synthetic-lab-password'
  # Rename the originals to ensure the new server cannot silently use them.
  shutil.move(lab,OUT/'offline-original')
  proc=subprocess.Popen(restore_args,cwd=restored,stdout=log,stderr=subprocess.STDOUT)
  for _ in range(90):
   if proc.poll() is not None:raise RuntimeError('RESTORED_SERVER_EXITED')
   try:
    with socket.create_connection(('127.0.0.1',9000),timeout=1):break
   except OSError:time.sleep(1)
  else:raise RuntimeError('RESTORED_SERVER_READINESS_TIMEOUT')
  subprocess.run(['mvn','-B','-ntp','-Dtest=SeaweedRecoveryTest','test'],cwd=FIXTURE,env=java_env,check=True,timeout=600)
  recovery=ET.parse(FIXTURE/'target/surefire-reports/TEST-it.comune.trieste.ouf.storage.SeaweedRecoveryTest.xml').getroot()
  assert int(recovery.attrib['tests'])==1 and all(int(recovery.attrib.get(k,-1))==0 for k in ['failures','errors','skipped'])
  count+=1
  shutil.copytree(FIXTURE/'target/surefire-reports',OUT/'contract-reports')
  (OUT/'contract-result.json').write_text(json.dumps({'status':'PASS','tests':count,'actualOriginalAdapters':True,'transport':'loopback HTTPS, synthetic credentials and private test CA','targetE2E':False,'tlsQualified':False,'frontendTlsWithPrivateCaValidated':True,'prefixPolicyQualified':False,'syntheticPrefixAndPostPolicyDenialsValidated':True,'coldRestoreOnIndependentCopy':True,'postgresCoordinatedRecoveryQualified':False},indent=2)+'\n')
 finally:
  if (FIXTURE/'target/surefire-reports').exists() and not (OUT/'contract-reports').exists():shutil.copytree(FIXTURE/'target/surefire-reports',OUT/'contract-reports')
  proc.terminate()
  try:proc.wait(timeout=120)
  except subprocess.TimeoutExpired:proc.kill();proc.wait()
  # Do not publish the synthetic data volume or filer database.
  for name in ['lab','restored-lab','offline-original']:
   if (OUT/name).exists():shutil.rmtree(OUT/name)
