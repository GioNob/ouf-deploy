#!/usr/bin/env python3
"""Run original OUF adapters against a loopback-only disposable real server."""
import hashlib
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
assert json.loads((OUT/'candidate.json').read_text())['securityGate']=='PASS'
records=[]
for directory,(commit,files) in SOURCES.items():
 source=ROOT/directory
 assert subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip()==commit
 for file in files:
  origin=source/'src/main/java'/file;dest=FIXTURE/'src/main/java'/file
  dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(origin,dest)
  records.append({'repositoryDirectory':directory,'commit':commit,'path':file,'sha256':hashlib.sha256(origin.read_bytes()).hexdigest()})
(OUT/'adapter-source-inventory.json').write_text(json.dumps(records,indent=2)+'\n')
lab=OUT/'lab';lab.mkdir();(lab/'data').mkdir();(lab/'metadata').mkdir()
(lab/'filer.toml').write_text('[leveldb2]\nenabled = true\ndir = "'+str(lab/'metadata')+'"\n')
identities=[]
for name,actions in [('admin',['Admin','Read','Write','List','Tagging']),('staging',['Read:ouf-managed-files','Write:ouf-managed-files']),('udp',['Read:ouf-udp','Write:ouf-udp','List:ouf-udp'])]:
 identities.append({'name':'lab-'+name,'credentials':[{'accessKey':'lab-'+name,'secretKey':'lab-'+name+'-secret-not-production'}],'actions':actions})
(lab/'s3.json').write_text(json.dumps({'identities':identities}))
# No ports exposed outside loopback. Synthetic fixtures only; this is not the target TLS/IAM profile.
args=[str(OUT/'bin/weed'),'server','-ip=127.0.0.1','-ip.bind=127.0.0.1','-dir='+str(lab/'data'),'-master.port=19333','-master.volumeSizeLimitMB=32','-volume.port=18080','-volume.max=20','-filer','-filer.port=18888','-s3','-s3.port=18333','-s3.port.iceberg=0','-s3.port.lance=0','-s3.config='+str(lab/'s3.json')]
with (OUT/'server.log').open('w') as log:
 proc=subprocess.Popen(args,cwd=lab,stdout=log,stderr=subprocess.STDOUT)
 try:
  for _ in range(90):
   if proc.poll() is not None:raise RuntimeError('SERVER_EXITED')
   try:
    with socket.create_connection(('127.0.0.1',18333),timeout=1):break
   except OSError:time.sleep(1)
  else:raise RuntimeError('SERVER_READINESS_TIMEOUT')
  subprocess.run(['mvn','-B','-ntp','test'],cwd=FIXTURE,check=True,timeout=600)
  reports=list((FIXTURE/'target/surefire-reports').glob('TEST-*.xml'));assert reports
  count=0
  for path in reports:
   r=ET.parse(path).getroot();assert all(int(r.attrib.get(k,-1))==0 for k in ['failures','errors','skipped']);count+=int(r.attrib['tests'])
  assert count==5
  shutil.copytree(FIXTURE/'target/surefire-reports',OUT/'contract-reports')
  (OUT/'contract-result.json').write_text(json.dumps({'status':'PASS','tests':count,'actualOriginalAdapters':True,'transport':'loopback HTTP, synthetic credentials','targetE2E':False,'tlsQualified':False,'prefixPolicyQualified':False},indent=2)+'\n')
 finally:
  if (FIXTURE/'target/surefire-reports').exists() and not (OUT/'contract-reports').exists():shutil.copytree(FIXTURE/'target/surefire-reports',OUT/'contract-reports')
  proc.terminate()
  try:proc.wait(timeout=15)
  except subprocess.TimeoutExpired:proc.kill();proc.wait()
  # Do not publish the synthetic data volume or filer database.
  shutil.rmtree(lab)
