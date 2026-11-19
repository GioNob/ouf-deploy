#!/usr/bin/env python3
"""Exact selected application adapters against OCI33, with no target entry point."""
import argparse, hashlib, importlib.util, json, os, shutil, subprocess, tarfile
import xml.etree.ElementTree as ET
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SOURCES={
 'onboarding-source':('GioNob/ouf-source-onboarding','d5155899b09dda298494b68cefa7e1f281167652',[
 'it/comune/trieste/ouf/onboarding/application/ManagedFileStagingStore.java',
 'it/comune/trieste/ouf/onboarding/application/MinioManagedFileStagingStore.java',
 'it/comune/trieste/ouf/onboarding/domain/DomainFailure.java']),
 'udp-source':('GioNob/ouf-udp-object-resolution','0d40da05408a14db31d4d41af2372d6a71480291',[
 'it/comune/trieste/ouf/udp/LakeObjectStoragePort.java','it/comune/trieste/ouf/udp/S3LakeObjectStorageAdapter.java'])}
def require(value,code):
 if not value:raise ValueError(code)
def write(path,value):path.write_text(json.dumps(value,indent=2)+'\n')
def sha(raw):return hashlib.sha256(raw).hexdigest()
def command(args,timeout=120,env=None,cwd=None):
 result=subprocess.run(args,capture_output=True,text=True,timeout=timeout,env=env,cwd=cwd)
 if result.returncode:raise RuntimeError('COMMAND_FAILED:'+args[0]+':'+result.stdout[-4000:]+result.stderr[-8000:])
 return result.stdout.strip()
def rotation():
 spec=importlib.util.spec_from_file_location('clients33_rotation',ROOT/'scripts/run-storage-generation33-tls-rotation.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def stage(work,inputs):
 require(os.environ.get('GITHUB_ACTIONS')=='true' and not work.exists(),'NEW_ISOLATED_CI_WORK_REQUIRED')
 work.mkdir(mode=0o700);out=work/'evidence';out.mkdir();fixture=work/'fixture'
 shutil.copytree(ROOT/'tests/fixtures/storage-clients33',fixture)
 records=[]
 for directory,(repo,commit,files) in SOURCES.items():
  source=ROOT/directory;require(command(['git','-C',str(source),'rev-parse','HEAD'])==commit,'EXACT_APPLICATION_CHECKOUT')
  for file in files+['pom.xml']:
   path='pom.xml' if file=='pom.xml' else 'src/main/java/'+file;origin=source/path;raw=origin.read_bytes()
   blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
   require(command(['git','-C',str(source),'rev-parse',commit+':'+path])==blob,'EXACT_ADAPTER_GIT_BLOB')
   records.append({'repository':repo,'commit':commit,'path':path,'sha256':sha(raw),'gitBlobSha':blob})
   if file!='pom.xml':
    dest=fixture/path;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(raw)
  shutil.copyfile(source/'pom.xml',out/(directory+'-pom.xml'))
 write(out/'application-sources.json',records)
 with tarfile.open(out/'application-sources.tar.gz','w:gz') as archive:
  for directory,(_,_,files) in SOURCES.items():
   for file in files+['pom.xml']:
    path='pom.xml' if file=='pom.xml' else 'src/main/java/'+file;archive.add(ROOT/directory/path,arcname=directory+'/'+path,recursive=False)
 mvn=shutil.which('mvn');base=[mvn,'-B','-ntp','-Dmaven.repo.local='+str(work/'repository')]
 for arguments in [['dependency:go-offline'],['test-compile','-DskipTests','dependency:copy-dependencies','-DoutputDirectory='+str(work/'dependencies')],['help:effective-pom','-Doutput='+str(out/'effective-pom.xml')],['dependency:tree','-DoutputFile='+str(out/'dependency-tree.txt')]]:
  with (out/'build.log').open('a') as log:
   subprocess.run(base+arguments,cwd=fixture,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=600)
 write(work/'tools.json',{'mvn':mvn,'javaHome':os.environ['JAVA_HOME'],'uid':os.getuid(),'gid':os.getgid()})

def run(work,inputs):
 require(os.environ.get('GITHUB_ACTIONS')=='true','ISOLATED_CI_ONLY')
 out=work/'evidence';scan=json.loads((inputs/'trivy-clients.json').read_text());require(scan.get('SchemaVersion')==2 and scan.get('Results'),'RAW_CLIENT_SCAN_REQUIRED')
 findings=[v for r in scan['Results'] for v in r.get('Vulnerabilities',[]) or []]
 require(not any(v.get('Severity','UNKNOWN') in ['CRITICAL','HIGH','UNKNOWN'] for v in findings),'CLIENT_SECURITY_GATE_HELD')
 shutil.copyfile(inputs/'trivy-clients.json',out/'trivy-clients.json')
 rot=rotation();bound=rot.binding(inputs/'bound-cohort/cohort-receipt.json');cold=rot.labs.configured_harness('cold',bound);image=cold.prepare_image(inputs/'image.zip',work);write(out/'exact-image.json',image)
 config=work/'config';config.mkdir();data=work/'data';data.mkdir();(data/'metadata').mkdir();tools=json.loads((work/'tools.json').read_text())
 command(['openssl','req','-x509','-newkey','rsa:3072','-sha256','-nodes','-keyout',str(config/'tls.key'),'-out',str(config/'tls.crt'),'-days','1','-subj','/CN=ouf-clients33','-addext','subjectAltName=IP:127.0.0.1']);(config/'tls.key').chmod(0o600)
 command([str(Path(tools['javaHome'])/'bin/keytool'),'-importcert','-noprompt','-alias','ouf-clients33','-file',str(config/'tls.crt'),'-keystore',str(config/'trust.p12'),'-storetype','PKCS12','-storepass','synthetic-lab-password'])
 (config/'filer.toml').write_text('[leveldb2]\nenabled = true\ndir = "/data/metadata"\n')
 identities=[]
 for role,actions in [('admin',['Admin','Read','Write','List','Tagging']),('staging',['Read:ouf-managed-files','Write:ouf-managed-files']),('udp',['Read:ouf-udp','Write:ouf-udp','List:ouf-udp'])]:
  identities.append({'name':'lab-'+role,'credentials':[{'accessKey':'lab-'+role,'secretKey':'lab-'+role+'-secret-not-production'}],'actions':actions})
 write(config/'s3.json',{'identities':identities});name='ouf-clients33-'+os.environ['GITHUB_RUN_ID'];created=False
 try:
  args=['docker','run','--detach','--name',name,'--network','none','--user',str(os.getuid())+':'+str(os.getgid()),'--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','256','--memory','1g','--cpus','2','--log-opt','max-size=8m','--tmpfs','/tmp:rw,noexec,nosuid,size=67108864,mode=1777','--mount','type=bind,src='+str(data)+',dst=/data','--mount','type=bind,src='+str(config)+',dst=/config,readonly','--workdir','/config',cold.IMAGE_ID,'-logtostderr=true','server','-ip=127.0.0.1','-ip.bind=127.0.0.1','-dir=/data','-master.port=19333','-master.volumeSizeLimitMB=32','-volume.port=18080','-volume.max=20','-filer','-filer.port=18888','-s3','-s3.port=9000','-s3.port.https=18443','-s3.cert.file=/config/tls.crt','-s3.key.file=/config/tls.key','-s3.port.iceberg=0','-s3.port.lance=0','-s3.config=/config/s3.json']
  command(args);created=True;view=json.loads(command(['docker','inspect',name]))[0];host=view['HostConfig']
  require(view['State']['Running'] and view['Image']==cold.IMAGE_ID and host['NetworkMode']=='none' and host['ReadonlyRootfs'] and host['CapDrop']==['ALL'] and not host['PortBindings'] and not host['Privileged'],'ISOLATED_EXACT_OCI33')
  net=['sudo','-n','nsenter','-t',str(view['State']['Pid']),'-n'];interfaces=json.loads(command(net+['ip','-j','link']));routes=json.loads(command(net+['ip','-j','route']))
  require([x['ifname'] for x in interfaces]==['lo'] and not routes,'LOOPBACK_ONLY_NO_EGRESS')
  write(out/'isolation.json',{'containerId':view['Id'],'imageId':view['Image'],'interfaces':interfaces,'routes':routes,'readOnlyRoot':host['ReadonlyRootfs'],'capDrop':host['CapDrop'],'publishedPorts':host['PortBindings']})
  readiness='import socket,time\nend=time.monotonic()+90\nwhile True:\n try:\n  s=socket.create_connection(("127.0.0.1",18443),1);s.close();break\n except OSError:\n  if time.monotonic()>end:raise\n  time.sleep(1)\n'
  command(net+['python3','-I','-B','-S','-c',readiness],100)
  environment=['JAVA_HOME='+tools['javaHome'],'OUF_SW_ENDPOINT=https://127.0.0.1:18443','JAVA_TOOL_OPTIONS=-Djavax.net.ssl.trustStore='+str(config/'trust.p12')+' -Djavax.net.ssl.trustStorePassword=synthetic-lab-password']
  args=net+['setpriv','--reuid',str(tools['uid']),'--regid',str(tools['gid']),'--clear-groups','env',*environment,tools['mvn'],'-o','-B','-ntp','-Dmaven.repo.local='+str(work/'repository'),'-Dtest=StorageClients33Test','test']
  with (out/'native-clients.log').open('w') as log:result=subprocess.run(args,cwd=work/'fixture',stdout=log,stderr=subprocess.STDOUT,timeout=600)
  require(result.returncode==0,'NATIVE_CLIENT_CONTRACT_FAILED')
  report=work/'fixture/target/surefire-reports/TEST-it.comune.trieste.ouf.storage.StorageClients33Test.xml';xml=ET.parse(report).getroot()
  require(int(xml.attrib['tests'])==12 and all(int(xml.attrib.get(k,-1))==0 for k in ['failures','errors','skipped']),'TWELVE_CLIENT_CASES_WITHOUT_SKIP')
  names=[x.attrib['name'] for x in xml.findall('testcase')];require(len(set(names))==12,'TWELVE_DISTINCT_CASES')
  write(out/'qualification.json',{'schema':'ouf.storage-clients33-qualification.v1','status':'PASS_SYNTHETIC_APPLICATION_ADAPTERS_NOT_TARGET_ACCEPTANCE','producerSource':os.environ['GITHUB_SHA'],'candidateLockSha256':rot.LOCK_SHA,'destinationImage':cold.IMAGE_ID,'tests':names,'passed':12,'failed':0,'skipped':0,'onboardingReservedReferenceApi':True,'sourceAdaptersModified':False,'fixtureDependencyClosureDistinctFromFullServices':True,'applicationBeansOrEndpointsInstalled':False,'originalHistoricalContractTestsChanged':False,'targetOperations':0,'runtimeAuthorityIssued':False,'gatesClosed':0,'acceptanceTestsPassed':0})
 finally:
  reports=work/'fixture/target/surefire-reports'
  if reports.is_dir():
   for path in reports.iterdir():
    if path.is_file():shutil.copyfile(path,out/path.name)
  if created:
   log=subprocess.run(['docker','logs',name],capture_output=True,timeout=30);(out/'server.log').write_bytes((log.stdout+log.stderr)[-49152:])
   command(['docker','stop','--time','30',name],45);state=json.loads(command(['docker','inspect',name]))[0]['State'];write(out/'exit.json',state);command(['docker','rm',name]);require(not state['Running'] and not state['OOMKilled'] and state['ExitCode']==0,'CLEAN_SERVER_STOP')

def seal(work,inputs):
 out=work/'evidence';out.mkdir(parents=True,exist_ok=True)
 for name in ['cohort-publisher-verification.json','bound-cohort/cohort-receipt.json','trivy-clients.json']:
  source=inputs/name
  if source.is_file():shutil.copyfile(source,out/Path(name).name)
 paths=command(['git','ls-files'],cwd=ROOT).splitlines();selected=[p for p in paths if p.startswith(('tools/storage_security/','tests/fixtures/storage-clients33/')) or p.startswith('scripts/') and ('seaweedfs' in p or 'storage' in p) or p in ['.github/workflows/storage-clients33.yml','releases/storage-g0-evidence-request-20261105.json','releases/seaweedfs-452-generation33-candidate-lock-20261104.json']]
 write(out/'source-sha256.json',{p:sha((ROOT/p).read_bytes()) for p in selected})
 with tarfile.open(out/'source-files.tar.gz','w:gz') as archive:
  for path in selected:archive.add(ROOT/path,arcname=path,recursive=False)
 (out/'source-commit.txt').write_text(os.environ['GITHUB_SHA']+'\n');total=0
 for path in out.iterdir():
  require(path.is_file() and not path.is_symlink(),'REGULAR_PUBLIC_EVIDENCE');raw=path.read_bytes();total+=len(raw)
  require(len(raw)<=16*1024*1024 and total<=64*1024*1024 and b'-----BEGIN PRIVATE KEY' not in raw and b'-----BEGIN RSA PRIVATE KEY' not in raw,'BOUNDED_EVIDENCE_NO_KEYS')
 (out/'SHA256SUMS').write_text(''.join(sha(p.read_bytes())+'  '+p.name+'\n' for p in sorted(out.iterdir()) if p.name!='SHA256SUMS'))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('action',choices=['stage','run','seal']);p.add_argument('work',type=Path);p.add_argument('inputs',type=Path);a=p.parse_args();globals()[a.action](a.work.resolve(),a.inputs.resolve())
