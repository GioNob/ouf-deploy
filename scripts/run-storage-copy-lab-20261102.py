#!/usr/bin/env python3
"""Synthetic two-server copy tests; never uses OUF endpoints, data or credentials."""
import hashlib,json,os,shutil,socket,subprocess,sys,time,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/'copy-evidence';SW=ROOT/'sw-evaluation'
assert os.environ.get('GITHUB_ACTIONS')=='true'
def write(path,value):path.write_text(json.dumps(value,indent=2)+'\n')
def stage():
 OUT.mkdir();SW.mkdir();(SW/'bin').mkdir()
 with zipfile.ZipFile(ROOT/'sw-readback/original.zip') as z:
  for name in ['bin/weed','bin/storage-inventory','candidate.json','compiled-packages.json']:
   p=SW/name;p.write_bytes(z.read(name))
 for p in (SW/'bin').iterdir():p.chmod(0o500)
def check():
 subprocess.run([sys.executable,'-I','-B','-S',str(ROOT/'scripts/qualify-seaweedfs-20261102.py'),'gate',str(SW)],check=True)
 candidate=json.loads((SW/'candidate.json').read_text());assert candidate['securityGate']=='PASS' or candidate['isolatedLabEligible']
 report=json.loads((OUT/'trivy-copy-modules.json').read_text());assert report['SchemaVersion']==2 and report['Results']
 packages={p['Name'] for r in report['Results'] for p in r.get('Packages',[])}
 assert {'github.com/aws/aws-sdk-go-v2','github.com/aws/aws-sdk-go-v2/credentials','github.com/aws/aws-sdk-go-v2/service/s3'}<=packages
 counts=dict.fromkeys(['CRITICAL','HIGH','UNKNOWN','MEDIUM','LOW'],0)
 for r in report['Results']:
  for v in r.get('Vulnerabilities') or []:assert v['Severity'] in counts;counts[v['Severity']]+=1
 assert not any(counts[k] for k in ['CRITICAL','HIGH','UNKNOWN']),'COPY_MODULE_SECURITY_HELD'
 write(OUT/'security-gates.json',{'status':'PASS_FOR_SYNTHETIC_LAB_ONLY','copyModuleFindings':counts,'rawServerGate':candidate['securityGate'],'serverFindings':candidate['findings'],'rawServerGatePreserved':True,'releaseAdmitted':False,'targetOperations':0})
def tests(pattern,name,env):
 binary=SW/'bin/storage-copy-lab.test';path=OUT/(name+'.jsonl')
 with path.open('wb') as f:
  subprocess.run(['go','tool','test2json','-t','-p','it.comune.trieste.ouf/storage-copy-lab',str(binary),'-test.v','-test.run='+pattern,'-test.timeout=5m'],cwd=ROOT/'tools/storage_copy',env=env,stdout=f,stderr=subprocess.STDOUT,check=True,timeout=330)
 rows=[json.loads(l) for l in path.read_text().splitlines()];assert not any(r.get('Action') in ['fail','skip'] for r in rows)
 return [r['Test'] for r in rows if r.get('Action')=='pass' and 'Test' in r]
def run():
 env=dict(os.environ,GOTOOLCHAIN='go1.27.3',GOMEMLIMIT='256MiB',GOMAXPROCS='2')
 tmp=ROOT/'copy-test-temporaries';tmp.mkdir(mode=0o700);env['TMPDIR']=str(tmp)
 passed=tests('^TestUnit','unit-tests',env)
 lab=SW/'copy-lab';lab.mkdir(mode=0o700);processes=[];logs=[]
 subprocess.run(['openssl','req','-x509','-newkey','rsa:3072','-sha256','-nodes','-keyout',str(lab/'tls.key'),'-out',str(lab/'tls.crt'),'-days','1','-subj','/CN=ouf-copy-lab','-addext','subjectAltName=IP:127.0.0.1'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 try:
  for role,master,volume,filer,http,tls in [('source',19331,18081,18881,9001,18441),('destination',19332,18082,18882,9002,18442)]:
   root=lab/role;root.mkdir();(root/'data').mkdir();(root/'metadata').mkdir();(root/'filer.toml').write_text('[leveldb2]\nenabled = true\ndir = "'+str(root/'metadata')+'"\n')
   (root/'s3.json').write_text(json.dumps({'identities':[{'name':'synthetic-'+role+'-admin','credentials':[{'accessKey':'synthetic-'+role+'-admin','secretKey':'synthetic-'+role+'-secret-not-production'}],'actions':['Admin','Read','Write','List','Tagging']}]}))
   args=[str(SW/'bin/weed'),'server','-ip=127.0.0.1','-ip.bind=127.0.0.1','-dir='+str(root/'data'),'-master.port='+str(master),'-master.volumeSizeLimitMB=32','-volume.port='+str(volume),'-volume.max=20','-filer','-filer.port='+str(filer),'-s3','-s3.port='+str(http),'-s3.port.https='+str(tls),'-s3.cert.file='+str(lab/'tls.crt'),'-s3.key.file='+str(lab/'tls.key'),'-s3.port.iceberg=0','-s3.port.lance=0','-s3.config='+str(root/'s3.json')]
   log=(root/'server.log').open('wb');logs.append(log);p=subprocess.Popen(args,cwd=root,stdout=log,stderr=subprocess.STDOUT);processes.append(p)
   for _ in range(90):
    if p.poll() is not None:raise ValueError('SYNTHETIC_SERVER_EXITED')
    try:
     with socket.create_connection(('127.0.0.1',tls),timeout=1):break
    except OSError:time.sleep(1)
   else:raise ValueError('SYNTHETIC_READINESS_TIMEOUT')
  env.update(OUF_COPY_LAB='1',OUF_COPY_SOURCE='https://127.0.0.1:18441',OUF_COPY_DESTINATION='https://127.0.0.1:18442',OUF_COPY_DEST_HTTP='http://127.0.0.1:9002',OUF_COPY_CA=str(lab/'tls.crt'),OUF_COPY_INVENTORY_BINARY=str(SW/'bin/storage-inventory'),OUF_COPY_COMPILER=str(ROOT/'tools/storage_planning/inventory_manifest.py'))
  cases=[('^TestRealConditionalAtomicity$','real-conditional-cas'),('^TestRealCopy120FromExactInventoryCompilerWire$','real-copy-120'),('^TestRealProcessCrashResumeNoSecondPut$','real-process-crashes'),('^TestRealAmbiguous503RespectsRetryAfterAndReconciles$','real-ambiguous-503'),('^TestRealTagsAndEncodingPreserved$','real-metadata-tags'),('^TestRealSourceIfMatchAndVersionedDestinationDenials$','real-denials')]
  for pattern,name in cases:passed+=tests(pattern,name,env)
  write(OUT/'qualification.json',{'schema':'ouf.storage-copy-lab-qualification.v1','status':'PASS','producerSource':os.environ['GITHUB_SHA'],'passedTests':passed,'passedTestCount':len(passed),'twoIndependentRealS3Servers':True,'sourceServerIsMinio':False,'sourceAndDestination':'SYNTHETIC_SEAWEEDFS_FIXTURES','originalInventorySdkReused':True,'existingPrivatePlanCompilerWireExercised':True,'syntheticObjects':120,'syntheticLogicalBytes':203743,'missingAdvertisedHashes':10,'bodiesVerified':120,'realProcessCrashPoints':['BEFORE_PUT','AFTER_PUT','BEFORE_CHECKPOINT'],'destinationPutsPerCrashCase':1,'ambiguous503AfterStoreReconciledWithoutSecondPut':True,'retryAfterOneHourQualifiedWithVirtualClock':True,'sixHourOutageQualifiedWithVirtualClock':True,'cumulativeRequestBudget':10000,'maximumAttempts':128,'maximumOperationHours':24,'versionedDestinationCopySupported':False,'productionEntryPointExists':False,'rawServerGatePreserved':True,'runtimeAuthorityIssued':False,'migrationReady':False,'targetOperations':0})
 finally:
  for p in processes:
   p.terminate()
  for p in processes:
   try:p.wait(timeout=30)
   except subprocess.TimeoutExpired:p.kill();p.wait()
  for log in logs:log.close()
  for role in ["source","destination"]:
   p=lab/role/"server.log"
   if p.exists():(OUT/(role+"-synthetic-log-tail.txt")).write_bytes(p.read_bytes()[-16384:])
  shutil.rmtree(lab);shutil.rmtree(tmp)
def seal():
 for name in ['candidate.json','compiled-packages.json','trivy-binary.json']:shutil.copyfile(SW/name,OUT/name)
 sources={}
 for p in sorted((ROOT/'tools/storage_copy').glob('*')):
  if p.is_file():sources[str(p.relative_to(ROOT))]=hashlib.sha256(p.read_bytes()).hexdigest()
 sources['tools/storage_planning/inventory_manifest.py']=hashlib.sha256((ROOT/'tools/storage_planning/inventory_manifest.py').read_bytes()).hexdigest()
 write(OUT/'source-records.json',sources)
 shutil.copyfile(SW/'bin/storage-copy-lab.test',OUT/'storage-copy-lab.test')
 for name in ['byte-readback.json','publisher-verification.json']:shutil.copyfile(ROOT/'sw-readback'/name,OUT/('original-'+name))
 files=sorted(p for p in OUT.rglob('*') if p.is_file());(OUT/'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+str(p.relative_to(OUT))+'\n' for p in files))
if __name__=='__main__':{'stage':stage,'check':check,'run':run,'seal':seal}[sys.argv[1]]()
