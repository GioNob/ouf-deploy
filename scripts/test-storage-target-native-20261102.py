#!/usr/bin/env python3
"""CI root fixture: modeled Docker/history, real kernel namespace, sealed FDs and S3.

Never targets an OUF installation. Not included in the target capsule.
"""
import hashlib,importlib.util,json,os,shutil,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
assert os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true','ROOT_CI_FIXTURE_ONLY'
spec=importlib.util.spec_from_file_location('target',ROOT/'tools/storage_migration/target_inventory.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
pid=int(sys.argv[1]);binary=Path(sys.argv[2]);data=Path(sys.argv[3]);out=Path(sys.argv[4]);temporary=Path(tempfile.mkdtemp(prefix='ouf-storage-native-',dir='/root'))
try:
 backend=temporary/'inventory';shutil.copyfile(binary,backend);backend.chmod(0o500);m.BACKEND=backend;m.BACKEND_SHA=hashlib.sha256(backend.read_bytes()).hexdigest()
 origin=temporary/'origin';origin.mkdir(mode=0o700)
 old_result={'fixture':'synthetic-result'};old_private={'roles':{'minio':{'nativeImageId':'sha256:'+'a'*64}}}
 for name,record in [('result.json',old_result),('runtime-origin.private.json',old_private)]:
  p=origin/name;p.write_bytes(m.encoded(record));p.chmod(0o600)
 m.origins.OUTPUT=origin;m.ORIGIN_RESULT=m.digest(old_result);m.ORIGIN_PRIVATE=m.digest(old_private);m.origins.history=lambda control:({},None,None)
 class FixtureEngine:
  def __init__(self):self.gets=0
  def get(self,path):
   self.gets+=1
   if path=='/containers/json?all=1':return [{'Id':'a'*64,'Names':['/ouf-minio']}]
   assert path=='/containers/'+'a'*64+'/json'
   return {'Id':'a'*64,'Name':'/ouf-minio','Image':'sha256:'+'a'*64,'State':{'Running':True,'Paused':False,'Pid':pid},'Args':['server','/data'],'Config':{'Env':['MINIO_ROOT_USER=lab-admin','MINIO_ROOT_PASSWORD=lab-admin-secret-not-production']},'Mounts':[{'Destination':'/data','Source':str(data),'Type':'bind','RW':True}]}
 control=m.Capture(temporary/'scope');control.until=__import__('time').monotonic()+600
 report=m.capture(control,FixtureEngine());assert report['status']=='PRIVATE_STORAGE_BASELINE_CAPTURED_NOT_ADMITTED' and report['records']==1010 and report['credentialBytesSpooled']==0
 value={'status':'PASS','records':report['records'],'kernelNetworkNamespaceEntered':True,'anonymousSealedCredentialFds':2,'credentialBytesSpooled':0,'modeledDockerGets':report['directEngineGets'],'realDockerEngineQualified':False,'historicalScopeChecks':'MODELLED','retainedTargetScopesObserved':False,'targetOperations':0,'runtimeAuthorityIssued':False}
 out.write_text(json.dumps(value,indent=2)+'\n');out.chmod(0o644)
finally:shutil.rmtree(temporary)
