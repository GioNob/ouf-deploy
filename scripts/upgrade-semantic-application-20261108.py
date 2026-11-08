#!/usr/bin/env python3
"""Replace the observed V10 Registry with the exact c2dae image and V11/V12.

One journal, no automatic rollback/replay. Old Registry stays stopped after
migration dispatch. Provider/worker declarations and existing mounts persist.
"""
import copy, hashlib, http.client, importlib.util, json, os, re, socket, subprocess, sys, time, zipfile
from pathlib import Path
from datetime import datetime, timezone

SOURCE='c2dae77b42f1811b704465f6ab813c91d808ade4'
ZIP_SHA='1a7045ffb39486f2579fb342d7fd881f5a123f74a0810d353bce3c755bfc76ba'
ARCHIVE_SHA='7f6482b79589fd1063eaf96508ea948d6411a7b4f0dbe76d663746a08953a223'
JAR_SHA='e69f961a06fa37d019f4015d98dd5419ee9da1fa1387b5b0edaac4214a0cb016'
CONFIG_ID='sha256:a6f00cda30f1c570082c94cb49d5564f40d512758441f6b6eac75e21f423d14f'
NATIVE_ID='sha256:89e84f7a6208afa74039de7057c46ad5c9981fb283b22d9b93fa014e92d1b048' # OCI manifest in the exact archive
OLD_JAR='e0c26f0e0dea02b52f23e874b9494362dd2d58cc787e918a94948ff08340e786'
WORK=Path('/var/lib/ouf-storage-migration/semantic-application-upgrade-20261108')
JAVA=['java','-XX:MaxRAMPercentage=75','-jar','/app/application.jar']
GATE='OUF_APPLICATION_GATE=0; trap "OUF_APPLICATION_GATE=1" USR1; while [ "$OUF_APPLICATION_GATE" = 0 ]; do sleep 1 & wait "$!"; done; exec "$@"'
ENTRY=['/bin/sh','-c',GATE,'ouf-gated-application']
DOCKER=('/usr/bin/docker','--host','unix:///run/docker.sock','--config','/nonexistent')

def need(ok,code):
 if not ok:raise RuntimeError(code)
def sha(b):return hashlib.sha256(b).hexdigest()
def file_sha(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  while b:=f.read(1024*1024):h.update(b)
 return h.hexdigest()
def module(name,path,pin):
 raw=path.read_bytes();need(sha(raw)==pin,'DEPENDENCY_HASH_CHANGED')
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);exec(compile(raw,str(path),'exec'),m.__dict__);return m

def cli(*args,timeout=60):
 p=subprocess.run((*DOCKER,*args),capture_output=True,timeout=timeout)
 need(p.returncode==0,'DOCKER_COMMAND_FAILED');return p.stdout
class Engine:
 def api(self,method,path,body=None):
  class Unix(http.client.HTTPConnection):
   def connect(self):
    self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(self.timeout);self.sock.connect('/run/docker.sock')
  c=Unix('localhost',timeout=45)
  try:
   c.request(method,'/v1.44'+path,None if body is None else json.dumps(body).encode(),{'Content-Type':'application/json'})
   r=c.getresponse();b=r.read(2*1024*1024+1)
   need(r.status in (200,201,204) and len(b)<=2*1024*1024,'ENGINE_RESPONSE_UNEXPECTED')
   return json.loads(b) if b else None
  finally:c.close()
 def inspect(self,cid):return self.api('GET','/containers/'+cid+'/json')

def mounts(doc):return sorted(doc['Mounts'],key=lambda m:m['Destination'])
def request(old,image):
 c,h=copy.deepcopy(old['Config']),copy.deepcopy(old['HostConfig'])
 need(c.get('Entrypoint')==ENTRY and c.get('Cmd')==JAVA and c.get('User')=='10001:10001','EXACT_RETAINED_GATE_REQUIRED')
 nets=old['NetworkSettings']['Networks'];need(len(nets)==1,'SINGLE_BACKEND_REQUIRED')
 net,ep=next(iter(nets.items()))
 need(h['NetworkMode']==net and not h.get('AutoRemove') and not h.get('VolumesFrom'),'SUPPORTED_LIFECYCLE_REQUIRED')
 need(h['RestartPolicy']=={'Name':'no','MaximumRetryCount':0},'RETAINED_RESTART_NO_REQUIRED')
 # Every actual mount must already have an explicit reusable binding.
 declared={m['Target'] for m in h.get('Mounts') or []}
 declared.update(b.split(':')[1] for b in h.get('Binds') or [])
 need(all(m['Type']=='bind' and not m['RW'] and m['Destination'] in declared for m in old['Mounts']),'EXPLICIT_READONLY_BIND_MOUNTS_REQUIRED')
 c['Image']=image;c.pop('MacAddress',None)
 c['Labels']=dict(c.get('Labels') or {},**{'org.opencontainers.image.revision':SOURCE,'ouf.semantic.functional-upgrade':SOURCE})
 # Image-owned Java metadata must describe the new JRE, not the old image.
 c['Env']=[('JAVA_VERSION=jdk-21.0.13+9' if e.startswith('JAVA_VERSION=') else e) for e in c['Env']]
 ipam=copy.deepcopy(ep.get('IPAMConfig') or {});need(bool(ep.get('IPAddress')),'OBSERVED_IPV4_REQUIRED');ipam['IPv4Address']=ep['IPAddress']
 if ep.get('GlobalIPv6Address'):ipam['IPv6Address']=ep['GlobalIPv6Address']
 endpoint={'IPAMConfig':ipam,'Aliases':list(ep.get('Aliases') or []),'MacAddress':ep['MacAddress']}
 for k in ('Links','DriverOpts'):
  if ep.get(k):endpoint[k]=copy.deepcopy(ep[k])
 c.update(HostConfig=h,NetworkingConfig={'EndpointsConfig':{net:endpoint}})
 return c

def detached(mac,old,actual,name):
 # Two historically qualified profiles, no global omission of Config.MacAddress.
 if 'MacAddress' not in actual['Config']:return mac.verify_detached(old,actual,expected_name=name)['profile']
 need(actual['Config']==old['Config'],'DETACHED_CONFIG_CHANGED')
 mac.detached_config(old) # prove initial legacy MAC/endpoint agreement
 need(actual['Id']==old['Id'] and actual['Image']==old['Image'] and actual['Name']==name and
      actual['HostConfig']==old['HostConfig'] and mounts(actual)==mounts(old) and
      actual['State']['Running'] is False and actual['State']['Pid']==0 and
      actual['State']['StartedAt']==old['State']['StartedAt'] and actual['NetworkSettings']['Networks']=={},'DETACHED_FRAME_CHANGED')
 return 'UNCHANGED_EXPLICIT_LEGACY_CONFIG'

def verify_replacement(old,req,actual,started):
 expected={k:v for k,v in req.items() if k not in ('HostConfig','NetworkingConfig')}
 config=copy.deepcopy(actual['Config']);net,ep=next(iter(req['NetworkingConfig']['EndpointsConfig'].items()))
 if 'MacAddress' in config:need(config.pop('MacAddress')==ep['MacAddress'],'REPLACEMENT_LEGACY_MAC_CHANGED')
 need(config==expected,'REPLACEMENT_CONFIG_CHANGED')
 need(actual['Image']==req['Image'] and actual['HostConfig']==req['HostConfig'] and mounts(actual)==mounts(old),'REPLACEMENT_IMAGE_HOST_MOUNTS_CHANGED')
 need(set(actual['NetworkSettings']['Networks'])=={net},'REPLACEMENT_NETWORK_SET_CHANGED')
 current=actual['NetworkSettings']['Networks'][net]
 need(current['IPAMConfig']==ep['IPAMConfig'] and set(current.get('Aliases') or [])==set(ep['Aliases']),'REPLACEMENT_ADDRESS_ALIASES_CHANGED')
 if started:need(current['IPAddress']==ep['IPAMConfig']['IPv4Address'] and current['MacAddress']==ep['MacAddress'],'REPLACEMENT_ENDPOINT_CHANGED')
 need(actual['State']['Running'] is started,'REPLACEMENT_RUNNING_STATE_CHANGED')

def replace(engine,old,req,mac,record,report):
 mac.policy(old);record('old.private.json',old);record('request.private.json',req)
 cid=old['Id'];net=next(iter(old['NetworkSettings']['Networks']));name=old['Name'];retained=name+'-before-discovery-20261108'
 need(re.fullmatch('/[A-Za-z0-9_.-]+',name) and len(retained)<200,'BOUNDED_CONTAINER_NAME_REQUIRED')
 record('stop-intent.json',{'containerId':cid});report['oldStopDispatched']=True
 engine.api('POST','/containers/'+cid+'/stop?t=20')
 stopped=engine.inspect(cid)
 need(stopped['State']['Running'] is False and stopped['State']['Pid']==0 and stopped['Config']==old['Config'] and stopped['HostConfig']==old['HostConfig'] and mounts(stopped)==mounts(old),'STOPPED_FRAME_CHANGED')
 record('stopped.private.json',stopped)
 record('detach-intent.json',{'containerId':cid,'network':net});engine.api('POST','/networks/'+net+'/disconnect',{'Container':cid,'Force':False})
 after=engine.inspect(cid);report['oldMacTransition']=detached(mac,old,after,name);record('detached.private.json',after)
 record('rename-intent.json',{'name':retained});engine.api('POST','/containers/'+cid+'/rename?name='+retained[1:])
 detached(mac,old,engine.inspect(cid),retained)
 record('create-intent.json',{'requestSha256':sha(json.dumps(req,sort_keys=True).encode())})
 new=engine.api('POST','/containers/create?name='+name[1:],req)['Id'];report['replacementContainerId']=new;record('created.json',{'containerId':new})
 created=engine.inspect(new);record('created.private.json',created)
 verify_replacement(old,req,created,False)
 record('gate-start-intent.json',{'containerId':new});engine.api('POST','/containers/'+new+'/start')
 current=engine.inspect(new);verify_replacement(old,req,current,True)
 report['replacementGateStarted']=True;record('gated.private.json',current)
 detached(mac,old,engine.inspect(cid),retained)
 return current

def gate_running(doc):
 args=Path('/proc',str(doc['State']['Pid']),'cmdline').read_bytes().rstrip(b'\0').decode().split('\0')
 need(args==ENTRY+JAVA,'REPLACEMENT_GATE_NOT_PROVEN')

def readiness(cid):
 p=subprocess.run((*DOCKER,'exec',cid,'curl','--silent','--show-error','--fail','--max-time','2','http://127.0.0.1:8080/actuator/health/readiness'),capture_output=True,timeout=4)
 return p.returncode==0 and len(p.stdout)<65536 and json.loads(p.stdout).get('status')=='UP'

def run(report,archive):
 need(os.geteuid()==0 and sys.flags.isolated,'ISOLATED_ROOT_REQUIRED')
 base=Path(__file__).parent
 u=module('migration',base/'upgrade-semantic-v11-v12-20261108.py','af319a963f8556f5feb7459d369afe1e362f482562cb674d8a6028c5f1a128cc')
 mac=module('retained_mac',base/'retained_mac.py','cb5dbbee4a80ce71860dfe5d32362a662d98898c58fd82009e69c5eb6ac1f7ce')
 a,c,h=u.load_helpers();engine=Engine()
 need(archive.is_file() and archive.stat().st_size==203419418 and file_sha(archive)==ZIP_SHA,'EXACT_CANDIDATE_ZIP_REQUIRED')
 WORK.mkdir(mode=0o700);report['privateEvidenceDirectory']=str(WORK)
 record=lambda n,v:a.private(WORK,n,v)
 record('attempt.json',{'sourceCommit':SOURCE,'artifactId':13066396654,'archiveSha256':ZIP_SHA})
 # No archive extraction paths; materialize only the exact pinned image member.
 with zipfile.ZipFile(archive) as z:
  need(len(z.namelist())==len(set(z.namelist())),'DUPLICATE_ZIP_MEMBERS')
  with z.open('image.docker.tar') as src,open(WORK/'image.docker.tar','xb') as dst:
   import shutil;shutil.copyfileobj(src,dst)
 need(file_sha(WORK/'image.docker.tar')==ARCHIVE_SHA,'EXACT_IMAGE_ARCHIVE_REQUIRED')
 raw=h.read(h.PLAN,1048576);need(sha(raw)==h.PLAN_SHA,'RETAINED_PLAN_CHANGED');roles=h.parse(raw)['roles']
 old=h.inspect(u.CID);observed=h.parse(h.read(a.OBSERVED/'semantic.private.json',2*1024*1024))
 need(h.digest(h.frame(observed))==c.FRAME_PINS['semantic'] and a.stable_frame(h,old)==a.stable_frame(h,observed),'CURRENT_SEMANTIC_FRAME_CHANGED')
 need(old['Image']==u.IMAGE and old['State']['Running'],'CURRENT_SEMANTIC_IMAGE_CHANGED')
 need(file_sha(Path('/proc',str(old['State']['Pid']),'root/app/application.jar'))==OLD_JAR,'CURRENT_JAR_CHANGED')
 env=h.environment(old);u.selected_environment(env);mac.policy(old)
 need(env.get('JAVA_VERSION') in ('jdk-21.0.12+7','jdk-21.0.12.1+1','jdk-21.0.12.1+1-LTS','jdk-21.0.13+9') or env.get('JAVA_VERSION','').startswith('jdk-21.0.12'),'JAVA_ENVIRONMENT_UNEXPECTED')
 pg=h.inspect(roles['postgres']['containerId']);need(pg['Image']==roles['postgres']['nativeImage'] and pg['State']['Running'],'CURRENT_POSTGRES_CHANGED')
 user,name=c.db_binding(old,pg,'semantic',h)
 before=a.semantic_read(c,h,old,pg,WORK,report)
 need(str(before['databaseOid'])=='21558' and before['discoveryStates']==[] and not before['recoveryColumnPresent'],'DATABASE_BASELINE_CHANGED')
 report['before']=before
 # Import has no app/DB effect; image bytes were checked before invoking Engine.
 record('image-load-intent.json',{'archiveSha256':ARCHIVE_SHA});cli('load','--input',str(WORK/'image.docker.tar'),timeout=120);report['imageImported']=True
 image=json.loads(cli('image','inspect','ouf-cohort-semantic:'+SOURCE))[0]
 need(image['Id'] in (CONFIG_ID,NATIVE_ID) and image['Config']['User']=='10001:10001' and image['Config']['Entrypoint']==JAVA,'IMPORTED_IMAGE_BINDING_CHANGED')
 req=request(old,image['Id']);report['candidateImageId']=image['Id']
 need(a.stable_frame(h,h.inspect(u.CID))==a.stable_frame(h,old) and a.stable_frame(h,h.inspect(pg['Id']))==a.stable_frame(h,pg),'RUNTIME_CHANGED_BEFORE_STOP')
 current=replace(engine,old,req,mac,record,report);gate_running(current)
 need(file_sha(Path('/proc',str(current['State']['Pid']),'root/app/application.jar'))==JAR_SHA,'CANDIDATE_JAR_CHANGED')
 report['candidatePackage']=u.package(current,json.loads((base/'semantic-migration-source-20261108.json').read_bytes()))
 bundle=json.loads((base/'semantic-migration-helper-20261108.json').read_bytes());host,path=u.stage_class(current,bundle)
 try:
  gate_running(current);record('migration-intent.json',{'versions':[11,12]});report['javaMigrationDispatched']=True;report['migrationDispatched']=None
  result=u.invoke(c,current,path,env['OUF_SEM_DB_URL'],user,'21558')
  c.save_private(WORK,'migration.stdout.private',result.stdout);c.save_private(WORK,'migration.stderr.private',result.stderr)
  rows=[json.loads(l.split(b' ',1)[1]) for l in result.stdout.splitlines() if l.startswith(b'OUF_SEMANTIC_UPGRADE ')]
  report['migrationResult']=rows[-1] if rows else None
  report['migrationDispatched']=any(r['status']=='MIGRATION_DISPATCHED' for r in rows)
  need(result.returncode==0 and rows and rows[-1]['status']=='SEMANTIC_V11_V12_MIGRATED_VALIDATED','MIGRATION_NOT_CONFIRMED')
 finally:
  for leaf in ('SemanticMigration.class','loader.properties'):(host/leaf).unlink()
  host.rmdir()
 gate_running(engine.inspect(current['Id']))
 record('application-start-intent.json',{'containerId':current['Id']});report['applicationStartDispatched']=True
 engine.api('POST','/containers/'+current['Id']+'/kill?signal=USR1')
 for _ in range(60):
  live=engine.inspect(current['Id']);need(live['State']['Running'],'APPLICATION_EXITED')
  if readiness(current['Id']):break
  time.sleep(1)
 else:raise RuntimeError('READINESS_NOT_UP')
 verify_replacement(old,req,live,True);detached(mac,old,engine.inspect(old['Id']),old['Name']+'-before-discovery-20261108')
 need(Path('/proc',str(live['State']['Pid']),'cmdline').read_bytes().rstrip(b'\0').decode().split('\0')==JAVA,'JAVA_INIT_NOT_PROVEN')
 record('replacement.private.json',live)
 report.update(status='SEMANTIC_APPLICATION_V12_READY',readinessUp=True,oldRetainedStopped=True,backendAddressAliasesPreserved=True,
               providerEnabled=False,workerEnabled=False,discoveryFunctionalTested=False)
 record('complete.json',report)

def main():
 report={'schema':'ouf.semantic-application-upgrade.v1','status':'HELD','credentialValuesEmitted':False,
 'readOnlyDatabaseSessionsAttempted':0,'oldStopDispatched':False,'imageImported':False,'javaMigrationDispatched':False,
 'migrationDispatched':False,'applicationStartDispatched':False,'providerEnableDispatched':False,'businessRequestsIssued':0,
 's3Requests':0,'gatewayWrites':0,'permissionChanges':0,'automaticRollback':False}
 try:
  need(len(sys.argv)==2,'EXACT_CANDIDATE_ARCHIVE_ARGUMENT_REQUIRED');run(report,Path(sys.argv[1]))
 except FileExistsError:report['reason']='EXISTING_ATTEMPT_DO_NOT_REPLAY'
 except Exception as e:report['reason']=str(e) if type(e) is RuntimeError and re.fullmatch('[A-Z][A-Z0-9_]{0,100}',str(e)) else type(e).__name__
 report['observedAt']=datetime.now(timezone.utc).isoformat();print(json.dumps(report,sort_keys=True))
if __name__=='__main__':main()
