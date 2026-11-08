#!/usr/bin/env python3
"""Correct one discovery key-file declaration on the exited, migrated Registry.

No key publication/rotation, image import, explicit migration or route write.
The previous V10 and failed V12 containers remain stopped and retained.
"""
import copy,hashlib,hmac,importlib.util,json,os,re,stat,subprocess,sys,time
from datetime import datetime,timezone
from pathlib import Path
CID='11d9362c7db484a2204266062fd54b5c08fbf1da7382076fb2a164bc1a9dd070'
V10='790c62742c92eabc095d4ab22f2070e0c40a41e4a219685a7d8120e4661e4e5d'
IMAGE='sha256:89e84f7a6208afa74039de7057c46ad5c9981fb283b22d9b93fa014e92d1b048'
ROOT=Path('/var/lib/ouf-storage-migration')
ORIGINAL=ROOT/'semantic-application-upgrade-20261108'
OBSERVED=ROOT/'semantic-key-binding-m9oddh4s'
WORK=ROOT/'semantic-discovery-key-repair-20261108'
BAD='/run/secrets/semantic-discovery-owner.key'
GOOD='/run/secrets/semantic-read-owner.key'
PROPERTY='ouf.semantic.discovery-delegation.key-file'
CHECKSUMS=[-229176171,-370046820,1421470298,-1092036175,1905797703,648864672,1546537302,-319796023,521654427,1273060826,-1352811484,-969370259]

def need(ok,code):
 if not ok:raise RuntimeError(code)
def module(name,filename,pin):
 p=Path(__file__).with_name(filename);raw=p.read_bytes()
 need(hashlib.sha256(raw).hexdigest()==pin,'DEPENDENCY_HASH_CHANGED')
 spec=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(spec)
 exec(compile(raw,str(p),'exec'),m.__dict__);return m
def canonical(s):return re.sub('[._-]','',s).lower()
def repair_request(r,gated):
 req=r.request(gated,gated['Image']);changed=[]
 for i,entry in enumerate(req['Env']):
  key,value=entry.split('=',1)
  if canonical(key)==canonical(PROPERTY):
   need(value==BAD,'EXACT_OLD_DISCOVERY_PATH_REQUIRED')
   req['Env'][i]=key+'='+GOOD;changed.append(key)
 need(len(changed)==1,'ONE_DISCOVERY_ENV_DECLARATION_REQUIRED')
 return req,changed[0]

def exited_frame(r,gated,current):
 need(all(current.get(k)==gated.get(k) for k in ('Id','Image','Name','Config','HostConfig','Path','Args'))
  and r.mounts(current)==r.mounts(gated),'EXITED_APPLICATION_FRAME_CHANGED')
 s=current['State'];need(not s['Running'] and s['Pid']==0 and s['ExitCode']==1 and not s['OOMKilled']
  and s['StartedAt']==gated['State']['StartedAt'],'EXACT_FAILED_APPLICATION_GENERATION_REQUIRED')
 before=gated['NetworkSettings']['Networks'];now=current['NetworkSettings']['Networks']
 need(set(before)==set(now),'EXITED_NETWORK_SET_CHANGED')
 for net in before:
  for key in ('IPAMConfig','Aliases','NetworkID','Links','DriverOpts'):
   need(now[net].get(key)==before[net].get(key),'EXITED_ENDPOINT_BINDING_CHANGED')

def replace_exited(r,mac,engine,gated,observed,req,record,report):
 current=engine.inspect(gated['Id']);need(current==observed,'EXITED_INSPECT_CHANGED_BEFORE_DETACH')
 exited_frame(r,gated,current);mac.policy(gated)
 cid=gated['Id'];net=next(iter(gated['NetworkSettings']['Networks']));name=gated['Name']
 retained=name+'-before-discovery-key-fix-20261108'
 need(re.fullmatch('/[A-Za-z0-9_.-]+',name) and len(retained)<200,'BOUNDED_CONTAINER_NAME_REQUIRED')
 record('exited.private.json',current);record('request.private.json',req)
 record('detach-intent.json',{'containerId':cid,'network':net});report['failedContainerDetachDispatched']=True
 engine.api('POST','/networks/'+net+'/disconnect',{'Container':cid,'Force':False})
 detached=engine.inspect(cid);report['failedMacTransition']=r.detached(mac,gated,detached,name);record('detached.private.json',detached)
 record('rename-intent.json',{'name':retained});engine.api('POST','/containers/'+cid+'/rename?name='+retained[1:])
 r.detached(mac,gated,engine.inspect(cid),retained)
 record('create-intent.json',{'previousContainerId':cid});created=engine.api('POST','/containers/create?name='+name[1:],req)
 new=created['Id'];report['replacementContainerId']=new;record('created.json',{'containerId':new})
 actual=engine.inspect(new);r.verify_replacement(gated,req,actual,False);record('created.private.json',actual)
 record('gate-start-intent.json',{'containerId':new});engine.api('POST','/containers/'+new+'/start')
 actual=engine.inspect(new);r.verify_replacement(gated,req,actual,True);r.gate_running(actual)
 record('gated.private.json',actual);report['replacementGateStarted']=True
 return actual

def read_host_key(doc):
 mounts=[m for m in doc['Mounts'] if m['Destination']==GOOD]
 need(len(mounts)==1 and mounts[0]['Type']=='bind' and mounts[0]['RW'] is False,'EXACT_EXISTING_KEY_BIND_REQUIRED')
 path=Path(mounts[0]['Source']);need(path.is_absolute() and '..' not in path.parts,'KEY_SOURCE_PATH_INVALID')
 fds=[]
 try:
  fd=os.open('/',os.O_PATH|os.O_DIRECTORY);fds.append(fd)
  for part in path.parts[1:-1]:
   fd=os.open(part,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);fds.append(fd)
  keyfd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd);fds.append(keyfd);s=os.fstat(keyfd)
  need(stat.S_ISREG(s.st_mode) and s.st_uid==10001 and s.st_gid==10001 and stat.S_IMODE(s.st_mode)==0o400
   and s.st_nlink==1 and 64<=s.st_size<=128,'EXPECTED_EXISTING_KEY_METADATA_REQUIRED')
  raw=os.read(keyfd,129);after=os.fstat(keyfd)
  identity=lambda v:(v.st_dev,v.st_ino,v.st_size,v.st_mtime_ns,v.st_ctime_ns)
  need(identity(s)==identity(after)==identity(os.stat(path.name,dir_fd=fd,follow_symlinks=False)),'KEY_CHANGED_DURING_READ')
  value=raw.decode('ascii').strip();need(re.fullmatch('[0-9a-fA-F]{64}',value),'EXISTING_KEY_FORMAT_INVALID')
  return value,identity(s)
 finally:
  for fd in reversed(fds):os.close(fd)

def signer_binding(k,h,rows,apisix,semantic,key):
 values=k.selected(semantic,h);env=h.environment(apisix)
 for p in (PROPERTY,'ouf.semantic.delegation.key-file','ouf.iam.issuer','ouf.iam.audience','ouf.semantic.discovery-delegation.workload'):
  need(len(values[p])==1 and values[p][0]['origin']=='ENV','UNIQUE_ENV_BINDINGS_REQUIRED')
 need(values[PROPERTY][0]['value'] in (BAD,GOOD) and values['ouf.semantic.delegation.key-file'][0]['value']==GOOD,'EXACT_DECLARED_KEY_PATHS_REQUIRED')
 for path in k.PATHS:
  matches=[row for row in rows.values() if row.get('uri')==path];need(len(matches)==1,'ONE_CURRENT_SEMANTIC_ROUTE_REQUIRED')
  row=matches[0];cfg=k.constants(row)
  expected=('9a1575414108ef7255b100632561e1278f83408bdd4fa6bed07d5b09c8c18b6e' if path.endswith('/search') else
   '1d1c62ed4bc50337493f9198a11ce7cc23aaa69acde9e9be0f7e550eefec1dbd')
  need(h.digest(row['plugins']['serverless-post-function'])==expected,'OBSERVED_SIGNER_FUNCTION_CHANGED')
  need(cfg['OWNER_KEY_ENV']=='OUF_SEMANTIC_READ_OWNER_KEY' and cfg['DELEGATION_KEY_ENV']!=cfg['OWNER_KEY_ENV'],'OBSERVED_OWNER_REFERENCE_CHANGED')
  owner=env.get(cfg['OWNER_KEY_ENV']);mcp=env.get(cfg['DELEGATION_KEY_ENV'])
  need(isinstance(owner,str) and re.fullmatch('[0-9a-fA-F]{64}',owner) and hmac.compare_digest(key,owner),'GATEWAY_AND_EXISTING_KEY_DIFFER')
  need(isinstance(mcp,str) and bool(mcp) and not hmac.compare_digest(owner.encode(),mcp.encode()),'OWNER_KEY_MUST_DIFFER_FROM_MCP_DELEGATION')
  for prop,constant in (('ouf.iam.issuer','ISSUER'),('ouf.iam.audience','AUDIENCE'),('ouf.semantic.discovery-delegation.workload','MCP_WORKLOAD')):
   need(values[prop][0]['value']==cfg[constant],'DECLARED_OWNER_IAM_BINDING_DIFFERS')

def database_v12(value):
 rows=[r for r in value['migrations'] if r['version'] is not None]
 need(str(value['databaseOid'])=='21558' and value['readOnly'] and value['recoveryColumnPresent']
  and value['discoveryStates']==[] and len(rows)==12,'EXPECTED_IDLE_V12_DATABASE_REQUIRED')
 need(all(str(row['version'])==str(i+1) and row['checksum']==CHECKSUMS[i] and row['success'] is True for i,row in enumerate(rows)),
  'EXACT_V12_MIGRATION_HISTORY_REQUIRED')

def start_application(r,engine,gated,record,report):
 cid=gated['Id'];r.gate_running(engine.inspect(cid))
 record('application-start-intent.json',{'containerId':cid});report['applicationStartDispatched']=True
 engine.api('POST','/containers/'+cid+'/kill?signal=USR1')
 deadline=time.monotonic()+100
 while time.monotonic()<deadline:
  current=engine.inspect(cid);need(current['State']['Running'],'APPLICATION_EXITED')
  if r.readiness(cid):return current
  time.sleep(1)
 raise RuntimeError('READINESS_NOT_UP')

def run(report):
 need(os.geteuid()==0 and sys.flags.isolated,'ISOLATED_ROOT_REQUIRED');os.umask(0o077)
 r=module('rollout','upgrade-semantic-application-20261108.py','2e7e7e42367b3329f6ebd441bba665f974ea43871049d863415524610138efb1')
 mac=module('mac','retained_mac.py','cb5dbbee4a80ce71860dfe5d32362a662d98898c58fd82009e69c5eb6ac1f7ce')
 k=module('binding','read-semantic-discovery-key-binding-20261108.py','dad3bca82b930b2dded125183323fcb124ecb9ca127b699109498fb4ca2780a2')
 a=module('gateway','apply-gateway-analysis-delta-20261108.py','7064c8443bb323c12a56846267e4faa9cb25bf3e6dfb35455e753fbe71ce8b01')
 c,h=a.helpers();engine=r.Engine()
 need(not (ROOT/'semantic-discovery-current.json').exists(),'CURRENT_REPLACEMENT_MARKER_EXISTS')
 WORK.mkdir(mode=0o700);report['privateEvidenceDirectory']=str(WORK);record=lambda n,v:a.private(WORK,n,v)
 record('attempt.json',{'previousContainerId':CID,'changedProperty':PROPERTY,'oldPath':BAD,'newPath':GOOD})
 observed=h.parse(h.read(OBSERVED/'semantic.private.json',2*1024*1024));current=engine.inspect(CID)
 need(observed['Id']==CID and current['Image']==IMAGE and a.stable_frame(h,current)==a.stable_frame(h,observed),'OBSERVED_EXITED_REPLACEMENT_CHANGED')
 gated=h.parse(h.read(ORIGINAL/'gated.private.json',2*1024*1024));need(gated['Id']==CID,'ORIGINAL_GATED_BINDING_CHANGED')
 exited_frame(r,gated,current)
 migration=h.read(ORIGINAL/'migration.stdout.private',1024*1024)
 need(b'"status":"SEMANTIC_V11_V12_MIGRATED_VALIDATED"' in migration.replace(b' ',b''),'SUCCESSFUL_PREVIOUS_MIGRATION_REQUIRED')
 planraw=h.read(h.PLAN,1048576);need(hashlib.sha256(planraw).hexdigest()==h.PLAN_SHA,'PLAN_HASH_CHANGED');roles=h.parse(planraw)['roles']
 pg=engine.inspect(roles['postgres']['containerId']);need(pg['State']['Running'] and pg['Image']==roles['postgres']['nativeImage'],'CURRENT_POSTGRES_REQUIRED')
 original=engine.inspect(V10);need(not original['State']['Running'] and original['State']['Pid']==0 and original['NetworkSettings']['Networks']=={},'ORIGINAL_V10_MUST_REMAIN_STOPPED_DETACHED')
 env=h.environment(current);need(env.get('OUF_SCHEMA_GOV_ENABLED')=='false' and env.get('OUF_DISCOVERY_WORKER_ENABLED')=='false','PROVIDER_AND_WORKER_MUST_REMAIN_DISABLED')
 key,identity=read_host_key(current);report['existingKeyFileReads']+=1
 apisix=engine.inspect(roles['apisix']['containerId']);need(apisix['State']['Running'],'CURRENT_GATEWAY_REQUIRED')
 admin=a.Admin(c,h,apisix,report);routes=admin.routes();signer_binding(k,h,routes,apisix,current,key)
 report['existingKeyMatchesCurrentGatewaySigner']=True
 before_dir=WORK/'database-before';before_dir.mkdir(mode=0o700)
 before=a.semantic_read(c,h,current,pg,before_dir,report);database_v12(before);report['databaseBefore']=before
 req,changed=repair_request(r,gated);report['changedEnvironmentKey']=changed
 need(a.stable_frame(h,engine.inspect(CID))==a.stable_frame(h,current),'APPLICATION_CHANGED_BEFORE_REPAIR')
 fresh_key,fresh_identity=read_host_key(current);report['existingKeyFileReads']+=1
 need(identity==fresh_identity and hmac.compare_digest(key,fresh_key),'EXISTING_KEY_CHANGED_BEFORE_REPAIR')
 replacement=replace_exited(r,mac,engine,gated,current,req,record,report)
 need(r.file_sha(Path('/proc',str(replacement['State']['Pid']),'root/app/application.jar'))==r.JAR_SHA,'EXACT_CANDIDATE_JAR_REQUIRED')
 mounted,meta=c.mount_file(replacement,GOOD,True,128);report['existingKeyFileReads']+=1
 need(mounted is not None and meta['sameAsHostSource'] and meta['uid']==10001 and meta['modeOctal']=='0400'
  and hmac.compare_digest(mounted.decode('ascii').strip(),key),'REPLACEMENT_MOUNTED_KEY_DIFFERS')
 routes_after=admin.routes();need(routes_after==routes,'GATEWAY_ROUTES_CHANGED_DURING_REPAIR')
 signer_binding(k,h,routes_after,apisix,replacement,key)
 live=start_application(r,engine,replacement,record,report)
 r.verify_replacement(gated,req,live,True)
 need(Path('/proc',str(live['State']['Pid']),'cmdline').read_bytes().rstrip(b'\0').decode().split('\0')==r.JAVA,'JAVA_INIT_NOT_PROVEN')
 after_dir=WORK/'database-after';after_dir.mkdir(mode=0o700)
 after=a.semantic_read(c,h,live,pg,after_dir,report);database_v12(after)
 need(after['migrations']==before['migrations'],'MIGRATION_HISTORY_CHANGED')
 r.detached(mac,gated,engine.inspect(CID),gated['Name']+'-before-discovery-key-fix-20261108')
 need(a.stable_frame(h,engine.inspect(V10))==a.stable_frame(h,original),'ORIGINAL_V10_CHANGED')
 record('replacement.private.json',live)
 report.update(status='SEMANTIC_DISCOVERY_KEY_REPAIRED_V12_READY',readinessUp=True,
  migrationHistoryUnchanged=True,failedContainerRetainedStopped=True,originalV10RetainedStopped=True,
  sameApplicationImage=True,existingMountsPreserved=True,backendAddressAliasesPreserved=True,
  providerEnabled=False,workerEnabled=False,discoveryFunctionalTested=False)
 record('complete.json',report)
 a.private(ROOT,'semantic-discovery-current.json',{'containerId':live['Id'],'imageId':live['Image'],
  'sourceCommit':r.SOURCE,'evidenceDirectory':str(WORK),'previousContainerId':CID,'originalV10ContainerId':V10})

def main():
 report={'schema':'ouf.semantic-discovery-key-repair.v1','status':'HELD','credentialValuesEmitted':False,
  'existingKeyFileReads':0,'keyFilesWritten':0,'imageImports':0,'explicitMigrationDispatched':False,
  'readOnlyDatabaseSessionsAttempted':0,'databaseWritesByScript':0,'applicationStartupMayAccessDatabase':True,
  'failedContainerDetachDispatched':False,'replacementGateStarted':False,'applicationStartDispatched':False,
  'serviceStops':0,'adminCredentialConfigurationsRead':0,'externalAdminKeyFilesRead':0,'adminGetAttempts':0,
  'gatewayWrites':0,'providerEnableDispatched':False,'businessRequestsIssued':0,'s3Requests':0,'automaticRollback':False}
 try:run(report)
 except FileExistsError:report['reason']='EXISTING_ATTEMPT_DO_NOT_REPLAY'
 except Exception as e:
  report['reason']=str(e) if type(e) is RuntimeError and re.fullmatch('[A-Z][A-Z0-9_]{0,100}',str(e)) else type(e).__name__
  if report.get('applicationStartDispatched') and report.get('replacementContainerId'):
   try:
    reader=module('exit_reader','read-semantic-application-exit-20261108.py','68a3e85307fdefed431e3ea286ac55e32f388435522393fecc6784765c54fc00')
    meta,out,err=reader.command(WORK,'failed-startup',('logs','--timestamps','--tail','800',report['replacementContainerId']))
    report['startupLog']={'command':meta,'stdout':reader.summarize(out),'stderr':reader.summarize(err)}
   except Exception as diagnostic:report['startupLogReadError']=type(diagnostic).__name__
 report['observedAt']=datetime.now(timezone.utc).isoformat();print(json.dumps(report,sort_keys=True))
if __name__=='__main__':main()
