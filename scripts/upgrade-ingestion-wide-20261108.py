#!/usr/bin/env python3
"""Install the exact archived Ingestion CSV candidate; retain V18 and runtime data.

One attempt, one backend, exact retained generation, no explicit migration,
rollback, replay or new business request. Startup may run existing application work.
"""
import copy, hashlib, importlib.util, json, os, re, subprocess, sys, time, zipfile
from pathlib import Path
from datetime import datetime, timezone
SOURCE='c85d9fd3be215e518dc6e7d075797720b5afbd91'
ZIP_SHA='83e15e242528d9128ddf5a813d0a9d4512f4076d07f845bab6a63ca1456b0109'
ARCHIVE_SHA='6861abc6d2cbc41d8df07546c205a3b8268d0458a6f678b29cd8515350194dae'
JAR_SHA='d0e2acc49fe91998b7182d107d1b6f02b1f1da6b49a5520dd6f6eaefa5295523'
OLD_JAR='54424047880b6c96c512efb55dbd1c241e98180f4d679c342760980385f771f1'
CONFIG_ID='sha256:ac7936d6efe094479ad9abaacc3c2ec9910e3e03df96baab9b4aad754f2a954c'
NATIVE_ID='sha256:562e4c6e19d5227f00fb3159deb506da256d2245ee4a40a652b0c03865704baa'
WORK=Path('/var/lib/ouf-storage-migration/ingestion-wide-upgrade-20261108')
OBSERVED=WORK.parent/'ingestion-wide-preflight-ux56chih'
GATE='OUF_APPLICATION_GATE=0; trap "OUF_APPLICATION_GATE=1" USR1; while [ "$OUF_APPLICATION_GATE" = 0 ]; do sleep 1 & wait "$!"; done; exec "$@"'
ENTRY=['/bin/sh','-c',GATE,'ouf-gated-application']
DOCKER=('/usr/bin/docker','--host','unix:///run/docker.sock','--config','/nonexistent')
TABLES=('ing_run','ing_partition','processing_attempt','ing_lineage','handoff_outbox','runtime_configuration_snapshot','ing_schedule')
def need(ok,code):
 if not ok:raise RuntimeError(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def module(name,path,pin):
 raw=path.read_bytes();need(sha(raw)==pin,'HELPER_HASH_CHANGED')
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);exec(compile(raw,str(path),'exec'),m.__dict__);return m
def process(doc):return Path('/proc',str(doc['State']['Pid']),'cmdline').read_bytes().rstrip(b'\0').decode().split('\0')
def app_check(env,app):
 need(Path(app[0]).name=='java' and app.count('-jar')==1 and app[app.index('-jar')+1]=='/app/app.jar','KNOWN_JAVA_LAUNCH_REQUIRED')
 need(env.get('SPRING_FLYWAY_ENABLED')=='false' and [a for a in app if a.startswith('--spring.flyway.enabled')]==['--spring.flyway.enabled=false'],'EXPLICIT_FLYWAY_DISABLED_REQUIRED')
def request(old,image,app,mac):
 mac.policy(old);c,h=copy.deepcopy(old['Config']),copy.deepcopy(old['HostConfig'])
 app_check(dict(v.split('=',1) for v in c['Env']),app)
 need(c.get('User')=='10002:10002' and c.get('WorkingDir')=='/app','INGESTION_USER_WORKDIR_REQUIRED')
 nets=old['NetworkSettings']['Networks'];need(len(nets)==1,'SINGLE_BACKEND_REQUIRED');net,ep=next(iter(nets.items()))
 need(h['NetworkMode']==net and not h.get('AutoRemove') and not h.get('VolumesFrom'),'SUPPORTED_LIFECYCLE_REQUIRED')
 need(h['RestartPolicy']=={'Name':'no','MaximumRetryCount':0},'RETAINED_RESTART_NO_REQUIRED')
 declared={m['Target'] for m in h.get('Mounts') or []};declared.update(b.split(':')[1] for b in h.get('Binds') or [])
 need(all(m['Type']=='bind' and not m['RW'] and m['Destination'] in declared for m in old['Mounts']),'EXPLICIT_READONLY_BIND_MOUNTS_REQUIRED')
 need(not any('/app/app.jar'==m['Destination'] or '/app/app.jar'.startswith(m['Destination'].rstrip('/')+'/') for m in old['Mounts']),'IMAGE_JAR_MUST_NOT_BE_MOUNTED')
 if h.get('OomKillDisable') is None:h['OomKillDisable']=False
 c['Image']=image;c.pop('MacAddress',None);c['Entrypoint']=ENTRY;c['Cmd']=list(app)
 c['Labels']=dict(c.get('Labels') or {},**{'org.opencontainers.image.revision':SOURCE,'ouf.ingestion.wide-source':SOURCE})
 c['Env']=[('JAVA_VERSION=jdk-21.0.13+9' if x.startswith('JAVA_VERSION=') else x) for x in c['Env']]
 ipam=copy.deepcopy(ep.get('IPAMConfig') or {});need(bool(ep.get('IPAddress')),'OBSERVED_IPV4_REQUIRED');ipam['IPv4Address']=ep['IPAddress']
 if ep.get('GlobalIPv6Address'):ipam['IPv6Address']=ep['GlobalIPv6Address']
 endpoint={'IPAMConfig':ipam,'Aliases':list(ep.get('Aliases') or []),'MacAddress':ep['MacAddress']}
 for k in ('Links','DriverOpts'):
  if ep.get(k):endpoint[k]=copy.deepcopy(ep[k])
 c.update(HostConfig=h,NetworkingConfig={'EndpointsConfig':{net:endpoint}});return c

def detached(mac,old,actual,name):
 result=mac.verify_detached(old,actual,expected_name=name)
 need(actual['Path']==old['Path'] and actual['Args']==old['Args'],'DETACHED_LAUNCH_CHANGED')
 return result['profile']
def replace(r,engine,old,req,mac,record,report,stopped_check):
 mac.policy(old);record('old.private.json',old);record('request.private.json',req)
 cid=old['Id'];net=next(iter(old['NetworkSettings']['Networks']));name=old['Name'];retained=name+'-before-wide-20261108'
 need(re.fullmatch('/[A-Za-z0-9_.-]+',name) and len(retained)<200,'BOUNDED_CONTAINER_NAME_REQUIRED')
 record('stop-intent.json',{'containerId':cid});report['oldStopDispatched']=True
 engine.api('POST','/containers/'+cid+'/stop?t=35');stopped=engine.inspect(cid)
 need(not stopped['State']['Running'] and stopped['State']['Pid']==0 and stopped['State']['StartedAt']==old['State']['StartedAt'] and
      all(stopped[k]==old[k] for k in ('Config','HostConfig','Path','Args')) and r.mounts(stopped)==r.mounts(old),'STOPPED_FRAME_CHANGED')
 record('stopped.private.json',stopped);stopped_check()
 record('detach-intent.json',{'containerId':cid,'network':net});engine.api('POST','/networks/'+net+'/disconnect',{'Container':cid,'Force':False})
 actual=engine.inspect(cid);report['oldMacTransition']=detached(mac,old,actual,name);record('detached.private.json',actual)
 record('rename-intent.json',{'name':retained});engine.api('POST','/containers/'+cid+'/rename?name='+retained[1:]);detached(mac,old,engine.inspect(cid),retained)
 record('create-intent.json',{'requestSha256':sha(json.dumps(req,sort_keys=True).encode())})
 new=engine.api('POST','/containers/create?name='+name[1:],req)['Id'];report['replacementContainerId']=new;record('created.json',{'containerId':new})
 actual=engine.inspect(new);r.verify_replacement(old,req,actual,False);record('created.private.json',actual)
 record('gate-start-intent.json',{'containerId':new});engine.api('POST','/containers/'+new+'/start');actual=engine.inspect(new)
 r.verify_replacement(old,req,actual,True);record('gated.private.json',actual);report['replacementGateStarted']=True;return actual

def database_query(p,oldhelper):
 # Hash only on the database side; no row payload/identifier/checkpoint leaves PostgreSQL.
 parts=[]
 for table in TABLES:
  parts.append("'%s',(SELECT json_build_object('rows',count(*),'fingerprint',md5(coalesce(string_agg(d,',' ORDER BY d),''))) FROM (SELECT md5(row_to_json(t)::text) d FROM ouf_ingestion.%s t) x)"%(table,table))
 return p.query(oldhelper).replace("'applicationRoleSuperuser'","'retainedRows',json_build_object("+','.join(parts)+"),'applicationRoleSuperuser'")
def read_database(p,oldhelper,c,h,doc,pg,work,label,report):
 user,name=p.db_binding(doc,pg,c,h);report['readOnlyDatabaseSessionsAttempted']+=1
 q=subprocess.run((*DOCKER,'exec','-i','-e','PGOPTIONS=-c default_transaction_read_only=on',pg['Id'],
  'psql','-X','-w','-q','-A','-t','-v','ON_ERROR_STOP=1','-h','/var/run/postgresql','-U',user,'-d',name),
  input=database_query(p,oldhelper).encode(),capture_output=True,timeout=12)
 c.save_private(work,label+'-database.stderr.private',q.stderr[:65536]);need(q.returncode==0 and len(q.stdout)<=131072,'DATABASE_READ_FAILED')
 c.save_private(work,label+'-database.private.json',q.stdout);return p.result(oldhelper,h.parse(q.stdout),p.manifest())
def verify_database(value,oid,prior=None):
 need(value.get('readOnly') is True and str(value.get('databaseOid'))==str(oid) and value.get('exactCandidateMigrationHistory') is True and
      value.get('applicationRoleSuperuser') is False,'EXACT_ORDINARY_DATABASE_HISTORY_REQUIRED')
 need(set(value['activity']['runStates'])<={'SUCCEEDED'} and set(value['activity']['handoffStates'])<={'ACKED'} and
      value['activity']['unexpiredPartitionLeases']==0,'UNFINISHED_WORK_REQUIRES_RECONCILIATION')
 rows=value.get('retainedRows');need(isinstance(rows,dict) and set(rows)==set(TABLES),'RETAINED_TABLE_FINGERPRINTS_REQUIRED')
 need(all(type(v.get('rows'))is int and v['rows']>=0 and re.fullmatch('[a-f0-9]{32}',v.get('fingerprint','')) for v in rows.values()),'INVALID_TABLE_FINGERPRINT')
 if prior is not None:need(all(value[k]==prior[k] for k in ('migrations','activity','retainedRows')),'RETAINED_DATABASE_STATE_CHANGED')
def readiness(doc):
 child="import http.client,json; c=http.client.HTTPConnection('127.0.0.1',8080,timeout=2); c.request('GET','/actuator/health/readiness'); r=c.getresponse(); b=r.read(65537); print('UP' if r.status==200 and len(b)<=65536 and json.loads(b).get('status')=='UP' else 'DOWN'); c.close()"
 q=subprocess.run(('/usr/bin/nsenter','--target',str(doc['State']['Pid']),'--net',sys.executable,'-I','-B','-S','-c',child),capture_output=True,timeout=4)
 return q.returncode==0 and q.stdout.strip()==b'UP'
def run(report,archive):
 need(os.geteuid()==0 and sys.flags.isolated,'ISOLATED_ROOT_REQUIRED');base=Path(__file__).parent
 p=module('preflight',base/'read-ingestion-wide-preflight-20261108.py','4e04370c60cba787b1e125a7b934cc03bf6d8fc1dc0c867ae5c27b56e82be26f')
 r=module('lifecycle',base/'upgrade-semantic-application-20261108.py','2e7e7e42367b3329f6ebd441bba665f974ea43871049d863415524610138efb1')
 mac=module('mac',base/'retained_mac.py','cb5dbbee4a80ce71860dfe5d32362a662d98898c58fd82009e69c5eb6ac1f7ce')
 oldhelper,c,h=p.helpers();engine=r.Engine()
 need(archive.is_file() and archive.stat().st_size==132176251 and r.file_sha(archive)==ZIP_SHA,'EXACT_ARCHIVED_ZIP_REQUIRED')
 need(not (WORK.parent/'ingestion-wide-current.json').exists(),'CURRENT_REPLACEMENT_MARKER_EXISTS')
 WORK.mkdir(mode=0o700);report['privateEvidenceDirectory']=str(WORK)
 record=lambda n,v:c.save_private(WORK,n,(json.dumps(v,sort_keys=True)+'\n').encode())
 record('attempt.json',{'sourceCommit':SOURCE,'artifactId':13633320899,'archiveSha256':ZIP_SHA})
 with zipfile.ZipFile(archive) as z:
  need(sorted(z.namelist())==['SHA256SUMS','image.tar.gz','manifest.json'],'ARCHIVE_MEMBERS_CHANGED')
  c.save_private(WORK,'image.tar.gz',z.read('image.tar.gz'))
 need(r.file_sha(WORK/'image.tar.gz')==ARCHIVE_SHA,'EXACT_IMAGE_ARCHIVE_REQUIRED')
 raw=h.read(h.PLAN,1048576);need(sha(raw)==h.PLAN_SHA,'RETAINED_PLAN_CHANGED');roles=h.parse(raw)['roles']
 old=h.inspect(p.CID);observed=h.parse(h.read(OBSERVED/'ingestion.private.json',2*1024*1024))
 need(h.digest(h.frame(observed))==p.FRAME and h.frame(old)==h.frame(observed),'CURRENT_INGESTION_FRAME_CHANGED')
 need(old['Image']==p.IMAGE and old['State']['Running'],'CURRENT_INGESTION_IMAGE_STATE_CHANGED')
 app=process(old);app_check(h.environment(old),app)
 need(r.file_sha(Path('/proc',str(old['State']['Pid']),'root/app/app.jar'))==OLD_JAR,'CURRENT_JAR_CHANGED')
 need(len(old['Mounts'])==4 and set(old['NetworkSettings']['Networks'])=={'ouf-backend'},'OBSERVED_MOUNTS_NETWORK_REQUIRED')
 pg=h.inspect(roles['postgres']['containerId']);need(pg['Image']==roles['postgres']['nativeImage'] and pg['State']['Running'],'POSTGRES_CHANGED')
 before=read_database(p,oldhelper,c,h,old,pg,WORK,'before',report);verify_database(before,'21554')
 report['activityBefore']=before['activity'];need(readiness(old),'CURRENT_INGESTION_NOT_READY');mac.policy(old)
 record('image-load-intent.json',{'archiveSha256':ARCHIVE_SHA});r.cli('load','--input',str(WORK/'image.tar.gz'),timeout=120);report['imageImported']=True
 image=json.loads(r.cli('image','inspect','ouf-ingestion:'+SOURCE))[0]
 need(image['Id'] in (CONFIG_ID,NATIVE_ID) and image['Config']['User']=='10002:10002' and image['Config']['Entrypoint']==['java','-jar','/app/app.jar'],'IMPORTED_IMAGE_CHANGED')
 report['candidateImageId']=image['Id'];req=request(old,image['Id'],app,mac)
 need(h.frame(h.inspect(p.CID))==h.frame(old) and h.frame(h.inspect(pg['Id']))==h.frame(pg) and process(old)==app,'RUNTIME_CHANGED_BEFORE_STOP')
 def stopped_check():
  stopped=read_database(p,oldhelper,c,h,old,pg,WORK,'stopped',report);verify_database(stopped,'21554',before)
 live=replace(r,engine,old,req,mac,record,report,stopped_check)
 need(process(live)==ENTRY+app,'GATE_NOT_PROVEN');need(r.file_sha(Path('/proc',str(live['State']['Pid']),'root/app/app.jar'))==JAR_SHA,'CANDIDATE_JAR_CHANGED')
 record('application-start-intent.json',{'containerId':live['Id']});report['applicationStartDispatched']=True
 engine.api('POST','/containers/'+live['Id']+'/kill?signal=USR1')
 for _ in range(60):
  live=engine.inspect(live['Id']);need(live['State']['Running'],'APPLICATION_EXITED')
  if readiness(live):break
  time.sleep(1)
 else:raise RuntimeError('INGESTION_READINESS_NOT_UP')
 r.verify_replacement(old,req,live,True);detached(mac,old,engine.inspect(old['Id']),old['Name']+'-before-wide-20261108')
 need(process(live)==app,'JAVA_ARGUMENTS_CHANGED')
 final=read_database(p,oldhelper,c,h,live,pg,WORK,'final',report);verify_database(final,'21554',before)
 record('replacement.private.json',live)
 report.update(status='INGESTION_WIDE_1024_READY',readinessHttpStatus=200,readinessUp=True,oldRetainedStopped=True,
  backendAddressAliasesMacPreserved=True,existingMountsPreserved=True,environmentPreservedExceptImageJavaVersion=True,
  javaProcessArgumentsPreserved=True,flywayDisabledDeclarationsPreserved=True,migrationHistoryUnchanged=True,
  retainedTablesCompared=list(TABLES),retainedRowsUnchanged=True,wideIngestionFunctionalTested=False)
 record('complete.json',report);c.save_private(WORK.parent,'ingestion-wide-current.json',(json.dumps({'containerId':live['Id'],'imageId':live['Image'],
  'sourceCommit':SOURCE,'evidenceDirectory':str(WORK),'previousContainerId':old['Id']},sort_keys=True)+'\n').encode())
def main():
 report={'schema':'ouf.ingestion-wide-upgrade.v1','status':'HELD','credentialValuesEmitted':False,'credentialFileContentsRead':0,
  'readOnlyDatabaseSessionsAttempted':0,'oldStopDispatched':False,'imageImported':False,'explicitMigrationDispatched':False,
  'applicationStartDispatched':False,'automaticRollback':False,'automaticReplay':False,'businessRequestsIssued':0,
  's3RequestsByScript':0,'gatewayWrites':0,'permissionChanges':0,'credentialFileWrites':0,'databaseWritesByScript':0,
  'applicationStartupMayAccessDatabaseAndExistingWork':True,'rowPayloadsEmitted':False}
 try:
  need(len(sys.argv)==2,'EXACT_CANDIDATE_ZIP_ARGUMENT_REQUIRED');run(report,Path(sys.argv[1]))
 except FileExistsError:report['reason']='EXISTING_ATTEMPT_DO_NOT_REPLAY'
 except Exception as e:
  report['reason']=str(e) if type(e)is RuntimeError and re.fullmatch('[A-Z][A-Z0-9_]{0,100}',str(e)) else type(e).__name__
  if report.get('replacementContainerId'):
   try:
    q=subprocess.run((*DOCKER,'logs','--tail','120',report['replacementContainerId']),capture_output=True,timeout=10)
    for name,raw in [('application.stdout.private',q.stdout),('application.stderr.private',q.stderr)]:
     fd=os.open(WORK/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
     with os.fdopen(fd,'wb') as f:f.write(raw)
    report['privateStartupLogsRetained']=True
   except Exception:report['privateStartupLogsRetained']=False
 report['observedAt']=datetime.now(timezone.utc).isoformat();print(json.dumps(report,sort_keys=True))
if __name__=='__main__':main()
