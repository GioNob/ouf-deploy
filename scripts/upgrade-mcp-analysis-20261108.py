#!/usr/bin/env python3
"""Exact archived MCP analysis candidate and ordinary migration14. One attempt.

Preserve current ENV/mounts, historical permits/budgets and endpoint identity.
No privileged migration12->13, capability activation, rollback or replay.
"""
import copy, hashlib, importlib.util, json, os, re, subprocess, sys, time, zipfile
from pathlib import Path
from datetime import datetime, timezone

SOURCE='907ace32100d44a0fcf1fcbda5d713ee7bd8fd94'
PUBLISHER='e2a474ea09bf9c3cb130103ca142f1a128942a80'
ZIP_SHA='2eae47d8c90b00b992bc916e5ce5a5bd32d9e724abe27d2838bd5d08ebc68d5e'
ARCHIVE_SHA='5ea15eeff97021e90eedfc74ea0b3fc53bb29dbf5a14f4f21ada564d40e88d02'
BINARY_SHA='11f9bb088b6f86d2f82c945728cb904c46d8c43a866b4df4cec2a6531e10605a'
OLD_BINARY='e1d77aecd4c7fa2c6deb7128392d12b7c651382bac6eff3b81bdbc2790758860'
CONFIG_ID='sha256:8696d3e172a15cbffb9b1ed47c8837f5cb6e6ba0b1a9b6c0aa66c5e5df5c188f'
NATIVE_ID='sha256:d76fda00f9340dcea62ed1be58b1db3ebfb4d64d4be5449ffc07ab2c845254ff'
WORK=Path('/var/lib/ouf-storage-migration/mcp-analysis-upgrade-20261108')
OBSERVED=WORK.parent/'mcp-analysis-preflight-qd7ypr55'
APP=['/usr/local/bin/ouf-mcp','server']
GATE='OUF_APPLICATION_GATE=0; trap "OUF_APPLICATION_GATE=1" USR1; while [ "$OUF_APPLICATION_GATE" = 0 ]; do sleep 1 & wait "$!"; done; exec "$@"'
ENTRY=['/bin/sh','-c',GATE,'ouf-gated-application']
DOCKER=('/usr/bin/docker','--host','unix:///run/docker.sock','--config','/nonexistent')
MESSAGES={'database connection failed','database migration failed','database migrations applied',
 'database schema is not ready; run the migration role first','manifest load failed','manifest serialization failed',
 'manifest checksum failed','manifest persistence failed','workload identity initialization failed',
 'authorization policy bundle client initialization failed','authorization policy bundle bootstrap failed',
 'invalid policy max staleness','invalid authorization bundle refresh configuration','Gateway client initialization failed',
 'fingerprint key initialization failed','invalid semantic reprocessing configuration','kernel initialization failed',
 'invalid managed upload mode','host origins must be unset for the first-party file picker','OUF MCP server listening'}

def need(ok,code):
 if not ok:raise RuntimeError(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def module(name,path,pin):
 raw=path.read_bytes();need(sha(raw)==pin,'HELPER_HASH_CHANGED')
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec)
 exec(compile(raw,str(path),'exec'),m.__dict__);return m
def request(old,image):
 c,h=copy.deepcopy(old['Config']),copy.deepcopy(old['HostConfig'])
 need(c.get('User')=='10005:10005' and c.get('WorkingDir')=='/app','MCP_IMAGE_USER_WORKDIR_REQUIRED')
 nets=old['NetworkSettings']['Networks'];need(len(nets)==1,'SINGLE_BACKEND_REQUIRED');net,ep=next(iter(nets.items()))
 need(h['NetworkMode']==net and not h.get('AutoRemove') and not h.get('VolumesFrom'),'SUPPORTED_LIFECYCLE_REQUIRED')
 need(h['RestartPolicy']=={'Name':'no','MaximumRetryCount':0},'RETAINED_RESTART_NO_REQUIRED')
 declared={m['Target'] for m in h.get('Mounts') or []};declared.update(b.split(':')[1] for b in h.get('Binds') or [])
 need(all(m['Type']=='bind' and not m['RW'] and m['Destination'] in declared for m in old['Mounts']),'EXPLICIT_READONLY_BIND_MOUNTS_REQUIRED')
 if h.get('OomKillDisable') is None:h['OomKillDisable']=False
 c['Image']=image;c.pop('MacAddress',None);c['Entrypoint']=ENTRY;c['Cmd']=APP
 c['Labels']=dict(c.get('Labels') or {},**{'org.opencontainers.image.revision':PUBLISHER,'ouf.mcp.analysis-source':SOURCE})
 ipam=copy.deepcopy(ep.get('IPAMConfig') or {});need(bool(ep.get('IPAddress')),'OBSERVED_IPV4_REQUIRED');ipam['IPv4Address']=ep['IPAddress']
 if ep.get('GlobalIPv6Address'):ipam['IPv6Address']=ep['GlobalIPv6Address']
 endpoint={'IPAMConfig':ipam,'Aliases':list(ep.get('Aliases') or []),'MacAddress':ep['MacAddress']}
 for k in ('Links','DriverOpts'):
  if ep.get(k):endpoint[k]=copy.deepcopy(ep[k])
 c.update(HostConfig=h,NetworkingConfig={'EndpointsConfig':{net:endpoint}});return c

def replace(r,engine,old,req,mac,record,report):
 mac.policy(old);record('old.private.json',old);record('request.private.json',req)
 cid=old['Id'];net=next(iter(old['NetworkSettings']['Networks']));name=old['Name'];retained=name+'-before-analysis-20261108'
 need(re.fullmatch('/[A-Za-z0-9_.-]+',name) and len(retained)<200,'BOUNDED_CONTAINER_NAME_REQUIRED')
 record('stop-intent.json',{'containerId':cid});report['oldStopDispatched']=True
 engine.api('POST','/containers/'+cid+'/stop?t=20');stopped=engine.inspect(cid)
 need(not stopped['State']['Running'] and stopped['State']['Pid']==0 and stopped['Config']==old['Config'] and
      stopped['HostConfig']==old['HostConfig'] and r.mounts(stopped)==r.mounts(old),'STOPPED_FRAME_CHANGED')
 record('stopped.private.json',stopped)
 record('detach-intent.json',{'containerId':cid,'network':net});engine.api('POST','/networks/'+net+'/disconnect',{'Container':cid,'Force':False})
 actual=engine.inspect(cid);report['oldMacTransition']=r.detached(mac,old,actual,name);record('detached.private.json',actual)
 record('rename-intent.json',{'name':retained});engine.api('POST','/containers/'+cid+'/rename?name='+retained[1:]);r.detached(mac,old,engine.inspect(cid),retained)
 record('create-intent.json',{'requestSha256':sha(json.dumps(req,sort_keys=True).encode())})
 new=engine.api('POST','/containers/create?name='+name[1:],req)['Id'];report['replacementContainerId']=new;record('created.json',{'containerId':new})
 actual=engine.inspect(new);r.verify_replacement(old,req,actual,False);record('created.private.json',actual)
 record('gate-start-intent.json',{'containerId':new});engine.api('POST','/containers/'+new+'/start');actual=engine.inspect(new)
 r.verify_replacement(old,req,actual,True);record('gated.private.json',actual);report['replacementGateStarted']=True;return actual

def gate_running(doc):
 need(Path('/proc',str(doc['State']['Pid']),'cmdline').read_bytes().rstrip(b'\0').decode().split('\0')==ENTRY+APP,'MCP_GATE_NOT_PROVEN')

def public_files(c,doc,env,keys,report):
 result={}
 for key in keys:
  raw,meta=c.mount_file(doc,env[key],True)
  need(raw is not None and meta.get('sameAsHostSource'),'PUBLIC_DEPLOYMENT_BINDING_UNPROVEN')
  report['publicReprocessingMetadataFilesRead']+=1;result[key]=raw
 return result

def read_database(p,c,h,doc,pg,work,label,report):
 user,name=c.db_binding(doc,pg,'mcp',h)
 sql=p.QUERY.replace("'checksum',checksum)","'checksum',checksum,'appliedAt',applied_at)")
 if label!='before':
  sql=sql.replace("'analysisTaskTablePresent',to_regclass('ouf_mcp.profile_analysis_task') IS NOT NULL,",
   "'analysisTaskTablePresent',to_regclass('ouf_mcp.profile_analysis_task') IS NOT NULL, 'analysisRows',(SELECT count(*) FROM ouf_mcp.profile_analysis), 'analysisTaskRows',(SELECT count(*) FROM ouf_mcp.profile_analysis_task),")
 report['readOnlyDatabaseSessionsAttempted']+=1
 result=subprocess.run((*DOCKER,'exec','-i','-e','PGOPTIONS=-c default_transaction_read_only=on',pg['Id'],
  'psql','-X','-w','-q','-A','-t','-v','ON_ERROR_STOP=1','-h','/var/run/postgresql','-U',user,'-d',name),
  input=sql.encode(),capture_output=True,timeout=12)
 c.save_private(work,label+'-database.stderr.private',result.stderr[:65536]);need(result.returncode==0 and len(result.stdout)<=131072,'DATABASE_METADATA_READ_FAILED')
 c.save_private(work,label+'-database.private.json',result.stdout);return h.parse(result.stdout)

def verify_database(value,checksums,expected_oid,prior=None):
 need(value.get('readOnly') is True and str(value.get('databaseOid'))==str(expected_oid),'EXACT_DATABASE_REQUIRED')
 count=13 if prior is None else 14
 expected=[{'version':i,'checksum':checksums[str(i)]} for i in range(1,count+1)]
 rows=value.get('migrations',[])
 need([{k:v.get(k) for k in ('version','checksum')} for v in rows]==expected,'EXACT_MIGRATION_PREFIX_REQUIRED')
 need(value['applicationRole']['superuser'] is False and all(value['applicationRole'][k] is True for k in
  ('canCreateInSchema','canUseSchema','canReadMigrationHistory','canRecordMigration')),'ORDINARY_APPLICATION_ROLE_REQUIRED')
 if prior is None:need(not value['analysisTablePresent'] and not value['analysisTaskTablePresent'],'ANALYSIS_TABLES_ALREADY_PRESENT')
 else:
  need(rows[:13]==prior['migrations'],'PRIOR_MIGRATION_HISTORY_CHANGED')
  need(value['analysisTablePresent'] and value['analysisTaskTablePresent'] and value['analysisRows']==value['analysisTaskRows']==0,'EMPTY_ANALYSIS_TABLES_REQUIRED')

def migrate(cid):
 # The command uses only the candidate's existing environment and UID. No DSN/secret argv.
 return subprocess.run((*DOCKER,'exec',cid,'timeout','-k','5','-s','TERM','60','/usr/local/bin/ouf-mcp','migrate'),capture_output=True,timeout=75)

def summarize(raw):
 found=set();unknown=0
 for line in raw.splitlines():
  try:row=json.loads(line)
  except Exception:continue
  msg=row.get('msg')
  if msg in MESSAGES:found.add(msg)
  elif msg:unknown+=1
 return {'knownStartupMessages':sorted(found),'otherMessagesOmitted':unknown,'rawLogsEmitted':False}

def readiness(doc):
 child="import http.client; c=http.client.HTTPConnection('127.0.0.1',8080,timeout=2); c.request('GET','/health/ready'); r=c.getresponse(); print(r.status); c.close()"
 p=subprocess.run(('/usr/bin/nsenter','--target',str(doc['State']['Pid']),'--net',sys.executable,'-I','-B','-S','-c',child),capture_output=True,timeout=4)
 return p.returncode==0 and p.stdout.strip()==b'204'

def run(report,archive):
 need(os.geteuid()==0 and sys.flags.isolated,'ISOLATED_ROOT_REQUIRED');base=Path(__file__).parent
 p=module('preflight',base/'read-mcp-analysis-preflight-20261108.py','bf27b875fbc0fd90beb7cf5866835762faddaaa9df9dd353b1bc22c0e32d964a')
 r=module('lifecycle',base/'upgrade-semantic-application-20261108.py','2e7e7e42367b3329f6ebd441bba665f974ea43871049d863415524610138efb1')
 a=module('private_helpers',base/'apply-gateway-analysis-delta-20261108.py','7064c8443bb323c12a56846267e4faa9cb25bf3e6dfb35455e753fbe71ce8b01')
 mac=module('mac',base/'retained_mac.py','cb5dbbee4a80ce71860dfe5d32362a662d98898c58fd82009e69c5eb6ac1f7ce')
 c,h=p.helpers();engine=r.Engine()
 need(archive.is_file() and archive.stat().st_size==9904278 and r.file_sha(archive)==ZIP_SHA,'EXACT_CANDIDATE_ZIP_REQUIRED')
 need(not (WORK.parent/'mcp-analysis-current.json').exists(),'CURRENT_MCP_REPLACEMENT_MARKER_EXISTS')
 WORK.mkdir(mode=0o700);report['privateEvidenceDirectory']=str(WORK);record=lambda n,v:a.private(WORK,n,v)
 record('attempt.json',{'sourceCommit':SOURCE,'publisherCommit':PUBLISHER,'artifactId':13593930449,'archiveSha256':ZIP_SHA})
 with zipfile.ZipFile(archive) as z:
  need(len(z.namelist())==6 and len(set(z.namelist()))==6 and z.read('source-commit.txt').strip().decode()==PUBLISHER,'CANDIDATE_PAYLOAD_CHANGED')
  c.save_private(WORK,'image.tar.gz',z.read('image.tar.gz'))
 need(r.file_sha(WORK/'image.tar.gz')==ARCHIVE_SHA,'EXACT_IMAGE_ARCHIVE_REQUIRED')
 raw=h.read(h.PLAN,1048576);need(sha(raw)==h.PLAN_SHA,'RETAINED_PLAN_CHANGED');roles=h.parse(raw)['roles']
 old=h.inspect(p.CID);observed=h.parse(h.read(OBSERVED/'mcp.private.json',2*1024*1024))
 need(h.digest(h.frame(observed))==p.FRAME and a.stable_frame(h,old)==a.stable_frame(h,observed),'CURRENT_MCP_FRAME_CHANGED')
 need(old['Image']==p.IMAGE and old['State']['Running'],'CURRENT_MCP_IMAGE_OR_STATE_CHANGED')
 need(Path('/proc',str(old['State']['Pid']),'cmdline').read_bytes().rstrip(b'\0').decode().split('\0')==APP,'CURRENT_MCP_PROCESS_CHANGED')
 need(r.file_sha(Path('/proc',str(old['State']['Pid']),'root/usr/local/bin/ouf-mcp'))==OLD_BINARY,'CURRENT_MCP_BINARY_CHANGED')
 pg=h.inspect(roles['postgres']['containerId']);need(pg['Image']==roles['postgres']['nativeImage'] and pg['State']['Running'],'POSTGRES_CHANGED')
 files=p.startup(old,c,h,WORK,report);report['startupBefore']=files
 need(all(v.get('sameAsHostSource') and v.get('status')=='MOUNTED_REGULAR_FILE' for v in files['fileBindings'].values()),'STARTUP_MOUNTED_FILES_REQUIRED')
 need(files['managedUploadMode']=='picker' and files['reprocessing'].get('expiredAtRead') is True and files['reprocessing'].get('profileHashMatchesDeclaration') is True,'OBSERVED_STARTUP_CONFIGURATION_CHANGED')
 env=h.environment(old);public=public_files(c,old,env,p.FILES[2:],report)
 before=read_database(p,c,h,old,pg,WORK,'before',report);verify_database(before,c.MCP_CHECKSUMS,'21560');report['databaseBefore']=before
 need(readiness(old),'CURRENT_MCP_NOT_READY');mac.policy(old)
 record('image-load-intent.json',{'archiveSha256':ARCHIVE_SHA});r.cli('load','--input',str(WORK/'image.tar.gz'),timeout=90);report['imageImported']=True
 image=json.loads(r.cli('image','inspect','ouf-mcp:ci'))[0]
 need(image['Id'] in (CONFIG_ID,NATIVE_ID) and image['Config']['User']=='10005:10005' and image['Config']['Entrypoint']==APP[:1] and image['Config']['Cmd']==APP[1:],'IMPORTED_IMAGE_CHANGED')
 report['candidateImageId']=image['Id'];req=request(old,image['Id'])
 need(a.stable_frame(h,h.inspect(p.CID))==a.stable_frame(h,old) and a.stable_frame(h,h.inspect(pg['Id']))==a.stable_frame(h,pg),'RUNTIME_CHANGED_BEFORE_STOP')
 live=replace(r,engine,old,req,mac,record,report);gate_running(live)
 need(r.file_sha(Path('/proc',str(live['State']['Pid']),'root/usr/local/bin/ouf-mcp'))==BINARY_SHA,'CANDIDATE_BINARY_CHANGED')
 need(public_files(c,live,env,p.FILES[2:],report)==public,'PUBLIC_DEPLOYMENT_FILES_CHANGED')
 record('migration-intent.json',{'command':'migrate','expectedNewVersions':[14]});report['migrationDispatched']=True
 result=migrate(live['Id']);c.save_private(WORK,'migration.stdout.private',result.stdout);c.save_private(WORK,'migration.stderr.private',result.stderr)
 report['migrationLog']=summarize(result.stdout+result.stderr);need(result.returncode==0,'MIGRATION_NOT_CONFIRMED')
 after=read_database(p,c,h,live,pg,WORK,'after',report);verify_database(after,c.MCP_CHECKSUMS,'21560',before)
 report['migration14Verified']=True;report['priorMigrationHistoryPreserved']=True
 gate_running(engine.inspect(live['Id']));record('application-start-intent.json',{'containerId':live['Id']});report['applicationStartDispatched']=True
 engine.api('POST','/containers/'+live['Id']+'/kill?signal=USR1')
 for _ in range(60):
  live=engine.inspect(live['Id']);need(live['State']['Running'],'APPLICATION_EXITED')
  if readiness(live):break
  time.sleep(1)
 else:raise RuntimeError('MCP_READINESS_NOT_UP')
 r.verify_replacement(old,req,live,True);r.detached(mac,old,engine.inspect(old['Id']),old['Name']+'-before-analysis-20261108')
 need(Path('/proc',str(live['State']['Pid']),'cmdline').read_bytes().rstrip(b'\0').decode().split('\0')==APP,'MCP_SERVER_INIT_NOT_PROVEN')
 need(public_files(c,live,env,p.FILES[2:],report)==public,'PUBLIC_DEPLOYMENT_FILES_CHANGED_AFTER_START')
 final=read_database(p,c,h,live,pg,WORK,'final',report);verify_database(final,c.MCP_CHECKSUMS,'21560',before)
 record('replacement.private.json',live)
 report.update(status='MCP_ANALYSIS_V14_READY',readinessHttpStatus=204,readinessUp=True,oldRetainedStopped=True,
  backendAddressAliasesPreserved=True,existingMountsPreserved=True,existingEnvironmentPreserved=True,
  expiredReprocessingFilesUnchanged=True,newToolsRemainInactive=True,analysisFunctionalTested=False)
 record('complete.json',report);a.private(WORK.parent,'mcp-analysis-current.json',{'containerId':live['Id'],'imageId':live['Image'],
  'sourceCommit':SOURCE,'publisherCommit':PUBLISHER,'evidenceDirectory':str(WORK),'previousContainerId':old['Id']})

def main():
 report={'schema':'ouf.mcp-analysis-upgrade.v1','status':'HELD','credentialValuesEmitted':False,
  'readOnlyDatabaseSessionsAttempted':0,'publicReprocessingMetadataFilesRead':0,'oldStopDispatched':False,
  'imageImported':False,'migrationDispatched':False,'applicationStartDispatched':False,'automaticRollback':False,
  'businessRequestsIssued':0,'s3Requests':0,'gatewayWrites':0,'permissionChanges':0,'credentialFileWrites':0,
  'applicationStartupMayRequestTokensAndAccessDatabase':True,'privilegedMigrationDispatched':False}
 try:
  need(len(sys.argv)==2,'EXACT_CANDIDATE_ZIP_ARGUMENT_REQUIRED');run(report,Path(sys.argv[1]))
 except FileExistsError:report['reason']='EXISTING_ATTEMPT_DO_NOT_REPLAY'
 except Exception as e:
  report['reason']=str(e) if type(e) is RuntimeError and re.fullmatch('[A-Z][A-Z0-9_]{0,100}',str(e)) else type(e).__name__
  if report.get('replacementContainerId'):
   try:
    result=subprocess.run((*DOCKER,'logs','--tail','100',report['replacementContainerId']),capture_output=True,timeout=10)
    report['startupLog']=summarize(result.stdout+result.stderr)
    for name,raw in [('application.stdout.private',result.stdout),('application.stderr.private',result.stderr)]:
     fd=os.open(WORK/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
     with os.fdopen(fd,'wb') as f:f.write(raw)
   except Exception:report['startupLogReadIncomplete']=True
 report['observedAt']=datetime.now(timezone.utc).isoformat();print(json.dumps(report,sort_keys=True))
if __name__=='__main__':main()
