#!/usr/bin/env python3
"""Residual Ingestion replacement from the verified stopped prefix. No stop/import/replay."""
import copy,json,os,re,subprocess,sys,time
from pathlib import Path
from datetime import datetime,timezone
import hashlib,importlib.util
ROOT=Path('/var/lib/ouf-storage-migration/ingestion-wide-upgrade-20261108')
READ=ROOT.parent/'ingestion-resume-read-pycdpafx'
WORK=ROOT.parent/'ingestion-wide-resume-20261108'
FRAME='8531475a2343ba3640d50f18afe4e3b45f33ed1eebe72ee55e02875a8e4073a4'
DATABASE_SHA='e9d395e58d4ac98c54ff36c6c4df8fbf66db12361bc0b31f8974899cbb939929'
TABLES=('ing_run','ing_partition','processing_attempt','ing_lineage','handoff_outbox','runtime_configuration_snapshot','ing_schedule')
POLL_FIELDS={'discoveryVerifiedAt','lockVersion'}
REQUIRED=('attempt.json','image-load-intent.json','stop-intent.json','stopped.private.json')
ABSENT=('detach-intent.json','detached.private.json','rename-intent.json','create-intent.json','created.json','gate-start-intent.json','application-start-intent.json','complete.json')
def need(ok,code):
 if not ok:raise RuntimeError(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def module(name,path,pin):
 raw=path.read_bytes();need(sha(raw)==pin,'HELPER_HASH_CHANGED');s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);exec(compile(raw,str(path),'exec'),m.__dict__);return m
def helpers():
 b=Path(__file__).parent
 u=module('upgrade',b/'upgrade-ingestion-wide-20261108.py','f345e549aa75531f77a244966951ed775e98d90e0e24ebad85940a4bba7b8ee8')
 p=module('prerequisites',b/'read-ingestion-resume-prerequisites-20261108.py','0ea9e19b93be285f72e3431b38beb66814392f42e1023733c0728387563c0ab2')
 r=module('lifecycle',b/'upgrade-semantic-application-20261108.py','2e7e7e42367b3329f6ebd441bba665f974ea43871049d863415524610138efb1')
 mac=module('mac',b/'retained_mac.py','cb5dbbee4a80ce71860dfe5d32362a662d98898c58fd82009e69c5eb6ac1f7ce')
 c,h,f=p.helpers();return u,p,r,mac,c,h,f
def journal_guard(root,marker):
 need(not marker.exists(),'CURRENT_REPLACEMENT_MARKER_EXISTS')
 need(all((root/n).is_file() for n in REQUIRED) and not any((root/n).exists() for n in ABSENT),'EXACT_STOPPED_PREFIX_REQUIRED')
def stopped_guard(old,stopped,observed,current,h,r,mac):
 mac.policy(old)
 need(h.frame(stopped)==h.frame(observed)==h.frame(current),'STOPPED_FRAME_CHANGED')
 need(current['Id']==old['Id'] and current['Image']==old['Image'] and current['Name']==old['Name'],'STOPPED_IDENTITY_CHANGED')
 s=current['State'];need(s['Pid']==0 and not s['Running'] and not s['Restarting'] and not s['Paused'] and not s.get('OOMKilled') and s['StartedAt']==old['State']['StartedAt'],'OLD_STOPPED_GENERATION_REQUIRED')
 need(all(current[k]==old[k] for k in ('Config','HostConfig','Path','Args')) and r.mounts(current)==r.mounts(old),'STOPPED_CONFIGURATION_CHANGED')
 need(set(current['NetworkSettings']['Networks'])==set(old['NetworkSettings']['Networks']),'STOPPED_NETWORK_CHANGED')
def validate_database(v,oid):
 need(v.get('readOnly') is True and v.get('applicationRoleSuperuser') is False and str(v.get('databaseOid'))==str(oid),'ORDINARY_READ_ONLY_DATABASE_REQUIRED')
 need(isinstance(v.get('migrations'),list) and len(v['migrations'])==19 and all(x.get('success') is True for x in v['migrations']),'V18_HISTORY_REQUIRED')
 a=v.get('activity',{});need(set(a.get('runStates',{}))<= {'SUCCEEDED'} and set(a.get('handoffStates',{}))<= {'ACKED'} and a.get('unexpiredPartitionLeases')==0,'UNFINISHED_WORK_REQUIRES_RECONCILIATION')
 rows=v.get('retainedRows');need(isinstance(rows,dict) and set(rows)==set(TABLES),'EXACT_TABLE_SET_REQUIRED')
 need(all(type(x.get('rows'))is int and x['rows']>=0 and re.fullmatch('[a-f0-9]{32}',x.get('fingerprint','')) for x in rows.values()),'TABLE_FINGERPRINT_SHAPE')
 need(re.fullmatch('[a-f0-9]{32}',v.get('scheduleStableFingerprint','')),'SCHEDULE_FINGERPRINT_SHAPE')
 ss=v.get('scheduleMetadata');need(isinstance(ss,list) and len(ss)==2 and rows['ing_schedule']['rows']==2,'TWO_RETAINED_SCHEDULES_REQUIRED')
 for i,s in enumerate(ss,1):
  need(s.get('ordinal')==i and s.get('state')=='DISABLED' and s.get('triggerOnce') is True and s.get('publicationEnabled') is True and s.get('publicationPresent') is True and s.get('currentPublicationConsumed') is True and s.get('intervalSeconds')==0 and s.get('activationBlocked') is False and s.get('activationFailures')==0 and s.get('leaseOwnerPresent') is False and s.get('unexpiredLease') is False and s.get('leaseUntil') is None,'DISABLED_CONSUMED_UNLEASED_SCHEDULES_REQUIRED')
  need(type(s.get('lockVersion'))is int and s['lockVersion']>=0 and isinstance(s.get('discoveryVerifiedAt'),str) and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z',s['discoveryVerifiedAt']),'POLL_METADATA_SHAPE')
  datetime.fromisoformat(s['discoveryVerifiedAt'])
def compare_database(before,after,oid,allow_poll=False):
 validate_database(before,oid);validate_database(after,oid)
 need(all(before[k]==after[k] for k in ('migrations','activity','scheduleStableFingerprint')),'RETAINED_DATABASE_STATE_CHANGED')
 need(all(before['retainedRows'][t]==after['retainedRows'][t] for t in TABLES if t!='ing_schedule'),'RETAINED_BUSINESS_ROWS_CHANGED')
 if not allow_poll:
  need(before==after,'STOPPED_DATABASE_STATE_CHANGED');return False
 changed=False
 for a,b in zip(before['scheduleMetadata'],after['scheduleMetadata']):
  need({k:v for k,v in a.items() if k not in POLL_FIELDS}=={k:v for k,v in b.items() if k not in POLL_FIELDS},'SCHEDULE_OPERATIONAL_METADATA_CHANGED')
  need(b['lockVersion']>=a['lockVersion'] and b['discoveryVerifiedAt']>=a['discoveryVerifiedAt'],'POLL_METADATA_REGRESSED')
  need(b['lockVersion']!=a['lockVersion'] or b['discoveryVerifiedAt']==a['discoveryVerifiedAt'],'POLL_TIMESTAMP_WITHOUT_VERSION_CHANGE')
  changed=changed or a!=b
 need(changed or before['retainedRows']['ing_schedule']==after['retainedRows']['ing_schedule'],'SCHEDULE_FINGERPRINT_WITHOUT_POLL_CHANGE')
 return changed
def residual(u,r,engine,mac,old,req,record,report,prestart):
 # Caller has checked the stopped prefix and fresh DB. There is deliberately no STOP or LOAD.
 cid=old['Id'];net=next(iter(old['NetworkSettings']['Networks']));name=old['Name'];retained=name+'-before-wide-20261108'
 need(re.fullmatch('/[A-Za-z0-9_.-]+',name) and len(retained)<200,'BOUNDED_CONTAINER_NAME_REQUIRED')
 record('detach-intent.json',{'containerId':cid,'network':net});report['oldDetachDispatched']=True
 engine.api('POST','/networks/'+net+'/disconnect',{'Container':cid,'Force':False})
 actual=engine.inspect(cid);report['oldMacTransition']=u.detached(mac,old,actual,name);record('detached.private.json',actual)
 record('rename-intent.json',{'name':retained});engine.api('POST','/containers/'+cid+'/rename?name='+retained[1:]);u.detached(mac,old,engine.inspect(cid),retained)
 record('create-intent.json',{'requestSha256':sha(json.dumps(req,sort_keys=True).encode())})
 new=engine.api('POST','/containers/create?name='+name[1:],req)['Id'];report['replacementContainerId']=new;record('created.json',{'containerId':new})
 actual=engine.inspect(new);r.verify_replacement(old,req,actual,False);record('created.private.json',actual)
 record('gate-start-intent.json',{'containerId':new});engine.api('POST','/containers/'+new+'/start');actual=engine.inspect(new)
 r.verify_replacement(old,req,actual,True);report['replacementGateStarted']=True;record('gated.private.json',actual)
 need(u.process(actual)==u.ENTRY+req['Cmd'],'GATE_NOT_PROVEN')
 need(r.file_sha(Path('/proc',str(actual['State']['Pid']),'root/app/app.jar'))==u.JAR_SHA,'CANDIDATE_JAR_CHANGED')
 prestart(actual)
 record('application-start-intent.json',{'containerId':new});report['applicationStartDispatched']=True;engine.api('POST','/containers/'+new+'/kill?signal=USR1')
 for _ in range(60):
  actual=engine.inspect(new);need(actual['State']['Running'],'APPLICATION_EXITED')
  if u.readiness(actual):break
  time.sleep(1)
 else:raise RuntimeError('INGESTION_READINESS_NOT_UP')
 r.verify_replacement(old,req,actual,True);u.detached(mac,old,engine.inspect(cid),retained)
 need(u.process(actual)==req['Cmd'],'JAVA_ARGUMENTS_CHANGED');return actual
def read_database(p,c,h,doc,pg,label,report):
 user,name=p.db_binding(doc,pg,c,h);report['readOnlyDatabaseSessionsAttempted']+=1
 q=subprocess.run((*c.DOCKER,'exec','-i','-e','PGOPTIONS=-c default_transaction_read_only=on',pg['Id'],'psql','-X','-w','-q','-A','-t','-v','ON_ERROR_STOP=1','-h','/var/run/postgresql','-U',user,'-d',name),input=p.query().encode(),capture_output=True,timeout=12)
 c.save_private(WORK,label+'-database.stderr.private',q.stderr[:65536]);need(q.returncode==0 and len(q.stdout)<=131072,'DATABASE_READ_FAILED')
 c.save_private(WORK,label+'-database.private.json',q.stdout);return h.parse(q.stdout)
def run(report):
 need(os.geteuid()==0 and sys.flags.isolated and len(sys.argv)==1,'ISOLATED_ROOT_NO_ARGUMENTS_REQUIRED')
 u,p,r,mac,c,h,f=helpers();engine=r.Engine();marker=ROOT.parent/'ingestion-wide-current.json';journal_guard(ROOT,marker)
 originals={n:h.read(ROOT/n,2097152) for n in ('attempt.json','image-load-intent.json','stop-intent.json','old.private.json','stopped.private.json','request.private.json','stopped-database.private.json')}
 old=h.parse(originals['old.private.json']);stopped=h.parse(originals['stopped.private.json']);req=h.parse(originals['request.private.json'])
 need(old['Id']==p.CID and old['Image']==p.IMAGE,'EXACT_OLD_IDENTITY_REQUIRED')
 need(h.parse(originals['attempt.json'])=={'sourceCommit':u.SOURCE,'artifactId':13633320899,'archiveSha256':u.ZIP_SHA} and h.parse(originals['image-load-intent.json'])=={'archiveSha256':u.ARCHIVE_SHA} and h.parse(originals['stop-intent.json'])=={'containerId':p.CID},'HELD_INTENT_CHANGED')
 observed=h.parse(h.read(READ/'current-ingestion.private.json',2097152));need(h.digest(h.frame(observed))==FRAME,'OBSERVED_FRAME_PIN_CHANGED')
 stopped_guard(old,stopped,observed,h.inspect(p.CID),h,r,mac)
 raw=h.read(READ/'database.private.json',131072);need(sha(raw)==DATABASE_SHA,'OBSERVED_DATABASE_PIN_CHANGED');baseline=h.parse(raw)
 p.database_summary(baseline,h.parse(originals['stopped-database.private.json']),f)
 need(all(baseline[k]==h.parse(originals['stopped-database.private.json'])[k] for k in ('migrations','activity','retainedRows')),'STOPPED_DATABASE_EVIDENCE_CHANGED')
 image=engine.api('GET','/images/'+u.NATIVE_ID+'/json');need(image['Id']==u.NATIVE_ID and image['Config']['User']=='10002:10002' and image['Config']['Entrypoint']==['java','-jar','/app/app.jar'],'IMPORTED_IMAGE_CHANGED')
 need(u.request(old,u.NATIVE_ID,req['Cmd'],mac)==req,'RETAINED_CREATE_REQUEST_CHANGED');report['candidateImageId']=u.NATIVE_ID
 rawplan=h.read(h.PLAN,1048576);need(sha(rawplan)==h.PLAN_SHA,'RETAINED_PLAN_CHANGED');role=h.parse(rawplan)['roles']['postgres']
 pg=h.inspect(role['containerId']);need(pg['Image']==role['nativeImage'] and pg['State']['Running'],'POSTGRES_BINDING_CHANGED')
 WORK.mkdir(mode=0o700);report['privateEvidenceDirectory']=str(WORK)
 record=lambda n,v:c.save_private(WORK,n,(json.dumps(v,sort_keys=True)+'\n').encode())
 record('attempt.json',{'sourceCommit':u.SOURCE,'previousAttempt':str(ROOT),'observedFrameSha256':FRAME,'observedDatabaseSha256':DATABASE_SHA})
 record('request.private.json',req);before=read_database(p,c,h,old,pg,'before',report);compare_database(baseline,before,'21554')
 journal_guard(ROOT,marker);need(all(h.read(ROOT/n,2097152)==raw for n,raw in originals.items()),'RETAINED_FILES_CHANGED')
 stopped_guard(old,stopped,observed,h.inspect(p.CID),h,r,mac);need(h.frame(h.inspect(pg['Id']))==h.frame(pg),'POSTGRES_CHANGED')
 def prestart(doc):compare_database(before,read_database(p,c,h,doc,pg,'prestart',report),'21554')
 live=residual(u,r,engine,mac,old,req,record,report,prestart)
 after=read_database(p,c,h,live,pg,'final',report);poll=compare_database(before,after,'21554',allow_poll=True)
 record('replacement.private.json',live)
 report.update(status='INGESTION_WIDE_1024_READY',readinessUp=True,readinessHttpStatus=200,oldRetainedStopped=True,
  backendAddressAliasesMacPreserved=True,existingMountsPreserved=True,javaProcessArgumentsPreserved=True,
  environmentPreservedExceptImageJavaVersion=True,flywayDisabledDeclarationsPreserved=True,migrationHistoryUnchanged=True,
  sixBusinessTablesUnchanged=True,scheduleStableFieldsUnchanged=True,schedulePollMetadataChanged=poll,
  allowedSchedulePollFields=['discovery_verified_at','lock_version'],bothSchedulesDisabledConsumedAndUnleased=True,
  historicalBeforeStopChangeCauseProven=False,wideIngestionFunctionalTested=False)
 record('complete.json',report);c.save_private(marker.parent,marker.name,(json.dumps({'containerId':live['Id'],'imageId':live['Image'],'sourceCommit':u.SOURCE,'evidenceDirectory':str(WORK),'previousContainerId':old['Id']},sort_keys=True)+'\n').encode())
def main():
 report={'schema':'ouf.ingestion-wide-resume.v1','status':'HELD','credentialValuesEmitted':False,'credentialFileContentsRead':0,'credentialFileWrites':0,
  'readOnlyDatabaseSessionsAttempted':0,'databaseWritesByScript':0,'serviceStops':0,'imageImports':0,'explicitMigrationDispatched':False,
  'applicationStartDispatched':False,'automaticRollback':False,'automaticReplay':False,'businessRequestsIssued':0,'s3RequestsByScript':0,
  'gatewayWrites':0,'permissionChanges':0,'applicationStartupMayAccessDatabaseAndExistingWork':True,'rawLogsEmitted':False}
 try:run(report)
 except FileExistsError:report['reason']='EXISTING_ATTEMPT_DO_NOT_REPLAY'
 except Exception as e:
  report['reason']=str(e) if type(e)is RuntimeError and re.fullmatch('[A-Z][A-Z0-9_]{0,100}',str(e)) else type(e).__name__
  if report.get('replacementContainerId'):
   try:
    u,p,r,mac,c,h,f=helpers();q=subprocess.run((*c.DOCKER,'logs','--tail','120',report['replacementContainerId']),capture_output=True,timeout=10)
    c.save_private(WORK,'application.stdout.private',q.stdout);c.save_private(WORK,'application.stderr.private',q.stderr);report['privateStartupLogsRetained']=True
   except Exception:report['privateStartupLogsRetained']=False
 report['observedAt']=datetime.now(timezone.utc).isoformat();print(json.dumps(report,sort_keys=True))
if __name__=='__main__':main()
