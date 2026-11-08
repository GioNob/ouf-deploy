#!/usr/bin/env python3
"""Read the stopped Ingestion's exact configuration delta and current schedule metadata.
One read-only SQL session; no service mutation, credentials, IDs or payload emission.
"""
import copy,hashlib,importlib.util,json,os,re,signal,subprocess,sys,tempfile
from pathlib import Path
from datetime import datetime,timezone
ROOT=Path('/var/lib/ouf-storage-migration/ingestion-wide-upgrade-20261108')
CID='d69c3f763d75f8c8f8db382fef0159a4dd5a3b99ee62ae8737a24421f4285c14'
IMAGE='sha256:d173aa8beeb9a1ac29c35a163e254a902e95fedad2871e328886a41831c10697'
TABLES=('ing_run','ing_partition','processing_attempt','ing_lineage','handoff_outbox','runtime_configuration_snapshot','ing_schedule')
CONFIG_FIELDS=set('Hostname Domainname User AttachStdin AttachStdout AttachStderr ExposedPorts Tty OpenStdin StdinOnce Env Cmd Healthcheck ArgsEscaped Image Volumes WorkingDir Entrypoint NetworkDisabled MacAddress OnBuild Labels StopSignal StopTimeout Shell'.split())
NETWORK_FIELDS=set('Bridge SandboxID HairpinMode LinkLocalIPv6Address LinkLocalIPv6PrefixLen Ports SandboxKey SecondaryIPAddresses SecondaryIPv6Addresses EndpointID Gateway GlobalIPv6Address GlobalIPv6PrefixLen IPAddress IPPrefixLen IPv6Gateway MacAddress Networks'.split())
ENDPOINT_FIELDS=set('IPAMConfig Links Aliases MacAddress DriverOpts GwPriority NetworkID EndpointID Gateway IPAddress IPPrefixLen IPv6Gateway GlobalIPv6Address GlobalIPv6PrefixLen DNSNames'.split())
BOOL_FIELDS=('publicationEnabled','triggerOnce','currentPublicationConsumed','publicationPresent','activationBlocked','leaseOwnerPresent','unexpiredLease')
INT_FIELDS=('ordinal','intervalSeconds','activationFailures','lockVersion')
TIME_FIELDS=('nextRunAt','lastDispatchedAt','discoveryVerifiedAt','leaseUntil')

def need(ok,code):
 if not ok:raise RuntimeError(code)
def sha(b):return hashlib.sha256(b).hexdigest()
def module(name,path,pin):
 raw=path.read_bytes();need(sha(raw)==pin,'HELPER_HASH_CHANGED');s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);exec(compile(raw,str(path),'exec'),m.__dict__);return m
def helpers():
 base=Path(__file__).parent
 c=module('contract',base/'read-discovery-contract-20261108.py','468660ed73a24c7b8a842f5b99a9c268890c99bb4206ca2e4719865326b27277')
 f=module('retained',base/'read-ingestion-wide-held-state-20261108.py','d04eb75ec6aafec7fe82c6a7bf91e88814bd47e7fee829a32eeb83e4a6e7fb8c')
 return c,c.helper(),f

def fields_delta(a,b,allowed):
 changed=[k for k in set(a)|set(b) if (k in a)!=(k in b) or a.get(k)!=b.get(k)]
 return {'changedFields':sorted(set(changed)&allowed),'otherChangedFieldCount':len(set(changed)-allowed)}
def scalar_shape(d,key):
 if key not in d:return 'ABSENT'
 v=d[key]
 if v is None:return 'NULL'
 if isinstance(v,str):return 'EMPTY_STRING' if not v else 'STRING'
 if type(v)is int:return 'ZERO_INTEGER' if v==0 else 'INTEGER'
 return 'OTHER'
def mac_shape(d):
 v=d.get('MacAddress');valid=isinstance(v,str) and re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}',v) is not None
 return {'kind':scalar_shape(d,'MacAddress'),'formatValid':valid,'unicastNonzero':bool(valid and int(v.replace(':',''),16) and not(int(v[:2],16)&1))}
def frame_report(old,stopped,current):
 need(all(d.get('Id')==CID and d.get('Image')==IMAGE for d in (old,stopped,current)),'EXACT_OLD_IDENTITY_REQUIRED')
 stages={'beforeStop':old,'recordedStopped':stopped,'current':current};original=old['NetworkSettings']['Networks']
 need(set(original)=={'ouf-backend'},'OBSERVED_BACKEND_REQUIRED')
 orig=original['ouf-backend'];ep={}
 for name,d in stages.items():
  nets=d['NetworkSettings']['Networks'];n=nets.get('ouf-backend');entry={'networkCount':len(nets),'onlyObservedBackend':set(nets)==set(original),'legacy':mac_shape(d['Config'])}
  if n is not None:
   entry.update(endpointMac=mac_shape(n),legacyMatchesOriginalEndpoint=d['Config'].get('MacAddress')==orig.get('MacAddress'),
    endpointMacMatchesOriginal=n.get('MacAddress')==orig.get('MacAddress'),ipAddressMatchesOriginal=n.get('IPAddress')==orig.get('IPAddress'),
    endpointIdPresent=bool(n.get('EndpointID')),networkIdMatchesOriginal=n.get('NetworkID')==orig.get('NetworkID'),
    ipamMatchesOriginal=n.get('IPAMConfig')==orig.get('IPAMConfig'),aliasesMatchOriginal=n.get('Aliases')==orig.get('Aliases'),
    scalarShapes={k:scalar_shape(n,k) for k in ('MacAddress','IPAddress','Gateway','EndpointID','NetworkID','GlobalIPv6Address','IPPrefixLen')})
  ep[name]=entry
 s=current['State']
 return {'scope':'OBSERVATION_ONLY_NO_MAC_NORMALIZATION_OR_LIFECYCLE_ADMISSION',
  'running':s['Running'],'pidZero':s['Pid']==0,'exitCode':s['ExitCode'],'sameGeneration':s['StartedAt']==old['State']['StartedAt'],
  'sameName':current['Name']==old['Name'],'configBeforeToCurrent':fields_delta(old['Config'],current['Config'],CONFIG_FIELDS),
  'configStoppedToCurrent':fields_delta(stopped['Config'],current['Config'],CONFIG_FIELDS),
  'environmentUnchanged':current['Config'].get('Env')==old['Config'].get('Env'),
  'hostConfigUnchanged':current['HostConfig']==old['HostConfig'],'mountsUnchanged':current['Mounts']==old['Mounts'],
  'launchUnchanged':all(current[k]==old[k] for k in ('Path','Args')),
  'networkSettingsBeforeToCurrent':fields_delta(old['NetworkSettings'],current['NetworkSettings'],NETWORK_FIELDS),
  'networkSettingsStoppedToCurrent':fields_delta(stopped['NetworkSettings'],current['NetworkSettings'],NETWORK_FIELDS),
  'endpointBeforeToCurrent':fields_delta(orig,current['NetworkSettings']['Networks'].get('ouf-backend',{}),ENDPOINT_FIELDS),
  'endpointStoppedToCurrent':fields_delta(stopped['NetworkSettings']['Networks'].get('ouf-backend',{}),current['NetworkSettings']['Networks'].get('ouf-backend',{}),ENDPOINT_FIELDS),
  'stages':ep,'configurationValuesEmitted':False}

def query():
 fingerprints=','.join("'%s',(SELECT json_build_object('rows',count(*),'fingerprint',md5(coalesce(string_agg(d,',' ORDER BY d),''))) FROM (SELECT md5(row_to_json(t)::text) d FROM ouf_ingestion.%s t) x)"%(t,t) for t in TABLES)
 return """BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout='5s'; SET LOCAL lock_timeout='1s';
SELECT json_build_object(
 'readOnly',current_setting('transaction_read_only')='on',
 'databaseOid',(SELECT oid FROM pg_database WHERE datname=current_database()),
 'applicationRoleSuperuser',(SELECT rolsuper FROM pg_roles WHERE rolname=current_user),
 'migrations',(SELECT coalesce(json_agg(json_build_object('version',version,'checksum',checksum,'success',success,'type',type,'installedRank',installed_rank,'installedOn',installed_on) ORDER BY installed_rank),'[]'::json) FROM ouf_ingestion.flyway_schema_history),
 'activity',json_build_object(
 'runStates',(SELECT coalesce(json_object_agg(s,n),'{}'::json) FROM (SELECT CASE WHEN state IN ('READY','PREFLIGHT','RUNNING','DRAINING','SUCCEEDED','FAILED','PAUSED') THEN state ELSE 'OTHER' END s,count(*) n FROM ouf_ingestion.ing_run GROUP BY 1) x),
 'handoffStates',(SELECT coalesce(json_object_agg(s,n),'{}'::json) FROM (SELECT CASE WHEN state IN ('READY','DELIVERING','ACKED','FAILED_RETRYABLE','FAILED_TERMINAL') THEN state ELSE 'OTHER' END s,count(*) n FROM ouf_ingestion.handoff_outbox GROUP BY 1) x),
 'unexpiredPartitionLeases',(SELECT count(*) FROM ouf_ingestion.ing_partition WHERE lease_until>transaction_timestamp())),
 'retainedRows',json_build_object("""+fingerprints+"""),
 'scheduleStableFingerprint',(SELECT md5(coalesce(string_agg(d,',' ORDER BY d),'')) FROM (SELECT md5((to_jsonb(t)-'discovery_verified_at'-'lock_version')::text) d FROM ouf_ingestion.ing_schedule t) x),
 'scheduleMetadata',(SELECT coalesce(json_agg(x ORDER BY ordinal),'[]'::json) FROM (
 SELECT row_number() over(order by schedule_id) AS ordinal,state,
 interval_seconds AS "intervalSeconds",publication_enabled AS "publicationEnabled",trigger_once AS "triggerOnce",
 publication_id IS NOT NULL AS "publicationPresent",(publication_id IS NOT NULL AND consumed_publication_id IS NOT DISTINCT FROM publication_id) AS "currentPublicationConsumed",
 activation_blocked AS "activationBlocked",activation_failures AS "activationFailures",lock_version AS "lockVersion",
 lease_owner IS NOT NULL AS "leaseOwnerPresent",coalesce(lease_until>transaction_timestamp(),false) AS "unexpiredLease",
 to_char(next_run_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "nextRunAt",
 to_char(last_dispatched_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "lastDispatchedAt",
 to_char(discovery_verified_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "discoveryVerifiedAt",
 to_char(lease_until AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "leaseUntil"
 FROM ouf_ingestion.ing_schedule ORDER BY schedule_id LIMIT 33) x));
ROLLBACK;
"""
def database_summary(value,stopped,f):
 f.validate(value);need(re.fullmatch('[a-f0-9]{32}',value.get('scheduleStableFingerprint','')),'STABLE_FINGERPRINT_SHAPE')
 rows=value.get('scheduleMetadata');need(isinstance(rows,list) and len(rows)<=32 and len(rows)==value['retainedRows']['ing_schedule']['rows'],'BOUNDED_SCHEDULE_METADATA_REQUIRED')
 keys=set(BOOL_FIELDS+INT_FIELDS+TIME_FIELDS+('state',))
 for i,row in enumerate(rows,1):
  need(set(row)==keys and row['ordinal']==i and row['state'] in ('ACTIVE','PAUSED','DISABLED'),'SCHEDULE_METADATA_SHAPE')
  need(all(type(row[k])is bool for k in BOOL_FIELDS) and all(type(row[k])is int and row[k]>=0 for k in INT_FIELDS),'SCHEDULE_METADATA_SHAPE')
  need(all(row[k] is None or re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z',row[k]) for k in TIME_FIELDS),'SCHEDULE_METADATA_SHAPE')
 delta=f.compare(stopped,value);delta.pop('rowIdentifiersPayloadsAndCheckpointsRead',None)
 delta['scope']='RETAINED_STOPPED_SUMMARY_VS_CURRENT_READ_ONLY_DATABASE_SUMMARY'
 delta['rowValuesTransferred']=False;delta['databaseRowsHashedServerSide']=True
 return {'comparisonWithStoppedRead':delta,'scheduleMetadata':rows,
  'allSchedulesDisabled':all(x['state']=='DISABLED' for x in rows),'noUnexpiredScheduleLeases':all(not x['unexpiredLease'] for x in rows),
  'stableScheduleFingerprintRetainedPrivately':True,'stableFingerprintExcludes':['discovery_verified_at','lock_version'],
  'historicalChangedColumnsRecoverable':False,'reason':'EARLIER_EVIDENCE_HAS_ONLY_WHOLE_TABLE_FINGERPRINTS',
  'queryScope':'DECLARED_APPLICATION_DATABASE_ON_RETAINED_POSTGRES','credentialValuesEmitted':False}
def db_binding(doc,pg,c,h):
 env=h.environment(doc);translated=copy.deepcopy(doc)
 translated['Config']['Env']=[x for x in doc['Config']['Env'] if not x.startswith(('OUF_SEM_DB_URL=','OUF_SEM_DB_USER='))]
 translated['Config']['Env']+=['OUF_SEM_DB_URL='+env.get('OUF_ING_DB_URL',''),'OUF_SEM_DB_USER='+env.get('OUF_ING_DB_USER','')]
 return c.db_binding(translated,pg,'semantic',h)
def run(report):
 c,h,f=helpers();rawplan=h.read(h.PLAN,1048576);need(sha(rawplan)==h.PLAN_SHA,'RETAINED_PLAN_CHANGED');roles=h.parse(rawplan)['roles']
 original={n:h.read(ROOT/n,2097152) for n in ('old.private.json','stopped.private.json','stopped-database.private.json')}
 old=h.parse(original['old.private.json']);stopped=h.parse(original['stopped.private.json']);database=h.parse(original['stopped-database.private.json'])
 current=h.inspect(CID);report['dockerInspectAttempts']+=1;report['container']=frame_report(old,stopped,current)
 need(not current['State']['Running'] and current['State']['Pid']==0 and report['container']['sameGeneration'],'OLD_STOPPED_GENERATION_REQUIRED')
 # Report any exact delta; do not silently permit it for a future lifecycle step.
 work=Path(tempfile.mkdtemp(prefix='ingestion-resume-read-',dir=ROOT.parent));os.chmod(work,0o700);report['privateEvidenceDirectory']=str(work)
 c.save_private(work,'current-ingestion.private.json',(json.dumps(current,sort_keys=True)+'\n').encode())
 report['currentFrameSha256']=h.digest(h.frame(current))
 report['journalFilesPresent']={n:(ROOT/n).exists() for n in f.JOURNAL};report['currentReplacementMarkerPresent']=(ROOT.parent/'ingestion-wide-current.json').exists()
 pg=h.inspect(roles['postgres']['containerId']);report['dockerInspectAttempts']+=1
 need(pg['Image']==roles['postgres']['nativeImage'] and pg['State']['Running'],'POSTGRES_BINDING_CHANGED')
 user,name=db_binding(old,pg,c,h);report['readOnlyDatabaseSessionsAttempted']+=1
 q=subprocess.run((*c.DOCKER,'exec','-i','-e','PGOPTIONS=-c default_transaction_read_only=on',pg['Id'],'psql','-X','-w','-q','-A','-t','-v','ON_ERROR_STOP=1','-h','/var/run/postgresql','-U',user,'-d',name),input=query().encode(),capture_output=True,timeout=12)
 c.save_private(work,'database.stderr.private',q.stderr[:65536]);need(q.returncode==0 and len(q.stdout)<=131072,'SCHEDULE_METADATA_READ_FAILED')
 c.save_private(work,'database.private.json',q.stdout);value=h.parse(q.stdout);report['database']=database_summary(value,database,f)
 report['databaseEvidenceSha256']=sha(q.stdout)
 latest=h.inspect(CID);report['dockerInspectAttempts']+=1;report['runtimeUnchangedDuringRead']=h.frame(current)==h.frame(latest)
 report['retainedEvidenceUnchangedDuringRead']=all(h.read(ROOT/n,2097152)==b for n,b in original.items())
 need(report['runtimeUnchangedDuringRead'] and report['retainedEvidenceUnchangedDuringRead'],'INPUT_CHANGED_DURING_READ')
 report['status']='INGESTION_RESUME_PREREQUISITES_READ';c.save_private(work,'report.json',(json.dumps(report,sort_keys=True)+'\n').encode())
def main():
 report={'schema':'ouf.ingestion-resume-prerequisites-read.v1','status':'READ_INCOMPLETE','dockerInspectAttempts':0,'readOnlyDatabaseSessionsAttempted':0,
  'credentialFilesRead':0,'credentialValuesEmitted':False,'databaseWrites':0,'serviceStartDispatched':False,'serviceStops':0,
  'serviceConfigurationChanged':False,'imageImports':0,'businessRequestsIssued':0,'s3Requests':0,'rawLogsEmitted':False}
 try:
  need(os.geteuid()==0 and sys.flags.isolated,'ISOLATED_ROOT_REQUIRED')
  signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(RuntimeError('READ_DEADLINE')));signal.alarm(55);run(report)
 except Exception as e:report['reason']=str(e) if type(e)is RuntimeError and re.fullmatch('[A-Z][A-Z0-9_]{0,100}',str(e)) else type(e).__name__
 finally:signal.alarm(0)
 report['observedAt']=datetime.now(timezone.utc).isoformat();print(json.dumps(report,sort_keys=True))
if __name__=='__main__':main()
