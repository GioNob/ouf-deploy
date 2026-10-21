#!/usr/bin/env python3
"""Installation-specific retained-host acquisition metadata diagnosis; no token or property reads."""
import hashlib,http.client,json,os,re,selectors,signal,socket,stat,subprocess,sys,tempfile,time
from pathlib import Path
from urllib.parse import quote
BOOT=Path('/etc/ouf/deploy-snapshots/semantic-mcp-update-executor-code-yrvtskkt/execute.py')
BOOT_HASH='b02d9737af6d143903910654d34e91a1a82a52b6082d2429d5dbfd070d160af2'
CONTEXT=Path('/etc/ouf/deploy-snapshots/onboarding-audit-execution-ybmis4le')
REVIEW=None
POLICY_CONTEXT=Path('/etc/ouf/deploy-snapshots/ingestion-readiness-execution-d0bmyv9g')
POLICY_REVIEW='c42181ac012cd41417e2e9ec3c0f37908d3a5c0c379cc3805c918505f4bed5cd'
SOURCE='teatri-csv-6609b245'
VERSION='9860853e-e8f3-4b93-b9d2-03521a039962'
CHALLENGE='ecf36c5c-10b2-4393-bf81-0ff7d28b8d5b'
CONFIG_HASH='sha256:ae7f46b4214d09c55a9885530920026258f0dcd588462c353b06d82185e12c9b'
def require(ok,code):
 if not ok:raise ValueError(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(v):return hashlib.sha256(encoded(v)).hexdigest()
def emit(check,**values):
 print(json.dumps(dict(schema='ouf.teatri-active-acquisition-read.v1',check=check,readOnly=True,
  automaticRetry=False,budgetReset=False,installationSpecific=True,credentialFilesRead=0,credentialValuesPrinted=False,
  databaseMutations=0,grantRequests=0,readinessCalls=0,serviceMutations=0,
  completedTechnicalPhases=8,functionalMilestonesProven=2,**values),sort_keys=True),flush=True)

def runtime_pin(actual):
    return {'containerId':actual['Id'],'imageId':actual['Image'],
        'pid':actual['State']['Pid'],'startedAt':actual['State']['StartedAt'],
        **{name+'Hash':digest(actual[key])for name,key in
           (('config','Config'),('hostConfig','HostConfig'),('mounts','Mounts'),('networkSettings','NetworkSettings'))}}

def bounded(argv, seconds=15, maximum=2097152, discard=False):
    """Drain both pipes concurrently; cap bytes/time and kill the CLI on exit."""
    proc=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    output=bytearray(); errors=bytearray(); count=0; end=time.monotonic()+seconds
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout,selectors.EVENT_READ,'out')
            selector.register(proc.stderr,selectors.EVENT_READ,'err')
            while selector.get_map():
                require(time.monotonic()<end,'DIAGNOSTIC_HOST_TIME_BOUND_EXHAUSTED')
                for key,_ in selector.select(min(0.2,max(0,end-time.monotonic()))):
                    raw=os.read(key.fd,65536)
                    if not raw:selector.unregister(key.fileobj);continue
                    if key.data=='out':
                        count+=len(raw);require(count<=maximum,'DIAGNOSTIC_OUTPUT_BOUND_EXHAUSTED')
                        if not discard:output.extend(raw)
                    else:
                        require(len(errors)+len(raw)<=maximum,'DIAGNOSTIC_STDERR_BOUND_EXHAUSTED')
                        errors.extend(raw)
            code=proc.wait(timeout=max(0.01,end-time.monotonic()))
        return code,bytes(output),bytes(errors),count
    finally:
        if proc.poll() is None:proc.kill()
        proc.wait(timeout=5);proc.stdout.close();proc.stderr.close()

def executable(binding):
    path=Path(binding['path']);info=path.stat()
    require(path.is_absolute() and stat.S_ISREG(info.st_mode) and info.st_uid==0 and
        not info.st_mode&0o022 and hashlib.sha256(path.read_bytes()).hexdigest()==binding['sha256'],
        'NATIVE_EXECUTABLE_BINDING_DRIFT')
    return str(path)

def literal(value):
    require(type(value)is str and re.fullmatch('[A-Za-z0-9_:.-]{1,128}',value),'CLOSED_SQL_BINDING_REQUIRED')
    return "'"+value+"'"

def acquisition_query(module,tenant):
 t=literal(tenant);s=literal(SOURCE)
 header="BEGIN READ ONLY; SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='3s'; "
 if module=='ingestion':
  return header+"""
 WITH runs AS (SELECT * FROM ouf_ingestion.ing_run WHERE source_id="""+s+""" AND tenant_id="""+t+""" ORDER BY created_at DESC,run_id LIMIT 3)
 SELECT jsonb_build_object('database',current_database(),'databaseOid',(SELECT oid::bigint FROM pg_database WHERE datname=current_database()),'role',current_user,'transactionReadOnly',current_setting('transaction_read_only')='on',
 'schedules',coalesce((SELECT jsonb_agg(jsonb_build_object('state',state,'publicationId',publication_id,'publicationSequence',publication_sequence,'triggerOnce',trigger_once,'publicationEnabled',publication_enabled,'consumedPublicationId',consumed_publication_id,'activationFailures',activation_failures,'activationBlocked',activation_blocked,'discoveredAt',discovery_verified_at,'nextRunAt',next_run_at)) FROM ouf_ingestion.ing_schedule WHERE source_id="""+s+""" AND tenant_id="""+t+"""),'[]'::jsonb),
 'runs',coalesce((SELECT jsonb_agg(jsonb_build_object('runId',r.run_id,'state',r.state,'phase',r.phase,'failureCode',r.failure_code,'createdAt',r.created_at,'updatedAt',r.updated_at,
 'partitions',(SELECT count(*) FROM ouf_ingestion.ing_partition p WHERE p.run_id=r.run_id),
 'attempts',(SELECT count(*) FROM ouf_ingestion.processing_attempt a WHERE a.run_id=r.run_id),
 'failedAttempts',(SELECT count(*) FROM ouf_ingestion.processing_attempt a WHERE a.run_id=r.run_id AND a.state='FAILED'),
 'lineageCount',(SELECT count(*) FROM ouf_ingestion.ing_lineage l WHERE l.run_id=r.run_id),
 'handoffs',coalesce((SELECT jsonb_agg(x) FROM (SELECT state,count(*) count FROM ouf_ingestion.handoff_outbox h WHERE h.run_id=r.run_id GROUP BY state ORDER BY state)x),'[]'::jsonb),
 'ackedReceipts',(SELECT count(*) FROM ouf_ingestion.handoff_outbox h WHERE h.run_id=r.run_id AND h.state='ACKED' AND h.downstream_receipt_ref IS NOT NULL),
 'quarantine',coalesce((SELECT jsonb_agg(x) FROM (SELECT state,reason_code,count(*) count FROM ouf_ingestion.ing_quarantine q WHERE q.run_id=r.run_id GROUP BY state,reason_code ORDER BY state,reason_code LIMIT 8)x),'[]'::jsonb))) FROM runs r),'[]'::jsonb),
 'health',coalesce((SELECT jsonb_agg(jsonb_build_object('status',status,'consecutiveFailures',consecutive_failures,'lastCode',last_error_code,'updatedAt',updated_at)) FROM ouf_ingestion.source_health WHERE source_id="""+s+"""),'[]'::jsonb)); ROLLBACK;"""
 require(module=='udp','EXACT_ACQUISITION_DATABASE_MODULE_REQUIRED')
 return header+"""
 WITH intake AS (SELECT * FROM ouf_udp.handoff_intake WHERE source_id="""+s+"""), bound AS (SELECT b.* FROM ouf_udp.source_binding b JOIN ouf_udp.urban_object u USING(urban_object_id) WHERE b.source_id="""+s+""" AND u.tenant_id="""+t+"""), cinema AS (SELECT u.urban_object_id,u.revision,u.current_revision_id,r.canonical_hash,r.authority_hash FROM ouf_udp.urban_object u LEFT JOIN ouf_udp.object_revision r ON r.revision_id=u.current_revision_id WHERE u.tenant_id="""+t+""" AND u.canonical_type='https://schema.org/MovieTheater' AND u.status='ACTIVE')
 SELECT jsonb_build_object('database',current_database(),'databaseOid',(SELECT oid::bigint FROM pg_database WHERE datname=current_database()),'role',current_user,'transactionReadOnly',current_setting('transaction_read_only')='on',
 'handoffs',coalesce((SELECT jsonb_agg(x) FROM (SELECT state,failure_code,count(*) count FROM intake GROUP BY state,failure_code ORDER BY state,failure_code LIMIT 8)x),'[]'::jsonb),
 'materializationJobs',coalesce((SELECT jsonb_agg(x) FROM (SELECT j.state,count(*) count FROM ouf_udp.materialization_job j JOIN intake i USING(handoff_id) GROUP BY j.state ORDER BY j.state)x),'[]'::jsonb),
 'sourceBindings',(SELECT count(*) FROM bound),'distinctBoundObjects',(SELECT count(DISTINCT urban_object_id) FROM bound),
 'materializationObservations',(SELECT count(*) FROM ouf_udp.materialization_observation o JOIN intake i USING(handoff_id)),
 'boundObjectsWithRevision',(SELECT count(*) FROM ouf_udp.urban_object u WHERE u.current_revision_id IS NOT NULL AND u.urban_object_id IN(SELECT urban_object_id FROM bound)),
 'propertyContributions',(SELECT count(*) FROM ouf_udp.property_contribution p WHERE p.source_id="""+s+""" AND p.urban_object_id IN(SELECT urban_object_id FROM bound)),
 'resolutionIssues',coalesce((SELECT jsonb_agg(x) FROM (SELECT q.state,q.reason_code,count(*) count FROM ouf_udp.resolution_issue q JOIN intake i USING(handoff_id) GROUP BY q.state,q.reason_code ORDER BY q.state,q.reason_code LIMIT 8)x),'[]'::jsonb),
 'cinemaActiveCount',(SELECT count(*) FROM cinema),
 'cinemaSnapshotSha256',(SELECT encode(sha256(convert_to(coalesce(string_agg(urban_object_id::text||':'||revision::text||':'||coalesce(current_revision_id::text,'')||':'||coalesce(canonical_hash,'')||':'||coalesce(authority_hash,''),'|' ORDER BY urban_object_id),''),'UTF8')),'hex') FROM cinema)); ROLLBACK;"""


def main():
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_READ_REQUIRED')
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('READ_DEADLINE')));signal.alarm(65)
 for p in(BOOT.parent,*BOOT.parent.parents):
  a=p.lstat();require(stat.S_ISDIR(a.st_mode)and a.st_uid==0 and not a.st_mode&0o022,'RETAINED_HELPER_ANCESTRY_REQUIRED')
 fd=os.open(BOOT,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  a=os.fstat(fd);require(stat.S_ISREG(a.st_mode)and a.st_uid==a.st_gid==0 and a.st_nlink==1 and stat.S_IMODE(a.st_mode)==0o600 and 0<a.st_size<=131072,'RETAINED_HELPER_CUSTODY_REQUIRED')
  raw=os.read(fd,131073);require(len(raw)==a.st_size and hashlib.sha256(raw).hexdigest()==BOOT_HASH,'RETAINED_HELPER_HASH_CHANGED')
 finally:os.close(fd)
 ns={'__name__':'active_acquisition_read_helpers'};exec(compile(raw,'<verified-retained-read-helpers>','exec'),ns)
 old=ns['read'](ns['CONTEXT']/'review.json',8388608,ns['REVIEW']);link=old['scopes']['finiteActionProcess']['bundle']
 prepared=ns['read'](link['path'],8388608,link['sha256'])['prepared']
 require(digest(prepared)==old['privateInputHashes']['preparedInputs'],'PREPARED_INPUT_BINDING_CHANGED')
 review=ns['read'](CONTEXT/'review.json',8388608);plan=ns['read'](CONTEXT/'execution-plan.json',8388608);record=ns['read'](CONTEXT/'recovery.json',65536)
 scope=review['scopes']['onboardingAuditUpdate']
 require(review['kind']=='ONBOARDING_AUDIT_FIX'and digest(plan)==scope['planHash']and record['scopeHash']==digest(scope)and record['version']==29 and record['incidentState']=='RECOVERED'and record['nextStage']==len(record['effects'])==len(scope['stages'])==11 and all(e['state']=='APPLIED'for e in record['effects']),'COMPLETE_CURRENT_ONBOARDING_FIX_REQUIRED')
 expected=record['effects'][-1]['evidence']['applications']['onboarding']['runtimeBinding']
 app=ns['engine_get'](prepared['engine'],'containers',expected['containerId']);require(ns['runtime_pin'](app)==expected,'CURRENT_ONBOARDING_GENERATION_CHANGED')
 ing=ns['engine_get'](prepared['engine'],'containers',plan['unchangedIngestionRuntimeBinding']['containerId']);require(ns['runtime_pin'](ing)==plan['unchangedIngestionRuntimeBinding'],'CURRENT_INGESTION_GENERATION_CHANGED')
 db=prepared['databasePlan'];admin=db['mcpAuditRoleAdministration']['admin'];pg=ns['engine_get'](prepared['engine'],'containers',db['postgresRuntimeBinding']['containerId'])
 require(pg is not None and pg['State']['Running']is True and pg['State']['Paused']is False and runtime_pin(pg)==db['postgresRuntimeBinding'],'EXACT_POSTGRES_GENERATION_REQUIRED')
 require([v.split('=',1)[1]for v in pg['Config'].get('Env',[])if v.startswith('POSTGRES_USER=')]==[admin],'EXISTING_ADMINISTRATOR_BINDING_REQUIRED')
 selection=prepared['authorization']['plan']['selection'];tenant=selection['tenant'];require(tenant=='ouf-lab','EXACT_REVIEWED_TENANT_REQUIRED')
 emit('ROLLOUT_BINDING',contextPath=str(CONTEXT),reviewSha256=digest(review),journalVersion=29,reviewSignaturesVerifiedLocally=False)
 for module in('ingestion','udp'):
  binding=next(r for r in db['modules']if r['module']==module)
  for value in(admin,binding['database']):require(type(value)is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,62}',value),'EXACT_DATABASE_ROLE_REQUIRED')
  with tempfile.TemporaryDirectory(prefix='ouf-acquisition-db-read-')as config:
   argv=[executable(old['sourceClosure']['executables']['docker']),'--host','unix://'+prepared['engine']['socketPath'],'--config',config,'exec',pg['Id'],'env','LC_ALL=C',
    'PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=10000 -c lock_timeout=3000','timeout','-s','KILL','15','psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-U',admin,'-d',binding['database'],'-c',acquisition_query(module,tenant)]
   code,raw,err,_=bounded(argv,seconds=20,maximum=65536);require(code==0,'READ_ONLY_ACQUISITION_SQL_FAILED');facts=json.loads(raw)
  require(facts['database']==binding['database']and facts['databaseOid']==binding['databaseOid']and facts['role']==admin and facts['transactionReadOnly']is True,'EXACT_ACQUISITION_DATABASE_REQUIRED')
  if module=='ingestion':require(len(facts['schedules'])<=1 and len(facts['runs'])<=3 and len(facts['health'])<=1,'BOUNDED_INGESTION_FACTS_REQUIRED')
  emit('ACQUISITION_DATABASE',module=module,facts=facts,rawSqlOutputPrinted=False,propertyValuesPrinted=False)
 require(runtime_pin(ns['engine_get'](prepared['engine'],'containers',pg['Id']))==db['postgresRuntimeBinding'],'POSTGRES_GENERATION_CHANGED_DURING_READ')
 require(ns['runtime_pin'](ns['engine_get'](prepared['engine'],'containers',app['Id']))==expected and ns['read'](CONTEXT/'recovery.json',65536)==record,'ONBOARDING_CHANGED_DURING_READ')
 require(ns['runtime_pin'](ns['engine_get'](prepared['engine'],'containers',ing['Id']))==plan['unchangedIngestionRuntimeBinding'],'INGESTION_CHANGED_DURING_READ')
 emit('END',complete=True,reconciliationPerformed=False,runtimeAuthorityIssued=False,sourceActivationProvenByPriorOwnerRead=True,commitOfAll13RowsProven=False,cinemaHistoricalEqualityProven=False)
if __name__=='__main__':
 emit('BEGIN',maximumSeconds=65,maximumEngineReads=6,maximumSqlSessions=2)
 try:main()
 except Exception as error:
  reason=str(error)if type(error)is ValueError and re.fullmatch('[A-Z_]+',str(error))else type(error).__name__
  emit('STOP',reason=reason,exceptionMessagePrinted=False)
