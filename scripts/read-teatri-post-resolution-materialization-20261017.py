#!/usr/bin/env python3
"""Installation-specific retained-host acquisition metadata diagnosis; no token or property reads."""
import hashlib,http.client,json,os,re,selectors,signal,socket,stat,subprocess,sys,tempfile,time
from pathlib import Path
from urllib.parse import quote
BOOT=Path('/etc/ouf/deploy-snapshots/semantic-mcp-update-executor-code-yrvtskkt/execute.py')
BOOT_HASH='b02d9737af6d143903910654d34e91a1a82a52b6082d2429d5dbfd070d160af2'
CONTEXT=Path('/etc/ouf/deploy-snapshots/resolution-comparison-execution-di_tb213')
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
 print(json.dumps(dict(schema='ouf.teatri-post-resolution-materialization-read.v1',check=check,readOnly=True,
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
 require(module=='udp','ONLY_UDP_READ_REQUIRED')
 t=literal(tenant);s=literal(SOURCE)
 return "BEGIN READ ONLY; SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='3s'; "+"""
 WITH receipt AS (
  SELECT * FROM ouf_udp.resolution_review_package_confirmation
  WHERE package_id='a5183503-04ff-4e10-850f-e22bf874365e' AND tenant_id="""+t+"""
   AND actor_subject='b93d8cf6-cd14-4ee6-91d7-84cd76c4f500'
 ), intake AS (
  SELECT h.* FROM ouf_udp.handoff_intake h JOIN ouf_udp.lake_object l ON l.lake_object_id=h.raw_lake_object_id
  WHERE h.source_id="""+s+""" AND h.ingestion_run_id='a3208f2f-ebfd-415d-bddc-79ab05dea78f'
   AND h.type_code='https://schema.org/PerformingArtsTheater' AND l.tenant_id="""+t+"""
 ), decisions AS (
  SELECT d.*,q.handoff_id,q.state issue_state FROM ouf_udp.human_resolution_decision d
  JOIN ouf_udp.resolution_issue q ON q.issue_id=d.issue_id JOIN intake h USING(handoff_id)
  JOIN receipt r ON r.actor_subject=d.actor_subject AND r.confirmed_at=d.decided_at
    AND r.authorization_decision_ref=d.authorization_decision_ref
  WHERE q.tenant_id="""+t+"""
 ), details AS (
  SELECT d.issue_id,d.action,d.issue_state,h.state intake_state,j.state job_state,j.safe_failure_code,
   b.urban_object_id,b.state binding_state,o.status object_state,o.current_revision_id,
   obs.revision_id observation_revision,rv.revision_id verified_revision,
   (SELECT count(*) FROM ouf_udp.property_contribution c WHERE c.handoff_id=h.handoff_id AND c.urban_object_id=b.urban_object_id) contribution_count
  FROM decisions d JOIN intake h USING(handoff_id)
  LEFT JOIN ouf_udp.materialization_job j USING(handoff_id)
  LEFT JOIN ouf_udp.source_binding b ON b.source_id=h.source_id AND b.type_code=h.type_code AND b.source_object_id=h.source_object_id
  LEFT JOIN ouf_udp.urban_object o ON o.urban_object_id=b.urban_object_id AND o.tenant_id="""+t+"""
  LEFT JOIN ouf_udp.materialization_observation obs ON obs.handoff_id=h.handoff_id AND obs.urban_object_id=b.urban_object_id
  LEFT JOIN ouf_udp.object_revision rv ON rv.revision_id=obs.revision_id AND rv.urban_object_id=b.urban_object_id
 )
 SELECT jsonb_build_object('database',current_database(),'databaseOid',(SELECT oid::bigint FROM pg_database WHERE datname=current_database()),'role',current_user,'transactionReadOnly',current_setting('transaction_read_only')='on',
 'receiptCount',(SELECT count(*) FROM receipt),'receiptIssueCount',(SELECT issue_count FROM receipt),
 'matchedDecisionCount',(SELECT count(*) FROM decisions),'matchedDistinctIssues',(SELECT count(DISTINCT issue_id) FROM decisions),
 'decisionActions',coalesce((SELECT jsonb_agg(x) FROM (SELECT action,count(*) count FROM decisions GROUP BY action ORDER BY action)x),'[]'::jsonb),
 'sourceRowCount',(SELECT count(*) FROM intake),
 'sourceJobs',coalesce((SELECT jsonb_agg(x) FROM (SELECT j.state,j.safe_failure_code,count(*) count FROM ouf_udp.materialization_job j JOIN intake h USING(handoff_id) GROUP BY j.state,j.safe_failure_code ORDER BY j.state,j.safe_failure_code)x),'[]'::jsonb),
 'sourceIssues',coalesce((SELECT jsonb_agg(x) FROM (SELECT q.state,q.reason_code,count(*) count FROM ouf_udp.resolution_issue q JOIN intake h USING(handoff_id) WHERE q.tenant_id="""+t+""" GROUP BY q.state,q.reason_code ORDER BY q.state,q.reason_code)x),'[]'::jsonb),
 'confirmedDistinctObjects',(SELECT count(DISTINCT urban_object_id) FROM details),
 'confirmedObjectsWithCurrentRevision',(SELECT count(DISTINCT urban_object_id) FROM details WHERE current_revision_id IS NOT NULL),
 'confirmedMaterializedRows',(SELECT count(*) FROM details WHERE issue_state='RESOLVED' AND action='CREATE_NEW' AND job_state='SUCCEEDED' AND intake_state='PROCESSED' AND binding_state='ACTIVE' AND object_state='ACTIVE' AND current_revision_id IS NOT NULL AND observation_revision IS NOT NULL AND verified_revision=observation_revision AND contribution_count>0),
 'details',coalesce((SELECT jsonb_agg(x) FROM (SELECT issue_id,action,issue_state,intake_state,job_state,safe_failure_code,urban_object_id,binding_state,object_state,(current_revision_id IS NOT NULL) current_revision_present,(verified_revision IS NOT NULL) observation_revision_verified,contribution_count FROM details ORDER BY issue_id LIMIT 13)x),'[]'::jsonb)); ROLLBACK;"""

def materialization_proven(facts):
 return (facts.get('receiptCount')==1 and facts.get('receiptIssueCount')==11
  and facts.get('matchedDecisionCount')==facts.get('matchedDistinctIssues')==11
  and facts.get('confirmedDistinctObjects')==facts.get('confirmedObjectsWithCurrentRevision')==11
  and facts.get('confirmedMaterializedRows')==11)


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
 issued=ns['read'](CONTEXT/'authority.json',131072)
 scope=review['scopes']['resolutionComparisonUpdate']
 require(review['kind']=='RESOLUTION_COMPARISON_UPDATE'and digest(plan)==scope['planHash']
  and record['scopeHash']==digest(scope)and record['authorityHash']==digest(issued)
  and issued['resolutionComparisonUpdate']==scope and record['version']==57
  and issued['scopedExecution']['reviewHash']==digest(review)
  and review['sourceClosure']['declaration']['sourceCommit']=='d6da86415abe673d9ac1a692118bd2d0a218b644'
  and digest(review['sourceClosure'])==review['sourceClosureHash']==issued['sourceClosureHash']
  and record['incidentState']=='RECOVERED'and record['nextStage']==len(record['effects'])==len(scope['stages'])==21
  and [e['stage']for e in record['effects']]==scope['stages']
  and all(e['state']=='APPLIED'and e['intentHash']==digest({'planHash':scope['planHash'],'stage':e['stage']})for e in record['effects']),
  'COMPLETE_CURRENT_RESOLUTION_UPDATE_REQUIRED')
 def current_pin(actual):
  pin=ns['runtime_pin'](actual);pin['mountsHash']=digest(sorted(actual['Mounts'],key=lambda m:m['Destination']));return pin
 pins={**{name:record['effects'][-1]['evidence']['applications'][name]['runtimeBinding']for name in('udp','onboarding')},**plan['unchangedApplications']}
 for name,pin in pins.items():
  actual=ns['engine_get'](prepared['engine'],'containers',pin['containerId'])
  require(actual is not None and actual['State']['Running']is True and current_pin(actual)==pin,'CURRENT_APPLICATION_GENERATION_CHANGED')
 db=prepared['databasePlan'];admin=db['mcpAuditRoleAdministration']['admin'];pg=ns['engine_get'](prepared['engine'],'containers',db['postgresRuntimeBinding']['containerId'])
 require(pg is not None and pg['State']['Running']is True and pg['State']['Paused']is False and runtime_pin(pg)==db['postgresRuntimeBinding'],'EXACT_POSTGRES_GENERATION_REQUIRED')
 require([v.split('=',1)[1]for v in pg['Config'].get('Env',[])if v.startswith('POSTGRES_USER=')]==[admin],'EXISTING_ADMINISTRATOR_BINDING_REQUIRED')
 selection=prepared['authorization']['plan']['selection'];tenant=selection['tenant'];require(tenant=='ouf-lab','EXACT_REVIEWED_TENANT_REQUIRED')
 emit('ROLLOUT_BINDING',contextPath=str(CONTEXT),reviewSha256=digest(review),journalVersion=57,reviewSignaturesVerifiedLocally=False)
 for module in('udp',):
  binding=next(r for r in db['modules']if r['module']==module)
  for value in(admin,binding['database']):require(type(value)is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,62}',value),'EXACT_DATABASE_ROLE_REQUIRED')
  with tempfile.TemporaryDirectory(prefix='ouf-acquisition-db-read-')as config:
   argv=[executable(old['sourceClosure']['executables']['docker']),'--host','unix://'+prepared['engine']['socketPath'],'--config',config,'exec',pg['Id'],'env','LC_ALL=C',
    'PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=10000 -c lock_timeout=3000','timeout','-s','KILL','15','psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-U',admin,'-d',binding['database'],'-c',acquisition_query(module,tenant)]
   code,raw,err,_=bounded(argv,seconds=20,maximum=65536);require(code==0,'READ_ONLY_ACQUISITION_SQL_FAILED');facts=json.loads(raw)
  require(facts['database']==binding['database']and facts['databaseOid']==binding['databaseOid']and facts['role']==admin and facts['transactionReadOnly']is True,'EXACT_ACQUISITION_DATABASE_REQUIRED')
  require(facts['sourceRowCount']<=13 and len(facts['details'])<=13,'BOUNDED_SOURCE_FACTS_REQUIRED')
  emit('ACQUISITION_DATABASE',module=module,facts=facts,rawSqlOutputPrinted=False,propertyValuesPrinted=False)
 require(runtime_pin(ns['engine_get'](prepared['engine'],'containers',pg['Id']))==db['postgresRuntimeBinding'],'POSTGRES_GENERATION_CHANGED_DURING_READ')
 for name,pin in pins.items():
  require(current_pin(ns['engine_get'](prepared['engine'],'containers',pin['containerId']))==pin,'APPLICATION_CHANGED_DURING_READ')
 require(ns['read'](CONTEXT/'recovery.json',65536)==record,'ROLLOUT_RECORD_CHANGED_DURING_READ')
 emit('END',complete=True,confirmedElevenMaterialized=materialization_proven(facts),reconciliationPerformed=False,
  runtimeAuthorityIssued=False,confirmationReceipt='a5183503-04ff-4e10-850f-e22bf874365e',
  allThirteenMaterializedProven=False,cinemaHistoricalEqualityProven=False)
if __name__=='__main__':
 emit('BEGIN',maximumSeconds=65,maximumEngineReads=8,maximumSqlSessions=1)
 try:main()
 except Exception as error:
  reason=str(error)if type(error)is ValueError and re.fullmatch('[A-Z_]+',str(error))else type(error).__name__
  emit('STOP',reason=reason,exceptionMessagePrinted=False)
