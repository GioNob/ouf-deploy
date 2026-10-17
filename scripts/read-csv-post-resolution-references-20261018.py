#!/usr/bin/env python3
"""Installation-specific stage-3 row ledger on the retained, verified rollout.

Reuses the existing post-rollout transport and post-resolution receipt proof.
No source values, tokens, retries, profile publication or database writes.
"""
import fcntl,base64,hashlib,http.client,json,os,re,selectors,shlex,signal,socket,ssl,stat,subprocess,sys,tempfile,time
from urllib.parse import urlsplit,urlencode
from pathlib import Path
BOOT=Path('/etc/ouf/deploy-snapshots/semantic-mcp-update-executor-code-yrvtskkt/execute.py')
BOOT_HASH='b02d9737af6d143903910654d34e91a1a82a52b6082d2429d5dbfd070d160af2'
CONTEXT=Path('/etc/ouf/deploy-snapshots/linked-property-execution-cjecd1en')
POLICY_CONTEXT=Path('/etc/ouf/deploy-snapshots/ingestion-readiness-execution-d0bmyv9g')
POLICY_REVIEW='c42181ac012cd41417e2e9ec3c0f37908d3a5c0c379cc3805c918505f4bed5cd'
SOURCE='teatri-csv-6609b245'
VERSION='9860853e-e8f3-4b93-b9d2-03521a039962'
def require(ok,code):
 if not ok:raise ValueError(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(v):return hashlib.sha256(encoded(v)).hexdigest()
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


CREDENTIAL_FILES_READ=0
def emit(check,**values):
 fields=dict(schema='ouf.csv-post-resolution-reference-read.v2',check=check,readOnly=True,
  automaticRetry=False,budgetReset=False,credentialFilesRead=CREDENTIAL_FILES_READ,credentialValuesPrinted=False,
  databaseMutations=0,grantRequests=0,oauthRequests=0,serviceMutations=0,profilePublications=0,
  jobsRetried=0,completedTechnicalPhases=8,functionalMilestonesProven=2,installationSpecific=True)
 fields.update(values)
 print(json.dumps(fields,sort_keys=True),flush=True)

def application_pin(actual):
 value=runtime_pin(actual);value['mountsHash']=digest(sorted(actual['Mounts'],key=lambda m:m['Destination']));return value

def acquisition_query(module,tenant):
 require(module=='udp','ONLY_UDP_READ_REQUIRED')
 t=literal(tenant);s=literal(SOURCE)
 return "BEGIN READ ONLY; SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='3s'; "+"""
 WITH receipt AS (
  SELECT * FROM ouf_udp.resolution_review_package_confirmation
  WHERE package_id='a5183503-04ff-4e10-850f-e22bf874365e' AND tenant_id="""+t+"""
   AND actor_subject='b93d8cf6-cd14-4ee6-91d7-84cd76c4f500'
 ), intake AS (
  SELECT h.* FROM ouf_udp.handoff_intake h
  WHERE h.source_id="""+s+""" AND (
   EXISTS(SELECT 1 FROM ouf_udp.resolution_issue q WHERE q.handoff_id=h.handoff_id AND q.tenant_id="""+t+""")
   OR EXISTS(SELECT 1 FROM ouf_udp.source_binding b JOIN ouf_udp.urban_object o ON o.urban_object_id=b.urban_object_id
     WHERE b.source_id=h.source_id AND b.type_code=h.type_code AND b.source_object_id=h.source_object_id AND o.tenant_id="""+t+""")
   OR EXISTS(SELECT 1 FROM ouf_udp.lake_object l WHERE l.lake_object_id=h.raw_lake_object_id AND l.tenant_id="""+t+"""))
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
 ), source_details AS (
  SELECT h.handoff_id,h.state intake_state,h.content_hash,h.ingestion_run_id,
   (SELECT count(*) FROM ouf_udp.materialization_job j WHERE j.handoff_id=h.handoff_id) job_count,
   (SELECT j.state FROM ouf_udp.materialization_job j WHERE j.handoff_id=h.handoff_id ORDER BY j.state LIMIT 1) job_state,
   (SELECT j.safe_failure_code FROM ouf_udp.materialization_job j WHERE j.handoff_id=h.handoff_id ORDER BY j.state LIMIT 1) job_safe_failure_code,
   (SELECT jsonb_build_object('action',d.action,'issueId',q.issue_id,'issueState',q.state)
      FROM ouf_udp.human_resolution_decision d JOIN ouf_udp.resolution_issue q USING(issue_id)
      WHERE q.handoff_id=h.handoff_id AND q.tenant_id="""+t+""" ORDER BY d.decided_at DESC,d.issue_id DESC LIMIT 1) latest_decision,
   (SELECT count(*) FROM ouf_udp.source_binding b JOIN ouf_udp.urban_object o USING(urban_object_id)
      WHERE b.source_id=h.source_id AND b.type_code=h.type_code AND b.source_object_id=h.source_object_id
       AND o.tenant_id="""+t+""" AND b.state='ACTIVE' AND o.status='ACTIVE') binding_count,
   (SELECT b.urban_object_id FROM ouf_udp.source_binding b JOIN ouf_udp.urban_object o USING(urban_object_id)
      WHERE b.source_id=h.source_id AND b.type_code=h.type_code AND b.source_object_id=h.source_object_id
       AND o.tenant_id="""+t+""" AND b.state='ACTIVE' AND o.status='ACTIVE' ORDER BY b.urban_object_id LIMIT 1) urban_object_id,
   (SELECT count(*) FROM ouf_udp.materialization_observation obs JOIN ouf_udp.object_revision r
      ON r.revision_id=obs.revision_id AND r.urban_object_id=obs.urban_object_id
      JOIN ouf_udp.urban_object o ON o.urban_object_id=obs.urban_object_id
      WHERE obs.handoff_id=h.handoff_id AND o.tenant_id="""+t+"""
       AND EXISTS(SELECT 1 FROM ouf_udp.source_binding b WHERE b.source_id=h.source_id AND b.type_code=h.type_code
        AND b.source_object_id=h.source_object_id AND b.urban_object_id=o.urban_object_id AND b.state='ACTIVE')
       AND o.current_revision_id IS NOT NULL) verified_observations,
   (SELECT count(*) FROM ouf_udp.property_contribution c JOIN ouf_udp.urban_object o USING(urban_object_id)
      WHERE c.handoff_id=h.handoff_id AND c.source_id=h.source_id AND o.tenant_id="""+t+"""
       AND EXISTS(SELECT 1 FROM ouf_udp.source_binding b WHERE b.source_id=h.source_id AND b.type_code=h.type_code
        AND b.source_object_id=h.source_object_id AND b.urban_object_id=o.urban_object_id AND b.state='ACTIVE')) contribution_count,
   (SELECT count(*) FROM ouf_udp.resolution_issue q WHERE q.handoff_id=h.handoff_id AND q.tenant_id="""+t+""" AND q.state='OPEN') open_issue_count,
   EXISTS(SELECT 1 FROM decisions d WHERE d.handoff_id=h.handoff_id) in_confirmed_package
  FROM intake h
 )
 SELECT jsonb_build_object('database',current_database(),'databaseOid',(SELECT oid::bigint FROM pg_database WHERE datname=current_database()),'role',current_user,'transactionReadOnly',current_setting('transaction_read_only')='on',
 'receiptCount',(SELECT count(*) FROM receipt),'receiptIssueCount',(SELECT issue_count FROM receipt),
 'matchedDecisionCount',(SELECT count(*) FROM decisions),'matchedDistinctIssues',(SELECT count(DISTINCT issue_id) FROM decisions),
 'decisionActions',coalesce((SELECT jsonb_agg(x) FROM (SELECT action,count(*) count FROM decisions GROUP BY action ORDER BY action)x),'[]'::jsonb),
 'sourceRowCount',(SELECT count(*) FROM intake),
 'migrations',(SELECT jsonb_agg(x ORDER BY installed_rank) FROM (SELECT installed_rank,version,script,checksum,success FROM ouf_udp.flyway_schema_history ORDER BY installed_rank LIMIT 100)x),
 'sourceDetails',coalesce((SELECT jsonb_agg(x) FROM (SELECT handoff_id,intake_state,content_hash,ingestion_run_id,job_count,job_state,job_safe_failure_code,latest_decision,binding_count,urban_object_id,verified_observations,contribution_count,open_issue_count,in_confirmed_package FROM source_details ORDER BY handoff_id LIMIT 14)x),'[]'::jsonb),
 'sourceJobs',coalesce((SELECT jsonb_agg(x) FROM (SELECT j.state,j.safe_failure_code,count(*) count FROM ouf_udp.materialization_job j JOIN intake h USING(handoff_id) GROUP BY j.state,j.safe_failure_code ORDER BY j.state,j.safe_failure_code)x),'[]'::jsonb),
 'sourceIssues',coalesce((SELECT jsonb_agg(x) FROM (SELECT q.state,q.reason_code,count(*) count FROM ouf_udp.resolution_issue q JOIN intake h USING(handoff_id) WHERE q.tenant_id="""+t+""" GROUP BY q.state,q.reason_code ORDER BY q.state,q.reason_code)x),'[]'::jsonb),
 'confirmedDistinctObjects',(SELECT count(DISTINCT urban_object_id) FROM details),
 'confirmedObjectsWithCurrentRevision',(SELECT count(DISTINCT urban_object_id) FROM details WHERE current_revision_id IS NOT NULL),
 'confirmedMaterializedRows',(SELECT count(*) FROM details WHERE issue_state='RESOLVED' AND action='CREATE_NEW' AND job_state='SUCCEEDED' AND intake_state='PROCESSED' AND binding_state='ACTIVE' AND object_state='ACTIVE' AND current_revision_id IS NOT NULL AND observation_revision IS NOT NULL AND verified_revision=observation_revision AND contribution_count>0),
 'details',coalesce((SELECT jsonb_agg(x) FROM (SELECT issue_id,action,issue_state,intake_state,job_state,safe_failure_code,urban_object_id,binding_state,object_state,(current_revision_id IS NOT NULL) current_revision_present,(verified_revision IS NOT NULL) observation_revision_verified,contribution_count FROM details ORDER BY issue_id LIMIT 13)x),'[]'::jsonb)); ROLLBACK;"""

def ingestion_query(module,tenant):
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
 'handoffDetails',coalesce((SELECT jsonb_agg(x) FROM (SELECT h.handoff_id,h.state,h.lineage_id,
  (h.downstream_receipt_ref IS NOT NULL) receipt_present,
  EXISTS(SELECT 1 FROM ouf_ingestion.ing_lineage l WHERE l.lineage_id=h.lineage_id AND l.run_id=r.run_id) lineage_verified
  FROM ouf_ingestion.handoff_outbox h WHERE h.run_id=r.run_id ORDER BY h.handoff_id LIMIT 14)x),'[]'::jsonb),
 'ackedReceipts',(SELECT count(*) FROM ouf_ingestion.handoff_outbox h WHERE h.run_id=r.run_id AND h.state='ACKED' AND h.downstream_receipt_ref IS NOT NULL),
 'quarantine',coalesce((SELECT jsonb_agg(x) FROM (SELECT state,reason_code,count(*) count FROM ouf_ingestion.ing_quarantine q WHERE q.run_id=r.run_id GROUP BY state,reason_code ORDER BY state,reason_code LIMIT 8)x),'[]'::jsonb))) FROM runs r),'[]'::jsonb),
 'health',coalesce((SELECT jsonb_agg(jsonb_build_object('status',status,'consecutiveFailures',consecutive_failures,'lastCode',last_error_code,'updatedAt',updated_at)) FROM ouf_ingestion.source_health WHERE source_id="""+s+"""),'[]'::jsonb)); ROLLBACK;"""
 raise ValueError("ONLY_INGESTION_READ_REQUIRED")

def materialization_proven(facts):
 return (facts.get('receiptCount')==1 and facts.get('receiptIssueCount')==11
  and facts.get('matchedDecisionCount')==facts.get('matchedDistinctIssues')==11
  and facts.get('confirmedDistinctObjects')==facts.get('confirmedObjectsWithCurrentRevision')==11
  and facts.get('confirmedMaterializedRows')==11)

def row_ledger(facts):
 rows=facts.get('sourceDetails',[])
 require(len(rows)==facts.get('sourceRowCount')==13,'EXACT_THIRTEEN_SOURCE_ROWS_REQUIRED')
 require(len({r['handoff_id'] for r in rows})==13,'DUPLICATE_ROW_EVIDENCE')
 committed=[];quarantined=[];unproven=[]
 for r in rows:
  if (r['job_count']==1 and r['job_state']=='SUCCEEDED' and r['intake_state']=='PROCESSED'
      and r['binding_count']==1 and r['urban_object_id'] and r['verified_observations']==1
      and r['contribution_count']>0 and r['open_issue_count']==0):
   committed.append(r)
  elif (r['job_count']==1 and r['job_state']=='QUARANTINED' and r['binding_count']==0
       and r['verified_observations']==0 and r['contribution_count']==0 and r['open_issue_count']==1
       and not r['in_confirmed_package']):
   quarantined.append(r)
  else:unproven.append(r)
 objects=[r['urban_object_id'] for r in committed]
 return {'expectedRows':13,'committedRows':len(committed),'quarantinedRows':len(quarantined),
  'unprovenRows':len(unproven),'distinctCommittedObjects':len(set(objects)),
  'originalObjectRetained':'d6051381-934b-4a11-8e71-e1d89cee4e49' in objects,
  'expectedCurrentDispositionProven':len(committed)==len(set(objects))==12 and len(quarantined)==1 and not unproven and materialization_proven(facts) and 'd6051381-934b-4a11-8e71-e1d89cee4e49' in objects or len(committed)==13 and not quarantined and not unproven,
  'confirmedElevenMaterialized':materialization_proven(facts),
  'allRowsAccounted':len(committed)+len(quarantined)==13 and not unproven,
  'allThirteenMaterializedProven':len(committed)==13 and not quarantined and not unproven,
  'quarantineIntentionEvidence':'Historical exception; user now reports resolving it in THS. This read issues no decisions.',
  'historicalCriterionChanged':False}

def upstream_matches(ingestion,udp):
 runs=ingestion.get('runs',[])
 if len(runs)!=1:return False
 run=runs[0];up=run.get('handoffDetails',[]);down=udp.get('sourceDetails',[])
 return (str(run.get('runId'))=='a3208f2f-ebfd-415d-bddc-79ab05dea78f' and run.get('state')=='SUCCEEDED'
  and run.get('lineageCount')==run.get('ackedReceipts')==len(up)==len(down)==13
  and len({str(r['handoff_id']) for r in up})==13
  and {str(r['handoff_id']) for r in up}=={str(r['handoff_id']) for r in down}
  and all(r['state']=='ACKED' and r['receipt_present'] and r['lineage_verified'] for r in up))

def validate_history(facts,expected):
 rows=facts['migrations'];actual=[r for r in rows if r['version']is not None]
 require(len(rows)in(len(expected),len(expected)+1)and len(actual)==len(expected),'EXACT_MIGRATION_COUNT_REQUIRED')
 for found,wanted in zip(actual,expected):
  require(all(found[k]==wanted[k]for k in('version','script','checksum','success')),'INSTALLED_MIGRATION_HISTORY_CHANGED')

def reference_query(module,tenant):
 require(module=='udp','ONLY_UDP_READ_REQUIRED');t=literal(tenant);s=literal(SOURCE)
 return "BEGIN READ ONLY; SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='3s'; "+"""
 WITH selected AS (
 SELECT h.handoff_id,h.state intake_state,h.payload_json->'contractRefs' refs,
 j.job_id,j.state,j.state_version,j.attempts,j.integrity_attempts,j.safe_failure_code,
 j.missing_ref_hashes,j.integrity_baseline_hash,(j.claimed_by IS NOT NULL OR j.lease_until IS NOT NULL) lease_present,
 l.state lake_state,q.state issue_state,d.action latest_action,
 (SELECT count(*) FROM ouf_udp.source_binding b WHERE b.first_handoff_id=h.handoff_id OR
 (b.source_id=h.source_id AND b.type_code=h.type_code AND b.source_object_id=h.source_object_id)) binding_count,
 (SELECT count(*) FROM ouf_udp.materialization_observation o WHERE o.handoff_id=h.handoff_id) observation_count,
 (SELECT count(*) FROM ouf_udp.property_contribution c WHERE c.handoff_id=h.handoff_id) contribution_count
 FROM ouf_udp.handoff_intake h
 JOIN ouf_udp.materialization_job j ON j.handoff_id=h.handoff_id
 JOIN ouf_udp.resolution_issue q ON q.handoff_id=h.handoff_id AND q.issue_id='e16fec6e-311d-49f3-b1de-f274cb5a92d1'
 LEFT JOIN ouf_udp.lake_object l ON l.lake_object_id=h.raw_lake_object_id AND l.tenant_id=q.tenant_id
 LEFT JOIN LATERAL (SELECT action FROM ouf_udp.human_resolution_decision d WHERE d.issue_id=q.issue_id ORDER BY decided_at DESC LIMIT 1) d ON true
 WHERE h.handoff_id='9fde61f1-8d3c-4de7-b3fe-b534b32e45e3' AND h.source_id="""+s+""" AND q.tenant_id="""+t+"""
 )
 SELECT jsonb_build_object('database',current_database(),'databaseOid',(SELECT oid::bigint FROM pg_database WHERE datname=current_database()),
 'role',current_user,'transactionReadOnly',current_setting('transaction_read_only')='on',
 'selectedJobCount',(SELECT count(*) FROM selected),'contractRefs',(SELECT refs FROM selected LIMIT 1),
 'jobs',coalesce((SELECT jsonb_agg(to_jsonb(x)-'refs') FROM selected x),'[]'::jsonb)); ROLLBACK;"""

def normal(value):return re.sub('[^a-z0-9]','',value.lower())
def file_identity(s):return tuple(getattr(s,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def mounted_file(actual,root,target,maximum):
 p=Path(target);require(p.is_absolute()and str(p)==target and '..'not in p.parts,'EXACT_CONFIGURED_FILE_REQUIRED')
 mounts=[m for m in actual['Mounts']if target==m['Destination']or target.startswith(m['Destination'].rstrip('/')+'/')]
 require(bool(mounts),'CONFIGURED_FILE_MOUNT_REQUIRED');m=max(mounts,key=lambda x:len(x['Destination']))
 require(m.get('Type')=='bind'and m.get('RW')is False,'READ_ONLY_CONFIGURED_BIND_REQUIRED')
 fds=[os.dup(root)]
 try:
  for part in p.parts[1:-1]:fds.append(os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fds[-1]))
  fds.append(os.open(p.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fds[-1]));before=os.fstat(fds[-1])
  require(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<before.st_size<=maximum,'BOUNDED_CONFIGURED_FILE_REQUIRED')
  raw=os.read(fds[-1],maximum+1)
  require(len(raw)==before.st_size and file_identity(before)==file_identity(os.fstat(fds[-1])),'CONFIGURED_FILE_CHANGED')
  return raw
 finally:
  for fd in reversed(fds):os.close(fd)

def configured_properties(actual,root,required=("ouf.udp.execution.gateway-url","ouf.udp.execution.token-file")):
 env={};values={}
 for row in actual['Config'].get('Env')or[]:
  key,value=row.split('=',1);require(key not in env,'UNIQUE_ENVIRONMENT_REQUIRED');env[key]=value
 def add(key,value):
  if type(value)in(str,int,bool):values.setdefault(normal(key),set()).add(str(value))
 def flatten(obj,prefix='',depth=0):
  require(type(obj)is dict and depth<16,'BOUNDED_SPRING_JSON_REQUIRED')
  for key,value in obj.items():
   path=prefix+'.'+key if prefix else key
   if type(value)is dict:flatten(value,path,depth+1)
   else:add(path,value)
 for key,value in env.items():add(key,value)
 if env.get('SPRING_APPLICATION_JSON'):flatten(json.loads(env['SPRING_APPLICATION_JSON']))
 if required==('spring.datasource.url','spring.datasource.username'):
  for alias,key in(('OUF_SEM_DB_URL',required[0]),('OUF_SEM_DB_USER',required[1])):
   if env.get(alias):add(key,env[alias])
 if required==('ouf.authorization.registry-url','ouf.authorization.registry-token-file'):
  for alias,key in(('REGISTRY_URL',required[0]),('REGISTRY_TOKEN_FILE',required[1])):
   if env.get(alias):add(key,env[alias])
 argv=(actual['Config'].get('Entrypoint')or[])+(actual['Config'].get('Cmd')or[])
 for key in('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','JAVA_OPTS'):argv+=shlex.split(env.get(key,''))
 for arg in argv:
  if arg.startswith(('-D','--'))and '='in arg:
   k,v=arg[2:].split('=',1);add(k,v)

 def one(key):
  found=values.get(normal(key),set())-set(['']);require(len(found)==1,'EXACT_CONFIGURED_RUNTIME_CHANNEL_REQUIRED');return next(iter(found))
 # Explicit process environment / Spring JSON outrank ordinary application files.
 # Contradictory visible channels are rejected rather than silently selected.
 if all(values.get(normal(key),set())-set([''])for key in required):
  return one(required[0]),one(required[1]),None
 locations=[v for k,v in env.items()if normal(k)in('springconfiglocation','springconfigadditionallocation','springconfigimport')and v]
 require(len(locations)==1,'ONE_EXPLICIT_RUNTIME_CONFIG_SELECTOR_REQUIRED')
 location=locations[0].removeprefix('optional:');require(location.startswith('file:')and location.endswith(('.properties','.yaml','.yml'))and ','not in location,'LITERAL_PROPERTIES_CONFIG_REQUIRED')
 target=location[5:];raw=mounted_file(actual,root,target,262144)
 require(b'\\'not in raw and b'${'not in raw and b'\0'not in raw,'LITERAL_RUNTIME_CONFIGURATION_REQUIRED');seen=set()
 if location.endswith('.properties'):
  for line in raw.decode().splitlines():
   if not line.strip()or line.lstrip().startswith(('#','!')):continue
   m=re.fullmatch(r'[ \t]*([A-Za-z0-9_.-]+)[ \t]*[=:][ \t]*([^\r\n]*)',line);require(m is not None,'LITERAL_PROPERTY_REQUIRED')
   key=normal(m[1]);require(key not in seen,'UNIQUE_RUNTIME_PROPERTY_REQUIRED');seen.add(key);add(m[1],m[2].strip())
 else:
  stack=[]
  for line in raw.decode().splitlines():
   if not line.strip()or line.lstrip().startswith('#'):continue
   require('\t'not in line,'LITERAL_YAML_INDENT_REQUIRED')
   m=re.fullmatch(r'( *)([A-Za-z0-9_.-]+):(?: +(.*))?',line);require(m is not None,'LITERAL_YAML_MAPPING_REQUIRED')
   indent=len(m[1]);value=m[3]
   while stack and stack[-1][0]>=indent:stack.pop()
   key='.'.join([part for _,part in stack]+[m[2]]);normalized=normal(key)
   require(normalized not in seen,'UNIQUE_RUNTIME_PROPERTY_REQUIRED');seen.add(normalized)
   if value is None:stack.append((indent,m[2]));continue
   if value.startswith('"'):value=json.loads(value);require(type(value)is str,'LITERAL_YAML_STRING_REQUIRED')
   elif value.startswith("'"):
    require(value.endswith("'"),'LITERAL_YAML_STRING_REQUIRED');value=value[1:-1].replace("''", "'")
   else:
    require(not value.startswith(('{','[','&','*','!','|','>')),'LITERAL_YAML_SCALAR_REQUIRED');value=re.sub(r' +#.*$','',value).strip()
   add(key,value)

 return one(required[0]),one(required[1]),hashlib.sha256(raw).hexdigest()

def safe_get(origin,path,token):
 u=urlsplit(origin);require(u.scheme=='https'and u.hostname and not u.username and not u.password and not u.query and not u.fragment and u.path in('','/'),'REVIEWED_HTTPS_ORIGIN_REQUIRED')
 require((path.startswith('/api/')or path=='/internal/capabilities/v1/authorization/policy-bundle/active')and '\r'not in path and '\n'not in path,'BOUNDED_DEPENDENCY_PATH_REQUIRED')
 credential=token.decode('ascii').strip();require(0<len(credential)<=16384 and not any(x.isspace()for x in credential),'PRIVATE_WORKLOAD_TOKEN_REQUIRED')
 conn=http.client.HTTPSConnection(u.hostname,u.port or 443,timeout=5,context=ssl.create_default_context())
 try:
  conn.request('GET',path,headers={'Authorization':'Bearer '+credential,'Accept':'application/json'})
  response=conn.getresponse();raw=response.read(2097153);require(len(raw)<=2097152,'DEPENDENCY_RESPONSE_BOUND_EXHAUSTED')
  try:body=json.loads(raw)
  except(ValueError,UnicodeError):body={}
  if type(body)is not dict:body={}
  safe={'httpStatus':response.status,'hostTransportOnly':True,'responseValuesPrinted':False,'ownerAuthorizationDeniedDetail':body.get('detail')=='Owner authorization denied'}
  for key in('code','errorCode','reason','error','message','detail'):
   v=body.get(key)
   if type(v)is str and (re.fullmatch('(SEM_|UDP_|OUF_|AUTHORIZATION_)[A-Z0-9_:.-]{1,110}',v)or v in('insufficient_scope','invalid_token','access_denied','Forbidden','Unauthorized','SEM_CAPABILITY_REQUIRED:ouf.semantic.read','SEM_AUTHENTICATION_REQUIRED')):safe[key]=v
  return safe,body
 finally:conn.close()

def probe_dependencies(actual,refs,origin,plan):
 global CREDENTIAL_FILES_READ
 pid=actual['State']['Pid'];require(type(pid)is int and pid>1,'CURRENT_UDP_PROCESS_REQUIRED')
 def process_pin():
  raw=Path('/proc/'+str(pid)+'/stat').read_text();return(raw[raw.rfind(')')+2:].split()[19],os.readlink('/proc/'+str(pid)+'/ns/mnt'))
 before=process_pin();root=os.open('/proc/'+str(pid)+'/root',os.O_RDONLY|os.O_DIRECTORY)
 try:
  gateway,target,config_hash=configured_properties(actual,root)
  require(gateway.rstrip('/')==origin.rstrip('/'),'CONFIGURED_GATEWAY_EQUALS_REVIEWED_ORIGIN_REQUIRED')
  token=mounted_file(actual,root,target,16384);CREDENTIAL_FILES_READ=1;parts=token.decode('ascii').strip().split('.')
  require(len(parts)==3 and all(re.fullmatch('[A-Za-z0-9_-]+',p)for p in parts),'WORKLOAD_JWT_SHAPE_REQUIRED')
  claims=json.loads(base64.urlsafe_b64decode(parts[1]+'='*((-len(parts[1]))%4)));expiry=claims.get('exp');require(type(expiry)is int,'WORKLOAD_EXPIRY_REQUIRED')
  emit('UDP_EXECUTION_TOKEN_METADATA',configured=True,expiredAtRead=expiry<=time.time(),expiryEpoch=expiry,claimsAreMetadataOnly=True,signatureVerifiedLocally=False,configFileSha256=config_hash)
  emit_route_access_metadata(plan,claims)
  bundle=refs.get('bundleRef');require(type(bundle)is str and 0<len(bundle)<=2048,'EXACT_PINNED_BUNDLE_REFERENCE_REQUIRED')
  safe,envelope=safe_get(origin,'/api/onboarding/v1/runtime/publications/resolve?'+urlencode({'bundleRef':bundle}),token)
  emit('PINNED_PUBLICATION_GET',**safe)
  if safe['httpStatus']==200:
   bindings=envelope.get('bundle',{}).get('semanticReferenceBindings');require(type(bindings)is list and 0<len(bindings)<=32,'BOUNDED_SEMANTIC_REFERENCE_BINDINGS_REQUIRED')
   for i,binding in enumerate(bindings[:2]):
    sid=binding.get('semanticId');revision=binding.get('revisionId');publication=binding.get('publicationSetId')
    require(type(sid)is str and 0<len(sid)<=2048 and all(type(v)is str and re.fullmatch('[0-9a-f-]{36}',v)for v in(revision,publication)),'EXACT_PUBLISHED_SEMANTIC_BINDING_REQUIRED')
    safe,_=safe_get(origin,'/api/semantic/v1/references:resolve?'+urlencode({'semanticId':sid,'revisionId':revision,'publicationSetId':publication}),token)
    emit('SEMANTIC_REFERENCE_GET',bindingIndex=i,**safe)
    if safe['httpStatus']!=200:break
   emit('REFERENCE_PROBE_COVERAGE',semanticBindings=len(bindings),maximumSemanticGets=2,allSemanticDependenciesChecked=False)
  require(before==process_pin(),'UDP_PROCESS_CHANGED_DURING_DEPENDENCY_READ')
  return claims
 finally:os.close(root)


def emit_route_access_metadata(plan,claims):
 scope=claims.get('scope');scope=set(scope.split())if type(scope)is str else set(scope or[])
 actor=claims.get('ouf_actor_type');service=claims.get('client_id')or claims.get('azp');aud=claims.get('aud');aud=[aud]if type(aud)is str else aud or[]
 rows=[route for route in plan['gateway']['afterRoutes'].values()if route.get('uri')=='/api/semantic/v1/references:resolve'and 'GET'in route.get('methods',[])]

 if len(rows)!=1:
  emit('RETAINED_ROUTE_AND_TOKEN_METADATA',exactRouteCount=len(rows),routeMetadataIsRetained=True,liveRouteInventoryProven=False,semanticReadScopePresent='ouf.semantic.read'in scope,actorIsService=actor=='SERVICE');return
 route=rows[0];plugins=route.get('plugins')or{};oidc=plugins.get('openid-connect')or{}
 required=oidc.get('required_scopes')or[];require(type(required)is list and len(required)<=16 and all(type(v)is str and len(v)<=128 for v in required),'BOUNDED_ROUTE_SCOPE_METADATA_REQUIRED')
 functions=(plugins.get('serverless-post-function')or{}).get('functions')or[]
 tables={'services':[],'actors':[]}
 for kind,key in(('services','allowed_services'),('actors','allowed_actors')):
  for fn in functions:
   matches=re.findall(r'local '+key+r'=\{([^}]+)\}',fn)
   for body in matches:
    for value in re.findall(r'\[("(?:[^"\\]|\\.)*")\]=true',body):tables[kind].append(json.loads(value))
 emit('RETAINED_ROUTE_AND_TOKEN_METADATA',routeId=route['id'],routeMetadataIsRetained=True,liveRouteInventoryProven=False,
  requiredScopes=required,requiredScopesPresentInToken=all(v in scope for v in required),
  semanticReadScopePresent='ouf.semantic.read'in scope,actorIsService=actor=='SERVICE',
  principalCategory='UDP'if service=='ouf-udp'else'INGESTION'if service=='ouf-ingestion'else'OTHER',
  audienceMatchesRoute=oidc.get('client_id')in aud,bearerOnly=oidc.get('bearer_only')is True,
  workloadGuardMetadataParsed=bool(tables['services'])and bool(tables['actors']),
  servicePrincipalAllowedByRetainedGuard=service in tables['services'],actorAllowedByRetainedGuard=actor in tables['actors'])

def policy_metadata(doc,claims):
 bundle=doc.get('bundle');version=doc.get('bundleVersion')
 require(type(bundle)is dict and type(version)is int,'ACTIVE_OWNER_POLICY_ENVELOPE_REQUIRED')
 caps=bundle.get('capabilities');grants=bundle.get('grants')
 require(type(caps)is list and type(grants)is list and len(caps)<=10000 and len(grants)<=10000 and all(type(v)is dict for v in caps+grants),'BOUNDED_OWNER_POLICY_PAYLOAD_REQUIRED')
 compact=json.dumps(bundle,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
 checksum=hashlib.sha256(compact).hexdigest()==doc.get('contentHash')
 result={'bundleVersion':version,'compactBundleHashMatchesEnvelope':checksum,'loadedOwnerSnapshotProven':False}
 if not checksum:return result
 tenant=claims.get('tenant_id');subject=claims.get('ouf_subject')or claims.get('sub');service=claims.get('client_id')or claims.get('azp')
 require(all(type(v)is str and 0<len(v)<=256 for v in(tenant,subject,service)),'UDP_IDENTITY_METADATA_REQUIRED')
 result['capabilities']=[c for c in caps if c.get('capabilityId')=='ouf.semantic.read']
 selected=[g for g in grants if g.get('capabilityId')=='ouf.semantic.read'and g.get('tenantId')==tenant]
 require(len(selected)<=64,'BOUNDED_SEMANTIC_READ_GRANTS_REQUIRED');rows=[]
 def instant(value):
  if type(value)is not str:return None
  from datetime import datetime
  return datetime.fromisoformat(value.replace('Z','+00:00')).timestamp()
 for g in selected:
  constraints=g.get('constraints')or{};require(type(constraints)is dict,'OWNER_GRANT_CONSTRAINT_SHAPE_REQUIRED')
  start=instant(g.get('validFrom'));end=instant(g.get('validUntil'));attrs=constraints.get('resourceAttributes')or{}
  require(type(attrs)is dict,'OWNER_RESOURCE_ATTRIBUTES_SHAPE_REQUIRED')
  rows.append({'subjectMatchesToken':not g.get('subjectId')or g.get('subjectId')==subject,
   'servicePrincipalMatchesToken':not g.get('servicePrincipalId')or g.get('servicePrincipalId')==service,
   'organizationRestricted':bool(g.get('organizationId')),
   'validAtRead':start is not None and end is not None and start<=time.time()<end,
   'resourceTypeMatchesValidation':not constraints.get('resourceType')or constraints.get('resourceType')=='semantic.validation',
   'resourceIdMatchesUnspecified':not constraints.get('resourceId'),
   'moduleConstraintMatches':all(k=='module'and v=='SEMANTIC'for k,v in attrs.items()),'constraints':constraints})
 result['grants']=rows
 return result

def probe_owner_policy_channel(actual,origin,udp_claims=None):
 global CREDENTIAL_FILES_READ
 pid=actual['State']['Pid'];require(type(pid)is int and pid>1,'CURRENT_SEMANTIC_PROCESS_REQUIRED')
 def pin():
  raw=Path('/proc/'+str(pid)+'/stat').read_text();return(raw[raw.rfind(')')+2:].split()[19],os.readlink('/proc/'+str(pid)+'/ns/mnt'))
 before=pin();root=os.open('/proc/'+str(pid)+'/root',os.O_RDONLY|os.O_DIRECTORY)
 try:
  endpoint,target,config_hash=configured_properties(actual,root,('ouf.authorization.registry-url','ouf.authorization.registry-token-file'))
  path='/internal/capabilities/v1/authorization/policy-bundle/active'
  require(endpoint==origin.rstrip('/')+path,'REVIEWED_OWNER_POLICY_ENDPOINT_REQUIRED')
  token=mounted_file(actual,root,target,16384);CREDENTIAL_FILES_READ+=1
  parts=token.decode('ascii').strip().split('.');require(len(parts)==3,'OWNER_POLICY_JWT_SHAPE_REQUIRED')
  claims=json.loads(base64.urlsafe_b64decode(parts[1]+'='*((-len(parts[1]))%4)));expiry=claims.get('exp');require(type(expiry)is int,'OWNER_POLICY_TOKEN_EXPIRY_REQUIRED')
  emit('OWNER_POLICY_TOKEN_METADATA',configured=True,expiredAtRead=expiry<=time.time(),expiryEpoch=expiry,claimsAreMetadataOnly=True,signatureVerifiedLocally=False,configFileSha256=config_hash)
  safe,body=safe_get(origin,path,token)
  version=body.get('bundleVersion');version=version if type(version)is int else body.get('version')if type(body.get('version'))is int else None
  emit('OWNER_POLICY_TRANSPORT_GET',activeBundleVersion=version,loadedOwnerSnapshotProven=False,**safe)
  if safe['httpStatus']==200 and udp_claims is not None:
   emit('SEMANTIC_OWNER_POLICY_METADATA',facts=policy_metadata(body,udp_claims),policyObtainedFromConfiguredRegistryChannel=True,loadedOwnerSnapshotProven=False,rawPolicyPrinted=False)
  require(before==pin(),'SEMANTIC_PROCESS_CHANGED_DURING_POLICY_READ')
 finally:os.close(root)


def reviewed_registry(ns,engine):
 # Bind by the immutable reviewed identity, never by a guessed container name.
 review=ns['read'](POLICY_CONTEXT/'review.json',8388608,POLICY_REVIEW)
 link=review.get('workerReviewBinding',{})
 require(link.get('path')==str(POLICY_CONTEXT/'worker-review.json')and re.fullmatch('[0-9a-f]{64}',str(link.get('sha256',''))),'EXACT_WORKER_REVIEW_LINK_REQUIRED')
 worker=ns['read'](link['path'],8388608,link['sha256'])
 pin=worker['registryGeneration']
 require(type(pin)is dict and re.fullmatch('[0-9a-f]{64}',str(pin.get('containerId',''))),'EXACT_REVIEWED_REGISTRY_ID_REQUIRED')
 actual=ns['engine_get'](engine,'containers',pin['containerId'])
 require(actual is not None and actual['State']['Running']is True and ns['runtime_pin'](actual)==pin,'CURRENT_REVIEWED_REGISTRY_GENERATION_REQUIRED')
 return actual

def semantic_policy_query(tenant,claims):
 t=literal(tenant);subject=literal(claims.get('ouf_subject')or claims.get('sub'));service=literal(claims.get('client_id')or claims.get('azp'))
 return """BEGIN READ ONLY; SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='3s';
 WITH active AS (SELECT b.version,b.bundle_payload FROM ouf_authorization.active_policy_bundle a JOIN ouf_authorization.policy_bundle b ON b.bundle_id=a.bundle_id AND b.version=a.version WHERE a.singleton_key=true),
 selected AS (SELECT g FROM active a CROSS JOIN LATERAL jsonb_array_elements(a.bundle_payload->'grants') g WHERE g->>'capabilityId'='ouf.semantic.read' AND g->>'tenantId'="""+t+""")
 SELECT jsonb_build_object('database',current_database(),'databaseOid',(SELECT oid::bigint FROM pg_database WHERE datname=current_database()),'role',current_user,'transactionReadOnly',current_setting('transaction_read_only')='on',
 'bundleCount',(SELECT count(*) FROM active),'bundleVersion',(SELECT version FROM active),
 'capabilities',coalesce((SELECT jsonb_agg(c) FROM active a CROSS JOIN LATERAL jsonb_array_elements(a.bundle_payload->'capabilities') c WHERE c->>'capabilityId'='ouf.semantic.read'),'[]'::jsonb),
 'grants',coalesce((SELECT jsonb_agg(jsonb_build_object('servicePrincipalMatchesToken',coalesce(g->>'servicePrincipalId','')=''OR g->>'servicePrincipalId'="""+service+""",'subjectMatchesToken',coalesce(g->>'subjectId','')=''OR g->>'subjectId'="""+subject+""",'validAtRead',(g->>'validFrom')::timestamptz<=clock_timestamp()AND clock_timestamp()<(g->>'validUntil')::timestamptz,'organizationRestricted',coalesce(g->>'organizationId','')<>'','resourceTypeMatchesValidation',coalesce(g->'constraints'->>'resourceType','')IN('','semantic.validation'),'resourceIdMatchesUnspecified',coalesce(g->'constraints'->>'resourceId','')='','moduleConstraintMatches',coalesce(g->'constraints'->'resourceAttributes','{}'::jsonb)IN('null'::jsonb,'{}'::jsonb,'{"module":"SEMANTIC"}'::jsonb),'constraints',g->'constraints'))FROM selected),'[]'::jsonb)); ROLLBACK;"""

def unlocked(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  info=os.fstat(fd);require(stat.S_ISREG(info.st_mode)and info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o600,'PRIVATE_INVOCATION_LOCK_REQUIRED')
  try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:return False
  fcntl.flock(fd,fcntl.LOCK_UN);return True
 finally:os.close(fd)

def policy_worker_metadata(ns):
 read=ns['read'];base=read(POLICY_CONTEXT/'review.json',8388608,POLICY_REVIEW)
 prior=base['scopes']['policyTokenFiniteWorkerSession'];path=Path(prior['fenceBinding']['path'])
 fence=read(path,16384)
 require(fence.get('schema')=='ouf.semantic-functional-session-fence.v1'and fence.get('logicalOwnerScopeHash')==prior['logicalOwnerScopeHash'],'EXACT_LOGICAL_OWNER_FENCE_REQUIRED')
 journal=Path(fence['journalPath'])
 require(journal.parent==path.parent and journal.name=='semantic-functional-worker-'+fence['reviewHash'],'EXACT_CURRENT_WORKER_DIRECTORY_REQUIRED')
 rows={n:read(journal/n,131072)for n in('owner-session.json','owner-session-review.json','recovery.json','owner-status.json','owner-admission.json')}
 signed=rows['owner-session.json'];row=rows['recovery.json'];worker_review=rows['owner-session-review.json']
 require(signed['fenceBinding']=={'path':str(path),'value':fence}and digest(worker_review)==signed['reviewHash']==fence['reviewHash'],'CURRENT_WORKER_REVIEW_CHAIN_REQUIRED')
 prior_count=signed['predecessorGrantAttempts'];attempts=row['attempts'];ceiling=signed['maximumCumulativeGrantAttempts']
 require(type(attempts)is int and type(prior_count)is int and type(ceiling)is int and 0<=attempts<=signed['policy']['max_attempts']<=128 and row['controlledPredecessorGrantAttempts']==prior_count and row['controlledCumulativeGrantAttempts']==prior_count+attempts<=ceiling,'EXACT_CURRENT_CUMULATIVE_BUDGET_REQUIRED')
 state=row['state'];reason=row.get('reason');require(state in('NEW','ACTIVE','RETRY_WAIT','CANCELLED','FAILED','BLOCKED','EXHAUSTED')and(reason is None or re.fullmatch('[A-Z_]{1,100}',reason)),'SAFE_WORKER_STATE_REQUIRED')
 emit('CURRENT_POLICY_WORKER_HISTORY',journalPath=str(journal),state=state,reason=reason,attempts=attempts,publications=row.get('publicationCount'),priorControlledGrantAttempts=prior_count,controlledCumulativeGrantAttempts=prior_count+attempts,maximumCumulativeGrantAttempts=ceiling,remainingControlledGrantAttempts=ceiling-prior_count-attempts,invocationLockUnheldAtRead=unlocked(journal/'invocation.lock'),workerReviewHash=digest(worker_review),recordHashes={n:digest(v)for n,v in rows.items()},newWorkerStarted=False)
 require(read(path,16384)==fence and all(read(journal/n,131072)==v for n,v in rows.items()),'RECOVERY_METADATA_CHANGED_DURING_READ')


def main():
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_READ_REQUIRED')
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('READ_DEADLINE')));signal.alarm(120)
 fd=os.open(BOOT,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(fd);require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and 0<s.st_size<=131072,'RETAINED_HELPER_CUSTODY_REQUIRED')
  raw=os.read(fd,131073);require(len(raw)==s.st_size and hashlib.sha256(raw).hexdigest()==BOOT_HASH,'RETAINED_HELPER_HASH_CHANGED')
 finally:os.close(fd)
 ns={'__name__':'linked_property_read_helpers'};exec(compile(raw,'<verified-retained-read-helpers>','exec'),ns)
 old=ns['read'](ns['CONTEXT']/'review.json',8388608,ns['REVIEW']);link=old['scopes']['finiteActionProcess']['bundle']
 prepared=ns['read'](link['path'],8388608,link['sha256'])['prepared']
 require(digest(prepared)==old['privateInputHashes']['preparedInputs'],'PREPARED_INPUT_BINDING_CHANGED')
 review=ns['read'](CONTEXT/'review.json',8388608);plan=ns['read'](CONTEXT/'execution-plan.json',8388608)
 record=ns['read'](CONTEXT/'recovery.json',131072);authority=ns['read'](CONTEXT/'authority.json',131072)
 scope=review['scopes']['linkedPropertyUpdate']
 require(review['authorityDirectory']==str(CONTEXT)and digest(plan)==scope['planHash']
  and record['scopeHash']==digest(scope)and authority['linkedPropertyUpdate']==scope and digest(authority)==record['authorityHash']
  and record['version']==55 and record['incidentState']=='RECOVERED'and record['nextStage']==len(record['effects'])==len(scope['stages'])
  and [e['stage']for e in record['effects']]==scope['stages']and scope['stages'][-1]=='VERIFY_FINAL'
  and all(e['state']=='APPLIED'and e['intentHash']==digest({'planHash':scope['planHash'],'stage':e['stage']})for e in record['effects']),
  'EXACT_COMPLETED_LINKED_PROPERTY_UPDATE_REQUIRED')
 proofs=record['effects'][-1]['evidence']['applications']
 def applications():
  for module in('udp','onboarding'):
   actual=ns['engine_get'](prepared['engine'],'containers',proofs[module]['runtimeBinding']['containerId'])
   require(actual and actual['State']['Running']is True and application_pin(actual)==proofs[module]['runtimeBinding'],'CURRENT_APPLICATION_GENERATION_CHANGED')
 applications()
 db=prepared['databasePlan'];pg=ns['engine_get'](prepared['engine'],'containers',db['postgresRuntimeBinding']['containerId'])
 admin=db['mcpAuditRoleAdministration']['admin']
 require(pg and pg['State']['Running']is True and runtime_pin(pg)==db['postgresRuntimeBinding'],'EXACT_POSTGRES_GENERATION_REQUIRED')
 require([v.split('=',1)[1]for v in pg['Config']['Env']if v.startswith('POSTGRES_USER=')]==[admin],'EXISTING_ADMINISTRATOR_BINDING_REQUIRED')
 emit('ROLLOUT_READBACK',contextPath=str(CONTEXT),journalVersion=55,reviewSha256=digest(review),rootArtifactReviewLinksMatch=True,
      reviewSignaturesVerifiedLocally=False,applicationGenerationsMatch=True,backupEvidencePresent=any(e['stage']=='BACKUP_UDP'and e['evidence'].get('payloadParsed')is True for e in record['effects']))
 selection=prepared['authorization']['plan']['selection'];results={}
 with tempfile.TemporaryDirectory(prefix='ouf-linked-property-read-')as config:
  for module in('udp',):
   binding=next(r for r in db['modules']if r['module']==module)
   for v in(admin,binding['database']):require(type(v)is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,62}',v),'EXACT_DATABASE_ROLE_REQUIRED')
   argv=[executable(old['sourceClosure']['executables']['docker']),'--host','unix://'+prepared['engine']['socketPath'],'--config',config,'exec',pg['Id'],'env','LC_ALL=C',
    'PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=10000 -c lock_timeout=3000','timeout','-s','KILL','15','psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1',
    '-U',admin,'-d',binding['database'],'-c',(ingestion_query(module,selection['tenant']) if module=='ingestion' else acquisition_query(module,selection['tenant']))]
   code,raw,err,_=bounded(argv,seconds=20,maximum=524288);require(code==0,'READ_ONLY_PROFILE_SQL_FAILED');facts=json.loads(raw)
   require(facts['database']==binding['database']and facts['databaseOid']==binding['databaseOid']and facts['role']==admin and facts['transactionReadOnly']is True,'EXACT_DATABASE_FACTS_REQUIRED')
   results[module]=facts
   if module=='udp':
    validate_history(facts,plan['database']['expected'][module])
    require(facts['migrations'][-1]['version']=='35','V35_SCHEMA_UNPROVEN')
    require(len(facts['sourceDetails'])<=13 and len(facts['details'])<=13,'BOUNDED_SOURCE_FACTS_REQUIRED')
   else:
    require(len(facts['schedules'])<=1 and len(facts['runs'])<=3 and all(len(r.get('handoffDetails',[]))<=13 for r in facts['runs']),'BOUNDED_INGESTION_FACTS_REQUIRED')
   emit('ACQUISITION_DATABASE',module=module,facts=facts,rawSqlOutputPrinted=False,propertyValuesPrinted=False)

 binding=next(r for r in db['modules']if r['module']=='udp')
 with tempfile.TemporaryDirectory(prefix='ouf-csv-reference-read-')as config:
  argv=[executable(old['sourceClosure']['executables']['docker']),'--host','unix://'+prepared['engine']['socketPath'],'--config',config,'exec',pg['Id'],'env','LC_ALL=C',
   'PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=10000 -c lock_timeout=3000','timeout','-s','KILL','15','psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1',
   '-U',admin,'-d',binding['database'],'-c',reference_query('udp',selection['tenant'])]
  code,raw,err,_=bounded(argv,seconds=20,maximum=65536);require(code==0,'READ_ONLY_REFERENCE_SQL_FAILED');facts=json.loads(raw)
 require(facts['database']==binding['database']and facts['databaseOid']==binding['databaseOid']and facts['role']==admin and facts['transactionReadOnly']is True,'EXACT_REFERENCE_DATABASE_REQUIRED')
 refs=facts.pop('contractRefs');require(facts['selectedJobCount']==1 and type(refs)is dict,'EXACT_SINGLE_RESOLVED_ROW_REQUIRED')
 emit('REFERENCE_JOB_METADATA',facts=facts,rawSqlOutputPrinted=False,propertyValuesPrinted=False)
 udp=ns['engine_get'](prepared['engine'],'containers',proofs['udp']['runtimeBinding']['containerId'])
 claims=probe_dependencies(udp,refs,selection['origin'],plan)
 registry=None;registry_pin=None
 try:
  registry=reviewed_registry(ns,prepared['engine']);registry_pin=runtime_pin(registry)
  probe_owner_policy_channel(registry,selection['origin'],claims)
 except Exception as failure:
  reason=str(failure)if type(failure)is ValueError and re.fullmatch('[A-Z_]+',str(failure))else type(failure).__name__
  emit('OWNER_POLICY_CHANNEL_UNPROVEN',reason=reason,exceptionMessagePrinted=False)
 binding=next(r for r in db['modules']if r['module']=='onboarding')
 for v in(admin,binding['database']):require(type(v)is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,62}',v),'EXACT_DATABASE_ROLE_REQUIRED')
 with tempfile.TemporaryDirectory(prefix='ouf-csv-policy-read-')as config:
  argv=[executable(old['sourceClosure']['executables']['docker']),'--host','unix://'+prepared['engine']['socketPath'],'--config',config,'exec',pg['Id'],'env','LC_ALL=C',
   'PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=10000 -c lock_timeout=3000','timeout','-s','KILL','15','psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1',
   '-U',admin,'-d',binding['database'],'-c',semantic_policy_query(selection['tenant'],claims)]
  code,raw,err,_=bounded(argv,seconds=20,maximum=65536);require(code==0,'READ_ONLY_SEMANTIC_POLICY_SQL_FAILED');policy_facts=json.loads(raw)
 require(policy_facts['database']==binding['database']and policy_facts['databaseOid']==binding['databaseOid']and policy_facts['role']==admin and policy_facts['transactionReadOnly']is True,'EXACT_POLICY_DATABASE_REQUIRED')
 emit('PUBLISHED_SEMANTIC_READ_GRANTS',facts=policy_facts,loadedRegistrySnapshotProven=False,rawPolicyPrinted=False)
 try:policy_worker_metadata(ns)
 except Exception as failure:
  reason=str(failure)if type(failure)is ValueError and re.fullmatch('[A-Z_]+',str(failure))else type(failure).__name__
  emit('POLICY_WORKER_HISTORY_UNPROVEN',reason=reason,exceptionMessagePrinted=False,newWorkerStarted=False)
 if registry is not None:require(runtime_pin(ns['engine_get'](prepared['engine'],'containers',registry['Id']))==registry_pin,'SEMANTIC_GENERATION_CHANGED_DURING_READ')
 require(runtime_pin(ns['engine_get'](prepared['engine'],'containers',pg['Id']))==db['postgresRuntimeBinding'],'POSTGRES_GENERATION_CHANGED_DURING_READ')
 applications();require(ns['read'](CONTEXT/'recovery.json',131072)==record,'ROLLOUT_RECORD_CHANGED')
 emit('END',complete=True,dependencyProbeComplete=True,functionalStage3Proven=False,runtimeAuthorityIssued=False,rootCauseRequiresReadback=True)
if __name__=='__main__':
 emit('BEGIN',maximumSeconds=120,maximumEngineReads=9,maximumSqlSessions=3,maximumRows=13,maximumCredentialFiles=2,maximumGatewayGets=4)
 try:main()
 except Exception as error:
  reason=str(error)if type(error)is ValueError and re.fullmatch('[A-Z_]+',str(error))else type(error).__name__
  emit('STOP',reason=reason,exceptionMessagePrinted=False)
  raise SystemExit(2)
