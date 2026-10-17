#!/usr/bin/env python3
"""Installation-specific stage-3 row ledger on the retained, verified rollout.

Reuses the existing post-rollout transport and post-resolution receipt proof.
No source values, tokens, retries, profile publication or database writes.
"""
import hashlib,http.client,json,os,re,selectors,signal,socket,stat,subprocess,sys,tempfile,time
from pathlib import Path
BOOT=Path('/etc/ouf/deploy-snapshots/semantic-mcp-update-executor-code-yrvtskkt/execute.py')
BOOT_HASH='b02d9737af6d143903910654d34e91a1a82a52b6082d2429d5dbfd070d160af2'
CONTEXT=Path('/etc/ouf/deploy-snapshots/linked-property-execution-cjecd1en')
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


def emit(check,**values):
 fields=dict(schema='ouf.teatri-post-resolution-materialization-read.v3',check=check,readOnly=True,
  automaticRetry=False,budgetReset=False,credentialFilesRead=0,credentialValuesPrinted=False,
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

def main():
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_READ_REQUIRED')
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('READ_DEADLINE')));signal.alarm(65)
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
  for module in('ingestion','udp'):
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
 require(runtime_pin(ns['engine_get'](prepared['engine'],'containers',pg['Id']))==db['postgresRuntimeBinding'],'POSTGRES_GENERATION_CHANGED_DURING_READ')
 applications();require(ns['read'](CONTEXT/'recovery.json',131072)==record,'ROLLOUT_RECORD_CHANGED')
 ledger=row_ledger(results['udp']);linked=upstream_matches(results['ingestion'],results['udp'])
 stage3=linked and ledger['allThirteenMaterializedProven'] and ledger['confirmedElevenMaterialized'] and ledger['originalObjectRetained']
 emit('END',complete=True,udpMigrationVersion=35,rowLedger=ledger,upstreamHandoffsAndLineageMatch=linked,
  functionalStage3Proven=stage3,functionalMilestonesProven=3 if stage3 else 2,
  confirmedElevenMaterialized=ledger['confirmedElevenMaterialized'],allThirteenMaterializedProven=ledger['allThirteenMaterializedProven'],
  readbackProven=linked and ledger['allRowsAccounted'],profileActivationProven=False,runtimeAuthorityIssued=False)
if __name__=='__main__':
 emit('BEGIN',maximumSeconds=65,maximumEngineReads=6,maximumSqlSessions=2,maximumRows=13)
 try:main()
 except Exception as error:
  reason=str(error)if type(error)is ValueError and re.fullmatch('[A-Z_]+',str(error))else type(error).__name__
  emit('STOP',reason=reason,exceptionMessagePrinted=False)
  raise SystemExit(2)
