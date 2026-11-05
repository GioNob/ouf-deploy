"""Bounded read-only PostgreSQL evidence export. No provisioning, grants or retry.

The SQL is generated from fixed source-owned projections, never caller SQL.
Each export is one REPEATABLE READ READ ONLY transaction. Separate exports and
S3 observations are NOT a common recovery cut or an authorization decision.
"""
import argparse,hashlib,ipaddress,json,os,re,selectors,shutil,stat,subprocess,time
from pathlib import Path
from .inventory_manifest import canonical,decode,require,sha

MAX_ROWS=10000
MAX_BYTES=32<<20
MAX_LINE=256<<10
MAX_SECONDS=120
SOURCES={'onboarding':'d5155899b09dda298494b68cefa7e1f281167652','onboarding-retained':'73498c17596ae155a3ed9ab36acfd6bb69da9846','udp':'0d40da05408a14db31d4d41af2372d6a71480291','ingestion':'4165b9e149be467d5d7c6bed35e4e1af4e249db1'}
# Fields omitted from these projections include raw business payloads, samples,
# credentials, reasons, subjects and arbitrary configuration documents.
TABLES={
 'onboarding':{
  'ouf_onboarding.managed_file_asset':'asset_id,source_id,tenant_id,staging_ref,content_hash,size_bytes,media_type,status,retention_ref',
  'ouf_onboarding.file_profile':'profile_id,asset_id,version,sample_ref',
  'ouf_onboarding.file_profile_job':'job_id,asset_id,state,attempts,profile_id,lease_until,next_attempt_at',
  'ouf_onboarding.managed_file_upload_attempt':'tenant_id,idempotency_key,file_id,content_hash,size_bytes,asset_id',
  'ouf_onboarding.managed_file_onboarding_attempt':'asset_id,idempotency_key,source_id,onboarding_version_id,request_hash',
  'ouf_onboarding.managed_file_owner_reconciliation':'asset_id,job_id,tenant_id,content_hash,size_bytes,decision_ref',
  'ouf_onboarding_legacy.managed_file_ingestion':'ingestion_id,asset_id,profile_id,source_id,onboarding_version_id,state,output_ref,lease_until',
  'ouf_onboarding.managed_file_upload_intent':'intent_id,upload_kind,tenant_id,content_hash,size_bytes,staging_ref,epoch,state,asset_id,reconciliation_reads,reconcile_until,acknowledged_at',
  'ouf_onboarding.managed_file_storage_control':'singleton,epoch,phase',
  'ouf_onboarding.storage_recovery_authority_projection':'singleton,version,decision_id',
 },
 'udp':{
  'ouf_udp.lake_object':'lake_object_id,tenant_id,source_id,type_code,tier,content_hash,media_type,logical_size_bytes,locator,previous_locator,state,retention_class,retention_until,legal_hold,blocking_lineage_refs,historical_replay_required,active_export_refs,lease_until,lease_generation,state_version',
  'ouf_udp.compaction_manifest':'manifest_id,tenant_id,output_lake_object_id,output_content_hash,state',
  'ouf_udp.compaction_manifest_entry':'manifest_id,input_lake_object_id,logical_offset,logical_length',
  'ouf_udp.lake_shadow_rebuild_plan':'plan_id,tenant_id,tier,state,version,expected_object_count,verified_object_count,baseline_digest,shadow_digest,lease_until,lease_generation',
  'ouf_udp.lake_shadow_rebuild_entry':'plan_id,lake_object_id,source_locator,source_hash,source_size_bytes,shadow_locator,state,verified_generation',
  'ouf_udp.handoff_intake':'handoff_id,ingestion_run_id,ingestion_id,source_id,type_code,source_object_id,content_hash,receipt_ref,raw_lake_object_id,source_raw_lake_object_id,state',
  'ouf_udp.materialization_job':'job_id,handoff_id,state,attempts,lease_until,state_version',
  'ouf_udp.replay_plan':'replay_plan_id,tenant_id,source_handoff_id,raw_lake_object_id,replay_handoff_id,state,version,source_payload_hash',
  'ouf_udp.lake_maintenance_schedule':'task_name,state,next_run_at,lease_until,lease_generation',
 },
 'ingestion':{
  'ouf_ingestion.ing_run':'run_id,source_id,tenant_id,bundle_id,bundle_version,bundle_checksum,mode,phase,state',
  'ouf_ingestion.ing_partition':'run_id,partition_key,state,lock_version,lease_until,lease_generation',
  'ouf_ingestion.processing_attempt':'attempt_id,run_id,source_object_id,attempt_no,adapter_id,bundle_version,state',
  'ouf_ingestion.ing_lineage':'lineage_id,run_id,attempt_id,source_object_id,bundle_ref,adapter_ref',
  'ouf_ingestion.handoff_outbox':'handoff_id,run_id,lineage_id,idempotency_key,state,attempts,partition_key,sequence_no,downstream_receipt_ref,acked_at,lease_until',
  'ouf_ingestion.ing_watermark':'source_id,partition_key,committed_handoff_id,lock_version',
  'ouf_ingestion.checkpoint_history':'checkpoint_id,run_id,partition_key,sequence_no',
  'ouf_ingestion.runtime_configuration_snapshot':'snapshot_id,run_id,bundle_id,bundle_version,bundle_checksum',
  'ouf_ingestion.ing_quarantine':'quarantine_id,run_id,attempt_id,source_object_id,payload_ref,evidence_ref,state',
  'ouf_ingestion.replay_request':'replay_id,quarantine_id,target_bundle_ref,state',
  'ouf_ingestion.ing_schedule':'schedule_id,tenant_id,source_id,state,lease_until,next_run_at',
 }
}
TABLES['onboarding-retained']={k:v for k,v in TABLES['onboarding'].items() if k not in {'ouf_onboarding.managed_file_upload_intent','ouf_onboarding.managed_file_storage_control','ouf_onboarding.storage_recovery_authority_projection'}}
EXTRA={
 'ouf_ingestion.ing_partition':{'checkpoint_sha256':'checkpoint_json','committed_watermark_sha256':'committed_watermark_json'},
 'ouf_ingestion.ing_lineage':{'evidence_sha256':'evidence_json'},
 'ouf_ingestion.handoff_outbox':{'payload_sha256':'payload_json','candidate_watermark_sha256':'candidate_watermark_json'},
 'ouf_ingestion.ing_watermark':{'watermark_sha256':'watermark_json'},
 'ouf_ingestion.checkpoint_history':{'checkpoint_sha256':'checkpoint_json'},
 'ouf_ingestion.runtime_configuration_snapshot':{'snapshot_sha256':'snapshot_json'},
}
EXPRESSIONS={
 'ouf_ingestion.ing_lineage':{'raw_object_ref':"evidence_json->'data'->>'rawObjectRef'",'raw_hash':"evidence_json->'data'->>'rawHash'",'output_hash':"evidence_json->'data'->>'outputHash'"},
 'ouf_ingestion.handoff_outbox':{'raw_object_ref':"payload_json->>'rawObjectRef'",'payload_content_hash':"payload_json->>'contentHash'"},
 'ouf_ingestion.runtime_configuration_snapshot':{'binding_ref':"snapshot_json->>'bindingRef'",'staging_ref':"snapshot_json->'configuration'->>'stagingRef'",'asset_id_ref':"snapshot_json->'configuration'->>'assetId'"},
}
def columns(profile,table):return set(TABLES[profile][table].split(','))|set(EXTRA.get(table,{}))|set(EXPRESSIONS.get(table,{}))
def sql(profile):
 require(profile in TABLES,'G0_DB_PROFILE_REQUIRED')
 compatible="to_regclass('ouf_onboarding.managed_file_upload_intent') IS "+('NULL' if profile=='onboarding-retained' else 'NOT NULL') if profile.startswith('onboarding') else 'true'
 statements=["\\set ON_ERROR_STOP on","BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;","SET LOCAL search_path=pg_catalog;","SET LOCAL statement_timeout='5s';","SET LOCAL lock_timeout='1s';","SET LOCAL idle_in_transaction_session_timeout='15s';","SET LOCAL row_security=off;",
  "SELECT jsonb_build_object('kind','header','schema','ouf.storage-g0-db-export.v1','profile','"+profile+"','sourceSchemaCommit','"+SOURCES[profile]+"','database',current_database(),'databaseOid',(SELECT oid FROM pg_database WHERE datname=current_database()),'role',current_user,'serverAddress',inet_server_addr(),'serverPort',inet_server_port(),'postmasterStart',pg_postmaster_start_time(),'serverVersion',current_setting('server_version'),'snapshot',pg_current_snapshot()::text,'capturedAt',transaction_timestamp(),'readOnly',current_setting('transaction_read_only'),'isolation',current_setting('transaction_isolation'),'profileSchemaCompatible',"+compatible+");"]
 for table,fields in TABLES[profile].items():
  statements.append("SELECT jsonb_build_object('kind','section','table','"+table+"','tableOid',to_regclass('"+table+"')::oid,'columns',(SELECT jsonb_agg(jsonb_build_object('name',attname,'type',format_type(atttypid,atttypmod),'notNull',attnotnull) ORDER BY attnum) FROM pg_attribute WHERE attrelid=to_regclass('"+table+"') AND attnum>0 AND NOT attisdropped));")
  projection=fields
  for alias,column in EXTRA.get(table,{}).items():projection+=",encode(sha256(convert_to("+column+"::text,'UTF8')),'hex') AS "+alias
  for alias,expression in EXPRESSIONS.get(table,{}).items():projection+=","+expression+" AS "+alias
  # No offset pagination: bounded complete sections in one database snapshot.
  statements.append("SELECT jsonb_build_object('kind','row','table','"+table+"','value',to_jsonb(t)) FROM (SELECT "+projection+" FROM "+table+" ORDER BY "+fields.split(',')[0]+" LIMIT "+str(MAX_ROWS+1)+") t;")
 statements+=['COMMIT;',"SELECT jsonb_build_object('kind','footer','complete',true);"]
 return '\n'.join(statements)+'\n'
def parse_export(raw,profile):
 require(type(raw) is bytes and len(raw)<=MAX_BYTES,'G0_DB_EXPORT_BYTE_LIMIT')
 lines=raw.splitlines();require(lines and all(len(line)<=MAX_LINE for line in lines),'G0_DB_LINE_LIMIT')
 docs=[decode(line) for line in lines];require(len(docs)>=2 and all(type(d) is dict for d in docs),'G0_DB_TYPED_RECORDS')
 header=docs[0];require(header.get('kind')=='header' and header.get('schema')=='ouf.storage-g0-db-export.v1' and header.get('profile')==profile and header.get('sourceSchemaCommit')==SOURCES.get(profile),'G0_DB_EXACT_HEADER')
 require(header.get('readOnly')=='on' and header.get('isolation')=='repeatable read' and header.get('profileSchemaCompatible') is True and bool(header.get('snapshot')),'G0_DB_READ_ONLY_SNAPSHOT_PROFILE')
 require(docs[-1]=={'kind':'footer','complete':True},'G0_DB_COMMIT_FOOTER_REQUIRED')
 sections={};current=None
 for record in docs[1:-1]:
  table=record.get('table');require(table in TABLES[profile],'G0_DB_UNEXPECTED_TABLE')
  if record.get('kind')=='section':
   require(table not in sections and type(record.get('tableOid')) is int and type(record.get('columns')) is list and record['columns'],'G0_DB_EXACT_SECTION')
   sections[table]={'catalog':record,'rows':[]};current=table
  else:
   require(record.get('kind')=='row' and table==current and type(record.get('value')) is dict and set(record['value'])==columns(profile,table),'G0_DB_EXACT_PROJECTION')
   require(len(sections[table]['rows'])<MAX_ROWS,'G0_DB_ROW_LIMIT_NO_TRUNCATION');sections[table]['rows'].append(record['value'])
 require(set(sections)==set(TABLES[profile]),'G0_DB_COMPLETE_SECTION_SET')
 return {'header':header,'sections':sections,'rawSha256':sha(raw),'sqlSha256':sha(sql(profile).encode())}
def private_read(path,maximum):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  st=os.fstat(fd);require(stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode)==0o600 and st.st_uid==os.geteuid() and st.st_nlink==1 and 0<st.st_size<=maximum,'G0_DB_PRIVATE_INPUT')
  raw=os.read(fd,maximum+1);after=os.fstat(fd);require(len(raw)==st.st_size and (st.st_ino,st.st_mtime_ns,st.st_size)==(after.st_ino,after.st_mtime_ns,after.st_size),'G0_DB_STABLE_INPUT');return raw
 finally:os.close(fd)
def put_new(scope,name,raw):
 fd=os.open(scope/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  view=memoryview(raw)
  while view:n=os.write(fd,view);require(n>0,'G0_DB_EVIDENCE_WRITE');view=view[n:]
  os.fsync(fd)
 finally:os.close(fd)
 fd=os.open(scope,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
def ancestors(path):
 for p in [path,*path.parents]:
  st=p.lstat();require(stat.S_ISDIR(st.st_mode) and st.st_uid in (0,os.geteuid()) and (not st.st_mode&0o022 or st.st_mode&stat.S_ISVTX),'G0_DB_PROTECTED_ANCESTRY')
def export(config_path,scope):
 raw=private_read(config_path,16384);c=decode(raw)
 require(type(c) is dict and set(c)=={'schema','operationId','installationRef','profile','host','hostaddr','port','database','user','passwordFile','sslmode','rootCertificateFile'} and c['schema']=='ouf.storage-g0-db-input.v1','G0_DB_EXACT_INPUT')
 for key in ['operationId','installationRef','database','user']:require(type(c[key]) is str and re.fullmatch('[A-Za-z0-9_-]{1,128}',c[key]),'G0_DB_BOUND_IDENTITIES')
 require(c['profile'] in TABLES and scope.is_absolute() and str(scope)==os.path.normpath(scope) and scope.name==c['operationId'],'G0_DB_BOUND_NEW_SCOPE')
 address=ipaddress.ip_address(c['hostaddr']);require(address.version==4 and type(c['host']) is str and re.fullmatch('[A-Za-z0-9.-]{1,253}',c['host']) and type(c['port']) is int and 1<=c['port']<=65535,'G0_DB_SINGLE_BOUND_ENDPOINT')
 require(c['sslmode']=='verify-full' and bool(c['rootCertificateFile']) or c['sslmode']=='disable' and address.is_loopback and c['host']==c['hostaddr'] and c['rootCertificateFile']=='','G0_DB_TLS_OR_EXPLICIT_LOOPBACK')
 ancestors(scope.parent);scope.mkdir(mode=0o700);put_new(scope,'claim.private.json',canonical({'schema':'ouf.storage-g0-db-claim.v1','inputSha256':sha(raw),'operationId':c['operationId'],'installationRef':c['installationRef'],'profile':c['profile'],'sqlSha256':sha(sql(c['profile']).encode()),'maximumSeconds':MAX_SECONDS,'maximumBytes':MAX_BYTES,'maximumRowsPerSection':MAX_ROWS,'automaticReplayAllowed':False,'runtimeAuthorityIssued':False}))
 parent=os.open(scope.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(parent);os.close(parent)
 report={'schema':'ouf.storage-g0-db-summary.v1','status':'HELD','complete':False,'profile':c['profile'],'sections':0,'rows':0,'automaticReplayAllowed':False,'runtimeAuthorityIssued':False,'databaseWrites':0,'pointInTimeCommonCutProven':False}
 try:
  private_read(Path(c['passwordFile']),4096)
  if c['sslmode']=='verify-full':
   certificate=Path(c['rootCertificateFile']);st=certificate.lstat();require(stat.S_ISREG(st.st_mode) and st.st_size<=1<<20 and not st.st_mode&0o022,'G0_DB_EXPLICIT_ROOT_CERTIFICATE')
  psql=shutil.which('psql');require(psql is not None,'G0_DB_PSQL_UNAVAILABLE')
  env={'PATH':os.environ.get('PATH','/usr/bin:/bin'),'LC_ALL':'C','PGHOST':c['host'],'PGHOSTADDR':c['hostaddr'],'PGPORT':str(c['port']),'PGDATABASE':c['database'],'PGUSER':c['user'],'PGPASSFILE':c['passwordFile'],'PGSSLMODE':c['sslmode'],'PGCONNECT_TIMEOUT':'3','PGAPPNAME':'ouf-g0-read-only','PGGSSENCMODE':'disable'}
  if c['rootCertificateFile']:env['PGSSLROOTCERT']=c['rootCertificateFile']
  query=sql(c['profile']).encode();put_new(scope,'query.sql',query)
  proc=subprocess.Popen([psql,'-X','-q','-A','-t','-w','-v','ON_ERROR_STOP=1','-f',str(scope/'query.sql')],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  selector=selectors.DefaultSelector();selector.register(proc.stdout,selectors.EVENT_READ,'out');selector.register(proc.stderr,selectors.EVENT_READ,'err');out=bytearray();diagnostic=bytearray();until=time.monotonic()+MAX_SECONDS
  fd=os.open(scope/'export.partial.private.jsonl',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  try:
   while selector.get_map():
    require(time.monotonic()<until,'G0_DB_PROCESS_DEADLINE')
    for key,_ in selector.select(min(0.2,max(0,until-time.monotonic()))):
     chunk=os.read(key.fileobj.fileno(),65536)
     if not chunk:selector.unregister(key.fileobj);continue
     target=out if key.data=='out' else diagnostic;require(len(target)+len(chunk)<=(MAX_BYTES if key.data=='out' else 65536),'G0_DB_PROCESS_OUTPUT_LIMIT');target.extend(chunk)
     if key.data=='out':
      view=memoryview(chunk)
      while view:n=os.write(fd,view);require(n>0,'G0_DB_PARTIAL_WRITE');view=view[n:]
      os.fsync(fd)
   require(proc.wait(timeout=max(.1,until-time.monotonic()))==0,'G0_DB_QUERY_FAILED')
  finally:
   if proc.poll() is None:proc.kill()
   proc.wait(timeout=5);selector.close();proc.stdout.close();proc.stderr.close();os.close(fd)
  parsed=parse_export(bytes(out),c['profile']);put_new(scope,'export.private.jsonl',bytes(out));report.update(status='COMPLETE_READ_ONLY_EXPORT_NOT_COMMON_CUT',complete=True,sections=len(parsed['sections']),rows=sum(len(s['rows']) for s in parsed['sections'].values()),exportSha256=sha(bytes(out)),sqlSha256=parsed['sqlSha256'])
 except Exception as e:
  reason=str(e);report['reason']=reason if re.fullmatch('G0_DB_[A-Z0-9_]+',reason) else 'G0_DB_EXPORT_UNPROVEN'
 finally:put_new(scope,'summary.json',canonical(report))
 return report
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('config',type=Path);p.add_argument('scope',type=Path);a=p.parse_args()
 try:r=export(a.config,a.scope);print(json.dumps(r,sort_keys=True));raise SystemExit(0 if r['complete'] else 1)
 except (ValueError,OSError):print('{"status":"HELD","reason":"G0_DB_INPUT_OR_CONSUMED_SCOPE","complete":false}');raise SystemExit(1)
