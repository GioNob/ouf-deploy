#!/usr/bin/env python3
"""Installation-specific post-rollout read; source is the existing test fixture only.

No tokens, profile publication, scheduler activation, grants or database writes.
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
 print(json.dumps(dict(schema='ouf.linked-property-post-rollout-profile-read.v1',check=check,readOnly=True,
  automaticRetry=False,budgetReset=False,credentialFilesRead=0,credentialValuesPrinted=False,
  databaseMutations=0,grantRequests=0,oauthRequests=0,serviceMutations=0,profilePublications=0,
  jobsRetried=0,completedTechnicalPhases=8,functionalMilestonesProven=2,installationSpecific=True,**values),sort_keys=True),flush=True)

def application_pin(actual):
 value=runtime_pin(actual);value['mountsHash']=digest(sorted(actual['Mounts'],key=lambda m:m['Destination']));return value

def query(module,tenant,subject):
 require(module in('udp','onboarding'),'EXACT_MODULE_REQUIRED')
 schema='ouf_'+module
 common="""'database',current_database(),'databaseOid',(select oid::bigint from pg_database where datname=current_database()),
 'role',current_user,'transactionReadOnly',current_setting('transaction_read_only')='on',
 'migrations',(select jsonb_agg(x order by installed_rank) from (select installed_rank,version,script,checksum,success from SCHEMA.flyway_schema_history order by installed_rank limit 100)x)""".replace('SCHEMA',schema)
 if module=='udp':
  select="select jsonb_build_object("+common+""",
   'profileTablePresent',to_regclass('ouf_udp.handoff_property_profile') is not null,
   'evidenceColumnPresent',exists(select 1 from information_schema.columns where table_schema='ouf_udp' and table_name='property_value' and column_name='reconciliation_evidence'))"""
 else:
  select="""with selected as (
   select p.*,v.state version_state,v.configuration_hash,v.configuration,s.source_kind,s.acquisition_mode
   from ouf_onboarding.published_configuration p
   join ouf_onboarding.onboarding_version v using(onboarding_version_id,source_id)
   join ouf_onboarding.source s using(source_id)
   where p.source_id="""+literal(SOURCE)+""" and p.active=true limit 2
  ), projected as (
   select jsonb_build_object('sourceId',p.source_id,'onboardingVersionId',p.onboarding_version_id,
    'publicationId',p.publication_id,'publicationSequence',p.bundle_version,'publicationChecksum',p.checksum,
    'versionState',p.version_state,'configurationHash',p.configuration_hash,
    'selectedVersionMatches',p.onboarding_version_id="""+literal(VERSION)+"""::uuid,
    'sourceKind',p.source_kind,'acquisitionMode',p.acquisition_mode,
    'ownedReviewMatches',exists(select 1 from ouf_onboarding.managed_onboarding_review r
      where r.onboarding_version_id=p.onboarding_version_id and r.source_id=p.source_id
      and r.tenant_id="""+literal(tenant)+""" and r.subject_id="""+literal(subject)+"""),
    'profileMatchesApprovedConfiguration',p.bundle#>'{extractionProfile,runtime,udp,materialization}'=p.configuration#>'{extractionProfile,runtime,udp,materialization}',
    'materializationPolicyRef',p.bundle#>>'{extractionProfile,runtime,udp,materialization,policyRef}',
    'bitemporalProperties',p.bundle#>'{extractionProfile,runtime,udp,materialization,bitemporalProperties}',
    'geometryField',p.bundle#>>'{extractionProfile,runtime,udp,spatial,geometry,sourceField}',
    'changeMode',coalesce(p.configuration#>>'{changeRepresentationProfile,mode}',p.bundle#>>'{changeRepresentationProfile,mode}'),
    'incrementalMode',p.configuration#>>'{syncProfile,incremental}',
    'triggerOnce',p.bundle->'triggerOnce',
    'pollInterval',p.configuration#>>'{syncProfile,pollInterval}',
    'propertyCount',jsonb_array_length(p.bundle#>'{extractionProfile,runtime,udp,materialization,properties}'),
    'properties',coalesce((select jsonb_agg(jsonb_build_object(
      'propertyIri',r->>'propertyIri','sourceField',r->>'sourceField','datatype',r->>'datatype',
      'accessLabel',r->>'accessLabel','authorityOrder',r->'authorityOrder','reconciliation',r->'reconciliation') order by r->>'propertyIri')
      from (select r from jsonb_array_elements(p.bundle#>'{extractionProfile,runtime,udp,materialization,properties}')r limit 256)limited),'[]'::jsonb)
   ) row from selected p
  ) select jsonb_build_object("""+common+""",'activePublicationCount',(select count(*)from selected),
    'publications',coalesce((select jsonb_agg(row)from projected),'[]'::jsonb))"""
 return "BEGIN READ ONLY; SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='3s'; "+select+"; ROLLBACK;"

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
  for module in('udp','onboarding'):
   binding=next(r for r in db['modules']if r['module']==module)
   for v in(admin,binding['database']):require(type(v)is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,62}',v),'EXACT_DATABASE_ROLE_REQUIRED')
   argv=[executable(old['sourceClosure']['executables']['docker']),'--host','unix://'+prepared['engine']['socketPath'],'--config',config,'exec',pg['Id'],'env','LC_ALL=C',
    'PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=10000 -c lock_timeout=3000','timeout','-s','KILL','15','psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1',
    '-U',admin,'-d',binding['database'],'-c',query(module,selection['tenant'],selection['subject'])]
   code,raw,err,_=bounded(argv,seconds=20,maximum=524288);require(code==0,'READ_ONLY_PROFILE_SQL_FAILED');facts=json.loads(raw)
   require(facts['database']==binding['database']and facts['databaseOid']==binding['databaseOid']and facts['role']==admin and facts['transactionReadOnly']is True,'EXACT_DATABASE_FACTS_REQUIRED')
   validate_history(facts,plan['database']['expected'][module]);results[module]=facts
   if module=='udp':
    require(facts['profileTablePresent']and facts['evidenceColumnPresent']and facts['migrations'][-1]['version']=='35','V35_SCHEMA_UNPROVEN')
    emit('UDP_MIGRATION_READBACK',version=35,checksum=facts['migrations'][-1]['checksum'],migrationHistoryMatches=True,profileTablePresent=True,evidenceColumnPresent=True)
   else:
    require(facts['activePublicationCount']==len(facts['publications'])==1,'ONE_ACTIVE_SOURCE_PUBLICATION_REQUIRED')
    profile=facts['publications'][0]
    require(profile['selectedVersionMatches']and profile['ownedReviewMatches']and profile['profileMatchesApprovedConfiguration']
     and 0<profile['propertyCount']==len(profile['properties'])<=256,'EXACT_OWNED_SOURCE_PROFILE_REQUIRED')
    emit('PUBLISHED_PROFILE_METADATA',profile=profile,propertyValuesPrinted=False,rawConfigurationPrinted=False)
 require(runtime_pin(ns['engine_get'](prepared['engine'],'containers',pg['Id']))==db['postgresRuntimeBinding'],'POSTGRES_GENERATION_CHANGED_DURING_READ')
 applications();require(ns['read'](CONTEXT/'recovery.json',131072)==record,'ROLLOUT_RECORD_CHANGED')
 emit('END',complete=True,udpMigrationVersion=35,readbackProven=True,profileActivationProven=False,runtimeAuthorityIssued=False)
if __name__=='__main__':
 emit('BEGIN',maximumSeconds=65,maximumEngineReads=6,maximumSqlSessions=2,maximumProperties=256)
 try:main()
 except Exception as error:
  reason=str(error)if type(error)is ValueError and re.fullmatch('[A-Z_]+',str(error))else type(error).__name__
  emit('STOP',reason=reason,exceptionMessagePrinted=False)
  raise SystemExit(2)
