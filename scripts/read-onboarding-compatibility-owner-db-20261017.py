#!/usr/bin/env python3
"""Retained-host, zero-token read-only owner-policy and readiness diagnosis."""
import hashlib,http.client,json,os,re,selectors,signal,socket,stat,subprocess,sys,tempfile,time
from pathlib import Path
from urllib.parse import quote
BOOT=Path('/etc/ouf/deploy-snapshots/semantic-mcp-update-executor-code-yrvtskkt/execute.py')
BOOT_HASH='b02d9737af6d143903910654d34e91a1a82a52b6082d2429d5dbfd070d160af2'
CONTEXT=Path('/etc/ouf/deploy-snapshots/onboarding-audit-execution-i220f2c0')
REVIEW='21ca88f1c5aa682eb74612ead95c9bc6154ddf79a18a52af8f5d281e32abc605'
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
 print(json.dumps(dict(schema='ouf.onboarding-compatibility-owner-db-read.v1',check=check,readOnly=True,
  automaticRetry=False,budgetReset=False,credentialFilesRead=0,credentialValuesPrinted=False,
  databaseMutations=0,grantRequests=0,readinessCalls=0,serviceMutations=0,
  completedTechnicalPhases=8,functionalMilestonesProven=1,**values),sort_keys=True),flush=True)

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

def query(tenant,subject):
 t=literal(tenant);h=literal(subject)
 caps="'ouf.onboarding.configuration.read','ouf.ingestion.configuration.attest','ouf.onboarding.configuration.write'"
 return """BEGIN READ ONLY; SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='3s';
 WITH active AS (
  SELECT b.bundle_id,b.version,b.bundle_payload FROM ouf_authorization.active_policy_bundle a
  JOIN ouf_authorization.policy_bundle b ON b.bundle_id=a.bundle_id AND b.version=a.version
  WHERE a.singleton_key=true
 ), selected AS (
  SELECT g FROM active a CROSS JOIN LATERAL jsonb_array_elements(a.bundle_payload->'grants') g
  WHERE g->>'capabilityId' IN ("""+caps+""") AND g->>'tenantId'="""+t+"""
 )
 SELECT jsonb_build_object(
  'database',current_database(),'databaseOid',(SELECT oid::bigint FROM pg_database WHERE datname=current_database()),
  'role',current_user,'transactionReadOnly',current_setting('transaction_read_only')='on',
  'bundleCount',(SELECT count(*) FROM active),'bundleVersion',(SELECT version FROM active),
  'capabilities',coalesce((SELECT jsonb_agg(c) FROM active a CROSS JOIN LATERAL jsonb_array_elements(a.bundle_payload->'capabilities') c WHERE c->>'capabilityId' IN ("""+caps+""")),'[]'::jsonb),
  'grants',coalesce((SELECT jsonb_agg(jsonb_build_object(
   'capabilityId',g->>'capabilityId','servicePrincipalId',g->>'servicePrincipalId',
   'subjectRestricted',coalesce(g->>'subjectId','')<>'',
   'subjectMatchesReviewedHuman',coalesce(g->>'subjectId','')='' OR g->>'subjectId'="""+h+""",
   'validAtRead',(g->>'validFrom')::timestamptz<=clock_timestamp() AND clock_timestamp()<(g->>'validUntil')::timestamptz,
   'organizationRestricted',coalesce(g->>'organizationId','')<>'',
   'constraints',g->'constraints')) FROM selected),'[]'::jsonb),
  'review',coalesce((SELECT jsonb_agg(jsonb_build_object(
   'sourceMatches',source_id="""+literal(SOURCE)+""",'versionMatches',onboarding_version_id="""+literal(VERSION)+"""::uuid,
   'tenantMatches',tenant_id="""+t+""",'configurationHashMatches',configuration_hash="""+literal(CONFIG_HASH)+""",
   'readinessPhase',readiness_phase,'readinessAttempts',readiness_attempts,'readinessGeneration',readiness_generation,
   'lastCode',readiness_last_code,'leaseActive',readiness_lease_until>clock_timestamp(),
   'sourceState',(SELECT state FROM ouf_onboarding.onboarding_version v WHERE v.onboarding_version_id=r.onboarding_version_id),
   'challengeState',(SELECT status FROM ouf_onboarding.approval_challenge c WHERE c.challenge_id=r.challenge_id),
   'compatibilityCount',(SELECT count(*) FROM ouf_onboarding.consumer_compatibility_attestation c WHERE c.onboarding_version_id=r.onboarding_version_id AND c.configuration_hash=r.configuration_hash AND c.consumer='INGESTION_RUNTIME')
  )) FROM ouf_onboarding.managed_onboarding_review r WHERE challenge_id="""+literal(CHALLENGE)+"""::uuid),'[]'::jsonb)
 );ROLLBACK;"""


def main():
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_READ_REQUIRED')
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('READ_DEADLINE')));signal.alarm(40)
 fd=os.open(BOOT,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(fd);require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and 0<s.st_size<=131072,'RETAINED_HELPER_CUSTODY_REQUIRED')
  raw=os.read(fd,131073);require(len(raw)==s.st_size and hashlib.sha256(raw).hexdigest()==BOOT_HASH,'RETAINED_HELPER_HASH_CHANGED')
 finally:os.close(fd)
 ns={'__name__':'compatibility_owner_db_metadata'};exec(compile(raw,'<verified-retained-read-helpers>','exec'),ns)
 old=ns['read'](ns['CONTEXT']/'review.json',8388608,ns['REVIEW']);link=old['scopes']['finiteActionProcess']['bundle']
 prepared=ns['read'](link['path'],8388608,link['sha256'])['prepared']
 require(digest(prepared)==old['privateInputHashes']['preparedInputs'],'PREPARED_INPUT_BINDING_CHANGED')
 review=ns['read'](CONTEXT/'review.json',8388608,REVIEW);plan=ns['read'](CONTEXT/'execution-plan.json',8388608);record=ns['read'](CONTEXT/'recovery.json',65536)
 require(digest(plan)==review['scopes']['onboardingAuditUpdate']['planHash']and record['scopeHash']==digest(review['scopes']['onboardingAuditUpdate'])and record['version']==29 and record['incidentState']=='RECOVERED'and record['nextStage']==len(record['effects'])==len(review['scopes']['onboardingAuditUpdate']['stages'])==11 and all(e['state']=='APPLIED'for e in record['effects']),'COMPLETE_CURRENT_ONBOARDING_FIX_REQUIRED')
 app=ns['engine_get'](prepared['engine'],'containers',plan['replacements']['onboarding']['name'])
 require(ns['runtime_pin'](app)==record['effects'][-1]['evidence']['applications']['onboarding']['runtimeBinding'],'CURRENT_ONBOARDING_GENERATION_CHANGED')
 db=prepared['databasePlan'];binding=next(r for r in db['modules']if r['module']=='onboarding')
 admin=db['mcpAuditRoleAdministration']['admin'];pg=ns['engine_get'](prepared['engine'],'containers',db['postgresRuntimeBinding']['containerId'])
 require(pg is not None and pg['State']['Running']is True and pg['State']['Paused']is False and runtime_pin(pg)==db['postgresRuntimeBinding'],'EXACT_POSTGRES_GENERATION_REQUIRED')
 require([v.split('=',1)[1]for v in pg['Config'].get('Env',[])if v.startswith('POSTGRES_USER=')]==[admin],'EXISTING_ADMINISTRATOR_BINDING_REQUIRED')
 for value in(admin,binding['database']):require(type(value)is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,62}',value),'EXACT_DATABASE_ROLE_REQUIRED')
 selection=prepared['authorization']['plan']['selection']
 with tempfile.TemporaryDirectory(prefix='ouf-compatibility-db-read-')as config:
  argv=[executable(old['sourceClosure']['executables']['docker']),'--host','unix://'+prepared['engine']['socketPath'],'--config',config,'exec',pg['Id'],'env','LC_ALL=C',
   'PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=10000 -c lock_timeout=3000','timeout','-s','KILL','15','psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-U',admin,'-d',binding['database'],'-c',query(selection['tenant'],selection['subject'])]
  code,raw,err,_=bounded(argv,seconds=20,maximum=65536);require(code==0,'READ_ONLY_OWNER_POLICY_SQL_FAILED');facts=json.loads(raw)
 require(facts['database']==binding['database']and facts['databaseOid']==binding['databaseOid']and facts['role']==admin and facts['transactionReadOnly']is True and facts['bundleCount']==1 and len(facts['review'])==1 and len(facts['capabilities'])<=3 and len(facts['grants'])<=32,'EXACT_BOUNDED_OWNER_FACTS_REQUIRED')
 require(runtime_pin(ns['engine_get'](prepared['engine'],'containers',pg['Id']))==db['postgresRuntimeBinding'],'POSTGRES_GENERATION_CHANGED_DURING_READ')
 emit('OWNER_POLICY_AND_READINESS',facts=facts,rawSqlOutputPrinted=False,tokenExpiryIndependent=True)
 policy_review=ns['read'](POLICY_CONTEXT/'review.json',8388608,POLICY_REVIEW);scope=policy_review['scopes']['policyTokenFiniteWorkerSession']
 worker=ns['read'](Path(scope['fenceBinding']['value']['journalPath'])/'recovery.json',65536)
 require(worker['workerSessionHash']==digest(scope)and worker['controlledCumulativeGrantAttempts']==worker['controlledPredecessorGrantAttempts']+worker['attempts'],'CONTROLLED_WORKER_HISTORY_CHANGED')
 policy_authority=ns['read'](POLICY_CONTEXT/'authority.json',131072,'eec4345a68d09686909653238e5b0f9104b77f091f74084039a8f1666b01e39c')
 emit('POLICY_WORKER_METADATA',state=worker['state'],reason=worker['reason'],attempts=worker['attempts'],publications=worker['publicationCount'],controlledCumulativeGrantAttempts=worker['controlledCumulativeGrantAttempts'],maximumCumulativeGrantAttempts=scope['maximumCumulativeGrantAttempts'],workerSessionExpiredAtRead=time.time()>=policy_authority['expiresAt'],automaticRestart=False)
 require(ns['runtime_pin'](ns['engine_get'](prepared['engine'],'containers',app['Id']))==record['effects'][-1]['evidence']['applications']['onboarding']['runtimeBinding'] and ns['read'](CONTEXT/'recovery.json',65536)==record,'ONBOARDING_CHANGED_DURING_READ')
 emit('END',complete=True,reconciliationPerformed=False,runtimeAuthorityIssued=False)
if __name__=='__main__':
 emit('BEGIN',maximumSeconds=40,maximumEngineReads=4,maximumSqlSessions=1)
 try:main()
 except Exception as error:
  reason=str(error)if type(error)is ValueError and re.fullmatch('[A-Z_]+',str(error))else type(error).__name__
  emit('STOP',reason=reason,exceptionMessagePrinted=False)
