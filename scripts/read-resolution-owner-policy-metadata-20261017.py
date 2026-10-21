#!/usr/bin/env python3
"""Retained-host, zero-token read-only owner-policy and readiness diagnosis."""
import hashlib,http.client,json,os,re,selectors,signal,socket,stat,subprocess,sys,tempfile,time
from pathlib import Path
from urllib.parse import quote
BOOT=Path('/etc/ouf/deploy-snapshots/semantic-mcp-update-executor-code-yrvtskkt/execute.py')
BOOT_HASH='b02d9737af6d143903910654d34e91a1a82a52b6082d2429d5dbfd070d160af2'
CONTEXT=Path('/etc/ouf/deploy-snapshots/resolution-config-execution-q91d2ut7')
def require(ok,code):
 if not ok:raise ValueError(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(v):return hashlib.sha256(encoded(v)).hexdigest()
def emit(check,**values):
 print(json.dumps(dict(schema='ouf.resolution-owner-policy-metadata-read.v1',check=check,readOnly=True,
  automaticRetry=False,budgetReset=False,credentialFilesRead=0,credentialValuesPrinted=False,
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

def query(tenant,subject):
 t=literal(tenant);h=literal(subject);caps="'resolution.issue.read','resolution.match.approve'"
 return """BEGIN READ ONLY; SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='3s';
 WITH active AS (
 SELECT b.bundle_id,b.version,b.bundle_payload FROM ouf_authorization.active_policy_bundle a
 JOIN ouf_authorization.policy_bundle b ON b.bundle_id=a.bundle_id AND b.version=a.version WHERE a.singleton_key=true
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
 'capabilityId',g->>'capabilityId','servicePrincipalRestricted',coalesce(g->>'servicePrincipalId','')<>'',
 'subjectRestricted',coalesce(g->>'subjectId','')<>'','subjectMatchesReviewedHuman',coalesce(g->>'subjectId','')=''OR g->>'subjectId'="""+h+""",
 'validAtRead',(g->>'validFrom')::timestamptz<=clock_timestamp()AND clock_timestamp()<(g->>'validUntil')::timestamptz,
 'organizationRestricted',coalesce(g->>'organizationId','')<>'',
 'resourceTypeMatchesDefaultCapability',coalesce(g->'constraints'->>'resourceType','')IN('','capability'),
 'resourceTypeMatchesResolutionIssues',coalesce(g->'constraints'->>'resourceType','')IN('','resolution-issues'),
 'resourceAttributesMatchEmpty',coalesce(g->'constraints'->'resourceAttributes','{}'::jsonb)IN('null'::jsonb,'{}'::jsonb),
 'constraints',g->'constraints')) FROM selected),'[]'::jsonb)
 );ROLLBACK;"""


def main():
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_READ_REQUIRED')
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('READ_DEADLINE')));signal.alarm(40)
 fd=os.open(BOOT,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(fd);require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and 0<s.st_size<=131072,'RETAINED_HELPER_CUSTODY_REQUIRED')
  raw=os.read(fd,131073);require(len(raw)==s.st_size and hashlib.sha256(raw).hexdigest()==BOOT_HASH,'RETAINED_HELPER_HASH_CHANGED')
 finally:os.close(fd)
 ns={'__name__':'resolution_owner_policy_metadata'};exec(compile(raw,'<verified-retained-read-helpers>','exec'),ns)
 old=ns['read'](ns['CONTEXT']/'review.json',8388608,ns['REVIEW']);link=old['scopes']['finiteActionProcess']['bundle']
 prepared=ns['read'](link['path'],8388608,link['sha256'])['prepared']
 require(digest(prepared)==old['privateInputHashes']['preparedInputs'],'PREPARED_INPUT_BINDING_CHANGED')
 review=ns['read'](CONTEXT/'review.json',8388608);require(review['kind']=='RESOLUTION_THS_CONFIGURATION'and review['sourceClosure']['declaration']['sourceCommit']=='d830edbcdbf41c495672833b86aa698546e215a6','EXACT_QUALIFIED_RESOLUTION_SOURCE_REQUIRED');plan=ns['read'](CONTEXT/'execution-plan.json',8388608);record=ns['read'](CONTEXT/'recovery.json',65536)
 require(digest(plan)==review['scopes']['resolutionConfigurationUpdate']['planHash']and record['scopeHash']==digest(review['scopes']['resolutionConfigurationUpdate'])and record['version']==37 and record['incidentState']=='RECOVERED'and record['nextStage']==len(record['effects'])==len(review['scopes']['resolutionConfigurationUpdate']['stages'])==13 and all(e['state']=='APPLIED'for e in record['effects']),'COMPLETE_CURRENT_RESOLUTION_ROLLOUT_REQUIRED')
 app=ns['engine_get'](prepared['engine'],'containers',plan['replacements']['onboarding']['name'])
 require(ns['runtime_pin'](app)==record['effects'][-1]['evidence']['applications']['onboarding']['runtimeBinding'],'CURRENT_RESOLUTION_FRONTEND_GENERATION_CHANGED')
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
 require(facts['database']==binding['database']and facts['databaseOid']==binding['databaseOid']and facts['role']==admin and facts['transactionReadOnly']is True and facts['bundleCount']==1 and len(facts['capabilities'])<=2 and len(facts['grants'])<=32,'EXACT_BOUNDED_OWNER_FACTS_REQUIRED')
 require(runtime_pin(ns['engine_get'](prepared['engine'],'containers',pg['Id']))==db['postgresRuntimeBinding'],'POSTGRES_GENERATION_CHANGED_DURING_READ')
 emit('RESOLUTION_OWNER_POLICY_METADATA',facts=facts,rawSqlOutputPrinted=False,tokenExpiryIndependent=True)
 require(ns['runtime_pin'](ns['engine_get'](prepared['engine'],'containers',app['Id']))==record['effects'][-1]['evidence']['applications']['onboarding']['runtimeBinding'] and ns['read'](CONTEXT/'recovery.json',65536)==record,'ONBOARDING_CHANGED_DURING_READ')
 emit('END',complete=True,reconciliationPerformed=False,runtimeAuthorityIssued=False)
if __name__=='__main__':
 emit('BEGIN',maximumSeconds=40,maximumEngineReads=4,maximumSqlSessions=1)
 try:main()
 except Exception as error:
  reason=str(error)if type(error)is ValueError and re.fullmatch('[A-Z_]+',str(error))else type(error).__name__
  emit('STOP',reason=reason,exceptionMessagePrinted=False)
