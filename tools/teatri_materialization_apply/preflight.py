"""Read-only prerequisites for an exact retained receipt; never retries a job."""
import hashlib,json,os,re,selectors,shlex,stat,subprocess,tempfile,time
from pathlib import Path
from tools.teatri_materialization_apply.owner import require,digest,encoded
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

def jobs_query(tenant):
 t=literal(tenant)
 return """BEGIN READ ONLY; SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='3s';
 WITH selected AS (
 SELECT j.*,h.ingestion_run_id,h.source_id,h.type_code,h.source_object_id,h.state intake_state,h.payload_json,
 q.issue_id,q.state issue_state,q.tenant_id,q.resolved_at,q.resolved_by_subject,q.authorization_decision_ref issue_authorization,
 d.decision_id,d.action,d.actor_subject,d.authorization_decision_ref,d.decided_at,
 l.lake_object_id,l.access_label,l.state lake_state,l.tenant_id raw_tenant,l.source_id raw_source,l.type_code raw_type,l.tier raw_tier
 FROM ouf_udp.resolution_review_package_confirmation r
 JOIN ouf_udp.human_resolution_decision d ON d.actor_subject=r.actor_subject AND d.decided_at=r.confirmed_at AND d.authorization_decision_ref=r.authorization_decision_ref
 JOIN ouf_udp.resolution_issue q ON q.issue_id=d.issue_id AND q.tenant_id=r.tenant_id
 JOIN ouf_udp.handoff_intake h ON h.handoff_id=q.handoff_id
 JOIN ouf_udp.materialization_job j ON j.handoff_id=h.handoff_id
 LEFT JOIN ouf_udp.lake_object l ON l.lake_object_id=h.raw_lake_object_id
 WHERE r.package_id='a5183503-04ff-4e10-850f-e22bf874365e'AND r.tenant_id="""+t+"""
 AND r.actor_subject='b93d8cf6-cd14-4ee6-91d7-84cd76c4f500'AND h.source_id='teatri-csv-6609b245'AND d.action='CREATE_NEW')
 SELECT jsonb_build_object('database',current_database(),'databaseOid',(SELECT oid::bigint FROM pg_database WHERE datname=current_database()),'role',current_user,'transactionReadOnly',current_setting('transaction_read_only')='on',
 'confirmedJobCount',(SELECT count(*)FROM selected),'distinctContractSets',(SELECT count(DISTINCT payload_json->'contractRefs')FROM selected),
 'jobs',coalesce((SELECT jsonb_agg(jsonb_build_object('jobId',job_id,'jobVersion',state_version,'sourceId',source_id,'typeCode',type_code,'ingestionRunId',ingestion_run_id,'handoffId',handoff_id,'issueId',issue_id,'issueState',issue_state,'action',action,'state',state,'intakeState',intake_state,'safeFailureCode',safe_failure_code,'integrityAttempts',integrity_attempts,'baselinePresent',integrity_baseline_hash IS NOT NULL,'baselineHash',integrity_baseline_hash,
 'rawLakePresent',lake_object_id IS NOT NULL,'rawLakeState',lake_state,'rawAccessLabel',access_label,'rawLakeBindingMatches',raw_tenant=tenant_id AND raw_source=source_id AND raw_type=type_code AND raw_tier='RAW',
 'humanReceiptMatchesResolvedIssue',resolved_at=decided_at AND resolved_by_subject=actor_subject AND issue_authorization=authorization_decision_ref,
 'governedDecisionMatches',exists(SELECT 1 FROM ouf_udp.resolution_decision rd WHERE rd.handoff_id=s.handoff_id AND rd.strategy_id='GOVERNED_IDENTITY'AND rd.outcome='REVIEW_REQUIRED'AND rd.target_urban_object_id IS NULL),'latestHumanDecisionMatches',(SELECT hd.decision_id FROM ouf_udp.human_resolution_decision hd WHERE hd.issue_id=s.issue_id ORDER BY decided_at DESC,decision_id DESC LIMIT 1)=s.decision_id,
 'canonicalEffectsPresent',exists(SELECT 1 FROM ouf_udp.materialization_observation o WHERE o.handoff_id=s.handoff_id)OR exists(SELECT 1 FROM ouf_udp.object_revision r WHERE r.source_handoff_id=s.handoff_id)OR exists(SELECT 1 FROM ouf_udp.property_contribution p WHERE p.handoff_id=s.handoff_id)OR exists(SELECT 1 FROM ouf_udp.source_binding b WHERE b.first_handoff_id=s.handoff_id OR(b.source_id=s.source_id AND b.type_code=s.type_code AND b.source_object_id=s.source_object_id)),
 'leasePresent',claimed_by IS NOT NULL OR lease_until IS NOT NULL))FROM selected s),'[]'::jsonb));ROLLBACK;"""

def policy_query(tenant,subject):
 t=literal(tenant);h=literal(subject)
 return """BEGIN READ ONLY;SET LOCAL statement_timeout='10s';SET LOCAL lock_timeout='3s';
 WITH active AS(SELECT b.version,b.bundle_payload FROM ouf_authorization.active_policy_bundle a JOIN ouf_authorization.policy_bundle b ON b.bundle_id=a.bundle_id AND b.version=a.version WHERE a.singleton_key=true),selected AS(SELECT g FROM active a CROSS JOIN LATERAL jsonb_array_elements(a.bundle_payload->'grants')g WHERE g->>'tenantId'="""+t+""" AND g->>'capabilityId'IN('udp.materialization.retry','resolution.match.approve'))
 SELECT jsonb_build_object('database',current_database(),'databaseOid',(SELECT oid::bigint FROM pg_database WHERE datname=current_database()),'role',current_user,'transactionReadOnly',current_setting('transaction_read_only')='on','bundleCount',(SELECT count(*)FROM active),'bundleVersion',(SELECT version FROM active),
 'capabilities',coalesce((SELECT jsonb_agg(c)FROM active a CROSS JOIN LATERAL jsonb_array_elements(a.bundle_payload->'capabilities')c WHERE c->>'capabilityId'IN('udp.materialization.retry','resolution.match.approve')),'[]'::jsonb),
 'grants',coalesce((SELECT jsonb_agg(jsonb_build_object('capabilityId',g->>'capabilityId','subjectMatchesReviewedHuman',coalesce(g->>'subjectId','')=''OR g->>'subjectId'="""+h+""",'servicePrincipalRestricted',coalesce(g->>'servicePrincipalId','')<>'','organizationRestricted',coalesce(g->>'organizationId','')<>'','validAtRead',(g->>'validFrom')::timestamptz<=clock_timestamp()AND clock_timestamp()<(g->>'validUntil')::timestamptz,'constraints',g->'constraints'))FROM selected),'[]'::jsonb));ROLLBACK;"""

def sql_fact(prepared,ns,program,module,query):
 db=prepared['databasePlan'];admin=db['mcpAuditRoleAdministration']['admin'];binding=next(r for r in db['modules']if r['module']==module)
 for value in(admin,binding['database']):require(type(value)is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,62}',value),'EXACT_RETAINED_DATABASE_REQUIRED')
 pg=ns['engine_get'](prepared['engine'],'containers',db['postgresRuntimeBinding']['containerId'])
 require(pg is not None and pg['State']['Running']is True and pg['State']['Paused']is False and runtime_pin(pg)==db['postgresRuntimeBinding'],'CURRENT_REVIEWED_POSTGRES_REQUIRED')
 require([v.split('=',1)[1]for v in pg['Config'].get('Env',[])if v.startswith('POSTGRES_USER=')]==[admin],'EXACT_RETAINED_ADMINISTRATOR_REQUIRED')
 with tempfile.TemporaryDirectory(prefix='ouf-materialization-preflight-')as config:
  argv=[executable(program),'--host','unix://'+prepared['engine']['socketPath'],'--config',config,'exec',pg['Id'],'env','LC_ALL=C','PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=10000 -c lock_timeout=3000','timeout','-s','KILL','15','psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-U',admin,'-d',binding['database'],'-c',query]
  code,raw,err,_=bounded(argv,seconds=20,maximum=131072);require(code==0,'READ_ONLY_RECOVERY_PREFLIGHT_SQL_FAILED');fact=json.loads(raw)
 require(fact['database']==binding['database']and fact['databaseOid']==binding['databaseOid']and fact['role']==admin and fact['transactionReadOnly']is True,'EXACT_RECOVERY_PREFLIGHT_DATABASE_REQUIRED')
 require(runtime_pin(ns['engine_get'](prepared['engine'],'containers',pg['Id']))==db['postgresRuntimeBinding'],'POSTGRES_CHANGED_DURING_PREFLIGHT')
 return fact

def feature_metadata(actual):
 pid=actual['State']['Pid'];require(type(pid)is int and pid>1,'CURRENT_UDP_MAIN_PROCESS_REQUIRED')
 root=os.open('/proc/'+str(pid)+'/root',os.O_RDONLY|os.O_DIRECTORY)
 try:
  flag='ouf.udp.materialization-recovery.enabled'
  try:
   value,_,config_hash=configured_properties(actual,root,(flag,flag))
   require(value.lower()in('true','false'),'BOOLEAN_RECOVERY_FLAG_REQUIRED')
   return {'explicitFlagFound':True,'enabledInObservedConfiguration':value.lower()=='true','configFileSha256':config_hash,'effectiveConfigProven':False,'configurationValuesPrinted':False}
  except Exception as error:
   reason=str(error)if type(error).__name__ in ('ValueError','UpdateDenied') and re.fullmatch('[A-Z_]{1,160}',str(error))else type(error).__name__
   return {'explicitFlagFound':False,'enabledInObservedConfiguration':None,'reason':reason,'effectiveConfigProven':False,'configurationValuesPrinted':False}
 finally:os.close(root)

def collect(prepared,ns,program,actual,case,read):
 selection=prepared['authorization']['plan']['selection'];tenant=selection['tenant'];subject=selection['subject']
 require(tenant=='ouf-lab'and subject=='b93d8cf6-cd14-4ee6-91d7-84cd76c4f500','EXACT_REVIEWED_OPERATOR_REQUIRED')
 jobs=sql_fact(prepared,ns,program,'udp',jobs_query(tenant));policy=sql_fact(prepared,ns,program,'onboarding',policy_query(tenant,subject))
 require(jobs['confirmedJobCount']==11 and jobs['distinctContractSets']==1 and len(jobs['jobs'])==11 and policy['bundleCount']==1,'EXACT_ELEVEN_CONFIRMED_JOBS_REQUIRED')
 current=read(case['currentHumanReview']['path'],8388608,case['currentHumanReview']['sha256']);hb=current['authenticatedHuman']
 directory=Path(hb['sessionDirectory']);require(directory.parent==Path('/etc/ouf/deploy-snapshots/semantic-token-execution-usx0tsem')and all(hb[k]==selection[k]for k in('issuer','tenant','subject')),'EXACT_CURRENT_HUMAN_METADATA_REQUIRED')
 row=read(directory/'recovery.json',65536)
 require(row['binding']==hb and row.get('budgetReset')is False and type(row.get('attempts'))is int and 124<=row['attempts']<=256 and hb['retryProfile']['maximumAttempts']==256,'EXACT_PRESERVED_TEST_OAUTH_BUDGET_REQUIRED')
 require(row['state']in('NEW','DEVICE_START','DEVICE_POLL','REQUESTING','RETRY_WAIT','VERIFYING','READY','BLOCKED'),'SAFE_HUMAN_STATE_REQUIRED')
 human={'state':row['state'],'attempts':row['attempts'],'maximumCumulativeOAuthAttempts':256,'remainingOAuthAttempts':256-row['attempts'],'expiredAtRead':time.time()>=hb['expiresAt'],'expiresAt':hb['expiresAt'],'credentialValuesPrinted':False}
 worker=current['scopes']['policyTokenFiniteWorkerSession'];journal=Path(worker['fenceBinding']['value']['journalPath']);records={n:read(journal/n,131072)for n in('recovery.json','owner-session.json','owner-admission.json','owner-status.json')}
 recovery=records['recovery.json'];require(records['owner-session.json']==worker and recovery['workerSessionHash']==digest(worker)and recovery['controlledPredecessorGrantAttempts']==308 and type(recovery['attempts'])is int and 0<=recovery['attempts']<=8 and recovery['controlledCumulativeGrantAttempts']==308+recovery['attempts']<=316,'EXACT_CURRENT_RESTORATION_HISTORY_REQUIRED')
 require(recovery['state']in('ACTIVE','CANCELLED','NEW','RETRY_WAIT','ATTEMPTING','PUBLISHING','PAUSED_EXHAUSTED','BLOCKED','RECONCILE_REQUIRED'),'SAFE_WORKER_STATE_REQUIRED')
 reason=recovery.get('reason');require(reason is None or re.fullmatch('[A-Z_]{1,100}',reason),'SAFE_WORKER_REASON_REQUIRED')
 history={'state':recovery['state'],'reason':reason,'attempts':recovery['attempts'],'priorControlledGrantAttempts':308,'controlledCumulativeGrantAttempts':308+recovery['attempts'],'maximumCumulativeGrantAttempts':316,'remainingControlledGrantAttempts':8-recovery['attempts'],'recordHashes':{n:digest(v)for n,v in records.items()},'journalPath':str(journal),'budgetReset':False}
 require(read(directory/'recovery.json',65536)==row and all(read(journal/n,131072)==r for n,r in records.items()),'PREFLIGHT_HISTORY_CHANGED_DURING_READ')
 return {'jobs':jobs,'publishedRecoveryPolicyMetadata':policy,'recoveryEndpointConfiguration':feature_metadata(actual),'humanBudget':human,'workerHistory':history,'loadedOwnerPolicySnapshotProven':False,'credentialBearingJournalsRead':1,'tokenFilesRead':0,'grantRequests':0,'databaseMutations':0}
