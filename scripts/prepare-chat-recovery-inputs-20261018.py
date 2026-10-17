#!/usr/bin/env python3
"""Installation-specific post-rollout read; source is the existing test fixture only.

No tokens, profile publication, scheduler activation, grants or database writes.
"""
import hashlib,http.client,json,os,re,selectors,signal,socket,stat,subprocess,sys,tempfile,time
from pathlib import Path
BOOT=Path('/etc/ouf/deploy-snapshots/semantic-mcp-update-executor-code-yrvtskkt/execute.py')
BOOT_HASH='b02d9737af6d143903910654d34e91a1a82a52b6082d2429d5dbfd070d160af2'
CONTEXT=Path('/etc/ouf/deploy-snapshots/linked-property-execution-cjecd1en')
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
 print(json.dumps(dict(schema='ouf.chat-recovery-private-preparation.v1',check=check,readOnly=True,
  automaticRetry=False,budgetReset=False,credentialFilesRead=0,credentialValuesPrinted=False,
  databaseMutations=0,grantRequests=0,oauthRequests=0,serviceMutations=0,profilePublications=0,
  jobsRetried=0,completedTechnicalPhases=8,functionalMilestonesProven=3,installationSpecific=True,**values),sort_keys=True),flush=True)

def application_pin(actual):
 value=runtime_pin(actual);value['mountsHash']=digest(sorted(actual['Mounts'],key=lambda m:m['Destination']));return value

def validate_history(facts,expected):
 rows=facts['migrations'];actual=[r for r in rows if r['version']is not None]
 require(len(rows)in(len(expected),len(expected)+1)and len(actual)==len(expected),'EXACT_MIGRATION_COUNT_REQUIRED')
 for found,wanted in zip(actual,expected):
  require(all(found[k]==wanted[k]for k in('version','script','checksum','success')),'INSTALLED_MIGRATION_HISTORY_CHANGED')


def validate_database(module, facts, profile):
 require(facts['transactionReadOnly'] is True,'READ_ONLY_DATABASE_REQUIRED')
 if module=='udp':
  expected=profile['udpMigrations'][:-1]
  validate_history(facts,expected)
  require(len(expected)==35 and profile['udpMigrations'][-1]['version']=='36','EXACT_V35_V36_REQUIRED')
  require(facts['ownsMaterializationJob'] is True and facts['recoveryColumnCount']==0,'V36_PREFLIGHT_UNPROVEN')
 else:
  require(facts['migrations']==profile['mcpMigrations'],'EXACT_MCP_HISTORY_REQUIRED')

def sql(module, app):
 require(re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,62}',app) is not None,'EXACT_APPLICATION_ROLE_REQUIRED')
 common="'database',current_database(),'role',current_user,'transactionReadOnly',current_setting('transaction_read_only')='on','databaseOid',(select oid::bigint from pg_database where datname=current_database()),'databaseBytes',pg_database_size(current_database())"
 if module=='udp':
  fields=f"""'migrations',(select jsonb_agg(x order by installed_rank) from
   (select installed_rank,version,script,checksum,success from ouf_udp.flyway_schema_history order by installed_rank limit 100)x),
   'ownsMaterializationJob',(select pg_get_userbyid(relowner)='{app}' from pg_class where oid='ouf_udp.materialization_job'::regclass),
   'recoveryColumnCount',(select count(*) from information_schema.columns where table_schema='ouf_udp' and table_name='materialization_job'
    and column_name in('dependency_episode_id','dependency_started_at','dependency_attempts','dependency_cumulative_attempts'))"""
 else:
  fields="'migrations',(select jsonb_agg(x order by version) from (select version,checksum::text from ouf_mcp.schema_migration order by version limit 100)x)"
 return "BEGIN READ ONLY; SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='3s'; SELECT jsonb_build_object("+common+","+fields+"); ROLLBACK;"

def root_dir(path):
 require(path.is_absolute() and path.resolve()==path,'EXACT_ROOT_DIRECTORY_REQUIRED')
 for p in(path,*path.parents):
  s=p.lstat();require(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,'ROOT_DIRECTORY_CUSTODY_REQUIRED')

def private_write(path, raw):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  with os.fdopen(os.dup(fd),'wb')as out:out.write(raw);out.flush();os.fsync(out.fileno())
 finally:os.close(fd)

PROFILE=json.loads("{\"schema\":\"ouf.chat-recovery-private-preparation-profile.v1\",\"installationSpecific\":true,\"privateParent\":\"/etc/ouf/deploy-snapshots\",\"packageDirectory\":\"/home/oufadmin/ouf-deploy-runner/_work/ouf-deploy/ouf-chat-recovery-39079129729\",\"manifestSha256\":\"0bfff43df9281fbf664eaa24a703936f8fe3de1301fa88c45e99ac8542f73817\",\"components\":{\"mcp\":{\"id\":\"79e87c79c34bffb9ae20ccd0fc429455740d2829574120dbd6b120e97312e9b6\",\"image\":\"sha256:b11b656d22e2ab42a304d251ead2d04f301a1f3481b1925ca1a5d29dc545eeac\",\"paused\":false,\"restarting\":false,\"revision\":\"f00e7e3bfcaee9272b9b6d204a7fa3ea79a563a4\",\"running\":true},\"onboarding\":{\"id\":\"8dc539b0756beb40cee0d45b2b223a18eee1a53d8cdb4389d7d914dbda66aad9\",\"image\":\"sha256:b5f09f8b0273e4c2c6d99003b7d10e2f79e733811f5de18185843c7ed8e9b80d\",\"paused\":false,\"restarting\":false,\"revision\":\"cc7766e6348f9ed2e66ec04018ebb63a904d202d\",\"running\":true},\"udp\":{\"id\":\"8054ac2f5101d285947fdd47d86d7a6d13b8ec6500523afcd81b9ac6a82df97c\",\"image\":\"sha256:d2aebe8c3db9b92b6071d94a5c9747378bdc4b6f9caff72df75705b55bf9be40\",\"paused\":false,\"restarting\":false,\"revision\":\"4660b08fdf982f7f7ecc35a378fd8fcad30aa273\",\"running\":true}},\"udpMigrations\":[{\"checksum\":-52230585,\"script\":\"V1__handoff_and_resolution_core.sql\",\"sha256\":\"1b5ea3387b9a964ab58f5da4a8439f8ae2652f2d799effd115076859a7ebc314\",\"success\":true,\"version\":\"1\"},{\"checksum\":-744760032,\"script\":\"V2__canonical_revision_authority.sql\",\"sha256\":\"fa450cbe250ea4391d71418028f55503e08159c9b4aac1e7c30ca5996a54bb5f\",\"success\":true,\"version\":\"2\"},{\"checksum\":647181559,\"script\":\"V3__relationship_resolution.sql\",\"sha256\":\"f535e17a08b7b570333cd7ed42132ceeb23f01b0002c8f0292c84dd1790eb660\",\"success\":true,\"version\":\"3\"},{\"checksum\":-1155247595,\"script\":\"V4__spatial_resolution.sql\",\"sha256\":\"7a95b46d260e9767f25d0dd9cd69139f6992f0bde1df518b180e9d4bc7329173\",\"success\":true,\"version\":\"4\"},{\"checksum\":-1800875911,\"script\":\"V5__human_resolution_merge_split.sql\",\"sha256\":\"3c1e3381e6b9fe955e3d7dd20245ed96aba246b6e18c9cc1db38a6130465257f\",\"success\":true,\"version\":\"5\"},{\"checksum\":887404116,\"script\":\"V6__merge_repoint_and_contribution_links.sql\",\"sha256\":\"b55c6fbaa460ac6035613b5c22e27b5a0439711481747a22060f95a216165d7c\",\"success\":true,\"version\":\"6\"},{\"checksum\":-1523353946,\"script\":\"V7__governed_serving.sql\",\"sha256\":\"bf8a874226296a72d57471d3655f11f1643a4040e9cb1bb38dcfec38a3438739\",\"success\":true,\"version\":\"7\"},{\"checksum\":518442206,\"script\":\"V8__query_complexity_budget.sql\",\"sha256\":\"c416c4be18099730eb4c6cd7525623d60d906212429115a36fa06829de2b7b31\",\"success\":true,\"version\":\"8\"},{\"checksum\":-199210382,\"script\":\"V9__spatial_query_budget.sql\",\"sha256\":\"ce7122f87f83a35df8a004011b09cd27fdbc3fbbfae647d1dfb38dae88c10389\",\"success\":true,\"version\":\"9\"},{\"checksum\":491818960,\"script\":\"V10__lake_object_lifecycle.sql\",\"sha256\":\"fba0dcc22de4cd98e51f46f9667d7283bba8c42e9addf10727d453233a52a24b\",\"success\":true,\"version\":\"10\"},{\"checksum\":-1824633093,\"script\":\"V11__handoff_raw_lake_reference.sql\",\"sha256\":\"5fcaa3ac5aa5db81c2bdcad955cbedc7a5cd1894e9782b3cf0a46747c802ab32\",\"success\":true,\"version\":\"11\"},{\"checksum\":908347656,\"script\":\"V12__lake_maintenance_scheduler.sql\",\"sha256\":\"7ed3f5ba9431176918dc328e2193546665a1323a07a4c8e870ea343af268ab28\",\"success\":true,\"version\":\"12\"},{\"checksum\":739027995,\"script\":\"V13__lake_shadow_rebuild.sql\",\"sha256\":\"5c9d5efe92076880e83a32fe8f2c4e8e483ca3df4f95e0e2ceffd27ea1689b80\",\"success\":true,\"version\":\"13\"},{\"checksum\":61207461,\"script\":\"V14__shadow_rebuild_fencing_and_rollback.sql\",\"sha256\":\"dad5e2f33b70177f87f4919e1508e7eb2f69e96c112575465654905f9aaa820d\",\"success\":true,\"version\":\"14\"},{\"checksum\":-1718975492,\"script\":\"V15__historical_reproduce.sql\",\"sha256\":\"ee3fee6101ee2547fac4403d98958caeda3796f3543f0517066f13bd0d44c5c9\",\"success\":true,\"version\":\"15\"},{\"checksum\":-969460423,\"script\":\"V16__materialization_reference_integrity.sql\",\"sha256\":\"bf4c02fe476be49ace79a0e71ec50202c9ea3fe99d9388617e00028ac95949e9\",\"success\":true,\"version\":\"16\"},{\"checksum\":490009295,\"script\":\"V17__selective_bitemporal_delta_history.sql\",\"sha256\":\"5f5e6fb2da7f5770b9fa6ca8ac2ba76b9d322b1a362eb3e0ace8d81224896814\",\"success\":true,\"version\":\"17\"},{\"checksum\":-1000976960,\"script\":\"V18__capability_retry_guard.sql\",\"sha256\":\"f83874c5277783e3b7c182579dcc8f4f562810e4a682a47701ed6f1b6ce6a251\",\"success\":true,\"version\":\"18\"},{\"checksum\":169180654,\"script\":\"V19__source_raw_handoff_reference.sql\",\"sha256\":\"6736643837d0cbc43acf99b5c1cc65163b5ee0bc4698883d50d43fd0209f0e82\",\"success\":true,\"version\":\"19\"},{\"checksum\":26228480,\"script\":\"V20__governed_coordinate_transformations.sql\",\"sha256\":\"716157ae957f9cf55214f00f6e17f8c2d1c702ecdc5c2c51f88ecdd75084f478\",\"success\":true,\"version\":\"20\"},{\"checksum\":672268981,\"script\":\"V21__pinned_relationship_reconciliation.sql\",\"sha256\":\"2855fdecff9ca4038d746e67fa057568b6b05d1dcf03b620b846dbb85706bdde\",\"success\":true,\"version\":\"21\"},{\"checksum\":-252379595,\"script\":\"V22__weighted_identity_evidence.sql\",\"sha256\":\"543ee9a5461139b3698edef4c01dae33026e61a11fc1514ae7b31699bc9d69fc\",\"success\":true,\"version\":\"22\"},{\"checksum\":561679179,\"script\":\"V23__geometry_authority_conflict.sql\",\"sha256\":\"fecc2f227b1ce6895f9d2a55f6c8ea524fd9cbcd869e876d7efaa6a0cb69445b\",\"success\":true,\"version\":\"23\"},{\"checksum\":-835784960,\"script\":\"V24__human_geometry_decisions.sql\",\"sha256\":\"b4e2f023335a16ba9b424dfcc3f18f200712fae324de9da128b441161f5c2ed8\",\"success\":true,\"version\":\"24\"},{\"checksum\":-1491487699,\"script\":\"V25__human_property_decisions.sql\",\"sha256\":\"1e432653d62c82dd3c1ed3c5c9d9a27682b835d40479d873183d44fb1252c44f\",\"success\":true,\"version\":\"25\"},{\"checksum\":-369310849,\"script\":\"V26__geometry_roles_and_validity.sql\",\"sha256\":\"53e84a127549f91d3520e6f8afeaedc88bfeffe1da2186873659064e91e4700e\",\"success\":true,\"version\":\"26\"},{\"checksum\":-971238326,\"script\":\"V27__identity_scope_serialization.sql\",\"sha256\":\"cd1b07587c8f24e204c20fd5125e8575c77a7a262d3f0f1d9ae81b1a5362aabe\",\"success\":true,\"version\":\"27\"},{\"checksum\":1298756818,\"script\":\"V28__identity_value_lookup.sql\",\"sha256\":\"324a69e64ff1faf20627bf2519d9ee069807c8649aa12c6b7ddb12b3d1be5652\",\"success\":true,\"version\":\"28\"},{\"checksum\":2068388741,\"script\":\"V29__identity_field_shape_catalog.sql\",\"sha256\":\"17fe08e0cbd8df76d30babadb2124a2d0aa3019904728bf94159f97c76914859\",\"success\":true,\"version\":\"29\"},{\"checksum\":-419854425,\"script\":\"V30__resolution_review_package.sql\",\"sha256\":\"f64538ba09fd526b84926f91bf0188d754e22e5a9e3fcc176e4e64c1f9e193f8\",\"success\":true,\"version\":\"30\"},{\"checksum\":80452861,\"script\":\"V31__serialize_identity_coverage_invalidation.sql\",\"sha256\":\"e600eb4818afd4a60f1a4dc90f1215410cb12a3cf9bf510bc1a4aa0fe06906c0\",\"success\":true,\"version\":\"31\"},{\"checksum\":909978875,\"script\":\"V32__governed_identity_preactivation_attestation.sql\",\"sha256\":\"070c29c16b43d49f6aa2827f407373d5a0d5e2628e6225dfd9a9b3c55a048313\",\"success\":true,\"version\":\"32\"},{\"checksum\":-819055726,\"script\":\"V33__human_new_identity_decision.sql\",\"sha256\":\"8a1f8049781ea13aef864cc4d35f0a379bba1960fe9916c99d5eaaf095b2ee91\",\"success\":true,\"version\":\"33\"},{\"checksum\":592479726,\"script\":\"V34__repeat_human_review_after_stale_coverage.sql\",\"sha256\":\"13735a76f1cba075d5f7a600cc9a9676c823c9c398f59d6de2aa8a13dc1672ac\",\"success\":true,\"version\":\"34\"},{\"checksum\":-376865285,\"script\":\"V35__linked_property_reconciliation.sql\",\"sha256\":\"d9937d14b53471ea718ea3ec91c8fc729a48f4e9fbe9bfd23f9673e718705c1f\",\"success\":true,\"version\":\"35\"},{\"checksum\":-1335086670,\"script\":\"V36__publication_dependency_recovery.sql\",\"sha256\":\"9e9c045383561a333c177e7582abc718f84b02b9820388df80a7e5d8e8601c24\",\"success\":true,\"version\":\"36\"}],\"mcpMigrations\":[{\"version\":1,\"checksum\":\"a70a2389352f5f8387f96b6051becf97f64f1e922aba9c353545449e0fa0b225\"},{\"version\":2,\"checksum\":\"138614ca67d9365e7525c0d56313ab1514e3ea9f1fe32b5095a3d85e3ecbb74d\"},{\"version\":3,\"checksum\":\"044d5d6fe3fdd5f77179a4f677885aa3ca4f72ca1bc52f6f10c44b57306bfb3e\"},{\"version\":4,\"checksum\":\"9bae68eb83dabf8bd80fcfdf38189c54cced1228b3b22a7128c4c5cda3b7c72c\"},{\"version\":5,\"checksum\":\"3dc65eeee6668444e77e3a08982a71a1412fda53c3e8b90cbddd7d6959e5ad54\"},{\"version\":6,\"checksum\":\"8973286df97ef30dd7281dfaf5bfb251ca078d4a2862de235b6988bc5e5eb375\"},{\"version\":7,\"checksum\":\"ad1e6b93b10ae2b6e407015f4bfb5026f2cd633a8565d30584fddd98e274f174\"},{\"version\":8,\"checksum\":\"2e279669f11a1b4949c93e17522d127003aa7c3f54cd2af0461500676f2bef28\"},{\"version\":9,\"checksum\":\"798ec17290d8952a6824871739d4b352bc3984f4e600fda9c704d6784d704dd2\"},{\"version\":10,\"checksum\":\"64b586222b534976c379dbec667e4bcb3f7c58087b436b02f79f588e3bb9b0a5\"},{\"version\":11,\"checksum\":\"d6393214c1b83da875015018e5e50833fe6fe4ea0571adf98d5f34fbe390995e\"},{\"version\":12,\"checksum\":\"de64bdcfa45b1e373807d07e603cd1940defe056cec4a21e0db4c7667330cc68\"},{\"version\":13,\"checksum\":\"fe9ab352cbf649efecc708b08a9f61ff3c9aadb358211ebd763011ee9fd695b5\"}],\"candidates\":{\"mcp\":{\"imageId\":\"sha256:62e99695720eb48ffe9061ae273cee67cd4b1b2fd33b961e99f98903c5a2ef46\",\"sourceCommit\":\"5124178d5856b564691ca4274817efd45a0bb991\",\"sourceLockSha256\":\"6dd22df20fce1f9f930b428f1493fa4ddca775d92997820fc37f55965a9fd3cc\"},\"udp\":{\"imageId\":\"sha256:f0c83c2d9efcf6d155b3fc9013da064e0bdcbc87b56180d2d380948c2a0758a9\",\"sourceCommit\":\"0d40da05408a14db31d4d41af2372d6a71480291\",\"sourceLockSha256\":\"6dd22df20fce1f9f930b428f1493fa4ddca775d92997820fc37f55965a9fd3cc\"}}}")

def main(profile):
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_PREPARATION_REQUIRED')
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('PREPARATION_DEADLINE')));signal.alarm(180)
 root_dir(BOOT.parent)
 raw=BOOT.read_bytes();s=BOOT.lstat()
 require(stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and len(raw)<=131072 and hashlib.sha256(raw).hexdigest()==BOOT_HASH,'RETAINED_HELPER_HASH_CHANGED')
 ns={'__name__':'chat_recovery_read_helpers'};exec(compile(raw,'<verified-retained-read-helpers>','exec'),ns)
 old=ns['read'](ns['CONTEXT']/'review.json',8388608,ns['REVIEW']);link=old['scopes']['finiteActionProcess']['bundle']
 prepared=ns['read'](link['path'],8388608,link['sha256'])['prepared']
 require(digest(prepared)==old['privateInputHashes']['preparedInputs'],'PREPARED_INPUT_BINDING_CHANGED')
 def applications():
  result={}
  for module,expected in profile['components'].items():
   actual=ns['engine_get'](prepared['engine'],'containers',expected['id'])
   require(actual and actual['Id']==expected['id'] and actual['Image']==expected['image']
    and actual['State']['Running'] is True and actual['State']['Paused'] is False and actual['State']['Restarting'] is False
    and actual['Config'].get('Labels',{}).get('org.opencontainers.image.revision')==expected['revision'],'CURRENT_APPLICATION_CHANGED')
   result[module]=actual
  return result
 actuals=applications()
 db=prepared['databasePlan'];pg=ns['engine_get'](prepared['engine'],'containers',db['postgresRuntimeBinding']['containerId'])
 require(pg and runtime_pin(pg)==db['postgresRuntimeBinding'] and pg['State']['Running'] is True,'POSTGRES_GENERATION_CHANGED')
 admin=db['mcpAuditRoleAdministration']['admin']
 require([v.split('=',1)[1] for v in pg['Config']['Env'] if v.startswith('POSTGRES_USER=')]==[admin],'DATABASE_ADMINISTRATOR_CHANGED')
 parent=Path(profile['privateParent']);root_dir(parent)
 context=Path(tempfile.mkdtemp(prefix='chat-recovery-prepared-',dir=parent));context.chmod(0o700)
 emit('PRIVATE_CONTEXT',contextPath=str(context),runtimeReadOnly=True)
 facts={}
 for module in('udp','mcp'):
  binding=next(v for v in db['modules'] if v['module']==module)
  require(all(re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,62}',v) for v in(admin,binding['database'])),'EXACT_DATABASE_IDENTIFIERS_REQUIRED')
  argv=[executable(old['sourceClosure']['executables']['docker']),'--host','unix://'+prepared['engine']['socketPath'],'--config',str(context),
   'exec',pg['Id'],'env','LC_ALL=C','PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=10000 -c lock_timeout=3000',
   'timeout','-s','KILL','15','psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-U',admin,'-d',binding['database'],'-c',sql(module,binding['user'])]
  code,data,_,_=bounded(argv,seconds=20,maximum=131072);require(code==0,'DATABASE_PREFLIGHT_READ_FAILED')
  fact=json.loads(data)
  require(fact['database']==binding['database'] and fact['databaseOid']==binding['databaseOid'] and fact['role']==admin,'DATABASE_IDENTITY_CHANGED')
  validate_database(module,fact,profile);facts[module]=fact
  emit('DATABASE_PREFLIGHT',module=module,migrationPrefixMatches=True,pendingMigrations=1 if module=='udp' else 0)
 require({m:runtime_pin(v) for m,v in applications().items()}=={m:runtime_pin(v) for m,v in actuals.items()},'APPLICATION_CHANGED_DURING_PREPARATION')
 require(runtime_pin(ns['engine_get'](prepared['engine'],'containers',pg['Id']))==db['postgresRuntimeBinding'],'POSTGRES_CHANGED_DURING_PREPARATION')
 plan={'schema':'ouf.chat-recovery-private-inputs.v1','profile':profile,'engine':prepared['engine'],
  'databasePlan':db,'databaseFacts':facts,'privateApplicationObservations':actuals,
  'beforeApplications':{m:runtime_pin(v)for m,v in actuals.items()},'programs':old['sourceClosure']['executables'],
  'runtimeAuthorityIssued':False,'readyForExecution':False,'packageRootCustodyProven':False,
  'backupPerformed':False,'nativeFlywayConfigurationProven':False,'runtimeMutations':0}
 raw=encoded(plan);require(len(raw)<=8388608,'PRIVATE_PLAN_BOUND')
 private_write(context/'prepared-inputs.json',raw)
 fd=os.open(context,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
 require((context/'prepared-inputs.json').read_bytes()==raw,'PRIVATE_INPUT_READBACK_FAILED')
 emit('END',complete=True,contextPath=str(context),preparedInputsSha256=hashlib.sha256(raw).hexdigest(),
  udpFromVersion=35,udpToVersion=36,mcpMigrationsUnchanged=True,privatePreparationComplete=True,
  readyForExecution=False,runtimeAuthorityIssued=False,backupPerformed=False,packageRootCustodyProven=False)

if __name__=='__main__':
 try:
  require(len(sys.argv)==1,'NO_ARGUMENTS_REQUIRED')
  main(PROFILE)
 except Exception as error:
  emit('STOP',errorClass=type(error).__name__,exceptionMessagePrinted=False,readyForExecution=False)
  raise SystemExit(2)
