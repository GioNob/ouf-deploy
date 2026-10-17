#!/usr/bin/env python3
"""Disposable native update through the actual MCP server and signed permit.

The Authorization HTTPS server and HUMAN/key identities are synthetic fixtures.
No production endpoint, semantic tool call, or target deployment is exercised.
"""
import base64,copy,hashlib,http.client,importlib.util,json,os,shutil,socket,ssl,stat,subprocess,sys,tempfile,threading,time,uuid
from datetime import datetime,timezone
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_cutover_authority_native as signed
from engine_creation import Engine
import image_custody as custody
from tools.semantic_mcp_update.owner import SingleMcpUpdate,UpdatePaused,digest,scope
from tools.semantic_mcp_update.native import NativePorts
from tools.semantic_mcp_update.entry import admin_database_url
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
assert os.geteuid()==0 and os.environ.get('OUF_NATIVE_MCP_UPDATE_FIXTURE')=='EPHEMERAL_RUNNER_ONLY'

def cli(*args,input=None):
 p=subprocess.run(['docker',*args],input=input,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=90)
 assert p.returncode==0,'NATIVE_DOCKER_FIXTURE_FAILED: '+p.stderr.decode(errors='replace')[:2048]
 assert len(p.stdout)<=2097152 and len(p.stderr)<=2097152
 return p.stdout.strip()
def inspect(reference):return json.loads(cli('inspect',reference))[0]
def module(path,name):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
base=Path(os.environ['MCP_ATOMIC_PACKAGE_DIRECTORY']);record=json.loads((base/'package/package-record.json').read_text())
assert record['sourceCommit']=='f00e7e3bfcaee9272b9b6d204a7fa3ea79a563a4'
assert record['imageId']=='sha256:e61bc9e3bd6f7e2bbf25cca285bfd4319d1addf43b67918961a7a90fc37e78f8'
image_tar=base/'package/image.docker.tar';assert hashlib.sha256(image_tar.read_bytes()).hexdigest()=='6a86142d73de255ba8037fe8a36e7c2408071f11645119d31f8ca5ffff73a543'
continuity=json.loads((base/'migration-continuity.json').read_text())
network='mcp-real-bootstrap-fixture-'+uuid.uuid4().hex[:10];oldname=network+'-old';pgname=network+'-pg';migrator=network+'-migrate';retired=network+'-retired'
containers=[];crypto=signed.SignedCutover();tls_server=None;tls_thread=None
with tempfile.TemporaryDirectory(dir='/root',prefix='mcp-update-native-fixture-')as rootdir:
 root=Path(rootdir);root.chmod(0o700)
 with patch.object(signed,'ROOT',root):crypto.setUp()
 try:
  cli('network','create','--subnet','172.29.77.0/24',network)
  # This generated CA is solely for the disposable HTTPS policy source. The
  # MCP image, Go TLS verifier and endpoint validation remain unmodified.
  gateway='172.29.77.1';ca=root/'fixture-ca.pem';tlskey=root/'fixture-tls.key'
  subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
   '-keyout',str(tlskey),'-out',str(ca),'-subj','/CN=ephemeral-mcp-policy-fixture',
   '-addext','subjectAltName=IP:'+gateway,'-addext','basicConstraints=critical,CA:TRUE'],
   check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
  ca.chmod(0o444);tlskey.chmod(0o600)
  stamp=datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
  bundle={'bundleId':'ephemeral-bootstrap-policy','version':1,'publishedAt':stamp,'capabilities':[], 'grants':[]}
  rawbundle=json.dumps(bundle,separators=(',',':')).encode()
  envelope={'contentHash':hashlib.sha256(rawbundle).hexdigest(),'bundleId':bundle['bundleId'],
   'bundleVersion':1,'activatedAt':stamp,'bundle':bundle}
  policy_response=json.dumps(envelope,separators=(',',':')).encode()
  policy_path='/api/internal/v1/authorization/policy-bundles/active'
  fixture_calls={'policy':0,'unexpected':0}
  class PolicyFixture(BaseHTTPRequestHandler):
   def log_message(self,*args):pass
   def do_GET(self):
    if self.path==policy_path and self.headers.get('Authorization')=='Bearer SYNTHETIC_BOOTSTRAP_WORKLOAD':
     fixture_calls['policy']+=1;self.send_response(200);self.send_header('Content-Type','application/json')
     self.send_header('Content-Length',str(len(policy_response)));self.end_headers();self.wfile.write(policy_response)
    else:
     fixture_calls['unexpected']+=1;self.send_error(403)
   def do_POST(self):fixture_calls['unexpected']+=1;self.send_error(403)
  tls_server=ThreadingHTTPServer((gateway,0),PolicyFixture)
  tls_context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls_context.minimum_version=ssl.TLSVersion.TLSv1_2
  tls_context.load_cert_chain(str(ca),str(tlskey));tls_server.socket=tls_context.wrap_socket(tls_server.socket,server_side=True)
  tls_thread=threading.Thread(target=tls_server.serve_forever,daemon=True);tls_thread.start()
  tls_origin='https://'+gateway+':'+str(tls_server.server_port)
  pg_secret=root/'postgres-password';pg_secret.write_bytes(b'mcp:@/ file\n\n');pg_secret.chmod(0o440)
  pgid=cli('run','-d','--name',pgname,'--network',network,'--network-alias','pg-fixture','--volume',str(pg_secret)+':/run/secrets/postgres-password:ro','-e','POSTGRES_USER=mcp','-e','POSTGRES_PASSWORD_FILE=/run/secrets/postgres-password','-e','POSTGRES_DB=mcp_update_fixture','postgres:17').decode();containers.append(pgid)
  for _ in range(100):
   ready=subprocess.run(['docker','exec',pgid,'pg_isready','-h','127.0.0.1','-U','mcp','-d','mcp_update_fixture'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   if ready.returncode==0:break
   time.sleep(.1)
  else:raise AssertionError('NATIVE_POSTGRES_NOT_READY')
  def sql(text):return cli('exec','-i',pgid,'psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-U','mcp','-d','mcp_update_fixture',input=text.encode())
  baseline=Path(os.environ['MCP_BASELINE_SOURCE_DIRECTORY'])/'internal/adapter/postgres/migrations'
  sql('CREATE SCHEMA ouf_mcp; CREATE TABLE ouf_mcp.schema_migration(version int primary key,checksum char(64)not null);')
  for path in sorted(baseline.glob('*.sql')):
   assert int(path.name[:3])<=12;raw=path.read_bytes();h=hashlib.sha256(raw).hexdigest()
   sql('BEGIN;'+raw.decode()+f";INSERT INTO ouf_mcp.schema_migration VALUES({int(path.name[:3])},'{h}');COMMIT;")
  sql("CREATE ROLE fixture_application LOGIN PASSWORD 'fixture-application'; GRANT USAGE,CREATE ON SCHEMA ouf_mcp TO fixture_application; GRANT INSERT ON ouf_mcp.schema_migration TO fixture_application; GRANT REFERENCES ON ouf_mcp.tool_attempt,ouf_mcp.budget_window TO fixture_application;")
  sql('GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA ouf_mcp TO fixture_application; GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA ouf_mcp TO fixture_application;')
  attempt=str(uuid.uuid4());manifest='09981c1cd01f47bed227250b70448dd24d2a66e4d36e7878df4f6235b783fd4a';requesthash='b'*64
  sql(f"INSERT INTO ouf_mcp.manifest_snapshot(manifest_checksum,manifest_version,schema_version,payload)VALUES('cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc','fixture','fixture','{{}}');INSERT INTO ouf_mcp.tool_attempt(attempt_id,service_principal_id,principal_id,tenant_id,capability_id,operation_class,manifest_checksum,idempotency_key,request_hash,correlation_id,state,dispatch_state,completed_at,lock_version)VALUES('{attempt}','fixture-workload','fixture-human','fixture-tenant','ouf.semantic.propose','COMMAND','cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc','fixture-stable-command','{requesthash}','fixture','FAILED','ACKNOWLEDGED',clock_timestamp(),2);")
  data=json.loads(sql("SELECT json_build_object('oid',(SELECT oid::bigint FROM pg_database WHERE datname=current_database()),'functionHash',encode(sha256(convert_to(pg_get_functiondef(to_regprocedure('ouf_mcp.purge_terminal_attempt_graph(timestamp with time zone,integer)')),'UTF8')),'hex'))"))
  oldid=cli('run','-d','--name',oldname,'--network',network,'--user','10005:10005','--read-only','--volume',str(ca)+':/run/fixture-ca.pem:ro','--restart','no','--entrypoint','/bin/sh','alpine:3.22','-c','while true; do sleep 1; done').decode();containers.append(oldid)
  old=inspect(oldid);pg=inspect(pgid);net=old['NetworkSettings']['Networks'][network]
  sock=Path('/var/run/docker.sock').resolve();info=sock.lstat();engine=Engine(str(sock),(info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)))
  native_request=engine.request
  def fixture_request(method,path,body=None):
   status,value=native_request(method,path,body)
   if method!='GET'and not 200<=status<300:
    print(json.dumps({'syntheticFixtureDockerStatus':status,'operation':path.split('?')[0],
     'boundedFixtureMessage':str((value or{}).get('message',''))[:1024]}),flush=True)
   return status,value
  engine.request=fixture_request
  # Build fixture pins through the same explicitly reviewed Engine API as the
  # production observer; CLI inspect uses a newer API projection.
  old=engine.request('GET','/v1.44/containers/'+oldid+'/json')[1]
  pg=engine.request('GET','/v1.44/containers/'+pgid+'/json')[1]
  fixture_admin_review={'database':{'postgresRuntimeBinding':Engine.runtime_binding(pg),'backupReader':'mcp','binding':{'database':'mcp_update_fixture'}},'oldNativeConfig':{'Env':['MCP_DATABASE_URL=postgres://fixture_application:fixture-application@pg-fixture:5432/mcp_update_fixture?sslmode=disable']}}
  selected_admin_url=admin_database_url(fixture_admin_review,engine)
  net=old['NetworkSettings']['Networks'][network]
  dirname=root/'action';dirname.mkdir(mode=0o700);journal=Journal(dirname)
  def pin(actual):return {'containerId':actual['Id'],'imageId':actual['Image'],'pid':actual['State']['Pid'],'startedAt':actual['State']['StartedAt'],**{n+'Hash':digest(actual[k])for n,k in(('config','Config'),('hostConfig','HostConfig'),('mounts','Mounts'),('networkSettings','NetworkSettings'))}}
  audit=None;archive=dirname/'image.tagless.tar';nativeinfo=json.loads(cli('info','--format','{{json .}}'))
  containerd=nativeinfo['Driver']=='overlayfs'and dict(nativeinfo.get('DriverStatus')or[]).get('driver-type')=='io.containerd.snapshotter.v1'
  assert containerd or nativeinfo['Driver']=='overlay2'
  with image_tar.open('rb')as source:
   original=custody.archive(source,'6a86142d73de255ba8037fe8a36e7c2408071f11645119d31f8ca5ffff73a543',record['imageId'],record['sourceCommit'])
   with archive.open('x+b')as target:derived=custody.tagless_archive(source,target,original,containerd=containerd)
  archive.chmod(0o600)
  with archive.open('rb')as source:audit=custody.archive(source,derived['derivedArchiveSha256'],record['imageId'],record['sourceCommit'])
  if containerd:audit['nativeIdentity']=custody.native_identity(audit)
  nativeimage=custody.runtime_image_id(audit)
  predecessor=root/'predecessor.json';predecessor.write_text('{"fixture":true}');predecessor.chmod(0o600)
  docker=Path(shutil.which('docker')).resolve();program={'path':str(docker),'sha256':hashlib.sha256(docker.read_bytes()).hexdigest()}
  profile={'schema':'ouf.mcp-reprocessing-key-profile.v1','maxSessionsPerTenant':64,
   'installationRef':crypto.context['installationRef'],'entityRef':crypto.context['entityRef'],
   'installerKeyRef':crypto.grant['keyRef'],'intentIssuerRef':crypto.context['intentIssuerRef'],
   'approvalIssuerRef':crypto.context['approvalIssuerRef'],'trustPolicyHash':signed.sha(crypto.policy.read_bytes())}
  profile_raw=signed.encoded(profile);profile_hash=signed.sha(profile_raw);permit_now=int(time.time())
  permit={'schema':'ouf.mcp-semantic-reprocessing-session.v1','sessionId':str(uuid.uuid4()),
   'decisionRef':'EPHEMERAL_SIGNED_BOOTSTRAP_FIXTURE','reason':'FIXTURE_BOOTSTRAP_ONLY_NO_SEMANTIC_DISPATCH',
   'installationRef':profile['installationRef'],'keyProfileHash':profile_hash,'manifestChecksum':manifest,
   'servicePrincipalId':'fixture-workload','humanSubject':'fixture-human','tenantId':'fixture-tenant',
   'owner':'semantic','capabilityId':'ouf.semantic.propose','operationClass':'COMMAND','commandKey':'fixture-stable-command',
   'requestHash':requesthash,'predecessorAttemptId':attempt,'predecessorLockVersion':2,
   'predecessorOutcomeCode':'SEM_CAPABILITY_REQUIRED:ouf.semantic.propose','priorToolCalls':1,
   'maximumNewToolCalls':1,'maximumCumulativeToolCalls':2,'ownerReceiptAbsentAt':permit_now,
   'issuedAt':permit_now,'expiresAt':min(permit_now+480,crypto.grant['expiresAt'])}
  permit_raw=signed.encoded(permit);signatures={}
  for field,role in (('intent','DEPLOYMENT_INTENT'),('approval','FINAL_DEPLOYMENT_APPROVAL')):
   header={'schema':'ouf.semantic-deployment-detached-signature.v1','algorithm':'Ed25519',
    'keyRef':profile['installerKeyRef'],'role':role,'issuerRef':profile['intentIssuerRef'],
    'installationRef':profile['installationRef'],'entityRef':profile['entityRef'],'payloadHash':signed.sha(permit_raw)}
   frame=root/('permit-'+field+'.frame');crypto.write(frame,signed.signing_bytes(permit_raw,header))
   signature=crypto.native('pkeyutl','-sign','-rawin','-inkey',str(crypto.key),'-in',str(frame))
   signatures[field]={**header,'signature':signature.hex()}
  permit_envelope={'payload':base64.b64encode(permit_raw).decode(),**signatures}
  metadata={'directory':str(dirname/'public'),'target':'/run/ouf-reprocessing-fixture','gid':10005,
   'files':{'profile.json':profile_raw.decode(),'policy.json':crypto.policy.read_text(),'permit.json':signed.encoded(permit_envelope).decode()}}
  app_env=['MCP_DATABASE_URL=postgres://fixture_application:fixture-application@pg-fixture:5432/mcp_update_fixture?sslmode=disable',
   'MCP_WORKLOAD_TOKEN=SYNTHETIC_BOOTSTRAP_WORKLOAD','MCP_AUTHORIZATION_BUNDLE_ENDPOINT='+tls_origin+policy_path,
   'MCP_GATEWAY_ENDPOINT='+tls_origin+'/api/internal/v1/gateway','MCP_FINGERPRINT_KEY='+('SYNTHETIC_'*5),
   'SSL_CERT_FILE=/run/fixture-ca.pem','MCP_REPROCESSING_KEY_PROFILE_FILE='+metadata['target']+'/profile.json',
   'MCP_REPROCESSING_KEY_PROFILE_SHA256='+profile_hash,'MCP_REPROCESSING_PERMIT_FILE='+metadata['target']+'/permit.json',
   'MCP_REPROCESSING_EXISTING_POLICY_FILE='+metadata['target']+'/policy.json']
  host={'NetworkMode':network,'RestartPolicy':{'Name':'no','MaximumRetryCount':0},'ReadonlyRootfs':True,'AutoRemove':False}
  migration_request={'Image':nativeimage,'User':'10005:10005','Entrypoint':['/usr/local/bin/ouf-mcp'],'Cmd':['migrate-semantic-reprocessing'],'WorkingDir':'/app',
   'Env':['MCP_DATABASE_URL='+selected_admin_url,'MCP_MIGRATION_APPLICATION_ROLE=fixture_application','MCP_MIGRATION_DATABASE_OID='+str(data['oid']),'MCP_MIGRATION_RETENTION_FUNCTION_SHA256='+data['functionHash']],
   'HostConfig':host,'NetworkingConfig':{'EndpointsConfig':{network:{'NetworkID':net['NetworkID']}}}}
  replacement={'Image':nativeimage,'User':'10005:10005','Entrypoint':['/usr/local/bin/ouf-mcp'],
   'Cmd':['server','--http',':8080'],'WorkingDir':'/app','Env':app_env,
   'Labels':{'org.opencontainers.image.revision':record['sourceCommit']},
   'HostConfig':{**host,'Binds':[str(ca)+':/run/fixture-ca.pem:ro',metadata['directory']+':'+metadata['target']+':ro']},
   'NetworkingConfig':{'EndpointsConfig':{network:{'NetworkID':net['NetworkID'],'Aliases':[oldname],
    'IPAMConfig':{'IPv4Address':net['IPAddress']},'MacAddress':net['MacAddress']}}}}
  plan={'schema':'ouf.mcp-single-update-execution-plan.v1','authorityDirectory':str(dirname),'predecessorReviewPath':str(predecessor),'predecessorReviewHash':hashlib.sha256(predecessor.read_bytes()).hexdigest(),
   'oldRuntimeBinding':pin(old),'oldHostConfig':old['HostConfig'],'oldMounts':old['Mounts'],'postgresRuntimeBinding':pin(pg),
   'engine':{'socketPath':str(sock)},'programs':{'docker':program},'metadata':metadata,'imageAudit':audit,'imageImport':{'path':str(archive)},
   'database':{'name':'mcp_update_fixture','admin':'mcp','oid':data['oid'],'before':continuity['before'],'after':continuity['candidate'],'backupPath':str(dirname/'backup.dump'),'maximumBackupBytes':1073741824},
   'retainedClaim':{'attemptId':attempt,'state':'FAILED','dispatchState':'ACKNOWLEDGED','lockVersion':2,'requestHash':requesthash},
   'migration':{'name':migrator,'request':migration_request,'command':'migrate-semantic-reprocessing','committedMembershipAllowed':False},
   'replacement':{'name':oldname,'retiredName':retired,'request':replacement,'restoreRestartPolicy':{'Name':'no','MaximumRetryCount':0}},
   'network':{'name':network,'id':net['NetworkID'],'ip':net['IPAddress'],'mac':net['MacAddress']},'readiness':{'port':8080,'path':'/health/ready'},
   'maximumExecutionSeconds':900,'automaticRollbackAllowed':False,'databaseRestoreAllowed':False,'semanticDispatchAllowed':False}
  plan['logicalUpdateRef']=digest({'oldContainerId':oldid,'databaseOid':data['oid'],'predecessorAttemptId':attempt})
  c=crypto;c.now=int(time.time());c.approval['issuedAt']=c.now;c.approval['expiresAt']=min(c.now+500,c.grant['expiresAt']);c.authority=signed.encoded({'schema':'ouf.semantic-cutover-execution-authority.v1',**{k:v for k,v in c.expected.items()if k!='intakeHash'},'issuedAt':c.now,'expiresAt':min(c.now+480,c.grant['expiresAt']-5),'mcpSingleUpdate':scope(plan)})
  c.approval['executionAuthorityHash']=signed.sha(c.authority);c.write(c.mandate,signed.encoded(c.approval));c.approved=signed.sha(c.mandate.read_bytes())
  for role in c.grant['roles']:c.sign(role)
  action=AggregateAction(c.gate(),c.authority,c.expected['sourceClosureHash']);ports=NativePorts(action,engine,plan)
  update=SingleMcpUpdate(action,journal,plan,ports);update.initialize()
  end=time.monotonic()+110
  while True:
   try:result=update.run();break
   except UpdatePaused as paused:
    assert str(paused)=='READINESS_RETRY_WAIT','FIXTURE_EFFECT_REQUIRES_RECONCILIATION'
    assert time.monotonic()<end,'FIXTURE_FINITE_READINESS_EXHAUSTED'
    state=journal.read();time.sleep(min(.2,max(0,state['nextReadAt']-time.time())))
  assert result['applicationReady']and not result['acceptanceGranted'];assert inspect(oldid)['State']['Running']is False
  assert len(journal.read()['effects'])==16
  result2=update.run();assert result2['applicationReady']
  actual=inspect(oldname)
  assert actual['Config']['Entrypoint']==['/usr/local/bin/ouf-mcp'] and actual['Config']['Cmd']==['server','--http',':8080']
  assert actual['Config']['User']=='10005:10005' and actual['State']['Running']
  assert sql("SELECT count(*) FROM ouf_mcp.manifest_snapshot WHERE manifest_checksum='"+manifest+"' AND schema_version='mcp-manifest-v1'")==b'1'
  assert sql("SELECT count(*) FROM pg_auth_members WHERE roleid='ouf_mcp_retention_owner'::regrole")==b'0'
  assert sql("SELECT rolsuper OR rolcreaterole FROM pg_roles WHERE rolname='fixture_application'")==b'f'
  def request(method,path,body=None,headers=None):
   conn=http.client.HTTPConnection(net['IPAddress'],8080,timeout=3)
   try:
    conn.request(method,path,body=body,headers=headers or{});response=conn.getresponse();raw=response.read(1048577)
    assert len(raw)<=1048576;return response.status,raw
   finally:conn.close()
  assert request('GET','/health/live')[0]==204 and request('GET','/health/ready')[0]==204
  headers={'Content-Type':'application/json','Accept':'application/json, text/event-stream',
   'Mcp-Protocol-Version':'2026-07-28','Mcp-Method':'server/discover'}
  discover=json.dumps({'jsonrpc':'2.0','id':1,'method':'server/discover','params':{}})
  assert request('POST','/mcp',discover,headers)[0]==401
  assert fixture_calls['policy']>=1 and fixture_calls['unexpected']==0
  # Failed bootstrap cases are fresh disposable CI processes, never retries of
  # the governed target operation. A valid image must reject each bad binding.
  failed=[]
  def rejects_bootstrap(case,environment,mount):
   name=network+'-'+case;failed.append(name)
   argv=['run','-d','--name',name,'--network',network,'--user','10005:10005','--read-only',
    '--mount','type=bind,src='+str(ca)+',dst=/run/fixture-ca.pem,readonly',
    '--mount','type=bind,src='+str(mount)+',dst='+metadata['target']+',readonly',
    '--entrypoint','/usr/local/bin/ouf-mcp']
   for item in environment:argv.extend(['-e',item])
   cli(*argv,nativeimage,'server','--http',':8080')
   code=cli('wait',name)
   assert code==b'1','INVALID_BOOTSTRAP_NOT_REJECTED_'+case
   logs=cli('logs',name)
   assert b'invalid semantic reprocessing configuration'in logs,'WRONG_BOOTSTRAP_FAILURE_'+case
  try:
   rejects_bootstrap('wrong-profile',[v if not v.startswith('MCP_REPROCESSING_KEY_PROFILE_SHA256=')else'MCP_REPROCESSING_KEY_PROFILE_SHA256='+('0'*64)for v in app_env],metadata['directory'])
   bad=root/'bad-public';bad.mkdir(mode=0o750);os.chown(bad,0,10005)
   for name,text in metadata['files'].items():
    content=text
    if name=='permit.json':
     tampered=json.loads(text);tampered['approval']['signature']='0'*128;content=signed.encoded(tampered).decode()
    path=bad/name;path.write_text(content);os.chown(path,0,10005);path.chmod(0o440)
   rejects_bootstrap('bad-signature',app_env,bad)
   # Restore the original bytes, but make the root-owned profile group writable.
   (bad/'permit.json').write_text(metadata['files']['permit.json']);(bad/'permit.json').chmod(0o440)
   (bad/'profile.json').chmod(0o660)
   rejects_bootstrap('writable-profile',app_env,bad)
  finally:
   for name in failed:subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  assert fixture_calls['unexpected']==0
  assert sql('SELECT count(*) FROM ouf_mcp.semantic_reprocessing_session')==b'0'
  assert sql('SELECT count(*) FROM ouf_mcp.tool_attempt')==b'1'
  print(json.dumps({'realMcpBootstrapChecks':{'embeddedManifestPersisted':True,'nonrootApplication':True,
   'tlsPolicyBootstrap':True,'bothHealthEndpoints':True,'unsignedIngressRejected':True,
   'wrongProfileRejected':True,'badSignatureRejected':True,'writableProfileRejected':True,
   'retentionMemberships':0,'semanticReprocessingSessions':0,'toolAttemptsUnchanged':True}}))
  print(json.dumps({'schema':'ouf.mcp-single-update-native-fixture-qualification.v1','realDockerEffects':True,'realPostgreSQL17AtomicMigration':True,'backupRestoreListProven':True,
   'sameEndpointPreserved':True,'oldGenerationStopped':True,'publicMetadataCustodyProven':True,'completedStages':16,
   'replacementProcess':'REAL_OUF_MCP_SERVER_WITH_SYNTHETIC_TLS_AUTHORIZATION','mcpServerApplicationBootstrapProven':True,'realSemanticCalls':0,'targetOperations':0,'acceptanceGranted':False}))
 finally:
  if tls_server is not None:tls_server.shutdown();tls_server.server_close()
  if tls_thread is not None:tls_thread.join(timeout=3)
  for name in(oldname,retired,migrator,pgname):
   subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  subprocess.run(['docker','network','rm',network],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  crypto.doCleanups()
