#!/usr/bin/env python3
"""Disposable native Docker/PG adapter qualification; fixture HTTP process only.

Uses the actual unsigned MCP image for native migration and replacement image
custody. The fixture response loop is not the MCP server, Registry or E2E proof.
"""
import copy,hashlib,importlib.util,json,os,shutil,socket,stat,subprocess,sys,tempfile,time,uuid
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_cutover_authority_native as signed
from engine_creation import Engine
import image_custody as custody
from tools.semantic_mcp_update.owner import SingleMcpUpdate,digest,scope
from tools.semantic_mcp_update.native import NativePorts
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
network='mcp-update-fixture-'+uuid.uuid4().hex[:10];oldname=network+'-old';pgname=network+'-pg';migrator=network+'-migrate';retired=network+'-retired'
containers=[];crypto=signed.SignedCutover()
with tempfile.TemporaryDirectory(dir='/root',prefix='mcp-update-native-fixture-')as rootdir:
 root=Path(rootdir);root.chmod(0o700)
 with patch.object(signed,'ROOT',root):crypto.setUp()
 try:
  cli('network','create',network)
  pgid=cli('run','-d','--name',pgname,'--network',network,'--network-alias','pg-fixture','-e','POSTGRES_USER=mcp','-e','POSTGRES_PASSWORD=mcp','-e','POSTGRES_DB=mcp_update_fixture','postgres:17').decode();containers.append(pgid)
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
  attempt=str(uuid.uuid4());manifest='a'*64;requesthash='b'*64
  sql(f"INSERT INTO ouf_mcp.manifest_snapshot(manifest_checksum,manifest_version,schema_version,payload)VALUES('{manifest}','fixture','fixture','{{}}');INSERT INTO ouf_mcp.tool_attempt(attempt_id,service_principal_id,principal_id,tenant_id,capability_id,operation_class,manifest_checksum,idempotency_key,request_hash,correlation_id,state,dispatch_state,completed_at,lock_version)VALUES('{attempt}','fixture-workload','fixture-human','fixture-tenant','ouf.semantic.propose','COMMAND','{manifest}','fixture-stable-command','{requesthash}','fixture','FAILED','ACKNOWLEDGED',clock_timestamp(),2);")
  data=json.loads(sql("SELECT json_build_object('oid',(SELECT oid::bigint FROM pg_database WHERE datname=current_database()),'functionHash',encode(sha256(convert_to(pg_get_functiondef(to_regprocedure('ouf_mcp.purge_terminal_attempt_graph(timestamp with time zone,integer)')),'UTF8')),'hex'))"))
  oldid=cli('run','-d','--name',oldname,'--network',network,'--user','10005:10005','--read-only','--restart','no','--entrypoint','/bin/sh','alpine:3.22','-c','while true; do sleep 1; done').decode();containers.append(oldid)
  old=inspect(oldid);pg=inspect(pgid);net=old['NetworkSettings']['Networks'][network]
  sock=Path('/var/run/docker.sock').resolve();info=sock.lstat();engine=Engine(str(sock),(info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)))
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
  metadata={'directory':str(dirname/'public'),'target':'/run/ouf-reprocessing-fixture','gid':10005,'files':{k:'{}'for k in('profile.json','policy.json','permit.json')}}
  host={'NetworkMode':network,'RestartPolicy':{'Name':'no','MaximumRetryCount':0},'ReadonlyRootfs':True,'AutoRemove':False}
  migration_request={'Image':nativeimage,'User':'10005:10005','Entrypoint':['/usr/local/bin/ouf-mcp'],'Cmd':['migrate-semantic-reprocessing'],'WorkingDir':'/app',
   'Env':['MCP_DATABASE_URL=postgres://mcp:mcp@pg-fixture:5432/mcp_update_fixture?sslmode=disable','MCP_MIGRATION_APPLICATION_ROLE=fixture_application','MCP_MIGRATION_DATABASE_OID='+str(data['oid']),'MCP_MIGRATION_RETENTION_FUNCTION_SHA256='+data['functionHash']],
   'HostConfig':host,'NetworkingConfig':{'EndpointsConfig':{network:{'NetworkID':net['NetworkID']}}}}
  replacement={'Image':nativeimage,'User':'10005:10005','Entrypoint':['/bin/sh'],'Cmd':['-c',"while true; do printf 'HTTP/1.1 204 No Content\\r\\nConnection: close\\r\\n\\r\\n' | nc -l -p 8080; done"],'WorkingDir':'/app','Env':[],
   'Labels':{'org.opencontainers.image.revision':record['sourceCommit']},'HostConfig':{**host,'Binds':[metadata['directory']+':'+metadata['target']+':ro']},
   'NetworkingConfig':{'EndpointsConfig':{network:{'NetworkID':net['NetworkID'],'Aliases':[oldname],'IPAMConfig':{'IPv4Address':net['IPAddress']},'MacAddress':net['MacAddress']}}}}
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
  c=crypto;c.authority=signed.encoded({'schema':'ouf.semantic-cutover-execution-authority.v1',**{k:v for k,v in c.expected.items()if k!='intakeHash'},'issuedAt':c.now,'expiresAt':c.now+120,'mcpSingleUpdate':scope(plan)})
  c.approval['executionAuthorityHash']=signed.sha(c.authority);c.write(c.mandate,signed.encoded(c.approval));c.approved=signed.sha(c.mandate.read_bytes())
  for role in c.grant['roles']:c.sign(role)
  action=AggregateAction(c.gate(),c.authority,c.expected['sourceClosureHash']);ports=NativePorts(action,engine,plan)
  update=SingleMcpUpdate(action,journal,plan,ports);update.initialize();result=update.run()
  assert result['applicationReady']and not result['acceptanceGranted'];assert inspect(oldid)['State']['Running']is False
  assert len(journal.read()['effects'])==16
  result2=update.run();assert result2['applicationReady']
  print(json.dumps({'schema':'ouf.mcp-single-update-native-fixture-qualification.v1','realDockerEffects':True,'realPostgreSQL17AtomicMigration':True,'backupRestoreListProven':True,
   'sameEndpointPreserved':True,'oldGenerationStopped':True,'publicMetadataCustodyProven':True,'completedStages':16,
   'replacementProcess':'SYNTHETIC_BUSYBOX_HTTP_204','mcpServerApplicationBootstrapProven':False,'realSemanticCalls':0,'targetOperations':0,'acceptanceGranted':False}))
 finally:
  for name in(oldname,retired,migrator,pgname):
   subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  subprocess.run(['docker','network','rm',network],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  crypto.doCleanups()
