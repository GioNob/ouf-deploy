#!/usr/bin/env python3
"""Disposable CI: exact G0 package across distinct private provider networks."""
import copy,json,os,re,shutil,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from tools.storage_planning import g0_package as pkg,g0_network as net,g0_database as db
from tools.storage_planning.g0_host import ROLES
from tools.storage_planning.inventory_manifest import canonical,decode,require,sha
MINIO='ghcr.io/datalens-tech/minio@sha256:a1a8bd4ac40ad7881a245bab97323e18f971e4d4cba2c2007ec1bedd21cbaba2'
PG='postgis/postgis@sha256:894f570c0cf0664ed5576a8fd5d5bfb8fb1b19d592885b686c3a88c8bd90c41f'
def cmd(args,input=None,timeout=120,check=True):
 r=subprocess.run(args,input=input,capture_output=True,text=True,timeout=timeout)
 if check:require(r.returncode==0,'CI_COMMAND_FAILED:'+args[0]+':'+r.stderr[-1500:]);return r.stdout.strip()
 return r
def write(p,x):p.write_bytes(canonical(x));p.chmod(0o600)
def main(work):
 require(os.environ.get('GITHUB_ACTIONS')=='true' and os.geteuid()==0,'CI_ROOT_ONLY')
 out=work/'evidence';scan={'Results':decode((out/'trivy.json').read_bytes())['Results']+decode((out/'trivy-fixture.json').read_bytes())['Results']};require({'inventory','seed.test'}<={Path(x['Target']).name for x in scan.get('Results',[]) if x.get('Type')=='gobinary'},'BOTH_EXECUTABLES_SCANNED');require(not any(v.get('Severity','UNKNOWN') in ('HIGH','CRITICAL','UNKNOWN') for x in scan['Results'] for v in x.get('Vulnerabilities',[]) or []),'BINARY_SECURITY_HELD')
 root=Path('/var/lib')/('ouf-g0-network-fixture-'+os.environ['GITHUB_RUN_ID']);require(not root.exists(),'NEW_NATIVE_FIXTURE_ROOT');root.mkdir(mode=0o700);os.umask(0o077)
 for name in ('inputs','history','evidence','data'):(root/name).mkdir(mode=0o700)
 shutil.copytree(work/'package',root/'package');shutil.copyfile(work/'scan/fixture/seed.test',root/'seed.test');(root/'seed.test').chmod(0o500)
 created=[];stopped=set();prefix='g0net-'+os.environ['GITHUB_RUN_ID'];views={};migration_count={};host_net=net.namespace('self','net');host_mnt=net.namespace('self','mnt')
 def admin(sql,check=True):return cmd(['docker','exec','-i',views['postgres']['Id'],'psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-U','postgres','-d','g0'],input=sql,check=check)
 try:
  for image in (MINIO,PG):cmd(['docker','pull',image],timeout=300)
  uid=cmd(['docker','run','--rm','--network','none','--entrypoint','id',PG,'-u','postgres']);gid=cmd(['docker','run','--rm','--network','none','--entrypoint','id',PG,'-g','postgres'])
  pg=cmd(['docker','run','-d','--name',prefix+'-postgres','--network','none','--user',uid+':'+gid,'--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','1g','--pids-limit','128','--tmpfs','/var/lib/postgresql/data:rw,nosuid,size=536870912,uid='+uid+',gid='+gid+',mode=0700','--tmpfs','/var/run/postgresql:rw,nosuid,size=8388608,uid='+uid+',gid='+gid+',mode=0770','--tmpfs','/tmp:rw,nosuid,size=67108864,mode=1777','-e','POSTGRES_PASSWORD=fixture-only-admin','-e','POSTGRES_DB=g0',PG]);created.append(pg)
  views['postgres']=json.loads(cmd(['docker','inspect',pg]))[0]
  until=time.monotonic()+90
  while True:
   tcp=cmd(['docker','exec',pg,'pg_isready','-h','127.0.0.1','-U','postgres','-d','g0'],check=False)
   r=admin('SELECT PostGIS_Version();',False) if tcp.returncode==0 else tcp
   if tcp.returncode==r.returncode==0:break
   require(time.monotonic()<until,'CI_PG_READY_DEADLINE');time.sleep(.5)
  mi=cmd(['docker','run','-d','--name',prefix+'-minio','--network','none','--user','0:0','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','1g','--pids-limit','128','--tmpfs','/tmp:rw,nosuid,size=67108864,mode=1777','--mount','type=bind,src='+str(root/'data')+',dst=/data','-e','MINIO_ROOT_USER=synthetic-g0-admin','-e','MINIO_ROOT_PASSWORD=synthetic-g0-secret-not-production',MINIO,'server','/data','--address',':9000','--console-address',':9001']);created.append(mi);views['minio']=json.loads(cmd(['docker','inspect',mi]))[0]
  ns=['nsenter','--net=/proc/'+str(views['minio']['State']['Pid'])+'/ns/net','--']
  ready='import urllib.request,time\ne=time.monotonic()+60\nwhile True:\n try:\n  assert urllib.request.urlopen("http://127.0.0.1:9000/minio/health/ready",timeout=2).status==200;break\n except Exception:\n  if time.monotonic()>e:raise\n  time.sleep(.5)\n';cmd(ns+[sys.executable,'-I','-B','-S','-c',ready],timeout=70)
  for role in ROLES:
   if role in views:continue
   cid=cmd(['docker','create','--name',prefix+'-'+role,'--network','none','--read-only','--cap-drop','ALL','--entrypoint','/not-executed',MINIO]);created.append(cid);views[role]=json.loads(cmd(['docker','inspect',cid]))[0]
  for profile,directory in [('onboarding','onboarding-source'),('udp','udp-source'),('ingestion','ingestion-source')]:
   files=sorted((ROOT/directory/'src/main/resources/db/migration').glob('V*.sql'),key=lambda p:int(re.match('V([0-9]+)',p.name)[1]));migration_count[profile]=len(files)
   for f in files:admin('SET search_path=ouf_'+profile+',public;\n'+f.read_text())
   role='g0_'+profile;admin('CREATE ROLE '+role+" LOGIN PASSWORD 'fixture-only-password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; ALTER ROLE "+role+' SET default_transaction_read_only=on;')
   admin(''.join('GRANT USAGE ON SCHEMA '+s+' TO '+role+';' for s in {t.split('.')[0] for t in db.TABLES[profile]})+''.join('GRANT SELECT ON '+t+' TO '+role+';' for t in db.TABLES[profile]))
  admin((ROOT/'tests/fixtures/storage-g0-db/seed.sql').read_text())
  for name,value in [('access','synthetic-g0-admin'),('secret','synthetic-g0-secret-not-production')]:p=root/'inputs'/name;p.write_text(value);p.chmod(0o600)
  cmd(ns+['env','OUF_G0_NETWORK_WORK='+str(root),str(root/'seed.test'),'-test.v','-test.run=^TestG0NetworkSeed$','-test.timeout=60s'],timeout=70)
  c=decode((root/'package/input-template.json').read_bytes());c.update(operationId='native-network',installationRef='synthetic-network',outputParent=str(root/'evidence'),collectionDecisionRef='CI_FIXTURE_ONLY_NOT_RUNTIME_AUTHORITY');c['capacityPaths']={k:str(root) for k in ('source','destination','backup')};c['roles']={k:{'containerId':v['Id'],'nativeImage':v['Image']} for k,v in views.items()}
  binding={'schema':'ouf.storage-g0-network-binding.v1','operationId':c['operationId'],'installationRef':c['installationRef'],'bootId':net.boot_id(),'targets':{k:{**c['roles'][k],'process':net.process_pin(views[k]['State']['Pid'])} for k in ('minio','postgres')}}
  require(binding['targets']['minio']['process']['namespaces']['net']!=binding['targets']['postgres']['process']['namespaces']['net'] and all(v['process']['namespaces']['net']!=host_net for v in binding['targets'].values()),'DISTINCT_PRIVATE_PROVIDER_NAMESPACES')
  require(all(not views[k]['HostConfig']['PortBindings'] and views[k]['HostConfig']['NetworkMode']=='none' for k in ('minio','postgres')),'NO_PUBLISHED_PROVIDER_PORTS')
  c['networkBindingFile']=str(root/'inputs/network.json');write(Path(c['networkBindingFile']),binding)
  for key in ('s3','onboarding','udp','ingestion'):
   conf={'schema':'ouf.storage-g0-collection-input.v1' if key=='s3' else 'ouf.storage-g0-db-input.v1','operationId':c['operationId']+'-'+key,'installationRef':c['installationRef']}
   if key=='s3':conf['connection']={'endpoint':'http://127.0.0.1:9000','region':'us-east-1','accessKeyFile':str(root/'inputs/access'),'secretKeyFile':str(root/'inputs/secret'),'allowLoopbackHttp':True}
   else:
    password=root/'inputs'/('pass-'+key);password.write_text('127.0.0.1:5432:g0:g0_'+key+':fixture-only-password\n');password.chmod(0o600)
    conf.update(profile=key,host='127.0.0.1',hostaddr='127.0.0.1',port=5432,database='g0',user='g0_'+key,passwordFile=str(password),sslmode='disable',rootCertificateFile='')
   path=root/'inputs'/(key+'.json');write(path,conf);c['connectionFiles'][key]=str(path)
  runtime={'schema':'ouf.storage-g0-operator-evidence.v1','installationRef':c['installationRef'],'section':'RUNTIME','provenance':'TECHNICAL_OBSERVATION','ownerRef':'CI_FIXTURE','capturedAt':'2026-11-06T00:00:00Z','evidenceRefs':['CI_FIXTURE_ONLY'],'storageBuckets':{'onboarding':'ouf-managed-files','udp':'ouf-udp'}};write(root/'inputs/runtime.json',runtime);c['operatorEvidenceFiles']['runtime']=str(root/'inputs/runtime.json')
  for i in range(1,18):
   path=root/'history'/str(i);write(path,{'fixtureControl':i});c['priorReceiptFiles'][i-1]={'control':i,'path':str(path),'sha256':sha(path.read_bytes())}
  config=root/'inputs/package.json';write(config,c);manifest_sha=sha((root/'package/package-manifest.json').read_bytes())
  pre=pkg.preflight(config,root/'package',manifest_sha)[-1];require(pre['targetReads']==0 and not pre['targetCommandAuthorized'],'LOCAL_CHECK_NOT_ADMISSION')
  result=pkg.collect(config,root/'package',manifest_sha);write(out/'network-package-result.json',result)
  scope=root/'evidence'/c['operationId']
  for p in scope.glob('network-entry-*.json'):shutil.copyfile(p,out/p.name)
  for p in scope.glob('*/summary.json'):shutil.copyfile(p,out/(p.parent.name+'-summary.json'))
  require(result['technicalCaptureComplete'] and result['status']=='OBSERVATIONS_SEALED_G0_REVIEW_REQUIRED' and result['sections']['OBJECTS']['verifiedBodies']==2 and result['sections']['DB']['findings']==0 and result['databaseExportsAttempted']==3,'COMPLETE_NAMESPACE_PACKAGE_CAPTURE')
  require(result['engineGets']==28 and result['cumulativeEngineGets']==80 and not result['g0Complete'] and not result['runtimeAuthorityIssued'],'SAME_FINITE_BUDGET_NO_ACCEPTANCE')
  entries=[decode(p.read_bytes()) for p in scope.glob('network-entry-*.json')];require(len(entries)==4 and all(e['enteredNet']==binding['targets'][e['role']]['process']['namespaces']['net'] and e['mountNamespaceUnchanged'] for e in entries),'FOUR_EXACT_NETWORK_ONLY_CHILDREN')
  require(net.namespace('self','net')==host_net and net.namespace('self','mnt')==host_mnt,'PARENT_CONTEXT_PRESERVED')
  try:pkg.collect(config,root/'package',manifest_sha);raise AssertionError('scope replayed')
  except ValueError as e:require(str(e)=='G0_PACKAGE_SCOPE_CONSUMED','EXACT_REPLAY_DENIAL')
  # Deliberately substitute PostgreSQL's namespace FD into the S3 worker.
  bad=root/'bad-fd';bad.mkdir(mode=0o700)
  with net.PinnedNetwork(binding,'minio') as a,net.PinnedNetwork(binding,'postgres') as b:
   args=[sys.executable,'-I','-B','-S',str(root/'package/network-worker.py'),'s3',c['networkBindingFile'],sha(Path(c['networkBindingFile']).read_bytes()),c['connectionFiles']['s3'],str(bad/(c['operationId']+'-s3')),str(b.netfd),str(a.pidfd)]
   denial=net.run_child(args,{'PATH':'/usr/bin:/bin'},(b.netfd,a.pidfd),5,lambda:None)
   require(denial.returncode==1 and decode(denial.stdout)['reason']=='G0_NETWORK_FD_BINDING' and not list(bad.iterdir()),'WRONG_NETWORK_DENIED_BEFORE_COLLECTOR')
  with net.PinnedNetwork(binding,'minio') as a:
   cmd(['docker','stop','--time','30',mi],timeout=45);stopped.add(mi)
   try:a.check();raise AssertionError('dead owner accepted')
   except (ValueError,OSError):pass
  write(out/'native-network.json',{'schema':'ouf.storage-g0-network-native.v1','status':'PASS_DISTINCT_NATIVE_NAMESPACES_NOT_TARGET_ACCEPTANCE','providerImages':{'minio':MINIO,'postgres':PG},'migrationsApplied':migration_count,'providersInDistinctNetworks':True,'publishedPorts':0,'currentOwnerProfiles':3,'conditionalBodies':2,'conditionalBytes':6,'namespaceChildren':4,'stoppedOtherRoleFixtures':11,'parentNetworkAndMountPreserved':True,'wrongNetworkFdDeniedBeforeCollector':True,'deadOwnerDeniedWhileFdHeld':True,'sameOperationReplayDenied':True,'priorReceiptsUnchanged':all(sha(Path(v['path']).read_bytes())==v['sha256'] for v in c['priorReceiptFiles']),'fullApplicationServicesQualified':False,'postgresRemoteTlsQualified':False,'newNamespaceCompositionNative':True,'runtimeAuthorityIssued':False,'targetOperations':0,'acceptanceCreditAdded':0})
 finally:
  exits={}
  for cid in reversed(created):
   v=json.loads(cmd(['docker','inspect',cid]))[0]
   if v['State']['Running']:cmd(['docker','stop','--time','30',cid],timeout=45)
   v=json.loads(cmd(['docker','inspect',cid]))[0];exits[cid]={'exitCode':v['State']['ExitCode'],'oomKilled':v['State']['OOMKilled'],'running':v['State']['Running']};cmd(['docker','rm',cid])
  write(out/'network-fixture-exits.json',exits)
  for p in out.iterdir():
   if p.is_file():p.chmod(0o644)
  require(len(exits)==13 and all(x=={'exitCode':0,'oomKilled':False,'running':False} for x in exits.values()),'CLEAN_NAMESPACE_FIXTURE_STOPS')
if __name__=='__main__':main(Path(sys.argv[1]).resolve())
