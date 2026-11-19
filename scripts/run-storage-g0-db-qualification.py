#!/usr/bin/env python3
"""Disposable PostgreSQL + conditional MinIO body observation integration."""
import argparse,copy,hashlib,importlib.util,json,os,re,shutil,subprocess,sys,tarfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from tools.storage_planning import g0_database as db
from tools.storage_planning.g0_reconciliation import reconcile
from tools.storage_planning.inventory_manifest import canonical,decode,require,sha
spec=importlib.util.spec_from_file_location('g0fixture',ROOT/'scripts/run-storage-g0-qualification.py');base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
PG='postgis/postgis:17-3.5-alpine'
APPS={'onboarding':('onboarding-source','ouf-source-onboarding'),'udp':('udp-source','ouf-udp-object-resolution'),'ingestion':('ingestion-source','ouf-ingestion-runtime')}
def cmd(args,timeout=120,input=None,check=True):
 r=subprocess.run(args,input=input,capture_output=True,text=True,timeout=timeout)
 if check:require(r.returncode==0,'FIXTURE_COMMAND_FAILED:'+args[0]+':'+r.stderr[-3000:])
 return r.stdout.strip() if check else r
def write(p,x):p.write_bytes(canonical(x));p.chmod(0o600)
def stage(w):
 require(os.environ.get('GITHUB_ACTIONS')=='true' and not w.exists(),'NEW_CI_SCOPE');w.mkdir(mode=0o700)
 for n in ['evidence','private','scan','module','tls','data']:(w/n).mkdir(mode=0o700)
 for p in (ROOT/'tools/storage_inventory').iterdir():
  if p.suffix=='.go' or p.name in ['go.mod','go.sum']:shutil.copyfile(p,w/'module'/p.name)
 shutil.copyfile(ROOT/'tests/fixtures/storage-g0-db/seed_test.go',w/'module/g0_db_seed_test.go')
 with (w/'evidence/unit.log').open('w') as log:subprocess.run([sys.executable,'-m','unittest','discover','-s','tests','-p','test_storage_g0_database.py','-v'],cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=60)
 for args in [['build','-trimpath','-o',str(w/'scan/inventory'),'.'],['test','-c','-o',str(w/'scan/inventory.test')]]:subprocess.run(['go',*args],cwd=w/'module',env=dict(os.environ,GOTOOLCHAIN='go1.27.3',GOMAXPROCS='2'),check=True,timeout=300)
 write(w/'evidence/executables.json',{p.name:sha(p.read_bytes()) for p in (w/'scan').iterdir()})
 for profile,(directory,_) in APPS.items():require(cmd(['git','-C',str(ROOT/directory),'rev-parse','HEAD'])==db.SOURCES[profile],'EXACT_APPLICATION_SOURCE')
def config(w,profile,op):
 role='g0_'+profile.split('-')[0];p=w/'private'/('password-'+role)
 if not p.exists():p.write_text('127.0.0.1:15432:g0:'+role+':fixture-only-password\n');p.chmod(0o600)
 c={'schema':'ouf.storage-g0-db-input.v1','operationId':op,'installationRef':'synthetic-db-integration','profile':profile,'host':'127.0.0.1','hostaddr':'127.0.0.1','port':15432,'database':'g0','user':role,'passwordFile':str(p),'sslmode':'disable','rootCertificateFile':''}
 path=w/'private'/(op+'.json');write(path,c);return path
def observe(w,profile,op):
 r=db.export(config(w,profile,op),w/'private'/op);write(w/'evidence'/(op+'-summary.json'),r);return r
def inside(w,profile):
 require(os.environ.get('OUF_G0_DB_FIXTURE')=='true','EXPLICIT_FIXTURE_NAMESPACE')
 if profile=='retained':
  r=observe(w,'onboarding-retained','retained');require(r['complete'],'RETAINED_EXPORT_FAILED');shutil.copyfile(w/'private/retained/export.private.jsonl',w/'evidence/retained-synthetic.jsonl');return
 if profile=='rls':
  r=observe(w,'udp','rls-held');require(not r['complete'] and r['reason']=='G0_DB_QUERY_FAILED' and not (w/'private/rls-held/export.private.jsonl').exists(),'RLS_MUST_NOT_SILENTLY_FILTER');return
 if profile=='revoked':
  r=observe(w,'udp','privilege-held');require(not r['complete'] and r['reason']=='G0_DB_QUERY_FAILED','REVOKED_PRIVILEGE_MUST_HOLD');return
 require(profile=='current','KNOWN_FIXTURE_PHASE')
 with (w/'evidence/body-seed.log').open('w') as log:subprocess.run([str(w/'scan/inventory.test'),'-test.v','-test.run=^TestG0DBSeed$','-test.timeout=120s'],env=dict(os.environ,OUF_G0_DB_WORK=str(w)),stdout=log,stderr=subprocess.STDOUT,check=True,timeout=130)
 exports={}
 for p in APPS:
  r=observe(w,p,p);require(r['complete'],'NATIVE_EXPORT_FAILED_'+p.upper());raw=(w/'private'/p/'export.private.jsonl').read_bytes();exports[p]=db.parse_export(raw,p);(w/'evidence'/(p+'-synthetic.jsonl')).write_bytes(raw)
 try:db.export(w/'private/onboarding.json',w/'private/onboarding');raise AssertionError('consumed scope replayed')
 except FileExistsError:pass
 # A retained profile is not accepted against the upgraded schema.
 incompatible=observe(w,'onboarding-retained','wrong-profile');require(not incompatible['complete'],'INSTALLED_SCHEMA_NOT_INFERRED')
 collection=decode((w/'private/bodies/collection.private.json').read_bytes());write(w/'evidence/synthetic-body-collection.json',collection)
 writers={'schema':'ouf.storage-g0-writer-census.v1','installationRef':'synthetic-db-integration','paths':[]};buckets={'onboarding':'ouf-managed-files','udp':'ouf-udp'}
 result=reconcile(collection,exports,buckets,writers);write(w/'evidence/reconciliation.json',result);require(result['findingsCount']==0 and result['classifiedBodies']==2 and not result['g0Complete'],'RELATIONAL_BODY_JOIN')
 negative={}
 for case in ['missing-body','raw-hash','ack-receipt','watermark','lineage-run','partial-export']:
  c=copy.deepcopy(collection);e=copy.deepcopy(exports)
  if case=='partial-export':
   try:db.parse_export((w/'evidence/udp-synthetic.jsonl').read_bytes().rsplit(b'\n',2)[0],'udp');raise AssertionError('partial accepted')
   except ValueError:negative[case]=True;continue
  if case=='missing-body':c['objects'].pop()
  if case=='raw-hash':e['ingestion']['sections']['ouf_ingestion.ing_lineage']['rows'][0]['raw_hash']='sha256:'+'0'*64
  if case=='ack-receipt':e['ingestion']['sections']['ouf_ingestion.handoff_outbox']['rows'][0]['downstream_receipt_ref']='wrong'
  if case=='watermark':e['ingestion']['sections']['ouf_ingestion.ing_watermark']['rows'][0]['watermark_sha256']='0'*64
  if case=='lineage-run':e['ingestion']['sections']['ouf_ingestion.ing_lineage']['rows'][0]['run_id']='missing'
  negative[case]=reconcile(c,e,buckets,writers)['findingsCount']>0
 require(all(negative.values()),'NEGATIVE_RELATIONAL_CASES')
 write(w/'evidence/native-db.json',{'schema':'ouf.storage-g0-db-native.v1','status':'PASS_SYNTHETIC_NOT_TARGET_ACCEPTANCE','currentProfiles':3,'retainedProfileAlsoQualified':True,'conditionalBodies':2,'conditionalBytes':6,'separateRepeatableReadSnapshots':True,'sameOperationReplayDenied':True,'incompatibleSchemaDenied':True,'rawHashDistinctFromCanonicalOutputHash':True,'negativeCases':negative,'g0Complete':False,'runtimeAuthorityIssued':False,'targetOperations':0})
def run(w):
 require(os.environ.get('GITHUB_ACTIONS')=='true','CI_ONLY');scan=decode((w/'evidence/trivy.json').read_bytes());require({'inventory','inventory.test'}<={Path(x['Target']).name for x in scan.get('Results',[]) if x.get('Type')=='gobinary'},'EXECUTABLE_SCANS_REQUIRED');require(not any(v.get('Severity','UNKNOWN') in ('HIGH','CRITICAL','UNKNOWN') for x in scan['Results'] for v in x.get('Vulnerabilities',[]) or []),'TOOL_SECURITY_HELD')
 require(shutil.which('psql'),'PSQL_REQUIRED');cmd(['docker','pull',PG],300);pgview=json.loads(cmd(['docker','image','inspect',PG]))[0];pgid=pgview['Id'];uid=cmd(['docker','run','--rm','--network','none','--entrypoint','id',pgid,'-u','postgres']);gid=cmd(['docker','run','--rm','--network','none','--entrypoint','id',pgid,'-g','postgres'])
 cmd(['docker','pull',base.MINIO],300);require(json.loads(cmd(['docker','image','inspect',base.MINIO]))[0]['Id']==base.MINIO_ID,'EXACT_MINIO')
 cmd(['openssl','req','-x509','-newkey','rsa:3072','-sha256','-nodes','-days','1','-subj','/CN=OUF synthetic DB integration','-addext','subjectAltName=IP:127.0.0.1','-keyout',str(w/'tls/private.key'),'-out',str(w/'tls/public.crt')]);(w/'tls/private.key').chmod(0o600)
 pg='g0-db-'+os.environ['GITHUB_RUN_ID'];minio=pg+'-minio';created=[];out=w/'evidence'
 def admin(sql,check=True):return cmd(['docker','exec','-i',pg,'psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-U','postgres','-d','g0','-p','15432'],input=sql,check=check)
 def grants(profile):
  role='g0_'+profile.split('-')[0]
  schemas={t.split('.')[0] for t in db.TABLES[profile]};admin(''.join('GRANT USAGE ON SCHEMA '+s+' TO '+role+';' for s in schemas)+''.join('GRANT SELECT ON '+t+' TO '+role+';' for t in db.TABLES[profile]))
 try:
  cmd(['docker','run','-d','--name',pg,'--network','none','--user',uid+':'+gid,'--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','1g','--cpus','2','--pids-limit','128','--tmpfs','/var/lib/postgresql/data:rw,nosuid,size=536870912,uid='+uid+',gid='+gid+',mode=0700','--tmpfs','/var/run/postgresql:rw,nosuid,size=8388608,uid='+uid+',gid='+gid+',mode=0770','--tmpfs','/tmp:rw,nosuid,size=67108864,mode=1777','-e','POSTGRES_PASSWORD=fixture-only-admin','-e','POSTGRES_DB=g0',pgid,'postgres','-p','15432']);created.append(pg)
  until=time.monotonic()+90
  while True:
   r=cmd(['docker','exec',pg,'pg_isready','-h','127.0.0.1','-U','postgres','-d','g0','-p','15432'],check=False)
   if r.returncode==0:
    probe=admin('SELECT PostGIS_Version();',check=False)
    if probe.returncode==0:break
   require(time.monotonic()<until,'POSTGRES_READY_DEADLINE');time.sleep(1)
  view=json.loads(cmd(['docker','inspect',pg]))[0];ns=['sudo','-n','nsenter','-t',str(view['State']['Pid']),'-n'];links=json.loads(cmd(ns+['ip','-j','link']));routes=json.loads(cmd(ns+['ip','-j','route']));require([x['ifname'] for x in links]==['lo'] and not routes and not view['HostConfig']['PortBindings'],'ISOLATED_PG_NAMESPACE')
  insidecmd=ns+['setpriv','--reuid',str(os.getuid()),'--regid',str(os.getgid()),'--clear-groups','env','OUF_G0_DB_FIXTURE=true',sys.executable,'-I','-B','-S',str(Path(__file__).resolve())]
  cmd(['docker','run','-d','--name',minio,'--network','container:'+pg,'--user',str(os.getuid())+':'+str(os.getgid()),'--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','1g','--cpus','2','--pids-limit','128','--tmpfs','/tmp:rw,nosuid,size=67108864,mode=1777','--mount','type=bind,src='+str(w/'data')+',dst=/data','--mount','type=bind,src='+str(w/'tls')+',dst=/tls,readonly','-e','MINIO_ROOT_USER=synthetic-g0-admin','-e','MINIO_ROOT_PASSWORD=synthetic-g0-secret-not-production',base.MINIO_ID,'server','/data','--address',':18443','--console-address',':19001','--certs-dir','/tls']);created.append(minio)
  readiness='import ssl,urllib.request,time\nc=ssl.create_default_context(cafile='+repr(str(w/'tls/public.crt'))+')\ne=time.monotonic()+60\nwhile True:\n try:\n  assert urllib.request.urlopen("https://127.0.0.1:18443/minio/health/ready",context=c,timeout=2).status==200;break\n except Exception:\n  if time.monotonic()>e:raise\n  time.sleep(1)\n';cmd(ns+[sys.executable,'-I','-B','-S','-c',readiness],70)
  for p in APPS:admin('CREATE ROLE g0_'+p+" LOGIN PASSWORD 'fixture-only-password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; ALTER ROLE g0_"+p+" SET default_transaction_read_only=on;")
  migration_count={}
  for profile,(directory,_) in APPS.items():
   files=sorted((ROOT/directory/'src/main/resources/db/migration').glob('V*.sql'),key=lambda p:int(re.match('V([0-9]+)',p.name)[1]));migration_count[profile]=len(files)
   for f in files:
    n=int(re.match('V([0-9]+)',f.name)[1]);admin('SET search_path=ouf_'+profile+',public;\n'+f.read_text())
    if profile=='onboarding' and n==38:grants('onboarding-retained');cmd(insidecmd+['inside',str(w),'--profile','retained'],180)
   grants(profile)
  admin((ROOT/'tests/fixtures/storage-g0-db/seed.sql').read_text())
  # Privileges deny DML even if the session attempts to opt out of read-only.
  denied=admin("SET ROLE g0_udp; SET default_transaction_read_only=off; INSERT INTO ouf_udp.lake_object(lake_object_id) VALUES(gen_random_uuid());",check=False);require(denied.returncode!=0 and 'permission denied' in denied.stderr,'ROLE_DML_DENIED')
  cmd(insidecmd+['inside',str(w),'--profile','current'],600)
  admin('ALTER TABLE ouf_udp.lake_object ENABLE ROW LEVEL SECURITY; CREATE POLICY hide_all ON ouf_udp.lake_object FOR SELECT TO g0_udp USING(false);');cmd(insidecmd+['inside',str(w),'--profile','rls'],180)
  admin('ALTER TABLE ouf_udp.lake_object DISABLE ROW LEVEL SECURITY; REVOKE SELECT ON ouf_udp.lake_object FROM g0_udp;');cmd(insidecmd+['inside',str(w),'--profile','revoked'],180)
  write(out/'database-isolation.json',{'postgresImageRequested':PG,'postgresImageId':pgid,'postgresRepoDigests':pgview.get('RepoDigests'),'serverVersion':admin('SELECT version();'),'clientVersion':cmd(['psql','--version']),'migrationsApplied':migration_count,'interfaces':links,'routes':routes,'publishedPorts':view['HostConfig']['PortBindings'],'readOnlyRoot':view['HostConfig']['ReadonlyRootfs'],'capDrop':view['HostConfig']['CapDrop'],'roleDmlDenied':True,'rowSecurityHeldWithoutSilentFiltering':True,'revokedSelectHeld':True,'fixtureTlsMode':'loopback-only PostgreSQL; verified TLS MinIO','runtimeAuthorityIssued':False,'targetOperations':0})
 finally:
  exits={}
  for name in reversed(created):
   logs=cmd(['docker','logs',name],check=False);(out/(name+'-server.log')).write_text((logs.stdout+logs.stderr)[-32768:]);cmd(['docker','stop','--time','30',name],45);state=json.loads(cmd(['docker','inspect',name]))[0]['State'];exits[name]={'exitCode':state['ExitCode'],'oomKilled':state['OOMKilled'],'running':state['Running']};cmd(['docker','rm',name])
  write(out/'exits.json',exits);require(all(x=={'exitCode':0,'oomKilled':False,'running':False} for x in exits.values()),'CLEAN_FIXTURE_STOPS')
def seal(w):
 out=w/'evidence';out.mkdir(parents=True,exist_ok=True);sources={}
 selected=['tools/storage_planning/g0_database.py','tools/storage_planning/g0_reconciliation.py','tools/storage_planning/inventory_manifest.py','scripts/run-storage-g0-qualification.py','scripts/run-storage-g0-db-qualification.py','.github/workflows/storage-g0-db-qualification.yml','tests/test_storage_g0_database.py']
 selected += [str(p.relative_to(ROOT)) for p in (ROOT/'tools/storage_inventory').iterdir() if p.suffix=='.go' or p.name in ['go.mod','go.sum']]
 selected += [str(p.relative_to(ROOT)) for p in (ROOT/'tests/fixtures/storage-g0-db').iterdir() if p.is_file()]
 for p in selected:sources[p]=(ROOT/p).read_bytes()
 bindings={'deploy':os.environ['GITHUB_SHA']}
 for profile,(directory,repo) in APPS.items():
  bindings[repo]=cmd(['git','-C',str(ROOT/directory),'rev-parse','HEAD'])
  for f in (ROOT/directory/'src/main/resources/db/migration').glob('V*.sql'):sources[repo+'/'+str(f.relative_to(ROOT/directory))]=f.read_bytes()
 with tarfile.open(out/'sources.tar.gz','w:gz') as tar:
  import io
  for path,data in sorted(sources.items()):info=tarfile.TarInfo(path);info.size=len(data);info.mode=0o644;tar.addfile(info,io.BytesIO(data))
 write(out/'source-sha256.json',{p:sha(b) for p,b in sources.items()});write(out/'source-commits.json',bindings)
 total=0
 for p in out.iterdir():require(p.is_file() and not p.is_symlink(),'REGULAR_EVIDENCE');b=p.read_bytes();total+=len(b);require(len(b)<=8<<20 and total<=32<<20 and b'-----BEGIN PRIVATE KEY' not in b,'BOUNDED_SYNTHETIC_EVIDENCE')
 (out/'SHA256SUMS').write_text(''.join(sha(p.read_bytes())+'  '+p.name+'\n' for p in sorted(out.iterdir()) if p.name!='SHA256SUMS'))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('action',choices=['stage','run','seal','inside']);p.add_argument('work',type=Path);p.add_argument('--profile');a=p.parse_args()
 if a.action=='inside':inside(a.work.resolve(),a.profile)
 else:globals()[a.action](a.work.resolve())
