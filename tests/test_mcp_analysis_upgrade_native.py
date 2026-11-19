"""Archived MCP binary, V13->14, expired signed files and exact legacy lifecycle."""
import hashlib,http.server,importlib.util,json,os,pathlib,ssl,subprocess,tempfile,threading,time,unittest,uuid
from urllib.parse import parse_qs
ROOT=pathlib.Path(__file__).resolve().parents[1]
def mod(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
u=mod('mcp_upgrade',ROOT/'scripts/upgrade-mcp-analysis-20261108.py')
r=mod('lifecycle',ROOT/'scripts/upgrade-semantic-application-20261108.py')
m=mod('mac',ROOT/'tools/acquisition_read_native/retained_mac.py')
p=mod('preflight',ROOT/'scripts/read-mcp-analysis-preflight-20261108.py');c,h=p.helpers()
D=u.DOCKER
def cmd(*args,**kw):
 p=subprocess.run(args,capture_output=True,timeout=120,**kw)
 if p.returncode:raise AssertionError(p.stderr.decode(errors='replace')[-2500:])
 return p.stdout

class Native(unittest.TestCase):
 def setUp(self):
  self.tag='ouf-mcp-roll-'+uuid.uuid4().hex[:8];self.ids=[];self.e=r.Engine();self.calls={'token':0,'policy':0,'business':0}
  self.temp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.temp.name);self.root.chmod(0o755)
  self.pub=self.root/'public';self.pub.mkdir();self.pub.chmod(0o550);os.chown(self.pub,0,10005)
  for n in ('profile.json','policy.json','permit.json'):
   path=self.pub/n;path.write_bytes((ROOT/'mcp-fixture'/n).read_bytes());os.chown(path,0,10005);path.chmod(0o440)
  self.secrets=self.root/'secrets';self.secrets.mkdir();self.secrets.chmod(0o750);os.chown(self.secrets,0,10005)
  for n,raw in [('client','synthetic-secret'),('fingerprint','f'*64)]:
   path=self.secrets/n;path.write_text(raw);os.chown(path,10005,10005);path.chmod(0o600)
  self.ca=self.root/'ca';self.ca.mkdir();self.ca.chmod(0o755)
  cmd(*D,'load','-i',str(ROOT/'mcp-candidate/image.tar.gz'))
  self.image=json.loads(cmd(*D,'image','inspect','ouf-mcp:ci'))[0]['Id'];self.assertIn(self.image,(u.CONFIG_ID,u.NATIVE_ID))
  cmd(*D,'network','create',self.tag);network=json.loads(cmd(*D,'network','inspect',self.tag))[0];gateway=network['IPAM']['Config'][0]['Gateway']
  self.pg=self.tag+'-pg';cmd(*D,'run','-d','--name',self.pg,'--network',self.tag,'-e','POSTGRES_PASSWORD=synthetic-only','postgres:17');self.ids.append(self.pg)
  for _ in range(60):
   if subprocess.run((*D,'exec',self.pg,'pg_isready','-U','postgres'),capture_output=True).returncode==0:break
   time.sleep(1)
  else:raise AssertionError('postgres not ready')
  self.sql("CREATE ROLE fixture LOGIN SUPERUSER PASSWORD 'synthetic-only'; CREATE DATABASE fixture OWNER fixture;",'postgres','postgres')
  self.sql('CREATE SCHEMA ouf_mcp; CREATE TABLE ouf_mcp.schema_migration(version integer primary key,checksum char(64) not null,applied_at timestamptz not null default transaction_timestamp());')
  for path in sorted((ROOT/'mcp-source/internal/adapter/postgres/migrations').glob('*.sql')):
   version=int(path.name.split('_')[0])
   if version>13:continue
   raw=path.read_bytes();self.assertEqual(hashlib.sha256(raw).hexdigest(),c.MCP_CHECKSUMS[str(version)])
   self.sql("BEGIN;\n"+raw.decode()+"\nINSERT INTO ouf_mcp.schema_migration(version,checksum) VALUES(%d,'%s');\nCOMMIT;"%(version,hashlib.sha256(raw).hexdigest()))
  self.sql('ALTER ROLE fixture NOSUPERUSER NOCREATEROLE NOCREATEDB;', 'postgres')
  self.oid=self.sql('SELECT oid FROM pg_database WHERE datname=current_database();')
  self.sql("INSERT INTO ouf_mcp.manifest_snapshot(manifest_checksum,manifest_version,schema_version,payload) VALUES(repeat('a',64),'fixture-old','fixture','{}');")
  self.sql("INSERT INTO ouf_mcp.application_session(application_session_id,application_conversation_ref,service_principal_id,principal_id,tenant_id,created_manifest_checksum,expires_at) VALUES('11111111-1111-1111-1111-111111111111','keep','fixture','human','tenant',repeat('a',64),now()+interval '1 hour');")
  cmd('openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=fixture',
      '-addext','subjectAltName=IP:'+gateway,'-keyout',str(self.root/'server.key'),'-out',str(self.ca/'ca.pem'))
  outer=self
  class Handler(http.server.BaseHTTPRequestHandler):
   def log_message(self,*args):pass
   def do_POST(self):
    if self.path!='/token':outer.calls['business']+=1;self.send_error(404);return
    values=parse_qs(self.rfile.read(int(self.headers.get('Content-Length','0'))).decode())
    if values!={'grant_type':['client_credentials'],'client_id':['fixture'],'client_secret':['synthetic-secret']}:self.send_error(401);return
    outer.calls['token']+=1;body=b'{"access_token":"synthetic-token","expires_in":3600,"token_type":"Bearer"}'
    self.send_response(200);self.end_headers();self.wfile.write(body)
   def do_GET(self):
    if self.path!='/policy':outer.calls['business']+=1;self.send_error(404);return
    if self.headers.get('Authorization')!='Bearer synthetic-token':self.send_error(401);return
    outer.calls['policy']+=1
    bundle={'bundleId':'fixture','version':1,'publishedAt':'2026-01-01T00:00:00Z','capabilities':[],'grants':[]}
    raw=json.dumps(bundle,separators=(',',':')).encode();body=json.dumps({'bundleId':'fixture','bundleVersion':1,'activatedAt':'2026-01-01T00:00:01Z','bundle':bundle,'contentHash':hashlib.sha256(raw).hexdigest()},separators=(',',':')).encode()
    self.send_response(200);self.end_headers();self.wfile.write(body)
  self.server=http.server.ThreadingHTTPServer(('0.0.0.0',0),Handler);ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(str(self.ca/'ca.pem'),str(self.root/'server.key'));self.server.socket=ctx.wrap_socket(self.server.socket,server_side=True)
  self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start();self.origin='https://'+gateway+':'+str(self.server.server_port)
 def tearDown(self):
  if hasattr(self,'server'):self.server.shutdown();self.server.server_close()
  for cid in self.ids:subprocess.run((*D,'rm','-f',cid),capture_output=True)
  subprocess.run((*D,'network','rm',self.tag),capture_output=True);self.temp.cleanup()
 def sql(self,body,user='fixture',database='fixture'):
  return cmd(*D,'exec','-i',self.pg,'psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-U',user,'-d',database,input=body.encode()).decode().strip()
 def read(self,label):
  report={'readOnlyDatabaseSessionsAttempted':0};doc=self.current;pg=self.e.inspect(self.sql_pg_id)
  return u.read_database(p,c,h,doc,pg,self.root,label,report)
 def ready(self,cid):
  for _ in range(40):
   doc=self.e.inspect(cid)
   if not doc['State']['Running']:raise AssertionError(cmd(*D,'logs',cid).decode())
   if u.readiness(doc):return doc
   time.sleep(1)
  raise AssertionError('MCP not ready: '+cmd(*D,'logs',cid).decode())
 def exercise(self,explicit):
  mac='02:42:ac:44:01:07';binds=[str(self.pub)+':/run/fixture-public:ro',str(self.secrets)+':/run/fixture-secrets:ro',str(self.ca)+':/run/fixture-ca:ro']
  env=['MCP_DATABASE_URL=postgres://fixture:synthetic-only@'+self.pg+':5432/fixture?sslmode=disable',
   'MCP_OIDC_CLIENT_ID=fixture','MCP_OIDC_CLIENT_SECRET_FILE=/run/fixture-secrets/client','MCP_OIDC_TOKEN_ENDPOINT='+self.origin+'/token',
   'MCP_AUTHORIZATION_BUNDLE_ENDPOINT='+self.origin+'/policy','MCP_GATEWAY_ENDPOINT='+self.origin+'/execute',
   'MCP_FINGERPRINT_KEY_FILE=/run/fixture-secrets/fingerprint','SSL_CERT_FILE=/run/fixture-ca/ca.pem',
   'MCP_MANAGED_UPLOAD_ENABLED=picker','MCP_MANAGED_FILE_PICKER_URL='+self.origin+'/trusted-human/managed-files/',
   'MCP_REPROCESSING_KEY_PROFILE_FILE=/run/fixture-public/profile.json','MCP_REPROCESSING_PERMIT_FILE=/run/fixture-public/permit.json',
   'MCP_REPROCESSING_EXISTING_POLICY_FILE=/run/fixture-public/policy.json','MCP_REPROCESSING_KEY_PROFILE_SHA256='+(ROOT/'mcp-fixture/profile.sha256').read_text()]
  req={'Image':self.image,'User':'10005:10005','WorkingDir':'/app','Env':env,'Entrypoint':u.ENTRY,'Cmd':u.APP,
   'HostConfig':{'NetworkMode':self.tag,'RestartPolicy':{'Name':'no','MaximumRetryCount':0},'Binds':binds},
   'NetworkingConfig':{'EndpointsConfig':{self.tag:{'MacAddress':mac,'Aliases':['mcp-fixture']}}}}
  if explicit:req['MacAddress']=mac
  cid=self.e.api('POST','/containers/create?name='+self.tag,req)['Id'];self.ids.append(cid);self.e.api('POST','/containers/'+cid+'/start');self.e.api('POST','/containers/'+cid+'/kill?signal=USR1')
  old=self.ready(cid);self.assertEqual(old['Config'].get('MacAddress'),mac,'required real legacy MAC precondition');self.current=old;self.sql_pg_id=json.loads(cmd(*D,'inspect',self.pg))[0]['Id']
  before=self.read('before');u.verify_database(before,c.MCP_CHECKSUMS,self.oid)
  sentinel=self.sql("SELECT row_to_json(t) FROM ouf_mcp.application_session t WHERE application_conversation_ref='keep'")
  pub={n:(self.pub/n).read_bytes() for n in ('profile.json','policy.json','permit.json')}
  report={};events={};replacement=u.request(old,self.image)
  try:self.current=u.replace(r,self.e,old,replacement,m,lambda k,v:events.setdefault(k,v),report)
  finally:
   if report.get('replacementContainerId'):self.ids.append(report['replacementContainerId'])
  u.gate_running(self.current);self.assertEqual(r.file_sha(pathlib.Path('/proc',str(self.current['State']['Pid']),'root/usr/local/bin/ouf-mcp')),u.BINARY_SHA)
  self.assertEqual(cmd(*D,'exec',self.current['Id'],'id','-u').strip(),b'10005')
  migrated=u.migrate(self.current['Id']);self.assertEqual(migrated.returncode,0,migrated.stderr.decode());after=self.read('after');u.verify_database(after,c.MCP_CHECKSUMS,self.oid,before)
  self.e.api('POST','/containers/'+self.current['Id']+'/kill?signal=USR1');self.current=self.ready(self.current['Id']);r.verify_replacement(old,replacement,self.current,True)
  r.detached(m,old,self.e.inspect(old['Id']),old['Name']+'-before-analysis-20261108');u.verify_database(self.read('final'),c.MCP_CHECKSUMS,self.oid,before)
  self.assertEqual(sentinel,self.sql("SELECT row_to_json(t) FROM ouf_mcp.application_session t WHERE application_conversation_ref='keep'"))
  self.assertEqual(pub,{n:(self.pub/n).read_bytes() for n in pub});self.assertEqual(self.calls['business'],0)
  self.assertGreaterEqual(self.calls['token'],2);self.assertGreaterEqual(self.calls['policy'],2)
  print(json.dumps({'profile':'EXPLICIT_LEGACY_CONFIG' if explicit else 'ENDPOINT_ONLY_COMPAT_CONFIG',
   'legacyInitiallyPresent':True,'transition':report['oldMacTransition'],'image':self.image,'exactArchivedBinary':True,
   'ordinaryRoleMigration13To14':True,'priorHistoryAndSessionPreserved':True,'expiredSignedFilesUnchanged':True,
   'clientCredentialsAndPolicyTls':True,'readinessHttpStatus':204,'oldRetainedStopped':True,'productionAccess':False}),flush=True)
 def test_explicit_legacy(self):self.exercise(True)
 def test_endpoint_only_legacy(self):self.exercise(False)

if __name__=='__main__':unittest.main(verbosity=2)
