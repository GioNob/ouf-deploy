"""Exact V35 native effects in disposable CI; target history is not reproduced.

Actual Engine, PostgreSQL17/Flyway, candidate CI image, Ed25519, controlling PTY,
custom backup, generation custody, CAS and parent-loss quarantine. Historical
bootstrap/admission metadata and the six non-application service roles are
explicit fixture inputs; no target credentials or runtime authority exist here.
"""
import copy,fcntl,gzip,hashlib,http.client,importlib.util,json,os,pty,re,select,shutil,signal,stat,subprocess,sys,tempfile,termios,time,types,unittest,uuid
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[3]if Path(__file__).parent.name=='tests'else Path(__file__).parent
def file(repo,local):
    p=ROOT/repo;return p if p.exists()else ROOT/local
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);v=importlib.util.module_from_spec(spec);sys.modules[name]=v;spec.loader.exec_module(v);return v
old=module('v35_native_existing_metadata',file('tools/ingestion_readiness_patch_execution/tests/test_onboarding_engine_metadata.py','test_onboarding_engine_metadata.py'))
m,d,r=old.m,old.d,old.r
q=module('v35_native_current_sql',file('scripts/read-current-onboarding-database-20261024.py','read-current-onboarding-database-20261024.py'))
p=module('v35_native_package',file('scripts/prepare-onboarding-v35-review-inputs-20261024.py','prepare-onboarding-v35-review-inputs-20261024.py'))
n=module('v35_native_frozen_compiler',file('scripts/freeze-onboarding-v35-native-plan-20261024.py','freeze-onboarding-v35-native-plan-20261024.py'))
core=module('v35_native_protocol',file('tools/onboarding_v35_native/protocol.py','onboarding_v35_execution_protocol.py'))
ports=module('v35_native_ports',file('tools/onboarding_v35_native/ports.py','onboarding_v35_native_ports.py'))
quarantine=module('v35_native_quarantine',file('tools/onboarding_v35_native/quarantine.py','onboarding_v35_quarantine.py'));ports.quarantine=quarantine
entry=module('v35_native_entry',file('scripts/apply-onboarding-v35-native-20261024.py','apply-onboarding-v35-native-20261024.py'))
from tools.ingestion_readiness_patch_execution import runtime_bindings
from tools.chatbot_file_cohort import gateway
from tools.semantic_registry_recovery_execution import postboot_authority
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator
import image_custody
CONFIG=file('tools/source_revision_update/configuration.py','v35-retained-configuration.py').read_bytes()
REPLACEMENT=file('tools/source_revision_update/plan.py','v35-retained-replacement.py').read_bytes()
IMPORT_RAW=file('tools/ingestion_readiness_patch_execution/image_import.py','v35-retained-image-import.py').read_bytes()
def private(path,value,mode=0o400):
    raw=value if type(value)is bytes else core.encoded(value);path.write_bytes(raw);path.chmod(mode);return core.sha(raw)
def fixture_trust(root):
    now=int(time.time());bindings={};refs={};keys=[]
    for name,issuer,roles in(('installer','fixture-installer',['DEPLOYMENT_INTENT','FINAL_DEPLOYMENT_APPROVAL']),('attestor','fixture-attestor',['CREATION_ATTESTATION'])):
        path=root/(name+'.key');subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(path)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);path.chmod(0o600)
        public=subprocess.check_output(['openssl','pkey','-in',str(path),'-pubout','-outform','DER']);bindings[name]={'path':str(path),'sha256':core.sha(path.read_bytes())};refs[name]='fixture-'+name+'-key'
        keys.append({'keyRef':refs[name],'issuerRef':issuer,'roles':roles,'publicKey':public[-32:].hex(),'notBefore':now-60,'expiresAt':now+3600,'state':'ACTIVE'})
    policy={'schema':'ouf.semantic-deployment-trust-policy.v1','installationRef':'fixture-installation','entityRef':'fixture-entity','keys':keys}
    policy_binding={'path':str(root/'policy.json'),'sha256':private(root/'policy.json',policy,0o600)}
    openssl=Path(shutil.which('openssl')).resolve();version=re.match(rb'OpenSSL ([0-9.]+[a-z]?)\b',subprocess.check_output([str(openssl),'version'])).group(1).decode()
    inputs={'trustPolicy':policy_binding,'executables':{'openssl':{'path':str(openssl),'sha256':core.sha(openssl.read_bytes()),'version':version}},
        'context':{'installationRef':'fixture-installation','entityRef':'fixture-entity','attestorRef':'fixture-attestor','intentIssuerRef':'fixture-installer','approvalIssuerRef':'fixture-installer'}}
    return inputs,{'keyBindings':bindings,'keyRefs':refs},policy

def minimal_review(root,inputs):
    plan={'frozenPlanHash':entry.FROZEN_HASH}
    return {'schema':'ouf.onboarding-v35-native-review.v1','executionRoot':str(root),'maximumSeconds':900,'maximums':copy.deepcopy(core.LIMITS),
        'stages':list(core.STAGES),'frozenPlanHash':entry.FROZEN_HASH,'nativePlan':plan,'nativePlanHash':core.digest(plan),'sourceClosure':{},'sourceClosureHash':core.digest({}),
        'logicalOperationRef':'a'*64,'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'negativeCleanup':{'maximumAdditionalSeconds':30,'startupSeconds':180,'candidateStopOnly':True,'maximumStops':1},
        'verification':{**inputs['executables'],'trustPolicy':inputs['trustPolicy'],'context':inputs['context']},'preflightCounts':{k:0 for k in core.LIMITS},
        'databaseRestoreAuthorized':False,'humanBudgetOrSourceActivationAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}

def tty_call(callback,wrong=False,kill_after_start_root=None):
    master,slave=pty.openpty();pid=os.fork()
    if pid==0:
        try:
            os.close(master);os.setsid();fcntl.ioctl(slave,termios.TIOCSCTTY,0)
            for fd in(0,1,2):os.dup2(slave,fd)
            if slave>2:os.close(slave)
            callback();os._exit(0)
        except BaseException as error:
            # CI fixtures have no service secrets, but keep exception to a code.
            print('FIXTURE_EXCEPTION '+type(error).__name__+': '+str(error),flush=True);os._exit(2)
    os.close(slave);data=b'';approved=False;deadline=time.monotonic()+800;killed=False
    try:
        while time.monotonic()<deadline:
            ready,_,_=select.select([master],[],[],.2)
            if ready:
                try:chunk=os.read(master,65536)
                except OSError:chunk=b''
                data+=chunk
                if len(data)>1048576:raise AssertionError('bounded fixture output')
            if not approved:
                match=re.search(rb'Scrivi APPROVO ([a-f0-9]{64}).*?\r?\n> ',data,re.S)
                if match:
                    os.write(master,b'APPROVO '+(b'0'*64 if wrong else match.group(1))+b'\n');approved=True
            if kill_after_start_root and not killed:
                path=Path(kill_after_start_root)/'recovery.json'
                if path.exists():
                    row=json.loads(path.read_bytes())
                    if row['nextStage']==9 and row.get('createdGeneration'):
                        os.kill(pid,signal.SIGKILL);killed=True
            ended,status=os.waitpid(pid,os.WNOHANG)
            if ended:return os.waitstatus_to_exitcode(status),data,approved,killed
        os.kill(pid,signal.SIGKILL);os.waitpid(pid,0);raise AssertionError('finite CI controller deadline: '+data[-3000:].decode(errors='replace'))
    finally:os.close(master)

@unittest.skipUnless(Path('/proc/sys/kernel/random/boot_id').exists(),'native boot custody required')
class Guards(unittest.TestCase):
    def test_exact_policy_tamper_wrong_terminal_and_dual_signature_scope(self):
        with tempfile.TemporaryDirectory(dir=ROOT)as directory:
            root=Path(directory);root.chmod(0o700);inputs,profile,policy=fixture_trust(root);review=minimal_review(root,inputs)
            code,output,approved,_=tty_call(lambda:core.terminal_decision(review,root/'review.json'),wrong=True)
            self.assertTrue(approved);self.assertEqual(code,2);self.assertIn(b'EXACT_V35_REVIEW_NOT_APPROVED',output);self.assertFalse((root/'authority').exists())
            decision={'reviewHash':core.digest(review),'decision':core.DECISION,'approvedAt':int(time.time())}
            gate=core.issue(review,root,profile,decision,m.new_file,r.json_at);self.assertEqual(gate.check()['state'],'ACTIVE')
            self.assertTrue(all(stat.S_IMODE(f.stat().st_mode)==0o600 for f in(root/'authority').glob('*.DEPLOYMENT_INTENT.json')))
            sig=root/'authority'/(core.sha(gate.raw)+'.FINAL_DEPLOYMENT_APPROVAL.json');saved=sig.read_bytes();sig.unlink()
            with self.assertRaises(Exception):gate.check()
            private(sig,saved,0o600);gate.check()
            altered=copy.deepcopy(review);altered['nativePlan']['foreign']=True;altered['nativePlanHash']=core.digest(altered['nativePlan'])
            with self.assertRaises(Exception):core.SignedAuthority(altered,gate.raw,str(root/'authority/human.json'),core.digest(json.loads((root/'authority/human.json').read_bytes())),gate.verifier,r.json_at)
            policy['keys'][0]['state']='REVOKED';private(root/'policy.json',policy,0o600)
            with self.assertRaises(Exception):gate.check()
            ctx=types.SimpleNamespace(core=core,root=root,check_sources=lambda:None)
            negative=quarantine.check(ctx,review,gate.raw);self.assertEqual(negative['cleanupExpiresAt'],negative['expiresAt']+30)
            copied=DetachedAuthenticator({'path':str(root/'authority/issued-trust-policy.json'),'sha256':inputs['trustPolicy']['sha256']},str(root/'authority'),inputs['executables']['openssl'])
            with self.assertRaisesRegex(core.Stop,'SAME_V35_ROLE_POLICY'):
                core.SignedAuthority(review,gate.raw,str(root/'authority/human.json'),core.digest(json.loads((root/'authority/human.json').read_bytes())),copied,r.json_at)
    def test_no_replay_and_whole_cleanup_key_window_before_signing(self):
        with tempfile.TemporaryDirectory(dir=ROOT)as directory:
            root=Path(directory);root.chmod(0o700);name='onboarding-v35-apply-'+'e'*64
            made=entry.create_context(root,name)
            with self.assertRaises(FileExistsError):entry.create_context(root,name)
            inputs,profile,policy=fixture_trust(made);policy['keys'][0]['expiresAt']=int(time.time())+920
            inputs['trustPolicy']['sha256']=private(made/'policy.json',policy,0o600);review=minimal_review(made,inputs)
            from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
            with patch.object(ExistingEd25519Signer,'sign',side_effect=AssertionError('NO_SIGN_BEFORE_WINDOW')):
                with self.assertRaisesRegex(core.Stop,'FULL_V35_KEY_WINDOW'):core.issue(review,made,profile,{'reviewHash':core.digest(review),'decision':core.DECISION,'approvedAt':int(time.time())},m.new_file,r.json_at)
    def test_actual_signed_journal_guard_reservations_and_claimed_effect_never_replayed(self):
        for fail in(False,True):
            with tempfile.TemporaryDirectory(dir=ROOT)as directory:
                root=Path(directory);root.chmod(0o700);inputs,profile,_=fixture_trust(root);review=minimal_review(root,inputs)
                gate=core.issue(review,root,profile,{'reviewHash':core.digest(review),'decision':core.DECISION,'approvedAt':int(time.time())},m.new_file,r.json_at)
                class ComponentPorts:
                    def __init__(self):self.root=root;self.ctx=types.SimpleNamespace(preflight_counts={k:0 for k in core.LIMITS});self.execution=None;self.dispatched=0
                    def guard(self,stage):self.execution.reserve('engineGets')
                    def execute(self,stage):
                        self.execution.reserve('engineGets');self.dispatched+=1
                        if fail:raise core.Stop('FIXTURE_AMBIGUOUS_EFFECT_NO_REPLAY')
                        return {'componentProof':True}
                    def final_result(self):return self.execution.record()
                adapter=ComponentPorts();execution=core.Execution(gate,Journal(root),adapter);execution.initialize()
                if fail:
                    with self.assertRaisesRegex(core.Stop,'AMBIGUOUS'):execution.run()
                    before=execution.journal.read();self.assertEqual(before['effects'][0]['state'],'CLAIMED')
                    with self.assertRaisesRegex(core.Stop,'CLAIMED_EFFECT'):execution.run()
                    self.assertEqual(execution.journal.read(),before);self.assertEqual(adapter.dispatched,1)
                else:
                    row=execution.run();self.assertEqual(row['state'],'COMPLETE');self.assertEqual(row['counts']['engineGets'],26)
                    self.assertEqual(row['nextStage'],13)
                gate.clock=lambda:time.time()+931
                with self.assertRaises(core.Stop):gate.check()
    def test_exact_limits_native_defaults_and_no_unqualified_restore_or_source_activation(self):
        with tempfile.TemporaryDirectory(dir=ROOT)as directory:
            root=Path(directory);root.chmod(0o700);inputs,_,_=fixture_trust(root);review=minimal_review(root,inputs)
            for key in('automaticReplayAllowed','budgetReset','databaseRestoreAuthorized','humanBudgetOrSourceActivationAuthorized'):
                changed=copy.deepcopy(review);changed[key]=True
                with self.assertRaises(core.Stop):core.validate_review(changed)
            self.assertEqual(core.LIMITS['sqlSessions'],6);self.assertEqual(len(core.STAGES),13)

@unittest.skipUnless(os.environ.get('OUF_NATIVE_V35_APPLY')=='1','root disposable Docker/PG17/real exact CI image required')
class Native(unittest.TestCase):
    def docker(self,*args):return subprocess.check_output(['docker',*args],stderr=subprocess.PIPE).decode().strip()
    def inspect(self,cid):
        from engine_creation import Engine
        selected=Path('/var/run/docker.sock').resolve();info=selected.stat()
        engine=Engine(str(selected),(info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)))
        status,value=engine.request('GET','/v1.44/containers/'+cid+'/json')
        self.assertEqual(status,200);self.assertEqual(value['Id'],cid);return value
    def sql(self,sql):return self.docker('exec',self.pg,'psql','-X','-w','-q','-A','-t','-v','ON_ERROR_STOP=1','-U','pgadmin','-d','onboarding_fixture','-c',sql)
    def health(self,ip):
        try:
            c=http.client.HTTPConnection(ip,8080,timeout=2);c.request('GET','/actuator/health/readiness');response=c.getresponse();body=response.read(262144);c.close();return response.status==200 and json.loads(body)['status']=='UP'
        except (OSError,ValueError):return False
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=ROOT);self.root=Path(self.tmp.name);self.root.chmod(0o700);self.ids=[];self.network='v35-'+self.root.name;self.created=[]
        self.docker('network','create','--subnet','10.203.0.0/24',self.network)
        self.addCleanup(self.cleanup)
        self.pg=self.docker('run','-d','--network',self.network,'--network-alias','fixture-postgres','-e','POSTGRES_USER=pgadmin','-e','POSTGRES_DB=onboarding_fixture','-e','POSTGRES_HOST_AUTH_METHOD=trust','postgres:17');self.ids.append(self.pg)
        until=time.monotonic()+60
        while subprocess.run(['docker','exec',self.pg,'pg_isready','-h','127.0.0.1','-U','pgadmin','-d','onboarding_fixture'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode:
            self.assertLess(time.monotonic(),until);time.sleep(.5)
        self.sql("CREATE ROLE app_role LOGIN PASSWORD 'fixture-password'; CREATE SCHEMA ouf_onboarding AUTHORIZATION app_role; GRANT CREATE ON DATABASE onboarding_fixture TO app_role;")
        owned=self.root/'owned';owned.mkdir(mode=0o750);os.chown(owned,1000,1000)
        self.overlay=owned/'owner.yml';self.overlay.write_text('{"ouf":{"authorization":{"ths":{"enabled":false}}}}');os.chown(self.overlay,10003,10003);self.overlay.chmod(0o400)
        self.custody={str(self.overlay):{'parents':{str(owned):(1000,1000,0o750)},'file':(10003,10003,0o400)}}
        self.custody_patch=patch.object(gateway,'_EXISTING_CONFIG_CUSTODY',self.custody);self.custody_patch.start();self.addCleanup(self.custody_patch.stop)
        for name in('access','secret','token'):private(self.root/name,b'fixture-only',0o444)
        args=['run','-d','--name','v35-onboarding-'+self.root.name,'--network',self.network,'--restart','unless-stopped','--label','org.opencontainers.image.revision='+q.SOURCE]
        env={'OUF_ONB_DB_URL':'jdbc:postgresql://fixture-postgres:5432/onboarding_fixture','OUF_ONB_DB_USER':'app_role','OUF_ONB_DB_PASSWORD':'fixture-password',
            'SPRING_APPLICATION_JSON':'{"ouf.authorization.ths.enabled":false}','SPRING_CONFIG_ADDITIONAL_LOCATION':'file:/fixture/owner.yml',
            'OUF_ONBOARDING_STAGING_ENDPOINT':'http://127.0.0.1:9000','OUF_ONBOARDING_STAGING_BUCKET':'ouf-managed-files',
            'OUF_ONBOARDING_STAGING_ACCESS_KEY_FILE':'/run/secrets/onboarding-minio-access-key','OUF_ONBOARDING_STAGING_SECRET_KEY_FILE':'/run/secrets/onboarding-minio-secret-key',
            'OUF_ONBOARDING_OBJECT_STORE_GATEWAY_BASE_URL':'http://127.0.0.1:9080','OUF_ONBOARDING_OBJECT_STORE_TOKEN_FILE':'/run/ouf-onboarding-auth/token'}
        for k,v in env.items():args+=['-e',k+'='+v]
        for source,target in((self.overlay,'/fixture/owner.yml'),(self.root/'access','/run/secrets/onboarding-minio-access-key'),(self.root/'secret','/run/secrets/onboarding-minio-secret-key'),(self.root/'token','/run/ouf-onboarding-auth/token')):args+=['-v',str(source)+':'+target+':ro']
        self.app=self.docker(*args,os.environ['OUF_V35_OLD_IMAGE']);self.ids.append(self.app);actual=self.inspect(self.app);ip=actual['NetworkSettings']['Networks'][self.network]['IPAddress'];until=time.monotonic()+150
        while not self.health(ip):
            current=self.inspect(self.app)
            if current['RestartCount']>0 or current['State']['Running']is not True:raise AssertionError('B0 fixture process failed: '+self.docker('logs','--tail','80',self.app))
            if time.monotonic()>=until:raise AssertionError('B0 fixture startup failed: '+self.docker('logs','--tail','80',self.app))
            time.sleep(1)
        self.sql('REVOKE CREATE ON DATABASE onboarding_fixture FROM app_role;')
        self.assertEqual(self.sql("SELECT has_database_privilege('app_role','onboarding_fixture','CREATE')"),'f')
        self.seed()
        self.rows={'onboarding':self.inspect(self.app),'postgres':self.inspect(self.pg)}
        for name in('gateway','ingestion','mcp','udp','registry'):
            cid=self.docker('run','-d','--network',self.network,'--label','fixture-service='+name,os.environ['OUF_V35_HOLD_IMAGE']);self.ids.append(cid);self.rows[name]=self.inspect(cid)
        self.ctx=self.context()
    def cleanup(self):
        if hasattr(self,'ctx')and (self.ctx.root/'recovery.json').exists():
            row=json.loads((self.ctx.root/'recovery.json').read_bytes())
            if row.get('createdId'):self.ids.append(row['createdId'])
        for cid in self.ids:subprocess.run(['docker','rm','-f',cid],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        subprocess.run(['docker','network','rm',self.network],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);self.tmp.cleanup()
    def seed(self):
        parent=str(uuid.uuid4());challenge=str(uuid.uuid4());source=d.SOURCE;child=d.VERSION;hashed=d.CONFIGURATION;prior='sha256:'+'a'*64
        self.sql("INSERT INTO ouf_onboarding.source(source_id,name,source_kind,acquisition_mode,owner_ref) VALUES('"+source+"','Fixture','EXTERNAL_API','PULL','fixture-owner');"
            "INSERT INTO ouf_onboarding.onboarding_version(onboarding_version_id,source_id,version,state,configuration_hash,frozen_at) VALUES('"+parent+"','"+source+"',1,'ACTIVE','"+prior+"',clock_timestamp());"
            "INSERT INTO ouf_onboarding.onboarding_version(onboarding_version_id,source_id,version,state,parent_version_id,configuration_hash,frozen_at) VALUES('"+child+"','"+source+"',2,'APPROVED','"+parent+"','"+hashed+"',clock_timestamp());"
            "INSERT INTO ouf_onboarding.approval_challenge(challenge_id,onboarding_version_id,source_id,configuration_hash,status,expires_at,confirmed_at) VALUES('"+challenge+"','"+child+"','"+source+"','"+hashed+"','CONFIRMED',clock_timestamp()-interval '1 hour',clock_timestamp()-interval '2 hours');"
            "INSERT INTO ouf_onboarding.managed_onboarding_review(tenant_id,subject_id,command_key,request_hash,source_id,onboarding_version_id,challenge_id,configuration_hash,readiness_started_at,readiness_attempts,readiness_generation,readiness_phase,readiness_last_code) VALUES('fixture-tenant','fixture-human','review-key','"+hashed+"','"+source+"','"+child+"','"+challenge+"','"+hashed+"',clock_timestamp()-interval '25 hours',3,4,'PAUSED','ONB_READINESS_DEPENDENCY_503');"
            "INSERT INTO ouf_onboarding.source_property_revision(tenant_id,subject_id,command_key,request_hash,source_id,parent_version_id,parent_configuration_hash,onboarding_version_id,publication_effect) VALUES('fixture-tenant','fixture-human','revision-key','"+hashed+"','"+source+"','"+parent+"','"+prior+"','"+child+"','NEW_PUBLICATION_MAY_START_ACQUISITION');")
        self.retained=self.sql("SELECT jsonb_build_object('review',to_jsonb(m),'revision',to_jsonb(r)) FROM ouf_onboarding.managed_onboarding_review m CROSS JOIN ouf_onboarding.source_property_revision r")
    def context(self):
        ctx=entry.Context.__new__(entry.Context);ctx.n=types.SimpleNamespace(definitions=n.definitions,OWNER_OVERLAY=str(self.overlay));ctx.p,ctx.q,ctx.d,ctx.m,ctx.r=p,q,d,m,r
        ctx.core,ctx.ports_module=core,ports;ctx.importer=entry.image_import_definitions(n,IMPORT_RAW);ctx.configuration_raw=CONFIG;ctx.replacement_raw=REPLACEMENT;ctx.preflight_counts={k:0 for k in core.LIMITS};ctx.before=None;ctx.files=m.Facts()
        package=Path(os.environ['OUF_V35_TEST_PACKAGE'])
        with patch.object(p,'PACKAGE',str(package)):ctx.contract,ctx.manifest,ctx.image,ctx.jar=p.packaged(m,ctx.files)
        contract,manifest=ctx.contract,ctx.manifest
        actual=self.rows['onboarding'];oldsave=self.root/'old-image.tar';subprocess.run(['docker','save','-o',str(oldsave),os.environ['OUF_V35_OLD_IMAGE']],check=True)
        with oldsave.open('rb')as stream:tarsha,_=image_custody.hashed(stream,image_custody.LIMIT);stream.seek(0);oldaudit=image_custody.archive(stream,tarsha,json.loads(self.docker('image','inspect',os.environ['OUF_V35_OLD_IMAGE']))[0]['Id'],q.SOURCE)
        native=image_custody.native_identity(oldaudit)
        if actual['Image']==native['nativeImageId']:oldaudit['nativeIdentity']=native
        self.assertEqual(image_custody.runtime_image_id(oldaudit),actual['Image']);ctx.oldplan={'replacements':{'onboarding':{'imageAudit':oldaudit}}}
        ctx.inputs={'currentProcessIdentities':{name:m.process(row)for name,row in self.rows.items()}}
        sock=str(Path('/var/run/docker.sock').resolve());s=Path(sock).stat();engine={'socketPath':sock,'socketBinding':[s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)]}
        from engine_creation import Engine
        ctx.engine=Engine(sock,tuple(engine['socketBinding']))
        identity={'database':'onboarding_fixture','databaseOid':int(self.sql('SELECT oid FROM pg_database WHERE datname=current_database()')),'runtimeRole':'app_role','adminRole':'pgadmin','schema':'ouf_onboarding','postgresPort':5432}
        docker=Path(shutil.which('docker')).resolve();ctx.profile={'schema':'ouf.current-onboarding-database-snapshot-profile.v1','maximumSqlSessionAttempts':1,'identity':identity,
            'sqlSha256':core.sha(q.query(d,'app_role').encode()),'engineBinding':engine,'postgresRuntimeBinding':runtime_bindings.observed(self.rows['postgres'],runtime_bindings.NATIVE),
            'dockerExecutable':{'path':str(docker),'sha256':core.sha(docker.read_bytes())},'containerPrograms':{'env':'/usr/bin/env','timeout':'/usr/bin/timeout','psql':'/usr/bin/psql'},'unixSocketDirectory':'/var/run/postgresql'}
        expected={'path':str(self.overlay),'sha256':core.sha(self.overlay.read_bytes()),'metadata':list(m.identity(self.overlay.stat()))}
        with patch.object(n,'OWNER_OVERLAY',str(self.overlay)):
            verifier=n.configuration_verifier(CONFIG,d,p,m,expected,ctx.jar)
            classification=verifier.verify(actual,{'jar':ctx.jar},self.rows['postgres'],{'database':'onboarding_fixture','user':'app_role','schema':'ouf_onboarding'},5432,contract['applicationYamlSha256'])
        # Compiler gets an actual CI candidate config from its exact image archive.
        import tarfile
        with tarfile.open(package/'image.tar.gz','r:gz')as tar:
            config=json.load(tar.extractfile('blobs/sha256/'+contract['imageId'].split(':')[1]))['config']
        endpoint=actual['NetworkSettings']['Networks'][self.network];saved={'module':'onboarding','name':actual['Name'][1:],'restoreRestartPolicy':actual['HostConfig']['RestartPolicy'],
            'creationRequest':{'HostConfig':copy.deepcopy(actual['HostConfig']),'NetworkingConfig':{'EndpointsConfig':{self.network:{'Aliases':[actual['Name'][1:]]}}}}}
        namespace={'copy':copy,'ipaddress':__import__('ipaddress'),'re':re,'require':entry.require,'digest':core.digest,
            'runtime':lambda a:runtime_bindings.observed(a,runtime_bindings.SORTED),'runtime_image_id':lambda a:a['imageId'],
            'requested_host_config_matches':__import__('engine_creation').requested_host_config_matches}
        compiler=n.definitions(REPLACEMENT,('replacement',),namespace)
        case={'deployedSourceCommits':{'onboarding':q.SOURCE},'candidateSourceCommits':{'onboarding':manifest['testedCommit']},'readiness':{'onboarding':{'readinessPort':8080,'readinessPath':'/actuator/health/readiness'}}}
        replacement=compiler.replacement(saved,actual,{'imageAudit':{'imageId':contract['imageId'],'imageConfig':config},'imageArchive':ctx.image},case,'onboarding')
        logical=core.digest({'fixtureOld':actual['Id'],'candidate':contract['archiveSha256']});parent=self.root/'contexts';parent.mkdir(mode=0o700)
        code_root=self.root/'code';code_root.mkdir(mode=0o700)
        for source,name in((core,'protocol.py'),(ports,'ports.py'),(quarantine,'quarantine.py'),(entry,'apply.py')):
            raw=Path(source.__file__).read_bytes();source.__qualified_source_sha256__=private(code_root/name,raw)
        private(code_root/'image_import.py',IMPORT_RAW)
        helper=code_root/'retained-helper';helper.mkdir(mode=0o700)
        private(helper/'plan.py',Path(n.__file__).read_bytes());private(helper/'configuration.py',CONFIG);private(helper/'replacement.py',REPLACEMENT)
        ctx.authority_inputs,self.signing_profile,self.public_policy=fixture_trust(self.root)
        owner=self.root/'fixture-old-owner';owner.mkdir(mode=0o700);old_plan=owner/'execution-plan.json';old_hash=private(old_plan,ctx.oldplan)
        inputs_path=self.root/'inputs.json';input_hash=private(inputs_path,{'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),**ctx.inputs})
        frozen_root=self.root/'frozen-proposal';frozen_root.mkdir(mode=0o700);frozen_path=frozen_root/'execution-plan.json'
        frozen={'schema':'ouf.onboarding-v35-frozen-native-plan.v1','kind':'FROZEN_PROPOSAL_NOT_EXECUTABLE_AUTHORITY',
            'proposalHash':n.PROPOSAL_HASH,'inputHash':input_hash,'targetApplyAuthorized':False,'runtimeAuthorityIssued':False,
            'databaseMigration':{'flywayChecksum':1095739786},'stages':[{'name':stage}for stage in core.STAGES],
            'retainedFiles':[{'path':str(old_plan),'sha256':old_hash}],'boundDatabaseProfile':ctx.profile,
            'engine':engine,'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'logicalOperationRef':logical,
            'proposedAuthorityDirectory':str(parent/('onboarding-v35-apply-'+logical)),'replacements':{'onboarding':replacement},
            'unchangedApplications':{name:runtime_bindings.observed(row,runtime_bindings.NATIVE)for name,row in self.rows.items()if name!='onboarding'},
            'nativeFlywayConfiguration':classification}
        frozen_hash=private(frozen_path,frozen);private(frozen_root/'complete.json',{'privatePlanHash':frozen_hash,'complete':True,'status':'ONBOARDING_V35_CURRENT_CONFIGURATION_AND_PLAN_FROZEN'})
        retained_path=self.root/'fixture-retained-authority-inputs.json';retained_hash=private(retained_path,{'review':{'authorityInputs':ctx.authority_inputs}})
        prior_path=self.root/'fixture-prior-review.json';prior_hash=private(prior_path,{'proposal':{'inputsBinding':{'path':str(retained_path),'sha256':retained_hash}}})
        fake_r=types.SimpleNamespace(REVIEW=str(prior_path),REVIEW_HASH=prior_hash,json_at=r.json_at)
        fake_n=types.SimpleNamespace(PROPOSAL_HASH=n.PROPOSAL_HASH,CONFIG_HASH=n.CONFIG_HASH,REPLACEMENT_HASH=n.REPLACEMENT_HASH,OWNER_OVERLAY=str(self.overlay),definitions=n.definitions)
        # Only the already-proven historical bootstrap and private plan identity
        # are fixture inputs. Execute the entire NEW Context constructor itself.
        with patch.multiple(entry,FROZEN=str(frozen_path),FROZEN_HASH=frozen_hash,PARENT=str(parent),HELPER=str(helper/'plan.py'),__file__=str(code_root/'apply.py')),\
             patch.multiple(d,INPUT=str(inputs_path),INPUT_HASH=input_hash),patch.object(q,'OWNER',str(owner)),patch.object(p,'PACKAGE',str(package)):
            verified=entry.Context(fake_n,p,q,None,None,d,m,fake_r,CONFIG,REPLACEMENT,core,ports,code_root)
        verified.fixture_frozen_hash=frozen_hash;self.assertTrue((verified.root/'preparation.claim.json').exists())
        self.assertEqual(verified.frozen,frozen);self.assertEqual(verified.inputs['currentProcessIdentities'],ctx.inputs['currentProcessIdentities'])
        self.assertEqual(verified.preflight_counts,{k:0 for k in core.LIMITS});verified.check_sources()
        return verified
    def perform(self,kill=False):
        ctx=self.ctx
        with patch.object(entry,'FROZEN_HASH',ctx.fixture_frozen_hash),patch.object(p,'PACKAGE',os.environ['OUF_V35_TEST_PACKAGE']),patch.object(postboot_authority,'authority_metadata',return_value=(self.signing_profile,self.public_policy)):
            def invoke():
                try:return entry.operator(ctx)
                except BaseException:
                    path=ctx.root/'recovery.json'
                    if path.exists():
                        row=json.loads(path.read_bytes());print('FIXTURE_STAGE '+str(row['nextStage'])+' '+str(row['counts']),flush=True)
                        responses=sorted(ctx.root.glob('engine-response-*.json'))
                        if responses:
                            last=json.loads(responses[-1].read_bytes())
                            if last['status']>=400:print('FIXTURE_ENGINE_ERROR '+json.dumps(last)[:3000],flush=True)
                    raise
            code,output,approved,killed=tty_call(invoke,kill_after_start_root=str(ctx.root)if kill else None)
        self.assertTrue(approved,output.decode(errors='replace'));return code,output,killed
    def test_actual_exact_image_signed_pty_v34_to_v35_backup_and_source_preservation(self):
        code,output,_=self.perform();self.assertEqual(code,0,output.decode(errors='replace'))
        row=json.loads((self.ctx.root/'recovery.json').read_bytes());self.assertEqual(row['state'],'COMPLETE');self.assertEqual(row['nextStage'],13)
        self.assertEqual([v['state']for v in row['effects']],['APPLIED']*13);self.assertEqual(row['counts']['sqlSessions'],6);self.assertEqual(row['counts']['imageLoadAttempts'],1)
        self.assertEqual(row['counts']['quarantineStops'],0);self.assertIsNone(row['quarantine']);self.assertTrue(row['backup']['payloadParsed'])
        self.assertEqual(self.sql("SELECT count(*) FROM ouf_onboarding.flyway_schema_history WHERE version='35' AND checksum=1095739786 AND success"),'1')
        self.assertEqual(self.sql('SELECT count(*) FROM ouf_onboarding.managed_readiness_budget_session'),'0')
        after=self.sql("SELECT jsonb_build_object('review',to_jsonb(m)-'readiness_session_id','revision',to_jsonb(r)) FROM ouf_onboarding.managed_onboarding_review m CROSS JOIN ouf_onboarding.source_property_revision r")
        self.assertEqual(json.loads(after),json.loads(self.retained));self.assertFalse(self.inspect(self.app)['State']['Running'])
        self.assertTrue(self.inspect(row['createdId'])['State']['Running']);self.assertEqual(self.inspect(row['createdId'])['HostConfig']['RestartPolicy']['Name'],'unless-stopped')
        for name,original in self.rows.items():
            if name!='onboarding':self.assertEqual(runtime_bindings.observed(self.inspect(original['Id']),runtime_bindings.NATIVE),runtime_bindings.observed(original,runtime_bindings.NATIVE))
        receipt=json.loads((self.ctx.root/'result.json').read_bytes());review=json.loads((self.ctx.root/'review.json').read_bytes());v=review['verification'];verify=DetachedAuthenticator(v['trustPolicy'],str(self.ctx.root/'authority'),v['openssl'])
        self.assertTrue(verify(core.encoded(receipt),'CREATION_ATTESTATION','fixture-attestor','fixture-installation','fixture-entity'))
        with self.assertRaises(FileExistsError):entry.create_context(self.ctx.root.parent,self.ctx.root.name)
        journal=Journal(self.ctx.root)
        with self.assertRaises(FileExistsError):journal.initialize(row)
    def test_parent_sigkill_stops_only_known_unproven_candidate_once_without_replay(self):
        code,output,killed=self.perform(kill=True);self.assertTrue(killed,output.decode(errors='replace'));self.assertEqual(code,-signal.SIGKILL)
        until=time.monotonic()+30
        while True:
            row=json.loads((self.ctx.root/'recovery.json').read_bytes())
            if row.get('quarantine',{} )and row['quarantine'].get('state')=='APPLIED':break
            if (self.ctx.root/'watchdog-stop.json').exists():self.fail('quarantine unproven: '+str(row))
            self.assertLess(time.monotonic(),until);time.sleep(.2)
        self.assertEqual(row['counts']['quarantineStops'],1);self.assertFalse(self.inspect(row['createdId'])['State']['Running']);self.assertFalse(self.inspect(self.app)['State']['Running'])
        self.assertEqual(self.sql('SELECT readiness_attempts||\'|\'||readiness_generation||\'|\'||readiness_phase FROM ouf_onboarding.managed_onboarding_review'),'3|4|PAUSED')
        self.assertLessEqual(row['nextStage'],10);self.assertEqual(row['quarantine']['reason'],'PARENT_LOST')
        for name,original in self.rows.items():
            if name!='onboarding':self.assertEqual(runtime_bindings.observed(self.inspect(original['Id']),runtime_bindings.NATIVE),runtime_bindings.observed(original,runtime_bindings.NATIVE))
        with self.assertRaises(FileExistsError):entry.create_context(self.ctx.root.parent,self.ctx.root.name)

if __name__=='__main__':unittest.main()
