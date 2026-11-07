"""Real disposable Keycloak26.7.4, local Engine and GET-only namespace transport.

Only fixture setup imports a realm and logs in. The production reader reads
that exact existing session and performs namespace-bound GETs without kcadm. Other cohort/profile/Registry lineage
is modeled; this does not qualify target IAM, a bearer or full M2 admission.
"""
import copy,hashlib,json,os,shutil,socket,stat,struct,subprocess,sys,tempfile,time,unittest,uuid
from pathlib import Path
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_m2_discovery_current_iam_workload as fixtures
from tools.m2_discovery_installation_profile import current_iam_workload as m

IMAGE='quay.io/keycloak/keycloak@sha256:82a77884f3af238beab1e7afd63b5f530e1b5c0590bd7aa60b40a40463e29b2c'
SECRET='fixture-existing-credential-123456'


class NativeWorkloadIam(unittest.TestCase):
    @classmethod
    def command(cls,args,**kwargs):
        return subprocess.run([cls.docker,*args],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,check=True,timeout=120,**kwargs).stdout

    @classmethod
    def setUpClass(cls):
        if os.geteuid()!=0 or os.environ.get('GITHUB_ACTIONS')!='true':raise AssertionError('DISPOSABLE_HOSTED_CI_ONLY')
        cls.docker=str(Path(shutil.which('docker')).resolve())
        cls.temp=tempfile.TemporaryDirectory(dir=ROOT,prefix='current-iam-native-');cls.addClassCleanup(cls.temp.cleanup)
        cls.root=Path(cls.temp.name);cls.root.chmod(0o700)
        def claim(name,value):
            return {'name':name,'protocol':'openid-connect','protocolMapper':'oidc-hardcoded-claim-mapper',
                'config':{'claim.name':name,'claim.value':value,'jsonType.label':'String','access.token.claim':'true'}}
        client={'id':fixtures.CLIENT,'clientId':'ouf-semantic','enabled':True,'protocol':'openid-connect',
            'publicClient':False,'clientAuthenticatorType':'client-secret','secret':SECRET,'serviceAccountsEnabled':True,
            'standardFlowEnabled':False,'directAccessGrantsEnabled':False,'defaultClientScopes':[],
            'optionalClientScopes':[fixtures.SCOPE],'protocolMappers':[claim('tenant_id','tenant-fixture'),
                claim('ouf_actor_type','SERVICE'),{'name':'subject','protocol':'openid-connect','protocolMapper':'oidc-sub-mapper',
                'config':{'access.token.claim':'true'}},{'name':'audience','protocol':'openid-connect',
                'protocolMapper':'oidc-audience-mapper','config':{'included.custom.audience':'ouf-gateway','access.token.claim':'true'}}]}
        realm={'realm':'ouf','enabled':True,'sslRequired':'none','clientScopes':[{'name':fixtures.SCOPE,
            'protocol':'openid-connect','attributes':{'include.in.token.scope':'true'}}],'clients':[client]}
        path=cls.root/'realm.json';path.write_text(json.dumps(realm));path.chmod(0o644)
        name='ouf-current-iam-native-'+uuid.uuid4().hex[:12]
        cls.cid=cls.command(['run','-d','--name',name,'--memory','1g','--memory-swap','1g','--cpus','2','--pids-limit','512',
            '--cap-drop','ALL','--security-opt','no-new-privileges','--network','none',
            '-v',str(path)+':/opt/keycloak/data/import/realm.json:ro',
            '-e','KC_BOOTSTRAP_ADMIN_USERNAME=fixture-admin','-e','KC_BOOTSTRAP_ADMIN_PASSWORD=DISPOSABLE_CI_ADMIN_PASSWORD',
            '-e','JAVA_OPTS_KC_HEAP=-Xms128m -Xmx512m',IMAGE,'start-dev','--hostname=https://iam.fixture.invalid',
            '--http-enabled=true','--import-realm']).decode().strip()
        cls.addClassCleanup(lambda:cls.command(['rm','-f',cls.cid]))
        deadline=time.monotonic()+120
        while True:
            p=subprocess.run([cls.docker,'exec',cls.cid,'bash','-c',
                'exec 3<>/dev/tcp/127.0.0.1/8080; printf "GET /realms/ouf/.well-known/openid-configuration HTTP/1.0\\r\\nHost: localhost\\r\\n\\r\\n" >&3; read -r reply <&3; [[ "$reply" == *" 200 "* ]]'],
                stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
            if p.returncode==0:break
            if time.monotonic()>=deadline:raise AssertionError('DISPOSABLE_CURRENT_IAM_READINESS_EXHAUSTED')
            time.sleep(.5)
        version=cls.command(['exec',cls.cid,'/opt/keycloak/bin/kc.sh','--version']).decode()
        if '26.7.4' not in version:raise AssertionError('EXACT_KEYCLOAK_2674_FIXTURE_REQUIRED')
        cls.command(['exec',cls.cid,'/opt/keycloak/bin/kcadm.sh','config','credentials',
            '--server','http://localhost:8080','--realm','master','--user','fixture-admin','--password','DISPOSABLE_CI_ADMIN_PASSWORD'])
        cls.service=cls.kc('get','clients/'+fixtures.CLIENT+'/service-account-user')['id']
        selected=Path('/var/run/docker.sock').resolve();info=selected.stat()
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as channel:
            channel.connect(str(selected));peer=list(struct.unpack('3i',channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)))
        cls.engine_binding={'socketPath':str(selected),'socketBinding':[info.st_dev,info.st_ino,info.st_uid,info.st_gid,
            stat.S_IMODE(info.st_mode)],'peerCredentials':peer,'startTicks':fixtures.cohort.m.process_pin(peer[0])['startTicks']}

    @classmethod
    def kc(cls,verb,path,*query):
        raw=cls.command(['exec',cls.cid,'/opt/keycloak/bin/kcadm.sh',verb,path,'--server','http://localhost:8080','-r','ouf',*query])
        return json.loads(raw) if verb=='get' else None

    def prepared(self):
        case=fixtures.WorkloadIam();case.setUp();self.addCleanup(case.doCleanups)
        old,_,_,_,_=case.prepared();case.admin_session_patch.stop();selected=old.runtime.selected
        actual=json.loads(self.command(['inspect',self.cid]))[0];binding=m.Engine.runtime_binding(actual)
        inputs=copy.deepcopy(old.inputs)
        session=Path('/proc')/str(binding['pid'])/'root/opt/keycloak/.keycloak/kcadm.config'
        inputs['readOnlyAdmin']['sessionFile'].update(sha256=hashlib.sha256(session.read_bytes()).hexdigest(),
            metadataHash=m.digest(m.readonly_iam_admin.attrs(session.stat())))
        inputs.update(serviceAccountUuid=self.service,keycloakRuntimeBinding=binding,
            dockerBinding={'path':self.docker,'sha256':hashlib.sha256(Path(self.docker).read_bytes()).hexdigest()})
        runtime_inputs=copy.deepcopy(old.runtime.inputs);runtime_inputs.pop('additionalInputsHashes');runtime_inputs['schema']=fixtures.cohort.m.INPUT_SCHEMA
        runtime_inputs['peers']['keycloak']['runtimeBinding']=binding
        runtime_inputs['peers']['keycloak']['processPin']=fixtures.cohort.m.process_pin(binding['pid'])
        runtime_inputs['engineBinding']=copy.deepcopy(self.engine_binding)
        runtime_inputs['rootProcessPins']['engine']=fixtures.cohort.m.process_pin(self.engine_binding['peerCredentials'][0])
        runtime_inputs=m.bind_iam_workload_inputs(runtime_inputs,inputs)
        review=copy.deepcopy(case.review);review['components']['cohortInstallation']['currentAdmission']=copy.deepcopy(
            review['components']['cohortInstallation']['currentAdmission']['requirements'])
        case.review=fixtures.cohort.m.bind_runtime_review(review,runtime_inputs);parent=case.authority(seconds=300)
        selected.images.parent=parent;selected.images.component=case.review['components']['cohortInstallation']
        selected.images.engine=m.Engine(self.engine_binding['socketPath'],tuple(self.engine_binding['socketBinding']))
        selected.guard=lambda:parent.guard('cohortInstallation',selected.images.component)
        runtime=m.CurrentCohortRuntime(selected,runtime_inputs);auth=old.authorization
        auth.transport.selection.update(keycloakContainer=self.cid,docker=copy.deepcopy(inputs['dockerBinding']))
        auth.plan['selection']=copy.deepcopy(auth.transport.selection);auth.hash=m.digest(auth.plan)
        auth.window.assembly['authorizationPlan']=copy.deepcopy(auth.plan)
        auth.window.lineage=Mock(side_effect=lambda:parent.guard('cohortInstallation',selected.images.component))
        return m.CurrentWorkloadIam(runtime,auth,inputs)

    def test_actual_keycloak_configuration_and_secret_match_without_grant_probe(self):
        reader=self.prepared();proof=reader.observe()
        self.assertTrue(proof['currentMountedCredentialMatchesKeycloak']);self.assertTrue(proof['currentWorkloadConfigurationObserved'])
        self.assertEqual((proof['iamMetadataGets'],proof['engineGets'],proof['tokenGrantProbesIssued']),(12,2,0))
        self.assertFalse(proof['actualWorkloadBearerAdmissionProven']);self.assertFalse(proof['fullCohortProven'])
        self.assertEqual(proof['kcadmInvocations'],0);self.assertFalse(proof['adminLoginOrRefreshDispatched'])
        self.assertNotIn(SECRET,m.encoded(proof).decode())

    def test_actual_changed_issuer_secret_is_denied_and_not_repaired(self):
        reader=self.prepared();self.kc('update','clients/'+fixtures.CLIENT,'-s','secret=DIFFERENT_DISPOSABLE_CI_CREDENTIAL')
        try:
            with self.assertRaisesRegex(ValueError,'CREDENTIAL_DIFFER'):reader.observe()
            current=self.kc('get','clients/'+fixtures.CLIENT+'/client-secret')
            self.assertEqual(current['value'],'DIFFERENT_DISPOSABLE_CI_CREDENTIAL')
            self.assertEqual(Path(reader.runtime.selected.installation.application.profile.selection['files']['providerCredential']['source']).read_text(),SECRET)
        finally:self.kc('update','clients/'+fixtures.CLIENT,'-s','secret='+SECRET)

    def test_expired_cached_admin_session_stops_before_get_and_does_not_refresh(self):
        actual=json.loads(self.command(['inspect',self.cid]))[0]
        path=Path('/proc')/str(actual['State']['Pid'])/'root/opt/keycloak/.keycloak/kcadm.config';original=path.read_bytes()
        try:
            value=json.loads(original);value['endpoints']['http://localhost:8080']['master']['expiresAt']=1
            path.write_text(json.dumps(value));changed=path.read_bytes();reader=self.prepared()
            with patch.object(m.readonly_iam_admin,'dispatch') as get, self.assertRaisesRegex(ValueError,'BEARER_REQUIRED_NO_REFRESH'):
                reader.observe()
            get.assert_not_called();self.assertEqual(path.read_bytes(),changed)
        finally:path.write_bytes(original)

    def test_invalid_existing_bearer_is_denied_without_login_refresh_or_cache_repair(self):
        actual=json.loads(self.command(['inspect',self.cid]))[0]
        path=Path('/proc')/str(actual['State']['Pid'])/'root/opt/keycloak/.keycloak/kcadm.config';original=path.read_bytes()
        try:
            value=json.loads(original);value['endpoints']['http://localhost:8080']['master']['token']='invalid.existing.token'
            path.write_text(json.dumps(value));changed=path.read_bytes();reader=self.prepared()
            with self.assertRaisesRegex(ValueError,'ADMIN_GET_UNPROVEN_NO_REFRESH'):reader.observe()
            self.assertEqual(path.read_bytes(),changed)
        finally:path.write_bytes(original)

if __name__=='__main__':unittest.main()
