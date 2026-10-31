"""Current configuration and proposal compiler. Histories/package are fixtures.

Native case uses two real Docker containers, their Engine/proc/rootfs, and the
existing named nonroot custody reader. No SQL or lifecycle action by planner.
"""
import copy,hashlib,http.client,importlib.util,io,json,os,shutil,socket,stat,subprocess,tarfile,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[3]if Path(__file__).parent.name=='tests'else Path(__file__).parent
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v);return v
def file(repo,local):
    p=ROOT/repo;return p if p.exists()else ROOT/local
old=module('native_plan_existing_sealed_helpers',file('tools/ingestion_readiness_patch_execution/tests/test_onboarding_engine_metadata.py','test_onboarding_engine_metadata.py'))
c,d,m,r=old.c,old.d,old.m,old.r
n=module('v35_current_native_plan',file('scripts/freeze-onboarding-v35-native-plan-20261024.py','freeze-onboarding-v35-native-plan-20261024.py'))
p=module('v35_current_package_definitions',file('scripts/prepare-onboarding-v35-review-inputs-20261024.py','prepare-onboarding-v35-review-inputs-20261024.py'))
CONFIG=file('tools/source_revision_update/configuration.py','v35-retained-configuration.py').read_bytes()
REPLACEMENT=file('tools/source_revision_update/plan.py','v35-retained-replacement.py').read_bytes()
from tools.chatbot_file_cohort import gateway
from tools.ingestion_readiness_patch_execution import database_read,runtime_bindings
def private(path,value):
    raw=value if type(value)is bytes else m.encoded(value);path.write_bytes(raw);path.chmod(0o400);return m.sha(raw)
class Guards(unittest.TestCase):
    def test_original_complete_sources_are_pinned_and_only_named_functions_selected(self):
        self.assertEqual(m.sha(CONFIG),n.CONFIG_HASH);self.assertEqual(m.sha(REPLACEMENT),n.REPLACEMENT_HASH)
        out=n.definitions(b"raise Exception('NO_MODULE_ENTRY')\ndef selected():return 7\n",('selected',),{})
        self.assertEqual(out.selected(),7)
        with self.assertRaises(n.Stop):n.definitions(CONFIG,('not_an_original_function',),{})
    def test_closed_owner_json_never_permits_datasource_migration_or_loader_overrides(self):
        selected=n.definitions(CONFIG,('application_json_metadata','owner_json_overlay','additional_location'),
            {'require':n.require,'json':json,'hashlib':hashlib,'Path':Path,'re':__import__('re')})
        allowed='{"ouf":{"authorization":{"ths":{"enabled":true}}}}'
        self.assertTrue(selected.application_json_metadata(allowed)['retainedOwnerBindingsOnly'])
        for raw in ('{"spring.datasource.url":"fixture"}','{"spring.flyway.enabled":false}',
                    '{"loader.path":"fixture"}','{"ouf.authorization.ths.enabled":true,"ouf.authorization.ths.enabled":false}'):
            with self.assertRaises(n.Stop):selected.application_json_metadata(raw)
        with self.assertRaises(n.Stop):selected.owner_json_overlay('{"spring":{"datasource":{"password":"secret"}}}')
        for value in ('http://fixture/owner.yml','file:/run/../owner.yml','file:/run/owner.yml,file:/run/other.yml'):
            with self.assertRaises(n.Stop):selected.additional_location(value)
    def test_custody_is_named_not_a_general_nonroot_exception(self):
        selected=gateway._EXISTING_CONFIG_CUSTODY[n.OWNER_OVERLAY]
        self.assertEqual(selected['file'],(10003,10003,0o400));self.assertEqual(selected['parents']['/opt/ouf'],(1000,1000,0o750))
        class Info:st_uid=1000;st_gid=1000;st_mode=stat.S_IFDIR|0o750
        self.assertTrue(gateway.selected_directory_custody(Info,'/opt/ouf',selected))
        self.assertFalse(gateway.selected_directory_custody(Info,'/unrelated/nonroot',selected))
    def test_scope_replay_refusal_precedes_file_reads_and_no_apply_stage_dispatch_exists(self):
        with tempfile.TemporaryDirectory(dir=ROOT)as directory:
            root=Path(directory);(root/n.SCOPE).mkdir(mode=0o700)
            with patch.object(p,'PACKAGE',str(root)),patch.object(m.Facts,'json',side_effect=AssertionError('NO_READS')):
                with self.assertRaisesRegex(n.Stop,'ALREADY_CLAIMED'):n.freeze(p,None,None,c,d,m,r,CONFIG,REPLACEMENT)
        self.assertEqual(len(n.STAGES),13);self.assertNotIn('GRANT_BUDGET',n.STAGES)

@unittest.skipUnless(os.environ.get('OUF_NATIVE_V35_PLAN')=='1','isolated root Docker/Engine/proc fixture required')
class Native(unittest.TestCase):
    def docker(self,*args):return subprocess.check_output(['docker',*args],stderr=subprocess.DEVNULL).decode().strip()
    def inspect(self,cid):
        selected=str(Path('/var/run/docker.sock').resolve())
        class Local(http.client.HTTPConnection):
            def connect(connection):connection.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);connection.sock.connect(selected)
        connection=Local('fixture-engine',timeout=4)
        try:
            connection.request('GET','/v1.44/containers/'+cid+'/json');response=connection.getresponse();self.assertEqual(response.status,200);return json.loads(response.read())
        finally:connection.close()
    def test_actual_engine_generations_named_uid_custody_config_and_exact_replacement_without_any_sql_or_writes(self):
        import zipfile
        with tempfile.TemporaryDirectory(dir=ROOT)as directory:
            root=Path(directory);root.chmod(0o700);ids=[];image=None;network=None
            try:
                owned=root/'owned';owned.mkdir(mode=0o750);os.chown(owned,1000,1000)
                overlay=owned/'owner.yml';overlay.write_text('{"ouf":{"workflow":{"ths":{"gateway-base-url":"fixture-private"}}}}');os.chown(overlay,10003,10003);overlay.chmod(0o400)
                expected={'path':str(overlay),'sha256':m.sha(overlay.read_bytes()),'metadata':list(m.identity(overlay.stat()))}
                custody={str(overlay):{'parents':{str(owned):(1000,1000,0o750)},'file':(10003,10003,0o400)}}
                (root/'hold.c').write_text('#include <unistd.h>\nint main(void){for(;;)sleep(60);}\n')
                subprocess.run(['gcc','-static','-Os','-o',str(root/'hold'),str(root/'hold.c')],check=True)
                (root/'Dockerfile').write_text('FROM scratch\nCOPY hold /hold\nUSER 10003:10003\nWORKDIR /app\nENTRYPOINT ["/hold"]\n')
                image='ouf-v35-plan-fixture:'+root.name;self.docker('build','-q','-t',image,str(root))
                network='ouf-v35-plan-'+root.name;self.docker('network','create',network)
                pg=self.docker('run','-d','--network',network,'-e','POSTGRES_USER=pgadmin',image);ids.append(pg)
                pgrow=self.inspect(pg)
                app=self.docker('run','-d','--network',network,'--label','org.opencontainers.image.revision=b0f5e3dacbe59ebf87e22dd6af2575e41249f51d',
                    '-e','OUF_ONB_DB_URL=jdbc:postgresql://'+pgrow['Config']['Hostname']+':5432/onboarding_fixture','-e','OUF_ONB_DB_USER=app_role',
                    '-e','OUF_ONB_DB_PASSWORD=fixture-password','-e','SPRING_APPLICATION_JSON={"ouf.authorization.ths.enabled":true}',
                    '-e','SPRING_CONFIG_ADDITIONAL_LOCATION=file:/fixture/owner.yml','-v',str(overlay)+':/fixture/owner.yml:ro',image);ids.append(app)
                actual=self.inspect(app);pgrow=self.inspect(pg)
                package=root/'package';package.mkdir(mode=0o700)
                jar=package/'application.jar';yaml=b'spring: fixture\n'
                with zipfile.ZipFile(jar,'w')as z:z.writestr('BOOT-INF/classes/application.yml',yaml);z.writestr('BOOT-INF/lib/flyway-core-fixture.jar',b'fixture')
                jar.chmod(0o400);jpin={'path':str(jar),'sha256':m.sha(jar.read_bytes()),'bytes':jar.stat().st_size,'metadata':list(m.identity(jar.stat()))}
                candidate_config=copy.deepcopy(actual['Config']);candidate_config['Labels']['org.opencontainers.image.revision']=p.TESTED
                raw=m.encoded({'os':'linux','architecture':'amd64','config':candidate_config});imageid='sha256:'+m.sha(raw)
                archive=package/'image.tar.gz'
                with tarfile.open(archive,'w:gz')as tar:
                    entry=tarfile.TarInfo('blobs/sha256/'+m.sha(raw));entry.size=len(raw);tar.addfile(entry,io.BytesIO(raw))
                archive.chmod(0o400);apin={'path':str(archive),'sha256':m.sha(archive.read_bytes()),'bytes':archive.stat().st_size,'metadata':list(m.identity(archive.stat()))}
                contract={'imageId':imageid,'archiveSha256':apin['sha256'],'archiveBytes':apin['bytes'],'applicationYamlSha256':m.sha(yaml)}
                manifest={'reviewedSourceCommit':p.SOURCE,'testedCommit':p.TESTED}
                owner=root/'completed-owner';owner.mkdir(mode=0o700)
                boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip();refs={};bindings={};processes={}
                for name,row in(('onboarding',actual),('postgres',pgrow)):
                    path=root/(name+'.json');refs[name]={'path':str(path),'sha256':private(path,row)};bindings[name]=runtime_bindings.observed(row,runtime_bindings.NATIVE);processes[name]=m.process(row)
                for i,name in enumerate(('gateway','ingestion','mcp','udp','registry'),1):bindings[name]={'containerId':str(i)*64}
                sock=str(Path('/var/run/docker.sock').resolve());s=Path(sock).stat();engine={'socketPath':sock,'socketBinding':[s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)]}
                inputs={'bootId':boot,'runtimeObservations':refs,'currentBindings':bindings,'currentProcessIdentities':processes,
                    'restartCounts':{'onboarding':0,'postgres':0},'engineBinding':engine}
                ip=root/'inputs.json';ih=private(ip,inputs)
                saved={'name':actual['Name'].lstrip('/'),'restoreRestartPolicy':copy.deepcopy(actual['HostConfig']['RestartPolicy']),
                    'readiness':{'readinessPort':8080,'readinessPath':'/actuator/health/readiness'},
                    'request':{'HostConfig':copy.deepcopy(actual['HostConfig']),'NetworkingConfig':{'EndpointsConfig':{network:{'Aliases':[actual['Name'].lstrip('/')]}}}}}
                profile={'identity':{'runtimeRole':'app_role','database':'onboarding_fixture','schema':'ouf_onboarding','postgresPort':5432}}
                class Owner:OWNER=str(owner)
                with patch.object(n,'OWNER_OVERLAY',str(overlay)),patch.object(gateway,'_EXISTING_CONFIG_CUSTODY',custody):
                    for k in n.COUNTS:n.COUNTS[k]=0
                    verifier=n.configuration_verifier(CONFIG,d,p,m,expected,jpin)
                    classification=verifier.verify(actual,{'jar':{'path':str(jar),'sha256':jpin['sha256']}},pgrow,
                        {'user':'app_role','database':'onboarding_fixture','schema':'ouf_onboarding'},5432,m.sha(yaml))
                    oldplan={'schema':'ouf.installation-binding-owner-update-plan.v1','authorityDirectory':str(owner),'nativeFlywayConfiguration':classification,'replacements':{'onboarding':saved}}
                    op=owner/'execution-plan.json';oh=private(op,oldplan)
                    proposal={'schema':'ouf.onboarding-v35-private-review-inputs.v1','kind':'PROPOSAL_NOT_EXECUTABLE_AUTHORITY','targetApplyAuthorized':False,'runtimeAuthorityIssued':False,
                        'retainedFiles':[{'path':str(op),'sha256':oh}],'historyAssessment':{'all34SqlMigrationChecksumsMatchCandidate':True,'allHistoryRowsSuccessful':True,'nonSqlHistoryTypesRecognized':True,'v35AlreadyRecorded':False},
                        'schemaAssessment':{'fixture':True},'capacitySnapshotHasHeadroom':True,'currentOwnerPlanBinding':{'path':str(op),'sha256':oh},'boundDatabaseProfile':profile,
                        'proposedMigration':{'version':'35','script':'V35__managed_readiness_budget_sessions.sql','flywayChecksum':1095739786}}
                    done=root/'prior-proposal';done.mkdir(mode=0o700);pp=done/'review-inputs.json';ph=private(pp,proposal);private(done/'complete.json',{'privateReviewInputsHash':ph,'complete':True})
                    script=root/'planner.py';private(script,Path(n.__file__).read_bytes())
                    before={f:f.read_bytes()for f in (op,ip,pp,overlay,jar,archive,script)}
                    for k in n.COUNTS:n.COUNTS[k]=0
                    with patch.multiple(n,PROPOSAL=str(pp),PROPOSAL_HASH=ph,HELPER=str(package/'prepare.py'),__file__=str(script)),patch.multiple(d,INPUT=str(ip),INPUT_HASH=ih),\
                         patch.multiple(p,PACKAGE=str(package),SNAPSHOT=str(root/'retained-sql.json'),SNAPSHOT_HASH='f'*64),\
                         patch.object(p,'packaged',return_value=(contract,manifest,apin,jpin)),\
                         patch.object(database_read,'bounded_read',side_effect=AssertionError('NO_SQL')),patch.object(p,'prepare',side_effect=AssertionError('NO_OLD_ENTRY')),\
                         patch.object(d,'prepare',side_effect=AssertionError('NO_OLD_ENTRY')),patch.object(subprocess,'Popen',side_effect=AssertionError('NO_SUBPROCESS')):
                        result=n.freeze(p,Owner,None,c,d,m,r,CONFIG,REPLACEMENT)
                        self.assertTrue(result['allCurrentConfigurationPrecedenceResolved']);self.assertEqual(result['engineGetAttempts'],4);self.assertEqual(result['ownerConfigurationFileContentReads'],2)
                        self.assertFalse(result['targetApplyAuthorized']);self.assertEqual(result['sqlSessionAttempts'],0);self.assertFalse(result['applyEntryQualified'])
                        self.assertNotIn('fixture-password',json.dumps(result));self.assertNotIn('fixture-private',json.dumps(result))
                        plan=json.loads((package/n.SCOPE/'execution-plan.json').read_bytes());self.assertEqual(result['privatePlanHash'],n.digest(plan))
                        row=plan['replacements']['onboarding'];self.assertEqual(row['request']['Image'],imageid);self.assertEqual(row['request']['Env'],actual['Config']['Env'])
                        self.assertEqual(row['request']['Labels']['org.opencontainers.image.revision'],p.TESTED);self.assertEqual(row['oldRuntimeBinding'],runtime_bindings.observed(actual,runtime_bindings.SORTED))
                        self.assertEqual(plan['retainedSource']['attempts'],3);self.assertFalse(plan['newBudgetOrActivationAuthorized'])
                        with self.assertRaisesRegex(n.Stop,'ALREADY_CLAIMED'):n.freeze(p,Owner,None,c,d,m,r,CONFIG,REPLACEMENT)
                    self.assertEqual(before,{f:f.read_bytes()for f in before})
                    overlay.chmod(0o600)
                    with self.assertRaises(Exception):gateway.private_config(str(overlay),expected)
                for cid,row in((app,actual),(pg,pgrow)):self.assertEqual(runtime_bindings.observed(self.inspect(cid),runtime_bindings.NATIVE),runtime_bindings.observed(row,runtime_bindings.NATIVE))
            finally:
                for cid in ids:subprocess.run(['docker','rm','-f',cid],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)
                if network:subprocess.run(['docker','network','rm',network],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)
                if image:subprocess.run(['docker','image','rm',image],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)
if __name__=='__main__':unittest.main()
