"""One real PostgreSQL17 read-only exec and two real Engine generations.

Owner/authority histories, input capture receipt and unrelated cohort entries
are SYNTHETIC fixtures. No target authority/admission/deployment qualification.
"""
import copy
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[3]if Path(__file__).parent.name=='tests'else Path(__file__).parent

def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

SCRIPT=ROOT/'scripts/read-onboarding-finite-database-20261024.py'
if not SCRIPT.exists():SCRIPT=ROOT/'read-onboarding-finite-database-20261024.py'
HELPER=ROOT/'scripts/prepare-onboarding-finite-session-inputs-20261024.py'
if not HELPER.exists():HELPER=ROOT/'prepare-onboarding-finite-session-inputs-20261024.py'
REPAIR=ROOT/'scripts/repair-registry-network-projection-20261024.py'
if not REPAIR.exists():REPAIR=ROOT/'repair.py'
CAPSULE=ROOT/'releases/semantic-registry-checkpoint-successor-20261023.py'
if not CAPSULE.exists():CAPSULE=ROOT/'capsule.py'
d=module('onboarding_db_snapshot',SCRIPT);m=module('onboarding_db_metadata_helpers',HELPER)
r=module('onboarding_db_sealed_dependencies',REPAIR);r.CAPSULE=str(CAPSULE);r.load_legacy()
from tools.ingestion_readiness_patch_execution import runtime_bindings
from tools.ingestion_readiness_patch_execution import database_read

def private(path,value):
    body=value if type(value)is bytes else m.encoded(value);path.write_bytes(body);path.chmod(0o400);return m.sha(body)


class Guards(unittest.TestCase):
    def test_sql_is_fixed_readonly_and_rejects_identifier_injection(self):
        sql=d.query('onboarding_fixture')
        self.assertTrue(sql.startswith('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;'))
        self.assertTrue(sql.endswith('ROLLBACK;'))
        self.assertNotIn('FOR UPDATE',sql)
        self.assertIn('ouf_onboarding.flyway_schema_history',sql)
        self.assertIn('ouf_onboarding.managed_onboarding_review',sql)
        for bad in("role';COMMIT;--",'role name','role.name','a'*64,''):
            with self.assertRaises(d.Stop):d.query(bad)

    def selection(self,**extra):
        env={'OUF_ONB_DB_URL':'jdbc:postgresql://private-fixture:5544/onboarding_fixture','OUF_ONB_DB_USER':'onboarding_role',**extra}
        actual={'Config':{'Env':[k+'='+v for k,v in env.items()],'Entrypoint':['java','-jar','/app/application.jar'],'Cmd':None}}
        binding={'database':'onboarding_fixture','databaseOid':100,'user':'onboarding_role'}
        return actual,binding,{'identity':{'postgresPort':5544}}

    def test_selection_does_not_use_ingestion_identity_and_reports_precedence_limit(self):
        args=self.selection();p=d.database_selection(*args)
        self.assertEqual(p['database'],'onboarding_fixture');self.assertEqual(p['runtimeRole'],'onboarding_role')
        self.assertTrue(p['allCurrentConfigurationPrecedenceResolved'])
        for env in ({'SPRING_CONFIG_IMPORT':'configtree:/run/secrets/'},{'JAVA_TOOL_OPTIONS':'-Xmx128m'},
                    {'SPRING_APPLICATION_JSON':'{"spring":{"datasource":{"url":"private"}}}'}):
            self.assertFalse(d.database_selection(*self.selection(**env))['allCurrentConfigurationPrecedenceResolved'])
        for env in ({'OUF_ONB_DB_URL':'jdbc:postgresql://private-fixture:5544/wrong'},
                    {'SPRING_DATASOURCE_USERNAME':'different_role'},
                    {'OUF_ONB_DB_URL':'jdbc:postgresql://private-fixture:5545/onboarding_fixture'},
                    {'OUF_ONB_DB_URL':'jdbc:postgresql://user:secret@private-fixture:5544/onboarding_fixture'},
                    {'OUF_ONB_DB_URL':'jdbc:postgresql://private-fixture:5544/onboarding_fixture?currentSchema=ouf_ingestion'}):
            with self.assertRaises(d.Stop):d.database_selection(*self.selection(**env))

    def test_one_session_argv_disables_credential_fallback_and_profile_rebinding(self):
        p={'schema':'ouf.onboarding-finite-database-snapshot-profile.v1','maximumSqlSessionAttempts':1,
            'identity':{'database':'onboarding_fixture','runtimeRole':'app_role','adminRole':'pgadmin','postgresPort':5544},
            'sqlSha256':hashlib.sha256(d.query('app_role').encode()).hexdigest(),
            'dockerExecutable':{'path':'/protected/docker'},'engineBinding':{'socketPath':'/protected/engine.sock'},
            'postgresRuntimeBinding':{'containerId':'a'*64},'containerPrograms':{'env':'/usr/bin/env','timeout':'/usr/bin/timeout','psql':'/usr/bin/psql'},
            'unixSocketDirectory':'/private/socket'}
        argv=d.arguments(p,'/private/empty-config')
        for value in('PGPASSFILE=/dev/null','PGSERVICEFILE=/dev/null','PGSYSCONFDIR=/nonexistent','-i','-w','-X'):self.assertIn(value,argv)
        self.assertEqual(argv[-1],d.query('app_role'));self.assertEqual(argv[argv.index('-d')+1],'onboarding_fixture')
        p['schema']='ouf.ingestion-rollout-native-database-read.v1'
        with self.assertRaises(d.Stop):d.arguments(p,'/private/empty-config')

    def test_snapshot_is_observation_not_admission_and_identity_is_mandatory(self):
        p={'identity':{'database':'onboarding_fixture','databaseOid':100,'adminRole':'pgadmin','postgresPort':5544}}
        facts={'database':'onboarding_fixture','databaseOid':100,'role':'pgadmin','postgresPort':5544,'transactionReadOnly':True,
            'history':[{'type':'SQL','version':'33','success':True}],
            'selectedReview':[{'configuration_hash':d.CONFIGURATION,'readiness_attempts':3,'readiness_generation':4,'readiness_phase':'PAUSED'}],
            'roles':[{}],'relations':[],'columns':[],'constraints':[],'activeReadinessLeases':0,
            'serverVersionNumber':170000,'serverEncoding':'UTF8'}
        report=d.qualify_snapshot(facts,p);self.assertEqual(report['highestSqlVersion'],33)
        self.assertFalse(report['databaseAdmissionProven']);self.assertFalse(report['migrationAuthorized'])
        for key,value in [('database','ingestion_fixture'),('databaseOid',101),('role','other'),('transactionReadOnly',False)]:
            with self.assertRaises(d.Stop):d.qualify_snapshot({**facts,key:value},p)
        facts['history'].append({'type':'SQL','version':'33','success':True})
        with self.assertRaises(d.Stop):d.qualify_snapshot(facts,p)

    def test_fresh_claim_refusal_precedes_inputs_or_sql(self):
        with tempfile.TemporaryDirectory(dir=ROOT)as directory:
            root=Path(directory);(root/d.SCOPE).mkdir(mode=0o700)
            with patch.object(m,'PACKAGE',str(root)),patch.object(m.Facts,'json',side_effect=AssertionError('no replay')):
                with self.assertRaisesRegex(d.Stop,'ALREADY_CLAIMED'):d.prepare(m,r)


@unittest.skipUnless(os.environ.get('OUF_NATIVE_ONBOARDING_DATABASE')=='1','isolated root PostgreSQL Docker runner required')
class Native(unittest.TestCase):
    def docker(self,*args):return subprocess.check_output(['docker',*args],stderr=subprocess.DEVNULL)
    def inspect(self,cid):
        selected=str(Path('/var/run/docker.sock').resolve())
        class Local(http.client.HTTPConnection):
            def connect(connection):
                connection.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);connection.sock.settimeout(4);connection.sock.connect(selected)
        connection=Local('fixture-engine',timeout=4)
        try:
            connection.request('GET','/v1.44/containers/'+cid+'/json');response=connection.getresponse()
            self.assertEqual(response.status,200);return json.loads(response.read())
        finally:connection.close()
    def sql(self,pg,sql):
        return self.docker('exec',pg,'psql','-X','-w','-q','-A','-t','-v','ON_ERROR_STOP=1','-U','pgadmin','-d','onboarding_fixture','-c',sql)

    def test_actual_pg17_sql_snapshot_private_custody_history_and_no_replay(self):
        with tempfile.TemporaryDirectory(dir=ROOT)as directory:
            root=Path(directory);root.chmod(0o700);ids=[];image=None
            try:
                pg=self.docker('run','-d','-e','POSTGRES_USER=pgadmin','-e','POSTGRES_DB=onboarding_fixture',
                    '-e','POSTGRES_HOST_AUTH_METHOD=trust','postgres:17').decode().strip();ids.append(pg)
                deadline=time.monotonic()+45
                while True:
                    if subprocess.run(['docker','exec',pg,'pg_isready','-U','pgadmin','-d','onboarding_fixture'],
                        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:break
                    self.assertLess(time.monotonic(),deadline);time.sleep(.5)
                self.sql(pg,"CREATE ROLE onboarding_role LOGIN; CREATE SCHEMA ouf_onboarding AUTHORIZATION onboarding_role;"
                    "CREATE TABLE ouf_onboarding.flyway_schema_history(installed_rank integer,version varchar(50),script varchar(200),type varchar(20),checksum integer,success boolean);"
                    "INSERT INTO ouf_onboarding.flyway_schema_history VALUES(1,'33','V33__fixture.sql','SQL',123,true);"
                    "CREATE TABLE ouf_onboarding.managed_onboarding_review(source_id text,onboarding_version_id uuid,configuration_hash text,readiness_attempts integer,readiness_generation bigint,readiness_phase text,readiness_lease_until timestamptz);"
                    "ALTER TABLE ouf_onboarding.managed_onboarding_review OWNER TO onboarding_role;"
                    "INSERT INTO ouf_onboarding.managed_onboarding_review VALUES('"+d.SOURCE+"','"+d.VERSION+"','"+d.CONFIGURATION+"',3,4,'PAUSED',NULL);")
                dboid=int(self.sql(pg,'SELECT oid FROM pg_database WHERE datname=current_database()').strip())
                (root/'hold.c').write_text('#include <unistd.h>\nint main(void){for(;;)sleep(60);}\n')
                subprocess.run(['gcc','-static','-Os','-o',str(root/'hold'),str(root/'hold.c')],check=True)
                (root/'Dockerfile').write_text('FROM scratch\nCOPY hold /hold\nUSER 10003:10003\nENTRYPOINT ["/hold"]\n')
                image='ouf-db-input-fixture:'+root.name;self.docker('build','-q','-t',image,str(root))
                app=self.docker('run','-d','-e','OUF_ONB_DB_URL=jdbc:postgresql://fixture-postgres:5432/onboarding_fixture',
                    '-e','OUF_ONB_DB_USER=onboarding_role',image).decode().strip();ids.append(app)
                pgrow=self.inspect(pg);approw=self.inspect(app)
                sock=str(Path('/var/run/docker.sock').resolve());s=Path(sock).stat()
                engine={'socketPath':sock,'socketBinding':[s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)]}
                legacyconfig=root/'legacy-empty';legacyconfig.mkdir(mode=0o700);cs=legacyconfig.stat()
                docker=str(Path(shutil.which('docker')).resolve())
                transport={'schema':'ouf.ingestion-rollout-native-database-read.v1','engineBinding':engine,
                    'postgresRuntimeBinding':runtime_bindings.observed(pgrow,runtime_bindings.SORTED),
                    'postgresRestartCount':0,'runtimeBindingProfile':runtime_bindings.SORTED,
                    'identity':{'database':'ingestion_different_fixture','user':'ingestion_role','databaseOid':dboid+1,'postgresPort':5432},
                    'dockerExecutable':{'path':docker,'sha256':m.sha(Path(docker).read_bytes())},
                    'dockerConfigDirectory':str(legacyconfig),'dockerConfigIdentity':[cs.st_dev,cs.st_ino,cs.st_uid,cs.st_gid,cs.st_mode],
                    'containerPrograms':{'env':'/usr/bin/env','timeout':'/usr/bin/timeout','psql':'/usr/bin/psql'},
                    'unixSocketDirectory':'/var/run/postgresql'}
                package=root/'package';package.mkdir(mode=0o700);capture=package/'input-preparation-v1';capture.mkdir(mode=0o700)
                refs={}
                for name,row in [('onboarding',approw),('postgres',pgrow)]:
                    p=capture/(name+'.json');refs[name]={'path':str(p),'sha256':private(p,row)}
                current={name:runtime_bindings.observed(row,runtime_bindings.NATIVE)for name,row in [('onboarding',approw),('postgres',pgrow)]}
                for i,name in enumerate(('gateway','ingestion','mcp','udp','registry'),1):current[name]={'containerId':str(i)*64}
                inputs={'schema':'ouf.onboarding-finite-session-private-inputs.v1','kind':'INPUTS_NOT_EXECUTABLE_AUTHORITY',
                    'targetApplyAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False,
                    'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'retainedFacts':[],
                    'runtimeObservations':refs,'legacyIngestionDatabaseControlProfile':transport,'engineBinding':engine,'currentBindings':current,
                    'currentProcessIdentities':{'onboarding':m.process(approw),'postgres':m.process(pgrow)},'restartCounts':{'onboarding':0,'postgres':0}}
                ip=capture/'inputs.json';ih=private(ip,inputs)
                private(capture/'complete.json',{'complete':True,'privateInputsHash':ih,'engineGetAttempts':14,'currentCohortStable':True})
                base=root/'base';base.mkdir(mode=0o700);owner=root/'owner';owner.mkdir(mode=0o700)
                prepared={'engine':engine,'databasePlan':{'modules':[{'module':'onboarding','schema':'ouf_onboarding',
                    'database':'onboarding_fixture','user':'onboarding_role','databaseOid':dboid}],
                    'mcpAuditRoleAdministration':{'admin':'pgadmin'}}}
                pp=base/'prepared.json';ph=private(pp,{'prepared':prepared})
                br={'scopes':{'finiteActionProcess':{'bundle':{'path':str(pp),'sha256':ph}}},'privateInputHashes':{'preparedInputs':d.digest(prepared)}}
                bh=private(base/'review.json',br)
                names=['FIXTURE_'+str(i)for i in range(10)]+['VERIFY_FINAL']
                plan={'replacements':{'onboarding':{'name':approw['Name'].lstrip('/')}},'maximumGatewayWrites':0,'engine':engine}
                scope={'planHash':d.digest(plan),'stages':names};review={'kind':'ONBOARDING_AUDIT_FIX','scopes':{'onboardingAuditUpdate':scope}}
                rh=private(owner/'review.json',review);private(owner/'execution-plan.json',plan)
                authority={'scopedExecution':{'reviewHash':d.digest(review),'approvalRef':'fixture-only'}}
                private(owner/'authority.json',authority);private(owner/'decision.json',{'reviewHash':rh,'approvalRef':'fixture-only','decision':'APPROVE_EXACT_FINITE_SCOPED_ACTION'})
                private(owner/'human.json',{'intakeHash':rh,'executionAuthorityHash':d.digest(authority),'approvalRef':'fixture-only'})
                effects=[{'stage':name,'state':'APPLIED'}for name in names]
                effects[-1]['evidence']={'applications':{'onboarding':{'runtimeBinding':runtime_bindings.observed(approw,runtime_bindings.SORTED)}}}
                journal={'scopeHash':d.digest(scope),'authorityHash':d.digest(authority),'incidentState':'RECOVERED','version':29,'nextStage':11,'effects':effects}
                private(owner/'recovery.json',journal)
                oldbytes={p:p.read_bytes()for folder in(base,owner,capture)for p in folder.iterdir()}
                for key in d.COUNTS:d.COUNTS[key]=0
                pins={'INPUT':str(ip),'INPUT_HASH':ih,'BASE':str(base),'BASE_REVIEW':bh,'OWNER':str(owner),'OWNER_REVIEW':rh}
                with patch.multiple(d,**pins),patch.object(m,'PACKAGE',str(package)):
                    result=d.prepare(m,r)
                    self.assertEqual(result['engineGetAttempts'],4);self.assertEqual(result['sqlSessionAttempts'],1)
                    self.assertEqual(result['highestSqlVersion'],33);self.assertEqual(result['selectedReadinessAttempts'],3)
                    self.assertEqual(result['selectedReadinessGeneration'],4);self.assertTrue(result['transactionReadOnly'])
                    self.assertTrue(result['onboardingDatabaseIdentityMatchesRetainedOwner']);self.assertFalse(result['databaseAdmissionProven'])
                    self.assertFalse(result['targetApplyAuthorized']);self.assertFalse(result['historicalAuthorityReused'])
                    report=json.loads((package/d.SCOPE/'snapshot-inputs.json').read_bytes())
                    self.assertEqual(result['privateSnapshotInputsHash'],d.digest(report))
                    self.assertEqual(report['profile']['identity']['database'],'onboarding_fixture')
                    self.assertNotEqual(report['profile']['identity']['database'],transport['identity']['database'])
                    self.assertEqual(list((package/d.SCOPE/'empty-docker-config').iterdir()),[])
                    self.assertTrue(all(stat.S_IMODE(p.stat().st_mode)==0o400 for p in (package/d.SCOPE).iterdir()if p.is_file()))
                    with self.assertRaisesRegex(d.Stop,'ALREADY_CLAIMED'):d.prepare(m,r)
                    self.assertEqual(d.COUNTS['sqlSessionAttempts'],1)
                    # A failed dispatch remains claimed and cannot be retried.
                    other=root/'failed-snapshot';other.mkdir(mode=0o700)
                    for key in d.COUNTS:d.COUNTS[key]=0
                    with patch.object(m,'PACKAGE',str(other)),patch.object(database_read,'bounded_read',return_value=(2,b'',b'private failure')):
                        with self.assertRaisesRegex(d.Stop,'SNAPSHOT_UNPROVEN'):d.prepare(m,r)
                        self.assertTrue((other/d.SCOPE/'sql-attempt-01.json').exists())
                        self.assertFalse((other/d.SCOPE/'complete.json').exists())
                        self.assertEqual(d.COUNTS['sqlSessionAttempts'],1)
                        with self.assertRaisesRegex(d.Stop,'ALREADY_CLAIMED'):d.prepare(m,r)
                        self.assertEqual(d.COUNTS['sqlSessionAttempts'],1)
                self.assertEqual(oldbytes,{p:p.read_bytes()for p in oldbytes})
                self.assertEqual(self.sql(pg,'SELECT readiness_attempts,readiness_generation,readiness_phase FROM ouf_onboarding.managed_onboarding_review').strip(),b'3|4|PAUSED')
                self.assertEqual(self.sql(pg,'SELECT count(*) FROM ouf_onboarding.flyway_schema_history').strip(),b'1')
                for cid,row in((pg,pgrow),(app,approw)):
                    self.assertEqual(runtime_bindings.observed(self.inspect(cid),runtime_bindings.NATIVE),runtime_bindings.observed(row,runtime_bindings.NATIVE))
                # Native read-only flags actually prevent a write, independently
                # of the SELECT-only production query (fixture command only).
                denied=subprocess.run(['docker','exec',pg,'env','-i','LC_ALL=C','PGPASSFILE=/dev/null',
                    'PGOPTIONS=-c default_transaction_read_only=on','/usr/bin/psql','-X','-w','-v','ON_ERROR_STOP=1',
                    '-U','pgadmin','-d','onboarding_fixture','-c','CREATE TABLE public.forbidden_fixture(value integer)'],
                    stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
                self.assertNotEqual(denied.returncode,0);self.assertIn(b'read-only transaction',denied.stderr)
            finally:
                for cid in ids:subprocess.run(['docker','rm','-f',cid],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)
                if image:subprocess.run(['docker','image','rm',image],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)

if __name__=='__main__':unittest.main()
