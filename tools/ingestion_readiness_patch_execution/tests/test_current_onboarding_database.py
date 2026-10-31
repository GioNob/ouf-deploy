"""Current b0 owner-bound reader with real PostgreSQL17 and Engine generations.

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



qpath=ROOT/'scripts/read-current-onboarding-database-20261024.py'
if not qpath.exists():qpath=ROOT/'read-current-onboarding-database-20261024.py'
q=module('current_onboarding_database',qpath)
cpath=ROOT/'scripts/reconcile-onboarding-engine-metadata-20261024.py'
if not cpath.exists():cpath=ROOT/'reconcile-onboarding-engine-metadata-20261024.py'
c=module('current_database_metadata_helpers',cpath)
l=None  # bootstrap is distinct; production never invokes prior prepare/main.

def history(owner,engine=None,boot='fixture',runtime=None,name='fixture'):
    runtime=q.HISTORICAL_RUNTIME if runtime is None else runtime
    plan={'schema':'ouf.installation-binding-owner-update-plan.v1','authorityDirectory':owner,'engine':engine,
        'replacements':{'onboarding':{'imageAudit':{'sourceCommit':q.SOURCE},'name':name}},
        'databaseMigration':None,'onboardingMigrationsUnchanged':True,'maximumGatewayWrites':0}
    scope={'planHash':q.digest(plan),'stages':list(q.STAGES),'candidateSourceCommit':q.SOURCE,'onboardingMigrationsUnchanged':True}
    review={'scopes':{'installationOwnerUpdate':scope}}
    authority={'scopedExecution':{'reviewHash':q.digest(review)}}
    effects=[{'stage':stage,'state':'APPLIED','intentHash':q.digest({'planHash':q.digest(plan),'stage':stage})}for stage in q.STAGES]
    effects[-1]['evidence']={'onboarding':{'runtimeBinding':runtime},'databaseMigrationsPerformed':0,'metadataChanged':False,
        'routeMapHash':'d5a4040e30e289c150f9d2862ff41e83e22809a9e2202ac19388e744f2c5e927'}
    journal={'schema':'ouf.installation-binding-owner-update-journal.v1','version':29,'scopeHash':q.digest(scope),
        'authorityHash':q.digest(authority),'bootId':boot,'budgetReset':False,'incidentState':'RECOVERED','nextStage':len(effects),'effects':effects}
    return plan,review,authority,journal

class Guards(unittest.TestCase):
    def test_b0_owner_is_not_be388_parent_and_eleven_complete_stages_required(self):
        self.assertEqual(q.SOURCE,'b0f5e3dacbe59ebf87e22dd6af2575e41249f51d')
        self.assertEqual(len(q.STAGES),11)
        rows=history(q.OWNER);self.assertEqual(q.verify_owner(*rows,q.digest(rows[2]),None,'fixture')['onboarding']['runtimeBinding'],q.HISTORICAL_RUNTIME)

    def test_wrong_owner_engine_source_or_database_effect_refused(self):
        for field in ('context','engine','source','migration'):
            rows=history(q.OWNER);plan=rows[0]
            if field=='context':plan['authorityDirectory']='/old/owner'
            elif field=='engine':plan['engine']={'wrong':'binding'}
            elif field=='source':plan['replacements']['onboarding']['imageAudit']['sourceCommit']='be388e1462778438a208c2e00e166370fee32189'
            else:plan['databaseMigration']={'to':35}
            with self.assertRaises(q.Stop):q.verify_owner(*rows,q.digest(rows[2]),None,'fixture')

    def test_partial_intent_authority_boot_and_runtime_drift_refused(self):
        for field in ('partial','intent','authority','boot','runtime'):
            rows=history(q.OWNER);journal=rows[3]
            if field=='partial':journal['effects'][-1]['state']='CLAIMED'
            elif field=='intent':journal['effects'][3]['intentHash']='0'*64
            elif field=='authority':journal['authorityHash']='0'*64
            elif field=='boot':journal['bootId']='different'
            else:journal['effects'][-1]['evidence']['onboarding']['runtimeBinding']={}
            with self.assertRaises(q.Stop):q.verify_owner(*rows,q.digest(rows[2]),None,'fixture')

    def test_fixed_query_reads_v34_trigger_and_rejects_injection(self):
        sql=q.query(d,'onboarding_role')
        self.assertTrue(sql.startswith('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;'));self.assertTrue(sql.endswith('ROLLBACK;'))
        self.assertIn('pg_get_triggerdef',sql);self.assertIn('source_property_revision',sql);self.assertNotIn('FOR UPDATE',sql)
        with self.assertRaises(d.Stop):q.query(d,"role';COMMIT;--")

    def test_attempt_scope_is_distinct_and_replay_precedes_all_reads(self):
        self.assertNotEqual(q.SCOPE,d.SCOPE)
        with tempfile.TemporaryDirectory(dir=ROOT)as directory:
            root=Path(directory);(root/q.SCOPE).mkdir(mode=0o700)
            with patch.object(m,'PACKAGE',str(root)),patch.object(m.Facts,'json',side_effect=AssertionError('no reads')):
                with self.assertRaisesRegex(q.Stop,'ALREADY_CLAIMED'):q.prepare(None,c,d,m,r)

    def test_profile_does_not_accept_old_scope_or_credential_fallback(self):
        p={'schema':'ouf.current-onboarding-database-snapshot-profile.v1','maximumSqlSessionAttempts':1,
            'identity':{'database':'onboarding_fixture','runtimeRole':'app_role','adminRole':'pgadmin','postgresPort':5432},
            'sqlSha256':hashlib.sha256(q.query(d,'app_role').encode()).hexdigest(),
            'dockerExecutable':{'path':'/protected/docker'},'engineBinding':{'socketPath':'/protected/engine.sock'},
            'postgresRuntimeBinding':{'containerId':'a'*64},'containerPrograms':{'env':'/usr/bin/env','timeout':'/usr/bin/timeout','psql':'/usr/bin/psql'},
            'unixSocketDirectory':'/private/socket'}
        argv=q.arguments(d,p,'/private/empty')
        for v in ('PGPASSFILE=/dev/null','PGSERVICEFILE=/dev/null','PGSYSCONFDIR=/nonexistent','-i','-X','-w'):self.assertIn(v,argv)
        self.assertEqual(argv[-1],q.query(d,'app_role'));p['schema']='ouf.onboarding-finite-database-snapshot-profile.v1'
        with self.assertRaises(q.Stop):q.arguments(d,p,'/private/empty')

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
                    # The official image's temporary init server listens only
                    # on Unix sockets; wait for the final TCP server instead.
                    if subprocess.run(['docker','exec',pg,'pg_isready','-h','127.0.0.1','-U','pgadmin','-d','onboarding_fixture'],
                        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:break
                    self.assertLess(time.monotonic(),deadline);time.sleep(.5)
                self.sql(pg,"CREATE ROLE onboarding_role LOGIN; CREATE SCHEMA ouf_onboarding AUTHORIZATION onboarding_role;"
                    "CREATE TABLE ouf_onboarding.flyway_schema_history(installed_rank integer,version varchar(50),script varchar(200),type varchar(20),checksum integer,success boolean);"
                    "INSERT INTO ouf_onboarding.flyway_schema_history VALUES(1,'33','V33__fixture.sql','SQL',123,true);"
                    "CREATE TABLE ouf_onboarding.managed_onboarding_review(source_id text,onboarding_version_id uuid,configuration_hash text,readiness_attempts integer,readiness_generation bigint,readiness_phase text,readiness_lease_until timestamptz);"
                    "ALTER TABLE ouf_onboarding.managed_onboarding_review OWNER TO onboarding_role;"
                    "INSERT INTO ouf_onboarding.managed_onboarding_review VALUES('"+d.SOURCE+"','"+d.VERSION+"','"+d.CONFIGURATION+"',3,4,'PAUSED',NULL);")
                self.sql(pg,"CREATE TABLE ouf_onboarding.source_property_revision(dummy integer);"
                    "CREATE FUNCTION ouf_onboarding.reject_fixture_change() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'append-only fixture'; END;$$;"
                    "CREATE TRIGGER source_property_revision_append_only BEFORE UPDATE OR DELETE ON ouf_onboarding.source_property_revision FOR EACH ROW EXECUTE FUNCTION ouf_onboarding.reject_fixture_change();"
                    "INSERT INTO ouf_onboarding.flyway_schema_history VALUES(2,'34','V34__source_property_revision.sql','SQL',-1996496299,true);")
                dboid=int(self.sql(pg,'SELECT oid FROM pg_database WHERE datname=current_database()').strip())
                (root/'hold.c').write_text('#include <unistd.h>\nint main(void){for(;;)sleep(60);}\n')
                subprocess.run(['gcc','-static','-Os','-o',str(root/'hold'),str(root/'hold.c')],check=True)
                (root/'Dockerfile').write_text('FROM scratch\nCOPY hold /hold\nUSER 10003:10003\nENTRYPOINT ["/hold"]\n')
                image='ouf-db-input-fixture:'+root.name;self.docker('build','-q','-t',image,str(root))
                app=self.docker('run','-d','--label','org.opencontainers.image.revision='+q.SOURCE,'-e','OUF_ONB_DB_URL=jdbc:postgresql://fixture-postgres:5432/onboarding_fixture',
                    '-e','OUF_ONB_DB_USER=onboarding_role','-e','JAVA_TOOL_OPTIONS=-Xmx128m',image).decode().strip();ids.append(app)
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
                newowner=root/'current-b0-owner';newowner.mkdir(mode=0o700)
                current_pin=runtime_bindings.observed(approw,runtime_bindings.SORTED)
                newplan,newreview,newauthority,newjournal=history(str(newowner),engine,inputs['bootId'],current_pin,approw['Name'].lstrip('/'))
                for name,row in [('execution-plan.json',newplan),('review.json',newreview),('authority.json',newauthority),('recovery.json',newjournal)]:private(newowner/name,row)
                lineageroot=root/'completed-lineage';lineageroot.mkdir(mode=0o700)
                lp=lineageroot/'lineage.json'
                selection=d.database_selection(approw,prepared['databasePlan']['modules'][0],transport)
                lh=private(lp,{'schema':'ouf.current-source-revision-lineage-private.v1','inputHash':ih,
                    'assessment':{'historicalPostgresRuntimeMatchesCaptured':True,'declaredCapturedOnboardingSourceCommit':q.SOURCE},
                    'newBindingAcceptedForRuntime':False,'newSqlAttemptAuthorized':False,'oldBudgetImageBlocked':True,'targetApplyAuthorized':False,
                    'retainedFiles':[{'path':str(pp),'sha256':ph}],
                    'proposedOnboardingIdentity':{'binding':prepared['databasePlan']['modules'][0],'adminRole':'pgadmin','currentEnvironmentDeclaration':selection}})
                private(lineageroot/'complete.json',{'complete':True,'privateLineageHash':lh,'status':'CURRENT_SOURCE_REVISION_LINEAGE_OBSERVED'})
                for key in d.COUNTS:d.COUNTS[key]=0
                pins={'INPUT':str(ip),'INPUT_HASH':ih,'BASE':str(base),'BASE_REVIEW':bh,'OWNER':str(owner),'OWNER_REVIEW':rh}
                with patch.multiple(d,**pins),patch.multiple(q,OWNER=str(newowner),LINEAGE=str(lp),LINEAGE_HASH=lh,HISTORICAL_RUNTIME=current_pin),patch.object(m,'PACKAGE',str(package)):
                    result=q.prepare(l,c,d,m,r)
                    self.assertEqual(result['engineGetAttempts'],4);self.assertEqual(result['sqlSessionAttempts'],1)
                    self.assertEqual(result['highestSqlVersion'],34);self.assertTrue(result['v34SourcePropertyRevisionObserved']);self.assertTrue(result['sourceRevisionAppendOnlyTriggerObserved']);self.assertFalse(result['v35AlreadyRecorded']);self.assertFalse(result['allCurrentConfigurationPrecedenceResolved']);self.assertEqual(result['selectedReadinessAttempts'],3)
                    self.assertEqual(result['selectedReadinessGeneration'],4);self.assertTrue(result['transactionReadOnly'])
                    self.assertTrue(result['onboardingDatabaseIdentityMatchesRetainedOwner']);self.assertFalse(result['databaseAdmissionProven'])
                    self.assertFalse(result['targetApplyAuthorized']);self.assertFalse(result['historicalAuthorityReused'])
                    report=json.loads((package/q.SCOPE/'snapshot-inputs.json').read_bytes())
                    self.assertEqual(result['privateSnapshotInputsHash'],d.digest(report))
                    self.assertEqual(report['profile']['identity']['database'],'onboarding_fixture')
                    self.assertNotEqual(report['profile']['identity']['database'],transport['identity']['database'])
                    self.assertEqual(list((package/q.SCOPE/'empty-docker-config').iterdir()),[])
                    self.assertTrue(all(stat.S_IMODE(p.stat().st_mode)==0o400 for p in (package/q.SCOPE).iterdir()if p.is_file()))
                    with self.assertRaisesRegex(q.Stop,'ALREADY_CLAIMED'):q.prepare(l,c,d,m,r)
                    self.assertEqual(d.COUNTS['sqlSessionAttempts'],1)
                    # A failed dispatch remains claimed and cannot be retried.
                    other=root/'failed-snapshot';other.mkdir(mode=0o700)
                    for key in d.COUNTS:d.COUNTS[key]=0
                    with patch.object(m,'PACKAGE',str(other)),patch.object(database_read,'bounded_read',return_value=(2,b'',b'private failure')):
                        with self.assertRaisesRegex(q.Stop,'SNAPSHOT_UNPROVEN'):q.prepare(l,c,d,m,r)
                        self.assertTrue((other/q.SCOPE/'sql-attempt-01.json').exists())
                        self.assertFalse((other/q.SCOPE/'complete.json').exists())
                        self.assertEqual(d.COUNTS['sqlSessionAttempts'],1)
                        with self.assertRaisesRegex(q.Stop,'ALREADY_CLAIMED'):q.prepare(l,c,d,m,r)
                        self.assertEqual(d.COUNTS['sqlSessionAttempts'],1)
                    driftroot=root/'drift-before-sql';driftroot.mkdir(mode=0o700)
                    for key in d.COUNTS:d.COUNTS[key]=0
                    changed=copy.deepcopy(approw);changed['Config']['Env'].append('FIXTURE_CHANGED=true')
                    def drift_get(engine,cid):
                        engine.calls+=1;return changed,b''
                    with patch.object(m,'PACKAGE',str(driftroot)),patch.object(m.Engine,'get',drift_get),patch.object(database_read,'bounded_read',side_effect=AssertionError('no SQL after drift')):
                        with self.assertRaisesRegex(q.Stop,'GENERATION_CHANGED'):q.prepare(l,c,d,m,r)
                        self.assertEqual(d.COUNTS['engineGetAttempts'],1);self.assertEqual(d.COUNTS['sqlSessionAttempts'],0)
                        self.assertFalse((driftroot/q.SCOPE/'sql-attempt-01.json').exists())
                self.assertEqual(oldbytes,{p:p.read_bytes()for p in oldbytes})
                self.assertEqual(self.sql(pg,'SELECT readiness_attempts,readiness_generation,readiness_phase FROM ouf_onboarding.managed_onboarding_review').strip(),b'3|4|PAUSED')
                self.assertEqual(self.sql(pg,'SELECT count(*) FROM ouf_onboarding.flyway_schema_history').strip(),b'2')
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
