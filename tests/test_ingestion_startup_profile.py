import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('startup_contract',ROOT/'tools/ingestion_startup_profile/contract.py')
contract=importlib.util.module_from_spec(spec);spec.loader.exec_module(contract)


class BootstrapContract(unittest.TestCase):
    def test_closed_delta_preserves_other_bootstrap_settings(self):
        before={'Entrypoint':['java','-jar','/app/app.jar'],'Cmd':['--server.port=8081'],
                'Env':['OUF_ING_DB_PASSWORD=fixture-secret'],'User':'10002:10002','Labels':{'fixture':'kept'}}
        saved=copy.deepcopy(before);after=contract.compile_config(before)
        self.assertEqual(before,saved)
        self.assertEqual(after['Cmd'],before['Cmd']+list(contract.FLAGS))
        self.assertEqual(after['Env'],before['Env']+['SPRING_FLYWAY_ENABLED=false'])
        restored=copy.deepcopy(after);restored['Cmd']=before['Cmd'];restored['Env']=before['Env']
        self.assertEqual(restored,before)

    def test_ambiguous_or_conflicting_policy_is_denied(self):
        base={'Entrypoint':['java','-jar','/app/app.jar'],'Cmd':[],'Env':[]}
        for args in (['--'],['--spring.flyway.enabled=true'],['--spring-flyway-enabled=true'],['--ouf.ingestion.startup.schema-mode=OTHER']):
            with self.subTest(args=args),self.assertRaises(ValueError):contract.compile_config(dict(base,Cmd=args))
        for entries in (['SPRING_FLYWAY_ENABLED=true'],['A=1','A=2']):
            with self.assertRaises(ValueError):contract.compile_config(dict(base,Env=entries))
        with self.assertRaises(ValueError):contract.compile_config(dict(base,Entrypoint=['sh','-c']))


if 'OUF_TEST_ROOT' in os.environ:
    import test_ingestion_db_preflight_native as legacy

    class NativeStartupProfile(legacy.NativeDatabase):
        @classmethod
        def setUpClass(cls):
            super().setUpClass()
            pg=cls.inspect(cls.pg)
            port=pg['NetworkSettings']['Ports']['5432/tcp'][0]['HostPort']
            cls.app_environment=dict(os.environ,OUF_ING_DB_URL='jdbc:postgresql://127.0.0.1:'+port+'/'+cls.db,
                OUF_ING_DB_USER=cls.user,OUF_ING_DB_PASSWORD='ci-only-runtime')
            cls.app_classpath=os.environ['OUF_STARTUP_CLASSPATH']
            cls.admin("CREATE FUNCTION public.fixture_deny_app_ddl() RETURNS event_trigger LANGUAGE plpgsql AS $$ BEGIN IF current_user='"+cls.user+"' THEN RAISE EXCEPTION 'CI_APP_DDL_FORBIDDEN' USING ERRCODE='42501'; END IF; END $$")
            cls.admin("CREATE EVENT TRIGGER fixture_no_app_ddl ON ddl_command_start EXECUTE FUNCTION public.fixture_deny_app_ddl()")

        def probe(self,mode='health',arguments=(),environment=None,seconds=45):
            args=[os.environ['OUF_FIXTURE_JAVA'],'-cp',self.app_classpath,'StartupProfileProbe',mode,*arguments]
            result=subprocess.run(args,capture_output=True,timeout=seconds,env=environment or self.app_environment)
            self.assertEqual(result.returncode,0,'NATIVE_STARTUP_PROBE_FAILED: '+result.stdout.decode(errors='replace')[-1800:]+result.stderr.decode(errors='replace')[-1200:])
            lines=[v.split('=',1)[1]for v in result.stdout.decode().splitlines()if v.startswith('OUF_STARTUP_PROFILE_PROOF=')]
            self.assertEqual(len(lines),1)
            return json.loads(lines[0])

        def test_readiness_exact_release_history_uses_read_only_transaction(self):
            result=self.probe()
            self.assertEqual(result['status'],'UP')
            self.assertEqual(result['details']['sqlMigrations'],18)
            self.assertTrue(result['details']['transactionReadOnly'])

        def test_readiness_checksum_drift_fails_closed_without_repair(self):
            self.admin("UPDATE ouf_ingestion.flyway_schema_history SET checksum=checksum+1 WHERE version='18'")
            try:self.assertEqual(self.probe()['status'],'DOWN')
            finally:self.admin("UPDATE ouf_ingestion.flyway_schema_history SET checksum=checksum-1 WHERE version='18'")

        def test_readiness_failed_or_future_migration_fails_closed(self):
            self.admin("UPDATE ouf_ingestion.flyway_schema_history SET success=false WHERE version='18'")
            try:self.assertEqual(self.probe()['status'],'DOWN')
            finally:self.admin("UPDATE ouf_ingestion.flyway_schema_history SET success=true WHERE version='18'")
            self.admin("UPDATE ouf_ingestion.flyway_schema_history SET version='19' WHERE version='18'")
            try:self.assertEqual(self.probe()['status'],'DOWN')
            finally:self.admin("UPDATE ouf_ingestion.flyway_schema_history SET version='18' WHERE version='19'")

        def test_readiness_missing_required_migration_fails_closed(self):
            row=self.admin("SELECT row_to_json(h) FROM ouf_ingestion.flyway_schema_history h WHERE version='18'").decode().strip()
            self.admin("DELETE FROM ouf_ingestion.flyway_schema_history WHERE version='18'")
            try:self.assertEqual(self.probe()['status'],'DOWN')
            finally:self.admin("INSERT INTO ouf_ingestion.flyway_schema_history SELECT * FROM json_populate_record(NULL::ouf_ingestion.flyway_schema_history,$fixture$"+row+"$fixture$::json)")

        def test_actual_spring_context_has_no_flyway_and_makes_no_schema_changes(self):
            before=self.facts()
            flags=contract.compile_config({'Entrypoint':['java','-jar','/app/app.jar'],'Cmd':[],'Env':[]})['Cmd']
            arguments=[*flags,'--server.port=0','--spring.main.banner-mode=off','--logging.level.root=ERROR']
            result=self.probe('context',arguments)
            self.assertEqual(result['flywayBeans'],0)
            self.assertTrue(result['guardPresent'])
            after=self.facts()
            self.assertEqual(before['history'],after['history'])
            self.assertEqual(before['catalog'],after['catalog'])

        def test_cli_profile_wins_over_json_and_jvm_flyway_true(self):
            flags=list(contract.FLAGS)+['--server.port=0','--spring.main.banner-mode=off','--logging.level.root=ERROR']
            environment=dict(self.app_environment,SPRING_FLYWAY_ENABLED='true',
                SPRING_APPLICATION_JSON='{"spring":{"flyway":{"enabled":true}}}',
                JAVA_TOOL_OPTIONS='-Dspring.flyway.enabled=true')
            result=self.probe('context',flags,environment)
            self.assertFalse(result['effectiveFlywayEnabled'])

        def test_true_flyway_is_blocked_before_startup_migration(self):
            name=self.db+'_empty'
            self.admin('CREATE DATABASE '+name+' OWNER '+self.user)
            environment=dict(self.app_environment,OUF_ING_DB_URL=self.app_environment['OUF_ING_DB_URL'].rsplit('/',1)[0]+'/'+name)
            try:
                result=self.probe('blocked',['--ouf.ingestion.startup.schema-mode=VALIDATE_ONLY',
                    '--spring.flyway.enabled=true','--spring.main.banner-mode=off','--logging.level.root=ERROR'],environment)
                self.assertEqual(result['reason'],'ING_STARTUP_MIGRATE_FORBIDDEN')
                check=subprocess.run([self.docker,'exec',self.pg,'psql','-X','-q','-A','-t','-U','postgres','-d',name,
                    '-c',"SELECT count(*) FROM pg_namespace WHERE nspname='ouf_ingestion'"],capture_output=True,timeout=10)
                self.assertEqual(check.returncode,0);self.assertEqual(check.stdout.strip(),b'0')
            finally:self.admin('DROP DATABASE '+name+' WITH (FORCE)')


if __name__=='__main__':unittest.main()
