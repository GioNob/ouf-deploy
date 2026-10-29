"""Actual PostgreSQL17/18 Flyway migrations and new native SQL/Engine channels.

Disposable GitHub CI fixture only. HUMAN is a signed synthetic test session;
this suite does not prove target admission, Onboarding or full rollout G2.
"""
import copy
import os
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),
             str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_ingestion_db_preflight_native as legacy
import test_ingestion_rollout_execution as core
from tools.ingestion_rollout_execution import contract as c,database_read as d
from tools.ingestion_rollout_execution.engine_channel import NativeEngineChannel
from tools.ingestion_rollout_execution.replacement import EngineReader
from tools.chatbot_file_cohort.human_session import HumanSession
from engine_creation import Engine

@unittest.skipUnless(os.environ.get('OUF_ISOLATED_NATIVE_PLATFORM')=='1','explicit disposable platform fixture required')
class NativeDatabasePlatform(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.platform=type('_DisposablePostgresFixture',(legacy.NativeDatabase,),{})
        cls.addClassCleanup(cls.platform.doClassCleanups);cls.platform.setUpClass()
    def setUp(self):
        p=self.platform;selected=p.selected;engine=selected['engine']
        config=p.root/('empty-channel-'+self._testMethodName);config.mkdir(mode=0o700)
        self.profile={'schema':'ouf.ingestion-rollout-native-database-read.v1',
            'engineBinding':copy.deepcopy(engine),'runtimeBindingProfile':'ouf.runtime-binding.native-mount-order.v1',
            'postgresRuntimeBinding':selected['postgres'],'postgresRestartCount':p.inspect(p.pg)['RestartCount'],
            'identity':{'database':p.db,'user':p.user,'databaseOid':selected['databaseOid'],'postgresPort':5432},
            'dockerExecutable':d.governance.executable(selected['docker']['path']),
            'dockerConfigDirectory':str(config),'dockerConfigIdentity':d.empty_config_directory(str(config)),
            'containerPrograms':{'env':'/usr/bin/env','timeout':'/usr/bin/timeout','psql':'/usr/local/bin/psql'},
            'unixSocketDirectory':'/var/run/postgresql'}
        original=core.review_fixture
        def fixture(context='/fixture/execution',key_path=None):
            review,packet,inputs=original(context,key_path)
            review.update(databaseControlProfile=copy.deepcopy(self.profile),maximumDatabaseReadSessions=128,
                maximumDirectEngineGets=4096,maximumDirectEnginePosts=32,engineBinding=copy.deepcopy(engine))
            return review,packet,inputs
        with patch.object(core,'review_fixture',side_effect=fixture):core.SignedFiniteRunner.setUp(self)
        row=self.runner.journal.read();mono=time.monotonic()
        self.runner.journal.compare_and_save(row,{**row,'expiresMonotonic':mono+480,'version':row['version']+1})
        self.human=HumanSession.__new__(HumanSession);self.human.current=lambda:self.scope['humanBinding']
        actual=Engine(engine['socketPath'],tuple(engine['socketBinding']))
        self.channel=NativeEngineChannel(self.action,self.runner.journal,self.review,self.human,actual)
        self.native=d.NativeDatabaseRead(self.action,self.runner.journal,self.review,self.human,EngineReader(actual))
    def test_actual_native_fixed_query_repeated_freshness_and_no_admission(self):
        before=self.platform.facts()
        for _ in range(5):
            proof=self.native.snapshot()
            self.assertTrue(proof['databaseReadPrerequisitesProven']);self.assertTrue(proof['transactionReadOnly'])
            self.assertFalse(proof['databaseAdmissionProven']);self.assertFalse(proof['runtimeStartupMigrationPolicyProven'])
            self.assertGreaterEqual(time.time()-proof['observedAtUnix'],0)
        after=self.platform.facts()
        self.assertEqual(before['catalog'],after['catalog']);self.assertEqual(before['history'],after['history'])
        self.assertEqual(self.runner.journal.read()['nativeDatabaseReadSessions'],5)
        self.assertGreater(self.runner.journal.read()['nativeDirectEngineGets'],0)
        self.assertNotIn('nativeDirectEnginePosts',self.runner.journal.read())
    def test_real_migration_checksum_drift_is_rejected_without_repair(self):
        p=self.platform;p.admin("UPDATE ouf_ingestion.flyway_schema_history SET checksum=checksum+1 WHERE version='18'")
        try:
            with self.assertRaises(c.Denied):self.native.snapshot()
        finally:p.admin("UPDATE ouf_ingestion.flyway_schema_history SET checksum=checksum-1 WHERE version='18'")
        self.assertEqual(self.runner.journal.read()['nativeDatabaseReadSessions'],1)
        self.assertTrue(self.native.snapshot()['databaseReadPrerequisitesProven'])
    def test_real_broad_role_membership_is_rejected_then_history_retained(self):
        p=self.platform;p.admin('GRANT pg_read_all_data TO '+p.user)
        try:
            with self.assertRaises(c.Denied):self.native.snapshot()
        finally:p.admin('REVOKE pg_read_all_data FROM '+p.user)
        self.assertEqual(self.runner.journal.read()['nativeDatabaseReadSessions'],1)
        self.assertTrue(self.native.snapshot()['databaseReadPrerequisitesProven'])

if __name__=='__main__':unittest.main()
