import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('db_preflight', ROOT / 'scripts/read-ingestion-db-preflight-20261020.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


def fixture_facts():
    return {'observedAtUnix':1792472533,'database':'selected_db','databaseOid':42,'role':'runtime_role','readOnly':True,
            'serverVersionNum':170009,'encoding':'UTF8','allowConnections':True,'preparedTransactions':0,
            'connectAllowed':True,'schemaUsage':True,'schemaCreate':True,
            'roleFlags':dict.fromkeys(('superuser','createRole','createDb','replication','bypassRls'),False),
            'broadRoleMemberships':dict.fromkeys(('pg_read_all_data','pg_write_all_data','pg_execute_server_program','pg_read_server_files','pg_write_server_files','pg_signal_backend'),False),
            'history':[dict(r,installed_rank=i+1) for i,r in enumerate(m.expected_history())],
            'catalog':{k:[] for k in ('relations','columns','constraints','indexes','triggers','functions','sequences','policies')},
            'tablePrivileges':[dict(name=n,select_allowed=True,insert_allowed=True,update_allowed=True,delete_allowed=True) for n in sorted(m.TABLES | {'flyway_schema_history'})],
            'sequencePrivileges':[dict(name=n,usage_allowed=True) for n in sorted(m.SEQUENCES)],
            'functionExecuteAllowed':True,
            'pressurePolicies':[dict(policy_key='GLOBAL',state='NORMAL',global_running_limit=8,soft_outbox_limit=1000,hard_outbox_limit=5000,recovery_outbox_limit=500)],
            'work':dict.fromkeys(('runnableRuns','eligibleSchedules','liveScheduleLeases','unackedOutbox','liveOutboxLeases'),0),
            'connections':dict(serverMaximum=100,serverObserved=8,databaseObserved=2,databaseLimit=-1,lockWaiters=0,unobservablePeers=0,advisoryLocks=0)}


class ReadContract(unittest.TestCase):
    def setUp(self):
        self.facts = fixture_facts()
        self.selected = dict(database='selected_db',databaseOid=42,user='runtime_role')

    def result(self):
        with patch.object(m,'REFERENCE_CATALOG_SHA256',m.digest(fixture_facts()['catalog'])):
            return m.analyze(self.facts,self.selected)

    def test_complete_read_prerequisites_do_not_issue_runtime_authority(self):
        report = self.result()
        self.assertTrue(report['databaseReadPrerequisitesProven'])
        self.assertTrue(report['runtimeRoleBroadFlagsAbsent'])
        self.assertEqual(report['installedSqlMigrationCount'],18)
        self.assertNotIn('database',report); self.assertNotIn('role',report)

    def test_unqualified_catalog_cannot_prove_read_prerequisites(self):
        with patch.object(m,'REFERENCE_CATALOG_SHA256',None):
            self.assertFalse(m.analyze(self.facts,self.selected)['databaseReadPrerequisitesProven'])

    def test_wrong_oid_or_role_or_non_read_only_is_denied(self):
        for key,value in (('databaseOid',43),('role','admin'),('readOnly',False)):
            facts = dict(self.facts,**{key:value})
            with self.assertRaises(m.Denied): m.analyze(facts,self.selected)

    def test_history_missing_failed_or_checksum_changed_is_not_accepted(self):
        for kind in ('missing','failed','checksum','extra'):
            self.facts = fixture_facts()
            if kind == 'missing': self.facts['history'].pop()
            elif kind == 'failed': self.facts['history'][-1]['success'] = False
            elif kind == 'checksum': self.facts['history'][-1]['checksum'] += 1
            else: self.facts['history'].append(dict(self.facts['history'][-1],version='19',script='V19__foreign.sql'))
            self.assertFalse(self.result()['databaseReadPrerequisitesProven'])

    def test_exact_schema_marker_is_retained(self):
        self.facts['history'].insert(0,dict(installed_rank=0,version=None,script='"ouf_ingestion"',type='SCHEMA',checksum=None,success=True))
        self.assertTrue(self.result()['schemaCreationMarkerRetained'])
        self.assertTrue(self.result()['sqlHistoryMatchesCandidate'])

    def test_catalog_drift_is_not_hidden_by_unchanged_history(self):
        self.facts['catalog']['columns'].append({'name':'rogue'})
        result = self.result()
        self.assertTrue(result['sqlHistoryMatchesCandidate'])
        self.assertFalse(result['runtimeCatalogMatchesQualifiedCandidate'])
        self.assertIsNone(result['catalogDigest'])
        self.assertFalse(result['databaseReadPrerequisitesProven'])

    def test_privilege_gap_or_broad_membership_blocks_preflight(self):
        row = next(r for r in self.facts['tablePrivileges'] if r['name']=='ing_run')
        row['update_allowed'] = False
        self.assertFalse(self.result()['requiredRuntimePrivilegesAvailable'])
        self.assertIn({'table':'ing_run','permission':'update_allowed'},self.result()['privilegeGaps'])
        self.facts = fixture_facts(); self.facts['broadRoleMemberships']['pg_execute_server_program'] = True
        self.assertFalse(self.result()['databaseReadPrerequisitesProven'])

    def test_superuser_role_is_not_runtime_admission(self):
        self.facts['roleFlags']['superuser'] = True
        self.assertFalse(self.result()['runtimeRoleBroadFlagsAbsent'])

    def test_pressure_active_work_and_control_capacity_block(self):
        for kind in ('pressure','runnable','schedule','lease','headroom','invisible','advisory','outbox'):
            self.facts = fixture_facts()
            if kind == 'pressure': self.facts['pressurePolicies'][0]['state'] = 'HARD_PRESSURE'
            elif kind == 'runnable': self.facts['work']['runnableRuns'] = 1
            elif kind == 'schedule': self.facts['work']['eligibleSchedules'] = 1
            elif kind == 'lease': self.facts['work']['liveOutboxLeases'] = 1
            elif kind == 'headroom': self.facts['connections']['serverObserved'] = 98
            elif kind == 'invisible': self.facts['connections']['unobservablePeers'] = 1
            elif kind == 'advisory': self.facts['connections']['advisoryLocks'] = 1
            else: self.facts['work']['unackedOutbox'] = 10001
            self.assertFalse(self.result()['databaseReadPrerequisitesProven'],kind)

    def test_sql_file_and_embedded_query_are_exactly_equal_and_non_mutating(self):
        self.assertEqual(m.SQL,(ROOT/'tools/ingestion_db_preflight/query.sql').read_text())
        self.assertIn('REPEATABLE READ READ ONLY',m.SQL)
        self.assertNotRegex(m.SQL,r'(?im)^\s*(CREATE|ALTER|DROP|INSERT|UPDATE|DELETE|GRANT|REVOKE|TRUNCATE|COPY|CALL|DO)\b')
        self.assertNotIn('FOR UPDATE',m.SQL)
        self.assertNotIn('refresh_pressure_state()',m.SQL)

    def test_fixed_native_arguments_do_not_forward_credentials_or_services(self):
        selected = dict(self.selected,postgres={'containerId':'e'*64},engine={'socketPath':'/run/retained.sock'},dockerConfigDirectory='/private/context')
        args = m.native_arguments(selected,'/bound/docker')
        self.assertIn('PGPASSFILE=/dev/null',args)
        self.assertIn('env',args); self.assertIn('-i',args); self.assertIn('-w',args)
        self.assertEqual(args[-1],m.SQL)
        for bad in ('role;DROP TABLE x','other/db','-hforeign'):
            with self.assertRaises(m.Denied): m.native_arguments(dict(selected,user=bad),'/bound/docker')

    def test_bounded_native_child_has_output_and_time_caps(self):
        code,out,_ = m.bounded_command([sys.executable,'-I','-S','-c','print("bounded")'])
        self.assertEqual((code,out),(0,b'bounded\n'))
        with self.assertRaises(m.Denied):
            m.bounded_command([sys.executable,'-I','-S','-c','print("x"*10000)'],maximum=50)
        with self.assertRaises(m.Denied):
            m.bounded_command([sys.executable,'-I','-S','-c','import time;time.sleep(5)'],seconds=.1)


class RetainedSelection(unittest.TestCase):
    def setUp(self):
        self.engine = {'socketPath':'/run/selected.sock','socketBinding':[1,2,0,0,0o600]}
        binding = {'sessionDirectory':'/retained/HUMAN_NOT_OPENED'}
        db = {'schema':'ouf.chatbot-cohort-database-plan.v1','postgresRuntimeBinding':{'containerId':'a'*64},
              'mcpAuditRoleAdministration':None,
              'modules':[{'module':n,'schema':'ouf_'+n,'database':n+'_db','user':n+'_role','databaseOid':42+i,
                          'expectedMigrations':m.expected_history()} for i,n in enumerate(('onboarding','udp','ingestion','mcp'))]}
        original = {'schema':'ouf.chatbot-file-cohort-prepared-inputs.v1','databasePlan':db,
                    'cohortPlan':{'databasePlanHash':m.digest(db)},'engine':self.engine}
        case = {'humanBinding':binding,'originalBinding':{'path':'/retained/original.json','sha256':m.digest(original)}}
        package = {'sourceCommit':m.SOURCE,'closure':{'declaration':{'moduleCount':244},'executables':{'docker':{'path':'/bound/docker','sha256':'e'*64}}},
                   'fileHashes':{'case.json':m.digest(case)},'executionPins':{'caseSha256':m.digest(case)}}
        review = {'sourceClosureHash':m.digest(package['closure'])}
        self.original,self.package,self.case = original,package,case
        self.values = {str(m.OWNER/'execution-plan.json'):{'humanBinding':binding,'engine':self.engine,'currentApplications':{'ingestion':{'containerId':'b'*64}}},
                       str(m.OWNER/'update-result.json'):{'complete':True,'planHash':m.OWNER_PLAN},str(m.CONTEXT/'package.json'):package,
                       str(m.CONTEXT/'review.json'):review,str(m.CONTEXT/'decision.json'):{'reviewHash':m.digest(review)},
                       str(m.CONTEXT/'runtime.claim.json'):{'packageHash':m.digest(package),'automaticReplayAllowed':False},
                       str(m.CONTEXT/'case.json'):case,case['originalBinding']['path']:original,
                       str(m.INPUT/'inputs.json'):{'candidateMetadata':{'sourceCommit':m.MANIFEST['sourceCommit'],'imageId':m.MANIFEST['imageId'],
                         'migrationInventory':{r['script']:r['resourceSha256'] for r in m.MANIFEST['migrations']}}}}
        self.reads = []

    def parse(self,path,expected=None):
        self.reads.append(str(path))
        if str(path) == str(m.OWNER/'execution-plan.json'): self.assertEqual(expected,m.OWNER_PLAN)
        if str(path) == self.case['originalBinding']['path']: self.assertEqual(expected,self.case['originalBinding']['sha256'])
        if str(path) == str(m.INPUT/'inputs.json'): self.assertEqual(expected,m.INPUT_HASH)
        return copy.deepcopy(self.values[str(path)])

    def test_runtime_role_is_selected_even_without_old_mcp_admin_binding(self):
        selected = m.selection(self.parse)
        self.assertEqual(selected['user'],'ingestion_role')
        self.assertEqual(selected['database'],'ingestion_db')
        self.assertEqual(selected['databaseOid'],44)
        self.assertFalse(any('HUMAN_NOT_OPENED' in p or p.endswith('human-access.jwt') for p in self.reads))

    def test_tampered_database_plan_or_candidate_manifest_is_denied(self):
        self.original['databasePlan']['modules'][2]['database'] = 'foreign_db'
        with self.assertRaises(m.Denied): m.selection(self.parse)


if __name__ == '__main__': unittest.main()
