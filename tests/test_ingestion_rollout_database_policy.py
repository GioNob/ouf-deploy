"""Strict new DB snapshot policy, synthetic facts only; no native admission."""
import ast
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from tools.ingestion_rollout_execution import database_policy as p
from tools.ingestion_rollout_execution.contract import Denied,digest

def facts():
    return {'observedAtUnix':1792480000,'database':'ente_db','databaseOid':42,'role':'ente_runtime','readOnly':True,
        'serverVersionNum':170009,'serverPort':15432,'encoding':'UTF8','allowConnections':True,'preparedTransactions':0,
        'connectAllowed':True,'schemaUsage':True,'schemaCreate':True,'functionExecuteAllowed':True,
        'roleFlags':dict.fromkeys(p.ROLE_FLAGS,False),'broadRoleMemberships':dict.fromkeys(p.BROAD_ROLES,False),
        'history':[dict(r,installed_rank=i+1)for i,r in enumerate(p.expected_history())],
        'catalog':{k:[]for k in p.CATALOG_LIMITS},
        'tablePrivileges':[dict(name=n,select_allowed=True,insert_allowed=True,update_allowed=True,delete_allowed=True)
                           for n in sorted(p.TABLES|{'flyway_schema_history'})],
        'sequencePrivileges':[dict(name=n,usage_allowed=True)for n in sorted(p.SEQUENCES)],
        'pressurePolicies':[dict(policy_key='GLOBAL',state='NORMAL',global_running_limit=8,soft_outbox_limit=1000,
                                 hard_outbox_limit=5000,recovery_outbox_limit=500)],
        'work':dict.fromkeys(p.WORK,0),
        'connections':dict(serverMaximum=100,serverObserved=8,databaseObserved=2,databaseLimit=-1,
                           lockWaiters=0,unobservablePeers=0,advisoryLocks=0)}

class SnapshotPolicy(unittest.TestCase):
    def setUp(self):
        self.facts=facts();self.selected={'database':'ente_db','user':'ente_runtime','databaseOid':42,'postgresPort':15432}
        self.now=self.facts['observedAtUnix']+1.
    def synthetic_result(self):
        # Empty catalog is deliberately synthetic. It never matches the fixed
        # production release hash; positive policy branches are unit-level only.
        with patch.object(p,'REFERENCE_CATALOG_SHA256',digest(facts()['catalog'])):
            return p.qualify_snapshot(self.facts,self.selected,now=self.now)
    def test_snapshot_never_issues_runtime_admission_even_for_positive_unit_branches(self):
        report=self.synthetic_result();self.assertTrue(report['databaseReadPrerequisitesProven'])
        self.assertFalse(report['databaseAdmissionProven']);self.assertFalse(report['runtimeAuthorityIssued'])
        self.assertFalse(report['runtimeStartupMigrationPolicyProven'])
        self.assertNotIn('database',report);self.assertNotIn('role',report)
    def test_synthetic_catalog_cannot_pass_real_release_pin(self):
        report=p.qualify_snapshot(self.facts,self.selected,now=self.now)
        self.assertFalse(report['databaseReadPrerequisitesProven'])
        self.assertFalse(report['runtimeCatalogMatchesQualifiedCandidate'])
    def test_role_membership_omission_and_integer_boolean_are_rejected(self):
        for mutate in(lambda f:f.update(broadRoleMemberships={}),
                      lambda f:f['broadRoleMemberships'].update(pg_read_all_data=0),
                      lambda f:f.update(roleFlags={}),
                      lambda f:f.update(readOnly=1)):
            f=copy.deepcopy(self.facts);mutate(f)
            with self.assertRaises(Denied):p.qualify_snapshot(f,self.selected,now=self.now)
    def test_duplicate_or_missing_privilege_rows_cannot_mask_denial(self):
        for field in('tablePrivileges','sequencePrivileges'):
            f=copy.deepcopy(self.facts);f[field][-1]=copy.deepcopy(f[field][0])
            with self.subTest(field=field),self.assertRaises(Denied):p.qualify_snapshot(f,self.selected,now=self.now)
    def test_stale_or_future_snapshot_does_not_become_current_admission(self):
        for now in(self.now+5,self.now-2,float('nan'),float('inf')):
            with self.subTest(now=now),self.assertRaises(Denied):p.qualify_snapshot(self.facts,self.selected,now=now)
    def test_foreign_identity_or_port_and_unparameterized_selection_block(self):
        for key,value in(('database','foreign_db'),('user','foreign_role'),('databaseOid',43),('serverPort',5432)):
            f=copy.deepcopy(self.facts);f[key]=value
            with self.subTest(key=key),self.assertRaises(Denied):p.qualify_snapshot(f,self.selected,now=self.now)
        selected=copy.deepcopy(self.selected);selected.pop('postgresPort')
        with self.assertRaises(Denied):p.qualify_snapshot(self.facts,selected,now=self.now)
    def test_active_work_pressure_broad_role_or_insufficient_headroom_deny_prerequisites(self):
        mutations=[lambda f:f['work'].update(eligibleSchedules=1),
                   lambda f:f['pressurePolicies'][0].update(state='HARD_PRESSURE'),
                   lambda f:f['connections'].update(serverObserved=98),
                   lambda f:f['connections'].update(unobservablePeers=1),
                   lambda f:f['roleFlags'].update(superuser=True),
                   lambda f:f['broadRoleMemberships'].update(pg_execute_server_program=True),
                   lambda f:f.update(preparedTransactions=1)]
        for mutate in mutations:
            self.facts=facts();mutate(self.facts);self.assertFalse(self.synthetic_result()['databaseReadPrerequisitesProven'])
    def test_duplicate_history_rank_checksum_drift_and_lost_work_counter_are_rejected(self):
        f=copy.deepcopy(self.facts);f['history'][1]['installed_rank']=f['history'][0]['installed_rank']
        with self.assertRaises(Denied):p.qualify_snapshot(f,self.selected,now=self.now)
        self.facts['history'][0]['checksum']+=1
        self.assertFalse(self.synthetic_result()['databaseReadPrerequisitesProven'])
        f=facts();f['work'].pop('unackedOutbox')
        with self.assertRaises(Denied):p.qualify_snapshot(f,self.selected,now=self.now)
    def test_release_sql_and_migrations_are_reused_without_historical_installation_selectors(self):
        source=(ROOT/'scripts/read-ingestion-db-postboot-preflight-20261020.py').read_text()
        tree=ast.parse(source)
        sql=next(ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)
                 and any(getattr(t,'id',None)=='SQL'for t in n.targets))
        self.assertEqual(p.SQL,sql.replace("extract(epoch FROM transaction_timestamp())::bigint", "floor(extract(epoch FROM transaction_timestamp()))::bigint").replace("'observedAtUnix',","'serverPort',current_setting('port')::integer,\n 'observedAtUnix',",1))
        self.assertTrue(p.SQL.startswith('-- Closed read-only'))
        self.assertIn('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;',p.SQL)
        self.assertTrue(p.SQL.rstrip().endswith('ROLLBACK;'))
        self.assertEqual(len(p.expected_history()),18)
        self.assertFalse(any(hasattr(p,n)for n in('selection','CONTEXT','OWNER','INPUT','POSTBOOT')))

if __name__=='__main__':unittest.main()
