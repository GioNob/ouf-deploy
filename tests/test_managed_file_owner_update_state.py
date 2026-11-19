import copy,importlib.util,json,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    s=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
old=load('owner_retained_state_fixture','tests/test_profile_recovery_update_state_fence.py');base=old.m
m=load('owner_v38_fence','tools/managed_file_owner_update/state_fence.py').bind(base)
MIGRATIONS=json.loads((ROOT/'releases/managed-file-owner-v38-image-custody-20261028.json').read_text())['application']['migrations']
def facts(after=False):
    f=old.facts(True);f['jobControl']={'generation':0,'version':0,'hasRecoverySession':False};f['retainedAsset']={'uploaderMatchesExpected':True,'hashMatchesExpected':True,'sizeMatchesExpected':True}
    f['states'].update({t:{'rows':0,'sha256':'a'*64}for t in m.TABLES if t not in f['states']})
    f['ownershipSchema']={'tenantColumn':1,'nonNullLegacyTenants':0,'ownerReceipts':0,'enabledGuards':2}if after else{'deltaAbsent':True}
    if after:f['history'] += [{'version':r['version'],'script':r['script'],'checksum':r['flywayChecksum'],'success':True,'type':'SQL'}for r in MIGRATIONS[36:]]
    return f
class State(unittest.TestCase):
    def test_exact36_to38_preserves12_operational_rows_without_owner_adoption(self):
        before=facts();a=m.validate(before,old.PROFILE,MIGRATIONS);b=m.validate(facts(True),old.PROFILE,MIGRATIONS,before,after=True)
        self.assertEqual(a['operationalStateHash'],b['operationalStateHash']);self.assertEqual(b['installedSchemaVersion'],38);self.assertTrue(b['newOwnerReceiptTableEmpty']);self.assertTrue(b['legacyTenantNotBackfilled'])
    def test_preexisting38_partial37_or_changed_history_cannot_be_adopted(self):
        with self.assertRaises(base.StateFenceDenied):m.validate(facts(True),old.PROFILE,MIGRATIONS)
        for mode in('partial','checksum','extra'):
            f=facts(True)
            if mode=='partial':f['history'].pop()
            elif mode=='checksum':f['history'][-1]['checksum']+=1
            else:f['history'].append(copy.deepcopy(f['history'][-1]))
            with self.subTest(mode=mode),self.assertRaises(base.StateFenceDenied):m.validate(f,old.PROFILE,MIGRATIONS,facts(),after=True)
    def test_tenant_backfill_owner_receipt_or_guard_loss_is_denied(self):
        for key in facts(True)['ownershipSchema']:
            f=facts(True);f['ownershipSchema'][key]+=1
            with self.subTest(key=key),self.assertRaises(base.StateFenceDenied):m.validate(f,old.PROFILE,MIGRATIONS,facts(),after=True)
    def test_same_job_counters_asset_hash_and_uploader_are_mandatory(self):
        for key in facts()['retainedAsset']:
            f=facts();f['retainedAsset'][key]=False
            with self.subTest(key=key),self.assertRaises(base.StateFenceDenied):m.validate(f,old.PROFILE,MIGRATIONS)
        for key in facts()['jobControl']:
            f=facts();f['jobControl'][key]=1
            with self.subTest(key=key),self.assertRaises(base.StateFenceDenied):m.validate(f,old.PROFILE,MIGRATIONS)
    def test_all12_fingerprints_must_remain_exact(self):
        for table in m.TABLES:
            f=facts(True);f['states'][table]['sha256']='b'*64
            with self.subTest(table=table),self.assertRaisesRegex(base.StateFenceDenied,'OPERATIONAL_ROWS'):m.validate(f,old.PROFILE,MIGRATIONS,facts(),after=True)
    def test_new_budget_event_or_reset_is_not_authorized(self):
        for table in('managed_profile_budget_session','managed_profile_event'):
            f=facts();f['states'][table]['rows']=1
            with self.assertRaises(base.StateFenceDenied):m.validate(f,old.PROFILE,MIGRATIONS)
        for attempt in(0,6):
            f=facts();f['job']['attempts']=attempt
            with self.assertRaises(base.StateFenceDenied):m.validate(f,old.PROFILE,MIGRATIONS)
    def test_closed_read_only_queries_preserve_full_job_and_only_project_asset_tenant(self):
        for after in(False,True):
            q=m.query(after);self.assertTrue(q.startswith('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;'));self.assertEqual(q.count("to_jsonb(x)-'tenant_id'"),1);self.assertNotIn("to_jsonb(x)-ARRAY['generation'",q)
            for verb in('INSERT ','UPDATE ','DELETE ','ALTER ','CREATE ','TRUNCATE '):self.assertNotIn(verb,q)
        self.assertNotIn('FROM ouf_onboarding.managed_file_owner_reconciliation',m.query(False));self.assertIn('FROM ouf_onboarding.managed_file_owner_reconciliation',m.query(True))
        with self.assertRaises(base.StateFenceDenied):m.arguments({},Path('/fixture'),'SELECT 1')
if __name__=='__main__':unittest.main()
