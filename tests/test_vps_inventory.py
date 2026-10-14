import copy,importlib.util,json,os
from pathlib import Path
import tempfile,unittest
from unittest.mock import patch

SCRIPT=Path(__file__).resolve().parents[1]/'scripts/collect-vps-inventory.py'
spec=importlib.util.spec_from_file_location('inventory',SCRIPT);p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)

def row():
    return {'Id':'a'*64,'Name':'/ouf-semantic','Image':'sha256:'+'b'*64,
        'State':{'Pid':123,'StartedAt':'2026-10-14T00:00:00Z','Running':True,'Paused':False,'Status':'running'},
        'Config':{'Env':['PASSWORD=never-print-this-secret','OUF_SEM_DB_USER=app'],'Labels':{},'User':'10001'},
        'HostConfig':{'RestartPolicy':{'Name':'no','MaximumRetryCount':0}},'Mounts':[],
        'NetworkSettings':{'Networks':{}}}

class InventoryTests(unittest.TestCase):
    def test_full_historical_comparison_finds_config_with_unchanged_generation(self):
        old=row();new=copy.deepcopy(old);new['Config']['Env'][0]='PASSWORD=a-new-private-value'
        result=p.compare(old,new)
        self.assertFalse(result['equal']);self.assertEqual(result['changedBindingFields'],['configHash'])
        self.assertEqual(result['changedEnvironmentNames'],['PASSWORD'])
        self.assertNotIn('never-print',json.dumps(result));self.assertNotIn('new-private',json.dumps(result))
    def test_host_mount_and_network_differences_are_not_hidden_by_stability(self):
        old=row();new=copy.deepcopy(old)
        new['HostConfig']['OomKillDisable']=False;new['Mounts']=[{'Source':'/private/never-print-this-secret'}]
        new['NetworkSettings']['SandboxKey']='/var/run/docker/netns/fff'
        result=p.compare(old,new)
        self.assertEqual(set(result['changedBindingFields']),{'hostConfigHash','mountsHash','networkSettingsHash'})
        self.assertNotIn('/private/',json.dumps(result))
    def test_summary_never_returns_environment_or_label_values(self):
        x=row();x['Config']['Labels']['private-label']='never-print-this-secret'
        value=p.container_summary(x)
        self.assertNotIn('never-print',json.dumps(value));self.assertNotIn('Env',value)
    def test_duplicate_environment_is_rejected_without_values(self):
        x=row();x['Config']['Env'].append('PASSWORD=other')
        with self.assertRaisesRegex(ValueError,'DUPLICATE_ENVIRONMENT_METADATA'):p.environment(x)
    def test_error_reason_is_constant_or_class_only(self):
        self.assertEqual(p.safe_error(ValueError('never-print-this-secret')), 'ValueError')
        self.assertEqual(p.safe_error(ValueError('PG_READ_FAILED_42501')), 'PG_READ_FAILED_42501')
        self.assertEqual(p.safe_error(OSError('/private/never-print-this-secret')), 'OSError')
    def test_selected_file_hash_size_and_symlink_guards(self):
        with tempfile.TemporaryDirectory() as d:
            f=Path(d)/'selected';f.write_bytes(b'private');f.chmod(0o600)
            raw,meta=p.file_bytes(f);self.assertEqual(raw,b'private');self.assertEqual(meta['bytes'],7)
            with self.assertRaisesRegex(ValueError,'HASH_MISMATCH'):p.file_bytes(f,'0'*64)
            with self.assertRaisesRegex(ValueError,'BOUNDED_REGULAR'):p.file_bytes(f,limit=3)
            link=Path(d)/'link';link.symlink_to(f)
            with self.assertRaises(OSError):p.file_bytes(link)
    def test_changed_key_filter_does_not_return_arbitrary_private_text(self):
        self.assertEqual(p.named_changes({'key with private text':1,'KnownKey':1},{'KnownKey':2}),['KnownKey'])
    def test_database_identifiers_deny_injection(self):
        for value in ('a;DROP TABLE x','a"','../a','a b',''):
            with self.assertRaises(ValueError):p.ident(value)
    def test_query_proves_read_only_and_rolls_back(self):
        native=p.Native.__new__(p.Native);calls=[]
        def run(args,data):
            calls.append((args,data));return 0,json.dumps({'transactionReadOnly':True,'value':{'ok':True}}).encode(),b''
        native.run=run
        self.assertEqual(native.query('a'*64,'app','test','SELECT true'),{'ok':True})
        args,sql=calls[0];self.assertIn('PGOPTIONS=-c default_transaction_read_only=on',args)
        self.assertIn(b'BEGIN READ ONLY',sql);self.assertIn(b'ROLLBACK',sql);self.assertIn('-w',args)
    def test_query_denies_unproven_read_only_and_redacts_failure(self):
        native=p.Native.__new__(p.Native)
        native.run=lambda *args:(0,b'{"transactionReadOnly":false,"value":{}}',b'')
        with self.assertRaisesRegex(ValueError,'READ_ONLY_TRANSACTION_NOT_PROVEN'):native.query('a'*64,'app','test','SELECT true')
        native.run=lambda *args:(2,b'',b'FATAL: role "never-print-this-secret" does not exist')
        with self.assertRaisesRegex(ValueError,'PG_READ_FAILED_UNKNOWN'):native.query('a'*64,'app','test','SELECT true')
    def test_independent_failure_does_not_erase_other_observations(self):
        class N:
            def remaining(self):return 10
        inv=p.Inventory(N())
        def bad():raise ValueError('private value should not escape')
        inv.check('first',bad);inv.check('second',lambda:{'seen':True})
        self.assertEqual(inv.areas['first'],{'status':'UNAVAILABLE','reason':'ValueError'})
        self.assertEqual(inv.areas['second']['data'],{'seen':True})
    def test_closed_admin_key_reader(self):
        raw=b'deployment:\n  admin:\n    admin_key:\n      - name: audit\n        key: "private-secret-value"\n        role: admin\n'
        self.assertEqual(p.admin_key(raw),'private-secret-value')
        with self.assertRaisesRegex(ValueError,'AMBIGUOUS'):p.admin_key(raw+b'        key: duplicate\n')
    def test_config_inventory_prints_keys_not_values(self):
        x=row();x['Mounts']=[{'Source':'/selected/private','Destination':'/run/secrets/onboarding-ths.yaml','RW':False}]
        raw=b'spring:\n  security:\n    client-secret: never-print-this-secret\n'
        with patch.object(p,'file_bytes',return_value=(raw,{'sha256':'a'*64,'uid':0})):
            result=p.selected_configs(x)
        self.assertNotIn('never-print',json.dumps(result));self.assertIn('client-secret',json.dumps(result))
    def test_iam_reader_only_uses_get_and_explicit_fields(self):
        calls=[]
        class N:
            def json(self,args):calls.append(args);return []
        inv=p.Inventory(N());inv.rows['ouf-keycloak']=row()
        result=inv.iam_catalogue()
        self.assertTrue(result['cachedSessionOnly']);self.assertFalse(result['clientSecretsRequested'])
        self.assertTrue(all(args[3]=='get' for args in calls));self.assertTrue(all('--fields' in args for args in calls))
        self.assertTrue(all('secret' not in args[4] for args in calls))
    def test_total_call_and_time_limits_are_finite(self):
        self.assertEqual(p.MAX_SECONDS,240)
        native=p.Native.__new__(p.Native);native.deadline=0
        with self.assertRaisesRegex(ValueError,'BUDGET_EXHAUSTED'):native.remaining()
    def test_whole_aggregation_keeps_differences_and_never_emits_raw_containers(self):
        rows={name:row() for name in p.EXPECTED}
        for index,(name,x) in enumerate(rows.items()):x['Name']='/'+name;x['Id']=format(index+1,'x')*64
        old=copy.deepcopy(rows['ouf-semantic']);rows['ouf-semantic']['Config']['Env'][0]='PASSWORD=new-private-value'
        class N:
            calls=0
            def remaining(self):return 10
            def inspect(self,name):
                return copy.deepcopy(rows.get(name) or next(v for v in rows.values() if v['Id']==name))
            def json(self,args):return {'ServerVersion':'29.8.1'}
        inv=p.Inventory(N())
        def historical(key,*args):
            if key=='declaration':inv.raw[key]={'retainedNativeCreationFrame':old}
            return {'expectedHashMatched':True}
        inv.historical=historical
        inv.container_inventory=lambda:{'oufContainers':{}}
        inv.projection=lambda:{'metadata':{'sha256':'a'*64}}
        inv.image=lambda row:{'imageMatchesContainer':True}
        inv.runc=lambda row:{'stableDoubleRead':True}
        inv.networks=lambda:[]
        inv.iam_catalogue=lambda:{'cachedSessionOnly':True}
        inv.gateway_routes=lambda:{'routeCount':10}
        inv.owner_grants=lambda pg:{'projectionOnlyNotEffectivePermissionProof':True}
        inv.existing_input=lambda pg:{'rows':13,'columns':20}
        inv.retained_history=lambda:{'historicalOnly':True}
        inv.tool_stability=lambda:{'unchanged':True}
        with patch.object(p,'db_inventory',return_value={'transactionReadOnly':True}),patch.object(p,'selected_configs',return_value=[]):
            result=inv.collect()
        self.assertEqual(result['registryChangedBindingFields'],['configHash'])
        self.assertFalse(result['completeEnvironmentInventory'])
        self.assertIn('freshMcpRead',result['unavailableAreas'])
        self.assertNotIn('never-print',json.dumps(result));self.assertNotIn('new-private-value',json.dumps(result))
        self.assertEqual(result['databaseMutations'],0)

if __name__=='__main__':unittest.main()
