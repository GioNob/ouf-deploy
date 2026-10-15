import copy,importlib.util,json,os,http.server,socketserver,threading,time
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
            def inspect_api(self,cid):return self.inspect(cid)
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
        inv.api_versions=lambda:{'preparerApiVersion':'1.44'}
        with patch.object(p,'db_inventory',return_value={'transactionReadOnly':True}),patch.object(p,'selected_configs',return_value=[]):
            result=inv.collect()
        self.assertEqual(result['registryChangedBindingFields'],['configHash'])
        self.assertFalse(result['completeEnvironmentInventory'])
        self.assertIn('freshMcpRead',result['unavailableAreas'])
        self.assertNotIn('never-print',json.dumps(result));self.assertNotIn('new-private-value',json.dumps(result))
        self.assertEqual(result['databaseMutations'],0)
        self.assertTrue(result['areas']['registryObservationChannels']['data']['stableComparisonUsable'])
        self.assertFalse(result['areas']['registryObservationChannels']['data']['preparationGenerationGateWouldPass'])

    def test_missing_null_is_reported_as_presence_difference(self):
        self.assertEqual(p.named_changes({}, {'OnBuild':None}), ['OnBuild'])
        old=row();new=copy.deepcopy(old);new['Config']['OnBuild']=None
        paths=p.structural_differences(old,new)
        self.assertEqual(paths,[{'path':['Config','OnBuild'],'oldPresent':False,'newPresent':True,'oldType':None,'newType':'NoneType'}])

    def test_structural_diff_redacts_values_lists_and_untrusted_keys(self):
        old=row();new=copy.deepcopy(old)
        new['Config']['Env'][0]='PASSWORD=another-secret'
        new['Config']['Labels']['a key containing private material']='private-value'
        text=json.dumps(p.structural_differences(old,new))
        for value in ('never-print','another-secret','private-value','private material'):self.assertNotIn(value,text)
        self.assertIn('REDACTED_KEY',text)

    def channel_inventory(self,cli,api):
        class N:
            def inspect(self,cid):return copy.deepcopy(cli)
            def inspect_api(self,cid):return copy.deepcopy(api)
        return p.Inventory(N())

    def test_same_generation_api_representation_difference_explains_exact_gate(self):
        cli=row();api=copy.deepcopy(cli)
        api['Config']['OnBuild']=None
        api['HostConfig']['KernelMemoryTCP']=0
        api['NetworkSettings']['Bridge']=''
        historical=copy.deepcopy(cli)
        observed=self.channel_inventory(cli,api).registry_channels(historical)
        self.assertTrue(observed['sameContainerImagePidStartedAt'])
        self.assertTrue(observed['historicalVsCli']['equal'])
        self.assertFalse(observed['preparationGenerationGateWouldPass'])
        self.assertTrue(observed['historicalCliMatchAndPreparerApiMismatchObserved'])
        self.assertEqual(set(observed['historicalVsPreparerApi']['changedBindingFields']),{'configHash','hostConfigHash','networkSettingsHash'})
        self.assertEqual(historical,cli)
        self.assertFalse(observed['bindingNormalizationApplied'])
        self.assertNotIn('never-print',json.dumps(observed))

    def test_real_configuration_difference_remains_a_difference(self):
        old=row();current=copy.deepcopy(old);current['Config']['Env'][0]='PASSWORD=new-secret'
        observed=self.channel_inventory(current,current).registry_channels(old)
        self.assertFalse(observed['historicalVsCli']['equal'])
        self.assertFalse(observed['historicalVsPreparerApi']['equal'])
        self.assertFalse(observed['stableChannelDifferenceObserved'])
        self.assertFalse(observed['preparationGenerationGateWouldPass'])

    def test_unstable_channel_never_supplies_usable_comparison(self):
        inv=self.channel_inventory(row(),row());count=0
        def unstable(cid):
            nonlocal count
            count+=1;value=row();value['State']['Pid']=count;return value
        inv.native.inspect_api=unstable
        observed=inv.registry_channels(row())
        self.assertFalse(observed['stableComparisonUsable'])
        self.assertFalse(observed['preparationGenerationGateWouldPass'])
        self.assertFalse(observed['historicalCliMatchAndPreparerApiMismatchObserved'])

    def test_api_unavailable_remains_named_gap_without_raw_error(self):
        class N:
            def remaining(self):return 5
        inv=p.Inventory(N())
        def unavailable():raise p.NativeReadFailure('ENGINE_GET_UNAVAILABLE',{'httpStatus':400,'responseBodyPrinted':False})
        inv.check('registryObservationChannels',unavailable)
        self.assertEqual(inv.areas['registryObservationChannels']['facts']['httpStatus'],400)
        self.assertEqual(inv.areas['registryObservationChannels']['status'],'UNAVAILABLE')

    def test_ninety_eight_containers_use_bounded_batches_without_deep_candidate_reads(self):
        rows=[]
        for i in range(98):
            x=row();x['Id']=format(i+1,'064x');x['Name']='/ouf-retained-'+str(i);rows.append(x)
        rows[0]['Name']='/ouf-semantic'
        calls=[]
        class N:
            def run(self,args):return 0,('\n'.join(x['Id']+'\t'+x['Name'][1:] for x in rows)).encode(),b''
            def inspect_many(self,ids):
                calls.append(ids);return [x for x in rows if x['Id'] in ids]
        inv=p.Inventory(N());observed=inv.container_inventory()
        self.assertEqual(observed['totalContainerCount'],98)
        self.assertEqual(observed['oufContainerCount'],98)
        self.assertEqual(len(calls),7);self.assertLessEqual(max(map(len,calls)),16)
        self.assertEqual(set(inv.rows),{'ouf-semantic'})
        self.assertNotIn('never-print',json.dumps(observed))

    def test_inventory_limit_rejects_before_inspecting_any_container(self):
        class N:
            def run(self,args):return 0,('\n'.join(format(i,'064x')+'\touf-fixture-'+str(i) for i in range(513))).encode(),b''
            def inspect_many(self,ids):raise AssertionError('must not inspect beyond budget')
        with self.assertRaisesRegex(ValueError,'CONTAINER_INVENTORY_LIMIT'):p.Inventory(N()).container_inventory()

    def test_inspect_batch_rejects_unselected_and_oversized_replies(self):
        native=p.Native.__new__(p.Native);native.json=lambda args:[row()]
        self.assertEqual(native.inspect_many(['a'*64]),[row()])
        for ids in ([],['a'*64]*17,['private-name']):
            with self.assertRaises(ValueError):native.inspect_many(ids)
        with self.assertRaisesRegex(ValueError,'EXACT_CONTAINER_BATCH_REQUIRED'):native.inspect_many(['b'*64])

    def selected_db_rows(self,module,query=''):
        pg=row();pg['Name']='/ouf-postgres';pg['Config']['Env']=[]
        pg['NetworkSettings']['Networks']['ouf-backend']={'IPAddress':'10.0.0.2','Aliases':['ouf-postgres']}
        prefix={'semantic':'OUF_SEM','onboarding':'OUF_ONB','ingestion':'OUF_ING','udp':'OUF_UDP'}.get(module)
        env=['MCP_DATABASE_URL=postgresql://app@ouf-postgres:5432/test'+query] if module=='mcp' else [prefix+'_DB_URL=jdbc:postgresql://ouf-postgres:5432/test',prefix+'_DB_USER=app']
        return pg,{'Config':{'Env':env}}

    def test_non_identity_query_is_observed_without_connecting_via_dsn(self):
        pg,x=self.selected_db_rows('mcp','?sslmode=disable&connect_timeout=5')
        self.assertEqual(p.db_selector('mcp',x,pg),('app','test','ouf_mcp'))

    def test_query_identity_overrides_remain_denied_including_percent_encoding(self):
        for query in ('?host=other','?user=other','?password=private-value','?%68ost=other','?service=other'):
            pg,x=self.selected_db_rows('mcp',query)
            with self.assertRaisesRegex(ValueError,'DB_QUERY_IDENTITY_OVERRIDE_DENIED'):p.db_selector('mcp',x,pg)

    def test_peer_port_and_query_failures_are_distinct(self):
        pg,x=self.selected_db_rows('mcp');x['Config']['Env'][0]=x['Config']['Env'][0].replace('ouf-postgres','another-host')
        with self.assertRaisesRegex(ValueError,'DB_PEER_NOT_SELECTED'):p.db_selector('mcp',x,pg)
        pg,x=self.selected_db_rows('mcp');x['Config']['Env'][0]=x['Config']['Env'][0].replace('5432','5433')
        with self.assertRaisesRegex(ValueError,'DB_PORT_UNSUPPORTED'):p.db_selector('mcp',x,pg)
        pg,x=self.selected_db_rows('mcp','?'+('&'.join('x'+str(i)+'=0' for i in range(33))))
        with self.assertRaisesRegex(ValueError,'DB_QUERY_UNBOUNDED'):p.db_selector('mcp',x,pg)

    def test_exact_quoted_flyway_schema_markers_are_preserved_in_all_four_histories(self):
        for module,schema in (('semantic','ouf_sem'),('onboarding','ouf_onboarding'),('ingestion','ouf_ingestion'),('udp','ouf_udp')):
            marker={'version':None,'script':'"'+schema+'"','type':'SCHEMA','checksum':None,'success':True}
            pg,x=self.selected_db_rows(module)
            class N:
                def query(self,cid,user,db,sql):return [marker] if 'flyway_schema_history' in sql else {'oid':1}
            observed=p.db_inventory(N(),pg,module,x)
            self.assertEqual(observed['migrations'],[marker]);self.assertTrue(observed['transactionReadOnly'])

    def test_unknown_marker_and_private_metadata_are_not_silently_accepted(self):
        pg,x=self.selected_db_rows('semantic')
        history=[{'version':None,'script':'"other_schema"','type':'SCHEMA','checksum':None,'success':True}]
        class N:
            def query(self,cid,user,db,sql):return history if 'flyway_schema_history' in sql else {'oid':1}
        with self.assertRaisesRegex(ValueError,'EXACT_FLYWAY_SCHEMA_MARKER_REQUIRED'):p.db_inventory(N(),pg,'semantic',x)
        history[:]=[{'version':'1','script':'arbitrary private metadata','type':'SQL','checksum':1,'success':True}]
        with self.assertRaises(p.NativeReadFailure) as error:p.db_inventory(N(),pg,'semantic',x)
        self.assertEqual(error.exception.facts,{'rejectedMetadataField':'script','rawValuePrinted':False})
        self.assertNotIn('arbitrary',str(error.exception))

    def test_iam_failure_classification_never_emits_stderr(self):
        native=p.Native.__new__(p.Native)
        for diagnostic,expected in ((b'invalid_grant never-print-secret','IAM_CACHED_SESSION_UNAVAILABLE'),(b'403 forbidden never-print-secret','IAM_GET_AUTHORIZATION_DENIED'),(b'connection refused never-print-secret','IAM_TRANSPORT_UNAVAILABLE'),(b'unknown never-print-secret','UNCLASSIFIED_COMMAND_FAILURE')):
            native.run=lambda args:(1,b'',diagnostic)
            with self.assertRaises(p.NativeReadFailure) as error:native.json(['exec','a'*64,'/opt/keycloak/bin/kcadm.sh','get','clients'])
            self.assertEqual(error.exception.facts['classification'],expected)
            self.assertNotIn('never-print',json.dumps(error.exception.facts))

    def test_actual_unix_http_get_is_read_only_bounded_and_pins_socket(self):
        requests=[]
        class Server(socketserver.UnixStreamServer):pass
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append((self.command,self.path))
                status,body=(200,json.dumps(row()).encode()) if self.path.endswith('/json') else (404,b'never-print-secret')
                self.send_response(status);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
            def log_message(self,*args):pass
        with tempfile.TemporaryDirectory() as directory:
            socket_path=Path(directory)/'engine.sock'
            try:server=Server(str(socket_path),Handler)
            except PermissionError:
                if os.environ.get('GITHUB_ACTIONS')=='true':raise
                self.skipTest('local sandbox denies Unix sockets; this test is mandatory in GitHub Actions')
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            native=p.Native.__new__(p.Native);native.socket=socket_path;native.calls=0;native.deadline=time.monotonic()+10
            s=socket_path.stat();native.socket_pin=(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode&0o777)
            try:
                self.assertEqual(native.inspect_api('a'*64),row())
                with self.assertRaises(p.NativeReadFailure) as error:native.engine_get('/version')
                self.assertEqual(error.exception.facts,{'httpStatus':404,'responseBodyPrinted':False})
                for path in ('/containers/json','/v1.44/containers/a/json','/v1.44/containers/'+('a'*64)+'/start'):
                    with self.assertRaisesRegex(ValueError,'NON_SELECTED_ENGINE_GET_DENIED'):native.engine_get(path)
                native.calls=p.MAX_CALLS
                with self.assertRaisesRegex(ValueError,'CALL_LIMIT'):native.inspect_api('a'*64)
                native.calls=0;socket_path.chmod(0o600 if (s.st_mode&0o777)!=0o600 else 0o660)
                with self.assertRaisesRegex(ValueError,'ENGINE_SOCKET_CHANGED'):native.inspect_api('a'*64)
            finally:server.shutdown();thread.join();server.server_close()
        self.assertEqual(requests,[('GET','/v1.44/containers/'+('a'*64)+'/json'),('GET','/version')])

if __name__=='__main__':unittest.main()
