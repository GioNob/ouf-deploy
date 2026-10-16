"""Fixed-context GET-only gateway diagnostics: redaction, custody and checkpoints."""
import ast,contextlib,copy,hashlib,importlib.util,io,json,os,signal,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import test_mcp_migration_readback as old
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('gateway_readback',ROOT/'scripts/read-chatbot-gateway-state-20261016.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)

def routes():
    before={'existing':{'id':'existing','uri':'PRIVATE_SENTINEL'}}
    after={**before,'new':{'id':'new','uri':'PRIVATE_SENTINEL','plugins':{'openid-connect':{'client_secret':'PRIVATE_SENTINEL'}}}}
    change={'id':'new','before':None,'after':after['new']}
    plan={'schema':'ouf.chatbot-file-cohort.gateway-publication.v1','previousRoutes':before,'proposedRoutes':after,
        'previousRuntimeHash':r.digest(before),'proposedRuntimeHash':r.digest(after),'changes':[change],'transportBinding':{}}
    journal={'planHash':r.digest(plan),'authorityHash':r.AUTHORITY,'budgetReset':False,'nextStep':0,
        'effects':[{'routeId':'new','intentHash':r.digest(change),'state':'CLAIMED'}]}
    return plan,journal

class Reader(unittest.TestCase):
    def test_missing_exact_normalized_and_unrelated_maps_are_distinct(self):
        p,j=routes()
        a=r.gateway_projection(p,j,p['previousRoutes']);self.assertTrue(a['matchesBeforeClaim']);self.assertFalse(a['claimedRoutePresent'])
        a=r.gateway_projection(p,j,p['proposedRoutes']);self.assertTrue(a['matchesAfterClaim']);self.assertEqual(a['differenceCount'] if 'differenceCount'in a else a['differingRouteCount'],0)
        observed=copy.deepcopy(p['proposedRoutes']);observed['new']['status']=1
        a=r.gateway_projection(p,j,observed);self.assertFalse(a['matchesAfterClaim']);self.assertEqual(a['unrelatedDifferingRouteCount'],0)
        self.assertEqual(a['routeDifferences'][0]['samples'][0]['path'],'/status')
        self.assertEqual(a['routeDifferences'][0]['samples'][0]['observed'],1)
        observed['existing']['uri']='CHANGED_PRIVATE';a=r.gateway_projection(p,j,observed)
        self.assertEqual(a['unrelatedDifferingRouteCount'],1);self.assertNotIn('PRIVATE',json.dumps(a))
    def test_diffs_redact_dynamic_keys_values_and_bound_output(self):
        a={'plugins':{'SENSITIVE_PLUGIN_NAME':{'privatekey':'PRIVATE_SENTINEL'}}}
        b={'plugins':{'SENSITIVE_PLUGIN_NAME':{'privatekey':'OTHER_PRIVATE'}}}
        result=r.difference(a,b);self.assertEqual(result['differenceCount'],1)
        self.assertNotIn('SENSITIVE',json.dumps(result));self.assertNotIn('PRIVATE',json.dumps(result))
        result=r.difference({}, {str(i):'PRIVATE_SENTINEL' for i in range(100)})
        self.assertEqual(result['differenceCount'],100);self.assertEqual(len(result['samples']),64);self.assertTrue(result['samplesTruncated'])
    def test_typed_differences_and_list_lengths(self):
        self.assertEqual(r.difference({'status':True},{'status':1})['fieldCounts'],{'TYPE':1})
        self.assertEqual(r.difference({'methods':['GET']},{'methods':[]})['fieldCounts'],{'ARRAY_LENGTH':1})
    def test_bad_claim_scope_or_intent_denied(self):
        p,j=routes()
        for key,value in [('nextStep',2),('authorityHash','0'*64),('planHash','0'*64),('budgetReset',True)]:
            with self.subTest(key=key),self.assertRaises(r.ReadDenied):r.gateway_projection(p,{**j,key:value},p['proposedRoutes'])
        j['effects'][0]['intentHash']='0'*64
        with self.assertRaises(r.ReadDenied):r.gateway_projection(p,j,p['proposedRoutes'])
    def test_timestamp_normalization_and_duplicate_routes(self):
        rows=[{'value':{'id':'a','create_time':1,'update_time':2,'status':1}}]
        self.assertEqual(r.route_map(rows),{'a':{'id':'a','status':1}})
        with self.assertRaises(r.ReadDenied):r.route_map(rows*2)
    def test_all_http_calls_are_literal_get_and_child_has_no_operation_input(self):
        for source in (Path(r.__file__).read_text(),r.GET_CHILD):
            for node in ast.walk(ast.parse(source)):
                if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr=='request':
                    self.assertEqual(ast.literal_eval(node.args[0]),'GET')
        for value in ('pg_dump','pg_restore','SIGUSR1',"'PUT'","'POST'","'DELETE'"):
            self.assertNotIn(value,Path(r.__file__).read_text())
        self.assertIn("set(data)!={'key'}",r.GET_CHILD)
    def test_custody_and_credential_parser_match_qualified_source(self):
        source=ast.parse((ROOT/'tools/chatbot_file_cohort/gateway.py').read_text());reader=ast.parse(Path(r.__file__).read_text())
        names=('route_map','route_value','private_config','selected_admin_key','selected_directory_custody','selected_file_custody')
        for name in names:
            a=next(n for n in source.body if isinstance(n,ast.FunctionDef)and n.name==name)
            b=next(n for n in reader.body if isinstance(n,ast.FunctionDef)and n.name==name)
            self.assertEqual(ast.dump(a,include_attributes=False),ast.dump(b,include_attributes=False))

    def test_completed_module_generation_and_host_drift_are_reported(self):
        p,_,_,actual,_=old.fixture();row={'module':'udp'};p['cohortPlan']['replacements']=[row];p['engine']={}
        proof={'containerId':actual['Id'],'imageId':actual['Image'],'configHash':r.digest(actual['Config']),
            'hostConfigHash':r.digest(actual['HostConfig']),'mountsHash':r.digest(actual['Mounts']),'runtimeState':actual['State']}
        effects=[{'step':'udp.'+stage,'state':'APPLIED','intentHash':r.digest({'modulePlan':row,'stage':stage}),
            'evidence':proof,'evidenceHash':r.digest(proof)} for stage in ('rename','create','start','ready','restart_policy')]
        with patch.object(r,'engine_get',return_value=actual):
            self.assertTrue(r.module_native(p,{'effects':effects},'udp')['generationMatches'])
            actual['HostConfig']['Unexpected']=True
            self.assertFalse(r.module_native(p,{'effects':effects},'udp')['generationMatches'])
        effects[0]['state']='CLAIMED'
        with self.assertRaises(r.ReadDenied):r.module_native(p,{'effects':effects},'udp')

    def full(self,mutate=False):
        with tempfile.TemporaryDirectory(dir=ROOT)as directory:
            root=Path(directory);root.chmod(0o700)
            def write(path,value):
                path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);path.write_bytes(r.encoded(value));path.chmod(0o600)
                return hashlib.sha256(path.read_bytes()).hexdigest()
            p,name,request,actual,image=old.fixture();b,plan,facts=old.dbfixture()
            facts.update(migrations=b['expectedMigrations'],schemaCreate=False,membershipCount=0,appMembership=0,functionOwnerCount=2)
            actual['State'].update(Status='exited',StartedAt='2026-10-16',ExitCode=0)
            plan['modules']=[{**b,'module':m,'schema':'fixture_'+m,'maximumArchiveBytes':1048576} for m in r.MODULES]
            pg=copy.deepcopy(actual);pg['Id']='f'*64;pg['Config']={'Env':['POSTGRES_USER=fixture_admin']};pg['State'].update(Running=True,Status='running',Pid=123)
            plan['postgresRuntimeBinding']=r.runtime_pin(pg)
            gp,gj=routes();p.update(databasePlan=plan,engine={'socketPath':'/run/docker.sock'},postGrantWorkerDirectory=str(root/'owner'),
                registry={'directoryPlan':{'transition':str(root/'transition')}},gatewayPlan=gp,gatewayRuntimePlan=None)
            p['cohortPlan'].update(databasePlanHash=r.digest(plan),gatewayPlanHash=r.digest(gp))
            dirs={k:str(root/k)for k in ('databases','backups','containers','authorization','gateway')}
            for path in dirs.values():Path(path).mkdir(mode=0o700)
            journal={'schema':'ouf.chatbot-cohort-database-journal.v1','planHash':r.digest(plan),'authorityHash':r.AUTHORITY,
                'budgetReset':False,'restorePerformed':False,'backups':{},'mcpMigration':{'state':'COMPLETE','name':name,
                'intentHash':r.digest(request),'historyHash':r.digest(b['expectedMigrations']),'containerId':actual['Id']},'mcpAuditRole':{'state':'CLEAN'}}
            for row in plan['modules']:
                path=root/'backups'/(row['module']+'.dump');path.write_bytes(b'PGDMP'+b'x'*150);path.chmod(0o600)
                journal['backups'][row['module']]={'state':'COMPLETE','scopeHash':r.digest(row),'archiveSha256':hashlib.sha256(path.read_bytes()).hexdigest(),'archiveBytes':155,'payloadParsed':True}
            write(root/'databases/recovery.json',journal)
            write(root/'gateway/recovery.json',gj);write(root/'authorization/recovery.json',{'effects':[]})
            write(root/'containers/recovery.json',{'planHash':r.digest(p['cohortPlan']),'authorityHash':r.AUTHORITY,'nextStep':10,'effects':[{}]*10})
            write(root/'transition/recovery.json',{'state':'READY','effects':[{'state':'APPLIED'}]*10})
            for file in ('recovery.json','owner-session.json','owner-admission.json','owner-first-grant.json'):
                write(root/'owner'/file,{'state':'CANCELLED','attempts':1,'controlledCumulativeGrantAttempts':7,'private':'PRIVATE_SENTINEL'})
            declaration={'sourceCommit':r.SOURCE};bundle={'prepared':p,'declaration':declaration};bundlehash=write(root/'bundle.json',bundle)
            scopes={'finiteActionProcess':{'unit':r.UNIT,'authorityDirectory':str(root),'bundle':{'path':str(root/'bundle.json'),'sha256':bundlehash},'directoryPlan':dirs},
                'policyTokenOwnerInstallation':{'journalPath':str(root/'owner')}}
            review={'sourceClosure':{'declaration':declaration,'executables':{'systemctl':{},'docker':{}}},'scopes':scopes,'privateInputHashes':{'preparedInputs':r.digest(p)}}
            reviewhash=write(root/'review.json',review);write(root/'authority.json',{**scopes,'expiresAt':1})
            write(root/'delivery-status.json',{'authorityHash':r.AUTHORITY,'phase':'PAUSED_REQUIRES_RECONCILIATION','reason':'GATEWAY_WRITE_OUTCOME_UNPROVEN_NO_REPLAY'})
            original_read=r.read
            def read(path,*a,**kw):
                if Path(path)==root/'authority.json':return original_read(path,131072)
                return original_read(path,*a,**kw)
            def engine(e,kind,ref):return pg if ref==pg['Id'] else actual
            def get(*args):
                if mutate:write(root/'owner/recovery.json',{'state':'ACTIVE'})
                return gp['proposedRoutes']
            output=io.StringIO()
            with patch.object(r,'CONTEXT',root),patch.object(r,'REVIEW',reviewhash),patch.object(r,'read',side_effect=read),\
                 patch.object(r.sys,'flags',type('Flags',(),{'isolated':1})()),patch.object(r.signal,'alarm'),patch.object(r,'stopped'),\
                 patch.object(r,'executable',return_value='/docker'),patch.object(r,'engine_get',side_effect=engine),\
                 patch.object(r,'sql_read',return_value=r.database_projection(facts,b,plan)),\
                 patch.object(r,'module_native',side_effect=lambda p,j,m:{'module':m,'generationMatches':True}),\
                 patch.object(r,'module_schema_read',return_value={'expectedMigrationsMatch':True}),\
                 patch.object(r,'transport_binding',return_value={'runtimeBinding':{'containerId':'a'*64}}),\
                 patch.object(r,'gateway_read',side_effect=get),contextlib.redirect_stdout(output):r.main()
            self.assertNotIn('PRIVATE_SENTINEL',output.getvalue())
            return [json.loads(line)for line in output.getvalue().splitlines()]
    def test_complete_reader_reports_clean_mcp_and_gateway_without_mutations(self):
        rows=self.full();end=rows[-1]
        self.assertTrue(end['complete']);self.assertEqual(end['technicalPhase'],5);self.assertEqual(end['gatewayWrites'],0)
        self.assertEqual(next(x for x in rows if x['check']=='DATABASE_CHECKPOINT')['auditRoleState'],'CLEAN')
        self.assertEqual(next(x for x in rows if x['check']=='WORKER')['controlledCumulativeGrantAttempts'],7)
    def test_concurrent_journal_change_blocks_completion(self):
        with self.assertRaisesRegex(r.ReadDenied,'RETAINED_RECORD_CHANGED_DURING_READ'):self.full(mutate=True)

class NativeTransport(unittest.TestCase):
    def test_actual_get_child_uses_selected_namespace_without_mutations(self):
        if not hasattr(os,'setns'):
            if os.environ.get('OUF_NATIVE_NAMESPACES')=='1':self.fail('native setns required')
            self.skipTest('native namespace fixture required in CI')
        reader,writer=os.pipe();pid=os.fork()
        if pid==0:
            os.close(reader)
            try:
                fd=os.open('/proc/self/ns/net',os.O_RDONLY);os.setns(fd,0);os.close(fd)
                from http.server import HTTPServer,BaseHTTPRequestHandler
                class Handler(BaseHTTPRequestHandler):
                    def log_message(self,*args):pass
                    def do_GET(self):
                        assert self.path=='/apisix/admin/routes' and self.headers['X-API-KEY']=='0123456789abcdef0123456789abcdef'
                        raw=json.dumps({'total':1,'list':[{'value':{'id':'existing','status':1,'uri':'PRIVATE_SENTINEL'}}]}).encode()
                        self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
                    def do_PUT(self):os._exit(90)
                    def do_POST(self):os._exit(91)
                    def do_DELETE(self):os._exit(92)
                server=HTTPServer(('127.0.0.1',9180),Handler);os.write(writer,b'READY');os.close(writer);server.serve_forever()
            except BaseException:os.write(writer,b'UNAVAILABLE');os._exit(1)
        os.close(writer);status=os.read(reader,32);os.close(reader)
        if status!=b'READY':
            os.waitpid(pid,0)
            if os.environ.get('OUF_NATIVE_NAMESPACES')=='1':self.fail('native namespace unavailable')
            self.skipTest('kernel denies native setns; CI forbids skip')
        self.addCleanup(lambda:(os.kill(pid,signal.SIGTERM),os.waitpid(pid,0)))
        with tempfile.TemporaryDirectory(dir=ROOT)as directory:
            root=Path(directory);root.chmod(0o700);config=root/'config.yaml'
            config.write_text('deployment:\n  admin:\n    admin_key:\n      - name: admin\n        key: 0123456789abcdef0123456789abcdef\n        role: admin\n');config.chmod(0o600)
            actual={'Id':'a'*64,'Name':'/ouf-apisix','Image':'sha256:'+'b'*64,'Config':{},'HostConfig':{},'NetworkSettings':{},
                'Mounts':[{'Destination':'/usr/local/apisix/conf/config.yaml','Type':'bind','RW':False,'Source':str(config)}],
                'State':{'Running':True,'Paused':False,'Pid':pid,'StartedAt':'fixture'}}
            _,cb=r.private_config(str(config));ns=os.stat('/proc/'+str(pid)+'/ns/net')
            binding={'runtimeBinding':r.runtime_pin(actual),'configBinding':cb,'adminKeyBinding':None,
                'pythonExecutable':{'path':'/usr/bin/python3','sha256':hashlib.sha256(Path('/usr/bin/python3').read_bytes()).hexdigest()},
                'networkNamespace':{'device':ns.st_dev,'inode':ns.st_ino}}
            before=os.stat('/proc/self/ns/net')
            with patch.object(r,'engine_get',return_value=actual):
                for _ in range(2):self.assertEqual(r.gateway_read({},binding)['existing']['status'],1)
                bad=copy.deepcopy(binding);bad['networkNamespace']['inode']+=1
                with self.assertRaisesRegex(r.ReadDenied,'NAMESPACE_DRIFT'):r.gateway_read({},bad)
                config.write_text('changed')
                with self.assertRaises(r.ReadDenied):r.gateway_read({},binding)
            after=os.stat('/proc/self/ns/net');self.assertEqual((before.st_dev,before.st_ino),(after.st_dev,after.st_ino))

class NativeSql(unittest.TestCase):
    def test_actual_flyway_schema_query_is_readonly_and_exact(self):
        cid=os.environ.get('OUF_POSTGRES_CONTAINER_ID')
        if not cid:
            if os.environ.get('OUF_NATIVE_POSTGRES')=='1':self.fail('native PostgreSQL fixture required')
            self.skipTest('native PostgreSQL required in CI')
        require=lambda ok:self.assertTrue(ok)
        import shutil
        binary=shutil.which('docker');require(binary)
        sql="CREATE SCHEMA fixture_udp; CREATE SCHEMA fixture_onboarding; CREATE TABLE fixture_udp.flyway_schema_history(installed_rank int,version text,script text,type text,checksum int,success boolean); CREATE TABLE fixture_onboarding.flyway_schema_history(LIKE fixture_udp.flyway_schema_history); INSERT INTO fixture_udp.flyway_schema_history VALUES(1,'1','V1.sql','SQL',123,true); INSERT INTO fixture_onboarding.flyway_schema_history VALUES(1,'1','V1.sql','SQL',123,true);"
        subprocess.run([binary,'exec',cid,'psql','-U','postgres','-v','ON_ERROR_STOP=1','-c',sql],check=True,stdout=subprocess.DEVNULL)
        result=subprocess.run([binary,'exec',cid,'psql','-U','postgres','-At','-c',"SELECT oid FROM pg_database WHERE datname='postgres'"],check=True,capture_output=True)
        oid=int(result.stdout)
        p={'engine':{'socketPath':'/var/run/docker.sock'},'databasePlan':{'postgresRuntimeBinding':{'containerId':cid}}}
        expected=[{'version':'1','script':'V1.sql','type':'SQL','checksum':123,'success':True}]
        with tempfile.TemporaryDirectory()as config:
            for module in ('udp','onboarding'):
                binding={'module':module,'schema':'fixture_'+module,'database':'postgres','user':'postgres','databaseOid':oid,'expectedMigrations':expected}
                observed=r.module_schema_read(binary,p,config,binding)
                self.assertTrue(observed['readOnly']);self.assertTrue(observed['expectedMigrationsMatch']);self.assertEqual(observed['migrationCount'],1)

if __name__=='__main__':unittest.main()
