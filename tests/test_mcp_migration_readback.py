"""Phase-2 bounded reader: complete private fixture, redaction and denial gates."""
import ast,contextlib,copy,hashlib,importlib.util,io,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('migration_readback',ROOT/'scripts/read-chatbot-mcp-migration-state-20261016.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)

def fixture():
    creation={'Image':'sha256:'+'a'*64,'User':'10005:10005','Entrypoint':['/usr/local/bin/ouf-mcp'],
        'Env':['MCP_DATABASE_URL=PRIVATE_SENTINEL'],'NetworkingConfig':{'EndpointsConfig':{'ouf-backend':{'NetworkID':'b'*64}}}}
    prepared={'cohortPlan':{'replacements':[{'module':'mcp','retiredName':'ouf-mcp-before-fixture','creationRequest':creation}]}}
    name,request=r.migration_request(prepared)
    actual={'Id':'c'*64,'Name':'/'+name,'Image':creation['Image'],
        'Config':{k:v for k,v in request.items() if k not in ('HostConfig','NetworkingConfig','Image')},
        'HostConfig':{**request['HostConfig'],'Privileged':False},'Mounts':[],
        'NetworkSettings':{'Networks':{'ouf-backend':{'NetworkID':'b'*64}}},
        'State':{'Status':'created','Running':False,'Paused':False,'Restarting':False,'Dead':False,
            'Pid':0,'ExitCode':0,'StartedAt':'0001-01-01T00:00:00Z'},'RestartCount':0}
    image={'Id':creation['Image'],'Config':{'Env':['PATH=/bin'],'Labels':{'org.opencontainers.image.revision':'d'*40}}}
    return prepared,name,request,copy.deepcopy(actual),image

def dbfixture():
    incident={'oid':22,'ownerOid':33,'aclHash':'d'*64,'triggerAuthority':False,'triggerGrantCount':0}
    binding={'module':'mcp','database':'fixture_mcp','user':'fixture_app','databaseOid':42,
        'beforeMigrations':[{'version':1,'checksum':'a'*64}],
        'expectedMigrations':[{'version':1,'checksum':'a'*64},{'version':2,'checksum':'b'*64}]}
    plan={'mcpAuditRoleAdministration':{'admin':'fixture_admin','temporaryIncidentTrigger':True},
        'mcpAuditRolePreflight':{'incidentBinding':incident}}
    facts={'databaseOid':42,'databaseMatched':True,'roleMatched':True,'superuser':True,'readOnly':True,
        'roleExists':True,'noLogin':True,'schemaCreate':True,'membershipCount':1,'appMembership':1,
        'functionOwnerCount':0,'migrations':binding['beforeMigrations'],'incidentBinding':incident.copy()}
    return binding,plan,facts

class Reader(unittest.TestCase):
    def test_image_defaults_diagnosed_without_accepting_or_disclosing_values(self):
        p,name,req,actual,image=fixture()
        actual['Config']['Env']+=image['Config']['Env'];actual['Config']['Labels'].update(image['Config']['Labels'])
        result=r.native_projection(name,req,actual,image)
        self.assertFalse(result['originalPredicateMatches'])
        self.assertFalse(result['fieldMatches']['Config.Env']);self.assertFalse(result['fieldMatches']['Config.Labels'])
        self.assertTrue(result['environmentMatchesImageDefaultsAndRequest'])
        self.assertTrue(result['labelsMatchImageDefaultsAndRequest'])
        self.assertNotIn('PRIVATE_SENTINEL',json.dumps(result))
        actual['Config']['Env'].append('UNREQUESTED=PRIVATE_SENTINEL')
        self.assertFalse(r.native_projection(name,req,actual,image)['environmentMatchesImageDefaultsAndRequest'])
    def test_requested_secret_change_duplicate_env_and_wrong_image(self):
        p,name,req,a,i=fixture();a=copy.deepcopy(a)
        a['Config']['Env']=['MCP_DATABASE_URL=WRONG']
        self.assertFalse(r.native_projection(name,req,a,i)['environmentRequestedValuesMatch'])
        a['Config']['Env']=['X=1','X=2']
        with self.assertRaises(r.ReadDenied):r.native_projection(name,req,a,i)
        i['Id']='sha256:'+'e'*64
        with self.assertRaises(r.ReadDenied):r.native_projection(name,req,a,i)
    def test_network_and_lifecycle_classified_separately(self):
        p,n,q,a,i=fixture();a['NetworkSettings']['Networks']['ouf-backend']['NetworkID']=''
        result=r.native_projection(n,q,a,i);self.assertTrue(result['networkIdEmpty']);self.assertFalse(result['fieldMatches']['NetworkID'])
        self.assertTrue(r.native_state(a)['neverStarted'])
        a['State'].update(Status='running',Running=True,Pid=123,StartedAt='2026-10-16T01:00:00Z')
        self.assertFalse(r.native_state(a)['neverStarted']);self.assertTrue(r.native_state(a)['running'])
    def test_sql_is_select_only_and_reports_actual_temporary_privileges(self):
        b,p,f=dbfixture();q=r.state_query(b,p)
        self.assertTrue(q.startswith('SELECT '))
        for word in ('GRANT ','REVOKE ','CREATE ROLE','UPDATE ','DELETE ','INSERT '):self.assertNotIn(word,q)
        result=r.database_projection(f,b,p)
        self.assertTrue(result['beforeMigrationsMatch']);self.assertFalse(result['expectedMigrationsMatch'])
        self.assertTrue(result['schemaCreate']);self.assertEqual(result['appMembership'],1)
        self.assertTrue(result['incidentPreservedAclMatches'])
    def test_database_identity_shape_and_injection_denied(self):
        b,p,f=dbfixture()
        for k,v in [('readOnly',False),('databaseOid',43),('extra','PRIVATE_SENTINEL'),('membershipCount','secret')]:
            bad={**f,k:v}
            with self.assertRaises(r.ReadDenied):r.database_projection(bad,b,p)
        b['user']="app';DROP ROLE x;--"
        with self.assertRaises(r.ReadDenied):r.state_query(b,p)
    def test_reader_contains_no_runtime_effect_route(self):
        source=Path(r.__file__).read_text();tree=ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr=='request':
                self.assertEqual(ast.literal_eval(node.args[0]),'GET')
        for name in ('pg_dump','pg_restore','SIGUSR1','docker start','systemctl restart'):
            self.assertNotIn(name,source)
    def full(self,drift=False,mutate=False):
        with tempfile.TemporaryDirectory(dir=ROOT)as directory:
            root=Path(directory);root.chmod(0o700)
            def write(path,value):
                path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);path.write_bytes(r.encoded(value));path.chmod(0o600)
                return hashlib.sha256(path.read_bytes()).hexdigest()
            p,name,request,actual,image=fixture();b,plan,facts=dbfixture()
            plan['modules']=[{**b,'module':m,'maximumArchiveBytes':1048576} for m in r.MODULES]
            pg=copy.deepcopy(actual);pg['Id']='f'*64;pg['Config']={'Env':['POSTGRES_USER=fixture_admin']};pg['State'].update(Running=True,Status='running',Pid=123)
            plan['postgresRuntimeBinding']=r.runtime_pin(pg)
            p.update(databasePlan=plan,engine={'socketPath':'/run/docker.sock'},postGrantWorkerDirectory=str(root/'owner'),
                registry={'directoryPlan':{'transition':str(root/'transition')}})
            p['cohortPlan']['databasePlanHash']=r.digest(plan)
            dirs={k:str(root/k)for k in ('databases','backups','containers','authorization','gateway')}
            for path in dirs.values():Path(path).mkdir(mode=0o700)
            journal={'schema':'ouf.chatbot-cohort-database-journal.v1','planHash':r.digest(plan),'authorityHash':r.AUTHORITY,
                'budgetReset':False,'restorePerformed':False,'backups':{},
                'mcpMigration':{'state':'CLAIMED','name':name,'intentHash':r.digest(request)},'mcpAuditRole':{'state':'BOOTSTRAPPED'}}
            for row in plan['modules']:
                path=root/'backups'/(row['module']+'.dump');path.write_bytes(b'PGDMP'+b'x'*150);path.chmod(0o600)
                journal['backups'][row['module']]={'state':'COMPLETE','scopeHash':r.digest(row),'archiveSha256':hashlib.sha256(path.read_bytes()).hexdigest(),'archiveBytes':155,'payloadParsed':True}
            if drift:journal['backups']['mcp']['archiveSha256']='0'*64
            write(root/'databases/recovery.json',journal)
            for component in ('containers','authorization','gateway'):write(root/component/'recovery.json',{'effects':[]})
            write(root/'transition/recovery.json',{'state':'READY','effects':[{'state':'APPLIED'}]*10})
            for file in ('recovery.json','owner-session.json','owner-admission.json','owner-first-grant.json'):
                write(root/'owner'/file,{'state':'CANCELLED','attempts':1,'controlledCumulativeGrantAttempts':6,'private':'PRIVATE_SENTINEL'})
            declaration={'sourceCommit':r.SOURCE};bundle={'prepared':p,'declaration':declaration}
            bundlehash=write(root/'bundle.json',bundle)
            scopes={'finiteActionProcess':{'unit':r.UNIT,'authorityDirectory':str(root),'bundle':{'path':str(root/'bundle.json'),'sha256':bundlehash},'directoryPlan':dirs},
                'policyTokenOwnerInstallation':{'journalPath':str(root/'owner')}}
            review={'sourceClosure':{'declaration':declaration,'executables':{'systemctl':{},'docker':{}}},'scopes':scopes,'privateInputHashes':{'preparedInputs':r.digest(p)}}
            reviewhash=write(root/'review.json',review);write(root/'authority.json',scopes)
            write(root/'delivery-status.json',{'authorityHash':r.AUTHORITY,'phase':'PAUSED_REQUIRES_RECONCILIATION','reason':'MCP_MIGRATION_ROLE_NATIVE_IDENTITY_DRIFT'})
            original_read=r.read
            def read(path,*a,**kw):
                if Path(path)==root/'authority.json':kw['expected']=None;a=()
                return original_read(path,*a,**kw)
            def engine(e,kind,ref):return image if kind=='images' else pg if ref==pg['Id'] else actual
            def sql(*args):
                if mutate:write(root/'owner/recovery.json',{'state':'ACTIVE'})
                return r.database_projection(facts,b,plan)
            output=io.StringIO()
            with patch.object(r,'CONTEXT',root),patch.object(r,'REVIEW',reviewhash),patch.object(r,'read',side_effect=read),\
                 patch.object(r.sys,'flags',type('Flags',(),{'isolated':1})()),patch.object(r.signal,'alarm'),\
                 patch.object(r,'stopped'),patch.object(r,'executable',return_value='/docker'),\
                 patch.object(r,'engine_get',side_effect=engine),patch.object(r,'sql_read',side_effect=sql),contextlib.redirect_stdout(output):
                r.main()
            self.assertNotIn('PRIVATE_SENTINEL',output.getvalue())
            return [json.loads(line)for line in output.getvalue().splitlines()]
    def test_complete_reader_verifies_four_archives_and_retained_worker(self):
        rows=self.full();self.assertEqual(sum(x['check']=='RETAINED_ARCHIVE' for x in rows),4)
        self.assertEqual(next(x for x in rows if x['check']=='WORKER')['controlledCumulativeGrantAttempts'],6)
        self.assertTrue(rows[-1]['complete']);self.assertFalse(rows[-1]['runtimeAuthorityIssued'])
    def test_bad_backup_or_concurrent_record_change_denies_completion(self):
        with self.assertRaisesRegex(r.ReadDenied,'COMPLETE_ARCHIVE_DRIFT'):self.full(drift=True)
        with self.assertRaisesRegex(r.ReadDenied,'RETAINED_RECORD_CHANGED_DURING_READ'):self.full(mutate=True)

if __name__=='__main__':unittest.main()
