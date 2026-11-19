import copy, importlib.util, io, json, os, pathlib, subprocess, unittest, zipfile

ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('onb_preflight',ROOT/'scripts/read-onboarding-wide-preflight-20261108.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
c,h=m.helpers();expected=m.manifest()

def rows():
    result=[{'version':None,'checksum':None,'success':True,'type':'SCHEMA',
             'installedRank':-1,'installedOn':'2026-11-08T19:00:00'}]
    for x in sorted(expected['migrations'],key=lambda x:int(x['name'].split('__')[0][1:])):
        v=x['name'].split('__')[0][1:]
        result.append({'version':v,'checksum':x['flywayStyleCrc32Utf8'],'success':True,
                       'type':'SQL','installedRank':int(v),'installedOn':'2026-11-08T19:00:00'})
    return result

class Preflight(unittest.TestCase):
    def test_missing_changed_failed_or_extra_migration_is_not_exact(self):
        v={'readOnly':True,'databaseOid':21559,'migrations':rows()}
        self.assertTrue(m.database_result(copy.deepcopy(v),expected)['exactCandidateMigrationHistory'])
        for mode in ('checksum','missing','extra','failed','baseline'):
            changed=copy.deepcopy(v)
            if mode=='checksum':changed['migrations'][1]['checksum']+=1
            if mode=='missing':changed['migrations'].pop()
            if mode=='extra':changed['migrations'].append(dict(changed['migrations'][-1],version='39',installedRank=39))
            if mode=='failed':changed['migrations'][3]['success']=False
            if mode=='baseline':changed['migrations'][3]['type']='BASELINE'
            self.assertFalse(m.database_result(changed,expected)['exactCandidateMigrationHistory'],mode)
        v['migrations'][0]['installedOn']='PRIVATE_DATA'
        with self.assertRaises(RuntimeError):m.database_result(v,expected)

    def test_storage_overrides_and_secret_values_are_not_emitted(self):
        props={'endpoint':'https://ouf-seaweedfs-stage:9002','bucket':'ouf-managed-files',
               'access-key-file':'/run/ouf-seaweedfs/access-key','secret-key-file':'/run/ouf-seaweedfs/secret-key'}
        args=['java','-jar',m.JAR]+['--ouf.onboarding.staging.'+k+'='+v for k,v in props.items()]
        env={'JAVA_TOOL_OPTIONS':'-Djavax.net.ssl.trustStore=/run/ouf-seaweedfs/truststore.p12 -Djavax.net.ssl.trustStorePassword=PRIVATE',
             'SPRING_APPLICATION_JSON':'{"password":"PRIVATE"}','OUF_ONB_DB_PASSWORD':'PRIVATE'}
        s=m.selected_declarations(env,args)
        self.assertTrue(s['allStagingArgumentsMatchSeaweedfsSwitch']);self.assertTrue(s['truststoreDeclarationMatchesSwitch'])
        self.assertNotIn('PRIVATE',json.dumps(s))
        args.append('--ouf.onboarding.staging.endpoint=http://old-minio:9000')
        self.assertFalse(m.selected_declarations(env,args)['allStagingArgumentsMatchSeaweedfsSwitch'])
        env['_JAVA_OPTIONS']='-Djavax.net.ssl.trustStore=/other'
        self.assertFalse(m.selected_declarations(env,args)['truststoreDeclarationMatchesSwitch'])

    def test_jdbc_binding_stays_on_retained_postgres(self):
        doc={'Config':{'Env':['OUF_ONB_DB_URL=jdbc:postgresql://ouf-postgres:5432/ouf_onboarding',
                              'OUF_ONB_DB_USER=onboarding','OUF_ONB_DB_PASSWORD=PRIVATE']}}
        pg={'Name':'/ouf-postgres','NetworkSettings':{'Networks':{}}}
        self.assertEqual(m.db_binding(doc,pg,c,h),('onboarding','ouf_onboarding'))
        original=copy.deepcopy(doc)
        m.db_binding(doc,pg,c,h);self.assertEqual(doc,original)
        for url in ('jdbc:postgresql://elsewhere/ouf_onboarding','jdbc:postgresql://ouf-postgres/ouf_onboarding?user=postgres'):
            doc['Config']['Env'][0]='OUF_ONB_DB_URL='+url
            with self.assertRaises(RuntimeError):m.db_binding(doc,pg,c,h)

    def test_package_comparison_does_not_confuse_candidate_class_presence_with_runtime(self):
        raw=io.BytesIO();sql=b'SELECT 1;';yaml=b'spring: {}';cls='BOOT-INF/classes/x/ManagedFileProfiler.class'
        with zipfile.ZipFile(raw,'w') as z:
            z.writestr('BOOT-INF/classes/db/migration/V1__fixture.sql',sql)
            z.writestr('BOOT-INF/classes/application.yml',yaml);z.writestr(cls,b'old')
        target={'migrations':[{'name':'V1__fixture.sql','sha256':m.sha(sql)}],
                'applicationYaml':{'sha256':m.sha(yaml)},'selectedClasses':{cls:m.sha(b'new')}}
        v=m.package(raw.getvalue(),target)
        self.assertTrue(v['allMigrationFilesMatchCandidate']);self.assertTrue(v['applicationYamlMatchesCandidate'])
        self.assertFalse(v['selectedClasses']['ManagedFileProfiler.class']['matchesCandidate'])
        self.assertFalse(v['classPresenceProvesRuntimeBehavior'])
        target['migrations'][0]['sha256']='0'*64
        self.assertFalse(m.package(raw.getvalue(),target)['allMigrationFilesMatchCandidate'])

class NativeQuery(unittest.TestCase):
    @unittest.skipUnless(os.getenv('OUF_NATIVE_PREFLIGHT')=='1','native PostgreSQL fixture not selected')
    def test_select_only_role_reads_history_without_changing_it(self):
        def sql(text):
            p=subprocess.run(['psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1'],input=text.encode(),capture_output=True,timeout=15)
            self.assertEqual(p.returncode,0,p.stderr.decode());return p.stdout.decode().strip()
        values=','.join('(%d,%s,%s,%s,\'%s\',\'%s\')'%(r['installedRank'],
            'NULL' if r['version'] is None else "'"+r['version']+"'",'NULL' if r['checksum'] is None else r['checksum'],
            'true',r['type'],r['installedOn']) for r in rows())
        sql("CREATE ROLE reader NOLOGIN; CREATE SCHEMA ouf_onboarding; CREATE TABLE ouf_onboarding.flyway_schema_history("
            "installed_rank integer primary key,version varchar(50),checksum integer,success boolean,type varchar(20),installed_on timestamp);"
            "INSERT INTO ouf_onboarding.flyway_schema_history VALUES "+values+"; GRANT USAGE ON SCHEMA ouf_onboarding TO reader;"
            "GRANT SELECT ON ouf_onboarding.flyway_schema_history TO reader;")
        before=sql('SELECT json_agg(t ORDER BY installed_rank) FROM ouf_onboarding.flyway_schema_history t;')
        v=json.loads(sql('SET ROLE reader;'+m.QUERY))
        self.assertTrue(v['readOnly']);self.assertFalse(v['applicationRoleSuperuser'])
        self.assertTrue(m.database_result(v,expected)['exactCandidateMigrationHistory'])
        self.assertEqual(before,sql('SELECT json_agg(t ORDER BY installed_rank) FROM ouf_onboarding.flyway_schema_history t;'))
        sql("UPDATE ouf_onboarding.flyway_schema_history SET checksum=checksum+1 WHERE version='38';")
        v=json.loads(sql('SET ROLE reader;'+m.QUERY))
        self.assertFalse(m.database_result(v,expected)['exactCandidateMigrationHistory'])

if __name__=='__main__':unittest.main(verbosity=2)
