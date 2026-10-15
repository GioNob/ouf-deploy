"""Real CLI/API and semantic Flyway history; disposable CI resources only."""
import hashlib,json,os,shutil,stat,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import test_chatbot_cohort_runtime_layout as setup

p=setup.p
ROOT=Path(__file__).resolve().parents[1]

@unittest.skipUnless(os.environ.get('OUF_NATIVE_SOCKETS')=='1' and os.environ.get('OUF_POSTGRES_CONTAINER_ID'),'explicit disposable native fixture required')
class NativeRetainedInspection(unittest.TestCase):
    def test_paired_inspection_and_semantic_marker_preserve_fixture(self):
        docker=str(Path(shutil.which('docker')).resolve());binding={'path':docker,'sha256':hashlib.sha256(Path(docker).read_bytes()).hexdigest()}
        pg_id=os.environ['OUF_POSTGRES_CONTAINER_ID'];suffix=str(os.getpid())
        db='ouf_sem_inspection_'+suffix;app='ouf_inspection_app_'+suffix
        name='ouf-channel-proof-'+suffix;network='ouf-backend';cid=None;net_created=False;connected=False;role_created=False;db_created=False
        def command(args,data=None):
            return subprocess.run([docker,*args],input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15,check=True).stdout
        def sql(database,user,text):
            return command(['exec','-i',pg_id,'psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-U',user,'-d',database],text.encode()).decode().strip()
        with tempfile.TemporaryDirectory(dir=ROOT,prefix='inspection-native-') as config,patch.dict(os.environ):
            socket_path=str(Path('/var/run/docker.sock').resolve());s=os.stat(socket_path)
            engine=p.Engine(socket_path,(s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)))
            # The paired reader needs a pinned empty CLI configuration, not
            # the authorization-owner installer imported by delivery.py.
            os.environ.update(PATH='/usr/sbin:/usr/bin:/sbin:/bin',DOCKER_HOST='unix://'+socket_path,DOCKER_CONFIG=config)
            for key in ('DOCKER_CONTEXT','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH','DOCKER_API_VERSION'):os.environ.pop(key,None)
            try:
                command(['network','create',network]);net_created=True
                command(['network','connect',network,pg_id]);connected=True
                cid=command(['run','-d','--network',network,'--name',name,'--entrypoint','/bin/sleep','postgres:17-alpine','120']).decode().strip()
                old=json.loads(command(['inspect','--type=container',cid]))[0]
                api,native=p.paired_retained_inspection(engine,old,binding,p.ObservationBudget(60))
                self.assertEqual(p.Engine.runtime_binding(old),p.Engine.runtime_binding(native))
                code,again=engine.request('GET','/v1.44/containers/'+cid+'/json')
                self.assertEqual(code,200);self.assertEqual(p.Engine.runtime_binding(api),p.Engine.runtime_binding(again))
                print(json.dumps({'pairedNativeCliBinding':p.Engine.runtime_binding(native),'pairedNativeApiBinding':p.Engine.runtime_binding(api),'fullBindingsRetained':True}),flush=True)
                # Separate actual PostgreSQL application/bootstrap identities.
                sql('postgres','postgres','CREATE ROLE '+app+' LOGIN;');role_created=True
                sql('postgres','postgres','CREATE DATABASE '+db+' OWNER '+app+';');db_created=True
                sql(db,app,'CREATE SCHEMA ouf_sem AUTHORIZATION '+app+'; CREATE TABLE ouf_sem.flyway_schema_history(installed_rank int,version text,type text,script text,checksum int,success bool); '
                    'INSERT INTO ouf_sem.flyway_schema_history VALUES (0,NULL,\'SCHEMA\',\'"ouf_sem"\',NULL,true),(1,\'1\',\'SQL\',\'V1__init.sql\',123,true); '
                    "CREATE TABLE ouf_sem.retained_rows(k int PRIMARY KEY,v text); INSERT INTO ouf_sem.retained_rows VALUES(1,'retained');")
                before=sql(db,app,"SELECT json_build_object('rows',(SELECT json_agg(x ORDER BY k) FROM ouf_sem.retained_rows x),'history',(SELECT json_agg(h ORDER BY installed_rank) FROM ouf_sem.flyway_schema_history h),'roles',(SELECT count(*) FROM pg_roles),'applicationSuperuser',(SELECT rolsuper FROM pg_roles WHERE rolname=current_user));")
                pg=json.loads(command(['inspect','--type=container',pg_id]))[0]
                self.assertIn('POSTGRES_USER=postgres',pg['Config']['Env'])
                request={'Env':['OUF_SEM_DB_URL=jdbc:postgresql://'+pg['Name'].lstrip('/')+':5432/'+db,'OUF_SEM_DB_USER='+app]}
                expected=[{'version':'1','type':'SQL','script':'V1__init.sql','checksum':123,'success':True},
                          {'version':'2','type':'SQL','script':'V2__pending.sql','checksum':456,'success':True}]
                observed=p.registry_database(pg,request,expected)
                self.assertEqual(observed['expected'][0],{'version':None,'type':'SCHEMA','script':'"ouf_sem"','checksum':None,'success':True})
                self.assertEqual(len(observed['before']),2);self.assertEqual(len(observed['expected']),3)
                after=sql(db,app,"SELECT json_build_object('rows',(SELECT json_agg(x ORDER BY k) FROM ouf_sem.retained_rows x),'history',(SELECT json_agg(h ORDER BY installed_rank) FROM ouf_sem.flyway_schema_history h),'roles',(SELECT count(*) FROM pg_roles),'applicationSuperuser',(SELECT rolsuper FROM pg_roles WHERE rolname=current_user));")
                self.assertEqual(json.loads(before),json.loads(after));self.assertFalse(json.loads(after)['applicationSuperuser'])
            finally:
                if db_created:sql('postgres','postgres','DROP DATABASE '+db+' WITH (FORCE);')
                if role_created:sql('postgres','postgres','DROP ROLE '+app+';')
                if cid:command(['rm','-f',cid])
                if connected:command(['network','disconnect',network,pg_id])
                if net_created:command(['network','rm',network])

if __name__=='__main__':unittest.main()
