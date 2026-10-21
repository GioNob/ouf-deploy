#!/usr/bin/env python3
"""Disposable CI only: frozen MCP create/inspect and real PostgreSQL reader query."""
import hashlib,http.client,importlib.util,json,os,re,socket,subprocess,sys,tarfile,tempfile,uuid,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('reader',ROOT/'scripts/read-chatbot-mcp-migration-state-20261016.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
PART_SHA='554d04fc354cf48b56b32914ed0e63def8cca100606e24a8a5f62f7ee8c69208'

def docker(*argv):
    p=subprocess.run(['docker',*argv],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120)
    r.require(p.returncode==0,'DISPOSABLE_DOCKER_FAILED')
    return p.stdout.decode().strip()
def engine(method,path,body=None):
    class Local(http.client.HTTPConnection):
        def connect(self):
            self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(15)
            self.sock.connect('/var/run/docker.sock')
    c=Local('localhost',timeout=15)
    try:
        c.request(method,'/v1.44'+path,body=None if body is None else json.dumps(body),headers={'Content-Type':'application/json'})
        response=c.getresponse();raw=response.read(2097153)
        r.require(response.status in (200,201,204) and len(raw)<=2097152,'CI_ENGINE_FAILED')
        return json.loads(raw) if raw else None
    finally:c.close()
def main():
    r.require(os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true','DISPOSABLE_CI_ONLY')
    part=Path(sys.argv[1]);output=Path(sys.argv[2]);output.mkdir(mode=0o755)
    with part.open('rb')as f:r.require(hashlib.file_digest(f,'sha256').hexdigest()==PART_SHA,'FROZEN_MCP_ARTIFACT_DRIFT')
    info=json.loads(docker('info','--format','{{json .}}'))
    r.require(info['ServerVersion']=='29.8.1' and info['Driver']=='overlayfs','QUALIFIED_CI_DAEMON_REQUIRED')
    cid=pg=None
    with tempfile.TemporaryDirectory(prefix='ouf-mcp-ci-',dir='/var/lib')as d:
        root=Path(d)
        with zipfile.ZipFile(part)as z:
            r.require(len(z.namelist())==len(set(z.namelist())),'DUPLICATE_ARCHIVE_MEMBER')
            for name in ('image.docker.tar','package-record.json'):
                member=z.getinfo(name);r.require(not member.is_dir() and member.file_size<268435456,'BOUNDED_PACKAGE_REQUIRED')
                with z.open(member)as src,(root/name).open('xb')as dst:
                    while raw:=src.read(1048576):dst.write(raw)
        record=json.loads((root/'package-record.json').read_bytes())
        with tarfile.open(root/'image.docker.tar')as tar:
            manifest=json.load(tar.extractfile('manifest.json'));r.require(len(manifest)==1,'ONE_IMAGE_REQUIRED')
            config_raw=tar.extractfile(manifest[0]['Config']).read(2097153)
            r.require('sha256:'+hashlib.sha256(config_raw).hexdigest()==record['imageId'],'CONFIG_IMAGE_DRIFT')
            config=json.loads(config_raw)['config']
        r.require(config['Labels']['org.opencontainers.image.revision']==record['sourceCommit'],'SOURCE_LABEL_DRIFT')
        docker('load','--input',str(root/'image.docker.tar'))
        image=json.loads(docker('image','inspect',record['imageTag']))[0]
        r.require(image['Config']['Env']==config['Env'] and image['Config']['Labels']==config['Labels'],'LOADED_IMAGE_DRIFT')
        network=docker('network','create','ouf-backend')
        creation={'Image':image['Id'],'User':'10005:10005','Entrypoint':['/usr/local/bin/ouf-mcp'],
            'Env':['MCP_DATABASE_URL=postgres://synthetic:CI_ONLY@localhost/fixture'],
            'NetworkingConfig':{'EndpointsConfig':{'ouf-backend':{'NetworkID':network}}}}
        prepared={'cohortPlan':{'replacements':[{'module':'mcp','retiredName':'ouf-mcp-before-ci-'+uuid.uuid4().hex,'creationRequest':creation}]}}
        name,request=r.migration_request(prepared)
        try:
            created=engine('POST','/containers/create?name='+name,request);cid=created['Id']
            actual=engine('GET','/containers/'+cid+'/json')
            projection=r.native_projection(name,request,actual,image);state=r.native_state(actual)
            r.require(state['neverStarted'] and state['status']=='created' and state['pid']==0,'CI_MIGRATION_MUST_NOT_START')
            r.require(projection['environmentMatchesImageDefaultsAndRequest'] and projection['labelsMatchImageDefaultsAndRequest'],
                'NATIVE_MERGE_EXPLANATION_FAILED')
            r.require(not projection['originalPredicateMatches'],'FAILURE_NOT_REPRODUCED')
            summary={'schema':'ouf.mcp-migration-native-readback-qualification.v1','artifactId':11906464158,
                'artifactSha256':PART_SHA,'configImageId':record['imageId'],'sourceCommit':record['sourceCommit'],
                'nativeImageId':image['Id'],'dockerVersion':info['ServerVersion'],
                'migrationContainerStarted':False,'targetAccess':False,'runtimeAuthorityIssued':False,
                'originalPredicate':projection,'native':state}
            # Disposable local SQL fixture. No target connection or target credentials.
            pg=docker('run','--detach','--name','ouf-mcp-readback-pg','--network','none','--env','POSTGRES_USER=postgres','--env','POSTGRES_HOST_AUTH_METHOD=trust','postgres:17-alpine')
            ready=False
            import time
            for _ in range(60):
                probe=subprocess.run(['docker','exec',pg,'pg_isready','-U','postgres'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=3)
                if probe.returncode==0:ready=True;break
                time.sleep(1)
            r.require(ready,'CI_POSTGRES_NOT_READY')
            sql="""CREATE ROLE fixture_app NOLOGIN;
CREATE ROLE ouf_mcp_operational_audit_owner NOLOGIN;
CREATE SCHEMA ouf_mcp;
CREATE TABLE ouf_mcp.schema_migration(version int,checksum text);
INSERT INTO ouf_mcp.schema_migration VALUES (1,repeat('a',64));
CREATE TABLE ouf_mcp.security_incident(id int);
GRANT CREATE ON SCHEMA ouf_mcp TO ouf_mcp_operational_audit_owner;
GRANT ouf_mcp_operational_audit_owner TO fixture_app WITH INHERIT FALSE, SET TRUE;
"""
            docker('exec',pg,'psql','-X','-q','-v','ON_ERROR_STOP=1','-U','postgres','-c',sql)
            oid=int(docker('exec',pg,'psql','-X','-A','-t','-U','postgres','-c',"SELECT oid FROM pg_database WHERE datname='postgres'"))
            binding={'module':'mcp','user':'fixture_app','database':'postgres','databaseOid':oid,
                'beforeMigrations':[{'version':1,'checksum':'a'*64}],
                'expectedMigrations':[{'version':1,'checksum':'a'*64},{'version':2,'checksum':'b'*64}]}
            incident=json.loads(docker('exec',pg,'psql','-X','-A','-t','-U','postgres','-c',r.incident_metadata('fixture_app',True)))
            pg_native=json.loads(docker('inspect',pg))[0];s=os.stat('/var/run/docker.sock')
            p={'engine':{'socketPath':'/var/run/docker.sock','socketBinding':[s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode&0o777]},
               'databasePlan':{'postgresRuntimeBinding':r.runtime_pin(pg_native),
                 'mcpAuditRoleAdministration':{'admin':'postgres','temporaryIncidentTrigger':True},
                 'mcpAuditRolePreflight':{'incidentBinding':incident}}}
            config_dir=root/'docker-config';config_dir.mkdir(mode=0o700)
            facts=r.sql_read('/opt/ouf-docker-29/docker',p,str(config_dir),binding)
            r.require(facts['schemaCreate'] and facts['appMembership']==1 and facts['beforeMigrationsMatch'] and
                facts['incidentPreservedAclMatches'],'REAL_DATABASE_READBACK_FAILED')
            summary['realPostgresReadOnlyFacts']=facts
            output.joinpath('summary.json').write_text(json.dumps(summary,sort_keys=True,indent=2)+'\n')
            print(json.dumps(summary,sort_keys=True))
        finally:
            if cid:docker('rm',cid)
            if pg:docker('rm','--force',pg)
            docker('network','rm','ouf-backend')
if __name__=='__main__':
    try:main()
    except Exception as error:
        print(json.dumps({'ciFailureClass':type(error).__name__,'rawDiagnosticPrinted':False}))
        raise SystemExit(1)
