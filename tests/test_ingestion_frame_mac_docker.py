"""Real Docker29/API1.44 two-NIC create round trips, disposable CI only.

Uses the qualified Ingestion image for Docker configuration semantics. The
Gateway fixture sleeps; this is not APISIX readiness or signed rollout acceptance.
"""
import copy
import http.client
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
import uuid

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
r=load('mac_source',ROOT/'scripts/reconcile-ingestion-frame-mac-20261020.py')
old=load('original_custody',ROOT/'scripts/prepare-ingestion-rollout-packet-20261020.py')

def cli(args):return subprocess.run(['docker',*args],check=True,capture_output=True,timeout=90).stdout.decode().strip()
def engine(method,path,body=None):
    class Connection(http.client.HTTPConnection):
        def connect(self):
            self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(10);self.sock.connect('/var/run/docker.sock')
    c=Connection('ci-engine',timeout=10)
    try:
        c.request(method,'/v1.44'+path,body=None if body is None else json.dumps(body).encode(),headers={'Content-Type':'application/json'})
        response=c.getresponse();raw=response.read(8388608)
        if response.status not in(200,201,204,304):raise AssertionError('CI_ENGINE_'+str(response.status)+'_'+raw.decode()[:1200])
        return json.loads(raw)if raw else None
    finally:c.close()

class NativeCreation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        info=engine('GET','/info');assert info['ServerVersion']=='29.8.1'and info['Driver']=='overlayfs'
        cls.directory=tempfile.TemporaryDirectory(dir=os.environ['OUF_TEST_ROOT']);cls.root=Path(cls.directory.name)
        cls.addClassCleanup(cls.directory.cleanup)
        with open(os.environ['OUF_CANDIDATE_ZIP'],'rb')as f:proof=old.authenticate_candidate(f,cls.root)
        cli(['load','-i',proof['nativeArchivePath']]);cls.image=r.NATIVE_ID
        cls.image_config=proof['nativeImageAudit']['imageConfig']
        cls.key=cls.root/'fixture-key';cls.key.write_bytes(b'c'*64);os.chown(cls.key,10002,10002);cls.key.chmod(0o400)

    def test_ingestion_complete_frame_real_api144_legacy_mac_and_two_networks(self):self.roundtrip('ingestion')
    def test_gateway_complete_frame_real_api144_legacy_mac_and_two_networks(self):self.roundtrip('gateway')

    def roundtrip(self,module):
        label='ouf-mac-'+uuid.uuid4().hex[:10];networks=[label+'-one',label+'-two'];containers=[]
        for name in networks:cli(['network','create',name])
        try:
            ids=[json.loads(cli(['network','inspect',name]))[0]['Id']for name in networks]
            config=copy.deepcopy(self.image_config);config.update(Image=self.image,Hostname='',MacAddress='02:42:ac:11:00:81')
            config['Env']=[v for v in config.get('Env',[])if not v.startswith('SPRING_FLYWAY_ENABLED=')]+['SPRING_FLYWAY_ENABLED=false']
            if module=='gateway':config.update(Entrypoint=['/bin/sleep'],Cmd=['600'])
            else:config['Cmd']=['--spring.flyway.enabled=false','--ouf.ingestion.startup.schema-mode=VALIDATE_ONLY']
            original_file=self.root/(label+'-old.conf');original_file.write_bytes(b'ci old config');original_file.chmod(0o444)
            target=r.frames.CONFIG_DESTINATION if module=='gateway'else'/fixture-existing'
            host={'NetworkMode':networks[0],'RestartPolicy':{'Name':'unless-stopped','MaximumRetryCount':0},
                  'ReadonlyRootfs':True,'Memory':536870912,'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges'],
                  'Binds':[str(original_file)+':'+target+':ro']}
            initial={**config,'HostConfig':host,'NetworkingConfig':{'EndpointsConfig':{
                networks[0]:{'NetworkID':ids[0],'Aliases':[label+'-stable-one'],'MacAddress':'02:42:ac:11:00:81'}}}}
            cid=engine('POST','/containers/create?name='+label+'-old',initial)['Id'];containers.append(cid)
            engine('POST','/networks/'+ids[1]+'/connect',{'Container':cid,'EndpointConfig':{
                'Aliases':[label+'-stable-two'],'MacAddress':'02:42:ac:12:00:81'}})
            engine('POST','/containers/'+cid+'/start');engine('POST','/containers/'+cid+'/pause')
            actual=engine('GET','/containers/'+cid+'/json')
            self.assertTrue(actual['Config'].get('MacAddress'))
            self.assertEqual(len(actual['NetworkSettings']['Networks']),2)
            draft={'candidate':{'sourceCommit':r.package.SOURCE},'ingestion':{
                'ownerReadEnvironmentAdditions':{'OUF_ING_GATEWAY_READ_ENABLED':'true'},
                'startupEnvironmentAddition':{'SPRING_FLYWAY_ENABLED':'false'},
                'bootstrapCmd':['--spring.flyway.enabled=false','--ouf.ingestion.startup.schema-mode=VALIDATE_ONLY'],
                'readOnlyBindAddition':{'Type':'bind','Source':str(self.key),'Destination':'/run/secrets/fixture-owner-key','RW':False}}}
            staged=self.root/(label+'-new.conf');staged.write_bytes(b'ci proposed config');staged.chmod(0o444)
            frame=r.frames.frame(module,actual,self.image,self.image_config,draft,str(staged)if module=='gateway'else None)
            request=frame['requestTemplate'];self.assertNotIn('MacAddress',request)
            self.assertTrue(frame['legacyContainerMacMovedToExplicitEndpoints'])
            engine('POST','/containers/'+cid+'/unpause');engine('POST','/containers/'+cid+'/stop?t=1')
            for nid in ids:engine('POST','/networks/'+nid+'/disconnect',{'Container':cid,'Force':True})
            engine('POST','/containers/'+cid+'/rename?name='+label+'-retained')
            new=engine('POST','/containers/create?name='+frame['name'],request)['Id'];containers.append(new)
            engine('POST','/containers/'+new+'/start');engine('POST','/containers/'+new+'/pause')
            observed=engine('GET','/containers/'+new+'/json')
            differences=[]
            def same(actual_value,expected_value,field):
                if actual_value!=expected_value:differences.append((field,actual_value,expected_value))
            for name,endpoint in actual['NetworkSettings']['Networks'].items():
                after=observed['NetworkSettings']['Networks'][name]
                for field in ('NetworkID','IPAddress','GlobalIPv6Address','MacAddress'):
                    same(after.get(field),endpoint.get(field),(module,name,field))
                # API1.44 injects the new container short ID as its own DNS
                # alias. Only that generation identity may differ.
                aliases=[v for v in after.get('Aliases')or[]if v not in(new,new[:12])]
                same(sorted(aliases),sorted(request['NetworkingConfig']['EndpointsConfig'][name]['Aliases']),(module,name,'Aliases'))
            for key,value in request['HostConfig'].items():
                same(observed['HostConfig'].get(key),value,(module,'HostConfig',key))
            for key,value in request.items():
                if key in('HostConfig','NetworkingConfig','Hostname','MacAddress'):continue
                if key=='Env':same(r.frames.environment(observed['Config']['Env']),r.frames.environment(value),(module,'Config',key));continue
                same(observed['Config'].get(key),value,(module,'Config',key))
            self.assertEqual(differences,[])
            self.assertEqual(observed['Config']['Hostname'],new[:12]);self.assertEqual(observed['Image'],self.image)
            self.assertFalse(frame['targetApplyAuthorized'])
        finally:
            for cid in containers:
                subprocess.run(['docker','unpause',cid],capture_output=True,timeout=10)
                subprocess.run(['docker','rm','-f',cid],capture_output=True,timeout=20)
            for name in networks:subprocess.run(['docker','network','rm',name],capture_output=True,timeout=10)

if __name__=='__main__':unittest.main()
