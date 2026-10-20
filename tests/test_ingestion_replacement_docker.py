"""Actual Docker29 two-NIC verification and new Gateway namespace FD, CI only.

Sleeping Gateway fixture is not APISIX; running Ingestion is not DB admission
or readiness. Neither these tests nor a namespace FD grant runtime authority.
"""
import copy
import os
from pathlib import Path
import stat
import subprocess
import sys
import unittest
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover')]
import test_ingestion_frame_mac_docker as fixture
engine,cli,r=fixture.engine,fixture.cli,fixture.r
from tools.ingestion_rollout_execution.replacement import validate,generation,EngineReader
from tools.ingestion_rollout_execution.namespace import GatewayNamespacePin,identity
from tools.ingestion_rollout_execution.contract import Denied
from engine_creation import Engine

class NativeReplacement(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture.NativeCreation.setUpClass();cls.addClassCleanup(fixture.NativeCreation.doClassCleanups)
        cls.root=fixture.NativeCreation.root;cls.image=fixture.NativeCreation.image
        cls.image_config=fixture.NativeCreation.image_config;cls.key=fixture.NativeCreation.key
        socket_path='/var/run/docker.sock';s=os.stat(socket_path,follow_symlinks=False)
        cls.reader=EngineReader(Engine(socket_path,(s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))))
    def test_ingestion_full_created_running_and_process_fence_two_networks(self):self.roundtrip('ingestion')
    def test_gateway_private_resolution_and_new_namespace_fd_two_networks(self):self.roundtrip('gateway')
    def roundtrip(self,module):
        label='ouf-replacement-'+uuid.uuid4().hex[:10];networks=[label+'-one',label+'-two'];containers=[]
        for name in networks:cli(['network','create',name])
        try:
            ids=[engine('GET','/networks/'+name)['Id']for name in networks]
            config=copy.deepcopy(self.image_config);config.update(Image=self.image,Hostname='',MacAddress='02:42:ac:11:00:82')
            config['Env']=[v for v in config.get('Env',[])if not v.startswith('SPRING_FLYWAY_ENABLED=')]+['SPRING_FLYWAY_ENABLED=false']
            if module=='gateway':config.update(Entrypoint=['/bin/sleep'],Cmd=['600'])
            else:config['Cmd']=['--spring.flyway.enabled=false','--ouf.ingestion.startup.schema-mode=VALIDATE_ONLY']
            old_file=self.root/(label+'-old.conf');old_file.write_bytes(b'ci retained config');old_file.chmod(0o444)
            target=r.frames.CONFIG_DESTINATION if module=='gateway'else'/fixture-existing'
            host={'NetworkMode':networks[0],'RestartPolicy':{'Name':'unless-stopped','MaximumRetryCount':0},
                  'ReadonlyRootfs':True,'Memory':536870912,'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges'],
                  'Binds':[str(old_file)+':'+target+':ro']}
            initial={**config,'HostConfig':host,'NetworkingConfig':{'EndpointsConfig':{
                networks[0]:{'NetworkID':ids[0],'Aliases':[label+'-stable-one'],'MacAddress':'02:42:ac:11:00:82'}}}}
            old=engine('POST','/containers/create?name='+label,initial)['Id'];containers.append(old)
            engine('POST','/networks/'+ids[1]+'/connect',{'Container':old,'EndpointConfig':{
                'Aliases':[label+'-stable-two'],'MacAddress':'02:42:ac:12:00:82'}})
            engine('POST','/containers/'+old+'/start');engine('POST','/containers/'+old+'/pause')
            retained=engine('GET','/containers/'+old+'/json')
            old_namespace=identity(os.stat('/proc/'+str(retained['State']['Pid'])+'/ns/net'))
            draft={'candidate':{'sourceCommit':r.package.SOURCE},'ingestion':{
                'ownerReadEnvironmentAdditions':{'OUF_ING_GATEWAY_READ_ENABLED':'true'},
                'startupEnvironmentAddition':{'SPRING_FLYWAY_ENABLED':'false'},
                'bootstrapCmd':['--spring.flyway.enabled=false','--ouf.ingestion.startup.schema-mode=VALIDATE_ONLY'],
                'readOnlyBindAddition':{'Type':'bind','Source':str(self.key),'Destination':'/run/secrets/fixture-owner-key','RW':False}}}
            staged=self.root/(label+'-new.conf');staged.write_bytes(b'ci staged config');staged.chmod(0o444)
            frame=r.frames.frame(module,retained,self.image,self.image_config,draft,str(staged)if module=='gateway'else None)
            request=copy.deepcopy(frame['requestTemplate']);kwargs={}
            if module=='gateway':
                request['Env']=[v.replace('@ouf-secret-reference:ingestionReadOwnerKey','c'*64)for v in request['Env']]
                kwargs['resolved_owner_key']='c'*64
            engine('POST','/containers/'+old+'/unpause');engine('POST','/containers/'+old+'/stop?t=1')
            for nid in ids:engine('POST','/networks/'+nid+'/disconnect',{'Container':old,'Force':False})
            engine('POST','/containers/'+old+'/rename?name='+label+'-retained')
            new=engine('POST','/containers/create?name='+frame['name'],request)['Id'];containers.append(new)
            proof=validate(frame,self.reader.container(new),self.image_config,old,created_id=new,phase='CREATED',**kwargs)
            self.assertTrue(proof['neverStarted'])
            engine('POST','/containers/'+new+'/start')
            running=self.reader.container(new);process=generation(running)
            self.assertEqual(validate(frame,running,self.image_config,old,created_id=new,process=process,**kwargs),process)
            changed=copy.deepcopy(process);changed['pid']+=1
            with self.assertRaises(Denied):validate(frame,running,self.image_config,old,created_id=new,process=changed,**kwargs)
            if module=='gateway':
                namespace=identity(os.stat('/proc/'+str(process['pid'])+'/ns/net'))
                with self.assertRaises(Denied):
                    GatewayNamespacePin(self.reader,frame,self.image_config,old,new,process,namespace,namespace,**kwargs)
                with GatewayNamespacePin(self.reader,frame,self.image_config,old,new,process,namespace,old_namespace,**kwargs)as pin:
                    self.assertEqual(pin.check()['namespace'],identity(os.fstat(pin.fd)))
                    self.assertFalse(pin.check()['oldNamespaceReused'])
                    engine('POST','/containers/'+new+'/pause')
                    with self.assertRaises(Denied):pin.check()
                self.assertIsNone(pin.fd)
            # Native container retention is observable: no removal of predecessor.
            self.assertFalse(self.reader.container(old)['State']['Running'])
            self.assertEqual(self.reader.container(old)['Name'],'/'+label+'-retained')
        finally:
            for cid in containers:
                subprocess.run(['docker','unpause',cid],capture_output=True,timeout=10)
                subprocess.run(['docker','rm','-f',cid],capture_output=True,timeout=20)
            for name in networks:subprocess.run(['docker','network','rm',name],capture_output=True,timeout=10)

if __name__=='__main__':unittest.main()
