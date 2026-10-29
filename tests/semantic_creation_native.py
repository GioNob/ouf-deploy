"""Hosted disposable engine fixture. Never a target apply or real application."""
import copy
import http.client
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import uuid

s=importlib.util.spec_from_file_location('fixture',Path(__file__).with_name('test_semantic_creation_plan.py'))
f=importlib.util.module_from_spec(s);s.loader.exec_module(f)
m=f.m


def docker(*args):
    return subprocess.run(['docker',*args],capture_output=True,check=True,timeout=60).stdout


class UnixConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout);self.sock.connect('/var/run/docker.sock')


def native():
    assert os.geteuid()==0
    nonce=uuid.uuid4().hex[:12]
    network='ouf-creation-'+nonce;old_name=network+'-old';new_name=network+'-new'
    old=None;new=None
    with tempfile.TemporaryDirectory(prefix='ouf-creation-native-') as directory:
        root=Path(directory);root.chmod(0o755)
        roles=[]
        for name in ('auth','discovery','trust'):
            path=root/name;path.write_text('nonproduction-'+name)
            os.chown(path,10001,10001);path.chmod(0o400)
            roles.append({'source':str(path),'target':'/run/'+name,'readOnly':True,
                          'uid':10001,'gid':10001,'mode':0o400})
        secret=root/'database';secret.mkdir();os.chown(secret,10001,10001);secret.chmod(0o500)
        file=secret/'OUF_SEM_DB_PASSWORD';file.write_text('nonproduction-fixture-password')
        os.chown(file,10001,10001);file.chmod(0o400)
        try:
            docker('pull','alpine:3.22')
            image=json.loads(docker('image','inspect','alpine:3.22'))[0]['Id']
            docker('network','create','--internal','--subnet','172.30.77.0/24',network)
            old=docker('run','-d','--name',old_name,'--network',network,'--ip','172.30.77.6',
                       '--mac-address','02:42:ac:1e:4d:06','--user','10001:10001',
                       '--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',
                       image,'sleep','300').decode().strip()
            actual=json.loads(docker('inspect',old))[0]
            declaration,host=f.CreationPlan().fixture()
            declaration['retainedNativeCreationFrame']=actual
            declaration['candidateConfig']=copy.deepcopy(actual['Config'])
            declaration['candidateConfig']['Env']=[v for v in actual['Config']['Env']
                                                   if not v.startswith('OUF_SEM_DB_PASSWORD=')]
            declaration['candidateConfig']['Env'].append('SPRING_CONFIG_IMPORT=configtree:/run/database/')
            declaration['candidateImageId']=image
            declaration['roleOwnedReadOnlyMounts']=roles
            declaration['databaseSecretProjection']['sourceDirectory']=str(secret)
            binds=[r['source']+':'+r['target']+':ro' for r in roles]+[str(secret)+':/run/database:ro']
            declaration['hostDelta']['appendedReadOnlyBinds']=binds
            declaration['proposedHostConfig']=copy.deepcopy(actual['HostConfig'])
            declaration['proposedHostConfig']['Binds']=list(actual['HostConfig'].get('Binds') or [])+binds
            declaration['proposedHostConfig']['RestartPolicy']={'Name':'no','MaximumRetryCount':0}
            host['semantic']={'containerId':actual['Id'],'imageId':actual['Image'],
                'generation':{k:actual['State'][k] for k in ('Pid','StartedAt','Running')},
                'installedConfigHash':m.digest(actual['Config']),
                'installedHostConfigHash':m.digest(actual['HostConfig']),
                'installedMountsHash':m.digest(actual['Mounts']),
                'networkSettingsHash':m.digest(actual['NetworkSettings'])}
            request,public=m.compile_creation(declaration,m.digest(declaration),host)
            assert not public['productionApplyReady']
            # Fixture-only lifecycle: one endpoint owns IP/MAC at a time.
            docker('stop','--time','1',old);docker('network','disconnect',network,old)
            connection=UnixConnection('localhost',timeout=30)
            connection.request('POST','/v1.44/containers/create?name='+new_name,
                               body=m.encoded(request),headers={'Content-Type':'application/json'})
            response=connection.getresponse();body=response.read(65536);connection.close()
            assert response.status==201, (response.status,body.decode()[:300])
            new=json.loads(body)['Id'];docker('start',new)
            following=json.loads(docker('inspect',new))[0]
            for key in ('Memory','MemorySwap','NanoCpus','PidsLimit','RestartPolicy','ReadonlyRootfs',
                        'CapDrop','SecurityOpt','PortBindings','LogConfig','Ulimits'):
                assert following['HostConfig'][key]==request['HostConfig'][key],key
            assert following['Config']['User']=='10001:10001'
            for declared in roles + [{'source':str(secret),'target':'/run/database'}]:
                matches=[v for v in following['Mounts'] if v['Destination']==declared['target']]
                assert len(matches)==1 and matches[0]['Source']==declared['source'] and matches[0]['RW'] is False
            assert docker('exec',new,'id','-u').strip()==b'10001'
            assert docker('exec',new,'cat','/run/database/OUF_SEM_DB_PASSWORD')==b'nonproduction-fixture-password'
            denied=subprocess.run(['docker','exec',new,'sh','-c','echo forbidden >> /run/database/OUF_SEM_DB_PASSWORD'],
                                  capture_output=True,timeout=10)
            assert denied.returncode!=0
            endpoint=following['NetworkSettings']['Networks'][network]
            assert endpoint['IPAddress']=='172.30.77.6' and endpoint['MacAddress']=='02:42:ac:1e:4d:06'
            assert following['State']['Pid']>0 and following['State']['Running'] is True
            print('CI_SEMANTIC_CREATION=REAL_ENGINE_API_UID10001_READONLY_INPUT_RESOURCE_LIMITS_IP_MAC_PASS '
                  'FIXTURE_IMAGE_ALPINE=true TARGET_ACTIONS=0 COMPLETE_OCI_APPLICATION_ACCEPTANCE=false')
        finally:
            for cid in (new,old):
                if cid:subprocess.run(['docker','rm','-f',cid],capture_output=True,timeout=30)
            subprocess.run(['docker','network','rm',network],capture_output=True,timeout=30)


if __name__=='__main__':native()
