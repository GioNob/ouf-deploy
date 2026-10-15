"""Real Docker lifecycle contracts, not application/IAM/DB/OCI acceptance.

Four read-only binds, actual shell gate/nonroot process, pause/unpause/SIGUSR1,
HTTP readiness, native cohort comparator, policy update and network operations.
Only predecessor journal setup and attestation/admission boundaries are synthetic.
"""
import copy
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tests')]
import test_chatbot_cohort_containers as bootstrap
from engine_creation import Engine
from transition_journal import Transition,digest
from file_only_profile import FileOnlyProfile,PHASES
from gated_creation_plan import ENTRY,PROFILE as GATE_PROFILE
from creation_adapter import CreationAdapter
from gated_stage_adapter import GatedStageAdapter
from gated_release_adapter import GatedReleaseAdapter
from gated_process_observation import GatedProcessObservation
from native_evidence_store import NativeEvidenceStore
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.chatbot_file_cohort.containers import CohortContainers

JAVA=r'''#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
int main(void) {
 signal(SIGPIPE,SIG_IGN); int fd=socket(AF_INET,SOCK_STREAM,0),one=1;
 if(fd<0||setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one)))return 2;
 struct sockaddr_in a={0};a.sin_family=AF_INET;a.sin_addr.s_addr=htonl(INADDR_ANY);a.sin_port=htons(8080);
 if(bind(fd,(struct sockaddr*)&a,sizeof(a))||listen(fd,8))return 3;
 for(;;){int c=accept(fd,0,0);if(c<0){if(errno==EINTR)continue;return 4;}
 struct timeval t={2,0};setsockopt(c,SOL_SOCKET,SO_RCVTIMEO,&t,sizeof(t));
 char b[4097]={0};size_t used=0;
 while(used<sizeof(b)-1&&!strstr(b,"\r\n\r\n")){
 ssize_t n=read(c,b+used,sizeof(b)-1-used);if(n<=0)break;used+=(size_t)n;}
 const char response[]="HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"status\":\"UP\"}";
 size_t sent=0;while(sent<sizeof(response)-1){ssize_t n=write(c,response+sent,sizeof(response)-1-sent);if(n<=0)break;sent+=(size_t)n;}close(c);}
}'''

@unittest.skipUnless(os.environ.get('OUF_NATIVE_DOCKER_CONTRACT')=='1','explicit disposable Docker contract CI only')
class NativeDockerContract(unittest.TestCase):
    def test_created_through_paused_release_http_and_later_docker_operations(self):
        self.assertEqual(os.geteuid(),0)
        with tempfile.TemporaryDirectory(dir=ROOT) as temp:
            root=Path(temp);root.chmod(0o700);binary=shutil.which('docker');self.assertIsNotNone(binary)
            def docker(*args):
                result=subprocess.run([binary,*args],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180)
                self.assertEqual(result.returncode,0,result.stderr[-4000:].decode('utf-8','replace'))
                return result.stdout.decode().strip()
            info=os.stat('/var/run/docker.sock',follow_symlinks=False)
            engine=Engine('/var/run/docker.sock',(info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)))
            status,version=engine.request('GET','/version');self.assertEqual(status,200)
            status,host=engine.request('GET','/v1.44/info');self.assertEqual(status,200)
            expected=os.environ.get('OUF_DOCKER_EXPECTED_VERSION')
            if expected:self.assertEqual(version['Version'],expected)
            if expected=='29.8.1':
                self.assertEqual(host['Driver'],'overlayfs');self.assertEqual(host['CgroupDriver'],'systemd')
            print('DOCKER_CONTRACT_ENGINE='+json.dumps({k:version[k] for k in ('Version','ApiVersion','MinAPIVersion')}
                |{'driver':host['Driver'],'cgroupDriver':host['CgroupDriver']}),flush=True)
            build=root/'build';build.mkdir(mode=0o700);(build/'java.c').write_text(JAVA)
            compiled=subprocess.run([shutil.which('cc'),'-static','-O2','-Wall','-Wextra','-Werror',str(build/'java.c'),
                '-o',str(build/'java')],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
            self.assertEqual(compiled.returncode,0,compiled.stderr[-4000:].decode('utf-8','replace'))
            (build/'java').chmod(0o755)
            command=['java','-XX:MaxRAMPercentage=75','-jar','/app/application.jar']
            (build/'Dockerfile').write_text('FROM alpine:3.21\nCOPY java /usr/local/bin/java\n'
                'USER 10001:10001\nENTRYPOINT '+json.dumps(ENTRY)+'\nCMD '+json.dumps(command)+'\n')
            tag='ouf-docker-contract:'+hashlib.sha256(str(root).encode()).hexdigest()[:24]
            docker('build','--pull','-t',tag,str(build));image=docker('image','inspect','--format','{{.Id}}',tag)
            self.addCleanup(lambda:subprocess.run([binary,'image','rm','-f',tag],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20))
            status,image_data=engine.request('GET','/v1.44/images/'+image+'/json');self.assertEqual(status,200)
            self.assertIn(image_data['Config'].get('Volumes'),(None,{}))
            suffix=hashlib.sha256(str(root).encode()).hexdigest()[:12]
            networks=[]
            for part in ('primary','secondary'):
                name='ouf-backend' if part=='primary' else 'ouf-contract-'+part+'-'+suffix
                network=docker('network','create',name);networks.append((name,network))
                self.addCleanup(lambda n=network:subprocess.run([binary,'network','rm',n],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20))
            primary,nid=networks[0];status,network=engine.request('GET','/v1.44/networks/'+nid);self.assertEqual(status,200)
            subnet=ipaddress.ip_network(network['IPAM']['Config'][0]['Subnet']);address=str(subnet.network_address+7)
            targets=['/run/db','/run/token','/run/consult','/run/receipt'];binds=[];expected_mounts=set()
            for i,target in enumerate(targets):
                source=root/('bind'+str(i));source.mkdir(mode=0o755);os.chown(source,10001,10001)
                binds.append(str(source)+':'+target+':ro');expected_mounts.add(('bind',str(source),target,False))
            tree={'source':str(root/'bind0'),'target':'/run/db','readOnly':True,'uid':10001,'gid':10001,
                'directoryMode':0o500,'fileName':'OUF_SEM_DB_PASSWORD','fileMode':0o400,'maxBytes':1024,'sha256':'b'*64}
            env=list(image_data['Config']['Env'])+['OUF_SCHEMA_GOV_ENABLED=false','OUF_DISCOVERY_WORKER_ENABLED=false',
                'SPRING_CONFIG_IMPORT=configtree:/run/db/']
            request={'Image':image,'User':'10001:10001','WorkingDir':'/','Env':env,'Entrypoint':ENTRY,'Cmd':command,
                'HostConfig':{'Mounts':[],'Binds':binds,'NetworkMode':primary,'ReadonlyRootfs':True,
                    'RestartPolicy':{'Name':'no','MaximumRetryCount':0},'CapDrop':['ALL'],
                    'SecurityOpt':['no-new-privileges:true'],'OomKillDisable':False},
                'NetworkingConfig':{'EndpointsConfig':{primary:{'NetworkID':nid,'Aliases':['fixture-registry'],
                    'IPAMConfig':{'IPv4Address':address},'MacAddress':'02:42:ab:cd:01:07'}}}}
            profile=FileOnlyProfile(request,tree)
            for name in ('journal','evidence','before'):(root/name).mkdir(mode=0o700)
            journal=Journal(root/'journal');initial=Transition.initial_file_only('1'*64,digest(request),'2'*64,'3'*64,profile)
            journal.initialize(initial);transition=Transition(journal,initial['contextHash'],execution_profile=profile)
            store=NativeEvidenceStore(root/'evidence');before=NativeEvidenceStore(root/'before')
            original=engine.request;calls=[]
            def traced(method,path,body=None):
                calls.append((method,path));return original(method,path,body)
            engine.request=traced
            def finish(phase,intent,evidence):
                row=transition.read();transition.reconcile(phase,digest(intent),'APPLIED',digest(evidence),row['version'])
            def begin(phase,intent):
                row=transition.read();transition.begin(phase,digest(intent),'1'*64,row['version'])
            with transition.invocation():
                for phase in PHASES[:4]:
                    intent={'syntheticPredecessorBoundary':phase};begin(phase,intent);finish(phase,intent,{'synthetic':phase})
                begin('CREATE_REPLACEMENT',request)
                adapter=CreationAdapter(engine,transition,request,store);adapter.apply(request)
                outcome,created=adapter.observe(request);self.assertEqual(outcome,'APPLIED')
                self.assertIsNone(created['HostConfig'].get('Mounts'))
                self.assertEqual(created['HostConfig']['Binds'],binds)
                self.assertEqual({(m['Type'],m['Source'],m['Destination'],m['RW']) for m in created['Mounts']},expected_mounts)
                cid=created['Id'];self.addCleanup(lambda:subprocess.run([binary,'rm','-f',cid],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20))
                mutations_before=sum(method=='POST' for method,path in calls)
                self.assertEqual(adapter.observe(request)[0],'APPLIED')
                self.assertEqual(sum(method=='POST' for method,path in calls),mutations_before)
                # A successor private journal addresses the exact existing
                # created container by preserving the original context. Its
                # reconciliation must issue GETs only, even after a lost ACK.
                retained=journal.record.read_bytes();seed=transition.read()
                (root/'successor-journal').mkdir(mode=0o700)
                successor_journal=Journal(root/'successor-journal');successor_journal.initialize(seed)
                successor=Transition(successor_journal,transition.context,execution_profile=profile)
                observed=CreationAdapter(engine,successor,request,store).observe(request)
                self.assertEqual(observed[0],'APPLIED');self.assertEqual(observed[1]['Id'],cid)
                self.assertEqual(sum(method=='POST' for method,path in calls),mutations_before)
                self.assertEqual(journal.record.read_bytes(),retained);self.assertEqual(successor.read(),seed)
                finish('CREATE_REPLACEMENT',request,created)
                process=GatedProcessObservation(request);points=[]
                stage=GatedStageAdapter(engine,transition,request,store,process,points.append)
                stage_intent={'creationRequestHash':digest(request),'priorEvidencePhase':'CREATE_REPLACEMENT'}
                begin('STAGE_PAUSED_REPLACEMENT',stage_intent);stage.apply(stage_intent)
                outcome,paused=stage.observe(stage_intent);self.assertEqual(outcome,'APPLIED')
                self.assertEqual(process.observe(paused['State']['Pid'])['processKind'],'GATE_WAITING')
                # Independently known fixture policy, checked against actual
                # runc/OCI layout; never compile approval policy from this OCI.
                pid=paused['State']['Pid'];merged=Path(host['DockerRootDir'])/'rootfs'/'overlayfs'/cid
                self.assertEqual((merged.stat().st_dev,merged.stat().st_ino),
                    (Path('/proc/'+str(pid)+'/root').stat().st_dev,Path('/proc/'+str(pid)+'/root').stat().st_ino))
                runc=str(Path(binary).parent/'runc')
                state_command=subprocess.run([runc,'--root','/run/docker/runtime-runc/moby','state',cid],
                    stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
                self.assertEqual(state_command.returncode,0,state_command.stderr[-1000:].decode('utf-8','replace'))
                state=json.loads(state_command.stdout)
                self.assertEqual((state['id'],state['pid'],state['status']),(cid,pid,'paused'))
                self.assertEqual(state['bundle'],'/run/containerd/io.containerd.runtime.v2.task/moby/'+cid)
                oci=json.loads((Path(state['bundle'])/'config.json').read_bytes())
                self.assertEqual(oci['process']['user']['uid'],10001);self.assertEqual(oci['process']['user']['gid'],10001)
                self.assertTrue(oci['root']['readonly']);self.assertTrue(oci['process']['noNewPrivileges'])
                self.assertTrue(all(not values for values in oci['process']['capabilities'].values()))
                mounted={m['destination']:m for m in oci['mounts']}
                for source,target,readonly in ((s,t,True)for _,s,t,_ in expected_mounts):
                    self.assertEqual(mounted[target]['source'],source);self.assertIn('ro',mounted[target]['options'])
                finish('STAGE_PAUSED_REPLACEMENT',stage_intent,paused)
                for phase in ('ATTEST_NEW_OCI_PEER','ADMIT_MIGRATION'):
                    intent={'syntheticNonDockerBoundary':phase};begin(phase,intent);finish(phase,intent,{'synthetic':phase})
                release=GatedReleaseAdapter(engine,transition,request,store,before,process,points.append)
                release_intent={'creationRequestHash':digest(request),'priorEvidencePhase':'STAGE_PAUSED_REPLACEMENT','preApplicationGateProfile':GATE_PROFILE}
                begin('START_REPLACEMENT',release_intent);release.apply(release_intent)
                deadline=time.monotonic()+5
                while True:
                    outcome,released=release.observe(release_intent)
                    if outcome=='APPLIED':break
                    self.assertLess(time.monotonic(),deadline);time.sleep(.02)
                finish('START_REPLACEMENT',release_intent,released)
                self.assertEqual(sum(path.endswith('/kill?signal=SIGUSR1') for method,path in calls),1)
                self.assertEqual(sum(path.endswith('/unpause') for method,path in calls),1)
            deadline=time.monotonic()+5
            while True:
                client=http.client.HTTPConnection(address,8080,timeout=2)
                try:
                    client.request('GET','/actuator/health');response=client.getresponse()
                    self.assertEqual(response.status,200);self.assertEqual(json.loads(response.read(1024)),{'status':'UP'});break
                except OSError:
                    self.assertLess(time.monotonic(),deadline);time.sleep(.02)
                finally:client.close()
            owner=object.__new__(CohortContainers);owner.engine=engine
            row={'name':Engine.name(transition),'creationRequest':request,'oldRuntimeBinding':{'containerId':'f'*64},
                'oldMounts':[{'Type':t,'Source':s,'Destination':d,'RW':rw} for t,s,d,rw in expected_mounts],
                'restoreRestartPolicy':{'Name':'unless-stopped','MaximumRetryCount':0}}
            running=owner.running(row);self.assertEqual(running['Id'],cid)
            self.assertEqual(running['NetworkSettings']['Networks'][primary]['IPAddress'],address)
            self.assertEqual(running['NetworkSettings']['Networks'][primary]['MacAddress'],'02:42:ab:cd:01:07')
            status,_=engine.request('POST','/v1.44/containers/'+cid+'/update',{'RestartPolicy':row['restoreRestartPolicy']});self.assertEqual(status,200)
            status,updated=engine.request('GET','/v1.44/containers/'+cid+'/json');self.assertEqual(status,200)
            self.assertEqual(updated['HostConfig']['RestartPolicy'],row['restoreRestartPolicy'])
            self.assertEqual(updated['State']['Pid'],running['State']['Pid'])
            self.assertEqual(owner.running(row,True)['Id'],cid)
            secondary,secondary_id=networks[1]
            status,_=engine.request('POST','/v1.44/networks/'+secondary_id+'/connect',{'Container':cid,'EndpointConfig':{'Aliases':['fixture-secondary']}});self.assertEqual(status,200)
            status,connected=engine.request('GET','/v1.44/containers/'+cid+'/json');self.assertEqual(set(connected['NetworkSettings']['Networks']),{primary,secondary})
            status,_=engine.request('POST','/v1.44/networks/'+secondary_id+'/disconnect',{'Container':cid,'Force':False});self.assertEqual(status,200)
            status,_=engine.request('POST','/v1.44/containers/'+cid+'/stop?t=2');self.assertEqual(status,204)
            status,_=engine.request('POST','/v1.44/containers/'+cid+'/rename?name=ouf-contract-retired-'+suffix);self.assertEqual(status,204)
            status,retired=engine.request('GET','/v1.44/containers/'+cid+'/json');self.assertEqual(status,200)
            self.assertFalse(retired['State']['Running']);self.assertEqual(retired['State']['Pid'],0)
            print('DOCKER_CONTRACT_OPERATIONS='+json.dumps(sorted({path.split('?')[0].rsplit('/',1)[-1] for method,path in calls if method=='POST'})),flush=True)

if __name__=='__main__':unittest.main()
