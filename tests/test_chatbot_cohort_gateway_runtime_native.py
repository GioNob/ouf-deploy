"""Real Docker two-network replacement and child netns readback in disposable CI.

The nonroot scratch image serves static test admin JSON from a CI-built ELF. This tests native creation/custody and
journal reconciliation, not APISIX application semantics or a target acceptance.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import time
import unittest

import test_chatbot_cohort_gateway as fixture
from tools.chatbot_file_cohort import gateway_runtime as r
from tools.semantic_lease_recovery.recovery_journal import Journal
from engine_creation import Engine


@unittest.skipUnless(os.environ.get('OUF_NATIVE_POSTGRES')=='1','explicit disposable Docker CI only')
class NativeGatewayRuntime(unittest.TestCase):
    def test_actual_two_networks_same_image_private_config_namespace_and_no_second_replacement(self):
        self.assertEqual(os.geteuid(),0)
        f=fixture.crypto.SignedCutover();f.setUp();self.addCleanup(f.doCleanups)
        binary=Path(shutil.which('docker')).resolve()
        def docker(*args):
            reply=subprocess.run([str(binary),*args],stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,timeout=90)
            self.assertEqual(reply.returncode,0,'fixture Docker '+args[0]+' failed: '+reply.stderr[:2048].decode('utf-8','replace'))
            return reply.stdout
        path='/var/run/docker.sock';info=os.stat(path,follow_symlinks=False)
        engine=Engine(path,(info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)))
        root=f.root/'native-gateway';root.mkdir(mode=0o700)
        build=root/'build';build.mkdir(mode=0o700)
        (build/'passwd').write_text('apisix:x:10001:10001:fixture:/:/bin/false\n')
        retained={'id':'retained','uri':'/retained','methods':['GET']}
        body=json.dumps({'total':1,'list':[{'value':retained}]},separators=(',',':'))
        response='HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: '+str(len(body.encode()))+'\r\n\r\n'+body
        # Alpine's base busybox does not guarantee the httpd applet. Compile the
        # deliberately tiny server fixture so early process exit cannot turn
        # the subsequent two-network observation into an unrelated failure.
        server_source=r'''#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
static const char response[]=RESPONSE;
int main(void) {
    signal(SIGPIPE,SIG_IGN);
    int server=socket(AF_INET,SOCK_STREAM,0);if(server<0)return 2;
    int one=1;if(setsockopt(server,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one)))return 3;
    struct sockaddr_in a={0};a.sin_family=AF_INET;a.sin_addr.s_addr=htonl(INADDR_ANY);a.sin_port=htons(9180);
    if(bind(server,(struct sockaddr*)&a,sizeof(a))||listen(server,8))return 4;
    for(;;) {
        int c=accept(server,0,0);if(c<0){if(errno==EINTR)continue;return 5;}
        struct timeval timeout={3,0};setsockopt(c,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));setsockopt(c,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
        char input[4097]={0};size_t used=0;
        while(used<sizeof(input)-1&&!strstr(input,"\r\n\r\n")) {
            ssize_t n=read(c,input+used,sizeof(input)-1-used);if(n<=0)break;used+=(size_t)n;
        }
        if(strstr(input,"\r\n\r\n")&&strncmp(input,"GET /apisix/admin/routes HTTP/1.",32)==0) {
            size_t sent=0;while(sent<sizeof(response)-1){ssize_t n=write(c,response+sent,sizeof(response)-1-sent);if(n<=0)break;sent+=(size_t)n;}
        }
        close(c);
    }
}
'''.replace('RESPONSE',json.dumps(response))
        source=build/'server.c';source.write_text(server_source)
        compiler=shutil.which('cc');self.assertIsNotNone(compiler,'native CI C compiler is required')
        compiled=subprocess.run([compiler,'-static','-O2','-Wall','-Wextra','-Werror',str(source),'-o',str(build/'server')],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
        self.assertEqual(compiled.returncode,0,compiled.stderr[:2048].decode('utf-8','replace'))
        (build/'server').chmod(0o755)
        (build/'Dockerfile').write_text('FROM scratch\nCOPY server /server\n'
            'COPY passwd /etc/passwd\nUSER apisix\nENTRYPOINT ["/server"]\n')
        tag='ouf-native-gateway:'+hashlib.sha256(str(root).encode()).hexdigest()[:24]
        docker('build','--pull=false','-t',tag,str(build))
        image=docker('image','inspect','--format','{{.Id}}',tag).decode().strip()
        self.addCleanup(lambda:subprocess.run([str(binary),'image','rm','-f',image],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20))
        for network in ('ouf-backend','ouf-gateway-control'):
            nid=docker('network','create','--label','ouf.fixture='+f.root.name,network).decode().strip()
            self.addCleanup(lambda n=nid:subprocess.run([str(binary),'network','rm',n],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20))
        original=root/'original.yaml';original.write_text('nginx_config:\n  envs:\n  - RETAINED_KEY\ndeployment:\n  admin:\n    admin_key:\n      - name: admin\n        key: 0123456789abcdef0123456789abcdef\n        role: admin\n');original.chmod(0o644)
        updated=root/'updated.yaml';updated.write_bytes(fixture.preparation.expose_environment(original.read_bytes(),'PROPOSAL_KEY'));updated.chmod(0o444)
        _,old_config=fixture.g.private_config(original);_,new_config=fixture.g.private_config(updated)
        cid=docker('run','-d','--name','ouf-apisix','--restart','unless-stopped','--network','ouf-backend',
            '--network-alias','ouf-apisix','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',
            '--mount','type=bind,src='+str(original)+',dst=/usr/local/apisix/conf/config.yaml,readonly',
            '--env','RETAINED_KEY='+'1'*64,image).decode().strip()
        self.addCleanup(lambda:subprocess.run([str(binary),'rm','-f',cid],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20))
        code,started=engine.request('GET','/v1.44/containers/'+cid+'/json')
        self.assertEqual(code,200)
        self.assertTrue(started['State']['Running'] and not started['State']['Restarting']
                        and started['State']['Pid']>1 and started['RestartCount']==0,
                        'fixture server did not remain in its first running generation: '+
                        json.dumps({k:started['State'].get(k) for k in ('Status','Running','Restarting','ExitCode','Error')})[:2048])
        docker('network','connect','--alias','ouf-apisix','ouf-gateway-control',cid)
        code,old=engine.request('GET','/v1.44/containers/'+cid+'/json');self.assertEqual(code,200)
        key,key_binding,_=fixture.preparation.stage_proposal_key(root)
        plan=r.compile_runtime(old,old_config,new_config,'PROPOSAL_KEY',key,key_binding['sha256'],'native-fixture')
        raw=json.loads(f.authority);raw['gatewayRuntimeInstallation']=r.runtime_scope(plan)
        f.authority=fixture.crypto.encoded(raw);f.approval['executionAuthorityHash']=fixture.crypto.sha(f.authority)
        f.write(f.mandate,fixture.crypto.encoded(f.approval));f.approved=fixture.crypto.sha(f.mandate.read_bytes())
        for role in f.grant['roles']:f.sign(role)
        action=fixture.g.AggregateAction(f.gate(),f.authority,f.expected['sourceClosureHash'])
        journal=root/'journal';journal.mkdir(mode=0o700)
        owner=r.GatewayRuntime(action,engine,plan,Journal(journal));owner.initialize()
        def remove_created():
            # Only the ID proved by this private creation journal can be removed.
            record=owner.record()
            if record['nextStep']>=4:
                exact=record['effects'][3]['evidence']['containerId']
                subprocess.run([str(binary),'rm','-f',exact],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20)
        self.addCleanup(remove_created)
        deadline=time.time()+40
        while True:
            try:receipt=owner.apply();break
            except r.CohortPaused as paused:
                self.assertLess(time.time(),deadline)
                time.sleep(min(5,max(0,paused.next_attempt_at-time.time())))
            except Exception as error:
                if str(error)=='APISIX_CANDIDATE_HOST_DRIFT':
                    # This is the synthetic scratch fixture only. Never emit
                    # Config/Env or credentials; expose exact HostConfig diff
                    # so no production guard is relaxed based on a guess.
                    record=owner.record();step=r.STEPS[record['nextStep']]
                    observed=owner.inspect(owner.plan['oldName'])
                    expected=copy.deepcopy(owner.plan['creationRequest']['HostConfig'])
                    if step=='restore_restart':expected['RestartPolicy']=owner.plan['originalRestartPolicy']
                    diff={k:{'expected':value,'actual':observed['HostConfig'].get(k)}
                          for k,value in expected.items() if observed['HostConfig'].get(k)!=value}
                    print('SYNTHETIC_APISIX_HOST_CONFIG_DIFF '+json.dumps({'step':step,'difference':diff},sort_keys=True)[:16384],flush=True)
                raise
        first=owner.record();actual=owner.generation()
        self.assertNotEqual(actual['Id'],cid);self.assertEqual(actual['Image'],old['Image'])
        self.assertEqual(set(actual['NetworkSettings']['Networks']),{'ouf-backend','ouf-gateway-control'})
        self.assertEqual(r.environment(actual['Config']['Env'])['PROPOSAL_KEY'],key)
        self.assertEqual(owner.transport().routes(),{'retained':retained})
        self.assertEqual(owner.apply(),receipt);self.assertEqual(owner.record(),first)
        self.assertEqual(owner.generation()['Id'],actual['Id'])
        self.assertFalse(owner.old(True)['State']['Running'])
        f.approval['state']='REVOKED';f.write(f.mandate,fixture.crypto.encoded(f.approval))
        with self.assertRaises(Exception):owner.apply()

if __name__=='__main__':unittest.main()
