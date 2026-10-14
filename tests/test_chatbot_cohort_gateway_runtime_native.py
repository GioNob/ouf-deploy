"""Real Docker two-network replacement and child netns readback in disposable CI.

The image serves static test admin JSON. This tests native creation/custody and
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
            return subprocess.run([str(binary),*args],check=True,stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE,timeout=90).stdout
        path='/var/run/docker.sock';info=os.stat(path,follow_symlinks=False)
        engine=Engine(path,(info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)))
        code,pg=engine.request('GET','/v1.44/containers/'+os.environ['OUF_POSTGRES_CONTAINER_ID']+'/json')
        self.assertEqual(code,200)
        root=f.root/'native-gateway';root.mkdir(mode=0o700)
        build=root/'build';build.mkdir(mode=0o700)
        (build/'passwd').write_text('apisix:x:10001:10001:fixture:/:/bin/false\n')
        www=build/'www'/'apisix'/'admin';www.mkdir(parents=True)
        retained={'id':'retained','uri':'/retained','methods':['GET']}
        (www/'routes').write_text(json.dumps({'total':1,'list':[{'value':retained}]}))
        base_tag='ouf-native-gateway-base:'+hashlib.sha256(str(root).encode()).hexdigest()[:24]
        docker('tag',pg['Image'],base_tag)
        self.addCleanup(lambda:subprocess.run([str(binary),'image','rm',base_tag],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20))
        (build/'Dockerfile').write_text('FROM '+base_tag+' AS base\nFROM scratch\n'
            'COPY --from=base /bin/busybox /bin/busybox\nCOPY --from=base /lib /lib\n'
            'COPY passwd /etc/passwd\nCOPY www /www\nUSER apisix\n'
            'ENTRYPOINT ["/bin/busybox","httpd","-f","-p","9180","-h","/www"]\n')
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
