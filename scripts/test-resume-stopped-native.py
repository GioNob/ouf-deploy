"""Actual Docker metadata creation with sealed empty adapter; no target acceptance."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
import sys
ROOT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('create',ROOT/'resume-provider-v2-stopped.py')
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
"""Real isolated dockerd SIGHUP and unchanged running fixture; root CI only."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parent/'registration'
spec=importlib.util.spec_from_file_location('registration',ROOT/'register-provider-v2-runtime.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class NativeCreationTest(unittest.TestCase):
    def test_real_daemon_reload_empty_adapter_and_running_fixture_preserved(self):
        self.assertEqual(os.geteuid(),0)
        root=Path(tempfile.mkdtemp(prefix='ouf-native-runtime-',dir='/root'));root.chmod(0o700)
        self.addCleanup(shutil.rmtree,root)
        package=root/'package';package.mkdir(mode=0o700);shutil.copytree(ROOT/'source',package/'source')
        for p in (package/'source').rglob('*'):p.chmod(0o700 if p.is_dir() else 0o600)
        for n in ('sources.json',m.SELF):shutil.copyfile(ROOT/n,package/n);(package/n).chmod(0o600)
        daemon_file=root/'daemon.json';wrapper=root/'runtime';socket='unix://'+str(root/'docker.sock')
        guard=root/'guard.json';lock=root/'guard.lock';lock.touch(mode=0o600)
        guard.write_bytes(m.encoded({'lockFile':str(lock)}));guard.chmod(0o600)
        bindings={name:(str(Path(shutil.which(tool)).resolve()),m.sha(Path(shutil.which(tool)).resolve().read_bytes()))
            for name,tool in {'python':'python3','docker':'docker','runc':'runc'}.items()}
        daemon_path=shutil.which('dockerd');self.assertTrue(daemon_path)
        # A non-default explicit config path must exist at daemon startup.
        # Remove only this isolated fixture file after readiness to model the target's absent default config.
        daemon_file.write_bytes(b'{}\n');daemon_file.chmod(0o600)
        log=(root/'daemon.log').open('wb');self.addCleanup(log.close)
        daemon=subprocess.Popen([daemon_path,'--config-file',str(daemon_file),'--data-root',str(root/'data'),
            '--exec-root',str(root/'exec'),'--pidfile',str(root/'pid'),'-H',socket,'--bridge','none',
            '--iptables=false','--ip6tables=false',*(['--feature','containerd-snapshotter=true'] if os.environ.get('OUF_TEST_CONTAINERD')=='1' else ['--storage-driver','vfs'])],stdout=log,stderr=log)
        def stop():
            if daemon.poll() is None:
                daemon.terminate()
                try:daemon.wait(timeout=20)
                except subprocess.TimeoutExpired:daemon.kill();daemon.wait(timeout=5)
        self.addCleanup(stop)
        def docker(*argv,timeout=30):
            return subprocess.run([bindings['docker'][0],'-H',socket,*argv],capture_output=True,timeout=timeout)
        deadline=time.monotonic()+60
        while docker('info').returncode:
            if daemon.poll() is not None:
                self.fail('isolated dockerd startup: '+(root/'daemon.log').read_text()[-8000:])
            self.assertLess(time.monotonic(),deadline,'isolated dockerd readiness timeout');time.sleep(.25)
        daemon_file.unlink()
        p=docker('pull','busybox:1.37.0',timeout=120);self.assertEqual(p.returncode,0,'fixture image unavailable')
        p=docker('run','-d','--network','none','--name','existing-fixture','busybox:1.37.0','sleep','600')
        self.assertEqual(p.returncode,0,'running isolated fixture unavailable')
        self.addCleanup(lambda:docker('rm','-f','existing-fixture'))
        with patch.object(m,'DAEMON',daemon_file),patch.object(m,'WRAPPER',wrapper),patch.object(m,'SOCKET',socket),\
             patch.object(m,'GUARD',guard),patch.object(m,'GUARD_HASH',m.sha(guard.read_bytes())),\
             patch.object(m,'BINDS',bindings),patch.object(m,'daemon_pid',return_value=daemon.pid),\
             patch.object(m,'preflight',return_value={'simulatedGuardCustody':True}):
            report=m.operate(package,m.sha((package/'sources.json').read_bytes()))
            self.assertTrue(report['daemonPidUnchanged']);self.assertTrue(report['existingContainerStatesUnchanged'])
            self.assertEqual(report['existingContainerCount'],1);self.assertEqual(report['candidateCount'],0)
            p=subprocess.run([str(wrapper),'--version'],capture_output=True,timeout=10)
            self.assertEqual(p.returncode,0);self.assertIn(b'runc version',p.stdout)
            p=subprocess.run([str(wrapper),'--root','/run/docker/unused','create','--bundle',str(root/'unused'),'b'*64],capture_output=True,timeout=10)
            self.assertEqual(p.returncode,1);self.assertIn(b'UNSTAGED_DOCKER_CANDIDATE',p.stderr)
            self.assertEqual(docker('inspect','--format','{{.State.Running}}','existing-fixture').stdout.strip(),b'true')
            self.assertIsNone(daemon.poll())
            nets={}
            for key,subnet,internal in [('backend','172.18.0.0/16',True),('internal','172.21.0.0/16',True),('egress','172.22.0.0/16',False)]:
                argv=['network','create','--subnet',subnet]
                if internal:argv.append('--internal')
                q=docker(*argv,'fixture-'+key);self.assertEqual(q.returncode,0)
                nets[key]=('fixture-'+key,q.stdout.decode().strip())
            # Stopped legacy metadata deliberately declares the same planned static address.
            q=docker('create','--name','legacy-stopped','--network',nets['internal'][1],'--ip','172.21.0.3','busybox:1.37.0','true')
            self.assertEqual(q.returncode,0)
            original=c.snapshot(m)
            imgid=docker('image','inspect','--format','{{.Id}}','busybox:1.37.0').stdout.decode().strip()
            img=c.image(m,imgid);startup={k:img['Config'].get(k) for k in ('Entrypoint','Cmd','WorkingDir','User')}
            cfg=root/'public-config';cfg.write_bytes(b'fixture\n');cfg.chmod(0o600)
            specs=[]
            for role,uid,attachments in [('adapter',10006,[('internal','172.21.0.3'),('egress','172.22.0.3')]),('southbound',636,[('backend','172.18.0.14'),('internal','172.21.0.2'),('egress','172.22.0.2')])]:
                specs.append({'role':role,'name':'fixture-'+role,'uid':uid,'gid':uid,'user':f'{uid}:{uid}',
                    'imageId':imgid,'startup':startup,'command':['true'],'runtimeName':m.NAME,
                    'memoryBytes':268435456,'pidsLimit':128,'readOnlyRoot':role=='adapter',
                    'dns':['46.38.252.230','46.38.225.230'],'envFile':None,'environmentNames':[],
                    'mounts':[c.mount(cfg,'/fixture-config',0,0,c.sha(cfg.read_bytes()))],
                    'networks':[{'key':k,'ip':ip} for k,ip in attachments]})
            # Exercise real export/import and manifest-to-config resolution on each store.
            import gzip,hashlib,json,tarfile
            saved=root/'fixture.tar.gz'
            with saved.open('wb') as target,gzip.GzipFile(fileobj=target,mode='wb') as compressed:
                q=docker('image','save',imgid,timeout=30);self.assertEqual(q.returncode,0);compressed.write(q.stdout)
            configs=[]
            with tarfile.open(saved,'r:gz') as archive:
                for item in archive:
                    if item.isfile() and item.size<=1048576:
                        raw=archive.extractfile(item).read()
                        if raw.lstrip().startswith(b'{'):
                            doc=json.loads(raw)
                            if 'rootfs' in doc and 'architecture' in doc:configs.append('sha256:'+hashlib.sha256(raw).hexdigest())
            self.assertEqual(len(configs),1)
            proof=c.archive_identity(saved,configs[0])
            self.assertNotEqual(proof['manifestDigest'],proof['configDigest'])
            c.load_archive(m,saved,root,'fixture')
            specs=[c.resolved_image(m,x,proof) for x in specs]
            self.assertTrue(all(x['configDigest']==configs[0] for x in specs))
            with patch.object(c,'NETWORKS',nets):
                rows=c.core_create(m,specs,root,'fixture-transaction')
                self.assertEqual(len(rows),2)
                self.assertTrue(all(x['neverStarted'] for x in rows))
                after=c.snapshot(m)
                self.assertEqual({k:after[k] for k in original},original)
                self.assertEqual(len(after),len(original)+2)
                for key in nets:
                    self.assertFalse(c.network(m,key)['Containers'])
                # The real empty adapter must reject an attempted start before any app runs.
                q=docker('start','fixture-adapter');self.assertNotEqual(q.returncode,0)
                q=docker('inspect','--format','{{.State.StartedAt}}','fixture-adapter')
                self.assertTrue(q.stdout.decode().startswith('0001-'))
            self.assertIsNone(daemon.poll())

if __name__=='__main__':unittest.main()
