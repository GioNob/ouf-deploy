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

ROOT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('registration',ROOT/'register-provider-v2-runtime.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class NativeRegistrationTest(unittest.TestCase):
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
        log=(root/'daemon.log').open('wb');self.addCleanup(log.close)
        daemon=subprocess.Popen([daemon_path,'--config-file',str(daemon_file),'--data-root',str(root/'data'),
            '--exec-root',str(root/'exec'),'--pidfile',str(root/'pid'),'-H',socket,'--bridge','none',
            '--iptables=false','--ip6tables=false','--storage-driver','vfs'],stdout=log,stderr=log)
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
            self.assertIsNone(daemon.poll(),'isolated dockerd stopped before fixture')
            self.assertLess(time.monotonic(),deadline,'isolated dockerd readiness timeout');time.sleep(.25)
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

if __name__=='__main__':unittest.main()
