"""Actual ten containers, Docker29 socket, process pins, mount metadata/FIFO.

Disposable scratch pause processes, not OUF applications or a target admission.
"""
import copy, os, shutil, socket, stat, struct, subprocess, sys, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path[:0] = [str(ROOT), str(ROOT/'tests')]
from tools.m2_discovery_installation_profile import retained_mount_capture as m
import test_m2_retained_mount_capture as fixture


class NativeRetainedMounts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true':
            raise AssertionError('DISPOSABLE_HOSTED_NATIVE_RETAINED_CAPTURE_ONLY')
        cls.case = fixture.RetainedMetadata(); cls.addClassCleanup(cls.case.doCleanups)
        cls.initial, cls.args, cls.seed, cls.root, cls.mounted, _, _ = cls.case.prepared()
        cls.docker = shutil.which('docker')
        if not cls.docker: raise AssertionError('ACTUAL_DOCKER_REQUIRED')
        def command(*args):
            return subprocess.run([cls.docker,*args],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,timeout=60,check=True).stdout.decode().strip()
        cls.command = staticmethod(command)
        assert command('version','--format','{{.Server.Version}}') == '29.8.1'
        build = cls.root/'build'; build.mkdir(mode=0o700)
        (build/'pause.c').write_text('#include <unistd.h>\nint main(void){for(;;)pause();}\n')
        subprocess.run([shutil.which('cc'),'-static','-O2','-Wall','-Wextra','-Werror',str(build/'pause.c'),'-o',str(build/'pause')],
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=True)
        (build/'Dockerfile').write_text('FROM scratch\nCOPY pause /pause\nUSER 10001:10001\nENTRYPOINT ["/pause"]\n')
        tag = 'ouf-retained-capture:'+cls.root.name
        command('build','--network','none','-t',tag,str(build))
        cls.addClassCleanup(lambda: command('image','rm','-f',tag))
        for role in sorted(m.RETAINED):
            cid = command('run','-d','--network','none','--read-only','--cap-drop','ALL',
                '--security-opt','no-new-privileges','--memory','16m','--pids-limit','8',
                '--mount','type=bind,src='+str(cls.mounted)+',dst=/run/input,readonly',
                '--mount','type=bind,src='+str(cls.root/'mutable')+',dst=/data',tag)
            cls.addClassCleanup(lambda cid=cid: command('rm','-f',cid))
            import json
            actual = json.loads(command('inspect',cid))[0]
            cls.seed['observations'][role] = actual
            cls.seed['processPins'][role] = m.process_pin(actual['State']['Pid'])
        path = Path('/var/run/docker.sock').resolve(); info = path.lstat()
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as channel:
            channel.connect(str(path)); peer = list(struct.unpack('3i',channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)))
        cls.seed['engineBinding'] = {'socketPath':str(path),
            'socketBinding':[info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)],'peerCredentials':peer}
        cls.seed['bootId'] = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        cls.seed['rootProcessPins'] = {'pid1':m.process_pin(1),'engine':m.process_pin(peer[0])}
        cls.args['seed_path'].write_bytes(m.encoded(cls.seed)); cls.args['seed_hash'] = m.digest(cls.seed)
        cls.args.update(engine_factory=m.RetainedEngine,pin=m.process_pin,boot_path=Path('/proc/sys/kernel/random/boot_id'))

    def capture(self, name): return m.RetainedCapture(self.root/name)

    def test_a_actual_ten_native_generations_and_twenty_gets_without_mount_file_reads(self):
        result = m.collect(self.capture('actual'),**self.args)
        self.assertEqual(result['counts']['engineGets'],20)
        self.assertEqual(result['counts']['mountFileContentBytesRead'],0)
        self.assertEqual(result['counts']['readonlyMounts'],10)
        self.assertEqual(result['counts']['mutableMounts'],10)
        self.assertEqual(result['counts']['specialSources'],10)
        self.assertFalse(result['completePrivateCustodyProven']); self.assertFalse(result['targetApplyAuthorized'])

    def test_b_native_file_custody_drift_does_not_use_unchanged_engine_config_as_custody(self):
        before = (self.mounted/'credential').stat().st_mode & 0o777
        self.addCleanup((self.mounted/'credential').chmod,before)
        class Changed(m.RetainedEngine):
            def get(engine,cid):
                actual = super().get(cid)
                if engine.c.counts['engineGets'] == 11: (self.mounted/'credential').chmod(0o400)
                return actual
        args = {**self.args,'engine_factory':Changed}; c = self.capture('changed-file')
        with self.assertRaisesRegex(ValueError,'SOURCE_CHANGED_DURING_CAPTURE'): m.collect(c,**args)
        self.assertFalse((c.scope/'retained-mounts.private.json').exists())

    def test_z_restarted_native_generation_blocks_before_get_without_repair(self):
        cid = self.seed['observations']['onboarding']['Id']; self.command('restart',cid)
        c = self.capture('changed-process')
        with self.assertRaisesRegex(ValueError,'PROCESS_GENERATION_CHANGED'): m.collect(c,**self.args)
        self.assertEqual(c.counts['engineGets'],0); self.assertFalse((c.scope/'retained-mounts.private.json').exists())


if __name__ == '__main__': unittest.main()
