"""Actual ten containers, Docker29 socket, process pins, mount metadata/FIFO/socket.

Disposable scratch pause processes, not OUF applications or a target admission.
"""
import copy, json, os, shutil, socket, stat, struct, subprocess, sys, unittest
from unittest.mock import Mock,patch
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path[:0] = [str(ROOT), str(ROOT/'tests')]
from tools.m2_discovery_installation_profile import retained_mount_role_correction as m
from tools.m2_discovery_installation_profile import retained_readonly_hashes as h
import test_m2_discovery_selected_runtime # retained dependency import setup
from tools.m2_discovery_installation_profile import retained_mount_intake as intake
from tools.m2_discovery_installation_profile import current_retained_mounts as current
import test_m2_retained_mount_capture as fixture
import test_m2_retained_mount_role_correction as correction
from tools.m2_discovery_installation_profile import retained_mount_capture as old


class NativeReadonlyHashes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true':
            raise AssertionError('DISPOSABLE_HOSTED_NATIVE_RETAINED_CAPTURE_ONLY')
        cls.case = fixture.RetainedMetadata(); cls.addClassCleanup(cls.case.doCleanups)
        cls.initial, cls.args, cls.seed, cls.root, cls.mounted, _, _ = cls.case.prepared()
        os.chown(cls.mounted/'credential',0,10001);(cls.mounted/'credential').chmod(0o440)
        for role,row in cls.seed['observations'].items():
            row['Name']='/ouf-'+('gateway-operational-owner' if role=='gateway-owner' else role)
            if role=='semantic':row['Name']='/ouf-semantic-cutover-'+'a'*64
        endpoint = socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); endpoint.bind(str(cls.mounted/'socket'))
        cls.addClassCleanup(endpoint.close)
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
            cid = command('run','-d','--name','ouf-'+('gateway-operational-owner' if role=='gateway-owner' else role),'--network','none','--read-only','--cap-drop','ALL',
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
        cls.aliases = correction.alias_fixture(cls.seed)
        cls.args['seed_path'].write_bytes(m.encoded(cls.seed)); cls.args['seed_hash'] = m.digest(cls.seed)
        cls.args.update(engine_factory=m.RetainedEngine,pin=m.process_pin,boot_path=Path('/proc/sys/kernel/random/boot_id'))
        try:
            old.collect(cls.initial,**cls.args)
        except old.Stop as failure:
            assert str(failure)=='EXACT_UNADMITTED_THIRTEEN_PEER_SEED_REQUIRED'
        else: raise AssertionError('FROZEN_REAL_SCHEMA_REGRESSION_REQUIRED')
        assert cls.initial.counts['engineGets']==0
        cls.initial.put('result.json',correction.FAILURE)
        cls.args.update(predecessor_root=cls.initial.scope,roster=correction.roster_for(cls.seed,cls.aliases))

        captured=m.RetainedCapture(cls.root/'successful-correction')
        result=m.collect(captured,**cls.args);captured.put('result.json',result)
        candidate=json.loads((captured.scope/'retained-mounts.private.json').read_bytes())
        bindings={'candidate_hash':m.digest(candidate),'result_hash':m.digest(result),
            'seed_hash':m.digest(cls.seed),'roster':cls.args['roster']}
        common=dict(zip(intake.COMMON,('a'*64,'b'*64,'c'*64,'d'*64)))
        proposal=intake.runtime_proposal(candidate,result,cls.seed,common,**bindings)
        selected={'candidatePath':str(captured.scope/'retained-mounts.private.json'),
            'resultPath':str(captured.scope/'result.json'),'seedPath':str(cls.args['seed_path']),
            'candidateHash':bindings['candidate_hash'],'resultHash':bindings['result_hash'],
            'seedHash':bindings['seed_hash'],'failedScope':str(cls.initial.scope)}
        for name,value in {'CASE':selected,'ROSTER':cls.args['roster']}.items():
            context=patch.object(h,name,value);context.start();cls.addClassCleanup(context.stop)

    def test_a_actual_engine_and_root_group_readonly_file_hash_only_no_special_content(self):
        c=h.ReadonlyHashPreparation(self.root/'hashes-a');result=h.collect(c)
        self.assertEqual(result['preparationDirectEngineGets'],20)
        self.assertEqual(result['counts']['readonlyRegularFilesHashed'],1)
        self.assertEqual(result['counts']['specialSources'],20)
        private=json.loads((c.scope/'readonly-content-hashes.private.json').read_bytes())
        file=private['files'][str(self.mounted/'credential')]
        import hashlib
        self.assertEqual(file['sha256'],hashlib.sha256(b'NEVER_READ_MOUNTED_FILE_CONTENT').hexdigest())
        self.assertEqual(file['metadata'][3:5],[0,10001]);self.assertEqual(file['metadata'][2]&0o777,0o440)
        self.assertTrue(result['credentialOrKeyFilesMayHaveBeenHashed'])
        self.assertFalse(result['rawValuesOrIndividualFileHashesPrinted'])
        self.assertFalse(result['completePrivateCustodyProven']);self.assertFalse(result['targetApplyAuthorized'])

    def test_b_native_mutable_content_changes_are_not_hashed(self):
        (self.root/'mutable/private-data').write_text('MUTABLE_UNREAD')
        (self.root/'mutable/extra').write_text('MUTABLE_UNREAD')
        c=h.ReadonlyHashPreparation(self.root/'hashes-b');result=h.collect(c)
        self.assertEqual(result['counts']['readonlyRegularFilesHashed'],1)
        self.assertFalse(result['mutableContentsObserved'])

    def test_c_native_content_race_does_not_publish_candidate(self):
        c=h.ReadonlyHashPreparation(self.root/'hashes-c');original=os.read;inode=(self.mounted/'credential').stat().st_ino
        changed=[]
        def mutate(fd,amount):
            raw=original(fd,amount)
            if os.fstat(fd).st_ino==inode and not changed:
                changed.append(True);(self.mounted/'credential').write_bytes(b'X'*len(raw))
            return raw
        with patch.object(os,'read',side_effect=mutate),self.assertRaisesRegex(ValueError,'CHANGED_DURING_HASH_READ'):h.collect(c)
        self.assertFalse((c.scope/'readonly-content-hashes.private.json').exists())

    def test_z_restarted_native_process_denies_before_engine_or_hashing(self):
        self.command('restart',self.seed['observations'][self.aliases['onboarding']]['Id'])
        c=h.ReadonlyHashPreparation(self.root/'hashes-z')
        with patch.object(h,'RetainedEngine') as engine,self.assertRaises((ValueError,OSError)):h.collect(c)
        engine.assert_not_called();self.assertFalse(c.hashes)


if __name__=='__main__':unittest.main()
