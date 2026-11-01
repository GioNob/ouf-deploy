"""Actual ten containers, Docker29 socket, process pins, mount metadata/FIFO/socket.

Disposable scratch pause processes, not OUF applications or a target admission.
"""
import copy, json, os, shutil, socket, sqlite3, stat, struct, subprocess, sys, unittest, threading
from unittest.mock import Mock,patch
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path[:0] = [str(ROOT), str(ROOT/'tests'),str(ROOT/'tests/fixtures')]
from tools.m2_discovery_installation_profile import retained_mount_role_correction as m
from tools.m2_discovery_installation_profile import retained_readonly_hashes as h
from tools.m2_discovery_installation_profile import retained_hash_reconciliation as recon
import test_m2_discovery_selected_runtime # retained dependency import setup
from tools.m2_discovery_installation_profile import retained_mount_intake as intake
from tools.m2_discovery_installation_profile import current_retained_mounts as current
import test_m2_retained_mount_capture as fixture
import test_m2_retained_mount_role_correction as correction
from tools.m2_discovery_installation_profile import retained_mount_capture as old


from retained_lifecycle_layout import layout,rotate
from tools.m2_discovery_installation_profile import retained_static_custody as static
from tools.m2_discovery_installation_profile import retained_mount_lifecycle as life


from tools.m2_discovery_installation_profile import current_retained_static as current_static


class NativeStaticIntake(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true':
            raise AssertionError('DISPOSABLE_HOSTED_NATIVE_RETAINED_CAPTURE_ONLY')
        cls.case = fixture.RetainedMetadata(); cls.addClassCleanup(cls.case.doCleanups)
        cls.initial, cls.args, cls.seed, cls.root, cls.mounted, _, _ = cls.case.prepared()
        cls.mount_layout,cls.auth,cls.database,cls.keys=layout(cls.root,gid=10001)
        for role,row in cls.seed['observations'].items():
            row['Name']='/ouf-'+('gateway-operational-owner' if role=='gateway-owner' else role)
            if role=='semantic':row['Name']='/ouf-semantic-cutover-'+'a'*64
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
        image_roles=m.ROLES if getattr(cls,'fixture_per_role_images',False) else m.RETAINED
        for role in sorted(image_roles):
            role_tag=tag
            if getattr(cls,'fixture_per_role_images',False):
                role_build=cls.root/('image-build-'+role);role_build.mkdir(mode=0o700)
                (role_build/'Dockerfile').write_text('FROM '+tag+'\nLABEL ouf.fixture.role='+role+'\n')
                role_tag=tag+'-'+role;command('build','--network','none','-t',role_tag,str(role_build))
                cls.addClassCleanup(lambda role_tag=role_tag:command('image','rm','-f',role_tag))
            mount_args=[]
            for mount in cls.mount_layout.get(role,[]):
                mount_args+=['--mount','type=bind,src='+mount['Source']+',dst='+mount['Destination']+(',readonly' if not mount['RW'] else '')]
            cid=command('run','-d','--name','ouf-'+('gateway-operational-owner' if role=='gateway-owner' else role),
                '--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',
                '--memory','16m','--pids-limit','8',*mount_args,role_tag)
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

        cls.failed=h.ReadonlyHashPreparation(cls.root/'failed-hashes')
        rotate(cls.auth['gateway'])
        db=sqlite3.connect(cls.database);db.execute('update fixture set value=value+1');db.commit();db.close()
        try:h.collect(cls.failed)
        except h.Stop as error:assert str(error)=='READONLY_HASH_MOUNT_METADATA_DIFFERS_FROM_CAPTURE'
        else:raise AssertionError('REAL_PINNED_HASH_FAILURE_REQUIRED')
        assert cls.failed.counts['engineGets']==2 and cls.failed.counts['readonlyFileBytesHashed']==0
        failed={'schema':'ouf.retained-readonly-hash-preparation-result.v1','status':'STOP_RECONCILE',
            'reasonCode':'READONLY_HASH_MOUNT_METADATA_DIFFERS_FROM_CAPTURE','scopeConsumed':True,
            'counts':{k:cls.failed.counts[k] for k in h.PUBLIC_COUNTS},'automaticReplayAllowed':False,
            'runtimeAuthorityIssued':False,'targetApplyAuthorized':False}
        cls.failed.put('result.json',failed)
        for name,value in {'CASE':selected,'ROSTER':cls.args['roster'],'FAILED_SCOPE':cls.failed.scope,
            'FAILED_HASH':h.digest(failed)}.items():
            context=patch.object(recon,name,value);context.start();cls.addClassCleanup(context.stop)

        reconciler=recon.Reconciliation(cls.root/'reconciliation')
        receipt=recon.collect(reconciler);reconciler.put('result.json',receipt)
        record=json.loads((reconciler.scope/'reconciliation.private.json').read_bytes())
        newcase={**selected,'reconciliationScope':str(reconciler.scope),'reconciliationCandidateHash':static.digest(record),
            'reconciliationResultHash':static.digest(receipt),'failedHashScope':str(cls.failed.scope),
            'failedHashResultHash':static.digest(failed)}
        for name,value in {'CASE':newcase,'ROSTER':cls.args['roster']}.items():
            context=patch.object(static,name,value);context.start();cls.addClassCleanup(context.stop)
        cls.runtime=object.__new__(current.CurrentCohortRuntime);cls.runtime.inputs=proposal['runtimeInputs']
        cls.runtime.input_hash=intake.digest(cls.runtime.inputs);cls.runtime.guard=Mock()
        class Selected:
            def held(self,expected=None):return {'state':'READY','nextPhase':12,'version':42}
        cls.runtime.selected=Selected()
        for name,value in {'CANDIDATE':captured.scope/'retained-mounts.private.json','SEED':cls.args['seed_path'],
            'CANDIDATE_HASH':bindings['candidate_hash'],'RESULT_HASH':bindings['result_hash'],
            'SEED_HASH':bindings['seed_hash'],'ROSTER':bindings['roster']}.items():
            context=patch.object(current,name,value);context.start();cls.addClassCleanup(context.stop)
        cls.observer=current.CurrentRetainedMountMetadata(cls.runtime)
        cls.candidate=candidate

        captured_static=static.StaticCustody(cls.root/'captured-static')
        result=static.collect(captured_static);captured_static.put('result.json',result)
        record=json.loads((captured_static.scope/'static-custody.private.json').read_bytes())
        for name,value in {'CANDIDATE':captured_static.scope/'static-custody.private.json',
            'CANDIDATE_HASH':static.digest(record),'RESULT_HASH':static.digest(result),'CASE':newcase}.items():
            context=patch.object(current_static,name,value);context.start();cls.addClassCleanup(context.stop)
        cls.static_observer=current_static.CurrentRetainedStaticBytes(cls.observer)

    def test_a_actual_current_thirteen_files_match_captured_bytes_while_sqlite_writes_and_token_rotates(self):
        first=self.static_observer.observe()
        for path in self.auth.values():rotate(path)
        stopped=threading.Event();written=threading.Event();failures=[]
        def writer():
            try:
                db=sqlite3.connect(self.database)
                try:
                    while not stopped.is_set():
                        db.execute('update fixture set value=value+1');db.commit();written.set();stopped.wait(.005)
                finally:db.close()
            except Exception as error:failures.append(type(error).__name__);written.set()
        thread=threading.Thread(target=writer);thread.start()
        try:
            self.assertTrue(written.wait(5));second=self.static_observer.observe()
        finally:stopped.set();thread.join(5)
        self.assertFalse(thread.is_alive());self.assertFalse(failures);self.assertEqual(first,second)
        self.assertEqual(second['staticFileCount'],13);self.assertEqual(second['directEngineGets'],0)
        self.assertTrue(second['currentStaticFileBytesMatchCapturedCandidate']);self.assertFalse(second['newCaptureScopeCreated'])
        self.assertEqual(second['liveTokenAndOperationalStoreContentBytesRead'],0)
        self.assertFalse(second['liveMembersObservedOrAdmitted']);self.assertFalse(second['completePrivateCustodyProven'])
        self.assertFalse(second['expectedPermissionOrContentPolicyEstablished']);self.assertFalse(second['targetApplyAuthorized'])
        self.assertFalse(second['fullCohortProven']);self.assertEqual(self.observer.observe()['directRetainedEngineGets'],20)

    def test_b_actual_live_root_custody_change_is_not_a_static_byte_success(self):
        path=self.auth['gateway'];original=path.stat().st_mode&0o777;path.chmod(0o700)
        try:
            with self.assertRaises((ValueError,OSError)):self.static_observer.observe()
        finally:path.chmod(original)

    def test_c_actual_file_content_change_denies_current_byte_proof(self):
        path=self.keys['gateway-key'];path.write_bytes(b'CHANGED_STATIC_CONTENT')
        with self.assertRaises((ValueError,OSError)):self.static_observer.observe()

    def test_z_actual_restarted_gateway_denies_current_static_byte_observer(self):
        self.command('restart',self.seed['observations'][self.aliases['gateway-owner']]['Id'])
        with self.assertRaises((ValueError,OSError)):self.static_observer.observe()


if __name__=='__main__':unittest.main()
