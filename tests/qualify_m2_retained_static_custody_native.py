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


class NativeStaticCustody(unittest.TestCase):
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
        for role in sorted(m.RETAINED):
            mount_args=[]
            for mount in cls.mount_layout[role]:
                mount_args+=['--mount','type=bind,src='+mount['Source']+',dst='+mount['Destination']+(',readonly' if not mount['RW'] else '')]
            cid=command('run','-d','--name','ouf-'+('gateway-operational-owner' if role=='gateway-owner' else role),
                '--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',
                '--memory','16m','--pids-limit','8',*mount_args,tag)
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

    def test_a_actual_twenty_five_readonly_and_live_sqlite_writer_static_input_has_zero_engine_gets(self):
        for path in self.auth.values():rotate(path)
        stopped=threading.Event();written=threading.Event();failures=[];count=[]
        def writer():
            try:
                db=sqlite3.connect(self.database)
                try:
                    while not stopped.is_set():
                        db.execute('update fixture set value=value+1');db.commit();count.append(1);written.set()
                        stopped.wait(.005)
                finally:db.close()
            except Exception as error:failures.append(type(error).__name__);written.set()
        thread=threading.Thread(target=writer);thread.start()
        try:
            self.assertTrue(written.wait(5));self.assertFalse(failures)
            c=static.StaticCustody(self.root/'static-a');result=static.collect(c)
        finally:stopped.set();thread.join(5)
        self.assertFalse(thread.is_alive());self.assertFalse(failures);self.assertTrue(count)
        self.assertEqual(result['classifiedMounts'],{'readonly':25,'mutable':4,'tokens':7,'stores':1,'staticRegularMounts':17,'nodes':33})
        self.assertEqual(result['counts']['engineGets'],0);self.assertEqual(result['counts']['readonlyRegularFilesHashed'],13)
        self.assertEqual(result['liveTokenAndOperationalStoreContentBytesRead'],0)
        self.assertFalse(result['liveMembersObservedOrAdmitted']);self.assertFalse(result['targetApplyAuthorized'])
        self.assertFalse(result['currentContainerConfigurationFreshlyObserved'])
        self.assertEqual(set(c.hashes),{str(p) for p in self.keys.values()})
        for path in self.auth.values():
            self.assertEqual((path/'token').stat().st_gid,10001);self.assertEqual((path/'token').stat().st_mode&0o777,0o440)

    def test_b_actual_current_metadata_witness_is_stable_across_token_rotation_and_database_writes(self):
        first=self.observer.observe()
        for path in self.auth.values():rotate(path)
        db=sqlite3.connect(self.database);db.execute('update fixture set value=value+1');db.commit();db.close()
        second=self.observer.observe()
        self.assertEqual(first,second);self.assertEqual(second['directRetainedEngineGets'],20)
        self.assertTrue(second['currentRetainedStaticMetadataMatchesCapturedCandidate'])
        self.assertTrue(second['liveMountRootsMatchCapturedCustody'])
        self.assertFalse(second['liveMembersObservedOrAdmitted']);self.assertEqual(second['mountedFileContentBytesRead'],0)
        self.assertFalse(second['completePrivateCustodyProven']);self.assertFalse(second['targetApplyAuthorized'])

    def test_c_actual_static_file_custody_change_is_not_bypassed(self):
        path=self.keys['gateway-key'];path.chmod(0o400)
        c=static.StaticCustody(self.root/'static-c')
        with self.assertRaises((ValueError,OSError)):static.collect(c)
        self.assertFalse(c.hashes);self.assertFalse((c.scope/'static-custody.private.json').exists())
        self.assertEqual(c.counts['engineGets'],0)
        with self.assertRaises((ValueError,OSError)):self.observer.observe()

    def test_z_actual_restarted_gateway_process_denies_host_input_before_static_read(self):
        self.command('restart',self.seed['observations'][self.aliases['gateway-owner']]['Id'])
        c=static.StaticCustody(self.root/'static-z')
        with self.assertRaises((ValueError,OSError)):static.collect(c)
        self.assertFalse(c.hashes);self.assertEqual(c.counts['engineGets'],0)


if __name__=='__main__':unittest.main()
