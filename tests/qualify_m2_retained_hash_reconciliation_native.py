"""Actual ten containers, Docker29 socket, process pins, mount metadata/FIFO/socket.

Disposable scratch pause processes, not OUF applications or a target admission.
"""
import copy, json, os, shutil, socket, stat, struct, subprocess, sys, unittest
from unittest.mock import Mock,patch
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path[:0] = [str(ROOT), str(ROOT/'tests')]
from tools.m2_discovery_installation_profile import retained_mount_role_correction as m
from tools.m2_discovery_installation_profile import retained_readonly_hashes as h
from tools.m2_discovery_installation_profile import retained_hash_reconciliation as recon
import test_m2_discovery_selected_runtime # retained dependency import setup
from tools.m2_discovery_installation_profile import retained_mount_intake as intake
from tools.m2_discovery_installation_profile import current_retained_mounts as current
import test_m2_retained_mount_capture as fixture
import test_m2_retained_mount_role_correction as correction
from tools.m2_discovery_installation_profile import retained_mount_capture as old


class NativeHashReconciliation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true':
            raise AssertionError('DISPOSABLE_HOSTED_NATIVE_RETAINED_CAPTURE_ONLY')
        cls.case = fixture.RetainedMetadata(); cls.addClassCleanup(cls.case.doCleanups)
        cls.initial, cls.args, cls.seed, cls.root, cls.mounted, _, _ = cls.case.prepared()
        os.chown(cls.mounted/'credential',0,10001);(cls.mounted/'credential').chmod(0o440)
        cls.gateway_source=cls.root/'gateway-source';cls.gateway_source.mkdir(mode=0o700)
        (cls.gateway_source/'credential').write_bytes(b'OLD_NATIVE_PRIVATE_VALUE');(cls.gateway_source/'credential').chmod(0o600)
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
                '--mount','type=bind,src='+str(cls.gateway_source if role=='gateway-owner' else cls.mounted)+',dst=/run/input,readonly',
                '--mount','type=bind,src='+str(cls.root/'mutable')+',dst=/data',
                *(['-e','OUF_AUTHORIZATION_REGISTRY_TOKEN_FILE=/run/input/credential'] if role=='gateway-owner' else []),tag)
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
        (cls.gateway_source/'credential').write_bytes(b'NEW_NATIVE_PRIVATE_VALUE_LONGER')
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

    def test_a_real_old_two_get_failure_then_zero_engine_zero_content_reconciliation(self):
        c=recon.Reconciliation(self.root/'recon-a')
        with patch.object(h,'RetainedEngine',side_effect=AssertionError('NO_ENGINE_AFTER_FAILED_PREDECESSOR')):
            result=recon.collect(c)
        self.assertEqual(result['counts']['engineGets'],0);self.assertEqual(result['counts']['mountedFileContentBytesRead'],0)
        self.assertTrue(any(d['category']=='SIZE_OR_TIME_CHANGED' for d in result['differences']))
        self.assertTrue(any(d['configuredReferenceClass']=='EXPLICIT_TOKEN_PATH_REFERENCE' for d in result['differences']))
        self.assertFalse(result['hashPreparationRearmed']);self.assertFalse(result['permissionOrContentPolicyEstablished'])
        self.assertFalse(result['currentContainerConfigurationFreshlyObserved']);self.assertFalse(result['targetApplyAuthorized'])

    def test_b_real_atomic_replacement_reports_inode_and_custody_difference(self):
        file=self.root/'replacement';file.write_bytes(b'NEW_ATOMIC_PRIVATE_VALUE');file.chmod(0o600)
        file.replace(self.gateway_source/'credential')
        result=recon.collect(recon.Reconciliation(self.root/'recon-b'))
        self.assertTrue(any('inode' in d['changedMetadataFields'] for d in result['differences']))
        self.assertTrue(any(d['category']=='KIND_OR_CUSTODY_CHANGED' for d in result['differences']))
        self.assertFalse(result['hashPreparationRearmed'])

    def test_c_real_drifted_link_is_reported_without_following(self):
        (self.gateway_source/'credential').unlink();(self.gateway_source/'credential').symlink_to(self.root/'must-not-read')
        result=recon.collect(recon.Reconciliation(self.root/'recon-c'))
        self.assertTrue(any(d['currentKind']=='SYMLINK' for d in result['differences']))
        self.assertEqual(result['counts']['mountedFileContentBytesRead'],0)

    def test_z_restarted_actual_gateway_generation_denies_before_scan(self):
        self.command('restart',self.seed['observations'][self.aliases['gateway-owner']]['Id'])
        c=recon.Reconciliation(self.root/'recon-z')
        with self.assertRaises((ValueError,OSError)):recon.collect(c)
        self.assertEqual(c.counts['reconciliationNodes'],0);self.assertEqual(c.counts['engineGets'],0)


if __name__=='__main__':unittest.main()
