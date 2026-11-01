"""Actual protected metadata/FIFOs; Engine and /proc generations modeled."""
import copy, json, os, socket, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]; sys.path[:0] = [str(ROOT)]
from tools.m2_discovery_installation_profile import retained_mount_capture as m


class RetainedMetadata(unittest.TestCase):
    def prepared(self):
        tmp = tempfile.TemporaryDirectory(dir=ROOT); self.addCleanup(tmp.cleanup)
        root = Path(tmp.name); root.chmod(0o700); mounted = root/'mounts'; mounted.mkdir(mode=0o700)
        secret = mounted/'credential'; secret.write_bytes(b'NEVER_READ_MOUNTED_FILE_CONTENT'); secret.chmod(0o000)
        os.mkfifo(mounted/'fifo', 0o600)
        mutable = root/'mutable'; mutable.mkdir(mode=0o700); (mutable/'private-data').write_bytes(b'NEVER_ENUMERATE_MUTABLE_CONTENT')
        c = m.RetainedCapture(root/'capture'); boot = root/'boot-id'; boot.write_text('fixture-boot')
        pin = lambda pid: {'pid':pid,'startTicks':pid+100,'namespaces':{'net':[1,pid+1],'mnt':[1,pid+2]}}
        observations = {}; pins = {}
        for i, role in enumerate(sorted(m.ROLES), 100):
            observations[role] = {'Id':format(i,'064x'),'Name':'/fixture-'+role,'Image':'sha256:'+format(i+50,'064x'),
                'Config':{'Env':['NEVER_EMIT_CONFIG_ENV=fixture-sensitive']},'HostConfig':{},
                'Mounts':[{'Type':'bind','Source':str(mounted),'Destination':'/run/input','RW':False},
                    {'Type':'volume','Source':str(mutable),'Destination':'/data','RW':True},
                    {'Type':'tmpfs','Destination':'/tmp','RW':True}], 'NetworkSettings':{},
                'State':{'Pid':i,'StartedAt':'fixture-start','Running':True,'Paused':False,'Restarting':False}}
            pins[role] = pin(i)
        seed = {'schema':'ouf.m2-discovery-current-private-bindings.v1','observations':observations,'processPins':pins,
            'rootProcessPins':{'pid1':pin(1),'engine':pin(2)},'bootId':'fixture-boot',
            'engineBinding':{'socketPath':'/fixture/socket','socketBinding':[1,2,0,0,0o600],'peerCredentials':[2,0,0]},
            'historicalAuthorityReused':False,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False}
        path = root/'seed.json'; path.write_bytes(m.encoded(seed)); path.chmod(0o600)
        reads = []
        class Engine:
            def __init__(self, capture, binding, ids):
                self.c = capture; self.ids = set(ids)
            def get(self, cid):
                reads.append(cid); self.c.counts['engineGets'] += 1
                return copy.deepcopy(next(v for v in observations.values() if v['Id']==cid))
        args = {'seed_path':path,'seed_hash':m.digest(seed),'engine_factory':Engine,'pin':pin,'boot_path':boot}
        return c, args, seed, root, mounted, mutable, reads

    def test_twenty_gets_metadata_only_and_explicit_unobserved_mutable_and_ephemeral_content(self):
        c, args, seed, root, mounted, _, reads = self.prepared(); original_open = os.open
        def no_content(path, flags, *a, **kw):
            if not flags & (os.O_PATH | os.O_DIRECTORY | os.O_WRONLY | os.O_RDWR):
                self.assertEqual(str(path), str(args['seed_path']), 'only the exact seed may open for content')
            return original_open(path, flags, *a, **kw)
        with patch.object(m.os, 'open', side_effect=no_content): result = m.collect(c, **args)
        self.assertEqual(len(reads),20); self.assertEqual(result['selectedRetainedPeers'],10)
        self.assertEqual(result['counts']['mountFileContentBytesRead'],0)
        self.assertEqual(result['counts']['readonlyMounts'],10); self.assertEqual(result['counts']['mutableMounts'],10)
        self.assertEqual(result['counts']['ephemeralMounts'],10); self.assertEqual(result['counts']['specialSources'],10)
        private = (c.scope/'retained-mounts.private.json').read_text(); public = json.dumps(result)
        for value in ('NEVER_READ_MOUNTED_FILE_CONTENT','NEVER_ENUMERATE_MUTABLE_CONTENT','fixture-sensitive'):
            self.assertNotIn(value, private+public)
        self.assertNotIn(str(mounted), public); self.assertEqual(len(result['retainedRuntimeImageIds']),10)
        self.assertEqual(os.stat(c.scope/'retained-mounts.private.json').st_mode & 0o777,0o600)
        self.assertFalse(result['completePrivateCustodyProven']); self.assertFalse(result['targetApplyAuthorized'])

    def test_symlink_and_hardlink_static_candidates_stop_without_following_or_reading(self):
        for kind in ('symlink','hardlink'):
            c, args, _, root, mounted, _, _ = self.prepared()
            secret = mounted/'credential'
            if kind == 'symlink': secret.unlink(); secret.symlink_to(root/'mutable/private-data')
            else: os.link(secret, mounted/'alias')
            with self.subTest(kind=kind), self.assertRaises((ValueError,OSError)): m.collect(c, **args)
            self.assertFalse((c.scope/'retained-mounts.private.json').exists())

    def test_bounded_static_tree_and_duplicate_mount_destination_deny(self):
        c, args, _, _, _, _, _ = self.prepared()
        with patch.dict(m.LIMITS, entries=1), self.assertRaises(ValueError): m.collect(c, **args)
        c, args, seed, _, _, _, _ = self.prepared()
        seed['observations']['onboarding']['Mounts'].append(copy.deepcopy(seed['observations']['onboarding']['Mounts'][0]))
        args['seed_path'].write_bytes(m.encoded(seed)); args['seed_hash'] = m.digest(seed)
        with self.assertRaisesRegex(ValueError,'MOUNT_DECLARATION'): m.collect(c, **args)

    def test_seed_hash_or_current_boot_pin_change_denies_before_any_engine_get(self):
        for kind in ('hash','boot','pin'):
            c, args, _, _, _, _, reads = self.prepared()
            if kind == 'hash': args['seed_hash'] = '0'*64
            elif kind == 'boot': args['boot_path'].write_text('other-boot')
            else: args['pin'] = lambda pid: {'pid':pid,'different':True}
            with self.subTest(kind=kind), self.assertRaises(ValueError): m.collect(c, **args)
            self.assertFalse(reads)

    def test_two_pass_configuration_or_static_metadata_drift_is_not_reconciled_as_complete(self):
        for kind in ('configuration','file'):
            c, args, _, _, mounted, _, _ = self.prepared(); original = args['engine_factory']
            class Changed(original):
                def get(self, cid):
                    actual = super().get(cid)
                    if self.c.counts['engineGets'] == 11:
                        if kind == 'configuration': actual['Config']['Env'] = ['CHANGED=true']
                        else: (mounted/'credential').chmod(0o400)
                    return actual
            args['engine_factory'] = Changed
            with self.subTest(kind=kind), self.assertRaises(ValueError): m.collect(c, **args)
            self.assertFalse((c.scope/'retained-mounts.private.json').exists())

    def test_readonly_metadata_cannot_be_weakened_by_another_writable_mount(self):
        c, args, seed, _, mounted, _, _ = self.prepared()
        for v in seed['observations'].values():
            v['Mounts'].append({'Type':'bind','Source':str(mounted/'credential'),'Destination':'/writable-alias','RW':True})
        args['seed_path'].write_bytes(m.encoded(seed)); args['seed_hash'] = m.digest(seed)
        original = args['engine_factory']
        class Changed(original):
            def get(self, cid):
                result = super().get(cid)
                if self.c.counts['engineGets'] == 11: (mounted/'credential').chmod(0o400)
                return result
        args['engine_factory'] = Changed
        with self.assertRaisesRegex(ValueError,'SOURCE_CHANGED_DURING_CAPTURE'): m.collect(c, **args)

    def test_scope_is_create_once_and_network_failure_does_not_retry_or_erase_claim(self):
        c, args, _, _, _, _, _ = self.prepared()
        with self.assertRaisesRegex(ValueError,'CONSUMED_NO_REPLAY'): m.RetainedCapture(c.scope)
        original = args['engine_factory']; reads = []
        class Unavailable(original):
            def get(self, cid): reads.append(cid); raise TimeoutError('fixture')
        args['engine_factory'] = Unavailable
        with self.assertRaises(TimeoutError): m.collect(c, **args)
        self.assertEqual(len(reads),1); self.assertTrue((c.scope/'capture.claim.json').exists())
        self.assertFalse((c.scope/'retained-mounts.private.json').exists())

    def test_engine_allowlist_denies_arbitrary_ids_before_socket_contact(self):
        c, _, seed, _, _, _, _ = self.prepared()
        ids = [seed['observations'][r]['Id'] for r in sorted(m.RETAINED)]
        engine = m.RetainedEngine(c,seed['engineBinding'],ids)
        with self.assertRaisesRegex(ValueError,'CLOSED_TWENTY'): engine.get('f'*64)
        self.assertEqual(c.counts['engineGets'],0)


if __name__ == '__main__': unittest.main()
