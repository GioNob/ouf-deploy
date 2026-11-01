"""Actual accepted producer chain then metadata-only view input on Docker29.

Namespace mutation helpers belong only to disposable native negative fixtures.
Source current/static witnesses and parent authority remain distinct obligations.
"""
import json,os,sys,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import qualify_m2_retained_views_native as fixture
from tools.m2_discovery_installation_profile import retained_view_capture as m
from tools.m2_discovery_installation_profile import retained_static_custody as previous


class NativeViewInput(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture.NativeViews.setUpClass.__func__(cls)
        owner=cls.static_observer
        selected={**owner.case,'staticCandidatePath':str(owner.path),
            'staticCandidateHash':owner.bindings['candidateHash'],'staticResultHash':owner.bindings['resultHash']}
        for name,value in {'CASE':selected,'ROSTER':previous.ROSTER}.items():
            context=patch.object(m,name,value);context.start();cls.addClassCleanup(context.stop)
    mutate=fixture.NativeViews.mutate
    unchanged_declaration=fixture.NativeViews.unchanged_declaration

    def test_a_actual_twenty_five_readonly_four_rw_and_eight_live_nodes_metadata_only(self):
        c=m.ViewCapture(self.root/'view-input-a')
        # An FD-based read guard rejects all token/SQLite/static content. Private
        # historical JSON and kernel proc metadata are the only O_RDONLY files.
        original=os.open;original_dup=os.dup;opened={}
        private={str(p) for root in (Path(m.CASE['candidatePath']).parent,Path(m.CASE['staticCandidatePath']).parent)
            for p in root.iterdir()}|{m.CASE['seedPath']}
        def closed(path,flags,*a,**kw):
            resolved=os.path.normpath(str(path)) if Path(path).is_absolute() else (
                os.path.normpath(str(Path(opened[kw['dir_fd']])/path)) if kw.get('dir_fd') in opened else None)
            if not flags&(os.O_DIRECTORY|os.O_PATH|os.O_WRONLY|os.O_RDWR):
                self.assertTrue(resolved in private or bool(resolved and resolved.startswith('/proc/')),resolved)
            fd=original(path,flags,*a,**kw)
            if resolved is not None:opened[fd]=resolved
            return fd
        def duplicate(fd):
            value=original_dup(fd)
            if fd in opened:opened[value]=opened[fd]
            return value
        with patch.object(os,'open',side_effect=closed),patch.object(os,'dup',side_effect=duplicate):result=m.collect(c)
        self.assertEqual(result['counts']['engineGets'],0);self.assertEqual(result['counts']['mountFileContentBytesRead'],0)
        self.assertEqual(result['counts']['effectiveReadonlyMounts'],25);self.assertEqual(result['counts']['effectiveWritableMounts'],4)
        self.assertEqual(result['counts']['liveLeafMetadataNodes'],8);self.assertEqual(result['counts']['liveCustodyContinuityDifferences'],0)
        self.assertEqual(result['cumulativeDirectEngineGets'],22);self.assertEqual(result['cumulativeControlAttempts'],6)
        self.assertTrue(result['allFivePriorScopesPreserved']);self.assertFalse(result['liveOwnerAuthenticated'])
        self.assertFalse(result['expectedPermissionOrContentPolicyEstablished']);self.assertFalse(result['targetApplyAuthorized'])
        record=json.loads((c.scope/'effective-views.private.json').read_bytes())
        text=json.dumps(record)+json.dumps(result)
        self.assertNotIn('SYNTHETIC_STATIC_PRIVATE_VALUE',text);self.assertNotIn('SYNTHETIC_LIVE_TOKEN',text)

    def test_b_actual_writeable_effective_mount_denies_while_docker_declarations_are_unchanged(self):
        target='/run/ouf-gateway-auth';self.mutate('rw',target)
        try:
            self.unchanged_declaration();c=m.ViewCapture(self.root/'view-input-b')
            with self.assertRaisesRegex(ValueError,'EFFECTIVE_MOUNT_ACCESS'):m.collect(c)
            self.assertFalse((c.scope/'effective-views.private.json').exists())
        finally:self.mutate('ro',target)

    def test_c_actual_permission_metadata_difference_is_recorded_not_learned_as_expected_policy(self):
        token=self.auth['gateway']/'token';mode=token.stat().st_mode&0o777;token.chmod(0o400)
        try:
            result=m.collect(m.ViewCapture(self.root/'view-input-c'))
            self.assertGreater(result['counts']['liveCustodyContinuityDifferences'],0)
            self.assertFalse(result['expectedPermissionOrContentPolicyEstablished']);self.assertFalse(result['completePrivateCustodyProven'])
        finally:token.chmod(mode)

    def test_d_actual_live_symlink_is_refused_without_following_or_reading(self):
        file=self.auth['gateway']/'token';old=self.auth['gateway']/'old-token';file.rename(old);file.symlink_to(self.keys['gateway-key'])
        try:
            c=m.ViewCapture(self.root/'view-input-d')
            with self.assertRaisesRegex(ValueError,'SOURCE_LINK_DENIED'):m.collect(c)
            self.assertFalse((c.scope/'effective-views.private.json').exists())
        finally:file.unlink();old.rename(file)

    def test_z_actual_gateway_restart_denies_before_kernel_or_content(self):
        self.command('restart',self.gateway['containerId']);c=m.ViewCapture(self.root/'view-input-z')
        with self.assertRaises((ValueError,OSError)):m.collect(c)
        self.assertEqual(c.counts['kernelReads'],0)


if __name__=='__main__':unittest.main()
