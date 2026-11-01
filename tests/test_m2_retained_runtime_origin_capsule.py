"""Closed public source package/CLI; no target inputs or metadata capture."""
import copy, hashlib, json, subprocess, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]; sys.path[:0] = [str(ROOT)]
from tools.m2_discovery_installation_profile import retained_runtime_origin_capsule as m


class RetainedCapsule(unittest.TestCase):
    def prepared(self):
        tmp = tempfile.TemporaryDirectory(dir=ROOT); self.addCleanup(tmp.cleanup)
        root = Path(tmp.name); root.chmod(0o700)
        raw, manifest = m.build(ROOT, 'c'*40); p = root/'capsule.py'; p.write_bytes(raw)
        return root, p, raw, manifest

    def test_twenty_three_exact_sources_keep_the_original_frozen_custody_helper_and_deterministic_bytes(self):
        _, _, raw, manifest = self.prepared(); again, other = m.build(ROOT, 'c'*40)
        self.assertEqual((raw,manifest),(again,other)); self.assertEqual(len(manifest['sources']),23)
        original = json.loads((ROOT/'tools/m2_discovery_installation_profile/current_review_sources.json').read_text())
        name = 'tools.m2_discovery_installation_profile.custody_capture'
        self.assertEqual(manifest['sources'][name],original[name]); self.assertFalse(manifest['targetApplyAuthorized'])
        self.assertFalse(manifest['mountFileContentReadAllowed']);self.assertFalse(manifest['liveTokenAndOperationalStoreContentReadAllowed'])
        self.assertFalse(manifest['onlyCapturedReadonlyRegularFilesMayBeRead']);self.assertFalse(manifest['engineReadAllowed'])
        self.assertEqual(manifest['maximumEngineGets'],0);self.assertFalse(manifest['privateImageArchiveOutputAllowed'])
        self.assertFalse(manifest['privateByteEvidenceOutputAllowed']);self.assertTrue(manifest['privateOriginEvidenceOutputAllowed']);self.assertFalse(manifest['rawValuesExportAllowed'])
        self.assertFalse(manifest['publisherTrustAccepted'])

    def test_actual_isolated_inspection_works_away_from_repository_without_target_reads(self):
        root, p, _, manifest = self.prepared()
        result = subprocess.run([sys.executable,'-I','-B','-S',str(p),'--inspect-source'],cwd=root,
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr); body = json.loads(result.stdout)
        self.assertEqual(body['sourceCount'],23); self.assertEqual(body['sourceRevisionClaim'],'c'*40)
        self.assertEqual(body['captureSourceManifestHash'],hashlib.sha256(json.dumps(manifest['sources'],sort_keys=True,separators=(',',':')).encode()).hexdigest())
        self.assertFalse(body['targetApplyAuthorized']); self.assertEqual(sorted(p.name for p in root.iterdir()),['capsule.py'])

    def test_nonisolated_execution_unknown_args_and_payload_tampering_never_echo_private_arguments(self):
        root, p, raw, _ = self.prepared(); sentinel = 'PRIVATE_ARG_MUST_NOT_APPEAR'
        for args in ([str(p),'--inspect-source'], ['-I','-B','-S',str(p),'--unknown',sentinel]):
            result = subprocess.run([sys.executable,*args],cwd=root,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
            self.assertNotEqual(result.returncode,0); self.assertNotIn(sentinel.encode(),result.stdout+result.stderr)
        text = raw.decode(); prefix = "PAYLOAD='"; index = text.index(prefix)+len(prefix)
        p.write_text(text[:index]+('A' if text[index]!='A' else 'B')+text[index+1:])
        result = subprocess.run([sys.executable,'-I','-B','-S',str(p),'--inspect-source'],cwd=root,
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.assertNotEqual(result.returncode,0); self.assertEqual(json.loads(result.stdout)['status'],'STOP_RECONCILE')

    def test_changed_source_and_consistently_changed_map_are_not_an_approved_compiler_input(self):
        root, _, _, _ = self.prepared(); pins = json.loads((ROOT/m.SOURCE_MAP).read_text())
        for pin in pins.values():
            target = root/pin['path']; target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes((ROOT/pin['path']).read_bytes())
        source = root/pins[m.ENTRY]['path']; source.write_bytes(source.read_bytes()+b'\n# changed\n')
        pins[m.ENTRY]['sha256'] = hashlib.sha256(source.read_bytes()).hexdigest()
        target = root/m.SOURCE_MAP; target.write_text(json.dumps(pins,indent=2,sort_keys=True)+'\n')
        with self.assertRaisesRegex(ValueError,'EXACT_RETAINED'): m.build(root,'c'*40)
        with patch.object(m,'RUNTIME',m.RUNTIME+'\n# changed\n'), self.assertRaisesRegex(ValueError,'EXACT_RETAINED'):
            m.build(ROOT,'c'*40)

    def test_export_is_create_only_and_its_real_cli_bytes_match_the_direct_builder(self):
        root, _, raw, _ = self.prepared(); output = root/'exported.py'
        args = [sys.executable,'-I','-B','-S',str(ROOT/'scripts/export-m2-retained-runtime-origins.py'),
            '--root',str(ROOT),'--source-revision','c'*40,'--output',str(output)]
        first = subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.assertEqual(first.returncode,0,first.stderr); self.assertEqual(output.read_bytes(),raw)
        second = subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.assertNotEqual(second.returncode,0); self.assertEqual(output.read_bytes(),raw)


if __name__ == '__main__': unittest.main()
