"""Actual protected metadata reads; no runtime or transport substitutes invoked."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('byte_stop_observer', ROOT / 'scripts/inspect-registry-preparation-byte-stop-20261023.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class ByteStop(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.boot = '00000000-1111-2222-3333-444444444444'
        self.bootfile = self.root / 'boot'; self.bootfile.write_text(self.boot)
        history = {'sourceClosure': {'executables': {}}}
        for name in ('python', 'docker', 'openssl'):
            p = self.root / name; p.write_bytes(b'synthetic executable'); p.chmod(0o500)
            history['sourceClosure']['executables'][name] = {'path': str(p), 'sha256': 'a' * 64}
        hist = self.root / 'history.json'; hist.write_bytes(m.encoded(history)); hist.chmod(0o400)
        case = {'preparation': {'privateParent': str(self.root), 'historicalReview': {'path': str(hist), 'sha256': m.digest(history)},
            'frozenWireRecovery': {'response': {'sha256': 'b' * 64}}}}
        manifest = {'fixture': True}; delivery = {'nativeDeclaration': manifest, 'caseHash': m.digest(case)}
        self.capsule = self.root / 'capsule.py'
        self.capsule.write_text('CASE = '+repr(case)+'\nDELIVERY = '+repr(delivery)+'\nDELIVERY_HASH = '+repr(m.digest(delivery))+"\nPACKED = ''\nBOOTSTRAP = 'raise AssertionError(\"must not execute\")'\n")
        self.capsule.chmod(0o400)
        self.prep = self.root / ('semantic-registry-postboot-inputs-' + m.digest({'retainedFrozenResponseHash': 'b' * 64, 'boot': self.boot, 'purpose': 'FROZEN_WIRE_V1'}))
        self.prep.mkdir(mode=0o700)
        claim = {'schema': 'ouf.semantic-registry-postboot-preparation-case.v1', 'caseHash': m.digest(case['preparation']),
            'sourceClosureHash': m.digest(manifest), 'bootId': self.boot, 'maximumEngineGets': 12, 'maximumAdminGets': 1,
            'maximumFrozenGets': 1, 'automaticReplayAllowed': False, 'runtimeAuthorityIssued': False,
            'maximumTlsHandshakes': 1, 'maximumMetadataReads': 256}
        self.write('claim.json', claim)
        for key, value in {'CAPSULE': str(self.capsule), 'CAPSULE_HASH': hashlib.sha256(self.capsule.read_bytes()).hexdigest(),
            'CLOSURE_HASH': m.digest(manifest), 'DECLARATION_HASH': m.digest(delivery), 'PARENT': str(self.root)}.items():
            p = patch.object(m, key, value); p.start(); self.addCleanup(p.stop)
        real = Path
        p = patch.object(m, 'Path', side_effect=lambda v: self.bootfile if v == '/proc/sys/kernel/random/boot_id' else real(v)); p.start(); self.addCleanup(p.stop)

    def write(self, name, value):
        p = self.prep / name
        if p.exists(): p.chmod(0o600)
        p.write_bytes(m.encoded(value)); p.chmod(0o400)

    def test_markers_and_size_only_without_executing_capsule_or_binary(self):
        for n in range(1, 13): self.write('engine-get-'+str(n)+'.json', {'attempt': n, 'requestPathHash': 'c' * 64})
        self.write('frozen-response.json', {'private': 'never printed'})
        self.prep.joinpath('source').mkdir(mode=0o500)
        result = m.inspect(m.Reader())
        self.assertEqual(result['engineAttemptMarkers'], list(range(1, 13)))
        self.assertTrue(result['artifacts']['source']['directory'])
        self.assertEqual(result['executableBytesOpened'], 0)
        self.assertFalse(result['failedReadIdentified']); self.assertFalse(result['capsuleExecuted'])
        self.assertNotIn('never printed', json.dumps(result)); self.assertNotIn(str(self.root), json.dumps(result))

    def test_tampered_capsule_rejected(self):
        self.capsule.chmod(0o600); self.capsule.write_text('raise AssertionError()')
        with self.assertRaisesRegex(ValueError, 'METADATA_HASH_OR_BYTE_BOUND'): m.inspect(m.Reader())

    def test_missing_marker_in_middle_rejected(self):
        self.write('engine-get-2.json', {'attempt': 2, 'requestPathHash': 'c' * 64})
        with self.assertRaisesRegex(ValueError, 'CONTIGUOUS_ENGINE_MARKERS'): m.inspect(m.Reader())

    def test_link_or_wrong_attempt_rejected(self):
        self.prep.joinpath('engine-get-1.json').symlink_to(self.prep / 'claim.json')
        with self.assertRaisesRegex(ValueError, 'PROTECTED_ARTIFACT'): m.inspect(m.Reader())
        self.prep.joinpath('engine-get-1.json').unlink()
        self.write('engine-get-1.json', {'attempt': 2, 'requestPathHash': 'c' * 64})
        with self.assertRaisesRegex(ValueError, 'EXACT_ENGINE_MARKER'): m.inspect(m.Reader())

    def test_claim_drift_rejected(self):
        p = self.prep / 'claim.json'; row = json.loads(p.read_bytes()); row['maximumMetadataReads'] = 999
        self.write('claim.json', row)
        with self.assertRaisesRegex(ValueError, 'EXACT_FAILED_PREPARATION_CLAIM'): m.inspect(m.Reader())


if __name__ == '__main__': unittest.main()
