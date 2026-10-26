"""Read-only preparation: synthetic installed history, real private custody."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('capture', ROOT/'scripts/prepare-mcp-denial-update-inputs-20261026.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('CAPTURE_TEST_ROOT', str(ROOT)))
        self.base = Path(self.tmp.name); self.base.chmod(0o700)
        self.source = self.base/'source'; self.source.mkdir(mode=0o700)
        self.installed = self.source/'installed'; self.installed.mkdir(mode=0o700)
        self.boot = self.base/'boot'; self.boot.write_text('ci-boot')
        self.pin = {'pid': 100, 'startTicks': 7, 'namespaces': {'net': [1, 2], 'mnt': [3, 4]}}
        self.ids = {name: format(i+1, '064x') for i, name in enumerate(('gateway', 'postgres', 'ingestion', 'udp', 'ingestion-read', 'udp-read', 'mcp'))}
        self.observations = {}
        for name, cid in self.ids.items():
            self.observations[cid] = {'Id': cid, 'Image': 'sha256:'+'a'*64, 'Name': '/ouf-mcp' if name == 'mcp' else '/'+name,
                'State': {'Running': True, 'Paused': False, 'Restarting': False, 'Pid': 100, 'StartedAt': 'ci-start'},
                'Config': {'Cmd': ['server'], 'Env': ['PRIVATE_CANARY=do-not-print'], 'Hostname': name, 'Labels': {}},
                'HostConfig': {'AutoRemove': False, 'RestartPolicy': {'Name': 'unless-stopped', 'MaximumRetryCount': 0}},
                'Mounts': [], 'NetworkSettings': {'Networks': {'ci-net': {'NetworkID': 'n'*64}}}}
        self.pins = {}
        for i, actual in enumerate(self.observations.values()):
            actual['State']['Pid'] = 100+i
            self.pins[100+i] = dict(copy.deepcopy(self.pin), pid=100+i)
        self.plan = {'existingApplications': {r: m.stable_binding(self.observations[self.ids[r]]) for r in ('gateway', 'postgres', 'ingestion', 'udp')},
                     'engineBinding': {'fixture': True}, 'mcpReplacement': {'name': 'ouf-mcp'}}
        self.captured = {'bootId': 'ci-boot', 'currentProcessPins': {r: self.pins[self.observations[self.ids[r]]['State']['Pid']] for r in self.plan['existingApplications']}}
        self.native = {'schema': 'ouf.acquisition-native-execution-inputs.v1', 'bootId': 'ci-boot',
                       'nativeProposal': {'capturedInputsHash': m.digest(self.captured)},
                       'candidateFacts': {r: {'nativeImageId': 'sha256:'+'a'*64} for r in ('ingestion', 'udp', 'mcp')}}
        self.native['nativeProposalHash'] = m.digest(self.native['nativeProposal'])
        self.review = {'stages': ['stage-'+str(i) for i in range(16)], 'nativePlan': {'proposal': self.plan}}
        self.result = {'complete': True, 'status': 'ACQUISITION_READ_PATH_INSTALLED_E2E_NOT_ACCEPTED', 'reviewHash': m.digest(self.review),
                       'authorityHash': m.AUTHORITY_HASH, 'counts': {'engineGets': 306}}
        self.journal = {'state': 'COMPLETE', 'nextStage': 16, 'counts': self.result['counts'], 'reviewHash': self.result['reviewHash'], 'authorityHash': m.AUTHORITY_HASH,
                        'effects': [{'stage': s, 'state': 'APPLIED'} for s in self.review['stages']],
                        'candidates': {r: {'id': self.ids[r if r == 'mcp' else r+'-read'], 'configurationVerified': True, 'readinessProven': True, 'generation': self.pins[self.observations[self.ids[r if r == 'mcp' else r+'-read']]['State']['Pid']]} for r in ('ingestion', 'udp', 'mcp')}}
        self.paths = {'native': self.source/'native.json', 'captured': self.source/'captured.json'}
        for path, value in [(self.paths['native'], self.native), (self.paths['captured'], self.captured), (self.installed/'result.json', self.result), (self.installed/'review.json', self.review), (self.installed/'recovery.json', self.journal)]:
            path.write_bytes(m.encoded(value)); path.chmod(0o600)
        self.patches = patch.multiple(m, NATIVE_HASH=m.digest(self.native), INSTALLED_RESULT_HASH=m.digest(self.result), INSTALLED_REVIEW_HASH=m.digest(self.review))
        self.patches.start(); self.calls = []
        outer = self
        class ReadOnlyFixture:
            def __init__(self, capture, binding, ids):
                assert set(ids) == set(outer.ids.values()); self.capture = capture
            def get(self, path):
                outer.calls.append(path); self.capture.counts['engineGets'] += 1
                if path == '/v1.44/info': return {'Driver': 'overlay2'}
                return copy.deepcopy(outer.observations[path.split('/')[3]])
        self.engine = ReadOnlyFixture
    def tearDown(self):
        self.patches.stop(); self.tmp.cleanup()
    def prepare(self):
        self.capture = m.Capture(self.base/'one-capture')
        return m.prepare(self.capture, native_path=self.paths['native'], captured_path=self.paths['captured'], installed=self.installed,
                         engine_factory=self.engine, pin=lambda pid: copy.deepcopy(self.pins[pid]), boot_path=self.boot)
    def test_exact_same_installed_generations_and_no_old_scope_writes(self):
        paths=list(self.source.rglob('*.json')); before={str(p):(p.read_bytes(),m.frame(p.stat())) for p in paths}
        result=self.prepare()
        self.assertTrue(result['complete']); self.assertEqual(len(self.calls),9)
        self.assertEqual(result['counts']['privateMetadataReads'],5)
        self.assertEqual(len(list(self.capture.root.glob('private-read-*-claim.json'))),5)
        self.assertFalse(result['runtimeAuthorityIssued']);self.assertEqual(result['containerWrites'],0)
        self.assertFalse(result['mcpOAuthScopesVerified']);self.assertFalse(result['mcpLoadedPolicyVersionObserved'])
        self.assertNotIn('PRIVATE_CANARY',json.dumps(result));self.assertNotIn('do-not-print',json.dumps(result))
        self.assertEqual(before,{str(p):(p.read_bytes(),m.frame(p.stat())) for p in paths})
        payload=json.loads((self.capture.root/'inputs.json').read_text());self.assertEqual(result['inputsHash'],m.digest(payload))
        self.assertEqual((self.capture.root/'inputs.json').stat().st_mode&0o777,0o600)
        with self.assertRaises(m.Stop):m.Capture(self.capture.root)
    def test_consumed_history_with_claim_or_bad_result_stops_before_network(self):
        self.journal['effects'][0]['state']='CLAIMED';p=self.installed/'recovery.json';p.write_bytes(m.encoded(self.journal))
        with self.assertRaises(m.Stop):self.prepare()
        self.assertEqual(self.calls,[])
    def test_restarted_candidate_stops_without_adopting_new_generation(self):
        self.pins[self.observations[self.ids['mcp']]['State']['Pid']]['startTicks']=8
        with self.assertRaises(m.Stop):self.prepare()
        self.assertLess(len(self.calls),9)
    def test_original_config_drift_is_not_ignored(self):
        self.observations[self.ids['gateway']]['Config']['Hostname']='changed'
        with self.assertRaises(m.Stop):self.prepare()
    def test_installed_mcp_wrong_image_is_not_adopted(self):
        self.observations[self.ids['mcp']]['Image']='sha256:'+'b'*64
        with self.assertRaises(m.Stop):self.prepare()
    def test_reformatted_sealed_input_is_not_silently_normalized(self):
        self.paths['native'].write_text(json.dumps(self.native,indent=2))
        with self.assertRaises(m.Stop):self.prepare()
        self.assertEqual(self.calls,[])
    def test_history_public_mode_is_rejected(self):
        self.paths['native'].chmod(0o644)
        with self.assertRaises(m.Stop):self.prepare()
        self.assertEqual(self.calls,[])
    def test_history_symlink_is_rejected(self):
        target=self.source/'elsewhere.json';self.paths['native'].rename(target);self.paths['native'].symlink_to(target)
        with self.assertRaises(OSError):self.prepare()
        self.assertEqual(self.calls,[])
    def test_engine_has_no_mutation_or_arbitrary_get_port(self):
        c=m.Capture(self.base/'one-engine');e=m.Engine(c,{},list(self.ids.values()))
        self.assertFalse(hasattr(e,'request'));self.assertFalse(hasattr(e,'load'))
        for path in ('/v1.44/containers/json','/v1.44/containers/'+('f'*64)+'/json','/v1.44/containers/'+self.ids['mcp']+'/logs'):
            with self.assertRaises(m.Stop):e.get(path)
        self.assertEqual(c.counts['engineGets'],0)


if __name__=='__main__':unittest.main(verbosity=2)
